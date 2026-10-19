"""Evidence collection core for the FAFO Inc. GRC pipeline (CGE-AZ stage 03).

Collect once, store once, stamp everything.

This module is deliberately free of Azure Functions imports so it can be
unit-tested with fakes and run locally. ``function_app.py`` is a thin timer
wrapper around :func:`run_collection`.

Design choices that close gaps found in the CGE-AZ Lab 6 walkthrough:

* **History, not overwrite.** Lab 6 derived the document id from
  ``assessment|resource`` only, so every run overwrote the last and Cosmos
  held latest-state, not history. Here the id is
  ``sha256(runId | findingKey)``: unique per run (history accumulates) and
  deterministic within a run (a retried upsert lands on the same document,
  so the write is idempotent).
* **Stable finding identity.** ``findingKey`` = ``sha256(source | nativeId |
  resourceId)`` is identical across runs, which is what lets the POA&M
  compute "first seen" from stored history instead of from memory.
* **Run manifests.** Lab 6's reporter picked the newest document's run,
  which could be a sweep still being written. Every run here writes a
  manifest first (``started``) and last (``completed``/``partial``/
  ``failed``); reports only ever read ``completed`` runs.
* **Scale by scope, not by size.** The collector discovers every subscription
  its management-group roles can see and collects each one. Nothing names a
  subscription, and every container's partition key starts with
  ``/subscriptionId``, so FAFO's second and third subscriptions need neither a
  code change nor a store reshape.
* **Three sources, collected once.** Defender assessments and Azure Policy
  compliance states land in ``findings``; role-assignment snapshots (something
  Defender does not give you) land in their own ``rbac`` container. The
  crosswalk (``frameworks/mappings.json``) maps findings to NIST SP 800-53
  Rev. 5 at report time, so no report ever triggers its own collection.
* **Trigger provenance.** Each manifest records whether a timer or a human
  started the run, so run history cannot be padded with manual runs unseen.
* **Two timestamps.** ``collectedAt`` is when we observed the record;
  ``sourceEvaluatedAt`` is when the platform last evaluated it. They are
  not the same thing and an assessor will ask.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Mapping, Protocol

LOG = logging.getLogger("fafo.collector")

ARM_ENDPOINT = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
SCHEMA_VERSION = "2.0"

API_DEFENDER_ASSESSMENTS = "2021-06-01"
API_POLICY_STATES = "2019-10-01"
API_RBAC = "2022-04-01"
API_SUBSCRIPTIONS = "2022-12-01"

# Containers, and why each is partitioned the way it is: docs/ARCHITECTURE.md#evidence-data-model
FINDINGS = "findings"  # hierarchical key [/subscriptionId, /runId]
RBAC = "rbac"  # hierarchical key [/subscriptionId, /runId]

RETRYABLE_STATUS = {429, 500, 502, 503, 504}

POLICY_STATE_SELECT = ",".join(
    [
        "resourceId",
        "subscriptionId",
        "policyAssignmentId",
        "policyAssignmentName",
        "policyDefinitionName",
        "policyDefinitionReferenceId",
        "policyDefinitionAction",
        "complianceState",
        "timestamp",
    ]
)


# --------------------------------------------------------------------------- errors


class ArmError(RuntimeError):
    """A non-retryable (or retries-exhausted) Azure Resource Manager failure."""

    def __init__(self, status: int, url: str, body: str) -> None:
        # Body is truncated: error payloads can be large and are logged.
        super().__init__(f"ARM {status} for {url}: {body[:500]}")
        self.status = status
        self.url = url


# --------------------------------------------------------------------------- protocols


class Credential(Protocol):
    def get_token(self, *scopes: str) -> Any: ...


class HttpResponse(Protocol):
    status_code: int
    headers: Mapping[str, str]
    text: str

    def json(self) -> Any: ...


class HttpSession(Protocol):
    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse: ...


class EvidenceStore(Protocol):
    """Write side of the evidence store. The collector never deletes."""

    def upsert(self, container: str, document: dict[str, Any]) -> None: ...


# --------------------------------------------------------------------------- ARM client


class ArmClient:
    """Minimal ARM client: bearer token, retry with Retry-After, pagination.

    Why not the Azure management SDKs? Defender and Policy Insights would
    pull in two large SDKs for three GET/POST calls; raw REST keeps the
    dependency surface (and the supply-chain risk) small and makes the exact
    API versions visible to an assessor.
    """

    def __init__(
        self,
        credential: Credential,
        session: HttpSession,
        *,
        max_retries: int = 5,
        sleep: Callable[[float], None] = time.sleep,
        audit: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._credential = credential
        self._session = session
        self._max_retries = max_retries
        self._sleep = sleep
        self._audit = audit or (lambda event: LOG.info("arm_call %s", json.dumps(event)))
        self._token: Any = None

    def _bearer(self) -> str:
        # Refresh five minutes early; get_token handles caching but we avoid
        # handing out a token that expires mid-pagination.
        now = time.time()
        if self._token is None or getattr(self._token, "expires_on", 0) - 300 < now:
            self._token = self._credential.get_token(ARM_SCOPE)
        return str(self._token.token)

    def request(self, method: str, url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        if url.startswith("/"):
            url = ARM_ENDPOINT + url
        attempt = 0
        while True:
            attempt += 1
            started = time.time()
            resp = self._session.request(
                method,
                url,
                headers={"Authorization": f"Bearer {self._bearer()}", "Content-Type": "application/json"},
                json=body,
                timeout=60,
            )
            # Audit trail of every external call (never the token).
            self._audit(
                {
                    "method": method,
                    "url": url.split("?")[0],
                    "status": resp.status_code,
                    "attempt": attempt,
                    "ms": int((time.time() - started) * 1000),
                }
            )
            if resp.status_code < 300:
                return resp.json() if resp.text else {}
            if resp.status_code in RETRYABLE_STATUS and attempt <= self._max_retries:
                retry_after = _retry_after_seconds(resp.headers, attempt)
                LOG.warning("ARM %s on %s, retrying in %.1fs", resp.status_code, url.split("?")[0], retry_after)
                self._sleep(retry_after)
                continue
            raise ArmError(resp.status_code, url.split("?")[0], resp.text)

    def paginate(self, method: str, url: str, body: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        """Yield every item across pages.

        Defender returns ``nextLink``; Policy Insights returns
        ``@odata.nextLink`` and expects the follow-up as POST again. Both
        are handled so neither source can silently truncate at page one.
        """
        next_url: str | None = url
        pages = 0
        while next_url:
            page = self.request(method, next_url, body)
            pages += 1
            yield from page.get("value", [])
            next_url = page.get("nextLink") or page.get("@odata.nextLink")
            if pages > 10_000:  # defensive: a server bug must not loop forever
                raise ArmError(0, url, "pagination exceeded 10000 pages")


def _retry_after_seconds(headers: Mapping[str, str], attempt: int) -> float:
    raw = None
    for key, value in headers.items():
        if key.lower() in ("retry-after", "x-ms-retry-after-ms"):
            raw = (key.lower(), value)
            break
    if raw:
        try:
            seconds = float(raw[1])
            return seconds / 1000 if raw[0] == "x-ms-retry-after-ms" else seconds
        except ValueError:
            pass
    return min(2 ** attempt, 60)


# --------------------------------------------------------------------------- identity helpers


def sha256_hex(*parts: str) -> str:
    """Deterministic id from ordered parts. '|' is not valid in ARM ids."""
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def finding_key(source: str, native_id: str, resource_id: str) -> str:
    """Stable across runs: the same control on the same resource."""
    return sha256_hex(source, native_id.lower(), resource_id.lower())


def content_sha256(document: dict[str, Any]) -> str:
    """Hash of a document's content in canonical form (sorted keys, no spaces).

    Cosmos adds system fields (``_rid``, ``_etag``, ``_ts``...) on write, so every
    key starting with ``_`` is left out; what remains is exactly what we wrote.
    ``reports_core.content_sha256`` must stay byte-for-byte identical to this.
    """
    body = {k: v for k, v in document.items() if not k.startswith("_")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def content_set_sha256(content_hashes: Mapping[str, str]) -> str:
    """One digest over every (id, content hash) pair in a run, in id order."""
    lines = (f"{doc_id} {content_hashes[doc_id]}" for doc_id in sorted(content_hashes))
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def document_id(run_id: str, f_key: str) -> str:
    """Unique per run, deterministic within it (idempotent retries)."""
    return sha256_hex(run_id, f_key)


def utc_now_iso(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


# --------------------------------------------------------------------------- normalization

DEFENDER_RESULT = {"healthy": "pass", "unhealthy": "fail", "notapplicable": "not_applicable"}
POLICY_RESULT = {
    "compliant": "pass",
    "noncompliant": "fail",
    "exempt": "not_applicable",
    "conflict": "fail",
    "unknown": "unknown",
}


@dataclass(frozen=True)
class RunContext:
    run_id: str
    collected_at: str
    app_version: str


def _defender_resource_id(item: dict[str, Any]) -> str:
    """Resolve the assessed resource. Prefer resourceDetails; fall back to
    stripping the assessment suffix from the item id (always present)."""
    details = (item.get("properties") or {}).get("resourceDetails") or {}
    for key in ("Id", "id", "ResourceId", "resourceId"):
        if details.get(key):
            return str(details[key])
    item_id = str(item.get("id", ""))
    marker = "/providers/microsoft.security/assessments/"
    idx = item_id.lower().find(marker)
    return item_id[:idx] if idx > 0 else item_id


def normalize_defender(item: dict[str, Any], ctx: RunContext, subscription_id: str) -> dict[str, Any]:
    props = item.get("properties") or {}
    status = props.get("status") or {}
    metadata = props.get("metadata") or {}
    native_id = str(item.get("name", ""))
    resource_id = _defender_resource_id(item)
    raw = str(status.get("code", "Unknown"))
    f_key = finding_key("defender", native_id, resource_id)
    return {
        "id": document_id(ctx.run_id, f_key),
        "runId": ctx.run_id,
        "schemaVersion": SCHEMA_VERSION,
        "source": "defender",
        "nativeId": native_id,
        "findingKey": f_key,
        "displayName": props.get("displayName") or metadata.get("displayName") or native_id,
        "result": DEFENDER_RESULT.get(raw.lower(), "unknown"),
        "rawStatus": raw,
        "statusCause": status.get("cause"),
        "statusDescription": status.get("description"),
        "severity": metadata.get("severity"),
        "categories": metadata.get("categories"),
        "resourceId": resource_id,
        "resourceIdLower": resource_id.lower(),
        "subscriptionId": subscription_id,
        "sourceEvaluatedAt": status.get("statusChangeDate") or status.get("firstEvaluationDate"),
        "collectedAt": ctx.collected_at,
        "collectorVersion": ctx.app_version,
    }


def normalize_policy_state(item: dict[str, Any], ctx: RunContext, subscription_id: str | None = None) -> dict[str, Any]:
    definition = str(item.get("policyDefinitionName", ""))
    assignment_id = str(item.get("policyAssignmentId", ""))
    assignment_name = str(item.get("policyAssignmentName") or assignment_id.rsplit("/", 1)[-1])
    reference = item.get("policyDefinitionReferenceId") or ""
    # Same definition assigned at two scopes = two findings, not one.
    native_id = f"{definition}@{assignment_id}#{reference}".lower()
    resource_id = str(item.get("resourceId", ""))
    raw = str(item.get("complianceState", "Unknown"))
    f_key = finding_key("policy", native_id, resource_id)
    return {
        "id": document_id(ctx.run_id, f_key),
        "runId": ctx.run_id,
        "schemaVersion": SCHEMA_VERSION,
        "source": "policy",
        "nativeId": native_id,
        "findingKey": f_key,
        "displayName": definition,
        "policyDefinitionName": definition,
        "policyAssignmentId": assignment_id,
        "policyAssignmentName": assignment_name,
        "effect": item.get("policyDefinitionAction"),
        "result": POLICY_RESULT.get(raw.lower(), "unknown"),
        "rawStatus": raw,
        "severity": None,
        "resourceId": resource_id,
        "resourceIdLower": resource_id.lower(),
        # Part of the partition key, so never null: fall back to the subscription queried.
        "subscriptionId": item.get("subscriptionId") or subscription_id,
        "sourceEvaluatedAt": item.get("timestamp"),
        "collectedAt": ctx.collected_at,
        "collectorVersion": ctx.app_version,
    }


# --------------------------------------------------------------------------- scope discovery


def discover_subscriptions(arm: ArmClient) -> list[str]:
    """Every enabled subscription this identity can see.

    Scale by scope, not by size: the collector's roles are granted at the
    management group (stage 03), so "what it can see" IS the governed estate.
    FAFO's second and third subscriptions are collected the first run after they
    are moved under mg-grc-sandbox - no setting, list or redeploy changes.
    """
    subs = arm.paginate("GET", f"/subscriptions?api-version={API_SUBSCRIPTIONS}")
    return sorted(str(s["subscriptionId"]) for s in subs if str(s.get("state", "Enabled")) == "Enabled")


# --------------------------------------------------------------------------- sources


def iter_defender(arm: ArmClient, subscription_id: str) -> Iterator[dict[str, Any]]:
    url = (
        f"/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments"
        f"?api-version={API_DEFENDER_ASSESSMENTS}&$expand=metadata"
    )
    return arm.paginate("GET", url)


def iter_policy_states(arm: ArmClient, subscription_id: str) -> Iterator[dict[str, Any]]:
    url = (
        f"/subscriptions/{subscription_id}"
        f"/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
        f"?api-version={API_POLICY_STATES}&$select={POLICY_STATE_SELECT}"
    )
    return arm.paginate("POST", url)


def iter_role_assignments(arm: ArmClient, subscription_id: str) -> Iterator[dict[str, Any]]:
    """Every role assignment that applies to the subscription: at it, below it (resource
    groups, resources) and inherited from above (management groups, root)."""
    url = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version={API_RBAC}"
    return arm.paginate("GET", url)


def role_definitions(arm: ArmClient, subscription_id: str) -> dict[str, dict[str, str]]:
    """Role definition GUID -> name and type, so a snapshot says "Owner", not a GUID."""
    url = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions?api-version={API_RBAC}"
    out: dict[str, dict[str, str]] = {}
    for d in arm.paginate("GET", url):
        props = d.get("properties") or {}
        out[str(d.get("name", "")).lower()] = {"roleName": str(props.get("roleName", "")), "roleType": str(props.get("type", ""))}
    return out


# --------------------------------------------------------------------------- RBAC snapshots

# Roles that can change resources or grant access. Matched by name AND built-in GUID, because a
# custom role can be named "Owner" and a built-in can be renamed in a display layer.
PRIVILEGED_ROLE_NAMES = {"Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"}
PRIVILEGED_ROLE_GUIDS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168",  # Role Based Access Control Administrator
}


def scope_level(scope: str) -> str:
    parts = [p.lower() for p in scope.strip("/").split("/") if p]
    if not parts:
        return "root"
    if parts[:2] == ["providers", "microsoft.management"]:
        return "managementGroup"
    if parts[0] == "subscriptions":
        if len(parts) == 2:
            return "subscription"
        if len(parts) == 4 and parts[2] == "resourcegroups":
            return "resourceGroup"
        return "resource"
    return "other"


def normalize_role_assignment(
    item: dict[str, Any], ctx: RunContext, subscription_id: str, definitions: Mapping[str, Mapping[str, str]]
) -> dict[str, Any]:
    props = item.get("properties") or {}
    assignment_id = str(item.get("id", ""))
    scope = str(props.get("scope", ""))
    role_definition_id = str(props.get("roleDefinitionId", ""))
    role_guid = role_definition_id.rsplit("/", 1)[-1].lower()
    definition = definitions.get(role_guid, {})
    role_name = definition.get("roleName") or "unknown"
    level = scope_level(scope)
    return {
        # One document per assignment PER SUBSCRIPTION VIEW per run: an assignment inherited
        # from the management group appears under every subscription it reaches, which is
        # exactly the question "who can act on subscription S?" asks.
        "id": sha256_hex(ctx.run_id, subscription_id, assignment_id.lower()),
        "runId": ctx.run_id,
        "subscriptionId": subscription_id,
        "schemaVersion": SCHEMA_VERSION,
        "type": "role-assignment",
        "assignmentId": assignment_id,
        "scope": scope,
        "scopeLevel": level,
        "inherited": level in ("root", "managementGroup"),
        "principalId": props.get("principalId"),
        "principalType": props.get("principalType"),
        "roleDefinitionId": role_definition_id,
        "roleName": role_name,
        "roleType": definition.get("roleType"),
        "privileged": role_guid in PRIVILEGED_ROLE_GUIDS or role_name in PRIVILEGED_ROLE_NAMES,
        "condition": props.get("condition"),
        "createdOn": props.get("createdOn"),
        "updatedOn": props.get("updatedOn"),
        "createdBy": props.get("createdBy"),
        "collectedAt": ctx.collected_at,
        "collectorVersion": ctx.app_version,
    }


def latest_state_document(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The starter's ``assessments`` document shape, kept so Lab 4-6 queries
    (and anything Frost built on them) keep working. Same id formula as the
    starter, so this upserts onto the existing documents rather than
    duplicating them. History lives in ``findings``; this is "now"."""
    starter_id = hashlib.sha256(f"{snapshot['nativeId']}|{snapshot['resourceId']}".encode()).hexdigest()[:32]
    return {
        "id": starter_id,
        "subscriptionId": snapshot["subscriptionId"],
        "assessmentId": snapshot["nativeId"],
        "displayName": snapshot["displayName"],
        "status": snapshot["rawStatus"],
        "statusCause": snapshot.get("statusCause"),
        "severity": snapshot.get("severity"),
        "categories": snapshot.get("categories"),
        "resourceId": snapshot["resourceId"],
        "collectedAt": snapshot["collectedAt"],
        "runId": snapshot["runId"],
        "snapshotId": snapshot["id"],
    }


# --------------------------------------------------------------------------- crosswalk


CROSSWALK_FRAMEWORK_ID = "fafo-crosswalk"


def crosswalk_document(mapping: dict[str, Any]) -> dict[str, Any]:
    """Version the crosswalk by content hash so a report can name the exact
    mapping it used, and so re-uploading an unchanged file is a no-op.
    Stored in the starter's ``mappings`` container (partition /frameworkId)."""
    canonical = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
    version = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return {
        "id": f"crosswalk-{version}",
        "frameworkId": CROSSWALK_FRAMEWORK_ID,
        "type": "crosswalk",
        "version": version,
        "mapping": mapping,
    }


# --------------------------------------------------------------------------- the run


@dataclass
class SourceResult:
    documents: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class ContainerSeal:
    """Digests for one container's documents in one run (see run manifests)."""

    content_hashes: dict[str, str] = field(default_factory=dict)  # last write wins, like the upsert

    def add(self, doc: dict[str, Any]) -> None:
        self.content_hashes[doc["id"]] = content_sha256(doc)

    def seal(self) -> dict[str, Any]:
        ids = sorted(self.content_hashes)
        return {
            "documents": len(ids),
            # Over the sorted id set: shows the run was not added to or trimmed afterwards.
            "documentSetSha256": hashlib.sha256("\n".join(ids).encode()).hexdigest(),
            # Over every document's CONTENT as well: the id digest alone cannot see a
            # document edited in place (same id, e.g. "fail" changed to "pass").
            "contentSetSha256": content_set_sha256(self.content_hashes),
        }


SOURCES = ("defender", "policy", "rbac")


def run_collection(
    arm: ArmClient,
    store: EvidenceStore,
    management_group: str,
    crosswalk: dict[str, Any],
    *,
    trigger: str = "timer",
    app_version: str = "dev",
    now: datetime | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Collect one complete snapshot of the governed scope and return its manifest.

    Scope: every subscription the collector's management-group roles reach
    (:func:`discover_subscriptions`). Each subscription and each source is
    isolated, so one throttled API does not discard the rest of the evidence.
    But a run with ANY source error in ANY subscription is marked ``partial``
    and is never used by reports - missing evidence must not read as "no findings".
    """
    if trigger not in ("timer", "manual"):
        raise ValueError(f"unknown trigger {trigger!r}")

    ctx = RunContext(
        run_id=run_id or str(uuid.uuid4()),
        collected_at=utc_now_iso(now),
        app_version=app_version,
    )
    xwalk = crosswalk_document(crosswalk)
    store.upsert("mappings", xwalk)

    manifest: dict[str, Any] = {
        "id": ctx.run_id,
        "runId": ctx.run_id,
        "type": "run-manifest",
        "status": "started",
        "trigger": trigger,
        "startedAt": ctx.collected_at,
        "scope": {"managementGroup": management_group, "subscriptions": []},
        "crosswalkVersion": xwalk["version"],
        "collectorVersion": app_version,
        "schemaVersion": SCHEMA_VERSION,
    }
    store.upsert("runs", dict(manifest))

    results = {name: SourceResult() for name in SOURCES}
    per_subscription: dict[str, dict[str, Any]] = {}
    seals = {FINDINGS: ContainerSeal(), RBAC: ContainerSeal()}
    discovery_errors: list[str] = []

    def _write(container: str, doc: dict[str, Any], source: str, sub: str) -> None:
        store.upsert(container, doc)
        if source == "defender":
            store.upsert("assessments", latest_state_document(doc))
        seals[container].add(doc)
        results[source].documents += 1
        per_subscription[sub][source] += 1

    def _collect(source: str, sub: str, body: Callable[[], None]) -> None:
        try:
            body()
        except Exception as exc:  # noqa: BLE001 - recorded in the manifest, not swallowed
            LOG.exception("%s collection failed for subscription %s", source, sub)
            message = f"{sub}: {exc}"
            results[source].errors.append(message)
            per_subscription[sub]["errors"].append(f"{source}: {exc}")

    try:
        subscriptions = discover_subscriptions(arm)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("subscription discovery failed")
        subscriptions = []
        discovery_errors.append(str(exc))
    if not subscriptions and not discovery_errors:
        discovery_errors.append(f"no enabled subscriptions visible under {management_group}")
    manifest["scope"]["subscriptions"] = subscriptions

    for sub in subscriptions:
        per_subscription[sub] = {name: 0 for name in SOURCES} | {"errors": []}

        def defender(sub: str = sub) -> None:
            for item in iter_defender(arm, sub):
                _write(FINDINGS, normalize_defender(item, ctx, sub), "defender", sub)

        def policy(sub: str = sub) -> None:
            for item in iter_policy_states(arm, sub):
                _write(FINDINGS, normalize_policy_state(item, ctx, sub), "policy", sub)

        def rbac(sub: str = sub) -> None:
            definitions = role_definitions(arm, sub)
            for item in iter_role_assignments(arm, sub):
                _write(RBAC, normalize_role_assignment(item, ctx, sub, definitions), "rbac", sub)

        _collect("defender", sub, defender)
        _collect("policy", sub, policy)
        _collect("rbac", sub, rbac)

    errors = discovery_errors + [e for r in results.values() for e in r.errors]
    total = sum(r.documents for r in results.values())
    if not errors:
        status = "completed"
    elif total:
        status = "partial"
    else:
        status = "failed"

    findings_seal = seals[FINDINGS].seal()
    manifest.update(
        {
            "status": status,
            "completedAt": utc_now_iso(),
            "documentCount": total,
            "uniqueDocumentCount": findings_seal["documents"] + seals[RBAC].seal()["documents"],
            "sources": {name: {"documents": r.documents, "errors": r.errors} for name, r in results.items()},
            "subscriptionResults": per_subscription,
            "discoveryErrors": discovery_errors,
            # Per-container seals. The top-level digests below are the findings seal, kept
            # at the top level because every report verifies them.
            "containers": {FINDINGS: findings_seal, RBAC: seals[RBAC].seal()},
            "documentSetSha256": findings_seal["documentSetSha256"],
            "contentSetSha256": findings_seal["contentSetSha256"],
        }
    )
    store.upsert("runs", manifest)
    LOG.info(
        "run %s %s (%s): %d subscriptions, %d documents (%d defender, %d policy, %d rbac)",
        ctx.run_id,
        status,
        trigger,
        len(subscriptions),
        total,
        results["defender"].documents,
        results["policy"].documents,
        results["rbac"].documents,
    )
    return manifest


# --------------------------------------------------------------------------- Cosmos adapter


class CosmosEvidenceStore:
    """Cosmos DB writer using Entra ID (the account has local auth disabled)."""

    def __init__(self, endpoint: str, database: str, credential: Any) -> None:
        from azure.cosmos import CosmosClient  # imported lazily for testability

        self._db = CosmosClient(endpoint, credential=credential).get_database_client(database)
        self._containers: dict[str, Any] = {}

    def upsert(self, container: str, document: dict[str, Any]) -> None:
        if container not in self._containers:
            self._containers[container] = self._db.get_container_client(container)
        self._containers[container].upsert_item(document)
