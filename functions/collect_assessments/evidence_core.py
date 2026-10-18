"""Evidence collection core for the Tallyfin GRC pipeline (CGE-AZ stage 03).

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
* **Two sources, collected once.** Defender assessments AND Azure Policy
  compliance states land in the same snapshot; the framework crosswalk
  (``frameworks/mappings.json``) maps them to every framework at report time,
  so no framework ever triggers its own collection.
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

LOG = logging.getLogger("tallyfin.collector")

ARM_ENDPOINT = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
SCHEMA_VERSION = "2.0"

API_DEFENDER_ASSESSMENTS = "2021-06-01"
API_POLICY_STATES = "2019-10-01"

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


def normalize_policy_state(item: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
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
        "subscriptionId": item.get("subscriptionId"),
        "sourceEvaluatedAt": item.get("timestamp"),
        "collectedAt": ctx.collected_at,
        "collectorVersion": ctx.app_version,
    }


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


def latest_state_document(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The starter's ``assessments`` document shape, kept so Lab 4-6 queries
    (and anything Frost built on them) keep working. Same id formula as the
    starter, so this upserts onto the existing documents rather than
    duplicating them. History lives in ``snapshots``; this is "now"."""
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


CROSSWALK_FRAMEWORK_ID = "tallyfin-crosswalk"


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


def run_collection(
    arm: ArmClient,
    store: EvidenceStore,
    subscription_id: str,
    crosswalk: dict[str, Any],
    *,
    trigger: str = "timer",
    app_version: str = "dev",
    now: datetime | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Collect one complete snapshot and return its manifest.

    Failure handling: one source failing (e.g. Defender throttling) must not
    discard the other source's evidence, so each source is isolated. But a
    run with any source error is marked ``partial`` and is never used by
    reports - missing evidence must not read as "no findings".
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
        "subscriptionId": subscription_id,
        "crosswalkVersion": xwalk["version"],
        "collectorVersion": app_version,
        "schemaVersion": SCHEMA_VERSION,
    }
    store.upsert("runs", dict(manifest))

    doc_ids: list[str] = []
    results: dict[str, SourceResult] = {"defender": SourceResult(), "policy": SourceResult()}

    def _write(doc: dict[str, Any], source: str) -> None:
        store.upsert("snapshots", doc)
        if source == "defender":
            store.upsert("assessments", latest_state_document(doc))
        doc_ids.append(doc["id"])
        results[source].documents += 1

    try:
        for item in iter_defender(arm, subscription_id):
            _write(normalize_defender(item, ctx, subscription_id), "defender")
    except Exception as exc:  # noqa: BLE001 - recorded in the manifest, not swallowed
        LOG.exception("defender collection failed")
        results["defender"].errors.append(str(exc))

    try:
        for item in iter_policy_states(arm, subscription_id):
            _write(normalize_policy_state(item, ctx), "policy")
    except Exception as exc:  # noqa: BLE001
        LOG.exception("policy state collection failed")
        results["policy"].errors.append(str(exc))

    errors = [e for r in results.values() for e in r.errors]
    total = len(doc_ids)
    if not errors:
        status = "completed"
    elif total:
        status = "partial"
    else:
        status = "failed"

    unique_ids = sorted(set(doc_ids))
    manifest.update(
        {
            "status": status,
            "completedAt": utc_now_iso(),
            "documentCount": total,
            "uniqueDocumentCount": len(unique_ids),
            "sources": {name: {"documents": r.documents, "errors": r.errors} for name, r in results.items()},
            # Digest over the sorted id set: anyone can recompute it from the stored
            # snapshots and show the run was not added to or trimmed afterwards.
            "documentSetSha256": hashlib.sha256("\n".join(unique_ids).encode()).hexdigest(),
        }
    )
    store.upsert("runs", manifest)
    LOG.info(
        "run %s %s (%s): %d documents (%d defender, %d policy)",
        ctx.run_id,
        status,
        trigger,
        total,
        results["defender"].documents,
        results["policy"].documents,
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
