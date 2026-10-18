"""Report generation core for the Tallyfin GRC pipeline (CGE-AZ stage 04).

Reports read from the evidence store ONLY. This module never imports an Azure
management SDK, and the reporter identity holds no Azure Resource Manager role
at all (stage 04), so a live-API call would fail even if someone added one.

Every artifact carries its receipts:
  * the runId it was built from, that run's documentSetSha256, and the
    crosswalk version in force;
  * the exact Cosmos queries (text + parameters) that produced its numbers,
    so ``scripts/reproduce_report.py`` can re-derive them from the store;
  * one reportExecutionId shared by every file of the same execution.

Lab 6 findings fixed here:
  * Reports pick the newest run whose MANIFEST says completed, never "the
    newest document" (which could belong to a sweep still being written).
  * One execution id names one folder; all files go in it and a manifest with
    each file's SHA-256 is written LAST. A folder without manifest.json is an
    incomplete execution and consumers ignore it. No more JSON/XLSX pairs with
    different timestamps, and no more same-day path collisions.
  * "First seen" comes from stored history, so POA&M due dates stop resetting
    every day the way the starter's ``today + SLA`` did.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Protocol

LOG = logging.getLogger("tallyfin.reports")

GENERATOR_VERSION = "2.0"
CROSSWALK_FRAMEWORK_ID = "tallyfin-crosswalk"
OPEN_RESULTS = {"fail"}

Q_LATEST_COMPLETED = (
    "SELECT TOP 1 * FROM c WHERE c.type = 'run-manifest' AND c.status = 'completed' "
    "ORDER BY c.completedAt DESC"
)
Q_PREVIOUS_COMPLETED = (
    "SELECT TOP 1 * FROM c WHERE c.type = 'run-manifest' AND c.status = 'completed' "
    "AND c.completedAt < @before ORDER BY c.completedAt DESC"
)
Q_RUN_SNAPSHOTS = "SELECT * FROM c WHERE c.runId = @runId"
Q_CROSSWALK = "SELECT * FROM c WHERE c.id = @id"
Q_FIRST_SEEN = (
    "SELECT c.findingKey, c.collectedAt FROM c "
    "WHERE c.result = 'fail' AND ARRAY_CONTAINS(@keys, c.findingKey)"
)


# --------------------------------------------------------------------------- errors


class NoCompletedRunError(RuntimeError):
    """No completed collection run exists yet."""


class StaleEvidenceError(RuntimeError):
    """The newest completed run is older than the freshness limit."""


class EvidenceIntegrityError(RuntimeError):
    """The run's stored documents no longer match the digests sealed at collection.
    Raised loudly: a report built on altered evidence would look exactly like a real one."""


class CrosswalkError(ValueError):
    """The crosswalk file is malformed. Raised loudly: a silently ignored
    match rule would quietly drop findings from every framework view."""


# --------------------------------------------------------------------------- protocols


class EvidenceReader(Protocol):
    def query(
        self,
        container: str,
        query: str,
        parameters: list[dict[str, Any]] | None = None,
        partition_key: str | None = None,
    ) -> list[dict[str, Any]]: ...


class ReportWriter(Protocol):
    def upload(self, path: str, data: bytes, content_type: str) -> None: ...


# --------------------------------------------------------------------------- lineage


@dataclass
class QueryLog:
    """Records every store query a report makes, verbatim, for its receipts."""

    entries: list[dict[str, Any]]

    def __init__(self) -> None:
        self.entries = []

    def run(
        self,
        reader: EvidenceReader,
        container: str,
        query: str,
        parameters: list[dict[str, Any]] | None = None,
        partition_key: str | None = None,
    ) -> list[dict[str, Any]]:
        rows = reader.query(container, query, parameters, partition_key)
        self.entries.append(
            {
                "container": container,
                "query": query,
                "parameters": parameters or [],
                "partitionKey": partition_key,
                "rowCount": len(rows),
            }
        )
        return rows


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# --------------------------------------------------------------------------- run selection


def latest_completed_run(
    reader: EvidenceReader, qlog: QueryLog, now: datetime, max_age_hours: float
) -> dict[str, Any]:
    rows = qlog.run(reader, "runs", Q_LATEST_COMPLETED)
    if not rows:
        raise NoCompletedRunError("no completed collection run in the store")
    run = rows[0]
    age = now - _parse_ts(run["completedAt"])
    if age > timedelta(hours=max_age_hours):
        raise StaleEvidenceError(
            f"newest completed run {run['runId']} finished {age} ago (limit {max_age_hours}h); "
            "refusing to publish stale numbers"
        )
    return run


def previous_completed_run(reader: EvidenceReader, qlog: QueryLog, run: dict[str, Any]) -> dict[str, Any] | None:
    rows = qlog.run(
        reader,
        "runs",
        Q_PREVIOUS_COMPLETED,
        [{"name": "@before", "value": run["completedAt"]}],
    )
    return rows[0] if rows else None


def load_snapshots(reader: EvidenceReader, qlog: QueryLog, run_id: str) -> list[dict[str, Any]]:
    # Single-partition read: snapshots are partitioned by runId.
    return qlog.run(reader, "snapshots", Q_RUN_SNAPSHOTS, [{"name": "@runId", "value": run_id}], run_id)


def content_sha256(document: dict[str, Any]) -> str:
    """Canonical content hash. Must stay byte-for-byte identical to
    ``evidence_core.content_sha256`` (tests/test_reports.py checks they agree)."""
    body = {k: v for k, v in document.items() if not k.startswith("_")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_run_digest(run: dict[str, Any], snapshots: Iterable[dict[str, Any]]) -> bool:
    """Recompute the manifest digests from the stored documents. A mismatch
    means the run's evidence changed after it was sealed.

    The id digest catches documents added to or removed from a run; the content
    digest catches a document edited in place. Runs collected before the content
    digest existed carry only the id digest, and are checked on that alone.
    """
    snaps = list(snapshots)
    ids_ok = hashlib.sha256("\n".join(sorted({d["id"] for d in snaps})).encode()).hexdigest() == run.get(
        "documentSetSha256"
    )
    sealed_content = run.get("contentSetSha256")
    if sealed_content is None:
        return ids_ok
    lines = (f"{d['id']} {content_sha256(d)}" for d in sorted(snaps, key=lambda d: d["id"]))
    content_ok = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest() == sealed_content
    return ids_ok and content_ok


def require_sealed_run(run: dict[str, Any], snapshots: list[dict[str, Any]]) -> bool:
    if not verify_run_digest(run, snapshots):
        LOG.error("run %s digest mismatch: evidence changed after the run was sealed", run["runId"])
        raise EvidenceIntegrityError(
            f"run {run['runId']}: stored snapshots no longer match the digests sealed at collection; "
            "refusing to publish a report from altered evidence"
        )
    return True


# --------------------------------------------------------------------------- crosswalk

MATCH_KEYS = {
    "source",
    "assessmentName",
    "policyDefinitionName",
    "policyAssignmentName",
    "displayNameContains",
    "displayNameContainsAny",
    "displayNameContainsAll",
}


class Crosswalk:
    """Resolves a stored finding to a control and its framework requirements.

    First matching control wins, in file order. Unknown match keys are an
    error, not a no-op.
    """

    def __init__(self, mapping: dict[str, Any], version: str) -> None:
        self.version = version
        self.frameworks: dict[str, Any] = mapping.get("frameworks", {})
        self.sla_days: dict[str, int] = mapping.get("slaDays", {"High": 30, "Medium": 90, "Low": 180})
        self.severity_defaults: dict[str, str] = mapping.get("severityDefaults", {})
        self.controls: list[dict[str, Any]] = mapping.get("controls", [])
        seen: set[str] = set()
        for c in self.controls:
            key = c.get("controlKey")
            if not key or key in seen:
                raise CrosswalkError(f"missing or duplicate controlKey: {key!r}")
            seen.add(key)
            unknown = set(c.get("match", {})) - MATCH_KEYS
            if unknown or "source" not in c.get("match", {}):
                raise CrosswalkError(f"{key}: bad match keys {sorted(unknown) or 'missing source'}")
            bad_fw = set(c.get("mappings", {})) - set(self.frameworks)
            if bad_fw:
                raise CrosswalkError(f"{key}: unknown frameworks {sorted(bad_fw)}")

    @staticmethod
    def _matches(rule: dict[str, Any], doc: dict[str, Any]) -> bool:
        name = str(doc.get("displayName") or "").lower()
        checks = {
            "source": lambda v: doc.get("source") == v,
            "assessmentName": lambda v: str(doc.get("nativeId", "")).lower() == str(v).lower(),
            "policyDefinitionName": lambda v: str(doc.get("policyDefinitionName", "")).lower() == str(v).lower(),
            "policyAssignmentName": lambda v: str(doc.get("policyAssignmentName", "")).lower() == str(v).lower(),
            "displayNameContains": lambda v: str(v).lower() in name,
            "displayNameContainsAny": lambda v: any(str(x).lower() in name for x in v),
            "displayNameContainsAll": lambda v: all(str(x).lower() in name for x in v),
        }
        return all(checks[k](v) for k, v in rule.items())

    def resolve(self, doc: dict[str, Any]) -> dict[str, Any] | None:
        for control in self.controls:
            if self._matches(control["match"], doc):
                return control
        return None

    def severity_for(self, doc: dict[str, Any], control: dict[str, Any] | None) -> str:
        return (
            doc.get("severity")
            or (control or {}).get("severity")
            or self.severity_defaults.get(str(doc.get("source")), "Medium")
        )


def load_crosswalk(reader: EvidenceReader, qlog: QueryLog, version: str) -> Crosswalk:
    rows = qlog.run(
        reader,
        "mappings",
        Q_CROSSWALK,
        [{"name": "@id", "value": f"crosswalk-{version}"}],
        CROSSWALK_FRAMEWORK_ID,
    )
    if not rows:
        raise CrosswalkError(f"crosswalk version {version} named by the run manifest is not in the store")
    return Crosswalk(rows[0]["mapping"], version)


# --------------------------------------------------------------------------- history


def first_seen(reader: EvidenceReader, qlog: QueryLog, keys: list[str], batch: int = 100) -> dict[str, str]:
    """Earliest stored observation of each finding failing. Uses history in
    ``snapshots``; history began when this collector was deployed, which the
    POA&M states rather than hides."""
    earliest: dict[str, str] = {}
    for i in range(0, len(keys), batch):
        chunk = keys[i : i + batch]
        for row in qlog.run(reader, "snapshots", Q_FIRST_SEEN, [{"name": "@keys", "value": chunk}]):
            k, ts = row["findingKey"], row["collectedAt"]
            if k not in earliest or _parse_ts(ts) < _parse_ts(earliest[k]):
                earliest[k] = ts
    return earliest


# --------------------------------------------------------------------------- POA&M


def _resource_group(resource_id: str) -> str | None:
    parts = resource_id.split("/")
    lowered = [p.lower() for p in parts]
    if "resourcegroups" in lowered:
        idx = lowered.index("resourcegroups")
        return parts[idx + 1] if idx + 1 < len(parts) else None
    return None


def build_poam(
    run: dict[str, Any],
    snapshots: list[dict[str, Any]],
    crosswalk: Crosswalk,
    seen: dict[str, str],
    now: datetime,
) -> dict[str, Any]:
    items = []
    for doc in snapshots:
        if doc.get("result") not in OPEN_RESULTS:
            continue
        control = crosswalk.resolve(doc)
        severity = crosswalk.severity_for(doc, control)
        detected = seen.get(doc["findingKey"], doc["collectedAt"])
        due = _parse_ts(detected).date() + timedelta(days=crosswalk.sla_days.get(severity, 90))
        items.append(
            {
                # Stable across days: the same finding keeps the same POA&M id until it closes.
                "poamId": f"POAM-{doc['findingKey'][:10].upper()}",
                "weakness": (control or {}).get("title") or doc.get("displayName"),
                "sourceFinding": doc.get("displayName"),
                "source": doc.get("source"),
                "controlKey": (control or {}).get("controlKey", "unmapped"),
                "frameworks": (control or {}).get("mappings", {}),
                "resourceId": doc.get("resourceId"),
                "resourceGroup": _resource_group(str(doc.get("resourceId", ""))),
                "severity": severity,
                "firstSeen": detected,
                "scheduledCompletion": due.isoformat(),
                "overdue": due < now.date(),
                "status": "Open",
                "evidence": {"snapshotId": doc["id"], "runId": doc["runId"], "findingKey": doc["findingKey"]},
            }
        )

    sev_rank = {"High": 0, "Medium": 1, "Low": 2}
    items.sort(key=lambda x: (sev_rank.get(x["severity"], 3), x["scheduledCompletion"], x["poamId"]))
    return {
        "items": items,
        "summary": {
            "open": len(items),
            "overdue": sum(1 for i in items if i["overdue"]),
            "bySeverity": dict(Counter(i["severity"] for i in items)),
            "unmapped": sum(1 for i in items if i["controlKey"] == "unmapped"),
            "historyNote": "firstSeen is the earliest stored failing observation; evidence history starts at the first snapshot run.",
        },
    }


def render_poam_xlsx(poam: dict[str, Any], lineage: dict[str, Any]) -> bytes:
    from openpyxl import Workbook  # imported lazily so tests of the core stay light

    wb = Workbook()
    ws = wb.active
    ws.title = "POA&M"
    headers = [
        "POA&M ID", "Weakness", "Severity", "Resource", "Resource Group", "Source",
        "Control Key", "NIST CSF 2.0", "PCI DSS 4.0.1", "GLBA", "First Seen",
        "Scheduled Completion", "Overdue", "Status", "Snapshot ID",
    ]
    ws.append(headers)
    for i in poam["items"]:
        fw = i["frameworks"]
        ws.append(
            [
                i["poamId"], i["weakness"], i["severity"], i["resourceId"], i["resourceGroup"], i["source"],
                i["controlKey"], ", ".join(fw.get("nist_csf_2", [])), ", ".join(fw.get("pci_dss_4_0_1", [])),
                ", ".join(fw.get("glba_safeguards", [])), i["firstSeen"], i["scheduledCompletion"],
                "YES" if i["overdue"] else "", i["status"], i["evidence"]["snapshotId"],
            ]
        )
    meta = wb.create_sheet("Lineage")
    for k in ("reportExecutionId", "generatedAt", "runId", "runCompletedAt", "documentSetSha256",
              "digestVerified", "crosswalkVersion", "generatorVersion"):
        meta.append([k, str(lineage.get(k))])
    meta.append([])
    meta.append(["Queries (re-run these against Cosmos to reproduce every number):"])
    for q in lineage.get("queries", []):
        meta.append([q["container"], q["query"], json.dumps(q["parameters"])])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# --------------------------------------------------------------------------- SAR + scorecard


def build_scorecard(
    snapshots: list[dict[str, Any]],
    previous: list[dict[str, Any]] | None,
    crosswalk: Crosswalk,
) -> dict[str, Any]:
    """Per framework requirement: how many mapped findings pass/fail in this run.
    Plus what changed since the previous completed run."""
    req: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    by_source: dict[str, Counter] = defaultdict(Counter)
    unmapped_open = 0
    for doc in snapshots:
        result = doc.get("result", "unknown")
        by_source[str(doc.get("source"))][result] += 1
        control = crosswalk.resolve(doc)
        if control is None:
            if result in OPEN_RESULTS:
                unmapped_open += 1
            continue
        for fw, reqs in control.get("mappings", {}).items():
            for r in reqs:
                req[fw][r][result] += 1

    frameworks = {}
    for fw, meta in crosswalk.frameworks.items():
        rows = []
        for r in sorted(req.get(fw, {})):
            c = req[fw][r]
            rows.append({"requirement": r, "pass": c["pass"], "fail": c["fail"], "notApplicable": c["not_applicable"]})
        failing = sum(1 for row in rows if row["fail"])
        frameworks[fw] = {
            "name": meta.get("name", fw),
            "requirementsWithEvidence": len(rows),
            "requirementsFailing": failing,
            "requirements": rows,
        }

    delta = None
    if previous is not None:
        prev_result = {d["findingKey"]: d.get("result") for d in previous}
        cur_result = {d["findingKey"]: d.get("result") for d in snapshots}
        delta = {
            "newlyFailing": sorted(k for k, v in cur_result.items() if v == "fail" and prev_result.get(k) != "fail"),
            # Only an explicit pass counts as fixed. A finding that merely disappeared is
            # reported separately: absence of a finding is weaker evidence than a pass.
            "fixed": sorted(k for k, v in cur_result.items() if v == "pass" and prev_result.get(k) == "fail"),
            "noLongerObserved": sorted(k for k in prev_result if k not in cur_result),
        }
    return {
        "bySource": {s: dict(c) for s, c in by_source.items()},
        "frameworks": frameworks,
        "unmappedOpenFindings": unmapped_open,
        "deltaFromPreviousRun": delta,
    }


def render_sar_markdown(scorecard: dict[str, Any], poam: dict[str, Any], lineage: dict[str, Any]) -> str:
    s = poam["summary"]
    lines = [
        "# Tallyfin Security Assessment Report (SAR)",
        "",
        f"- **Report execution:** `{lineage['reportExecutionId']}` at {lineage['generatedAt']}",
        f"- **Evidence run:** `{lineage['runId']}` (completed {lineage['runCompletedAt']}, digest verified: {lineage['digestVerified']})",
        f"- **Crosswalk version:** `{lineage['crosswalkVersion']}`",
        f"- **Open findings:** {s['open']} ({s['overdue']} overdue) - by severity: "
        + (", ".join(f"{k} {v}" for k, v in sorted(s["bySeverity"].items())) or "none"),
        f"- **Unmapped open findings:** {scorecard['unmappedOpenFindings']} (gaps in the crosswalk, listed in the POA&M as controlKey=unmapped)",
        "",
        "## Results by evidence source",
        "",
        "| Source | pass | fail | not applicable | unknown |",
        "|---|---|---|---|---|",
    ]
    for src, c in sorted(scorecard["bySource"].items()):
        lines.append(f"| {src} | {c.get('pass', 0)} | {c.get('fail', 0)} | {c.get('not_applicable', 0)} | {c.get('unknown', 0)} |")
    lines += ["", "## Framework scorecard (collect once, map many)", ""]
    for fw in scorecard["frameworks"].values():
        lines.append(
            f"### {fw['name']} - {fw['requirementsWithEvidence']} requirements with evidence, {fw['requirementsFailing']} failing"
        )
        lines.append("")
        if fw["requirements"]:
            lines += ["| Requirement | pass | fail | n/a |", "|---|---|---|---|"]
            lines += [f"| {r['requirement']} | {r['pass']} | {r['fail']} | {r['notApplicable']} |" for r in fw["requirements"]]
        else:
            lines.append("_No stored evidence maps to this framework in this run._")
        lines.append("")
    d = scorecard["deltaFromPreviousRun"]
    lines += ["## Change since previous completed run", ""]
    if d is None:
        lines.append("_No previous completed run in the store._")
    else:
        lines += [
            f"- Newly failing: {len(d['newlyFailing'])}",
            f"- Fixed (explicit fail -> pass): {len(d['fixed'])}",
            f"- No longer observed (not counted as fixed): {len(d['noLongerObserved'])}",
        ]
    lines += [
        "",
        "## Reproduce these numbers",
        "",
        "Every figure above comes from these stored queries (see manifest.json in this folder):",
        "",
    ]
    lines += [f"- `{q['container']}`: `{q['query']}`" for q in lineage["queries"]]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- publishing


def publish(
    writer: ReportWriter,
    report: str,
    artifacts: dict[str, tuple[bytes, str]],
    lineage: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Write every artifact into one execution folder, then manifest.json LAST.

    WORM makes each blob immutable; the manifest makes the SET verifiable.
    If an upload fails midway the folder has no manifest and is, by contract,
    an incomplete execution. Nothing is overwritten (overwrite=False) and
    nothing is deleted (the reporter's role cannot delete).
    """
    folder = f"{report}/{now:%Y/%m/%d}/{now:%Y%m%dT%H%M%SZ}-{lineage['reportExecutionId']}"
    files = {}
    for name, (data, ctype) in artifacts.items():
        path = f"{folder}/{name}"
        writer.upload(path, data, ctype)
        files[name] = {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    manifest = {"report": report, "folder": folder, "files": files, **lineage}
    writer.upload(
        f"{folder}/manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True).encode(),
        "application/json",
    )
    LOG.info("%s published to %s (%d files + manifest)", report, folder, len(files))
    return manifest


def _lineage(run: dict[str, Any], digest_ok: bool, crosswalk: Crosswalk, qlog: QueryLog, now: datetime, version: str) -> dict[str, Any]:
    return {
        "reportExecutionId": str(uuid.uuid4()),
        "generatedAt": now.isoformat(),
        "generatorVersion": f"{GENERATOR_VERSION}+{version}",
        "runId": run["runId"],
        "runCompletedAt": run["completedAt"],
        "runTrigger": run.get("trigger"),
        "documentSetSha256": run.get("documentSetSha256"),
        "contentSetSha256": run.get("contentSetSha256"),
        "digestVerified": digest_ok,
        "crosswalkVersion": crosswalk.version,
        "queries": qlog.entries,
    }


def generate_poam(
    reader: EvidenceReader, writer: ReportWriter, *, now: datetime | None = None,
    max_age_hours: float = 13, app_version: str = "dev",
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    qlog = QueryLog()
    run = latest_completed_run(reader, qlog, now, max_age_hours)
    snaps = load_snapshots(reader, qlog, run["runId"])
    digest_ok = require_sealed_run(run, snaps)
    xwalk = load_crosswalk(reader, qlog, run["crosswalkVersion"])
    open_keys = sorted({d["findingKey"] for d in snaps if d.get("result") in OPEN_RESULTS})
    seen = first_seen(reader, qlog, open_keys)
    poam = build_poam(run, snaps, xwalk, seen, now)
    lineage = _lineage(run, digest_ok, xwalk, qlog, now, app_version)
    body = {"lineage": lineage, **poam}
    return publish(
        writer,
        "poam",
        {
            "poam.json": (json.dumps(body, indent=2, sort_keys=True).encode(), "application/json"),
            "poam.xlsx": (
                render_poam_xlsx(poam, lineage),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
        },
        lineage,
        now,
    )


def generate_sar(
    reader: EvidenceReader, writer: ReportWriter, *, now: datetime | None = None,
    max_age_hours: float = 13, app_version: str = "dev",
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    qlog = QueryLog()
    run = latest_completed_run(reader, qlog, now, max_age_hours)
    snaps = load_snapshots(reader, qlog, run["runId"])
    digest_ok = require_sealed_run(run, snaps)
    xwalk = load_crosswalk(reader, qlog, run["crosswalkVersion"])
    prev_run = previous_completed_run(reader, qlog, run)
    prev_snaps = load_snapshots(reader, qlog, prev_run["runId"]) if prev_run else None
    open_keys = sorted({d["findingKey"] for d in snaps if d.get("result") in OPEN_RESULTS})
    seen = first_seen(reader, qlog, open_keys)
    poam = build_poam(run, snaps, xwalk, seen, now)
    scorecard = build_scorecard(snaps, prev_snaps, xwalk)
    lineage = _lineage(run, digest_ok, xwalk, qlog, now, app_version)
    lineage["previousRunId"] = prev_run["runId"] if prev_run else None
    return publish(
        writer,
        "sar",
        {
            "sar.md": (render_sar_markdown(scorecard, poam, lineage).encode(), "text/markdown"),
            "scorecard.json": (
                json.dumps({"lineage": lineage, **scorecard}, indent=2, sort_keys=True).encode(),
                "application/json",
            ),
        },
        lineage,
        now,
    )


# --------------------------------------------------------------------------- Azure adapters


class CosmosEvidenceReader:
    """Read-only Cosmos adapter (the reporter holds the built-in Data Reader role)."""

    def __init__(self, endpoint: str, database: str, credential: Any) -> None:
        from azure.cosmos import CosmosClient

        self._db = CosmosClient(endpoint, credential=credential).get_database_client(database)

    def query(self, container, query, parameters=None, partition_key=None):  # type: ignore[no-untyped-def]
        client = self._db.get_container_client(container)
        kwargs: dict[str, Any] = {"query": query, "parameters": parameters or []}
        if partition_key is not None:
            kwargs["partition_key"] = partition_key
        else:
            kwargs["enable_cross_partition_query"] = True
        return list(client.query_items(**kwargs))


class BlobReportWriter:
    """Create-only blob writer. overwrite=False is belt; WORM is braces."""

    def __init__(self, account_url: str, container: str, credential: Any) -> None:
        from azure.storage.blob import BlobServiceClient

        self._container = BlobServiceClient(account_url=account_url, credential=credential).get_container_client(container)

    def upload(self, path: str, data: bytes, content_type: str) -> None:
        from azure.storage.blob import ContentSettings

        self._container.upload_blob(
            path, data, overwrite=False, content_settings=ContentSettings(content_type=content_type)
        )


def today_utc() -> date:
    return datetime.now(timezone.utc).date()
