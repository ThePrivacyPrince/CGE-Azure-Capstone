"""scripts/verify_submission.py is the grader's cross-check, run before the grader. Build a
complete synthetic bundle from the in-memory pipeline, prove the verifier passes it, then
prove it catches each kind of gap a reviewer would find."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from datetime import timedelta
from pathlib import Path

import pytest

import reports_core as rc
from conftest import MG, ROOT, MemoryReader, MemoryStore, MemoryWriter
from test_reports import T0, collect

STAGES = ["01-foundation", "02-activation", "03-evidence-store", "04-reporting", "06-enforcement", "07-detection"]
MGP = f"/providers/Microsoft.Management/managementGroups/{MG}"


def verifier():
    spec = importlib.util.spec_from_file_location("verify_submission", ROOT / "scripts" / "verify_submission.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def put(base: Path, rel: str, obj) -> None:
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(obj if isinstance(obj, bytes) else json.dumps(obj, indent=2).encode())


def manifest(base: Path) -> None:
    files = {str(p.relative_to(base)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(base.rglob("*")) if p.is_file() and p.name != "MANIFEST.json"}
    put(base, "MANIFEST.json", {"files": files})


@pytest.fixture()
def bundle(tmp_path, crosswalk) -> Path:
    v = verifier()
    store = MemoryStore()
    collect(store, crosswalk, "Unhealthy", T0)
    m = collect(store, crosswalk, "Unhealthy", T0 + timedelta(hours=6))
    writer = MemoryWriter()
    now = T0 + timedelta(hours=7)
    rc.generate_poam(MemoryReader(store), writer, now=now)
    rc.generate_sar(MemoryReader(store), writer, now=now)
    for path, data in writer.blobs.items():
        put(tmp_path, f"reports/{path}", data)
    put(tmp_path, f"evidence/findings-{m['runId']}.json", [d for d in store.all("findings") if d["runId"] == m["runId"]])
    put(tmp_path, f"evidence/rbac-{m['runId']}.json", [d for d in store.all("rbac") if d["runId"] == m["runId"]])
    put(tmp_path, "plans/summary.json", {s: {"exitCode": 0, "meaning": "no changes", "pendingChanges": []} for s in STAGES})

    names = sorted(v.code_policy_names())
    corrective = [n for n in names if "-fix-" in n]
    put(tmp_path, "policy/custom-definitions.json", [{"name": n} for n in names])
    put(tmp_path, "policy/custom-initiatives.json", [{"name": "cge-grc-baseline", "policyDefinitions": [
        {"policyDefinitionId": f"{MGP}/providers/Microsoft.Authorization/policyDefinitions/{n}"} for n in names if n not in corrective]}])
    put(tmp_path, "policy/assignments.json", [
        {"scope": MGP, "policyDefinitionId": f"{MGP}/providers/Microsoft.Authorization/policySetDefinitions/cge-grc-baseline"},
        *({"scope": MGP, "policyDefinitionId": f"{MGP}/providers/Microsoft.Authorization/policyDefinitions/{n}"} for n in corrective),
    ])
    put(tmp_path, "identities/summary.json", {
        "remediation": {"roles": [f"Monitoring Contributor @ {MGP}", f"fafo-storage-baseline-remediator @ {MGP}"], "cosmosDataPlane": []},
        "collector": {"roles": [f"Security Reader @ {MGP}", f"fafo-grc-policy-state-reader @ {MGP}"], "cosmosDataPlane": [v.COSMOS_CONTRIBUTOR]},
        "reporter": {"roles": ["fafo-grc-report-writer @ /subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/e/blobServices/default/containers/reports"],
                     "cosmosDataPlane": [v.COSMOS_READER]},
    })
    put(tmp_path, "worm/delete-attempt.json", {"blob": "poam/x/manifest.json",
        "delete": {"exitCode": 1, "stderr": "ErrorCode: BlobImmutableDueToPolicy"},
        "overwrite": {"exitCode": 1, "stderr": "This operation is not permitted as the blob is immutable due to a policy."}})
    put(tmp_path, "worm/immutability-policy.json", {"immutabilityPeriodSinceCreationInDays": 90, "state": "Unlocked"})
    put(tmp_path, "worm/storage-blob-logs.json", {"rows": [{"OperationName": "DeleteBlob", "StatusCode": 409}]})
    put(tmp_path, "storage/shared-key-status.json", {
        "evidenceResourceGroup": [{"name": "stgrcevidabc", "allowSharedKeyAccess": False}, {"name": "stgrcfuncabc", "allowSharedKeyAccess": True}],
        "stateResourceGroup": [{"name": "stgrctfstate1234", "allowSharedKeyAccess": False}]})
    put(tmp_path, "run-history/run-history.json", {"runs": [{"trigger": "timer"}] * 80, "cadence": {
        "timerRuns": 80, "firstTimerRun": "2026-09-20T00:00:00+00:00", "lastTimerRun": "2026-10-10T00:00:00+00:00",
        "spanDays": 20.0, "expectedGapHours": 6, "maxGapHours": 6.0, "gapsOverOneAndAHalfIntervals": 0}})
    for name in ("ssp.json", "fafo-moderate-profile.json"):
        put(tmp_path, f"oscal/{name}", (ROOT / "oscal" / name).read_bytes())
    manifest(tmp_path)
    return tmp_path


def run_verifier(path: Path):
    v = verifier()
    code = v.main(["--dir", str(path)])
    return code, [r for r in v.results if r[0] == "FAIL"]


def test_a_coherent_bundle_passes(bundle):
    code, failures = run_verifier(bundle)
    assert code == 0, failures


def test_tampered_finding_is_caught(bundle):
    f = next(bundle.glob("evidence/findings-*.json"))
    docs = json.loads(f.read_text())
    next(d for d in docs if d["result"] == "fail")["result"] = "pass"
    f.write_text(json.dumps(docs))
    code, failures = run_verifier(bundle)
    assert code == 1 and any("seal" in msg or "open items" in msg for _, _, msg in failures)


def test_dirty_plan_is_caught(bundle):
    summary = json.loads((bundle / "plans/summary.json").read_text())
    summary["06-enforcement"] = {"exitCode": 2, "meaning": "changes pending", "pendingChanges": [{"address": "x", "actions": ["update"]}]}
    (bundle / "plans/summary.json").write_text(json.dumps(summary))
    code, failures = run_verifier(bundle)
    assert code == 1 and any(area == "plans" for _, area, _ in failures)


def test_policy_in_code_but_not_assigned_is_caught(bundle):
    assigns = json.loads((bundle / "policy/assignments.json").read_text())
    (bundle / "policy/assignments.json").write_text(json.dumps([a for a in assigns if "fafo-fix-min-tls" not in a["policyDefinitionId"]]))
    code, failures = run_verifier(bundle)
    assert code == 1 and any("NOT assigned" in msg for _, _, msg in failures)


def test_broad_role_on_an_identity_is_caught(bundle):
    ids = json.loads((bundle / "identities/summary.json").read_text())
    ids["collector"]["roles"].append(f"Contributor @ {MGP}")
    (bundle / "identities/summary.json").write_text(json.dumps(ids))
    code, failures = run_verifier(bundle)
    assert code == 1 and any("HOLDS" in msg for _, _, msg in failures)


def test_worm_delete_that_succeeded_is_caught(bundle):
    a = json.loads((bundle / "worm/delete-attempt.json").read_text())
    a["delete"] = {"exitCode": 0, "stderr": ""}
    (bundle / "worm/delete-attempt.json").write_text(json.dumps(a))
    code, failures = run_verifier(bundle)
    assert code == 1 and any(area == "worm" for _, area, _ in failures)


def test_report_file_changed_after_export_is_caught(bundle):
    poam = next(bundle.glob("reports/poam/**/poam.json"))
    poam.write_text(poam.read_text().replace('"open"', '"open" ', 1))
    code, failures = run_verifier(bundle)
    assert code == 1 and any("SHA-256" in msg or "MANIFEST" in msg for _, _, msg in failures)
