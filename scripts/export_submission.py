#!/usr/bin/env python3
"""Build submission/: the machine-readable evidence package the grader reads.

The grader cannot log into your subscription, so the submission has to prove itself. This
script exports, from the live environment, everything a reviewer needs to cross-check the
code against what is actually deployed:

    plans/        terraform plan per stage (expect "No changes"), text + action summary
    identities/   role assignments of every pipeline identity (ARM + Cosmos data plane)
    policy/       custom definitions, initiatives, assignments, compliance summary at the MG
    evidence/     run manifests; the findings + rbac documents of the run the reports used
    reports/      the latest POA&M and SAR execution folders, byte-for-byte from WORM
    worm/         immutability policy, a refused delete, a refused overwrite, the log lines
    storage/      shared-key status of every storage account in scope (+ the state account)
    run-history/  run-history.json + timer cadence (scripts/export_run_history.py)
    oscal/        the SSP and tailored profile
    MANIFEST.json SHA-256 of every file, the git commit, and when it was exported

Then run `python3 scripts/verify_submission.py` (offline) to cross-check the bundle the way
the grader does, and commit submission/.

Prerequisites: `az login` as the operator who applied the stages (holds Cosmos and Blob data
roles from stage 03), `terraform`, labs/03-foundation/backend.hcl, and the TF_VAR_* variables
from docs/RUNBOOK.md. Nothing secret is written: Terraform's text plan redacts sensitive values,
JSON plans are reduced to addresses and actions, and every file is scrubbed for keys and the
operator's e-mail addresses before it is saved.

    python3 scripts/export_submission.py                # everything
    python3 scripts/export_submission.py --only worm    # one section (plans, identities, policy,
                                                        #   evidence, reports, worm, worm-logs,
                                                        #   storage, run-history, oscal)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "submission"
STAGES = ["01-foundation", "02-activation", "03-evidence-store", "04-reporting", "06-enforcement", "07-detection"]
BACKEND = ROOT / "labs" / "03-foundation" / "backend.hcl"

# Never let a credential or the operator's PII into a public repository.
SECRET_PATTERNS = [
    re.compile(r"(AccountKey=)[^;\"'\s]+"),
    re.compile(r"(SharedAccessSignature=|sig=)[^&;\"'\s]+"),
    re.compile(r"(\"(?:primary|secondary)_(?:access_)?key\"\s*:\s*\")[^\"]+"),
    re.compile(r"(\"(?:primary|secondary)(?:Master|Readonly)?Key\"\s*:\s*\")[^\"]+"),
]


def pii_values() -> list[str]:
    values = [os.environ.get("TF_VAR_owner_email", ""), os.environ.get("TF_VAR_alert_email", "")]
    try:
        values += json.loads(os.environ.get("TF_VAR_approved_change_callers", "[]"))
    except json.JSONDecodeError:
        pass
    return sorted({v for v in values if v and "@" in v}, key=len, reverse=True)


def scrub(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m: m.group(1) + "[REDACTED]", text)
    for value in pii_values():
        text = text.replace(value, "[REDACTED-EMAIL]")
    return text


def write(rel: str, content: Any) -> Path:
    path = OUT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    text = content if isinstance(content, str) else json.dumps(content, indent=2, sort_keys=True, default=str)
    path.write_text(scrub(text) + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
    print(f"  wrote submission/{rel}")
    return path


def run(cmd: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:4])}... exited {proc.returncode}: {proc.stderr.strip()[:500]}")
    return proc


def az(*args: str) -> Any:
    out = run(["az", *args, "-o", "json"]).stdout
    return json.loads(out) if out.strip() else None


_outputs: dict[str, dict[str, Any]] = {}


def tf_init(stage: str) -> None:
    run(["terraform", f"-chdir=stages/{stage}", "init", "-input=false", "-no-color",
         f"-backend-config={BACKEND}"], cwd=ROOT)


def outputs(stage: str) -> dict[str, Any]:
    if stage not in _outputs:
        tf_init(stage)
        raw = json.loads(run(["terraform", f"-chdir=stages/{stage}", "output", "-json"], cwd=ROOT).stdout)
        _outputs[stage] = {k: v["value"] for k, v in raw.items()}
    return _outputs[stage]


# --------------------------------------------------------------------------- sections


def export_plans() -> None:
    summary = {}
    for stage in STAGES:
        tf_init(stage)
        with tempfile.TemporaryDirectory() as tmp:
            plan_file = Path(tmp) / "tf.plan"
            proc = run(["terraform", f"-chdir=stages/{stage}", "plan", "-input=false", "-lock=false", "-no-color",
                        "-detailed-exitcode", f"-out={plan_file}"], cwd=ROOT, check=False)
            write(f"plans/{stage}.plan.txt", proc.stdout + (("\n--- stderr ---\n" + proc.stderr) if proc.stderr.strip() else ""))
            changes: list[dict[str, Any]] = []
            if plan_file.exists():
                shown = json.loads(run(["terraform", f"-chdir=stages/{stage}", "show", "-json", str(plan_file)], cwd=ROOT).stdout)
                # Addresses and actions ONLY: plan JSON carries sensitive values in clear text.
                changes = [
                    {"address": rc["address"], "actions": rc["change"]["actions"]}
                    for rc in shown.get("resource_changes", [])
                    if rc["change"]["actions"] not in (["no-op"], ["read"])
                ]
        summary[stage] = {
            "exitCode": proc.returncode,  # 0 = no changes, 2 = changes (drift), 1 = error
            "meaning": {0: "no changes", 1: "error", 2: "changes pending"}.get(proc.returncode, "unknown"),
            "pendingChanges": changes,
        }
    write("plans/summary.json", summary)


def export_identities() -> None:
    f01, f03, f04 = outputs("01-foundation"), outputs("03-evidence-store"), outputs("04-reporting")
    ids = {
        "remediation": f01["remediation_identity_principal_id"],
        "collector": f03["collector_principal_id"],
        "reporter": f04["reporter_principal_id"],
    }
    if os.environ.get("AZURE_CLIENT_ID"):
        ids["ci-planner"] = az("ad", "sp", "show", "--id", os.environ["AZURE_CLIENT_ID"])["id"]
    summary = {}
    for name, oid in ids.items():
        assignments = az("role", "assignment", "list", "--assignee", oid, "--all", "--include-inherited")
        write(f"identities/{name}.role-assignments.json", assignments)
        summary[name] = {
            "principalId": oid,
            "roles": sorted({f"{a['roleDefinitionName']} @ {a['scope']}" for a in assignments}),
        }
    cosmos = az("cosmosdb", "sql", "role", "assignment", "list", "--account-name", f03["cosmos_account_name"],
                "--resource-group", f01["evidence_resource_group_name"])
    write("identities/cosmos-data-plane-role-assignments.json", cosmos)
    for name, oid in ids.items():
        summary.setdefault(name, {})["cosmosDataPlane"] = sorted(
            a["roleDefinitionId"].rsplit("/", 1)[-1] for a in cosmos if a.get("principalId") == oid
        )
    write("identities/summary.json", summary)


def export_policy() -> None:
    mg = outputs("01-foundation")["management_group_name"]
    scope = f"/providers/Microsoft.Management/managementGroups/{mg}"
    defs = [d for d in az("policy", "definition", "list", "--management-group", mg) if d.get("policyType") == "Custom"]
    write("policy/custom-definitions.json", defs)
    sets = [d for d in az("policy", "set-definition", "list", "--management-group", mg) if d.get("policyType") == "Custom"]
    write("policy/custom-initiatives.json", sets)
    write("policy/assignments.json", az("policy", "assignment", "list", "--scope", scope))
    write("policy/compliance-summary.json", az("policy", "state", "summarize", "--management-group", mg))


def _cosmos():
    from azure.cosmos import CosmosClient
    from azure.identity import DefaultAzureCredential

    f03 = outputs("03-evidence-store")
    return CosmosClient(f03["cosmos_endpoint"], DefaultAzureCredential()).get_database_client("grc")


def _query(db, container: str, query: str, params: list | None = None) -> list[dict[str, Any]]:
    rows = db.get_container_client(container).query_items(query, parameters=params or [], enable_cross_partition_query=True)
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]


def _latest_report_folders() -> dict[str, str]:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    acct = outputs("03-evidence-store")["evidence_storage_account"]
    container = BlobServiceClient(f"https://{acct}.blob.core.windows.net", credential=DefaultAzureCredential()).get_container_client("reports")
    folders = sorted({b.name.rsplit("/", 1)[0] for b in container.list_blobs() if b.name.endswith("/manifest.json")})
    latest: dict[str, str] = {}
    for f in folders:
        latest[f.split("/", 1)[0]] = f  # sorted by path = by date and timestamp; last wins
    return latest


def export_reports() -> None:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    acct = outputs("03-evidence-store")["evidence_storage_account"]
    container = BlobServiceClient(f"https://{acct}.blob.core.windows.net", credential=DefaultAzureCredential()).get_container_client("reports")
    latest = _latest_report_folders()
    for report, folder in sorted(latest.items()):
        for blob in container.list_blobs(name_starts_with=folder + "/"):
            data = container.download_blob(blob.name).readall()
            dest = OUT / "reports" / blob.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            # Byte-for-byte: the manifest's SHA-256s must still match. Reports hold no secrets.
            dest.write_bytes(data)
            print(f"  wrote submission/reports/{blob.name}")
    write("reports/latest.json", latest)


def export_evidence() -> None:
    db = _cosmos()
    runs = _query(db, "runs", "SELECT * FROM c WHERE c.type = 'run-manifest'")
    runs.sort(key=lambda r: r["startedAt"])
    write("evidence/runs.json", runs)
    used = set()
    for manifest_path in (OUT / "reports").rglob("manifest.json"):
        used.add(json.loads(manifest_path.read_text())["runId"])
    if not used:
        print("  (no exported reports yet: run --only reports first; exporting the newest completed run)")
        done = [r for r in runs if r["status"] == "completed"]
        used = {done[-1]["runId"]} if done else set()
    for run_id in sorted(used):
        params = [{"name": "@r", "value": run_id}]
        write(f"evidence/findings-{run_id}.json", _query(db, "findings", "SELECT * FROM c WHERE c.runId = @r", params))
        write(f"evidence/rbac-{run_id}.json", _query(db, "rbac", "SELECT * FROM c WHERE c.runId = @r", params))


def export_worm() -> None:
    f03 = outputs("03-evidence-store")
    acct, rg = f03["evidence_storage_account"], outputs("01-foundation")["evidence_resource_group_name"]
    write("worm/immutability-policy.json", az("storage", "container", "immutability-policy", "show",
                                             "--account-name", acct, "--resource-group", rg, "--container-name", "reports"))
    latest = _latest_report_folders()
    if not latest:
        raise RuntimeError("no sealed report in the reports container yet; wait for the daily POA&M")
    target = sorted(latest.values())[-1] + "/manifest.json"
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    attempt = run(["az", "storage", "blob", "delete", "--auth-mode", "login", "--account-name", acct,
                   "-c", "reports", "-n", target], check=False)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        fh.write('{"tampered": true}\n')
    over = run(["az", "storage", "blob", "upload", "--auth-mode", "login", "--account-name", acct, "-c", "reports",
                "-n", target, "-f", fh.name, "--overwrite"], check=False)
    os.unlink(fh.name)
    write("worm/delete-attempt.json", {
        "attemptedAt": stamp, "account": acct, "container": "reports", "blob": target,
        "delete": {"exitCode": attempt.returncode, "stderr": attempt.stderr.strip()[-2000:]},
        "overwrite": {"exitCode": over.returncode, "stderr": over.stderr.strip()[-2000:]},
        "expected": "both refused (non-zero exit, BlobImmutableDueToPolicy); the blob is unchanged",
    })
    print("  storage logs take ~5-15 minutes: run `--only worm-logs` afterwards")


def export_worm_logs() -> None:
    ws_id = outputs("01-foundation")["log_analytics_workspace_id"]
    customer_id = az("monitor", "log-analytics", "workspace", "show", "--ids", ws_id)["customerId"]
    query = ("StorageBlobLogs | where TimeGenerated > ago(1d) | where OperationName in ('DeleteBlob', 'PutBlob') "
             "| where Uri has '/reports/' and StatusCode >= 400 "
             "| project TimeGenerated, OperationName, StatusCode, StatusText, AuthenticationType, Uri")
    write("worm/storage-blob-logs.json", {"query": query, "rows": az("monitor", "log-analytics", "query",
                                                                     "-w", customer_id, "--analytics-query", query)})


def export_storage() -> None:
    rg = outputs("01-foundation")["evidence_resource_group_name"]
    fields = "[].{name:name, resourceGroup:resourceGroup, allowSharedKeyAccess:allowSharedKeyAccess, allowBlobPublicAccess:allowBlobPublicAccess, minimumTlsVersion:minimumTlsVersion, enableHttpsTrafficOnly:enableHttpsTrafficOnly}"
    accounts = az("storage", "account", "list", "-g", rg, "--query", fields)
    state = az("storage", "account", "list", "-g", "rg-grc-tfstate", "--query", fields)
    write("storage/shared-key-status.json", {
        "evidenceAccount": outputs("03-evidence-store")["evidence_storage_account"],
        "evidenceResourceGroup": accounts,
        "stateResourceGroup": state,
        "note": "stgrcfunc*/stgrcrpt* are the Y1 runtime accounts that must keep a key (RISK-0001, policy/exceptions.rego).",
    })


def export_run_history() -> None:
    env = dict(os.environ, COSMOS_ENDPOINT=outputs("03-evidence-store")["cosmos_endpoint"],
               EVIDENCE_ACCOUNT=outputs("03-evidence-store")["evidence_storage_account"])
    target = OUT / "run-history" / "run-history.json"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "export_run_history.py"), "--json", str(target)], check=True, env=env)
    target.write_text(scrub(target.read_text()), encoding="utf-8")
    shutil.copy(ROOT / "docs" / "evidence" / "RUN-HISTORY.md", OUT / "run-history" / "RUN-HISTORY.md")


def export_oscal() -> None:
    (OUT / "oscal").mkdir(parents=True, exist_ok=True)
    for name in ("ssp.json", "fafo-moderate-profile.json"):
        shutil.copy(ROOT / "oscal" / name, OUT / "oscal" / name)
        print(f"  wrote submission/oscal/{name}")


SECTIONS: dict[str, Callable[[], None]] = {
    "plans": export_plans,
    "identities": export_identities,
    "policy": export_policy,
    "reports": export_reports,
    "evidence": export_evidence,  # after reports: exports the runs the reports used
    "worm": export_worm,
    "worm-logs": export_worm_logs,
    "storage": export_storage,
    "run-history": export_run_history,
    "oscal": export_oscal,
}


def write_manifest() -> None:
    shutil.copy(ROOT / "docs" / "SUBMISSION.md", OUT / "README.md")
    files = {}
    for path in sorted(OUT.rglob("*")):
        if path.is_file() and path.name != "MANIFEST.json":
            files[str(path.relative_to(OUT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    commit = run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=False).stdout.strip()
    write("MANIFEST.json", {"exportedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            "gitCommit": commit, "files": files})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", choices=sorted(SECTIONS), action="append", help="export only these sections")
    args = parser.parse_args()
    if not BACKEND.exists():
        print(f"{BACKEND} missing: run labs/03-foundation/bootstrap.sh first", file=sys.stderr)
        return 2
    failed = []
    for name in args.only or [s for s in SECTIONS if s != "worm-logs"]:
        print(f"[{name}]")
        try:
            SECTIONS[name]()
            (OUT / "errors" / f"{name}.txt").unlink(missing_ok=True)
        except Exception as exc:  # noqa: BLE001 - a failed section is recorded, not fatal
            failed.append(name)
            write(f"errors/{name}.txt", f"{type(exc).__name__}: {exc}")
    write_manifest()
    if failed:
        print(f"sections with errors: {', '.join(failed)} (see submission/errors/)", file=sys.stderr)
        return 1
    print("done. Next: python3 scripts/verify_submission.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
