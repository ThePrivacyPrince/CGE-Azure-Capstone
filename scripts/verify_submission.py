#!/usr/bin/env python3
"""Cross-check submission/ against the code, the way the grader does. Offline: no Azure.

The grader reads what the code claims, then looks in the evidence bundle for proof. A gap
between the two is itself the finding ("the code declares nine custom policies, the evidence
shows eight assigned"). This script runs those cross-checks before the grader does:

  1. plans        every stage's exported plan says "no changes" (the repo IS the estate)
  2. policy       every custom policy in stages/ is deployed AND assigned at the MG
  3. identities   no pipeline identity holds a broad role; each holds only its job
  4. integrity    every report file matches its manifest SHA-256; every number recomputes
                  from the exported documents of the run it names; both seals verify
  5. worm         the delete and the overwrite were refused
  6. storage      shared-key access is off on the evidence and state accounts
  7. run history  timer runs accumulate over days at the declared cadence
  8. bundle       MANIFEST.json hashes match; OSCAL copies match the repo

    python3 scripts/verify_submission.py        # exit 1 if any check FAILs
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SUB = ROOT / "submission"
BROAD = {"Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"}
EXPECTED_ROLES = {
    "remediation": {"Monitoring Contributor", "fafo-storage-baseline-remediator"},
    "collector": {"Security Reader", "fafo-grc-policy-state-reader"},
    "reporter": {"fafo-grc-report-writer"},
    "ci-planner": {"fafo-grc-ci-planner", "Storage Blob Data Reader"},
}
COSMOS_READER, COSMOS_CONTRIBUTOR = "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"

results: list[tuple[str, str, str]] = []


def check(area: str, ok: bool | None, message: str) -> None:
    """ok: True = PASS, False = FAIL, None = WARN."""
    results.append(({True: "PASS", False: "FAIL", None: "WARN"}[ok], area, message))


def load(rel: str) -> Any:
    path = SUB / rel
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def content_sha256(doc: dict[str, Any]) -> str:
    body = {k: v for k, v in doc.items() if not k.startswith("_")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def seal(docs: list[dict[str, Any]]) -> tuple[str, str]:
    ids = sorted(d["id"] for d in docs)
    by_id = {d["id"]: d for d in docs}
    content = "\n".join(f"{i} {content_sha256(by_id[i])}" for i in ids)
    return hashlib.sha256("\n".join(ids).encode()).hexdigest(), hashlib.sha256(content.encode()).hexdigest()


# --------------------------------------------------------------------------- checks


def check_plans() -> None:
    summary = load("plans/summary.json")
    if summary is None:
        return check("plans", False, "plans/summary.json missing (export_submission.py --only plans)")
    for stage, s in sorted(summary.items()):
        detail = ", ".join(f"{c['address']} {'/'.join(c['actions'])}" for c in s.get("pendingChanges", [])[:5])
        check("plans", s["exitCode"] == 0, f"{stage}: {s['meaning']}" + (f" ({detail})" if detail else ""))


def code_policy_names() -> set[str]:
    names, roles = set(), set()
    for tf in (ROOT / "stages").rglob("*.tf"):
        text = tf.read_text()
        names |= set(re.findall(r'name\s*=\s*"((?:cge|fafo)-[a-z0-9-]+)"', text))
        roles |= set(re.findall(r'resource "azurerm_role_definition" "\w+" \{\s*name\s*=\s*"([^"]+)"', text))
    return {n for n in names - roles if n != "cge-grc-baseline"}


def check_policy() -> None:
    defs, sets, assigns = load("policy/custom-definitions.json"), load("policy/custom-initiatives.json"), load("policy/assignments.json")
    if defs is None or assigns is None:
        return check("policy", False, "policy exports missing (export_submission.py --only policy)")
    code = code_policy_names()
    deployed = {d["name"] for d in defs}
    missing = sorted(code - deployed)
    check("policy", not missing, f"{len(code)} custom policies in code, {len(code & deployed)} deployed" + (f"; NOT deployed: {missing}" if missing else ""))
    assigned_sets = {a["policyDefinitionId"].rsplit("/", 1)[-1] for a in assigns}
    in_assigned_set = {m for s in sets or [] if s["name"] in assigned_sets for m in
                       (ref["policyDefinitionId"].rsplit("/", 1)[-1] for ref in s.get("policyDefinitions", []))}
    unassigned = sorted(n for n in code if n not in in_assigned_set and n not in assigned_sets)
    check("policy", not unassigned, "every custom policy is assigned (directly or through the initiative)"
          + (f"; NOT assigned: {unassigned}" if unassigned else ""))
    mg_scoped = all("/managementGroups/" in a.get("scope", "") for a in assigns)
    check("policy", mg_scoped, "every exported assignment is at management-group scope")


def check_identities() -> None:
    summary = load("identities/summary.json")
    if summary is None:
        return check("identities", False, "identities/summary.json missing")
    for name, s in sorted(summary.items()):
        roles = {r.split(" @ ")[0] for r in s.get("roles", [])}
        broad = sorted(roles & BROAD)
        check("identities", not broad, f"{name}: no broad role" + (f" - HOLDS {broad}" if broad else ""))
        extra = sorted(roles - EXPECTED_ROLES.get(name, roles))
        check("identities", not extra, f"{name}: roles are its job only ({', '.join(sorted(roles)) or 'none'})"
              + (f"; unexpected: {extra}" if extra else ""))
    if "collector" in summary and "reporter" in summary:
        check("identities", COSMOS_CONTRIBUTOR in summary["collector"].get("cosmosDataPlane", []) and
              COSMOS_CONTRIBUTOR not in summary["reporter"].get("cosmosDataPlane", []) and
              COSMOS_READER in summary["reporter"].get("cosmosDataPlane", []),
              "segregation of duties: collector writes evidence, reporter only reads it")
        reporter_arm = [r for r in summary["reporter"].get("roles", []) if "/containers/reports" not in r]
        check("identities", not reporter_arm, "reporter holds no ARM role outside the reports container")


def check_integrity() -> None:
    manifests = sorted((SUB / "reports").rglob("manifest.json")) if (SUB / "reports").exists() else []
    if not manifests:
        return check("integrity", False, "no report manifests under submission/reports/")
    for mpath in manifests:
        m = json.loads(mpath.read_text())
        folder = mpath.parent
        for name, meta in m["files"].items():
            data = (folder / name).read_bytes() if (folder / name).exists() else b""
            check("integrity", hashlib.sha256(data).hexdigest() == meta["sha256"], f"{m['report']}: {name} matches its manifest SHA-256")
        findings = load(f"evidence/findings-{m['runId']}.json")
        if findings is None:
            check("integrity", False, f"{m['report']}: evidence/findings-{m['runId']}.json missing")
            continue
        ids_sha, content_sha = seal(findings)
        check("integrity", ids_sha == m["documentSetSha256"] and content_sha == (m.get("contentSetSha256") or content_sha),
              f"{m['report']}: run {m['runId'][:8]} findings seal recomputes from {len(findings)} exported documents")
        failing = [d for d in findings if d.get("result") == "fail"]
        if m["report"] == "poam":
            poam = json.loads((folder / "poam.json").read_text())
            check("integrity", poam["summary"]["open"] == len(failing),
                  f"poam: {poam['summary']['open']} open items = {len(failing)} failing documents in the run")
            if (folder / "poam.oscal.json").exists():
                oscal = json.loads((folder / "poam.oscal.json").read_text())["plan-of-action-and-milestones"]
                n = len(oscal["poam-items"]) if failing else 0
                check("integrity", n == len(failing), f"poam.oscal.json: {n} poam-items = {len(failing)} failing documents")
        if m["report"] == "sar":
            card = json.loads((folder / "scorecard.json").read_text())
            recount: dict[str, Counter] = {}
            for d in findings:
                recount.setdefault(str(d.get("source")), Counter())[d.get("result", "unknown")] += 1
            same = all(dict(recount.get(src, {})) == {k: v for k, v in counts.items() if v} for src, counts in card["bySource"].items())
            check("integrity", same, "sar: results by source recount exactly from the exported findings")
            rbac = load(f"evidence/rbac-{m['runId']}.json")
            pa = card.get("privilegedAccess")
            if rbac is not None and pa is not None:
                r_ids, r_content = seal(rbac)
                rseal = (m.get("containerSeals") or {}).get("rbac") or {}
                check("integrity", r_ids == rseal.get("documentSetSha256") and r_content == rseal.get("contentSetSha256"),
                      f"sar: rbac seal recomputes from {len(rbac)} exported snapshots")
                owners = sum(1 for d in rbac if d.get("roleName") == "Owner" and d.get("scopeLevel") == "subscription")
                check("integrity", pa["totals"]["subscriptionOwners"] == owners and pa["totals"]["privileged"] == sum(1 for d in rbac if d.get("privileged")),
                      f"sar: privileged access ({pa['totals']['privileged']} privileged, {owners} subscription Owners) recounts from snapshots")


def check_worm() -> None:
    attempt, policy = load("worm/delete-attempt.json"), load("worm/immutability-policy.json")
    if attempt is None:
        return check("worm", False, "worm/delete-attempt.json missing (export_submission.py --only worm)")
    check("worm", attempt["delete"]["exitCode"] != 0, f"delete of {attempt['blob']} was refused")
    check("worm", attempt["overwrite"]["exitCode"] != 0, "overwrite was refused")
    check("worm", "immutab" in (attempt["delete"]["stderr"] + attempt["overwrite"]["stderr"]).lower() or None,
          "refusal names the immutability policy")
    if policy:
        check("worm", int(policy.get("immutabilityPeriodSinceCreationInDays", 0)) >= 1,
              f"immutability policy: {policy.get('immutabilityPeriodSinceCreationInDays')} days, state {policy.get('state')}")
    check("worm", (SUB / "worm" / "storage-blob-logs.json").exists() or None, "the refused attempts appear in StorageBlobLogs (--only worm-logs)")


def check_storage() -> None:
    s = load("storage/shared-key-status.json")
    if s is None:
        return check("storage", False, "storage/shared-key-status.json missing")
    for acct in s["evidenceResourceGroup"] + s["stateResourceGroup"]:
        runtime = acct["name"].startswith(("stgrcfunc", "stgrcrpt"))
        off = acct.get("allowSharedKeyAccess") is False
        if runtime:
            check("storage", None if not off else True, f"{acct['name']}: Y1 runtime account, shared key {'off' if off else 'on (RISK-0001, excepted)'}")
        else:
            check("storage", off, f"{acct['name']}: shared-key access disabled")


def check_run_history() -> None:
    h = load("run-history/run-history.json")
    if h is None:
        return check("run history", False, "run-history/run-history.json missing")
    c = h["cadence"]
    check("run history", c["timerRuns"] > 0, f"{c['timerRuns']} timer runs from {c['firstTimerRun']} to {c['lastTimerRun']}")
    check("run history", True if c["spanDays"] >= 14 else (None if c["spanDays"] >= 3 else False),
          f"history spans {c['spanDays']} days (weeks is the target)")
    check("run history", True if not c["gapsOverOneAndAHalfIntervals"] else None,
          f"longest gap between timer runs {c['maxGapHours']} h (expected {c['expectedGapHours']} h)")
    manual = sum(1 for r in h["runs"] if r.get("trigger") == "manual")
    check("run history", manual <= max(1, len(h["runs"]) // 10) or None, f"{manual} manual runs of {len(h['runs'])}")


def check_bundle() -> None:
    m = load("MANIFEST.json")
    if m is None:
        return check("bundle", False, "MANIFEST.json missing")
    bad = [f for f, sha in m["files"].items() if not (SUB / f).exists() or hashlib.sha256((SUB / f).read_bytes()).hexdigest() != sha]
    check("bundle", not bad, f"{len(m['files'])} files match MANIFEST.json" + (f"; changed since export: {bad[:5]}" if bad else ""))
    for name in ("ssp.json", "fafo-moderate-profile.json"):
        same = (SUB / "oscal" / name).exists() and (SUB / "oscal" / name).read_bytes() == (ROOT / "oscal" / name).read_bytes()
        check("bundle", same, f"oscal/{name} matches the repository")
    check("bundle", not (SUB / "errors").exists() or not any((SUB / "errors").iterdir()), "no export section recorded an error")


def main(argv: list[str] | None = None) -> int:
    import argparse

    global SUB
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, default=SUB, help="bundle directory (default: submission/)")
    SUB = parser.parse_args(argv).dir
    results.clear()
    if not SUB.exists():
        print("submission/ missing: run python3 scripts/export_submission.py", file=sys.stderr)
        return 2
    for fn in (check_plans, check_policy, check_identities, check_integrity, check_worm, check_storage, check_run_history, check_bundle):
        fn()
    width = max(len(a) for _, a, _ in results)
    for status, area, message in results:
        print(f"{status}  {area:<{width}}  {message}")
    counts = Counter(s for s, _, _ in results)
    print(f"\n{counts['PASS']} passed, {counts['WARN']} warnings, {counts['FAIL']} failed")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
