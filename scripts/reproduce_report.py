#!/usr/bin/env python3
"""Re-derive a published report's numbers from the evidence store.

Every report folder ends with manifest.json listing the exact Cosmos queries (text,
parameters, partition key) that produced it and how many rows each returned. This
script re-runs them as YOU (az login; the deployer holds Cosmos data access from
stage 03) and checks the store still answers the same way, and that the run's
document-set and content digests still match what the collector sealed.

    az storage blob download --auth-mode login --account-name <evidence acct> \
        -c reports -n "<folder>/manifest.json" -f manifest.json
    COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint) \
        python3 scripts/reproduce_report.py manifest.json

Exit code 0 = reproduced; 1 = something differs (the output says what).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys


def main(path: str) -> int:
    from azure.cosmos import CosmosClient
    from azure.identity import DefaultAzureCredential

    manifest = json.load(open(path, encoding="utf-8"))
    db = CosmosClient(os.environ["COSMOS_ENDPOINT"], DefaultAzureCredential()).get_database_client(
        os.environ.get("COSMOS_DATABASE", "grc")
    )
    ok = True
    print(f"report {manifest['report']} execution {manifest['reportExecutionId']} from run {manifest['runId']}")

    for q in manifest["queries"]:
        kwargs = {"query": q["query"], "parameters": q["parameters"]}
        if q.get("partitionKey") is not None:
            kwargs["partition_key"] = q["partitionKey"]
        else:
            kwargs["enable_cross_partition_query"] = True
        rows = list(db.get_container_client(q["container"]).query_items(**kwargs))
        same = len(rows) == q["rowCount"]
        ok &= same
        # "latest run" queries legitimately change as new runs complete; flag, don't fail.
        moving = "TOP 1" in q["query"]
        status = "ok" if same else ("moved (newer runs exist)" if moving else "DIFFERS")
        if moving and not same:
            ok = True
        print(f"  [{status}] {q['container']}: {len(rows)} rows (report saw {q['rowCount']})")

    snaps = list(
        db.get_container_client("findings").query_items(
            "SELECT * FROM c WHERE c.runId = @r",
            parameters=[{"name": "@r", "value": manifest["runId"]}],
            enable_cross_partition_query=True,  # [/subscriptionId, /runId]: one partition per subscription
        )
    )
    digest = hashlib.sha256("\n".join(sorted({s["id"] for s in snaps})).encode()).hexdigest()
    sealed = digest == manifest.get("documentSetSha256")
    ok &= sealed
    print(f"  [{'ok' if sealed else 'DIFFERS'}] run {manifest['runId']} document-set digest")
    # Same canonical form as functions/*/content_sha256: sorted keys, Cosmos "_" fields dropped.
    def content(d: dict) -> str:
        body = {k: v for k, v in d.items() if not k.startswith("_")}
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

    if manifest.get("contentSetSha256"):
        lines = (f"{s['id']} {content(s)}" for s in sorted(snaps, key=lambda s: s["id"]))
        content_ok = hashlib.sha256("\n".join(lines).encode()).hexdigest() == manifest["contentSetSha256"]
        ok &= content_ok
        print(f"  [{'ok' if content_ok else 'DIFFERS'}] run {manifest['runId']} content digest")
    rbac_seal = (manifest.get("containerSeals") or {}).get("rbac")
    if rbac_seal:
        rbac = list(
            db.get_container_client("rbac").query_items(
                "SELECT * FROM c WHERE c.runId = @r",
                parameters=[{"name": "@r", "value": manifest["runId"]}],
                enable_cross_partition_query=True,
            )
        )
        ids_ok = hashlib.sha256("\n".join(sorted({d["id"] for d in rbac})).encode()).hexdigest() == rbac_seal["documentSetSha256"]
        lines = (f"{d['id']} {content(d)}" for d in sorted(rbac, key=lambda d: d["id"]))
        content_ok = hashlib.sha256("\n".join(lines).encode()).hexdigest() == rbac_seal["contentSetSha256"]
        ok &= ids_ok and content_ok
        print(f"  [{'ok' if ids_ok and content_ok else 'DIFFERS'}] run {manifest['runId']} rbac seal ({len(rbac)} snapshots)")
    print("REPRODUCED" if ok else "NOT REPRODUCED")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
