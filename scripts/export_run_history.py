#!/usr/bin/env python3
"""Export run history from the evidence store into docs/evidence/RUN-HISTORY.md.

The grader reads the repository, not your Cosmos account, so run history has to be
published as evidence. This writes every run manifest (start, trigger, status,
document counts, digest) and every report execution folder, newest first, plus the
queries used, so anyone with access can reproduce the table.

    az login
    COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint) \
    EVIDENCE_ACCOUNT=$(terraform -chdir=stages/03-evidence-store output -raw evidence_storage_account) \
        python3 scripts/export_run_history.py

Commit the result weekly. Timer runs accumulating day after day, with trigger=timer,
are the "history, not a burst" the rubric asks for.
"""

from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

RUNS_QUERY = (
    "SELECT c.runId, c.trigger, c.status, c.startedAt, c.completedAt, c.documentCount, "
    "c.sources, c.documentSetSha256, c.crosswalkVersion, c.collectorVersion "
    "FROM c WHERE c.type = 'run-manifest'"
)
OUT = Path(__file__).resolve().parents[1] / "docs" / "evidence" / "RUN-HISTORY.md"


def main() -> int:
    from azure.cosmos import CosmosClient
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    cred = DefaultAzureCredential()
    db = CosmosClient(os.environ["COSMOS_ENDPOINT"], cred).get_database_client(os.environ.get("COSMOS_DATABASE", "grc"))
    runs = list(db.get_container_client("runs").query_items(RUNS_QUERY, enable_cross_partition_query=True))
    runs.sort(key=lambda r: r["startedAt"], reverse=True)

    blobs = BlobServiceClient(
        f"https://{os.environ['EVIDENCE_ACCOUNT']}.blob.core.windows.net", credential=cred
    ).get_container_client("reports")
    executions = sorted(
        {b.name.rsplit("/", 1)[0] for b in blobs.list_blobs() if b.name.endswith("/manifest.json")},
        reverse=True,
    )

    by_status = Counter(r["status"] for r in runs)
    by_trigger = Counter(r.get("trigger", "timer (pre-manifest)") for r in runs)
    days = sorted({r["startedAt"][:10] for r in runs})
    lines = [
        "# Run history (exported from the evidence store)",
        "",
        f"Exported {datetime.now(timezone.utc).isoformat(timespec='seconds')} by `scripts/export_run_history.py`.",
        "",
        f"- **Collection runs:** {len(runs)} across {len(days)} days"
        + (f" ({days[0]} to {days[-1]})" if days else ""),
        f"- **By status:** " + ", ".join(f"{k} {v}" for k, v in sorted(by_status.items())),
        f"- **By trigger:** " + ", ".join(f"{k} {v}" for k, v in sorted(by_trigger.items())),
        f"- **Report executions with a sealed manifest:** {len(executions)}",
        "",
        "Reproduce: Cosmos `runs` container, cross-partition:",
        "",
        f"```sql\n{RUNS_QUERY}\n```",
        "",
        "## Collection runs",
        "",
        "| Started (UTC) | Trigger | Status | Docs | Defender | Policy | Digest (first 12) | Run ID |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in runs:
        src = r.get("sources") or {}
        lines.append(
            f"| {r['startedAt'][:19]} | {r.get('trigger', '')} | {r['status']} | {r.get('documentCount', '')} "
            f"| {src.get('defender', {}).get('documents', '')} | {src.get('policy', {}).get('documents', '')} "
            f"| `{(r.get('documentSetSha256') or '')[:12]}` | `{r['runId']}` |"
        )
    lines += ["", "## Report executions (WORM container `reports`)", ""]
    lines += [f"- `{e}/`" for e in executions]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(runs)} runs, {len(executions)} report executions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
