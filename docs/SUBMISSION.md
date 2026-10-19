# The submission bundle (`submission/`)

The grader can't log into FAFO's subscription. So the repository has to carry its own proof: machine-readable exports from the live environment that a reviewer can check against the code. This file describes that bundle. `scripts/export_submission.py` copies it into `submission/README.md`.

## How it's made

```bash
az login                                    # the operator who applied the stages
export TF_VAR_...                           # the environment block in docs/RUNBOOK.md
python3 scripts/export_submission.py        # writes submission/
sleep 900 && python3 scripts/export_submission.py --only worm-logs   # storage logs lag ~5-15 min
python3 scripts/verify_submission.py        # the grader's cross-checks, offline
git add submission && git commit -m "evidence: submission bundle"
```

Re-export the day before you submit, so the plans and the run history are current.

## What's in it, and what each file proves

| Path | Proves | Cross-checked against |
|---|---|---|
| `plans/<stage>.plan.txt`, `plans/summary.json` | The repo describes the estate that's actually deployed: every stage plans **No changes** | the Terraform in `stages/` |
| `identities/<identity>.role-assignments.json`, `identities/cosmos-data-plane-role-assignments.json`, `identities/summary.json` | Each pipeline identity holds exactly its job, nothing broad, and the collector and reporter are separated | the role grants in stages 01, 03, 04, 06 and `labs/06-loop/arm-your-fork.sh` |
| `policy/custom-definitions.json`, `policy/custom-initiatives.json`, `policy/assignments.json`, `policy/compliance-summary.json` | Every custom policy in code is deployed **and** assigned at the management group | `stages/01-foundation/policies.tf`, `stages/06-enforcement/main.tf` |
| `reports/<report>/<yyyy>/<mm>/<dd>/<execution>/...` | The latest POA&M (JSON, XLSX, OSCAL) and SAR, byte-for-byte from the WORM container, each with its `manifest.json` | the manifest's SHA-256 of every file |
| `evidence/runs.json`, `evidence/findings-<runId>.json`, `evidence/rbac-<runId>.json` | Every number in the reports recounts from the stored documents of the run the report names, and both seals (id and content digests) recompute | the report's `manifest.json` and `scorecard.json` |
| `worm/immutability-policy.json`, `worm/delete-attempt.json`, `worm/storage-blob-logs.json` | Deleting and overwriting a sealed report were both **refused** by the platform, and the refusals were logged | `stages/03-evidence-store/main.tf` (immutability policy) |
| `storage/shared-key-status.json` | Shared-key access is off on the evidence and state accounts. The Y1 runtime accounts are the one documented exception (RISK-0001) | `stages/03-evidence-store`, `labs/03-foundation/harden-state.sh` |
| `run-history/run-history.json`, `run-history/RUN-HISTORY.md` | The timers ran on their own, at the declared cadence, over weeks | `COLLECT_SCHEDULE` (stage 03), `POAM_SCHEDULE`/`SAR_SCHEDULE` (stage 04) |
| `oscal/ssp.json`, `oscal/fafo-moderate-profile.json` | The SSP that went out, identical to the repository's | `oscal/` |
| `MANIFEST.json` | Nothing in the bundle changed after export | every file above |

## What's deliberately not in it

- **Raw plan JSON.** `terraform show -json` prints sensitive values (for example, the Y1 runtime storage key) in clear text, and a key in a public repo is an automatic fail. The bundle keeps Terraform's text plan, which redacts sensitive values, plus a summary of addresses and actions only.
- **PII.** The operator's e-mail and UPN (from `TF_VAR_owner_email`, `TF_VAR_alert_email` and `TF_VAR_approved_change_callers`) are replaced with `[REDACTED-EMAIL]` in every exported file.
- **The gate blocking a PR.** That proof lives on GitHub: a closed, unmerged test PR with a red `plan + OPA gate` run. It's recorded in [evidence/GATE-BLOCK.md](evidence/GATE-BLOCK.md) (RUNBOOK C3).
