# Evidence

What the rubric asks you to *demonstrate*, kept as files an assessor can read cold. Each document states what was **verified** (observed output), what is **inferred**, and what was **not demonstrated**, because those are different claims.

| File | Demonstrates | Rubric dimension |
|---|---|---|
| [LAB6-LOOP-CLOSURE.md](LAB6-LOOP-CLOSURE.md) | Detect -> human-approved remediation -> attributed fix -> fresh evidence -> report, run 2026-10-17 | Pipeline Operations, Evidence Integrity |
| [RUN-HISTORY.md](RUN-HISTORY.md) | Timer runs accumulating over time (exported from Cosmos by `scripts/export_run_history.py`) | Pipeline Operations |
| [WORM-PROOF.md](WORM-PROOF.md) | Failed delete/overwrite of a report blob, and the attempt in the logs | Evidence Integrity |
| [GATE-BLOCK.md](GATE-BLOCK.md) | A closed test PR the gate blocked | Pipeline Operations |
| LOOP-CLOSURE-2.md | The loop again, with approval as code (RUNBOOK C4) | Pipeline Operations |
| [../SUBMISSION.md](../SUBMISSION.md) → `submission/` | The machine-readable bundle the grader cross-checks against the code: plans, identities, policies, reports, run documents, WORM refusal (RUNBOOK C6) | All four |

How to produce each one: [../RUNBOOK.md](../RUNBOOK.md), section C.
