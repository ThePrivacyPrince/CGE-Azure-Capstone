# Tallyfin GRC Pipeline (CGE-AZ capstone)

**Tallyfin** is a fictional fintech: a Plaid-style API that lets consumer apps connect to people's bank accounts. That makes it a holder of nonpublic personal financial information under the **GLBA Safeguards Rule (16 CFR 314.4)**, a service provider in scope for **PCI DSS 4.0.1**, and a company whose customers will ask for a **SOC 2** report. This repository is Tallyfin's automated GRC engineering pipeline on Azure: it defines the governed environment as code, collects evidence on a schedule, writes reports from that evidence alone, and fixes misconfigurations through one auditable identity, only after a human approves the fix.

It is built on the [CGE-AZ starter](https://github.com/GRCEngClub/cgeaz) (GRC Engineering Club) and substantially extends it. What changed from the starter, and why, is in [docs/DECISIONS.md](docs/DECISIONS.md); the short version is in the next section.

```
01 Foundation ─► 02 Activation ─► 03 Evidence store ─► 04 Reporting ─► 06 Enforcement ─► 07 Detection
 hierarchy,       discover the     Cosmos snapshots     POA&M + SAR      Modify policies    Activity Log
 6 policies,      Defender gap,    + run manifests,     from the store   in dry-run, one    tripwires as
 measured-gap     close only       WORM reports,        ONLY, with a     identity, human    alert rules
 data residency   that gap         2 evidence sources   receipt each     approval in a PR
                                                                               │
                ◄──────────── next collection records the fix ◄────────────────┘
```

## What this capstone adds to the starter

| Area | Starter | Tallyfin capstone |
|---|---|---|
| Own controls | 3 policies | **+3 own policies** (storage TLS 1.2 floor, Cosmos key-auth ban, data residency) and **+1 own corrective control** (`tf-fix-min-tls`) |
| Discovery-first | Defender plans (stage 02) | **Also data residency**: inventories every resource, measures the out-of-region gap, and runs the region policy at Audit until the gap is zero, then Deny |
| Evidence history | Latest state only (each run overwrote the last) | **Per-run snapshots** + **run manifests** (`started`/`completed`/`partial`/`failed`, with a digest of the document set); latest-state view kept for compatibility |
| Evidence sources | Defender assessments | **+ Azure Policy compliance states**, both mapped through one crosswalk ([frameworks/mappings.json](frameworks/mappings.json)) to NIST CSF 2.0, 800-53, PCI DSS 4.0.1, SOC 2, GLBA |
| Reports | Picked the newest *document's* run; same-day file paths collided | Read only **completed** runs; refuse **stale** evidence; one **execution ID** per report folder with a **manifest of SHA-256s written last**; POA&M due dates from **first-seen history** |
| Remediation identity | Storage Account Contributor (includes listKeys, delete) | **Custom role**: storage property read/write only, keys and delete explicitly excluded |
| Human gate | `az policy remediation create` by hand | **Approval as code**: a reviewer adds a control key + ticket to `approvals.auto.tfvars` in a CODEOWNERS-protected PR |
| CI identity | Contributor at `mg-grc` + state write | **Read-only planner** role + state **reader**; plans run `-lock=false`; fork PRs get a credential-free job only |
| Gate rules | 3 rules, one name-based exception | **14 rules** with **22 OPA unit tests**; expiring, ticketed exceptions; evidence-plane deletion and WORM shortening blocked; fixed a bug where the identity rule could never fire on a real plan |
| Drift, question 2 | KQL query run by hand | **Stage 07**: Activity Log tripwires as scheduled alert rules (unexpected writer; remediator out of its lane) |
| Credentials | HTTP triggers with function keys | HTTP triggers **off by default**; manual runs labeled `trigger=manual` in the manifest |

## Repository layout

```
stages/       one Terraform root module per stage, each with its own state file
  01-foundation/      hierarchy, initiative (6 policies), remediation identity, discovery.tf
  02-activation/      Defender plan discovery -> activation of the measured gap
  03-evidence-store/  Cosmos (assessments, snapshots, runs, frameworks, mappings), WORM blob, collector app
  04-reporting/       reporter app, custom no-delete report-writer role
  06-enforcement/     Modify policies, escalation ladder, custom remediator role, approval gate
  07-detection/       Activity Log routing (adopted) + tripwire alert rules
functions/    collector (collect_assessments/) and reports/ - Python, timer-triggered, managed identity
frameworks/   mappings.json - the collect-once crosswalk, as data
policy/       OPA/conftest gate rules, unit tests, time-boxed exceptions
tests/        pytest for collector + reports (no cloud needed); gate-fixtures/ for conftest
scripts/      deploy-functions.sh, reproduce_report.py
docs/         ARCHITECTURE, CONTROLS, BLAST-RADIUS, DECISIONS, RUNBOOK, evidence/
labs/         the six CGE-AZ lab guides (course material, lightly modified)
```

## Deploy from an empty subscription

Full detail, expected outputs and failure modes are in [docs/RUNBOOK.md](docs/RUNBOOK.md). The order:

**Prerequisites:** Azure CLI ≥ 2.60 (`az login`), Terraform ≥ 1.9, Python 3.11, an Azure subscription where you are Owner and can create management groups, and the one-time setup in [docs/SETUP.md](docs/SETUP.md) (resource providers, quota probe, budget).

```bash
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export TF_VAR_subscription_id=$ARM_SUBSCRIPTION_ID
export TF_VAR_owner_email="<you@example.com>"          # PII: environment only, never committed
export TF_VAR_alert_email="<alerts@example.com>"
export TF_VAR_approved_change_callers='["<your UPN>"]'

./labs/03-foundation/bootstrap.sh                      # 0. state account (versioned, keyless) -> backend.hcl
export TF_VAR_state_storage_account=$(grep storage_account_name labs/03-foundation/backend.hcl | cut -d'"' -f2)
./labs/02-toolkit/route-activity-log.sh                # 0. Activity Log -> workspace (adopted by stage 07)

for s in 01-foundation 02-activation 03-evidence-store 04-reporting 06-enforcement 07-detection; do
  (cd stages/$s && terraform init -backend-config=../../labs/03-foundation/backend.hcl \
     && terraform plan -out=tf.plan && terraform apply tf.plan)
done

./scripts/deploy-functions.sh                          # collector + reports code, stamped with the git SHA
./labs/06-loop/arm-your-fork.sh <github-user>          # read-only CI identity; add the printed repo variables
```

Stage 06 deploys in **dry-run** by default (`approvals.auto.tfvars`). Nothing is remediated until a reviewer approves a control key.

## Where to look as an assessor

| You want to verify | Look at |
|---|---|
| Which control each component serves | [docs/CONTROLS.md](docs/CONTROLS.md) |
| Stage flow and identity boundaries | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| What each enforcement change would break, and the rollback | [docs/BLAST-RADIUS.md](docs/BLAST-RADIUS.md) |
| Why regions, why dry-run, why the identity split | [docs/DECISIONS.md](docs/DECISIONS.md) |
| WORM failed-delete proof, gate-block proof, loop closure, run history | [docs/evidence/](docs/evidence/) |
| That a report's numbers come from the store | Any report folder's `manifest.json` + `scripts/reproduce_report.py` |

## Run the rubric's mechanical checks locally

```bash
./self-check.sh          # fmt, validate, tflint, checkov, OPA tests, gate-blocks-bad-fixture, pytest, docs
```

## What this is not

A capstone, not a production system. It runs in a single sandbox subscription, uses Y1 Consumption functions (which force one documented shared-key exception), keeps public network paths with Entra-only auth, and leaves the WORM policy unlocked so the course teardown works. Each of those is a deliberate, written-down trade-off in [docs/DECISIONS.md](docs/DECISIONS.md) with the production answer next to it.

*Built on the GRC Engineering Club CGE-AZ starter. Tallyfin is fictional; no real company data is used.*
