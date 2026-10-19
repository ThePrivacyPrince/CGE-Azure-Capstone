# Runbook

Three paths: **A** upgrade an existing CGE-AZ lab deployment to the Tallyfin capstone (the path for this repo's owner), **B** deploy from an empty subscription, **C** produce the evidence the rubric asks for. Teardown is at the end.

Shell conventions: run from the repo root unless a step says `cd`. Every apply uses a **saved plan you read first** (`plan -out` then `apply <file>`): a saved plan applies without another prompt, so the reading is the approval.

## Environment (every session)

```bash
az login
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export TF_VAR_subscription_id=$ARM_SUBSCRIPTION_ID
export TF_VAR_state_storage_account=$(grep storage_account_name labs/03-foundation/backend.hcl | cut -d'"' -f2)
export TF_VAR_owner_email="<you@example.com>"            # PII - shell only, never committed
export TF_VAR_alert_email="<alert inbox>"
export TF_VAR_approved_change_callers='["<your UPN as Activity Log shows it>"]'
tfp() { terraform -chdir="stages/$1" plan -out=tf.plan "${@:2}" && terraform -chdir="stages/$1" show -no-color tf.plan | tail -5; }
tfa() { terraform -chdir="stages/$1" apply tf.plan; }
```

Find your UPN as the Activity Log records it: `az ad signed-in-user show --query userPrincipalName -o tsv`.

## A. Upgrade an existing lab deployment (in place)

Your labs left live resources and, more importantly, accumulating evidence. Every step below is designed to be **in place**. The stop rule: **if any plan shows `destroy` or `replace` on Cosmos, a Cosmos container, the evidence storage account or the `reports` container, stop and do not apply.** The gate (TF-EVD-001) would block that plan in CI too.

0. **Bring your local edits along.** Your Lab 6 fix to `functions/reports/function_app.py` is superseded by `reports_core.py` (one execution ID per folder). Stash or commit your local changes, then check out this branch.
1. **Harden state** (keyless, soft delete, change feed, lock): `./labs/03-foundation/harden-state.sh`. Re-run `terraform init` in a stage afterwards to confirm the backend still works (it should: every stage uses `use_azuread_auth`).
2. **01-foundation:** `tfp 01-foundation`. Expect **3 to add** (the three `tf-*` definitions), **2 to change in place** (initiative, assignment), **0 to destroy**. Read `region_gap` and `out_of_region_resources` in the plan outputs: if the gap is not 0, the region policy deploys in Audit and the list is your migration backlog. `tfa 01-foundation`.
3. **03-evidence-store:** `tfp 03-evidence-store`. Expect adds (`snapshots`, `runs`, policy-state role + assignment, 2 locks, 2 diagnostic settings) and in-place changes (Cosmos `access_key_metadata_writes_enabled`, storage hardening, function app settings / `https_only`). **0 destroy.** `tfa 03-evidence-store`.
4. **04-reporting:** `tfp 04-reporting`. Expect the reporter's blob role assignment to be **replaced** (built-in -> custom no-delete role; role assignments are immutable, so a role change is a replace). That is the only replace. `tfa 04-reporting`.
5. **Deploy the code:** `./scripts/deploy-functions.sh` (copies the crosswalk, stamps the git SHA, zip-deploys both apps).
6. **06-enforcement:** `tfp 06-enforcement`. Expect the two `moved` addresses to show as moved (not destroyed), the `tf-fix-min-tls` definition + assignment and the custom remediator role to add, and the remediator role assignment to be replaced. `remediation_mode = "dry-run"`, `approved_remediations = []`. `tfa 06-enforcement`.
7. **07-detection:** `terraform -chdir=stages/07-detection init -backend-config=../../labs/03-foundation/backend.hcl`, then `tfp 07-detection`. Expect **1 to import** (your Lab 2 `ds-activity-to-law`), action group + 2 alert rules to add. If the state postconditions fail, step 1 did not finish. `tfa 07-detection`. Commit the new `stages/07-detection/.terraform.lock.hcl`.
8. **Arm CI read-only:** `./labs/06-loop/arm-your-fork.sh <github-user> CGE-Azure-Capstone` (the repo name must match exactly; it is part of the OIDC federation subject). If your fork was armed with the starter script, run the two `az role assignment delete` lines printed in its comments to remove Contributor and state write. Add the printed repository **variables**.
9. **Protect main:** Settings -> Branches -> rule for `main`: require a PR, require review from Code Owners, require status checks `static checks (no credentials)` and the `plan + OPA gate` jobs, disallow force pushes.
10. **Push** this branch and open a PR to your fork's `main`. Both gate jobs should go green. Merge it.

## B. Deploy from an empty subscription

1. One-time setup in [SETUP.md](SETUP.md): providers registered, quota probed (`labs/00-setup/probe-quota.sh`), budget created (`labs/01-sandbox/create-budget.sh`).
2. `./labs/03-foundation/bootstrap.sh` (creates and hardens state, writes `backend.hcl`), then the environment block above.
3. `./labs/02-toolkit/route-activity-log.sh` (needs the workspace: run it after stage 01, before stage 07).
4. Stages in order, each `init` / `tfp` / `tfa`: `01-foundation`, `02-activation`, `03-evidence-store`, `04-reporting`, `06-enforcement`, `07-detection`.
   - Stage 01 creates the management groups and moves the subscription under `mg-grc-sandbox`; that requires permission at the tenant root.
   - Seed the CSF 2.0 catalog once after stage 03: `python3 labs/04-evidence/seed_frameworks.py` (see its docstring).
5. `./scripts/deploy-functions.sh`.
6. Steps A.8 to A.10.

## C. Produce the rubric's evidence

Record each result in [`docs/evidence/`](evidence/) and commit it.

### C1. Prove the timers (run history over time)
Weekly, and the day before you submit:
```bash
COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint) \
EVIDENCE_ACCOUNT=$(terraform -chdir=stages/03-evidence-store output -raw evidence_storage_account) \
  python3 scripts/export_run_history.py
git add docs/evidence/RUN-HISTORY.md && git commit -m "evidence: run history export"
```
What good looks like: four `trigger=timer` collection runs per day and one POA&M + one SAR folder per day, continuous for **at least two to three weeks**. Gaps are fine if explained (a failed run shows as `failed` with its error, which is itself evidence the pipeline tells the truth).

### C2. WORM failed-delete proof
```bash
ACCT=$(terraform -chdir=stages/03-evidence-store output -raw evidence_storage_account)
BLOB=$(az storage blob list --auth-mode login --account-name $ACCT -c reports --query "[?ends_with(name,'manifest.json')].name | [0]" -o tsv)
az storage blob delete   --auth-mode login --account-name $ACCT -c reports -n "$BLOB"       # expect 409/403: immutability policy
az storage blob upload   --auth-mode login --account-name $ACCT -c reports -n "$BLOB" -f /etc/hosts --overwrite   # expect refusal
az storage container immutability-policy show --account-name $ACCT -c reports -o table      # retention days, state
```
Then show the attempt landed in the logs (who tried, and that it failed):
```kusto
StorageBlobLogs | where TimeGenerated > ago(1h) | where OperationName == "DeleteBlob"
| project TimeGenerated, StatusCode, StatusText, RequesterUpn, Uri
```
Paste outputs into `docs/evidence/WORM-PROOF.md` (redact your UPN if you prefer).

### C3. The gate blocks a non-compliant plan (closed test PR)
1. Branch `test/gate-blocks-public-storage`. In `stages/03-evidence-store/main.tf` add a storage account with `allow_nested_items_to_be_public = true` and `min_tls_version = "TLS1_0"`.
2. Open a PR. The `plan + OPA gate (03-evidence-store)` job fails with `TF-STG-001` and `TF-STG-003`.
3. Screenshot or link the failing run in `docs/evidence/GATE-BLOCK.md`, then **close the PR without merging** and delete the branch.
Local equivalent: `conftest test tests/gate-fixtures/bad-plan.json -p policy` (6 failures).

### C4. Close the loop with approval as code
Repeats Lab 6 with the human gate in git instead of in a terminal:
1. Stage 01: PR setting `public_blob_policy_effect = "Audit"` with an exception ticket in the description (time-boxed). Merge, apply.
2. `az storage account update -n <seed account> -g rg-grc-sandbox-dev --allow-blob-public-access true` (the out-of-band change; tripwire 1 should email you within ~15-30 min - that is detector 2 working).
3. Wait for the next collection; the POA&M shows the open finding with its first-seen date.
4. PR to `stages/06-enforcement/approvals.auto.tfvars`: `approved_remediations = ["fix-public-blob"]`, `remediation_change_ticket = "chg-0001"`. Merge, `tfa 06-enforcement` -> task `rem-fix-public-blob-chg-0001`.
5. Attribute it: Activity Log `caller` = `terraform -chdir=stages/06-enforcement output -raw remediator_principal_id`.
6. PR removing the key; PR restoring `Deny` in stage 01.
7. Next SAR: the finding appears under **fixed** (explicit fail -> pass). Record the run IDs, task name and caller match in `docs/evidence/LOOP-CLOSURE-2.md`.

Note: Azure Storage no longer accepts TLS 1.0/1.1 as a minimum on most accounts, so `fix-min-tls` may have nothing to remediate in a fresh sandbox. It remains a correct detective/corrective pair for legacy accounts; use `fix-public-blob` for the demonstration.

### C5. Reproduce a report from the store
```bash
az storage blob download --auth-mode login --account-name $ACCT -c reports -n "<folder>/manifest.json" -f manifest.json
COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint) python3 scripts/reproduce_report.py manifest.json
```
`REPRODUCED` means every query still returns what the report saw and the run's document-set digest still matches.

## Teardown

The evidence plane is locked on purpose. To tear down the course sandbox:
```bash
az lock delete --name lock-evidence-cosmos  --resource-group rg-grc-evidence-dev --resource-type Microsoft.DocumentDB/databaseAccounts --resource-name "<cosmos account>"
az lock delete --name lock-evidence-storage --resource-group rg-grc-evidence-dev --resource-type Microsoft.Storage/storageAccounts --resource-name "<evidence account>"
```
Then `terraform destroy` stages in reverse order (07, 06, 04, 03, 02, 01). Unexpired WORM blobs block deleting the reports container while the policy is **locked**; it is unlocked in this repo, so remove the immutability policy first if blobs are still in retention. The state resource group lock (`lock-tfstate`) goes last.
