# Runbook

Three paths: **A** upgrade an existing CGE-AZ lab deployment to the FAFO capstone (the path for this repo's owner), **B** deploy from an empty subscription, **C** produce the evidence the rubric asks for. Teardown is at the end.

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

Your labs left live resources and, more importantly, accumulating evidence. Every step below is **in place**, or it **forgets** a resource without destroying it. The stop rule: **if any plan shows `destroy` or `replace` on Cosmos, a Cosmos container, the evidence storage account or the `reports` container, stop and do not apply.** The gate (TF-EVD-001) would block that plan in CI too. Note that "forget" (from a `removed` block) is not destroy: Azure keeps the resource.

0. **Bring your local edits along.** Stash or commit local changes, then check out this branch.
1. **Harden state** (keyless, soft delete, change feed, lock): `./labs/03-foundation/harden-state.sh`. Re-run `terraform init` in a stage afterwards to confirm the backend still works (every stage uses `use_azuread_auth`).
2. **01-foundation.** First adopt the subscription's management-group membership, which used to be declared on the management group itself (ADR-014):
   ```bash
   terraform -chdir=stages/01-foundation import azurerm_management_group_subscription_association.sandbox \
     "/providers/Microsoft.Management/managementGroups/mg-grc-sandbox/subscriptions/$ARM_SUBSCRIPTION_ID"
   ```
   Then `tfp 01-foundation`. Expect the renamed and new FAFO policy definitions to **add** (`fafo-*`), any earlier `tf-*` definitions to be **destroyed** (policy definitions, not evidence), and the initiative and its assignment to **change in place**. Read `region_gap` and `out_of_region_resources` in the outputs: they now cover every subscription under the management group. If the gap isn't 0, the region policy deploys in Audit and the list is your migration backlog. `tfa 01-foundation`.
3. **02-activation.** `tfp 02-activation`. Expect `azurerm_security_center_subscription_pricing.baseline` to be **forgotten** (not destroyed: destroying would flip Defender to Free), one `azapi_update_resource.baseline["<subscription>/<plan>"]` per subscription and plan to add, the subscription-scoped `nist_csf_20` assignment to be **destroyed**, and `nist_800_53_r5` at the management group to **add** (ADR-013). `tfa 02-activation`.
4. **03-evidence-store.** `tfp 03-evidence-store`. Expect:
   - `findings` and `rbac` (hierarchical keys) to add;
   - `snapshots`, if you had it, to be **forgotten**;
   - the collector's role assignments to be **replaced** at management-group scope (role assignments are immutable);
   - `fafo-grc-policy-state-reader` to be replaced (new name and scope);
   - the collector's app settings to change (`MANAGEMENT_GROUP_ID` replaces `SUBSCRIPTION_ID`).

   **0 destroy on Cosmos, its containers or the evidence account.** `tfa 03-evidence-store`.
5. **04-reporting.** `tfp 04-reporting`. Expect the report-writer role (renamed `fafo-grc-report-writer`) and its assignment to be **replaced**. That's the only replace. `tfa 04-reporting`.
6. **Deploy the code:** `./scripts/deploy-functions.sh` (copies the crosswalk, stamps the git SHA, zip-deploys both apps). The next collector run discovers subscriptions from its MG-scoped roles: check its manifest's `scope.subscriptions`.
7. **06-enforcement.** `tfp 06-enforcement`. Expect the `fix-min-tls` definition and assignment to be **replaced** (renamed `fafo-fix-min-tls`), both corrective definitions to gain an `effect` parameter, the assignments to pass it, and the remediator role (renamed `fafo-storage-baseline-remediator`) and its assignment to be replaced. `remediation_mode = "dry-run"`, `approved_remediations = []`. `tfa 06-enforcement`.
8. **07-detection.** `terraform -chdir=stages/07-detection init -backend-config=../../labs/03-foundation/backend.hcl`. If you applied stage 07 before Activity Log routing became per-subscription, move the address first:
   ```bash
   terraform -chdir=stages/07-detection state mv azurerm_monitor_diagnostic_setting.activity_log \
     "azurerm_monitor_diagnostic_setting.activity_log[\"$ARM_SUBSCRIPTION_ID\"]"
   ```
   Then `tfp 07-detection`. Expect the two existing alert rules to show as **moved** into `tripwire["..."]`, two new FAFO tripwires (`off-hours-admin-changes`, `keyvault-secret-reads-non-pipeline`) to add, and, if you never applied stage 07, one Activity Log import. If the state postconditions fail, step 1 didn't finish. `tfa 07-detection`.
9. **Arm CI read-only:** `./labs/06-loop/arm-your-fork.sh <github-user> CGE-Azure-Capstone` (the repo name must match exactly; it's part of the OIDC federation subject). If your fork was armed with the starter script, run the two `az role assignment delete` lines printed in its comments to remove Contributor and state write. Add the printed repository **variables**.
10. **Protect main:** Settings -> Branches -> rule for `main`: require a PR, require review from Code Owners, require status checks `static checks (no credentials)` and the `plan + OPA gate` jobs, disallow force pushes.
11. **Push** this branch and open a PR to `main`. Both gate jobs should go green. Merge it.

## B. Deploy from an empty subscription

1. One-time setup in [SETUP.md](SETUP.md): providers registered, quota probed (`labs/00-setup/probe-quota.sh`), budget created (`labs/01-sandbox/create-budget.sh`).
2. **Seed the estate.** Run the course's `seed_estate.sh` (from the CGE-AZ starter repository) in your sandbox subscription. It deploys about a dozen cheap resources, several of them deliberately misconfigured, so discovery finds a gap, the assessments have something to assess, and the reports carry real findings with real resource IDs.
3. `./labs/03-foundation/bootstrap.sh` (creates and hardens state, writes `backend.hcl`), then the environment block above.
4. `./labs/02-toolkit/route-activity-log.sh` (needs the workspace: run it after stage 01, before stage 07). Or delete the `import` block in stage 07 and let it create the setting.
5. Stages in order, each `init` / `tfp` / `tfa`: `01-foundation`, `02-activation`, `03-evidence-store`, `04-reporting`, `06-enforcement`, `07-detection`.
   - Stage 01 creates the management groups and associates the subscription with `mg-grc-sandbox`; that requires permission at the tenant root.
   - Seed the catalog records once after stage 03: `python3 labs/04-evidence/seed_frameworks.py` (see its docstring).
6. `./scripts/deploy-functions.sh`. **Start the timers now:** run history is the one piece of evidence that can't be produced quickly.
7. Steps A.9 to A.11.

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

Note: Azure Storage no longer accepts TLS 1.0/1.1 as a minimum on most accounts, so `fafo-fix-min-tls` may have nothing to remediate in a fresh sandbox. It remains a correct detective/corrective pair for legacy accounts; use `fix-public-blob` for the demonstration.

### C5. Reproduce a report from the store
```bash
az storage blob download --auth-mode login --account-name $ACCT -c reports -n "<folder>/manifest.json" -f manifest.json
COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint) python3 scripts/reproduce_report.py manifest.json
```
`REPRODUCED` means every query still returns what the report saw and the run's document-set digest still matches.

### C6. Export and verify the submission bundle
The grader can't log in, so `submission/` proves the deployment ([SUBMISSION.md](SUBMISSION.md)):
```bash
python3 scripts/export_submission.py
sleep 900 && python3 scripts/export_submission.py --only worm-logs
python3 scripts/verify_submission.py
git add submission && git commit -m "evidence: submission bundle"
```
`verify_submission.py` must end with `0 failed`. Re-export the day before you submit.

## Teardown

The evidence plane is locked on purpose. To tear down the course sandbox:
```bash
az lock delete --name lock-evidence-cosmos  --resource-group rg-grc-evidence-dev --resource-type Microsoft.DocumentDB/databaseAccounts --resource-name "<cosmos account>"
az lock delete --name lock-evidence-storage --resource-group rg-grc-evidence-dev --resource-type Microsoft.Storage/storageAccounts --resource-name "<evidence account>"
```
Then `terraform destroy` stages in reverse order (07, 06, 04, 03, 02, 01). Unexpired WORM blobs block deleting the reports container while the policy is **locked**; it is unlocked in this repo, so remove the immutability policy first if blobs are still in retention. The state resource group lock (`lock-tfstate`) goes last.
