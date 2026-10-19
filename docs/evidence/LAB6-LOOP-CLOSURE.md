# Lab 6 - Close the loop (2026-10-17)

Run against the CGE-AZ starter deployment in the sandbox subscription, before the FAFO capstone changes. It is the baseline the capstone's design decisions respond to (see [../DECISIONS.md](../DECISIONS.md)).

## Sequence

Preventive control relaxed (Deny -> Audit, reviewed plan) -> sandbox storage account misconfigured out-of-band -> Azure Policy detects NonCompliant -> human creates remediation task -> user-assigned remediation identity performs the write -> Activity Log attributes it -> Defender assessments collected into Cosmos -> POA&M regenerated from stored evidence -> preventive control restored (Audit -> Deny).

## Verified (observed output)

| Step | Evidence |
|---|---|
| Enforcement deployed in dry-run | `terraform apply`: 3 added, 0 changed, 0 destroyed; `terraform output remediation_mode` = `"dry-run"` |
| Clean gate on the foundation plan | `conftest test lab6-clean.json -p policy/`: 4 tests, 4 passed |
| Controlled exception | Plan `publicBlobEffect: "Deny" -> "Audit"`, 0 add / 1 change / 0 destroy; applied. Re-applying the same saved plan failed with `Saved plan is stale` (state had moved on) |
| Misconfiguration | `stgrcseed15471` `allowBlobPublicAccess`: `False` -> `True` via Azure CLI (out-of-band) |
| Detection | `az policy state list ... cge-fix-public-blob`: `stgrcseed15471  NonCompliant` |
| Approved remediation | Task `fix-public-blob-<epoch>`: `Accepted` -> `Succeeded`, 1/1 deployments successful, 0 failed |
| Configuration after fix | `allowBlobPublicAccess` = `false` |
| Attribution | `Microsoft.Storage/storageAccounts/write` at 2026-10-17T18:14:20Z, status Succeeded, caller `d74e7837-dcaa-443c-9bba-e4579131a649` = principal ID of `id-grc-remediation-dev` |
| Control restored | Plan `Audit -> Deny`, 0 add / 1 change / 0 destroy; applied |
| Fresh evidence | Collection run `9c769c6e-2cbf-4dee-a842-5ff1d1567cae`: 100 documents at 2026-10-17T18:23:19Z |
| Report | After fixing a same-day path collision (HTTP 500), POA&M regenerated: 54 items, `runId` = the run above |
| Explicit positive evidence | Cosmos record for `stgrcseed15471`, run `9c769c6e...`: "Storage account public access should be disallowed", assessment `51fd8bb1-0db4-bbf1-7e2b-cfcba7eb66a6`, status **Healthy** |
| Negative gate test | Synthetic bad-plan fixture: 4 tests, 2 passed, 2 failures, both naming `azurerm_storage_account.lab6_bad` |

## Not concluded, on purpose

- The POA&M no longer listing a public-access finding was **not** taken as proof of the fix (absence of a finding is weaker than an explicit pass). The explicit Healthy record above is the proof.
- Azure Policy (NonCompliant before) and Defender (Healthy after) are different assessment systems. A Defender **Unhealthy** record for this assessment before remediation was **not** captured, so no Defender Unhealthy -> Healthy transition is claimed.
- The 54 remaining POA&M items (network rules, private link, shared key on the seed account) are unrelated controls; one fixed control does not close them.

## Not demonstrated in Lab 6

Armed GitHub OIDC CI; a PR blocked by the gate in GitHub; branch protection; scheduled drift workflow runs; KQL tripwire as an alert; per-run evidence history; a production approval workflow; teardown; an ATO decision. The capstone builds the first six (RUNBOOK sections A and C).

## Gaps found, and where the capstone closes them

| Lab 6 finding | Capstone change |
|---|---|
| Remediation identity held Storage Account Contributor (listKeys, delete) for a one-property job | Custom `tf-storage-baseline-remediator` role (ADR-011) |
| CI identity: Contributor at `mg-grc` + state write, for a "plan-only" workflow | Read-only planner + credential-free fork path (ADR-006) |
| Starter gate excepted shared keys by resource **name** prefix | Per-address, ticketed, expiring exceptions (`policy/exceptions.rego`) |
| Starter identity rule demanded identities on Audit-only assignments | Fail-closed rule that requires identity unless the plan proves non-remediation; also fixed it never firing on real plans (empty list is truthy) |
| Cosmos doc id excluded runId: each run overwrote the last | per-run history (`findings`, ADR-008, ADR-015) + `runs` manifests |
| Reports chose the newest document's run, possibly a partial sweep | Completed-run selection + staleness refusal (ADR-009) |
| Same-day report path collision; JSON/XLSX with different timestamps | One execution ID per folder, manifest last (ADR-010) |
| Manual triggers needed function keys | HTTP triggers off by default; manual runs labeled (ADR-002) |
| Approval was a terminal command with no reviewable record | Approval as code in a CODEOWNERS PR (stage 06) |
