# Design decisions

Why the non-obvious choices were made, what was traded away, and what production would do instead. Each decision names the starter behavior it changed (if any) and the evidence that motivated it. "Lab 6" refers to the Close-the-Loop lab run on 2026-10-17 ([evidence/LAB6-LOOP-CLOSURE.md](evidence/LAB6-LOOP-CLOSURE.md)).

## ADR-001 Extend the live deployment in place
**Decision:** every Terraform change is either additive or in-place. New containers (`snapshots`, `runs`) instead of re-partitioning `assessments`; `moved` blocks to re-address the starter's enforcement policy into a `for_each` map; no attribute changes that force replacement on Cosmos or the evidence storage account.
**Why:** the capstone is graded on run history that accumulates over time. Replacing the evidence store would wipe that history and the Lab 6 evidence with it. Gate rule TF-EVD-001 now makes a delete/replace of evidence-plane resources unmergeable, so this is enforced, not just intended.

## ADR-002 Zero stored credentials, with one documented exception
**Decision:** HTTP triggers (which need function keys) are compiled out unless `ENABLE_MANUAL_TRIGGERS=true`, default off. Manual runs, when enabled, are labeled `trigger=manual` in the run manifest. Every data path uses Entra ID; Cosmos and evidence storage have key auth disabled.
**Exception:** the Y1 Consumption runtime storage (`func_internal`) needs a key-based connection. It holds host scratch data only, never evidence. It is excepted per address in `policy/exceptions.rego` as RISK-0001, expiring 2027-04-30, exit plan ADR-007.
**Lab 6 motivation:** "the collector's outbound access uses its managed identity; the manual HTTP invocation uses a function key - the whole interaction is not literally keyless."

## ADR-003 Regions: `eastus`, `eastus2`, `centralus`, armed by the measured gap
**Decision:** US-only allowed list containing exactly the regions the stages already use: `eastus` (foundation, workspace, enforcement assignments), `eastus2` (evidence store, because East US often lacks Cosmos capacity for new subscriptions), `centralus` (Function tier, because Y1 quota on free and new subscriptions is regional and often zero elsewhere). The policy's effect is computed: Audit while any resource sits outside the list, Deny once the inventory gap is zero.
**Why:** Tallyfin holds consumer financial data; keeping it in US regions keeps the GLBA and state-privacy data map simple. Arming Deny blindly would block updates to any straggler, so the guardrail could cause the outage it exists to prevent. Discovery first, then activation of the measured gap, is the same pattern stage 02 uses for Defender plans.

## ADR-004 Effects: audit new controls, deny where earned, dry-run by default
- `tf-storage-min-tls12` and `tf-cosmos-no-local-auth` start at **Audit**: new controls first measure what they would break. Promote to Deny in a PR once the POA&M shows zero open findings for them.
- `cge-deny-public-blob` stays **Deny**: clear-cut, framework-mandated, and Lab 6 showed the Audit window is a controlled exception, not the baseline.
- Stage 06 defaults to **dry-run**: Modify is deployed, enforcement is off, and nothing changes until a reviewer approves a control key. Lab 6 confirmed that DoNotEnforce does not block an explicitly created remediation task, which is exactly the human-gated behavior wanted.

## ADR-005 Public network paths, Entra-only data access
**Decision:** Cosmos, the evidence storage account and the function apps keep public endpoints. Every data operation still requires an Entra ID token for a role-holding identity; shared keys are off.
**Why:** Y1 Consumption functions cannot use VNet integration or private endpoints, and private networking for a single-subscription course sandbox would add cost and teardown complexity without changing what the rubric measures.
**Production answer:** Flex Consumption or Premium functions with VNet integration, private endpoints for Cosmos and Blob, public network access disabled. Checkov's network findings are skipped inline with this ADR as the reason.

## ADR-006 CI plans, humans apply
**Decision:** the CI identity is read-only (custom `tf-grc-ci-planner` role + Blob Data Reader on state). PR plans and drift plans run `-lock=false`. Applies are run by a human from a terminal after the PR merges.
**Why (Lab 6, step 3):** the starter's arming script gave the CI identity Contributor at `mg-grc` and write access to state, while the workflow was "plan-only". A workflow file is editable by the PR it gates, so it cannot be its own security boundary; the identity's actual permissions are the boundary. Fork PRs get a credential-free job only (`static`), and the privileged `plan` job refuses to run unless the PR's head repo is this repo.
**Residual risk RISK-0005:** the planner role includes `listKeys` because azurerm's refresh reads the Y1 runtime storage key (which is also in state). It can read but not change anything. Removing Y1 (ADR-007) removes this action.
**Production answer:** a separate apply identity bound to a protected GitHub environment with required reviewers, federated only on `environment:production`.

## ADR-007 Stay on Y1 Consumption for the capstone
**Decision:** keep the starter's Y1 function apps; do not migrate to Flex Consumption now.
**Why:** a plan change replaces the function apps (new names, new system-assigned identities, re-granted roles) mid-capstone, for no change in what is graded, and Y1 is what the course validated quota for.
**Exit plan:** Flex Consumption supports identity-based host storage, which removes the last shared key (RISK-0001) and the planner's `listKeys` (RISK-0005).

## ADR-008 Evidence history: one snapshot per finding per run
**Decision:** `snapshots` container, partitioned by `/runId`, `id = sha256(runId | findingKey)`, `findingKey = sha256(source | nativeId | resourceId)`.
**Why (Lab 6, step 11):** the starter's id was `sha256(assessment | resource)`, so each run overwrote the last; Cosmos held latest state, not history, and an older report's numbers could not be re-derived. Including runId makes history accumulate; keeping it deterministic within a run keeps retries idempotent; a stable findingKey lets the POA&M compute "first seen" from stored history.
**Trade-off:** storage grows linearly (roughly documents x 4 runs/day). At sandbox scale on serverless Cosmos that is cents per month. Production would add a TTL or roll-up after the retention period required by policy.

## ADR-009 Reports read only completed, fresh runs; absence is not a fix
**Decision:** reports select the newest run whose manifest says `completed` (never `partial`/`failed`/`started`) and refuse to publish if it is older than `MAX_RUN_AGE_HOURS` (13 h). The SAR counts a finding as fixed only on an explicit fail -> pass; disappeared findings are listed as "no longer observed".
**Why (Lab 6, steps 11 and 13):** the starter selected the run of the newest document, which could be a sweep still being written. And Lab 6 deliberately did not treat the absence of a public-access finding as proof of the fix; it found the explicit Healthy record. The reports now encode that same evidentiary standard.

## ADR-010 One execution ID per report, manifest written last
**Decision:** every report execution writes into `<report>/<date>/<timestamp>-<executionId>/` and writes `manifest.json` (file SHA-256s, run lineage, verbatim queries) after all artifacts.
**Why (Lab 6, step 12):** same-day paths collided with `overwrite=False` (HTTP 500), the JSON/XLSX pair had different timestamps, and a partial upload would leave half a pair. Now a folder without a manifest is, by contract, incomplete; WORM makes each file immutable and the manifest makes the set verifiable.

## ADR-011 The remediation identity's role is its job
**Decision:** custom `tf-storage-baseline-remediator`: storage account read/write and resource group read; listKeys, regenerateKey and delete explicitly excluded.
**Why (Lab 6, step 2):** "a narrow policy operation does not make the identity's permissions equally narrow." Storage Account Contributor would let the identity read every blob via listKeys or delete accounts.
**Nuance worth knowing:** the policy rule's `roleDefinitionIds` still names Storage Account Contributor. That field tells the portal which role to auto-grant a system-assigned identity; it grants nothing itself. This repo assigns its own narrower role to its own identity.
**Residual risk RISK-0002:** ARM cannot scope `storageAccounts/write` to one property. Compensating control: stage 07 tripwire 2 alerts on any operation by this identity outside its lane, and all its writes are attributable by caller.

## ADR-012 Collector and reporter keep system-assigned identities
**Decision:** keep the starter's system-assigned identities for the two function apps; the remediation identity is user-assigned.
**Why:** the rubric's requirement is separate identities with role scopes that enforce segregation of duties, which these are (see ARCHITECTURE identity table). The remediation identity must be user-assigned because policy assignments reference it by ID and its Activity Log caller ID must be stable across redeploys. Converting the apps would add re-grant churn for no control benefit.

## Risk register (accepted, with owners and exits)

| ID | Risk | Compensating control | Exit | Review by |
|---|---|---|---|---|
| RISK-0001 | Y1 runtime storage uses a shared key | Holds no evidence; SAS policy bounds SAS lifetime; per-address expiring gate exception | Flex Consumption (ADR-007) | 2027-04-30 |
| RISK-0002 | `storageAccounts/write` is broader than one property | Tripwire 2; caller attribution | Azure Policy Modify with a property-scoped RBAC condition if it becomes available | 2027-04-30 |
| RISK-0003 | Platform-managed encryption keys on Cosmos and evidence storage | Infrastructure-level encryption at rest by default; Entra-only access | CMK in Key Vault with rotation | 2027-04-30 |
| RISK-0004 | Evidence storage is LRS | WORM, versioning, soft delete, delete lock | GRS/RA-GRS once replication change is validated non-destructive | 2027-04-30 |
| RISK-0005 | CI planner can call listKeys | Read-only otherwise; no state write; same-repo PRs only | Flex Consumption (ADR-007) | 2027-04-30 |
