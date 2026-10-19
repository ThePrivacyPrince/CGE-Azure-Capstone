# Design decisions

Why the non-obvious choices were made, what was traded away, and what production would do instead. Each decision names the starter behavior it changed (if any) and the evidence that motivated it. The scenario is FAFO Inc. (see the README). "Lab 6" refers to the Close-the-Loop lab run on 2026-10-17 ([evidence/LAB6-LOOP-CLOSURE.md](evidence/LAB6-LOOP-CLOSURE.md)).

## ADR-001 Extend the live deployment in place
**Decision:** every Terraform change is either additive or in-place. New containers (`findings`, `rbac`, `runs`) instead of re-partitioning `assessments`, and a retired container is forgotten by Terraform (`removed { destroy = false }`), never deleted; `moved` blocks to re-address the starter's enforcement policy into a `for_each` map; no attribute changes that force replacement on Cosmos or the evidence storage account.
**Why:** the capstone is graded on run history that accumulates over time. Replacing the evidence store would wipe that history and the Lab 6 evidence with it. Gate rule TF-EVD-001 now makes a delete/replace of evidence-plane resources unmergeable, so this is enforced, not just intended.

## ADR-002 Zero stored credentials, with one documented exception
**Decision:** HTTP triggers (which need function keys) are compiled out unless `ENABLE_MANUAL_TRIGGERS=true`, default off. Manual runs, when enabled, are labeled `trigger=manual` in the run manifest. Every data path uses Entra ID; Cosmos and evidence storage have key auth disabled.
**Exception:** the Y1 Consumption runtime storage (`func_internal`) needs a key-based connection. It holds host scratch data only, never evidence. It is excepted per address in `policy/exceptions.rego` as RISK-0001, expiring 2027-04-30, exit plan ADR-007.
**Lab 6 motivation:** "the collector's outbound access uses its managed identity; the manual HTTP invocation uses a function key - the whole interaction is not literally keyless."

## ADR-003 Regions: `eastus`, `eastus2`, `centralus`, armed by the measured gap
**Decision:** US-only allowed list containing exactly the regions the stages already use: `eastus` (foundation, workspace, enforcement assignments), `eastus2` (evidence store, because East US often lacks Cosmos capacity for new subscriptions), `centralus` (Function tier, because Y1 quota on free and new subscriptions is regional and often zero elsewhere). The policy's effect is computed: Audit while any resource sits outside the list, Deny once the inventory gap is zero.
**Why:** FAFO holds health data for hospital customers and is entering a federal pilot; both ask "where does the data live?" and "US" is a one-word answer. It maps to SA-9(5), which FAFO adds to its tailored Moderate baseline. Arming Deny blindly would block updates to any straggler, so the guardrail could cause the outage it exists to prevent. Discovery first, then activation of the measured gap, is the same pattern stage 02 uses for Defender plans.

## ADR-004 Effects: audit new controls, deny where earned, dry-run by default
- `fafo-storage-min-tls12` and `fafo-cosmos-no-local-auth` start at **Audit**: new controls first measure what they would break. Promote to Deny in a PR once the POA&M shows zero open findings for them.
- `cge-deny-public-blob` stays **Deny**: clear-cut, framework-mandated, and Lab 6 showed the Audit window is a controlled exception, not the baseline.
- Stage 06 defaults to **dry-run**: Modify is deployed, enforcement is off, and nothing changes until a reviewer approves a control key. Lab 6 confirmed that DoNotEnforce does not block an explicitly created remediation task, which is exactly the human-gated behavior wanted.

## ADR-005 Public network paths, Entra-only data access
**Decision:** Cosmos, the evidence storage account and the function apps keep public endpoints. Every data operation still requires an Entra ID token for a role-holding identity; shared keys are off.
**Why:** Y1 Consumption functions cannot use VNet integration or private endpoints, and private networking for a single-subscription course sandbox would add cost and teardown complexity without changing what the rubric measures.
**Production answer:** Flex Consumption or Premium functions with VNet integration, private endpoints for Cosmos and Blob, public network access disabled. Checkov's network findings are skipped inline with this ADR as the reason.

## ADR-006 CI plans, humans apply
**Decision:** the CI identity is read-only (custom `fafo-grc-ci-planner` role + Blob Data Reader on state). PR plans and drift plans run `-lock=false`. Applies are run by a human from a terminal after the PR merges.
**Why (Lab 6, step 3):** the starter's arming script gave the CI identity Contributor at `mg-grc` and write access to state, while the workflow was "plan-only". A workflow file is editable by the PR it gates, so it cannot be its own security boundary; the identity's actual permissions are the boundary. Fork PRs get a credential-free job only (`static`), and the privileged `plan` job refuses to run unless the PR's head repo is this repo.
**Residual risk RISK-0005:** azurerm's refresh reads secrets, so the planner role holds three actions that return them: storage `listKeys` (the Y1 runtime storage key, which is also in state), `Microsoft.Web/sites/config/list/action` (the function app settings, which carry that same key as the `AzureWebJobsStorage` connection string), and Cosmos `listKeys`/`listConnectionStrings` (the evidence account's keys). The Cosmos keys are inert: key auth is disabled on the account, and gate rule TF-STG-005 plus policy `fafo-cosmos-no-local-auth` keep it that way. The identity can read but not change anything, and only same-repo PRs and `main` can use it. Removing Y1 (ADR-007) removes the storage key.
**Production answer:** a separate apply identity bound to a protected GitHub environment with required reviewers, federated only on `environment:production`.

## ADR-007 Stay on Y1 Consumption for the capstone
**Decision:** keep the starter's Y1 function apps; do not migrate to Flex Consumption now.
**Why:** a plan change replaces the function apps (new names, new system-assigned identities, re-granted roles) mid-capstone, for no change in what is graded, and Y1 is what the course validated quota for.
**Exit plan:** Flex Consumption supports identity-based host storage, which removes the last shared key (RISK-0001) and the planner's `listKeys` (RISK-0005).

## ADR-008 Evidence history: one document per finding per run
**Decision:** `id = sha256(runId | findingKey)`, `findingKey = sha256(source | nativeId | resourceId)`. First built as the `snapshots` container on `/runId`; now the `findings` container on `[/subscriptionId, /runId]` (ADR-015).
**Why (Lab 6, step 11):** the starter's id was `sha256(assessment | resource)`, so each run overwrote the last; Cosmos held latest state, not history, and an older report's numbers could not be re-derived. Including runId makes history accumulate; keeping it deterministic within a run keeps retries idempotent; a stable findingKey lets the POA&M compute "first seen" from stored history.
**Trade-off:** storage grows linearly (roughly documents x 4 runs/day). At sandbox scale on serverless Cosmos that is cents per month. Production would add a TTL or roll-up after the retention period required by policy.

## ADR-009 Reports read only completed, fresh runs; absence is not a fix
**Decision:** reports select the newest run whose manifest says `completed` (never `partial`/`failed`/`started`) and refuse to publish if it is older than `MAX_RUN_AGE_HOURS` (13 h). The SAR counts a finding as fixed only on an explicit fail -> pass; disappeared findings are listed as "no longer observed".
**Why (Lab 6, steps 11 and 13):** the starter selected the run of the newest document, which could be a sweep still being written. And Lab 6 deliberately did not treat the absence of a public-access finding as proof of the fix; it found the explicit Healthy record. The reports now encode that same evidentiary standard.

## ADR-010 One execution ID per report, manifest written last
**Decision:** every report execution writes into `<report>/<date>/<timestamp>-<executionId>/` and writes `manifest.json` (file SHA-256s, run lineage, verbatim queries) after all artifacts.
**Why (Lab 6, step 12):** same-day paths collided with `overwrite=False` (HTTP 500), the JSON/XLSX pair had different timestamps, and a partial upload would leave half a pair. Now a folder without a manifest is, by contract, incomplete; WORM makes each file immutable and the manifest makes the set verifiable.

## ADR-011 The remediation identity's role is its job
**Decision:** custom `fafo-storage-baseline-remediator`: storage account read/write and resource group read; listKeys, regenerateKey and delete explicitly excluded.
**Why (Lab 6, step 2):** "a narrow policy operation does not make the identity's permissions equally narrow." Storage Account Contributor would let the identity read every blob via listKeys or delete accounts.
**Nuance worth knowing:** the policy rule's `roleDefinitionIds` still names Storage Account Contributor. That field tells the portal which role to auto-grant a system-assigned identity; it grants nothing itself. This repo assigns its own narrower role to its own identity.
**Residual risk RISK-0002:** ARM cannot scope `storageAccounts/write` to one property. Compensating control: stage 07 tripwire 2 alerts on any operation by this identity outside its lane, and all its writes are attributable by caller.

## ADR-012 Collector and reporter keep system-assigned identities
**Decision:** keep the starter's system-assigned identities for the two function apps; the remediation identity is user-assigned.
**Why:** the rubric's requirement is separate identities with role scopes that enforce segregation of duties, which these are (see ARCHITECTURE identity table). The remediation identity must be user-assigned because policy assignments reference it by ID and its Activity Log caller ID must be stable across redeploys. Converting the apps would add re-grant churn for no control benefit.

## ADR-013 Framework track: federal, NIST SP 800-53 Rev. 5 Moderate
**Decision:** FAFO serves the federal pilot first. NIST SP 800-53 Rev. 5 is the single control catalog for the crosswalk, POA&M, SAR and SSP. The baseline is Moderate, tailored with one addition, SA-9(5) (processing, storage and service location), in [oscal/fafo-moderate-profile.json](../oscal/fafo-moderate-profile.json). The SSP and POA&M go out as OSCAL 1.1.2.
**Why federal over healthcare or enterprise:** three reasons, in order. (1) **Coherence:** the pipeline's report formats (POA&M with FedRAMP remediation timelines, SAR) are federal artifacts already, so the track, catalog and report formats agree without inventing anything. (2) **Reach:** 800-53 is the superset. The hospital network's HIPAA Security Rule safeguards and the enterprise buyers' SOC 2 criteria are both routinely crosswalked *from* 800-53, so serving the strictest buyer first leaves the other two as mapping exercises, not rebuilds. (3) **Proof:** a federal reviewer recomputes, so every control ID here is checked against NIST's own OSCAL catalog ([frameworks/nist-800-53-rev5.json](../frameworks/nist-800-53-rev5.json), generated from usnistgov/oscal-content) and must be active and in the tailored baseline (`tests/test_catalog.py`).
**What was removed:** PCI DSS, GLBA and SOC 2 columns and mappings from an earlier fintech framing. A crosswalk to five frameworks for a company that has picked one would be incoherent, and every extra mapping is another ID that can be wrong. CONTROLS.md keeps a NIST CSF 2.0 category column because the published capstone rubric asks for it; it's an informative cross-reference, and nothing is collected or scored against it.

## ADR-014 Scale by scope, not by size
**Decision:** nothing names a subscription. Assignments are at the management group. Discovery runs over the management group (Resource Graph for regions; `all_subscription_ids` for Defender plans and Activity Log routing). The collector's roles are at the management group, and it collects whatever subscriptions those roles reach. Membership is an association resource, not the management group's `subscription_ids` list.
**Why:** FAFO has three subscriptions; the sandbox has one. A pipeline that only works because it was told the subscription ID is a one-subscription pipeline. With scope as the unit, moving FAFO's other two subscriptions under `mg-grc-sandbox` is the whole onboarding: policy inherits immediately, the collector picks them up on its next run, and the nightly drift plan flags stages 02 and 07 until they're applied (ARCHITECTURE, "what happens when FAFO's second subscription arrives").
**The trap avoided:** declaring `subscription_ids` on the management group makes Terraform the owner of membership. The next apply would move every hand-onboarded subscription back out. `lifecycle { ignore_changes = [subscription_ids] }` plus an association resource keeps Terraform responsible for the sandbox subscription only.
**Trade-off:** per-subscription settings that Azure Policy can't inherit (Defender plan tiers, the subscription Activity Log setting) converge on the next apply, not instantly. The drift workflow is the safety net that makes that delay visible.

## ADR-015 Hierarchical partition keys `[/subscriptionId, /runId]` for findings and rbac
**Decision:** `findings` and `rbac` use Cosmos hierarchical partition keys, subscription first and run second. `runs` stays on `/runId`. The old `/runId`-partitioned `snapshots` container is retired, not deleted.
**Why:** see the comparison table in [ARCHITECTURE.md](ARCHITECTURE.md#why-subscriptionid-runid-the-partition-key-chosen-on-purpose). In short: subscription first, so a new subscription is a new partition and the store never needs reshaping. Run second, so one subscription's ever-growing history never concentrates in a single logical partition (20 GB cap). Every report's hot read ("this run, every subscription") stays a small, bounded fan-out.
**Trade-off:** a partition key can't be changed in place, so moving from `snapshots` to `findings` starts history afresh in the new container. Reports and first-seen dates read `findings` only. The older documents stay in Azure, untouched, for anyone who needs them.

## ADR-016 A role-assignment collector with its own container
**Decision:** the collector also snapshots every role assignment that applies to each subscription (including inherited MG and root grants) into an `rbac` container, sealed per run like findings. The SAR recounts privileged access from it.
**Why:** Defender says what is misconfigured; it doesn't say who can change things. "Who holds Owner, since when, and through which scope?" is the first access-control question a federal reviewer asks (AC-2, AC-6(5), AC-6(7)). It's also the population `fafo-audit-subscription-owner` evaluates, so the claim has two independent sources: Azure Policy compliance and the stored snapshots. The documents are a different shape and are reviewed as a population, so they get their own container instead of polluting `findings`.

## ADR-017 KQL lives in files, and the files are the alert rules
**Decision:** every tripwire query is a `.kql` file under [kql/](../kql/) with a header naming FAFO's question, the data source and the 800-53 controls. Stage 07 loads the same files with `templatefile`. `tests/test_kql.py` proves the placeholders match what stage 07 passes.
**Why:** a query pasted into Terraform heredocs can't be read, reviewed or run on its own, and a query kept only in a doc drifts from the one that runs. One file serves both. Two of the four (off-hours changes, Key Vault secret reads by non-pipeline identities) are FAFO's own questions; `remediator-out-of-lane` is FAFO's compensating control for RISK-0002; `unexpected-writer` is the course's baseline, labeled as such.
**Supporting control:** the secret-read query needs Key Vault audit logs in the workspace, so `fafo-dine-keyvault-audit-logs` deploys them for every vault in every governed subscription.

## ADR-018 OSCAL SSP generated from reviewed data, validated against NIST's schemas
**Decision:** [oscal/ssp.json](../oscal/ssp.json) is generated by `scripts/generate_ssp.py` from [frameworks/ssp-implementation.json](../frameworks/ssp-implementation.json): 12 components (each naming the code that implements it) and per-control implementation statements. The reporter writes `poam.oscal.json` with every POA&M. Both, and the tailored profile, are validated against the official OSCAL 1.1.2 JSON schemas vendored in `tests/schemas/`.
**Why:** hand-edited OSCAL JSON is unreviewable and drifts. Generated OSCAL from a small, readable source makes every change to the plan a reviewed diff, and the tests make it impossible to claim a control that doesn't exist, sits outside the baseline, or names a component whose code is missing.

## ADR-019 The submission is an evidence package
**Decision:** `scripts/export_submission.py` exports, from the live environment, what a reviewer who can't log in needs: per-stage plans, every pipeline identity's role assignments, policy definitions and assignments, the run's documents, the latest reports byte-for-byte, a refused WORM delete, shared-key status, run history and the OSCAL documents. `scripts/verify_submission.py` cross-checks them against the code offline, the way the grader does.
**Why:** the grader reads code and evidence and looks for gaps between them ("three custom policies in code, two assigned"). Running that cross-check first turns a would-be deduction into a fix.
**Guardrails:** raw plan JSON is never exported (it carries sensitive values in clear text). Keys and the operator's e-mail and UPN are scrubbed from every file, and `MANIFEST.json` hashes every file so post-export edits are detectable.

## ADR-020 Corrective controls take their effect as a parameter
**Decision:** `cge-fix-public-blob` and `fafo-fix-min-tls` declare `effect` as a parameter (`Modify` / `Disabled`); the assignment passes `local.effect` from `remediation_mode`. In `audit` mode the corrective control is `Disabled` and the paired detective control in stage 01 keeps reporting the gap.
**Why:** an effect baked into the rule means escalating is an edit to the rule; a parameter means escalating is a reviewed variable change, and the rule an assessor reviewed stays the rule that runs. `Audit` isn't offered on a Modify definition because a Modify rule's `details` block isn't valid under Audit, so "observe only" belongs to the detective twin.

## Risk register (accepted, with owners and exits)

| ID | Risk | Compensating control | Exit | Review by |
|---|---|---|---|---|
| RISK-0001 | Y1 runtime storage uses a shared key | Holds no evidence; SAS policy bounds SAS lifetime; per-address expiring gate exception | Flex Consumption (ADR-007) | 2027-04-30 |
| RISK-0002 | `storageAccounts/write` is broader than one property | Tripwire 2; caller attribution | Azure Policy Modify with a property-scoped RBAC condition if it becomes available | 2027-04-30 |
| RISK-0003 | Platform-managed encryption keys on Cosmos and evidence storage | Infrastructure-level encryption at rest by default; Entra-only access | CMK in Key Vault with rotation | 2027-04-30 |
| RISK-0004 | Evidence storage is LRS | WORM, versioning, soft delete, delete lock | GRS/RA-GRS once replication change is validated non-destructive | 2027-04-30 |
| RISK-0005 | CI planner can read the Y1 storage key (listKeys, app settings) and the Cosmos keys | Read-only otherwise; no state write; same-repo PRs only; Cosmos keys inert (key auth disabled, TF-STG-005) | Flex Consumption (ADR-007) | 2027-04-30 |
