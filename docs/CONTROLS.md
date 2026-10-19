# Control Mappings

Every policy, collector, report, gate rule and detector in this repository, mapped to the **NIST SP 800-53 Rev. 5** controls it implements. That's FAFO's control catalog on the federal track, tailored from the Moderate baseline in [oscal/fafo-moderate-profile.json](../oscal/fafo-moderate-profile.json). Each row also carries the **NIST CSF 2.0** category the published capstone rubric asks for.

**One catalog, one answer.** 800-53 Rev. 5 is the only catalog in the crosswalk ([frameworks/mappings.json](../frameworks/mappings.json)), the POA&M, the SAR scorecard and the OSCAL SSP ([oscal/ssp.json](../oscal/ssp.json)). The CSF 2.0 column is an informative cross-reference (NIST publishes the official CSF ↔ 800-53 mapping). It's not a second framework, and nothing is collected or scored against it.

**Machine-checked, not just written down.** Tests fail CI if this file drifts from the code:

| Test | Fails when |
|---|---|
| `tests/test_catalog.py::test_every_800_53_id_in_controls_md_resolves` | a control cited here doesn't exist in Rev. 5, or was withdrawn |
| `tests/test_catalog.py::test_crosswalk_controls_all_appear_in_controls_md` | the crosswalk maps a control this file doesn't mention |
| `tests/test_catalog.py::test_every_crosswalk_control_is_in_the_tailored_baseline` | a mapped control is outside FAFO's tailored Moderate baseline |
| `tests/test_reports.py::test_every_policy_in_terraform_is_in_the_crosswalk` | a policy in Terraform is missing from the crosswalk |
| `self-check.sh` | a policy name in code isn't in this file |

Legend: **Type** = P preventive, D detective, C corrective, G governance. **Own** = FAFO's own control, beyond the course's taught set.

## Stage 01 - Foundation (the initiative, assigned at `mg-grc-sandbox`)

| Component | Type | Effect (default) | What it does | 800-53 Rev. 5 | CSF 2.0 |
|---|---|---|---|---|---|
| Management group hierarchy + initiative assignment at `mg-grc-sandbox` | G | n/a | Controls inherit to every current and future subscription; a new subscription is governed the moment it's moved in | CM-2, PL-2 | GV.PO, GV.OC |
| `cge-require-env-tag-rg` (taught) | D | Audit | Inventory hygiene; owner accountability for POA&M items | CM-8 | ID.AM |
| `cge-deny-public-blob` (taught) | P | Deny | Blocks public blob exposure at the API, before the resource exists | AC-3, AC-6, SC-7 | PR.DS, PR.AA |
| `cge-dine-storage-diagnostics` (taught) | C | DeployIfNotExists | Logging that enforces its own coverage, as the remediation identity | AU-2, AU-12, SI-4 | PR.PS, DE.CM |
| **`fafo-storage-min-tls12`** (own) | D | Audit (new control) | Storage must require TLS 1.2 for data in transit | SC-8, SC-8(1), SC-13 | PR.DS |
| **`fafo-cosmos-no-local-auth`** (own) | D | Audit | Cosmos DB must reject key auth, so every data-plane call is attributable | IA-2, IA-5, AC-2 | PR.AA |
| **`fafo-allowed-locations`** (own) | P/D | Audit until the measured gap is 0, then Deny | Data residency in approved US regions; effect decided by `discovery.tf` | SA-9(5), CM-2 | GV.OC, PR.PS |
| **`fafo-keyvault-purge-protection`** (own) | D | Audit | Key vaults must have purge protection, so keys guarding customer data can't be destroyed inside retention | SC-12, CP-9 | PR.DS |
| **`fafo-audit-subscription-owner`** (own) | D | Audit | Every standing Owner assignment at subscription scope becomes a finding | AC-6(5), AC-6(7) | PR.AA |
| **`fafo-dine-keyvault-audit-logs`** (own) | C | DeployIfNotExists | Key Vault `AuditEvent` logs reach the GRC workspace (data source for the secret-read tripwire) | AU-2, AU-6, AU-12 | DE.CM, PR.PS |
| `discovery.tf` (Resource Graph inventory across the MG → `region_gap`) | G | read-only | Measures before it arms; output is the migration list | CM-8, CM-2 | ID.AM |
| Remediation identity `id-grc-remediation-dev` (user-assigned) | G | n/a | Every automated change has one named, filterable author | AC-6, AC-5 | PR.AA, GV.RR |
| Log Analytics workspace | D | n/a | Central audit trail beyond the 90-day Activity Log default | AU-6, AU-11 | DE.CM |

## Stage 02 - Activation

| Component | Type | What it does | 800-53 Rev. 5 | CSF 2.0 |
|---|---|---|---|---|
| Defender plan discovery (`azapi` reads, every subscription under the MG) | G | Detects which baseline plans are already on; the gap map is an output | CA-7, RA-5 | ID.AM, ID.RA |
| Defender plan activation (only the gap, every subscription) | D | Converges the baseline to Standard without touching anything outside it | RA-5, SI-4 | DE.CM |
| Built-in NIST SP 800-53 Rev. 5 initiative, assigned at the management group | D | Platform-native assessment against FAFO's catalog | CA-2, CA-7 | GV.OV, ID.IM |

### Defender assessments the crosswalk maps (collected, never re-collected per framework)

| Crosswalk key | Type | Assessment | 800-53 Rev. 5 | CSF 2.0 |
|---|---|---|---|---|
| `defender:storage-public-access` | D | storage account public access disallowed | AC-3, SC-7, CA-7 | DE.CM, PR.DS |
| `defender:storage-shared-key` | D | storage accounts prevent shared key access | IA-2, AC-6 | DE.CM, PR.DS |
| `defender:storage-network-restriction` | D | storage network access restricted (VNet rules / private link) | SC-7, AC-4 | DE.CM, PR.DS |
| `defender:secure-transfer` | D | secure transfer to storage accounts enabled | SC-8 | DE.CM, PR.DS |
| `defender:mfa-privileged` | D | MFA on accounts with privileged permissions | IA-2(1) | DE.CM, PR.DS |

## Stage 03 - Evidence store and collector

| Component | Type | What it does | 800-53 Rev. 5 | CSF 2.0 |
|---|---|---|---|---|
| Cosmos DB, Entra-only (`local_authentication_enabled = false`, key-based metadata writes blocked) | P | The evidence database FAFO owns; no keys to steal | IA-2, AC-3 | PR.AA, PR.DS |
| `findings` container (one doc per finding per run, key `[/subscriptionId, /runId]`) | D | Evidence history; first-seen dates; any past report re-derivable; scales by subscription | AU-11, CA-7 | ID.IM, GV.OV |
| **`rbac` container + role-assignment collector** (own schema extension) | D | Who can act on each subscription, per run, including inherited grants; feeds access reviews | AC-2, AC-6(7) | PR.AA, ID.AM |
| `runs` container (manifests with per-subscription results and a seal per container) | D | Reports only use completed runs; add, remove or edit a sealed document and reports refuse to publish | SI-7, SI-7(1), AU-9 | PR.DS |
| `assessments` container (latest-state view, kept from the starter) | D | Backward-compatible "now" view | CA-7 | ID.RA |
| `mappings` container (versioned crosswalk) | G | Collect once, map to the catalog; each run records the crosswalk version | CA-2 | GV.OV |
| WORM immutability policy on `reports` (90 days) | P | Report artifacts can't be altered or deleted within retention | AU-9, AU-11 | PR.DS |
| Evidence storage: shared keys off, OAuth default, versioning, soft delete, change feed | P | Identity or nothing; recoverable deletes | IA-2, CP-9 | PR.AA, PR.DS |
| CanNotDelete locks on Cosmos and evidence storage | P | Destroying evidence is a deliberate two-step act | AU-9, CM-5 | PR.DS |
| Data-plane diagnostic settings (Cosmos, evidence blob) | D | Who read or wrote evidence is itself evidence; WORM delete attempts are logged | AU-2, AU-12 | DE.CM |
| **Collector**: subscriptions discovered from MG-scoped roles; Defender assessments, Policy states, role assignments; every 6 h | D | Continuous control testing with lineage (runId, collectedAt, sourceEvaluatedAt, findingKey) | CA-7, RA-5, SI-4 | DE.CM, ID.RA |
| Collector identity: Security Reader + `fafo-grc-policy-state-reader` at the MG, Cosmos data contributor | P | Can observe and record; can't change what it observes or author reports | AC-5, AC-6 | PR.AA, GV.RR |
| HTTP triggers off by default; manual runs labeled in the manifest | P | No function keys; run history can't be padded unnoticed | IA-5, AU-6 | PR.AA, GV.OV |

## Stage 04 - Reporting

| Component | Type | What it does | 800-53 Rev. 5 | CSF 2.0 |
|---|---|---|---|---|
| **POA&M generator** (daily; JSON, XLSX, **OSCAL 1.1.2**) | G | Open findings with stable IDs, first-seen from history, FedRAMP-timeline due dates, 800-53 mapping, overdue flag | CA-5, RA-3 | ID.RA, ID.IM |
| **SAR + control scorecard** (daily) | D | Per-control pass/fail grouped by 800-53 family; change since previous run (explicit fixes only); privileged-access recount from `rbac` | CA-2, CA-7, AC-6(7) | GV.OV, ID.IM |
| Completed-runs-only, stale-evidence refusal, seal verification | P | A partial sweep, a stalled collector or altered evidence can't produce numbers that look current | CA-7, SI-7 | GV.OV, ID.IM |
| Report manifest (execution ID, file SHA-256s, verbatim queries) written last | D | Every number traces to a stored query; incomplete executions are identifiable | SI-7, AU-9 | PR.DS |
| Reporter identity: Cosmos read + custom `fafo-grc-report-writer` (no delete) on `reports` only, **no ARM role** | P | Can't call live platform APIs or write evidence: segregation of duties by role scope | AC-5, AC-6 | PR.AA, GV.RR |
| **OSCAL SSP** ([oscal/ssp.json](../oscal/ssp.json)), generated from [frameworks/ssp-implementation.json](../frameworks/ssp-implementation.json) | G | The system security plan as machine-readable OSCAL, schema-validated in CI | PL-2, CA-2 | GV.PO |

## Stage 06 - Enforcement

| Component | Type | Effect | What it does | 800-53 Rev. 5 | CSF 2.0 |
|---|---|---|---|---|---|
| `cge-fix-public-blob` (taught) | C | Disabled / Modify (ladder, parameter) | Sets allowBlobPublicAccess=false through the remediation identity | CM-6, SI-2 | PR.PS, RS.MI |
| **`fafo-fix-min-tls`** (own) | C | Disabled / Modify (ladder, parameter) | Sets minimumTlsVersion=TLS1_2 | CM-6, SC-8(1) | PR.PS, PR.DS |
| `remediation_mode` (audit → dry-run → enforce) | G | n/a | Escalation is a reviewed diff in a CODEOWNERS path | CM-3, CM-5 | GV.PO, GV.RR |
| **Approval gate as code** (`approved_remediations` + required ticket → remediation task) | G | n/a | Automation acts, a human authorizes; git history is the approval log | CM-3, CM-4 | GV.RR, ID.RA |
| Custom `fafo-storage-baseline-remediator` role (no listKeys, no delete) | P | n/a | The remediation identity's permissions are its job, nothing more | AC-6, AC-6(1) | PR.AA |

## Stage 07 - Detection (every governed subscription's Activity Log, four KQL tripwires)

| Component | Type | FAFO question it answers | 800-53 Rev. 5 | CSF 2.0 |
|---|---|---|---|---|
| Activity Log routing for every subscription under the MG (Lab 2's setting adopted via `import`) | D | Is every control-plane write in the estate recorded centrally? | AU-2, AU-6 | DE.CM, PR.PS |
| Tripwire `unexpected-writer` ([kql](../kql/unexpected-writer.kql), course-derived) | D | Who is touching reality outside the approved path? | CM-3, AU-6, SI-4 | DE.CM, DE.AE |
| **Tripwire `remediator-out-of-lane`** ([kql](../kql/remediator-out-of-lane.kql), own) | D | Did the one identity allowed to fix things do anything else? | AC-6, AC-6(9), AU-6 | DE.CM, PR.AA |
| **Tripwire `off-hours-admin-changes`** ([kql](../kql/off-hours-admin-changes.kql), own) | D | Are people changing the environment outside the change window? | AC-2, AU-6, CM-3 | DE.CM, DE.AE |
| **Tripwire `keyvault-secret-reads-non-pipeline`** ([kql](../kql/keyvault-secret-reads-non-pipeline.kql), own) | D | Who, other than the pipeline, is reading the secrets that guard customer data? | AC-6(9), AU-6, SI-4 | DE.CM, PR.AA |
| State-backend postconditions (shared keys off, versioning, soft delete, TLS) | D | The state account is a controlled resource, re-verified on every drift run | CM-6, AU-9 | PR.DS, DE.CM |

## Repo gates and pipeline operations

Gate rules live in [policy/](../policy/); each has unit tests in `policy/gate_test.rego`.

| Rule / component | Mistake it makes unmergeable | 800-53 Rev. 5 | CSF 2.0 |
|---|---|---|---|
| TF-IAM-001 `broad_roles.rego` | Owner / Contributor / UAA / RBAC Admin grants, by name **or** GUID | AC-6, AC-6(5) | PR.AA |
| TF-IAM-002 | Custom roles with `*` actions | AC-6 | PR.AA |
| TF-POL-001 `policy_identity.rego` | Remediating assignment without an identity (fails closed when unprovable, including parameterized effects) | CM-6 | PR.PS |
| TF-POL-002 | Remediation through a system-assigned identity instead of the named one | AC-6, AU-3 | PR.AA, GV.RR |
| TF-STG-001..004 `storage.rego` | Public blobs, shared keys, TLS < 1.2, HTTP | SC-7, SC-8, IA-2 | PR.DS |
| TF-STG-005 | Cosmos key auth re-enabled | IA-2 | PR.AA |
| TF-STG-900 (warn) | Security attribute unknown at plan time; the gate says it can't see it | CA-7 | ID.IM |
| `exceptions.rego` | Exceptions are per address, ticketed, CODEOWNERS-reviewed, and expire | CA-7, RA-7 | GV.RM |
| TF-EVD-001/002 `evidence_protection.rego` | Deleting or replacing the evidence plane; shortening WORM retention | AU-9, AU-11 | PR.DS |
| `gate.yml` static job (no credentials, every PR) | Untested rules, failing tests, secrets, IaC lint findings | SA-11, CM-3 | PR.PS |
| `gate.yml` plan job (read-only identity, same-repo PRs) | A real plan that violates any rule above | CM-3, CM-4 | PR.PS, GV.SC |
| `drift.yml` (nightly plan per stage, `-detailed-exitcode`; a plan that errors fails the job) | Reality drifting from code unnoticed; a new subscription missing Defender or Activity Log routing | CM-3, CM-6 | DE.CM, ID.IM |
| CODEOWNERS on enforcement, policy, crosswalk, workflows | Control changes merging without review | CM-5 | GV.RR, GV.PO |
| Submission bundle (`scripts/export_submission.py` + `verify_submission.py`) | Code and deployed estate disagreeing without anyone noticing | CA-2, CA-7 | GV.OV |
