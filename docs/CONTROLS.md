# Control Mappings

Every policy, collector, report, gate rule and detector in this repo, mapped to the NIST CSF 2.0 category (and subcategory where it is unambiguous) it serves, with NIST SP 800-53 Rev. 5 and the Tallyfin-relevant obligations: PCI DSS 4.0.1 and the GLBA Safeguards Rule (16 CFR 314.4).

The same mappings live as **data** in [`frameworks/mappings.json`](../frameworks/mappings.json); the reports read them from the store, and `tests/test_reports.py::test_every_policy_in_terraform_is_in_the_crosswalk` fails CI if a policy in Terraform is missing from the crosswalk. Keep this file and that one in step.

Legend: **Type** = P preventive, D detective, C corrective, G governance.

## Stage 01 - Foundation

| Component | Type | Effect | What it does | CSF 2.0 | 800-53 | PCI DSS 4.0.1 / GLBA |
|---|---|---|---|---|---|---|
| Management group hierarchy + initiative assignment at `mg-grc-sandbox` | G | n/a | Controls inherit to every current and future subscription | GV.PO, GV.OC | PL-1, CM-2 | 12.1.1 / 314.4(c) |
| `cge-require-env-tag-rg` | D | Audit | Inventory hygiene; owner accountability for POA&M items | ID.AM (ID.AM-01) | CM-8, PM-5 | 12.5.1 / 314.4(c)(2) |
| `cge-deny-public-blob` | P | Deny | Blocks public blob exposure at the API, before the resource exists | PR.DS (PR.DS-01), PR.AA (PR.AA-05) | AC-3, SC-7 | 1.4.1, 7.2.1 / 314.4(c)(1) |
| `cge-dine-storage-diagnostics` | C | DeployIfNotExists | Logging that enforces its own coverage, as the remediation identity | PR.PS (PR.PS-04), DE.CM (DE.CM-09) | AU-2, AU-12, SI-4 | 10.2.1, 10.4.1 / 314.4(c)(8) |
| **`tf-storage-min-tls12`** (own) | D | Audit (new control) | Storage must require TLS 1.2 | PR.DS (PR.DS-02) | SC-8, SC-13 | 4.2.1 / 314.4(c)(3) |
| **`tf-cosmos-no-local-auth`** (own) | D | Audit | Cosmos DB must reject key auth so every data-plane call is attributable | PR.AA (PR.AA-01, PR.AA-03) | IA-2, IA-5, AC-2 | 8.2.1, 8.6.2 / 314.4(c)(1) |
| **`tf-allowed-locations`** (own) | P/D | Audit until measured gap = 0, then Deny | Data residency for consumer financial data; effect decided by `discovery.tf` | GV.OC (GV.OC-03), PR.PS (PR.PS-01) | SA-9(5), CM-7 | 12.5.2 / 314.4(c)(2) |
| `discovery.tf` (subscription inventory -> `region_gap`) | G | read-only | Measures before it arms; output is the migration list | ID.AM (ID.AM-01) | CM-8 | 12.5.1 |
| Remediation identity (user-assigned) | G | n/a | Every automated change has one named, filterable author | PR.AA (PR.AA-05), GV.RR | AC-6, AU-3 | 7.2.1, 10.2.2 |
| Log Analytics workspace | D | n/a | Central audit trail beyond the 90-day Activity Log default | DE.CM, PR.PS (PR.PS-04) | AU-6, AU-11 | 10.5.1 / 314.4(c)(8) |

## Stage 02 - Activation

| Component | Type | What it does | CSF 2.0 | 800-53 |
|---|---|---|---|---|
| Defender plan discovery (`azapi` reads) | G | Detects which baseline plans are already on; the gap map is an output | ID.AM, ID.RA | CA-7, RA-5 |
| Defender plan activation (only the gap) | D | Converges the baseline to Standard without touching anything outside it | DE.CM (DE.CM-09) | SI-4, RA-5 |
| NIST CSF 2.0 regulatory compliance assignment | D | Platform-native CSF assessment, adopted into code | GV.OV, ID.IM | CA-2 |

## Stage 03 - Evidence store

| Component | Type | What it does | CSF 2.0 | 800-53 | PCI DSS 4.0.1 / GLBA |
|---|---|---|---|---|---|
| Cosmos DB, Entra-only (`local_authentication_enabled = false`, metadata writes by key blocked) | P | The evidence database we own; no keys to steal | PR.AA (PR.AA-01), PR.DS (PR.DS-01) | IA-2, AC-3 | 8.2.1 / 314.4(c)(1) |
| `snapshots` container (one doc per finding per run) | D | Evidence history; first-seen dates; any past report re-derivable | ID.IM, GV.OV | AU-11, CA-7 | 10.5.1 / 314.4(d)(2) |
| `runs` container (run manifests + document-set digest) | D | Reports only use completed runs; tamper with a sealed run and the digest breaks | PR.DS (PR.DS-01) | AU-9, SI-7 | 10.3.2 |
| `assessments` container (latest-state view, kept from the starter) | D | Backward-compatible "now" view | ID.RA | CA-7 | - |
| `mappings` container (versioned crosswalk) | G | Collect once, map to every framework; each run records the crosswalk version | GV.OV, GV.PO | PM-9 | 12.4.1 |
| WORM immutability policy on `reports` | P | Report artifacts can't be altered or deleted within retention | PR.DS (PR.DS-01, PR.DS-11) | AU-9, AU-11 | 10.3.2, 10.5.1 / 314.4(c)(8) |
| Evidence storage: shared keys off, OAuth default, soft delete, change feed | P | Identity or nothing; recoverable deletes | PR.AA, PR.DS | IA-2, CP-9 | 8.2.2 |
| CanNotDelete locks on Cosmos + evidence storage | P | Destroying evidence is a deliberate two-step act | PR.DS (PR.DS-11) | AU-9, CM-5 | 10.3.2 |
| Data-plane diagnostic settings (Cosmos, evidence blob) | D | Who read or wrote evidence is itself evidence; WORM delete attempts are logged | DE.CM (DE.CM-03, DE.CM-09) | AU-2, AU-12 | 10.2.1 / 314.4(c)(8) |
| **Collector**: Defender assessments + **Azure Policy states**, timer every 6h | D | Continuous control-test capture with lineage (runId, collectedAt, sourceEvaluatedAt, findingKey) | DE.CM (DE.CM-09), ID.RA (ID.RA-01) | CA-7, RA-5 | 11.3.1 / 314.4(d)(2) |
| Collector identity: Security Reader + `tf-grc-policy-state-reader` + Cosmos write | P | Can observe and record; cannot change what it observes or author reports | PR.AA (PR.AA-05), GV.RR | AC-5, AC-6 | 7.2.2 |
| HTTP triggers off by default; manual runs labeled in the manifest | P | No function keys; run history can't be padded unnoticed | PR.AA, GV.OV | IA-5, AU-10 | 8.3.1 |

## Stage 04 - Reporting

| Component | Type | What it does | CSF 2.0 | 800-53 | PCI DSS 4.0.1 / GLBA |
|---|---|---|---|---|---|
| **POA&M generator** (daily) | G | Open findings with stable IDs, first-seen from history, SLA-dated due dates, framework mapping, overdue flag | ID.RA (ID.RA-06), ID.IM (ID.IM-01) | CA-5, PM-4 | 6.3.1, 12.4.2 / 314.4(b)(2) |
| **SAR + framework scorecard** (daily) | D | Assessment report; per-requirement pass/fail across 5 frameworks; change since previous run (explicit fixes only) | GV.OV (GV.OV-01), ID.IM | CA-2, CA-7 | 12.4.1 / 314.4(i) |
| Reports read only completed runs; stale-evidence refusal | P | A partial sweep or a stalled collector can't produce numbers that look current | GV.OV, ID.IM | CA-7, SI-4 | - |
| Report manifest (execution ID, file SHA-256s, verbatim queries) written last | D | Every number traces to a stored query; incomplete executions are identifiable | PR.DS (PR.DS-01) | AU-10, SI-7 | 10.3.2 |
| Reporter identity: Cosmos read + custom `tf-grc-report-writer` (no delete) on `reports` only, **no ARM role** | P | Can't call live platform APIs or write evidence: SoD enforced by role scope | PR.AA (PR.AA-05), GV.RR | AC-5, AC-6 | 7.2.2 |

## Stage 06 - Enforcement

| Component | Type | Effect | What it does | CSF 2.0 | 800-53 | PCI DSS 4.0.1 / GLBA |
|---|---|---|---|---|---|---|
| `cge-fix-public-blob` | C | Audit / Modify (ladder) | Sets allowBlobPublicAccess=false through the remediation identity | PR.PS (PR.PS-01), RS.MI | CM-6, SI-2 | 1.4.1, 2.2.1 / 314.4(c)(1) |
| **`tf-fix-min-tls`** (own) | C | Audit / Modify (ladder) | Sets minimumTlsVersion=TLS1_2 | PR.PS (PR.PS-01), PR.DS (PR.DS-02) | CM-6, SC-8 | 4.2.1 / 314.4(c)(3) |
| `remediation_mode` (audit -> dry-run -> enforce) | G | n/a | Escalation is a reviewed diff in a CODEOWNERS path | GV.PO, GV.RR | CM-3, CM-5 | 6.5.1 / 314.4(c)(7) |
| **Approval gate as code** (`approved_remediations` + ticket -> remediation task) | G | n/a | Automation acts, a human authorizes; git history is the approval log | GV.RR, ID.RA (ID.RA-06) | CM-3, CM-4 | 6.5.1, 6.5.2 / 314.4(c)(7) |
| **Custom `tf-storage-baseline-remediator` role** (no listKeys, no delete) | P | n/a | Remediation identity's permissions are its job, nothing more | PR.AA (PR.AA-05) | AC-6, AC-6(1) | 7.2.1, 7.2.2 |

## Stage 07 - Detection

| Component | Type | What it does | CSF 2.0 | 800-53 | PCI DSS 4.0.1 / GLBA |
|---|---|---|---|---|---|
| Activity Log routing (adopted from Lab 2 via `import`) | D | Every control-plane write in the subscription reaches the workspace | DE.CM (DE.CM-03), PR.PS (PR.PS-04) | AU-2, AU-6 | 10.2.1 / 314.4(c)(8) |
| Tripwire: change by unexpected principal (every 15 min) | D | Who is touching reality, including resources Terraform doesn't manage | DE.CM (DE.CM-03), DE.AE | CM-3, AU-6, SI-4 | 10.4.1, 11.5.2 / 314.4(c)(8) |
| Tripwire: remediation identity out of its lane | D | Compensating control for the residual breadth of `storageAccounts/write` | DE.CM (DE.CM-03), PR.AA (PR.AA-05) | AC-6(9), AU-6 | 10.2.1.2 |
| State-backend postconditions (shared keys off, versioning, soft delete) | D | The state account is a controlled resource, re-verified every drift run | PR.DS (PR.DS-01), DE.CM | CM-6, AU-9 | 10.3.2 |

## Repo gates (policy/) and pipeline operations

| Rule / component | Mistake it makes unmergeable | CSF 2.0 | 800-53 | PCI DSS 4.0.1 |
|---|---|---|---|---|
| TF-IAM-001 `broad_roles.rego` | Owner / Contributor / UAA / RBAC Admin grants, by name **or** GUID | PR.AA (PR.AA-05) | AC-6 | 7.2.1 |
| TF-IAM-002 | Custom roles with `*` actions | PR.AA (PR.AA-05) | AC-6 | 7.2.2 |
| TF-POL-001 `policy_identity.rego` | Remediating assignment without an identity (fail-closed when unprovable) | PR.PS (PR.PS-01) | CM-6 | 2.2.1 |
| TF-POL-002 | Remediation through a system-assigned identity instead of the named one | PR.AA (PR.AA-05), GV.RR | AC-6, AU-3 | 7.2.1 |
| TF-STG-001..004 `storage.rego` | Public blobs, shared keys, TLS < 1.2, HTTP | PR.DS (PR.DS-01, PR.DS-02) | SC-7, SC-8, IA-2 | 1.4.1, 4.2.1, 8.2.2 |
| TF-STG-005 | Cosmos key auth re-enabled | PR.AA (PR.AA-01) | IA-2 | 8.2.1 |
| TF-STG-900 (warn) | Security attribute unknown at plan time - the gate says it can't see it | ID.IM | CA-7 | - |
| `exceptions.rego` | Exceptions are per address, ticketed, CODEOWNERS-reviewed, and expire | GV.RM (GV.RM-04) | CA-7, PM-4 | 12.3.1 |
| TF-EVD-001/002 `evidence_protection.rego` | Deleting/replacing the evidence plane; shortening WORM retention | PR.DS (PR.DS-11) | AU-9, AU-11 | 10.3.2, 10.5.1 |
| `gate.yml` static job (no credentials, every PR) | Untested rules, failing tests, secrets, IaC lint findings | PR.PS (PR.PS-06) | SA-11, CM-3 | 6.2.4, 6.5.1 |
| `gate.yml` plan job (read-only identity, same-repo PRs) | A real plan that violates any rule above | PR.PS (PR.PS-06), GV.SC | CM-3, CM-4 | 6.5.1 |
| `drift.yml` (nightly plan, `-detailed-exitcode`) | Reality drifting from code unnoticed | DE.CM (DE.CM-09), ID.IM | CM-3, CM-6 | 11.5.2 / 314.4(c)(7) |
| CODEOWNERS on enforcement, policy, crosswalk, workflows | Control changes merging without review | GV.RR, GV.PO | CM-5 | 6.5.1 |
