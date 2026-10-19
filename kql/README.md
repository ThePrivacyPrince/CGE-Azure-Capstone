# KQL: the questions FAFO asks of its logs

Each `.kql` file answers one question an auditor, a hospital customer's security reviewer or the prime contractor would ask about FAFO. Each file is also the **source of a scheduled alert rule**: `stages/07-detection/main.tf` loads it with `templatefile`, so the query you read here is exactly the query that runs every 15 minutes. `tests/test_kql.py` fails CI if a placeholder is missing, unbalanced, or not passed by stage 07.

| File | FAFO's question | Data source | 800-53 | Own or taught |
|---|---|---|---|---|
| [off-hours-admin-changes.kql](off-hours-admin-changes.kql) | Are people changing the environment outside the change window? | `AzureActivity` (every governed subscription routes it, stage 07) | AC-2, AU-6, CM-3 | **FAFO's own** |
| [keyvault-secret-reads-non-pipeline.kql](keyvault-secret-reads-non-pipeline.kql) | Who, other than the pipeline, is reading the secrets that guard customer data? | `AzureDiagnostics` Key Vault `AuditEvent` (routed by policy `fafo-dine-keyvault-audit-logs`, stage 01) | AC-6(9), AU-6, SI-4 | **FAFO's own** |
| [remediator-out-of-lane.kql](remediator-out-of-lane.kql) | Did the one identity allowed to fix things do anything else? | `AzureActivity` | AC-6, AC-6(9), AU-6 | **FAFO's own** (compensating control for RISK-0002) |
| [unexpected-writer.kql](unexpected-writer.kql) | Who is touching reality outside the approved path? | `AzureActivity` | CM-3, AU-6, SI-4 | Course-derived baseline |

The taught queries (role assignments written, policy assignments deleted, the drift query) aren't reused. `unexpected-writer` is the course's out-of-band tripwire, kept as a baseline and labeled as such.

## Running a query by hand

The files contain `${placeholders}` that stage 07 fills. To run one in the Log Analytics portal:

1. Delete the `${new_rows_filter}` line. It only exists so the alert rule counts each row once: it looks back one hour but only counts rows ingested in the last 15 minutes.
2. Replace the other placeholders as documented at the top of each file. For example, in `off-hours-admin-changes.kql`: `${timezone}` → `"America/New_York"`, `${business_start}` → `8`, `${business_end}` → `18`.
3. Set the portal's time range (for example, last 30 days) and run.

## Why these questions

- **Off-hours changes.** Four engineers built FAFO's estate with no change control. The cheapest signal that a human account is misused, or that change control is being bypassed, is *when* the change happens. Workloads are excluded on purpose: the Activity Log records a person's `Caller` as a UPN and a workload as an object ID.
- **Secret reads by non-pipeline identities.** Key Vault holds the connection secrets for FAFO's analytics stores. A person reading a secret, or an unapproved workload doing it, is often the first step of credential harvesting. Approved readers are the pipeline's identities plus `approved_secret_reader_ids` (stage 07), and changing that list is a reviewed PR.
- **Remediator out of lane.** The remediation identity must hold `storageAccounts/write`, which can't be limited to one property. This query is the compensating control: it fires on anything the identity does beyond its two known jobs.
