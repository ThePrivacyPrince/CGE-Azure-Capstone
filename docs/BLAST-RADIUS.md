# Blast radius of every enforcement change

For each control that can change or block something: what changes, what could break, how you would know, and how to roll back. Read the row before you merge the PR that moves it.

## Escalation ladder (stage 06, `remediation_mode`)

| Step | What changes in Azure | What could break | Rollback |
|---|---|---|---|
| `audit` | Corrective policies' `effect` parameter is `Disabled`; the stage 01 detective twins (`cge-deny-public-blob`, `fafo-storage-min-tls12`) keep reporting. Remediator role assignment is **removed** (count = 0). | Nothing. | n/a |
| `audit` -> `dry-run` (default) | `effect` parameter becomes `Modify` with `enforce = false` (DoNotEnforce). Remediator role assigned. **No resource changes on its own.** | Nothing, until a human approves a remediation task. | PR back to `audit`. |
| Approve a key in `dry-run` (`approved_remediations = ["fix-..."]`, ticket id; Terraform refuses an approval without a ticket) | One remediation task per approved key fixes **every** non-compliant storage account in **every subscription** under `mg-grc-sandbox` that exists when the task runs. Stops if >10% of fixes fail. | See per-control rows below. | A completed fix is not undone by reverting the PR. Revert the property by hand, through a ticketed exception, after reading why it was fixed. |
| `dry-run` -> `enforce` | Modify applies to **every new create/update request** in scope, in flight. Existing resources still need tasks. | A deployment that sets the property to the bad value succeeds but silently gets the good value. Pipelines that assert on the bad value may fail. | PR back to `dry-run`; takes effect as soon as apply finishes. |

## Per-control blast radius

### fix-public-blob (`cge-fix-public-blob`)
- **Changes:** `allowBlobPublicAccess` -> `false` on storage accounts.
- **Could break:** anything serving blobs anonymously (static assets, public downloads). At FAFO, nothing should: the stage 01 Deny already blocks new public accounts, so only accounts created before the Deny, or changed out-of-band under a temporary Audit exception (the Lab 6 scenario), are affected.
- **Know it worked:** remediation task `Succeeded`, the property reads `false`, Activity Log `caller` = remediation principal ID, next collection records the policy state `Compliant` and Defender `51fd8bb1-...` `Healthy` (see [evidence/LAB6-LOOP-CLOSURE.md](evidence/LAB6-LOOP-CLOSURE.md)).
- **Rollback:** set `allowBlobPublicAccess` back by hand only with an approved exception; set stage 01 `public_blob_policy_effect = "Audit"` for the exception window, then restore `Deny` (Lab 6 steps 5 and 10).

### fix-min-tls (`fafo-fix-min-tls`) - FAFO's own
- **Changes:** `minimumTlsVersion` -> `TLS1_2`.
- **Could break:** clients that only speak TLS 1.0/1.1 (old SDKs, legacy SFTP/backup tools, some on-prem integrations). They will fail the TLS handshake.
- **Before approving:** check the storage account's `StorageRead`/`StorageWrite` logs for `TlsVersion` 1.0/1.1 callers over the last 30 days:
  ```kusto
  StorageBlobLogs | where TimeGenerated > ago(30d) | where TlsVersion in ("TLS 1.0","TLS 1.1")
  | summarize count() by AccountName, CallerIpAddress, UserAgentHeader
  ```
- **Rollback:** set `minimumTlsVersion` back on the affected account with an exception ticket; move the client.

## Preventive policies (stage 01)

| Policy | Effect now | If promoted to Deny | Rollback |
|---|---|---|---|
| `cge-deny-public-blob` | Deny | (already Deny) Blocks any create/update that enables public access. | `public_blob_policy_effect = "Audit"` for a ticketed, time-boxed window (Lab 6). |
| `fafo-storage-min-tls12` | Audit | Blocks creating/updating storage with TLS < 1.2 - including updates to an old account that still has TLS 1.0, so fix those first (`fix-min-tls`). | `storage_tls_policy_effect = "Audit"`. |
| `fafo-cosmos-no-local-auth` | Audit | Blocks Cosmos accounts with key auth. Breaks apps using connection strings with keys. | `cosmos_local_auth_policy_effect = "Audit"`. |
| `fafo-allowed-locations` | Audit while `region_gap > 0`, then **Deny automatically** | Blocks creating resources outside `allowed_locations`, **and updates to existing out-of-region resources** - which is why it waits for the gap to be zero. | `allowed_locations_effect_override = "Audit"` in a PR, with the reason. |
| `cge-require-env-tag-rg` | Audit | Blocks creating resource groups without `env`. | `tag_policy_effect = "Audit"`. |
| `cge-dine-storage-diagnostics` | DeployIfNotExists | (always remediating) Adds a diagnostic setting to storage accounts; can collide with an existing setting that already sends the same categories to the same workspace. | Remove from the initiative; delete the `ds-to-grc-workspace` settings it created. |
| `fafo-keyvault-purge-protection` | Audit | Blocks creating vaults without purge protection, and updates to existing ones. **One-way:** once enabled, purge protection can't be disabled, and a deleted vault's name stays reserved for its retention period. | `keyvault_purge_policy_effect = "Audit"`. Enabled purge protection is not rolled back. |
| `fafo-audit-subscription-owner` | Audit | Blocks **every** new Owner grant at subscription scope, including break-glass and onboarding. Keep at Audit until a just-in-time path (PIM) exists. | `subscription_owner_policy_effect = "Audit"` or `"Disabled"`. |
| `fafo-dine-keyvault-audit-logs` | DeployIfNotExists | (always remediating) Adds `ds-kv-to-grc-workspace` (AuditEvent) to vaults; can collide with an existing setting sending AuditEvent to the same workspace; adds ingestion cost per secret operation. | `keyvault_audit_logs_policy_effect = "AuditIfNotExists"`; delete the settings it created. |

## Activation (stage 02)

| Change | Blast radius | Rollback |
|---|---|---|
| A subscription is moved under `mg-grc-sandbox` | Next apply enables the baseline Defender plans (`StorageAccounts`, `KeyVaults`) **in that subscription**: billable after the 30-day trial. Policy and the 800-53 initiative apply immediately by inheritance. | Move the subscription out, or set its plans back to Free with `az security pricing create -n <plan> --tier Free`. Destroying stage 02 does **not** downgrade plans (azapi_update_resource). |
| NIST SP 800-53 Rev. 5 initiative at the management group (replaces the subscription-scoped CSF 2.0 assignment) | Adds Audit/AuditIfNotExists evaluations and Defender regulatory-compliance views across the scope; blocks nothing. | Delete the assignment. |

## Gate and detection changes

| Change | Blast radius | Rollback |
|---|---|---|
| Adding an exception to `policy/exceptions.rego` | One address, one rule, until the expiry date. Requires CODEOWNERS review. | Delete the entry; the rule applies again on the next PR. |
| Tripwire rule changes (stage 07, `kql/`) | Alert noise or silence only; no resource changes. `business_hours` and `approved_secret_reader_ids` widen or narrow two of them. | Revert the PR. |
| Locking the WORM policy (`locked = true`, stage 03) | **Irreversible.** The container and account cannot be deleted until every blob ages out of retention. | None. That is the point. Do this only in a real environment. |
