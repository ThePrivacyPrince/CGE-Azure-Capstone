# Gate rules TF-EVD-*: no PR can quietly destroy or weaken the evidence plane.
# Replacement counts as destruction: a "delete, create" plan on Cosmos wipes the history.
# Deliberate teardown happens outside the PR path (docs/RUNBOOK.md#teardown).
# (NIST CSF 2.0 PR.DS-01, PR.DS-11 · 800-53 AU-9, AU-11 · PCI DSS 4.0.1 10.3.2, 10.5.1)
package main

import rego.v1

protected_types := {
	"azurerm_cosmosdb_account",
	"azurerm_cosmosdb_sql_database",
	"azurerm_cosmosdb_sql_container",
	"azurerm_storage_container_immutability_policy",
	"azurerm_management_lock",
}

protected_addresses := {
	"azurerm_storage_account.evidence",
	"azurerm_storage_container.reports",
}

is_protected(rc) if rc.type in protected_types

is_protected(rc) if rc.address in protected_addresses

deny contains msg if {
	some rc in input.resource_changes
	is_protected(rc)
	"delete" in rc.change.actions
	msg := sprintf("TF-EVD-001 %s: plan would delete or replace evidence-plane resource (%v)", [rc.address, rc.change.actions])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_container_immutability_policy"
	"update" in rc.change.actions
	rc.change.after.immutability_period_in_days < rc.change.before.immutability_period_in_days
	msg := sprintf("TF-EVD-002 %s: WORM retention may not be shortened (%d -> %d days)", [rc.address, rc.change.before.immutability_period_in_days, rc.change.after.immutability_period_in_days])
}
