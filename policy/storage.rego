# Gate rules TF-STG-*: the pipeline's own storage must pass the pipeline's own standard.
# (NIST CSF 2.0 PR.DS-01, PR.DS-02, PR.AA-01 · PCI DSS 4.0.1 1.4.1, 4.2.1, 8.2.2 · GLBA 314.4(c))
package main

import rego.v1

storage_changes contains rc if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	creates_or_updates(rc)
}

deny contains msg if {
	some rc in storage_changes
	rc.change.after.allow_nested_items_to_be_public == true
	msg := sprintf("TF-STG-001 %s: storage accounts must not allow public blob access", [rc.address])
}

# Shared keys: no exception by naming convention (the starter's startswith(name,
# "func_internal") let ANY resource opt out by picking a name). Exceptions now live in
# exceptions.rego: per address, ticketed, CODEOWNERS-reviewed, and they expire.
deny contains msg if {
	some rc in storage_changes
	rc.change.after.shared_access_key_enabled == true
	not excepted(rc.address, "TF-STG-002")
	msg := sprintf("TF-STG-002 %s: shared key access must be disabled (identity or nothing); no unexpired exception in policy/exceptions.rego", [rc.address])
}

deny contains msg if {
	some rc in storage_changes
	tls := object.get(rc.change.after, "min_tls_version", "TLS1_2")
	tls != "TLS1_2"
	msg := sprintf("TF-STG-003 %s: min_tls_version must be TLS1_2 (got %s)", [rc.address, tls])
}

deny contains msg if {
	some rc in storage_changes
	rc.change.after.https_traffic_only_enabled == false
	msg := sprintf("TF-STG-004 %s: HTTPS-only must stay enabled", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_cosmosdb_account"
	creates_or_updates(rc)
	rc.change.after.local_authentication_enabled == true
	msg := sprintf("TF-STG-005 %s: Cosmos DB must disable key-based auth (local_authentication_enabled = false)", [rc.address])
}

# Unknown at plan time = the gate cannot see it. Say so instead of passing silently.
security_attributes := {"allow_nested_items_to_be_public", "shared_access_key_enabled", "min_tls_version"}

warn contains msg if {
	some rc in storage_changes
	some attr in security_attributes
	rc.change.after_unknown[attr] == true
	msg := sprintf("TF-STG-900 %s: %s is unknown until apply - the gate cannot verify it in this plan", [rc.address, attr])
}
