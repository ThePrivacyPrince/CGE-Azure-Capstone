# Unit tests for every gate rule: each rule is shown to FIRE on a violating input and to
# STAY QUIET on a compliant one. Run: opa test policy/ -v   (or: conftest verify -p policy)
package main

import rego.v1

sa(address, after) := {"address": address, "type": "azurerm_storage_account", "name": split(address, ".")[1], "change": {"actions": ["create"], "after": after, "after_unknown": {}}}

good_sa := {"allow_nested_items_to_be_public": false, "shared_access_key_enabled": false, "min_tls_version": "TLS1_2", "https_traffic_only_enabled": true}

has_rule(msgs, rule) if {
	some m in msgs
	startswith(m, rule)
}

# --- storage ---------------------------------------------------------------------

test_compliant_storage_passes if {
	count(deny) == 0 with input as {"resource_changes": [sa("azurerm_storage_account.evidence", good_sa)]}
}

test_public_blob_denied if {
	has_rule(deny, "TF-STG-001") with input as {"resource_changes": [sa("azurerm_storage_account.bad", object.union(good_sa, {"allow_nested_items_to_be_public": true}))]}
}

test_shared_key_denied_without_exception if {
	has_rule(deny, "TF-STG-002") with input as {"resource_changes": [sa("azurerm_storage_account.func_runtime_lookalike", object.union(good_sa, {"shared_access_key_enabled": true}))]}
}

test_shared_key_allowed_for_excepted_address if {
	not has_rule(deny, "TF-STG-002") with input as {"resource_changes": [sa("azurerm_storage_account.func_internal", object.union(good_sa, {"shared_access_key_enabled": true}))]}
}

test_expired_exception_stops_matching if {
	has_rule(deny, "TF-STG-002") with input as {"resource_changes": [sa("azurerm_storage_account.func_internal", object.union(good_sa, {"shared_access_key_enabled": true}))]}
		with exceptions as {"TF-STG-002": {"azurerm_storage_account.func_internal": {"ticket": "RISK-0001", "expires": "2020-01-01"}}}
}

test_name_prefix_no_longer_grants_exception if {
	# The starter excepted anything whose NAME started with func_internal.
	has_rule(deny, "TF-STG-002") with input as {"resource_changes": [sa("azurerm_storage_account.func_internal_but_evil", object.union(good_sa, {"shared_access_key_enabled": true}))]}
}

test_old_tls_denied if {
	has_rule(deny, "TF-STG-003") with input as {"resource_changes": [sa("azurerm_storage_account.bad", object.union(good_sa, {"min_tls_version": "TLS1_0"}))]}
}

test_unknown_security_attribute_warns if {
	rc := object.union(sa("azurerm_storage_account.x", good_sa), {"change": {"actions": ["create"], "after": good_sa, "after_unknown": {"shared_access_key_enabled": true}}})
	has_rule(warn, "TF-STG-900") with input as {"resource_changes": [rc]}
}

test_cosmos_key_auth_denied if {
	has_rule(deny, "TF-STG-005") with input as {"resource_changes": [{"address": "azurerm_cosmosdb_account.e", "type": "azurerm_cosmosdb_account", "name": "e", "change": {"actions": ["update"], "after": {"local_authentication_enabled": true}}}]}
}

test_deletes_are_not_storage_violations if {
	count(deny) == 0 with input as {"resource_changes": [{"address": "azurerm_storage_account.old", "type": "azurerm_storage_account", "name": "old", "change": {"actions": ["delete"], "after": null}}]}
}

# --- identity / roles ---------------------------------------------------------------

ra(after) := {"address": "azurerm_role_assignment.x", "type": "azurerm_role_assignment", "name": "x", "change": {"actions": ["create"], "after": after}}

test_contributor_by_name_denied if {
	has_rule(deny, "TF-IAM-001") with input as {"resource_changes": [ra({"role_definition_name": "Contributor"})]}
}

test_owner_by_guid_denied if {
	has_rule(deny, "TF-IAM-001") with input as {"resource_changes": [ra({"role_definition_id": "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"})]}
}

test_granular_role_passes if {
	count(deny) == 0 with input as {"resource_changes": [ra({"role_definition_name": "Security Reader"})]}
}

test_wildcard_custom_role_denied if {
	has_rule(deny, "TF-IAM-002") with input as {"resource_changes": [{"address": "azurerm_role_definition.r", "type": "azurerm_role_definition", "name": "r", "change": {"actions": ["create"], "after": {"permissions": [{"actions": ["*"], "data_actions": []}]}}}]}
}

# --- policy assignment identity --------------------------------------------------------

pd(name, rule) := {"address": sprintf("azurerm_policy_definition.%s", [name]), "type": "azurerm_policy_definition", "name": name, "change": {"actions": ["create"], "after": {"policy_rule": rule}}}

pa(name, identity) := {"address": sprintf("azurerm_management_group_policy_assignment.%s", [name]), "type": "azurerm_management_group_policy_assignment", "name": name, "change": {"actions": ["create"], "after": {"identity": identity}}}

cfg(assignment, definition) := {"configuration": {"root_module": {"resources": [{"address": sprintf("azurerm_management_group_policy_assignment.%s", [assignment]), "expressions": {"policy_definition_id": {"references": [sprintf("azurerm_policy_definition.%s.id", [definition]), sprintf("azurerm_policy_definition.%s", [definition])]}}}]}}}

test_modify_assignment_without_identity_denied if {
	inp := object.union(cfg("fix", "fix"), {"resource_changes": [pd("fix", "{\"then\":{\"effect\":\"Modify\"}}"), pa("fix", [])]})
	has_rule(deny, "TF-POL-001") with input as inp
}

test_audit_only_assignment_without_identity_allowed if {
	inp := object.union(cfg("tls", "tls"), {"resource_changes": [pd("tls", "{\"then\":{\"effect\":\"[parameters('effect')]\"}}"), pa("tls", [])]})
	not has_rule(deny, "TF-POL-001") with input as inp
}

test_parameterized_modify_effect_requires_identity if {
	# policy_rule only says [parameters('effect')]; the allowed values include Modify.
	def := object.union(pd("p", "{\"then\":{\"effect\":\"[parameters('effect')]\"}}"), {"change": {"actions": ["create"], "after": {
		"policy_rule": "{\"then\":{\"effect\":\"[parameters('effect')]\"}}",
		"parameters": "{\"effect\":{\"allowedValues\":[\"Audit\",\"Modify\"]}}",
	}}})
	inp := object.union(cfg("p", "p"), {"resource_changes": [def, pa("p", [])]})
	has_rule(deny, "TF-POL-001") with input as inp
}

test_unresolvable_assignment_fails_closed if {
	# No configuration block, so the definition cannot be proven non-remediating.
	has_rule(deny, "TF-POL-001") with input as {"resource_changes": [pa("mystery", [])]}
}

test_system_assigned_identity_denied if {
	inp := object.union(cfg("fix", "fix"), {"resource_changes": [pd("fix", "{\"then\":{\"effect\":\"Modify\"}}"), pa("fix", [{"type": "SystemAssigned"}])]})
	has_rule(deny, "TF-POL-002") with input as inp
}

test_user_assigned_identity_passes if {
	inp := object.union(cfg("fix", "fix"), {"resource_changes": [pd("fix", "{\"then\":{\"effect\":\"Modify\"}}"), pa("fix", [{"type": "UserAssigned", "identity_ids": ["/x"]}])]})
	count(deny) == 0 with input as inp
}

# --- evidence protection ------------------------------------------------------------

test_cosmos_replacement_denied if {
	has_rule(deny, "TF-EVD-001") with input as {"resource_changes": [{"address": "azurerm_cosmosdb_sql_container.assessments", "type": "azurerm_cosmosdb_sql_container", "name": "assessments", "change": {"actions": ["delete", "create"], "after": {}}}]}
}

test_worm_shortening_denied if {
	has_rule(deny, "TF-EVD-002") with input as {"resource_changes": [{"address": "azurerm_storage_container_immutability_policy.reports_worm", "type": "azurerm_storage_container_immutability_policy", "name": "reports_worm", "change": {"actions": ["update"], "before": {"immutability_period_in_days": 90}, "after": {"immutability_period_in_days": 1}}}]}
}

test_worm_lengthening_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{"address": "azurerm_storage_container_immutability_policy.reports_worm", "type": "azurerm_storage_container_immutability_policy", "name": "reports_worm", "change": {"actions": ["update"], "before": {"immutability_period_in_days": 90}, "after": {"immutability_period_in_days": 365}}}]}
}
