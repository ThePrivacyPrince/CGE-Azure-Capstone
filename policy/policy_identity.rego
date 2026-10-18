# Gate rule TF-POL-001/002: a policy assignment carrying remediation effects without an
# identity applies cleanly and then silently never remediates. Make that unmergeable.
#
# Capstone refinement (Lab 6 finding): the starter demanded an identity on EVERY
# assignment, but Audit/Deny assignments never write, and giving them an identity only
# widens the attack surface. This version requires an identity unless the plan PROVES the
# assignment is non-remediating. If it cannot prove it (unknown values, a set definition,
# a definition outside this plan), it fails closed and requires the identity.
# (NIST CSF 2.0 PR.PS-01, PR.AA-05 · 800-53 CM-6, AC-6)
package main

import rego.v1

assignment_types := {
	"azurerm_management_group_policy_assignment",
	"azurerm_subscription_policy_assignment",
	"azurerm_resource_group_policy_assignment",
	"azurerm_resource_policy_assignment",
}

remediating_effects := {"modify", "deployifnotexists"}

# Config entries don't carry for_each keys: x.fix["a"] lives under config address x.fix.
config_resource(rc) := r if {
	some r in input.configuration.root_module.resources
	r.address == sprintf("%s.%s", [rc.type, rc.name])
}

# The definition resources an assignment's policy_definition_id points at.
referenced_definitions(rc) := {d |
	some ref in config_resource(rc).expressions.policy_definition_id.references
	some d in input.resource_changes
	startswith(ref, sprintf("%s.%s", [d.type, d.name]))
}

provably_non_remediating(rc) if {
	defs := referenced_definitions(rc)
	count(defs) > 0
	every d in defs {
		d.type == "azurerm_policy_definition"
		is_string(d.change.after.policy_rule)
		not mentions_remediation(d.change.after.policy_rule)
		not remediating_parameters(d)
	}
}

# A parameterized effect ("[parameters('effect')]") hides the effect from policy_rule. If
# the definition's parameters allow modify/deployIfNotExists, an assignment could pick it.
remediating_parameters(d) if {
	params := object.get(d.change.after, "parameters", null)
	is_string(params)
	mentions_remediation(params)
}

mentions_remediation(rule) if {
	some effect in remediating_effects
	contains(lower(rule), effect)
}

# In plan JSON an absent identity block is an EMPTY LIST, and an empty list is truthy in
# Rego - so the starter's `not rc.change.after.identity` could never fire on a real plan.
# Count the entries instead. (Found by test_modify_assignment_without_identity_denied.)
has_identity(rc) if count(object.get(rc.change.after, "identity", [])) > 0

deny contains msg if {
	some rc in input.resource_changes
	rc.type in assignment_types
	creates_or_updates(rc)
	not has_identity(rc)
	not provably_non_remediating(rc)
	msg := sprintf("TF-POL-001 %s: assignment may carry modify/deployIfNotExists but has no identity block (remediation would silently no-op)", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type in assignment_types
	creates_or_updates(rc)
	some id in rc.change.after.identity
	id.type != "UserAssigned"
	msg := sprintf("TF-POL-002 %s: remediation must run as the named user-assigned identity, not %s", [rc.address, id.type])
}
