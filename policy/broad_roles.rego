# Gate rule TF-IAM-001/002: no broad role grants and no wildcard custom roles sneak into
# governance code - not even yours, not even at 2 AM with a deadline.
# (NIST CSF 2.0 PR.AA-05 · 800-53 AC-6 · PCI DSS 4.0.1 7.2.1)
package main

import rego.v1

broad_roles := {"Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"}

# Matching by GUID too: a role_definition_id grant is the same privilege as a name grant.
broad_role_guids := {
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635", # Owner
	"b24988ac-6180-42a0-ab88-20f7382dd24c", # Contributor
}

creates_or_updates(rc) if {
	some action in rc.change.actions
	action in {"create", "update"}
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_assignment"
	creates_or_updates(rc)
	rc.change.after.role_definition_name in broad_roles
	msg := sprintf("TF-IAM-001 %s: %s is not a whitelist - use a granular or custom role", [rc.address, rc.change.after.role_definition_name])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_assignment"
	creates_or_updates(rc)
	some guid in broad_role_guids
	endswith(lower(rc.change.after.role_definition_id), guid)
	msg := sprintf("TF-IAM-001 %s: role_definition_id resolves to a broad built-in role (%s)", [rc.address, guid])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_definition"
	creates_or_updates(rc)
	some perm in rc.change.after.permissions
	some action in array.concat(object.get(perm, "actions", []), object.get(perm, "data_actions", []))
	action == "*"
	msg := sprintf("TF-IAM-002 %s: custom roles must list actions, not '*'", [rc.address])
}
