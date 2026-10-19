# Stage contract: downstream stages consume these via terraform_remote_state.
# Outputs are the interface; everything else is this stage's private implementation.

output "subscription_id" {
  description = "The governed subscription."
  value       = data.azurerm_subscription.current.subscription_id
}

output "management_group_id" {
  description = "The sandbox management group — the scope governance attaches to."
  value       = azurerm_management_group.sandbox.id
}

output "log_analytics_workspace_id" {
  description = "The GRC program's log destination."
  value       = azurerm_log_analytics_workspace.grc.id
}

output "evidence_resource_group_name" {
  description = "Where the evidence store (Cosmos, WORM Blob, collectors) deploys."
  value       = azurerm_resource_group.evidence.name
}

output "remediation_identity_id" {
  description = "Resource ID of the user-assigned remediation identity."
  value       = azurerm_user_assigned_identity.remediation.id
}

output "remediation_identity_principal_id" {
  description = "Principal ID — use to filter the Activity Log for automated changes."
  value       = azurerm_user_assigned_identity.remediation.principal_id
}

# --- FAFO additions -------------------------------------------------

output "management_group_name" {
  description = "Sandbox management group name (the scope enforcement and remediation tasks target)."
  value       = azurerm_management_group.sandbox.name
}

output "region_gap" {
  description = "Resources discovered outside allowed_locations at plan time. The allowed-locations control stays in Audit until this is 0."
  value       = local.region_gap
}

output "out_of_region_resources" {
  description = "The measured gap itself: what must move (or be excepted) before Deny is earned."
  value       = local.out_of_region_resources
}

output "allowed_locations_effect" {
  description = "Effect the region guardrail is running with, and why lives in region_gap."
  value       = local.allowed_locations_effect
}
