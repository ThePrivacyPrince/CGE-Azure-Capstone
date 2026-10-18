# The Terraform state account, treated as a controlled resource.
#
# The state account is bootstrapped by script (it cannot manage itself), so no stage
# owns it in state. Instead this stage RE-VERIFIES its hardening on every plan, which
# means every nightly drift run: if someone re-enables shared keys or turns off soft
# delete, the postcondition fails the plan and drift.yml goes red with the reason.
# Hardening is applied by labs/03-foundation/harden-state.sh.

data "azapi_resource" "state_account" {
  type                   = "Microsoft.Storage/storageAccounts@2023-05-01"
  resource_id            = "/subscriptions/${var.subscription_id}/resourceGroups/${var.state_resource_group}/providers/Microsoft.Storage/storageAccounts/${var.state_storage_account}"
  response_export_values = ["properties.allowSharedKeyAccess", "properties.allowBlobPublicAccess", "properties.minimumTlsVersion"]

  lifecycle {
    postcondition {
      condition     = try(self.output.properties.allowSharedKeyAccess, true) == false
      error_message = "State account accepts shared keys. Run labs/03-foundation/harden-state.sh (state must be Entra-only)."
    }
    postcondition {
      condition     = try(self.output.properties.allowBlobPublicAccess, true) == false
      error_message = "State account allows public blob access."
    }
    postcondition {
      condition     = try(self.output.properties.minimumTlsVersion, "") == "TLS1_2"
      error_message = "State account minimum TLS is not 1.2."
    }
  }
}

data "azapi_resource" "state_blob_service" {
  type                   = "Microsoft.Storage/storageAccounts/blobServices@2023-05-01"
  resource_id            = "${data.azapi_resource.state_account.id}/blobServices/default"
  response_export_values = ["properties.isVersioningEnabled", "properties.deleteRetentionPolicy", "properties.containerDeleteRetentionPolicy"]

  lifecycle {
    postcondition {
      condition     = try(self.output.properties.isVersioningEnabled, false) == true
      error_message = "State blob versioning is off: prior state versions would not be recoverable."
    }
    postcondition {
      condition     = try(self.output.properties.deleteRetentionPolicy.enabled, false) == true
      error_message = "State blob soft delete is off. Run labs/03-foundation/harden-state.sh."
    }
  }
}

output "state_backend_hardened" {
  description = "True when every postcondition above passed in this plan."
  value       = true
  depends_on  = [data.azapi_resource.state_account, data.azapi_resource.state_blob_service]
}
