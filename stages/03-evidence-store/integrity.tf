# --- Tallyfin capstone: protect the evidence plane itself ---------------------------------
#
# The evidence store is the one place an auditor must be able to trust, so it gets the
# same three things the pipeline demands of everything else: deletion is deliberate,
# access is logged, and logs land outside the thing being logged.

locals {
  grc_workspace_id = data.terraform_remote_state.foundation.outputs.log_analytics_workspace_id
}

# blast radius: blocks `terraform destroy` and portal deletes of the evidence database and
# the WORM account until the lock is removed. Course teardown: remove these two locks
# first (docs/RUNBOOK.md#teardown). That friction is the control.
resource "azurerm_management_lock" "cosmos" {
  name       = "lock-evidence-cosmos"
  scope      = azurerm_cosmosdb_account.evidence.id
  lock_level = "CanNotDelete"
  notes      = "Evidence database. Deletion requires removing this lock through a reviewed change."
}

resource "azurerm_management_lock" "evidence_storage" {
  name       = "lock-evidence-storage"
  scope      = azurerm_storage_account.evidence.id
  lock_level = "CanNotDelete"
  notes      = "WORM report storage. Deletion requires removing this lock through a reviewed change."
}

# Who read or wrote evidence is itself evidence. Data-plane logs for both stores.
resource "azurerm_monitor_diagnostic_setting" "cosmos" {
  name                           = "evidence-to-grc-law"
  target_resource_id             = azurerm_cosmosdb_account.evidence.id
  log_analytics_workspace_id     = local.grc_workspace_id
  log_analytics_destination_type = "Dedicated"

  enabled_log {
    category = "DataPlaneRequests"
  }

  enabled_log {
    category = "ControlPlaneRequests"
  }
}

resource "azurerm_monitor_diagnostic_setting" "evidence_blob" {
  name                       = "evidence-blob-to-grc-law"
  target_resource_id         = "${azurerm_storage_account.evidence.id}/blobServices/default"
  log_analytics_workspace_id = local.grc_workspace_id

  # StorageDelete is where the WORM failed-delete proof shows up (403, by caller).
  enabled_log {
    category = "StorageDelete"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageRead"
  }
}
