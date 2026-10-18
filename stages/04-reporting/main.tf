locals {
  evidence_rg      = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  cosmos_endpoint  = data.terraform_remote_state.evidence.outputs.cosmos_endpoint
  cosmos_id        = data.terraform_remote_state.evidence.outputs.cosmos_account_id
  cosmos_name      = data.terraform_remote_state.evidence.outputs.cosmos_account_name
  evidence_storage = data.terraform_remote_state.evidence.outputs.evidence_storage_account
  common_tags = {
    env     = var.environment
    purpose = "grc-reporting"
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

data "azurerm_storage_account" "evidence" {
  name                = local.evidence_storage
  resource_group_name = local.evidence_rg
}

resource "azurerm_storage_account" "func_internal" {
  #checkov:skip=CKV2_AZURE_40:Y1 host storage requires a key; ticketed, expiring exception RISK-0001 in policy/exceptions.rego (exit plan: Flex Consumption, ADR-007).
  #checkov:skip=CKV_AZURE_59:Functions host must reach it; holds runtime scratch only, never evidence.
  #checkov:skip=CKV2_AZURE_33:Private endpoint deferred (ADR-005).
  #checkov:skip=CKV_AZURE_206:Runtime scratch, fully rebuildable; LRS is the right cost.
  #checkov:skip=CKV_AZURE_33:Queue logging not needed for host scratch storage.
  #checkov:skip=CKV2_AZURE_1:Runtime scratch only; platform-managed keys.
  #checkov:skip=CKV2_AZURE_41:sas_policy is set with action Log; Block would break Y1 run-from-package deployment SAS URLs.
  name                            = "stgrcrpt${random_string.suffix.result}"
  resource_group_name             = local.evidence_rg
  location                        = var.functions_location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  https_traffic_only_enabled      = true

  # Tallyfin: the key this account must keep is the only shared key in the pipeline,
  # so bound what a leaked SAS could do and keep deleted host data recoverable.
  sas_policy {
    expiration_period = "01.00:00:00"
    expiration_action = "Log"
  }

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }

  tags = local.common_tags
}

resource "azurerm_service_plan" "reporting" {
  #checkov:skip=CKV_AZURE_212:Consumption plan scales from zero by design; a missed timer run is visible as a gap in run manifests.
  #checkov:skip=CKV_AZURE_225:Zone redundancy is not available on Y1 Consumption.
  name                = "asp-grc-reporting-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1"
  tags                = local.common_tags
}

resource "azurerm_linux_function_app" "reporting" {
  name                       = "func-grc-reporting-${random_string.suffix.result}"
  resource_group_name        = local.evidence_rg
  location                   = var.functions_location
  service_plan_id            = azurerm_service_plan.reporting.id
  storage_account_name       = azurerm_storage_account.func_internal.name
  storage_account_access_key = azurerm_storage_account.func_internal.primary_access_key
  https_only                 = true # Tallyfin: no plaintext path to the app

  #checkov:skip=CKV_AZURE_221:Y1 Consumption cannot use private endpoints; timer-only by default (no HTTP triggers registered), ADR-005.

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    "COSMOS_ENDPOINT"                = local.cosmos_endpoint
    "COSMOS_DATABASE"                = "grc"
    "REPORTS_ACCOUNT_URL"            = data.azurerm_storage_account.evidence.primary_blob_endpoint
    "REPORTS_CONTAINER"              = "reports"
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
    "ENABLE_ORYX_BUILD"              = "true"

    # Tallyfin capstone settings
    "POAM_SCHEDULE"          = var.poam_schedule
    "SAR_SCHEDULE"           = var.sar_schedule
    "MAX_RUN_AGE_HOURS"      = tostring(var.max_run_age_hours)
    "APP_VERSION"            = var.app_version
    "ENABLE_MANUAL_TRIGGERS" = var.enable_manual_triggers ? "true" : "false"
  }


  # APP_VERSION is stamped with the git SHA by scripts/deploy-functions.sh at code-deploy
  # time. Ignoring it here keeps a code deploy from showing up as nightly "drift".
  lifecycle {
    ignore_changes = [app_settings["APP_VERSION"]]
  }
  tags = local.common_tags
}

# --- The reporting identity's whitelist — the mirror image of the collector's. ---
# Cosmos READ (built-in Data Reader), Blob WRITE into the WORM container. No path to
# live platform data: no Security Reader, no Cosmos write. SoD, enforced by scopes.

resource "azurerm_cosmosdb_sql_role_assignment" "reporter_cosmos_read" {
  resource_group_name = local.evidence_rg
  account_name        = local.cosmos_name
  role_definition_id  = "${local.cosmos_id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
  principal_id        = azurerm_linux_function_app.reporting.identity[0].principal_id
  scope               = local.cosmos_id
}

# Tallyfin capstone: the reporter's job is "create new report files". The starter's
# Storage Blob Data Contributor (account-wide) also grants delete and container management;
# WORM blocks the delete today, but least privilege should not lean on a second control.
# This custom role creates and reads blobs in the reports container only.
resource "azurerm_role_definition" "report_writer" {
  name        = "tf-grc-report-writer"
  scope       = data.azurerm_storage_account.evidence.id
  description = "Create and read report blobs. No delete, no overwrite-by-policy bypass, no container management."

  permissions {
    actions = [
      "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    ]
    data_actions = [
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
    ]
  }

  assignable_scopes = [data.azurerm_storage_account.evidence.id]
}

resource "azurerm_role_assignment" "reporter_blob_write" {
  scope              = "${data.azurerm_storage_account.evidence.id}/blobServices/default/containers/reports"
  role_definition_id = azurerm_role_definition.report_writer.role_definition_resource_id
  principal_id       = azurerm_linux_function_app.reporting.identity[0].principal_id
  principal_type     = "ServicePrincipal"
  description        = "Reporter: create report artifacts in the WORM container only."
}

output "reporting_function_app" {
  value = azurerm_linux_function_app.reporting.name
}

output "reporter_principal_id" {
  value = azurerm_linux_function_app.reporting.identity[0].principal_id
}
