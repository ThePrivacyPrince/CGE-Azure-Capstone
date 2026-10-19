# --- The collector Function App: timer-triggered Python, managed identity, zero keys. ---
# One app for collectors, a separate app (stage 04) for reporting: the Function App is
# the identity boundary, and no identity both writes evidence and generates reports.

# Internal plumbing storage for the Functions runtime (NOT the evidence store —
# that account has shared keys disabled; this one is the app's own scratch space).
resource "azurerm_storage_account" "func_internal" {
  #checkov:skip=CKV2_AZURE_40:Y1 host storage requires a key; ticketed, expiring exception RISK-0001 in policy/exceptions.rego (exit plan: Flex Consumption, ADR-007).
  #checkov:skip=CKV_AZURE_59:Functions host must reach it; holds runtime scratch only, never evidence.
  #checkov:skip=CKV2_AZURE_33:Private endpoint deferred (ADR-005).
  #checkov:skip=CKV_AZURE_206:Runtime scratch, fully rebuildable; LRS is the right cost.
  #checkov:skip=CKV_AZURE_33:Queue logging not needed for host scratch storage.
  #checkov:skip=CKV2_AZURE_1:Runtime scratch only; platform-managed keys.
  #checkov:skip=CKV2_AZURE_41:sas_policy is set with action Log; Block would break Y1 run-from-package deployment SAS URLs.
  name                            = "stgrcfunc${random_string.suffix.result}"
  resource_group_name             = local.evidence_rg
  location                        = var.functions_location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  https_traffic_only_enabled      = true

  # FAFO: the key this account must keep is the only shared key in the pipeline,
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

resource "azurerm_service_plan" "collectors" {
  #checkov:skip=CKV_AZURE_212:Consumption plan scales from zero by design; a missed timer run is visible as a gap in run manifests.
  #checkov:skip=CKV_AZURE_225:Zone redundancy is not available on Y1 Consumption.
  name                = "asp-grc-collectors-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption: pay per execution. Pennies.
  tags                = local.common_tags
}

resource "azurerm_linux_function_app" "collectors" {
  name                       = "func-grc-collectors-${random_string.suffix.result}"
  resource_group_name        = local.evidence_rg
  location                   = var.functions_location
  service_plan_id            = azurerm_service_plan.collectors.id
  storage_account_name       = azurerm_storage_account.func_internal.name
  storage_account_access_key = azurerm_storage_account.func_internal.primary_access_key
  https_only                 = true # FAFO: no plaintext path to the app

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
    "COSMOS_ENDPOINT"                = azurerm_cosmosdb_account.evidence.endpoint
    "COSMOS_DATABASE"                = azurerm_cosmosdb_sql_database.grc.name
    "SUBSCRIPTION_ID"                = local.subscription
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
    "ENABLE_ORYX_BUILD"              = "true"

    # FAFO settings
    "COLLECT_SCHEDULE" = var.collect_schedule
    "APP_VERSION"      = var.app_version
    # HTTP triggers need a function key - a stored credential. They are compiled out
    # unless this is "true", and every run manifest records whether a timer or a human
    # started it, so run history can't be padded with manual runs unnoticed.
    "ENABLE_MANUAL_TRIGGERS" = var.enable_manual_triggers ? "true" : "false"
  }


  # APP_VERSION is stamped with the git SHA by scripts/deploy-functions.sh at code-deploy
  # time. Ignoring it here keeps a code deploy from showing up as nightly "drift".
  lifecycle {
    ignore_changes = [app_settings["APP_VERSION"]]
  }
  tags = local.common_tags
}

# --- The collector identity's whitelist: read posture, write evidence. Nothing else. ---

# Security Reader at the subscription: read Defender assessments, change nothing.
resource "azurerm_role_assignment" "collector_security_reader" {
  scope                = "/subscriptions/${local.subscription}"
  role_definition_name = "Security Reader"
  principal_id         = azurerm_linux_function_app.collectors.identity[0].principal_id
}

# Cosmos data-plane write. "Cosmos DB Built-in Data Contributor" (00000000-0000-0000-0000-000000000002)
# is a Cosmos-native data-plane role, not an ARM role — control plane vs data plane, again.
resource "azurerm_cosmosdb_sql_role_assignment" "collector_cosmos_write" {
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  role_definition_id  = "${azurerm_cosmosdb_account.evidence.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = azurerm_linux_function_app.collectors.identity[0].principal_id
  scope               = azurerm_cosmosdb_account.evidence.id
}

# --- FAFO: the second evidence source (Azure Policy compliance states) -------
#
# Security Reader covers Defender assessments. Policy states are queried through a POST
# action that Security Reader does not grant, so the collector gets exactly that action
# and nothing else - not the broad built-in Reader.
resource "azurerm_role_definition" "policy_state_reader" {
  name        = "fafo-grc-policy-state-reader"
  scope       = "/subscriptions/${local.subscription}"
  description = "Query Azure Policy compliance states. Read-only."

  permissions {
    actions = [
      "Microsoft.PolicyInsights/policyStates/queryResults/read",
      "Microsoft.PolicyInsights/policyStates/queryResults/action",
    ]
  }

  assignable_scopes = ["/subscriptions/${local.subscription}"]
}

resource "azurerm_role_assignment" "collector_policy_states" {
  scope              = "/subscriptions/${local.subscription}"
  role_definition_id = azurerm_role_definition.policy_state_reader.role_definition_resource_id
  principal_id       = azurerm_linux_function_app.collectors.identity[0].principal_id
  principal_type     = "ServicePrincipal"
  description        = "Collector: read Azure Policy compliance states (second evidence source)."
}
