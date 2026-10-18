# Six policies, one initiative, assigned once at mg-grc-sandbox.
# Every subscription that ever joins the sandbox group inherits all of it. (CSF: GV.PO, PR.DS, PR.PS)
# Policies 1-3 are the CGE-AZ starter. Policies 4-6 are Tallyfin's own controls, added for a
# fintech that holds consumer bank data (GLBA Safeguards Rule, PCI DSS 4.0.1, SOC 2).

# --- 1. Require the `env` tag on resource groups (inventory hygiene; POA&M owner resolution) ---

resource "azurerm_policy_definition" "require_env_tag" {
  name                = "cge-require-env-tag-rg"
  display_name        = "Resource groups must carry an env tag"
  policy_type         = "Custom"
  mode                = "All"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Resources/subscriptions/resourceGroups" },
        { field = "tags['env']", exists = "false" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 2. Deny public blob access on storage accounts (clear-cut, framework-mandated: earned Deny) ---

resource "azurerm_policy_definition" "deny_public_blob" {
  name                = "cge-deny-public-blob"
  display_name        = "Storage accounts must not allow public blob access"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Deny"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", equals = "true" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 3. deployIfNotExists: storage accounts missing diagnostic settings get them, routed to the GRC workspace ---
# Logging that enforces its own coverage. Remediation runs AS the identity in identity.tf.

resource "azurerm_policy_definition" "storage_diagnostics" {
  name                = "cge-dine-storage-diagnostics"
  display_name        = "Storage accounts must route diagnostics to the GRC workspace"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    workspaceId = {
      type     = "String"
      metadata = { displayName = "Log Analytics workspace resource ID" }
    }
  })

  policy_rule = jsonencode({
    "if" = {
      field  = "type"
      equals = "Microsoft.Storage/storageAccounts"
    }
    then = {
      effect = "DeployIfNotExists"
      details = {
        type = "Microsoft.Insights/diagnosticSettings"
        roleDefinitionIds = [
          # Monitoring Contributor
          "/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa"
        ]
        existenceCondition = {
          allOf = [
            { field = "Microsoft.Insights/diagnosticSettings/workspaceId", equals = "[parameters('workspaceId')]" }
          ]
        }
        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              resourceName = { value = "[field('name')]" }
              workspaceId  = { value = "[parameters('workspaceId')]" }
              location     = { value = "[field('location')]" }
            }
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                resourceName = { type = "string" }
                workspaceId  = { type = "string" }
                location     = { type = "string" }
              }
              resources = [
                {
                  type       = "Microsoft.Storage/storageAccounts/providers/diagnosticSettings"
                  apiVersion = "2021-05-01-preview"
                  name       = "[concat(parameters('resourceName'), '/Microsoft.Insights/ds-to-grc-workspace')]"
                  properties = {
                    workspaceId = "[parameters('workspaceId')]"
                    metrics = [
                      { category = "Transaction", enabled = true }
                    ]
                  }
                }
              ]
            }
          }
        }
      }
    }
  })
}

# ================================================================================
# Tallyfin's own controls (4-6). Each starts at the effect it has EARNED:
#   4. TLS floor        -> Audit  (new control; promote after the POA&M shows zero)
#   5. Cosmos key auth  -> Audit  (data-service Deny gets its own reviewed change)
#   6. Data residency   -> Audit or Deny, decided by the measured gap (discovery.tf)
# ================================================================================

# --- 4. Storage accounts must require TLS 1.2 (GLBA 314.4(c)(3), PCI DSS 4.2.1) ---

resource "azurerm_policy_definition" "storage_min_tls" {
  name                = "tf-storage-min-tls12"
  display_name        = "Tallyfin: storage accounts must require TLS 1.2"
  description         = "Consumer financial data must be encrypted in transit with strong cryptography. GLBA Safeguards Rule 314.4(c)(3); PCI DSS 4.0.1 req. 4.2.1."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "Storage", version = "1.0.0", owner = "tallyfin-grc" })

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/minimumTlsVersion", notEquals = "TLS1_2" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 5. Cosmos DB must reject key-based (local) auth ---
# Account keys are shared and non-attributable: a write made with a key cannot be tied to a
# person or workload. Entra-only auth makes every data-plane call attributable. The evidence
# store is Cosmos, so this control also watches the watcher.

resource "azurerm_policy_definition" "cosmos_no_local_auth" {
  name                = "tf-cosmos-no-local-auth"
  display_name        = "Tallyfin: Cosmos DB accounts must disable key-based authentication"
  description         = "Entra ID only on Cosmos DB, so every read/write is attributable to an identity. NIST 800-53 IA-2, AC-2; PCI DSS 4.0.1 req. 8.2.1."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "Cosmos DB", version = "1.0.0", owner = "tallyfin-grc" })

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.DocumentDB/databaseAccounts" },
        { field = "Microsoft.DocumentDB/databaseAccounts/disableLocalAuth", notEquals = true }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 6. Data residency: approved US regions only (effect decided by discovery.tf) ---

resource "azurerm_policy_definition" "allowed_locations" {
  name                = "tf-allowed-locations"
  display_name        = "Tallyfin: resources must deploy to approved US regions"
  description         = "Consumer financial data stays in approved US regions. Effect is parameterized so the control starts in Audit until the measured out-of-region gap is zero."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "General", version = "1.0.0", owner = "tallyfin-grc" })

  parameters = jsonencode({
    allowedLocations = {
      type     = "Array"
      metadata = { displayName = "Allowed locations", strongType = "location" }
    }
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "location", notIn = "[parameters('allowedLocations')]" },
        { field = "location", notEquals = "global" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- The initiative: one assignment, whole-sandbox inheritance ---

resource "azurerm_management_group_policy_set_definition" "grc_baseline" {
  name                = "cge-grc-baseline"
  display_name        = "CGE-AZ GRC Baseline"
  policy_type         = "Custom"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    tagEffect             = { type = "String", defaultValue = "Audit" }
    publicBlobEffect      = { type = "String", defaultValue = "Deny" }
    workspaceId           = { type = "String" }
    tlsEffect             = { type = "String", defaultValue = "Audit" }
    cosmosLocalAuthEffect = { type = "String", defaultValue = "Audit" }
    allowedLocations      = { type = "Array" }
    locationsEffect       = { type = "String", defaultValue = "Audit" }
  })

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.require_env_tag.id
    parameter_values = jsonencode({
      effect = { value = "[parameters('tagEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.deny_public_blob.id
    parameter_values = jsonencode({
      effect = { value = "[parameters('publicBlobEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.storage_diagnostics.id
    parameter_values = jsonencode({
      workspaceId = { value = "[parameters('workspaceId')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.storage_min_tls.id
    reference_id         = "tallyfinStorageMinTls"
    parameter_values = jsonencode({
      effect = { value = "[parameters('tlsEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.cosmos_no_local_auth.id
    reference_id         = "tallyfinCosmosNoLocalAuth"
    parameter_values = jsonencode({
      effect = { value = "[parameters('cosmosLocalAuthEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.allowed_locations.id
    reference_id         = "tallyfinAllowedLocations"
    parameter_values = jsonencode({
      allowedLocations = { value = "[parameters('allowedLocations')]" }
      effect           = { value = "[parameters('locationsEffect')]" }
    })
  }
}

resource "azurerm_management_group_policy_assignment" "grc_baseline" {
  name                 = "cge-grc-baseline"
  display_name         = "CGE-AZ GRC Baseline"
  policy_definition_id = azurerm_management_group_policy_set_definition.grc_baseline.id
  management_group_id  = azurerm_management_group.sandbox.id
  location             = var.location

  parameters = jsonencode({
    tagEffect             = { value = var.tag_policy_effect }
    publicBlobEffect      = { value = var.public_blob_policy_effect }
    workspaceId           = { value = azurerm_log_analytics_workspace.grc.id }
    tlsEffect             = { value = var.storage_tls_policy_effect }
    cosmosLocalAuthEffect = { value = var.cosmos_local_auth_policy_effect }
    allowedLocations      = { value = var.allowed_locations }
    locationsEffect       = { value = local.allowed_locations_effect }
  })

  # Remediation effects (deployIfNotExists) execute AS this identity.
  # Without this block, Terraform applies cleanly and remediation silently never runs.
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.remediation.id]
  }
}
