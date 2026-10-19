# Nine policies, one initiative, assigned once at mg-grc-sandbox.
# Every subscription that ever joins the sandbox group inherits all of it the moment it lands:
# FAFO's other two subscriptions need a management-group move, not a code change.
# Policies 1-3 are the CGE-AZ starter's taught set. Policies 4-9 are FAFO's own controls, chosen
# for a health-analytics SaaS that is pursuing a federal pilot (NIST SP 800-53 Rev. 5 Moderate).
#
# Every policy below carries a blast-radius block: what it changes, what could break, how to roll
# back. Effects are parameters, never literals, so promotion (Audit -> Deny) is a reviewed
# variable change in this stage, not an edit to the rule.

# --- 1. Require the `env` tag on resource groups (inventory hygiene; POA&M owner resolution) ---
# 800-53: CM-8
# blast radius: Audit marks untagged resource groups non-compliant; nothing is blocked.
#   could break (if promoted to Deny): any pipeline creating resource groups without `env`.
#   rollback: tag_policy_effect = "Audit".

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
# 800-53: AC-3, AC-6, SC-7
# blast radius: blocks any create/update that sets allowBlobPublicAccess = true.
#   could break: deployments that serve anonymous blobs (static assets, public downloads).
#   rollback: public_blob_policy_effect = "Audit" for a ticketed, time-boxed window.

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
# 800-53: AU-2, AU-12, SI-4
# blast radius: adds a `ds-to-grc-workspace` diagnostic setting to storage accounts that lack one.
#   could break: collides with an existing setting that already sends the same categories to the
#   same workspace (Azure rejects duplicates); adds Log Analytics ingestion cost.
#   rollback: remove the reference from the initiative; delete the settings it created.

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
# FAFO's own controls (4-9). Each starts at the effect it has EARNED:
#   4. Storage TLS floor         -> Audit  (new control; promote after the POA&M shows zero)
#   5. Cosmos key auth           -> Audit  (data-service Deny gets its own reviewed change)
#   6. Data residency            -> Audit or Deny, decided by the measured gap (discovery.tf)
#   7. Key Vault purge protection -> Audit (seeded vaults are known to lack it; fix first)
#   8. Subscription Owner        -> Audit  (standing Owner is a finding, not a blocked deploy)
#   9. Key Vault audit logs      -> DeployIfNotExists (feeds kql/keyvault-secret-reads-non-pipeline.kql)
# ================================================================================

# --- 4. Storage accounts must require TLS 1.2 ---
# Health data in transit to and from storage must use strong cryptography.
# 800-53: SC-8, SC-8(1), SC-13
# blast radius: Audit only marks storage accounts whose minimumTlsVersion is not TLS1_2.
#   could break (if promoted to Deny): creating or UPDATING an old account still at TLS 1.0/1.1,
#   including a tag change - so remediate with fafo-fix-min-tls (stage 06) before promoting.
#   rollback: storage_tls_policy_effect = "Audit".

resource "azurerm_policy_definition" "storage_min_tls" {
  name                = "fafo-storage-min-tls12"
  display_name        = "FAFO: storage accounts must require TLS 1.2"
  description         = "Data in transit to storage must use TLS 1.2 or later. NIST SP 800-53 Rev. 5 SC-8(1), SC-13."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "Storage", version = "1.0.0", owner = "fafo-grc" })

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
# 800-53: IA-2, IA-5, AC-2
# blast radius: Audit only marks Cosmos accounts with disableLocalAuth != true.
#   could break (if promoted to Deny): applications that connect with account keys or
#   connection strings stop being deployable until they move to Entra ID.
#   rollback: cosmos_local_auth_policy_effect = "Audit".

resource "azurerm_policy_definition" "cosmos_no_local_auth" {
  name                = "fafo-cosmos-no-local-auth"
  display_name        = "FAFO: Cosmos DB accounts must disable key-based authentication"
  description         = "Entra ID only on Cosmos DB, so every read/write is attributable to an identity. NIST SP 800-53 Rev. 5 IA-2, IA-5, AC-2."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "Cosmos DB", version = "1.0.0", owner = "fafo-grc" })

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
# A federal pilot and hospital customers both ask "where does the data live?". One answer: US.
# 800-53: SA-9(5) (added to FAFO's tailored Moderate baseline, oscal/fafo-moderate-profile.json), CM-2
# blast radius: Audit marks resources outside allowed_locations. At Deny, blocks creating
#   resources outside the list AND updating existing out-of-region resources - which is why
#   it only arms once the measured gap (discovery.tf) is zero.
#   rollback: allowed_locations_effect_override = "Audit" in a PR, with the reason.

resource "azurerm_policy_definition" "allowed_locations" {
  name                = "fafo-allowed-locations"
  display_name        = "FAFO: resources must deploy to approved US regions"
  description         = "Customer health data stays in approved US regions. Effect is parameterized so the control starts in Audit until the measured out-of-region gap is zero. NIST SP 800-53 Rev. 5 SA-9(5)."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "General", version = "1.0.0", owner = "fafo-grc" })

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

# --- 7. Key vaults must have purge protection ---
# The keys and secrets that protect FAFO's data must not be destroyable before their
# retention ends - by an attacker or by a hurried `terraform destroy`.
# 800-53: SC-12, CP-9
# blast radius: Audit marks vaults without enablePurgeProtection = true.
#   could break (if promoted to Deny): creating vaults without purge protection, and updates to
#   existing ones. Purge protection is ONE-WAY: once enabled it cannot be turned off, and a
#   deleted vault's name stays reserved for the retention period (7-90 days).
#   rollback: keyvault_purge_policy_effect = "Audit". Enabled purge protection is not rolled back.

resource "azurerm_policy_definition" "keyvault_purge_protection" {
  name                = "fafo-keyvault-purge-protection"
  display_name        = "FAFO: key vaults must have purge protection enabled"
  description         = "Cryptographic keys and secrets cannot be permanently destroyed inside their retention window. NIST SP 800-53 Rev. 5 SC-12, CP-9."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "Key Vault", version = "1.0.0", owner = "fafo-grc" })

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
        { field = "type", equals = "Microsoft.KeyVault/vaults" },
        {
          anyOf = [
            { field = "Microsoft.KeyVault/vaults/enablePurgeProtection", exists = "false" },
            { field = "Microsoft.KeyVault/vaults/enablePurgeProtection", equals = "false" }
          ]
        }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 8. Audit standing Owner role assignments at subscription scope ---
# Four engineers built FAFO's estate with Owner. A standing subscription Owner is the single
# largest blast radius in the tenant; this turns "who has Owner?" (Lab 1.2) into a control.
# Built-in Owner role GUID below is a platform constant, not a tenant or subscription ID.
# 800-53: AC-6(5), AC-6(7)
# blast radius: Audit marks every Owner assignment made at subscription scope (resource-group
#   and resource scopes are excluded) as non-compliant. Nothing is blocked or removed.
#   could break (if promoted to Deny): every new subscription-scope Owner grant, including
#   break-glass and onboarding. Keep it at Audit until a PIM/JIT path exists.
#   rollback: subscription_owner_policy_effect = "Audit" (or "Disabled").

resource "azurerm_policy_definition" "audit_subscription_owner" {
  name                = "fafo-audit-subscription-owner"
  display_name        = "FAFO: audit Owner role assignments at subscription scope"
  description         = "Standing Owner at subscription scope is reviewed as a finding. NIST SP 800-53 Rev. 5 AC-6(5) privileged accounts, AC-6(7) review of user privileges."
  policy_type         = "Custom"
  mode                = "All"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "Authorization", version = "1.0.0", owner = "fafo-grc" })

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
        { field = "type", equals = "Microsoft.Authorization/roleAssignments" },
        { field = "Microsoft.Authorization/roleAssignments/roleDefinitionId", like = "*/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635" },
        { field = "id", notContains = "/resourceGroups/" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 9. deployIfNotExists: key vault audit events go to the GRC workspace ---
# Without this, "who read a secret?" has no answer. It is the data source for
# kql/keyvault-secret-reads-non-pipeline.kql (tripwire 4, stage 07).
# 800-53: AU-2, AU-6, AU-12
# blast radius: adds a `ds-kv-to-grc-workspace` diagnostic setting (AuditEvent) to vaults that
#   lack one, as the remediation identity. Adds Log Analytics ingestion cost per secret operation.
#   could break: collides with an existing setting sending AuditEvent to the same workspace.
#   rollback: keyvault_audit_logs_policy_effect = "AuditIfNotExists"; delete created settings.

resource "azurerm_policy_definition" "keyvault_audit_logs" {
  name                = "fafo-dine-keyvault-audit-logs"
  display_name        = "FAFO: key vaults must send audit events to the GRC workspace"
  description         = "Secret, key and certificate access is logged centrally. NIST SP 800-53 Rev. 5 AU-2, AU-6, AU-12."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "Key Vault", version = "1.0.0", owner = "fafo-grc" })

  parameters = jsonencode({
    workspaceId = {
      type     = "String"
      metadata = { displayName = "Log Analytics workspace resource ID" }
    }
    effect = {
      type          = "String"
      allowedValues = ["DeployIfNotExists", "AuditIfNotExists", "Disabled"]
      defaultValue  = "DeployIfNotExists"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      field  = "type"
      equals = "Microsoft.KeyVault/vaults"
    }
    then = {
      effect = "[parameters('effect')]"
      details = {
        type = "Microsoft.Insights/diagnosticSettings"
        roleDefinitionIds = [
          # Monitoring Contributor (the remediation identity already holds it, identity.tf)
          "/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa"
        ]
        existenceCondition = {
          allOf = [
            { field = "Microsoft.Insights/diagnosticSettings/workspaceId", equals = "[parameters('workspaceId')]" },
            { field = "Microsoft.Insights/diagnosticSettings/logs.enabled", equals = "true" }
          ]
        }
        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              resourceName = { value = "[field('name')]" }
              workspaceId  = { value = "[parameters('workspaceId')]" }
            }
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                resourceName = { type = "string" }
                workspaceId  = { type = "string" }
              }
              resources = [
                {
                  type       = "Microsoft.KeyVault/vaults/providers/diagnosticSettings"
                  apiVersion = "2021-05-01-preview"
                  name       = "[concat(parameters('resourceName'), '/Microsoft.Insights/ds-kv-to-grc-workspace')]"
                  properties = {
                    workspaceId = "[parameters('workspaceId')]"
                    logs = [
                      { category = "AuditEvent", enabled = true }
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

# --- The initiative: one assignment, whole-sandbox inheritance ---

resource "azurerm_management_group_policy_set_definition" "grc_baseline" {
  name                = "cge-grc-baseline"
  display_name        = "FAFO GRC Baseline (NIST SP 800-53 Rev. 5 Moderate, tailored)"
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
    kvPurgeEffect         = { type = "String", defaultValue = "Audit" }
    subOwnerEffect        = { type = "String", defaultValue = "Audit" }
    kvAuditLogsEffect     = { type = "String", defaultValue = "DeployIfNotExists" }
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
    reference_id         = "fafoStorageMinTls"
    parameter_values = jsonencode({
      effect = { value = "[parameters('tlsEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.cosmos_no_local_auth.id
    reference_id         = "fafoCosmosNoLocalAuth"
    parameter_values = jsonencode({
      effect = { value = "[parameters('cosmosLocalAuthEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.allowed_locations.id
    reference_id         = "fafoAllowedLocations"
    parameter_values = jsonencode({
      allowedLocations = { value = "[parameters('allowedLocations')]" }
      effect           = { value = "[parameters('locationsEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.keyvault_purge_protection.id
    reference_id         = "fafoKeyVaultPurgeProtection"
    parameter_values = jsonencode({
      effect = { value = "[parameters('kvPurgeEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.audit_subscription_owner.id
    reference_id         = "fafoAuditSubscriptionOwner"
    parameter_values = jsonencode({
      effect = { value = "[parameters('subOwnerEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.keyvault_audit_logs.id
    reference_id         = "fafoKeyVaultAuditLogs"
    parameter_values = jsonencode({
      workspaceId = { value = "[parameters('workspaceId')]" }
      effect      = { value = "[parameters('kvAuditLogsEffect')]" }
    })
  }
}

resource "azurerm_management_group_policy_assignment" "grc_baseline" {
  name                 = "cge-grc-baseline"
  display_name         = "FAFO GRC Baseline"
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
    kvPurgeEffect         = { value = var.keyvault_purge_policy_effect }
    subOwnerEffect        = { value = var.subscription_owner_policy_effect }
    kvAuditLogsEffect     = { value = var.keyvault_audit_logs_policy_effect }
  })

  # Remediation effects (deployIfNotExists) execute AS this identity.
  # Without this block, Terraform applies cleanly and remediation silently never runs.
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.remediation.id]
  }
}
