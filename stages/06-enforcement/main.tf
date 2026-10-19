terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }

  backend "azurerm" {
    key              = "06-enforcement.tfstate"
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {}
}

data "terraform_remote_state" "foundation" {
  backend = "azurerm"
  config = {
    resource_group_name  = var.state_resource_group
    storage_account_name = var.state_storage_account
    container_name       = "tfstate"
    key                  = "01-foundation.tfstate"
    use_azuread_auth     = true
  }
}

locals {
  mg_id           = data.terraform_remote_state.foundation.outputs.management_group_id
  remediation_id  = data.terraform_remote_state.foundation.outputs.remediation_identity_id
  remediation_pid = data.terraform_remote_state.foundation.outputs.remediation_identity_principal_id

  # The escalation ladder, wired to one variable. Each step up is a reviewed PR
  # (stages/06-enforcement is CODEOWNERS-protected; see docs/BLAST-RADIUS.md):
  #   audit   -> corrective controls Disabled; the paired DETECTIVE controls in stage 01
  #              (cge-deny-public-blob, fafo-storage-min-tls12) keep reporting the gap
  #   dry-run -> Modify effect deployed, but enforcement_mode DoNotEnforce;
  #              remediation happens only through a task a human approved (below)
  #   enforce -> Modify enforced on new/updated requests; existing resources
  #              STILL need a remediation task (Lab 6 finding)
  # The effect is an assignment PARAMETER (allowedValues Modify / Disabled), never a literal in
  # the rule. Audit is deliberately not offered: a Modify rule's details block is not valid
  # under Audit, so "observe only" belongs to the detective twin, not the corrective control.
  effect           = var.remediation_mode == "audit" ? "Disabled" : "Modify"
  enforcement_mode = var.remediation_mode == "enforce" ? "Default" : "DoNotEnforce"

  # Required field on Modify policies. It names the roles a PORTAL-created identity would
  # be auto-granted; it grants nothing itself. Our identity's real permissions are the
  # custom role below, which is narrower than this built-in.
  storage_account_contributor = "/providers/Microsoft.Authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab"

  # One entry per corrective control. fix-public-blob is the starter's; fix-min-tls is
  # FAFO's own (pairs with the fafo-storage-min-tls12 detective control in stage 01).
  corrective_controls = {
    fix-public-blob = {
      definition_name = "cge-fix-public-blob"
      display_name    = "Remediate: disable public blob access on storage accounts"
      condition       = { field = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", notEquals = "false" }
      field           = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess"
      value           = false
    }
    fix-min-tls = {
      definition_name = "fafo-fix-min-tls"
      display_name    = "FAFO remediate: set storage minimum TLS to 1.2"
      condition       = { field = "Microsoft.Storage/storageAccounts/minimumTlsVersion", notEquals = "TLS1_2" }
      field           = "Microsoft.Storage/storageAccounts/minimumTlsVersion"
      value           = "TLS1_2"
    }
  }
}

# Keep the starter's live objects: re-address them into the map instead of
# destroying and recreating the policy that Lab 6 already exercised.
moved {
  from = azurerm_policy_definition.fix_public_blob
  to   = azurerm_policy_definition.fix["fix-public-blob"]
}

moved {
  from = azurerm_management_group_policy_assignment.fix_public_blob
  to   = azurerm_management_group_policy_assignment.fix["fix-public-blob"]
}

# blast radius (both controls): see docs/BLAST-RADIUS.md for the per-control table.
#   fix-public-blob: flips allowBlobPublicAccess to false on storage accounts under
#     mg-grc-sandbox. Breaks: any workload serving anonymous blobs (none should exist -
#     the stage 01 Deny already blocks new ones). Cannot delete, cannot read data.
#   fix-min-tls: sets minimumTlsVersion to TLS1_2. Breaks: clients still on TLS 1.0/1.1
#     (old SDKs, legacy SFTP tooling) start failing handshakes.
#   rollback: set remediation_mode = "audit" (or remove the key from approved_remediations)
#     and merge. A completed remediation is not undone by rollback - revert the property
#     by hand only through a ticketed exception.
resource "azurerm_policy_definition" "fix" {
  for_each = local.corrective_controls

  name                = each.value.definition_name
  display_name        = each.value.display_name
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = local.mg_id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Modify", "Disabled"]
      defaultValue  = "Disabled"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        each.value.condition
      ]
    }
    then = {
      effect = "[parameters('effect')]"
      details = {
        roleDefinitionIds = [local.storage_account_contributor]
        conflictEffect    = "audit"
        operations = [
          { operation = "addOrReplace", field = each.value.field, value = each.value.value }
        ]
      }
    }
  })
}

# blast radius: an assignment by itself changes nothing in dry-run (DoNotEnforce).
# In enforce, it rewrites matching create/update requests in flight.
resource "azurerm_management_group_policy_assignment" "fix" {
  for_each = local.corrective_controls

  name                 = each.value.definition_name
  display_name         = "${each.value.display_name} (${var.remediation_mode})"
  policy_definition_id = azurerm_policy_definition.fix[each.key].id
  management_group_id  = local.mg_id
  location             = var.location
  enforce              = local.enforcement_mode == "Default"

  # The escalation ladder reaches the rule only through this parameter.
  parameters = jsonencode({
    effect = { value = local.effect }
  })

  # Remediation runs AS the single named identity. Activity Log `caller` will show its
  # principal ID - that is how Lab 6 attributed the fix.
  identity {
    type         = "UserAssigned"
    identity_ids = [local.remediation_id]
  }

  non_compliance_message {
    content = "Corrective control in ${var.remediation_mode} mode. Existing resources are fixed only by a remediation task approved in stages/06-enforcement (approved_remediations)."
  }
}

# --- Least privilege for the remediation identity -------------------------------------
#
# Lab 6 finding: Storage Account Contributor is far wider than "change one property".
# It includes listKeys (read every blob in every account), regenerateKey, and delete.
# This role is the job and nothing else.
#
# blast radius: the identity can update storage account properties under mg-grc-sandbox.
# It cannot read keys or data, cannot delete accounts, cannot touch any other resource type.
# Residual risk: ARM cannot scope a write to one property, so storageAccounts/write still
# allows other property changes. Compensating control: the stage 07 tripwire alerts on any
# operation by this identity, and every write it makes is attributable in the Activity Log.
# rollback: remove the assignment; remediation tasks then fail closed (AuthorizationFailed).
resource "azurerm_role_definition" "remediator" {
  name        = "fafo-storage-baseline-remediator"
  scope       = local.mg_id
  description = "Policy Modify remediation for storage baseline properties. No keys, no delete, no data access."

  permissions {
    actions = [
      "Microsoft.Storage/storageAccounts/read",
      "Microsoft.Storage/storageAccounts/write",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
    ]
    not_actions = [
      "Microsoft.Storage/storageAccounts/listKeys/action",
      "Microsoft.Storage/storageAccounts/regeneratekey/action",
      "Microsoft.Storage/storageAccounts/delete",
    ]
  }

  assignable_scopes = [local.mg_id]
}

# The remediation identity earns the role only when remediation can actually run.
resource "azurerm_role_assignment" "remediation_storage" {
  count              = var.remediation_mode == "audit" ? 0 : 1
  scope              = local.mg_id
  role_definition_id = azurerm_role_definition.remediator.role_definition_resource_id
  principal_id       = local.remediation_pid
  principal_type     = "ServicePrincipal"
  description        = "Single remediation identity for storage baseline Modify policies."
}

# --- The human gate, as code ------------------------------------------------------------
#
# Lab 6 approved remediation by running `az policy remediation create` by hand. That works,
# but the approval left no reviewable record. Here a reviewer approves a control key in a PR
# (approved_remediations + a change ticket); the merge IS the approval, and git history is
# the approval log. Audit mode has nothing to remediate with, so no task is created there.
#
# blast radius: one task fixes every non-compliant storage account in scope for that
# control at the time it runs (failure_percentage stops it if >10% of fixes fail).
resource "azurerm_management_group_policy_remediation" "approved" {
  for_each = var.remediation_mode == "audit" ? toset([]) : var.approved_remediations

  name                 = "rem-${each.key}-${var.remediation_change_ticket}"
  management_group_id  = local.mg_id
  policy_assignment_id = azurerm_management_group_policy_assignment.fix[each.key].id
  failure_percentage   = 0.1
  parallel_deployments = 5

  depends_on = [azurerm_role_assignment.remediation_storage]
}

output "remediation_mode" {
  value = var.remediation_mode
}

output "remediation_tasks" {
  description = "Remediation tasks this apply created. Empty unless a reviewer approved control keys."
  value       = { for k, r in azurerm_management_group_policy_remediation.approved : k => r.id }
}

output "remediator_principal_id" {
  description = "Match against Activity Log `caller` to attribute every automated fix."
  value       = local.remediation_pid
}
