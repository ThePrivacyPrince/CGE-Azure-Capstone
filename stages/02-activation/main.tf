terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # azurerm has a RESOURCE for Defender plan pricing but no data source —
    # azapi fills that gap by reading any ARM resource. This is the discovery
    # pattern for anything the azurerm provider can't yet interrogate.
    azapi = {
      source  = "azure/azapi"
      version = "~> 2.0"
    }
  }

  backend "azurerm" {
    key              = "02-activation.tfstate"
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {}
}

provider "azapi" {}

# The governed scope. Defender plans are a per-SUBSCRIPTION setting in Azure, so the stage
# enumerates every subscription under the management group from a data source and converges
# each one. A subscription moved under mg-grc-sandbox is in the next plan (and the nightly drift
# run flags it until applied) - nobody types its ID anywhere.
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

data "azurerm_management_group" "governed" {
  name = data.terraform_remote_state.foundation.outputs.management_group_name
}

locals {
  subscriptions = toset(data.azurerm_management_group.governed.all_subscription_ids)

  # One entry per (subscription, plan): "<subscription>/<plan>".
  pricing_targets = {
    for pair in setproduct(sort(local.subscriptions), sort(keys(var.baseline_plans))) :
    "${pair[0]}/${pair[1]}" => { subscription = pair[0], plan = pair[1], subplan = var.baseline_plans[pair[1]] }
  }
}

# ---------------------------------------------------------------------------
# STAGE 1 - DISCOVERY: detect what's already running, in every subscription.
# Pure reads. Run this stage a hundred times and it changes nothing on its own.
# ---------------------------------------------------------------------------

data "azapi_resource" "pricing" {
  for_each = local.pricing_targets

  type                   = "Microsoft.Security/pricings@2024-01-01"
  parent_id              = "/subscriptions/${each.value.subscription}"
  name                   = each.value.plan
  response_export_values = ["properties.pricingTier"]
}

locals {
  current_tier = {
    for key, d in data.azapi_resource.pricing :
    key => d.output.properties.pricingTier
  }

  # The gap map: what the baseline required that wasn't already on when this plan ran.
  # An INVENTORY OUTPUT, deliberately not the resource key - keying resources on live tiers
  # you're about to change makes Terraform undo the plan it just enabled on the next run
  # (read-your-own-writes). We validated that failure mode so you don't have to.
  activation_needed = {
    for key, tier in local.current_tier : key => tier
    if tier != "Standard"
  }
}

# ---------------------------------------------------------------------------
# STAGE 2 - ACTIVATION: converge the baseline to Standard in every subscription.
# azapi_update_resource PATCHES the pricing that Azure always has (Free or Standard), so no
# import is needed and plans outside the baseline are never touched. Destroying this stage
# leaves the plans as they are (course teardown: set them back to Free with az security pricing).
# ---------------------------------------------------------------------------

resource "azapi_update_resource" "baseline" {
  for_each = local.pricing_targets

  type        = "Microsoft.Security/pricings@2024-01-01"
  resource_id = "/subscriptions/${each.value.subscription}/providers/Microsoft.Security/pricings/${each.value.plan}"

  body = {
    properties = merge(
      { pricingTier = "Standard" },
      each.value.subplan != "" ? { subPlan = each.value.subplan } : {},
    )
  }
}

# The single-subscription azurerm resources this replaces are forgotten, not destroyed:
# destroying them would flip Defender back to Free.
removed {
  from = azurerm_security_center_subscription_pricing.baseline

  lifecycle {
    destroy = false
  }
}

# The federal track's platform-native assessment: the built-in NIST SP 800-53 Rev. 5 regulatory
# compliance initiative, assigned at the MANAGEMENT GROUP so every subscription inherits it.
# (Replaces the subscription-scoped NIST CSF 2.0 assignment adopted in Lab 2.)
# blast radius: Audit/AuditIfNotExists effects as assigned; adds Defender regulatory-compliance
#   views. Its few DeployIfNotExists members run as the remediation identity only through an
#   explicitly created remediation task. rollback: delete this assignment.
resource "azurerm_management_group_policy_assignment" "nist_800_53_r5" {
  name                 = "nist-800-53-r5"
  display_name         = "NIST SP 800-53 Rev. 5"
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/179d1daa-458f-4e47-8086-2a68d0d6c38f"
  management_group_id  = data.terraform_remote_state.foundation.outputs.management_group_id
  location             = var.location

  identity {
    type         = "UserAssigned"
    identity_ids = [data.terraform_remote_state.foundation.outputs.remediation_identity_id]
  }
}
