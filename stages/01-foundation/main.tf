# --- The hierarchy (adopted from Lab 1 via `terraform import`, never recreated) ---

data "azurerm_subscription" "current" {}

resource "azurerm_management_group" "grc" {
  name         = "mg-grc"
  display_name = "GRC Engineering"
}

resource "azurerm_management_group" "sandbox" {
  name                       = "mg-grc-sandbox"
  display_name               = "GRC Sandbox"
  parent_management_group_id = azurerm_management_group.grc.id

  # Membership is NOT declared here. A subscription list on the management group would make
  # Terraform remove every subscription someone moves in by hand - FAFO's other two would be
  # ripped back out on the next apply. Membership is the association below (this sandbox) or
  # an onboarding move; governance then inherits by scope.
  lifecycle {
    ignore_changes = [subscription_ids]
  }
}

# The sandbox subscription joins the governed scope. Existing deployments adopt it:
#   terraform import azurerm_management_group_subscription_association.sandbox \
#     "/providers/Microsoft.Management/managementGroups/mg-grc-sandbox/subscriptions/$ARM_SUBSCRIPTION_ID"
resource "azurerm_management_group_subscription_association" "sandbox" {
  management_group_id = azurerm_management_group.sandbox.id
  subscription_id     = data.azurerm_subscription.current.id
}

# --- The sandbox resource group (adopted from Lab 1) ---

resource "azurerm_resource_group" "sandbox" {
  name     = "rg-grc-sandbox-dev"
  location = var.location
  tags = {
    env     = var.environment
    owner   = var.owner_email
    purpose = "cge-az-labs"
  }
}

# --- Log Analytics workspace (adopted from Lab 2) — the GRC program's log destination ---

resource "azurerm_log_analytics_workspace" "grc" {
  name                = "law-grc-sandbox"
  location            = var.location
  resource_group_name = azurerm_resource_group.sandbox.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags = {
    env     = var.environment
    purpose = "cge-az-labs"
  }
}

# --- Evidence resource group — Domain 4 fills this with the store ---

resource "azurerm_resource_group" "evidence" {
  name     = "rg-grc-evidence-${var.environment}"
  location = var.location
  tags = {
    env     = var.environment
    owner   = var.owner_email
    purpose = "grc-evidence-plane"
  }
}
