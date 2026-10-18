terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # azurerm's storage data source does not expose allowSharedKeyAccess or blob
    # soft-delete settings; azapi reads any ARM property (same pattern as stage 02).
    azapi = {
      source  = "azure/azapi"
      version = "~> 2.0"
    }
  }

  backend "azurerm" {
    key              = "07-detection.tfstate"
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {}
  # Explicit targeting: the import ID below needs the subscription at plan time, so this
  # stage takes it as a variable (TF_VAR_subscription_id) instead of ARM_SUBSCRIPTION_ID.
  subscription_id = var.subscription_id
}

provider "azapi" {}

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
