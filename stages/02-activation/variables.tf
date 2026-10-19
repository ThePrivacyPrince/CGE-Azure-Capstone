variable "baseline_plans" {
  description = "Defender plans the course baseline requires at Standard, mapped to their subplan (Azure stamps a default subplan on enablement; omitting it in config forces replacement on every run — we validated that churn so you don't have to). Empty string = no subplan. Applied to every subscription under the management group. Each plan has a 30-day free trial."
  type        = map(string)
  default = {
    StorageAccounts = "DefenderForStorageV2"
    KeyVaults       = "PerKeyVault"
  }
}

variable "state_resource_group" {
  type    = string
  default = "rg-grc-tfstate"
}

variable "state_storage_account" {
  type = string
}

variable "location" {
  description = "Region for the regulatory-compliance assignment's managed identity record."
  type        = string
  default     = "eastus"
}
