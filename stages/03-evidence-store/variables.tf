variable "location" {
  description = "Azure region for the evidence store. Default eastus2: East US frequently lacks Cosmos capacity and consumption-plan quota for new subscriptions."
  type        = string
  default     = "eastus2"
}

variable "environment" {
  description = "Environment name used in tags and resource names."
  type        = string
  default     = "dev"
}

variable "state_resource_group" {
  description = "Resource group holding the Terraform state storage account (from bootstrap.sh)."
  type        = string
  default     = "rg-grc-tfstate"
}

variable "state_storage_account" {
  description = "Terraform state storage account name (from bootstrap.sh / backend.hcl)."
  type        = string
}

variable "reports_retention_days" {
  description = "WORM retention on the reports container. 90 for the course; whatever your obligations demand in production."
  type        = number
  default     = 90
}

variable "functions_location" {
  description = "Region for the Function tier. Free-account consumption (Y1) quota is REGIONAL and zero in most US regions; centralus and westus3 had quota in validation. Probe with labs/00-setup/probe-quota.sh."
  type        = string
  default     = "centralus"
}

# --- Tallyfin capstone additions -------------------------------------------------

variable "collect_schedule" {
  description = "NCRONTAB (UTC, 6 fields). Every 6 hours: four snapshots a day show posture moving over time, and a remediation shows up in evidence within hours instead of the next night."
  type        = string
  default     = "0 0 */6 * * *"
}

variable "enable_manual_triggers" {
  description = "Expose the key-protected HTTP trigger for demos. Off by default: the pipeline should need zero stored credentials, and run history should come from timers."
  type        = bool
  default     = false
}

variable "app_version" {
  description = "Stamped on every evidence document and manifest. Set to the git SHA when deploying code."
  type        = string
  default     = "dev"
}
