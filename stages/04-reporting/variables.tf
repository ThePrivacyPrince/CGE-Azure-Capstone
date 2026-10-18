variable "environment" {
  type    = string
  default = "dev"
}

variable "functions_location" {
  description = "Region for the reporting Function tier. Same free-account quota constraint as stage 03 — probe with labs/00-setup/probe-quota.sh."
  type        = string
  default     = "centralus"
}

variable "state_resource_group" {
  type    = string
  default = "rg-grc-tfstate"
}

variable "state_storage_account" {
  type = string
}

# --- Tallyfin capstone additions -------------------------------------------------

variable "poam_schedule" {
  description = "Daily POA&M (UTC). Runs 40 minutes after the 06:00 collection so it reads a completed run."
  type        = string
  default     = "0 40 6 * * *"
}

variable "sar_schedule" {
  description = "Daily SAR + framework scorecard (UTC). Daily rather than the starter's weekly so the grader sees a run history, not four data points."
  type        = string
  default     = "0 50 6 * * *"
}

variable "max_run_age_hours" {
  description = "Reports refuse to publish from a completed run older than this. A stalled collector then shows up as a failed report instead of stale numbers that look current."
  type        = number
  default     = 13
}

variable "enable_manual_triggers" {
  description = "Expose key-protected HTTP triggers for demos. Off by default."
  type        = bool
  default     = false
}

variable "app_version" {
  type    = string
  default = "dev"
}
