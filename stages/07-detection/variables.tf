variable "subscription_id" {
  description = "The subscription that hosts the state account and Lab 2's Activity Log setting (TF_VAR_subscription_id). An identifier, not a secret. Governance does NOT key off it: the routed subscriptions are discovered from the management group."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.subscription_id))
    error_message = "subscription_id must be a GUID."
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
  description = "Region for the alert rules (must match the workspace's region)."
  type        = string
  default     = "eastus"
}

variable "alert_email" {
  description = "Where tripwire alerts go. Supply via TF_VAR_alert_email; it is never committed (no PII in the repo)."
  type        = string
  sensitive   = true
}

variable "approved_change_callers" {
  description = "Activity Log `Caller` values whose writes are expected: your UPN (the human who runs terraform apply) and any CI apply identity's object ID. Supply via TF_VAR_approved_change_callers='[\"you@example.com\"]'. Everyone else's writes are out-of-band by definition."
  type        = list(string)
  default     = []
}

variable "activity_log_setting_name" {
  description = "Name of the subscription diagnostic setting Lab 2 created with route-activity-log.sh. This stage adopts it into code rather than creating a duplicate."
  type        = string
  default     = "ds-activity-to-law"
}
