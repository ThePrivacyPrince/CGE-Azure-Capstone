variable "remediation_mode" {
  description = "Escalation ladder: audit -> dry-run -> enforce. Each step up should be a reviewed PR — automation acts, humans authorize."
  type        = string
  default     = "dry-run"
  validation {
    condition     = contains(["audit", "dry-run", "enforce"], var.remediation_mode)
    error_message = "remediation_mode must be audit, dry-run, or enforce."
  }
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "state_resource_group" {
  type    = string
  default = "rg-grc-tfstate"
}

variable "state_storage_account" {
  type = string
}

# --- Tallyfin capstone: the human approval gate ------------------------------------

variable "approved_remediations" {
  description = "Corrective controls a reviewer has approved for a remediation task in THIS change. Remove the key after the task succeeds so the file always shows what is pending."
  type        = set(string)
  default     = []
  validation {
    condition     = alltrue([for k in var.approved_remediations : contains(["fix-public-blob", "fix-min-tls"], k)])
    error_message = "approved_remediations may only contain fix-public-blob or fix-min-tls."
  }
}

variable "remediation_change_ticket" {
  description = "Change ticket that approved the remediation (becomes part of the task name, so the Azure-side record points back to the approval)."
  type        = string
  default     = "none"
  validation {
    condition     = can(regex("^[a-z0-9-]{1,24}$", var.remediation_change_ticket))
    error_message = "Use a short lowercase ticket id such as chg-0007."
  }
}
