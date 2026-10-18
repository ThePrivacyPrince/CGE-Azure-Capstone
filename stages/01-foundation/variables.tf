variable "location" {
  description = "Azure region for foundation resources."
  type        = string
  default     = "eastus"
}

variable "owner_email" {
  description = "Owner tag applied to governed resource groups; the POA&M generator resolves finding owners from it."
  type        = string
}

variable "environment" {
  description = "Environment name used in tags and resource names."
  type        = string
  default     = "dev"
}

variable "tag_policy_effect" {
  description = "Effect for the require-env-tag policy (Audit while onboarding, Deny once clean)."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.tag_policy_effect)
    error_message = "tag_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "public_blob_policy_effect" {
  description = "Effect for the deny-public-blob-access policy. This one has earned Deny."
  type        = string
  default     = "Deny"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.public_blob_policy_effect)
    error_message = "public_blob_policy_effect must be Audit, Deny, or Disabled."
  }
}

# --- Tallyfin capstone additions -------------------------------------------------

variable "allowed_locations" {
  description = "Regions Tallyfin data may live in. US-only keeps the GLBA data map simple. Includes every region the starter stages already use (eastus for foundation, eastus2 for the evidence store, centralus for the Function tier) so nothing deployed today is out of policy."
  type        = list(string)
  default     = ["eastus", "eastus2", "centralus"]
}

variable "allowed_locations_effect_override" {
  description = "Leave null so the measured gap decides (Audit while anything is out of region, Deny at zero). Set only through a reviewed PR, with the reason in the PR body."
  type        = string
  default     = null
  validation {
    condition     = var.allowed_locations_effect_override == null ? true : contains(["Audit", "Deny", "Disabled"], var.allowed_locations_effect_override)
    error_message = "allowed_locations_effect_override must be null, Audit, Deny, or Disabled."
  }
}

variable "storage_tls_policy_effect" {
  description = "Effect for the storage TLS 1.2 floor. A new control starts at Audit; promote to Deny once the POA&M shows zero open findings for it."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.storage_tls_policy_effect)
    error_message = "storage_tls_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "cosmos_local_auth_policy_effect" {
  description = "Effect for the Cosmos DB key-auth control. Audit: the evidence store already complies, and Deny on a data service deserves its own reviewed change."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.cosmos_local_auth_policy_effect)
    error_message = "cosmos_local_auth_policy_effect must be Audit, Deny, or Disabled."
  }
}
