# --- Tallyfin capstone: discovery before activation for the data-residency guardrail ---
#
# Tallyfin (a fictional Plaid-style bank-data API) stores consumer financial data,
# so where resources live is a GLBA / state-privacy question, not a preference.
# The allowed-locations policy below must not be switched to Deny blindly: if any
# resource already sits outside the approved list, Deny would block its next update
# (a tag change, a scale operation) and the guardrail would cause the outage.
#
# So: inventory first (pure read), measure the gap, and let the gap decide the effect.
#   gap > 0  -> Audit  (the policy reports the stragglers; migrate them)
#   gap == 0 -> Deny   (the control has been earned)
# A reviewed override variable exists for the rare case a human must decide otherwise.

data "azurerm_resources" "subscription_inventory" {}

locals {
  # "global" covers non-regional resources (DNS zones, Front Door, some Defender
  # objects) that cannot be placed in a region and are out of this control's scope.
  location_exempt = ["global"]

  out_of_region_resources = sort([
    for r in data.azurerm_resources.subscription_inventory.resources : r.id
    if !contains(concat(var.allowed_locations, local.location_exempt), lower(replace(r.location, " ", "")))
  ])

  region_gap = length(local.out_of_region_resources)

  allowed_locations_effect = coalesce(
    var.allowed_locations_effect_override,
    local.region_gap == 0 ? "Deny" : "Audit",
  )
}
