# --- FAFO: discovery before activation for the data-residency guardrail ---------------
#
# FAFO holds health data for hospital customers and is entering a federal pilot, so where
# resources live is a contractual and regulatory question, not a preference.
# The allowed-locations policy must not be switched to Deny blindly: if any resource already
# sits outside the approved list, Deny would block its next update (a tag change, a scale
# operation) and the guardrail would cause the outage.
#
# So: inventory first (pure read), measure the gap, and let the gap decide the effect.
#   gap > 0  -> Audit  (the policy reports the stragglers; migrate them)
#   gap == 0 -> Deny   (the control has been earned)
# A reviewed override variable exists for the rare case a human must decide otherwise.
#
# Scale by scope, not by size: the inventory is an Azure Resource Graph query over the whole
# MANAGEMENT GROUP, not one subscription. When FAFO's other two subscriptions are moved under
# mg-grc-sandbox, their resources are in the next plan's gap with no change to this file.

locals {
  # "global" covers non-regional resources (DNS zones, Front Door, some Defender objects)
  # that cannot be placed in a region and are out of this control's scope.
  location_exempt  = ["global"]
  region_allowlist = join(", ", [for l in concat(var.allowed_locations, local.location_exempt) : "'${lower(l)}'"])
}

data "azapi_resource_action" "out_of_region" {
  type        = "Microsoft.ResourceGraph@2022-10-01"
  resource_id = "/providers/Microsoft.ResourceGraph"
  action      = "resources"
  method      = "POST"

  body = {
    managementGroups = [azurerm_management_group.sandbox.name]
    query            = "resources | where location !in~ (${local.region_allowlist}) | project id, location, subscriptionId | order by id asc"
    options          = { resultFormat = "objectArray", "$top" = 1000 }
  }

  response_export_values = ["data", "totalRecords"]
}

locals {
  out_of_region_resources = [for r in data.azapi_resource_action.out_of_region.output.data : r.id]

  # totalRecords, not length(data): the list is capped at 1000 rows, the count is not.
  region_gap = tonumber(data.azapi_resource_action.out_of_region.output.totalRecords)

  allowed_locations_effect = coalesce(
    var.allowed_locations_effect_override,
    local.region_gap == 0 ? "Deny" : "Audit",
  )
}
