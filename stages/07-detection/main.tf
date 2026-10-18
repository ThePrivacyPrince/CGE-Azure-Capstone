# Stage 07 - Detection: the second drift question, codified.
#
# Drift has two questions and the rubric asks for both:
#   1. Does reality match code?      -> .github/workflows/drift.yml (scheduled terraform plan)
#   2. Who is touching reality?      -> this stage (Activity Log tripwires, as alert rules)
# They fail differently, which is why both exist. A plan only sees resources in its own
# state - Lab 6's seed storage account was changed out-of-band and no plan would ever have
# noticed. The Activity Log sees every write in the subscription, managed or not.
#
# The starter ran the tripwire as a KQL query by hand (Lab 2). Here it is a scheduled
# alert rule that runs every 15 minutes whether anyone remembers or not.

locals {
  f = data.terraform_remote_state.foundation.outputs

  workspace_id    = local.f.log_analytics_workspace_id
  workspace_rg    = element(split("/", local.workspace_id), 4)
  remediation_pid = local.f.remediation_identity_principal_id

  # Expected writers: approved humans/CI + the remediation identity (which also has its
  # own, tighter rule). Activity Log records users by UPN and managed identities by
  # principal ID - Lab 6 verified the latter for the remediator.
  expected_callers     = distinct(concat(var.approved_change_callers, [local.remediation_pid]))
  expected_callers_kql = join(", ", [for c in local.expected_callers : "\"${c}\""])

  # The remediator's whole job, as Activity Log operations: the stage 06 Modify fixes
  # (storage writes) and the stage 01 DeployIfNotExists diagnostics (a deployment that
  # writes a diagnostic setting). Anything else is out of lane.
  remediator_lane = [
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
    "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
  ]
  remediator_lane_kql = join(", ", [for op in local.remediator_lane : "\"${op}\""])

  tags = {
    env     = "dev"
    purpose = "grc-detection"
  }
}

# Adopt Lab 2's Activity Log routing into code instead of creating a duplicate (Azure
# rejects two settings that send the same categories to the same workspace). If you never
# ran route-activity-log.sh, delete this import block and the resource will be created.
import {
  to = azurerm_monitor_diagnostic_setting.activity_log
  id = "/subscriptions/${var.subscription_id}|${var.activity_log_setting_name}"
}

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = var.activity_log_setting_name
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = local.workspace_id

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "Policy"
  }

  enabled_log {
    category = "Alert"
  }
}

resource "azurerm_monitor_action_group" "grc" {
  name                = "ag-tallyfin-grc"
  resource_group_name = local.workspace_rg
  short_name          = "grc-trip"

  email_receiver {
    name                    = "grc-owner"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }

  tags = local.tags
}

# Tripwire 1 - out-of-band change. Any successful write or delete by a caller who is not
# an approved operator or the remediation identity. (CSF DE.CM-03; 800-53 CM-3, AU-6)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "unexpected_writer" {
  name                 = "tripwire-unexpected-writer"
  resource_group_name  = local.workspace_rg
  location             = var.location
  scopes               = [local.workspace_id]
  display_name         = "GRC tripwire: change by an unexpected principal"
  description          = "Out-of-band change detector. Expected callers come from approved_change_callers plus the remediation identity."
  severity             = 2
  evaluation_frequency = "PT15M"
  window_duration      = "PT15M"

  criteria {
    query                   = <<-KQL
      AzureActivity
      | where CategoryValue == "Administrative"
      | where ActivityStatusValue =~ "Success"
      | where OperationNameValue endswith "/WRITE" or OperationNameValue endswith "/DELETE"
      | where Caller !in~ (${local.expected_callers_kql})
      | project TimeGenerated, Caller, OperationNameValue, _ResourceId, CorrelationId
    KQL
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }

  action {
    action_groups = [azurerm_monitor_action_group.grc.id]
  }

  tags = local.tags
}

# Tripwire 2 - the remediation identity out of its lane. Compensating control for the
# residual risk documented in stage 06: storageAccounts/write cannot be limited to one
# property, so anything outside the identity's two known jobs is alert-worthy. (800-53 AC-6(9); CSF PR.AA-05)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "remediator_out_of_lane" {
  name                 = "tripwire-remediator-out-of-lane"
  resource_group_name  = local.workspace_rg
  location             = var.location
  scopes               = [local.workspace_id]
  display_name         = "GRC tripwire: remediation identity acted outside its lane"
  description          = "Fires when the remediation identity performs any operation outside its lane (storage property writes, DINE diagnostic deployments)."
  severity             = 1
  evaluation_frequency = "PT15M"
  window_duration      = "PT15M"

  criteria {
    query                   = <<-KQL
      AzureActivity
      | where Caller =~ "${local.remediation_pid}"
      | where OperationNameValue !in~ (${local.remediator_lane_kql})
      | project TimeGenerated, OperationNameValue, ActivityStatusValue, _ResourceId, CorrelationId
    KQL
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }

  action {
    action_groups = [azurerm_monitor_action_group.grc.id]
  }

  tags = local.tags
}

output "tripwire_rules" {
  value = [
    azurerm_monitor_scheduled_query_rules_alert_v2.unexpected_writer.name,
    azurerm_monitor_scheduled_query_rules_alert_v2.remediator_out_of_lane.name,
  ]
}

output "expected_callers_count" {
  description = "How many callers are on the allow-list (values are not echoed)."
  value       = length(local.expected_callers)
}
