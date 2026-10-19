# Stage 07 - Detection: the second drift question, codified.
#
# Drift has two questions and the rubric asks for both:
#   1. Does reality match code?      -> .github/workflows/drift.yml (scheduled terraform plan)
#   2. Who is touching reality?      -> this stage (Activity Log tripwires, as alert rules)
# They fail differently, which is why both exist. A plan only sees resources in its own
# state - Lab 6's seed storage account was changed out-of-band and no plan would ever have
# noticed. The Activity Log sees every write in the subscription, managed or not.
#
# The starter ran the tripwire as a KQL query by hand (Lab 2). Here every query is a file in
# kql/ (readable and runnable on its own) and the SAME file becomes a scheduled alert rule via
# templatefile, so the query an assessor reads is the query that runs. Four rules:
#   1. unexpected-writer                    (course-derived baseline)
#   2. remediator-out-of-lane               (FAFO: compensating control for RISK-0002)
#   3. off-hours-admin-changes              (FAFO: humans changing prod outside the change window)
#   4. keyvault-secret-reads-non-pipeline   (FAFO: secrets read by anything but approved identities)

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

  # Identities allowed to read Key Vault secrets: the pipeline's own plus any approved app.
  pipeline_ids = distinct(compact(concat(
    [
      local.remediation_pid,
      data.terraform_remote_state.evidence.outputs.collector_principal_id,
      data.terraform_remote_state.reporting.outputs.reporter_principal_id,
    ],
    var.approved_secret_reader_ids,
  )))
  pipeline_ids_kql = join(", ", [for id in local.pipeline_ids : "\"${id}\""])

  kql_dir = "${path.module}/../../kql"

  tags = {
    env     = var.environment
    purpose = "grc-detection"
  }
}

# Every subscription under the management group routes its Activity Log to the one GRC
# workspace, so the tripwires below see the whole estate. Discovered, not listed: FAFO's next
# subscription is routed by the next apply (and the nightly drift plan says so until it is).
data "azurerm_management_group" "governed" {
  name = local.f.management_group_name
}

# Adopt Lab 2's routing for the sandbox subscription instead of creating a duplicate (Azure
# rejects two settings that send the same categories to the same workspace). Import is a
# no-op once the address is in state. If you never ran route-activity-log.sh, delete this block.
# If you applied stage 07 before it was per-subscription, first run:
#   terraform state mv azurerm_monitor_diagnostic_setting.activity_log \
#     'azurerm_monitor_diagnostic_setting.activity_log["<subscription-guid>"]'
import {
  for_each = toset([var.subscription_id])
  to       = azurerm_monitor_diagnostic_setting.activity_log[each.key]
  id       = "/subscriptions/${each.key}|${var.activity_log_setting_name}"
}

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  for_each = toset(data.azurerm_management_group.governed.all_subscription_ids)

  name                       = var.activity_log_setting_name
  target_resource_id         = "/subscriptions/${each.key}"
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
  name                = "ag-fafo-grc"
  resource_group_name = local.workspace_rg
  short_name          = "grc-trip"

  email_receiver {
    name                    = "grc-owner"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }

  tags = local.tags
}

# Every tripwire looks back an hour by event time but only counts rows INGESTED in the last
# 15 minutes. Activity Log and Key Vault rows often reach the workspace several minutes after the
# event; a plain 15-minute window on TimeGenerated would miss any row that arrived late, and a
# wider window alone would alert on the same row twice. ingestion_time() gives each row exactly
# one evaluation, as long as ingestion lag stays under 45 minutes.
locals {
  tripwire_window   = "PT1H"
  tripwire_new_rows = "| where ingestion_time() > ago(15m)"

  tripwires = {
    unexpected-writer = {
      display_name = "GRC tripwire: change by an unexpected principal"
      description  = "Out-of-band change detector (course-derived). Expected callers come from approved_change_callers plus the remediation identity."
      severity     = 2
      query = templatefile("${local.kql_dir}/unexpected-writer.kql", {
        new_rows_filter  = local.tripwire_new_rows
        expected_callers = local.expected_callers_kql
      })
    }
    remediator-out-of-lane = {
      display_name = "GRC tripwire: remediation identity acted outside its lane"
      description  = "The remediation identity performed an operation outside storage property writes and DINE diagnostic deployments (RISK-0002 compensating control)."
      severity     = 1
      query = templatefile("${local.kql_dir}/remediator-out-of-lane.kql", {
        new_rows_filter = local.tripwire_new_rows
        remediator_id   = local.remediation_pid
        lane_operations = local.remediator_lane_kql
      })
    }
    off-hours-admin-changes = {
      display_name = "FAFO tripwire: human change outside the change window"
      description  = "A person (UPN caller) changed resources outside ${var.business_hours.start}:00-${var.business_hours.end}:00 ${var.business_hours.timezone}, Monday to Friday."
      severity     = 3
      query = templatefile("${local.kql_dir}/off-hours-admin-changes.kql", {
        new_rows_filter = local.tripwire_new_rows
        timezone        = var.business_hours.timezone
        business_start  = var.business_hours.start
        business_end    = var.business_hours.end
      })
    }
    keyvault-secret-reads-non-pipeline = {
      display_name = "FAFO tripwire: Key Vault secret read by a non-pipeline identity"
      description  = "A secret was read or listed by an identity that is neither a pipeline identity nor an approved secret reader."
      severity     = 2
      query = templatefile("${local.kql_dir}/keyvault-secret-reads-non-pipeline.kql", {
        new_rows_filter     = local.tripwire_new_rows
        approved_reader_ids = local.pipeline_ids_kql
      })
    }
  }
}

# (CSF DE.CM-03; 800-53 AU-6, SI-4 - and per rule, the controls named at the top of each .kql file)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "tripwire" {
  for_each = local.tripwires

  name                 = "tripwire-${each.key}"
  resource_group_name  = local.workspace_rg
  location             = var.location
  scopes               = [local.workspace_id]
  display_name         = each.value.display_name
  description          = each.value.description
  severity             = each.value.severity
  evaluation_frequency = "PT15M"
  window_duration      = local.tripwire_window

  criteria {
    query                   = each.value.query
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }

  action {
    action_groups = [azurerm_monitor_action_group.grc.id]
  }

  tags = local.tags
}

# The two rules that existed before the for_each keep their Azure resources.
moved {
  from = azurerm_monitor_scheduled_query_rules_alert_v2.unexpected_writer
  to   = azurerm_monitor_scheduled_query_rules_alert_v2.tripwire["unexpected-writer"]
}

moved {
  from = azurerm_monitor_scheduled_query_rules_alert_v2.remediator_out_of_lane
  to   = azurerm_monitor_scheduled_query_rules_alert_v2.tripwire["remediator-out-of-lane"]
}

output "tripwire_rules" {
  value = sort([for r in azurerm_monitor_scheduled_query_rules_alert_v2.tripwire : r.name])
}

output "expected_callers_count" {
  description = "How many callers are on the allow-list (values are not echoed)."
  value       = length(local.expected_callers)
}
