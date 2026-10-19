locals {
  evidence_rg = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  # The governed SCOPE. Collector roles attach here, so every subscription that joins the
  # management group is collected without a change to this stage.
  mg_id   = data.terraform_remote_state.foundation.outputs.management_group_id
  mg_name = data.terraform_remote_state.foundation.outputs.management_group_name
  common_tags = {
    env     = var.environment
    purpose = "grc-evidence-plane"
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# --- Cosmos DB: the evidence database we OWN. Serverless; pennies at lab scale. ---

resource "azurerm_cosmosdb_account" "evidence" {
  #checkov:skip=CKV_AZURE_140:Satisfied by local_authentication_enabled = false; the check reads the attribute name removed in azurerm v4.
  #checkov:skip=CKV_AZURE_99:Y1 Consumption functions egress from shared ranges; access is Entra-only (no keys), see docs/DECISIONS.md ADR-005.
  #checkov:skip=CKV_AZURE_101:Same as CKV_AZURE_99 - private networking is the documented next step (ADR-005), not a capstone requirement.
  #checkov:skip=CKV_AZURE_100:Platform-managed keys. CMK adds a Key Vault dependency and rotation process; tracked as risk RISK-0003 in docs/DECISIONS.md.
  name                = "cosmos-grc-evidence-${random_string.suffix.result}"
  location            = var.location
  resource_group_name = local.evidence_rg
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  # Identity-only access: no key-based auth against the evidence database.
  # local_authentication_disabled was deprecated in favour of local_authentication_enabled
  # (removed in azurerm v5.0); the boolean inverts, so disabled=true becomes enabled=false.
  local_authentication_enabled = false

  # FAFO: block key-based writes to databases/containers/throughput (privilege
  # escalation path from a leaked key). In-place change.
  access_key_metadata_writes_enabled = false

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = var.location
    failover_priority = 0
  }

  tags = local.common_tags
}

resource "azurerm_cosmosdb_sql_database" "grc" {
  name                = "grc"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
}

# assessments: LATEST-STATE view, one document per assessment+resource (overwritten each run).
# Kept as the starter shipped it so Lab 4-6 queries keep working. History lives in `findings`.
resource "azurerm_cosmosdb_sql_container" "assessments" {
  name                = "assessments"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/subscriptionId"]
}

# frameworks: CSF 2.0 / 800-53 catalogs as records we own.
resource "azurerm_cosmosdb_sql_container" "frameworks" {
  name                = "frameworks"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/frameworkId"]
}

# mappings: the crosswalk — which assessment satisfies which control in which framework.
resource "azurerm_cosmosdb_sql_container" "mappings" {
  name                = "mappings"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/frameworkId"]
}

# --- FAFO: history, run manifests, and the store that scales by scope ------------------
#
# Lab 6 finding: the assessments doc id was sha256(assessment|resource), so every run
# overwrote the last and Cosmos held "now", not history. A POA&M could not say when a
# finding first appeared, and a past report's numbers could not be re-derived.
#
# findings: one document per finding PER RUN. id = sha256(runId|findingKey), so history
#           accumulates and a retried write inside a run is still idempotent.
# rbac:     one document per role assignment, per subscription it applies to, per run.
#           The collector Defender does not give us (who can act on what, and since when).
# runs:     one manifest per run, written at start ("started") and end ("completed" /
#           "partial" / "failed") with per-subscription counts, errors and a seal (id and
#           content digests) per container. Reports only ever read "completed" runs.
#
# Partition keys, chosen on purpose (full reasoning: docs/ARCHITECTURE.md#evidence-data-model):
#   findings, rbac -> HIERARCHICAL [/subscriptionId, /runId].
#     * Subscription first: FAFO arrives with three subscriptions. A new subscription is a new
#       top-level partition the moment its first document lands - no reshaping, no migration.
#     * Run second: one subscription's history grows with every run (4 a day). A flat
#       /subscriptionId key would put all of it in one logical partition and hit Cosmos's
#       20 GB per-logical-partition cap; with [subscription, run] the cap applies per run.
#     * The hot reads stay targeted: "this subscription, this run" is a single partition;
#       "this run, every subscription" is a fan-out to exactly one partition per subscription.
#   runs -> /runId. A run spans every subscription, so subscription cannot partition it; manifests
#     are tiny (one per run) and are always read by runId or "newest completed".
#
# `snapshots` (the first, /runId-partitioned history container) is retired, not deleted: TF-EVD-001
# forbids deleting evidence, and the `removed` block below lets Terraform forget it while Azure
# keeps it and its documents. Changing a partition key in place would force replacement.

resource "azurerm_cosmosdb_sql_container" "findings" {
  name                  = "findings"
  resource_group_name   = local.evidence_rg
  account_name          = azurerm_cosmosdb_account.evidence.name
  database_name         = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths   = ["/subscriptionId", "/runId"]
  partition_key_kind    = "MultiHash"
  partition_key_version = 2
}

resource "azurerm_cosmosdb_sql_container" "rbac" {
  name                  = "rbac"
  resource_group_name   = local.evidence_rg
  account_name          = azurerm_cosmosdb_account.evidence.name
  database_name         = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths   = ["/subscriptionId", "/runId"]
  partition_key_kind    = "MultiHash"
  partition_key_version = 2
}

resource "azurerm_cosmosdb_sql_container" "runs" {
  name                = "runs"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/runId"]
}

removed {
  from = azurerm_cosmosdb_sql_container.snapshots

  lifecycle {
    destroy = false
  }
}

# --- Evidence artifact storage: WORM reports container, zero shared keys. ---

resource "azurerm_storage_account" "evidence" {
  #checkov:skip=CKV_AZURE_59:Public network path needed by Y1 functions; data access is Entra-only with shared keys disabled (ADR-005).
  #checkov:skip=CKV2_AZURE_33:Private endpoint deferred with the rest of private networking (ADR-005).
  #checkov:skip=CKV_AZURE_206:LRS kept: changing replication on the live WORM account is avoided; WORM + versioning + soft delete protect integrity. GRS tracked as RISK-0004.
  #checkov:skip=CKV_AZURE_33:No queue service is used on the evidence account.
  #checkov:skip=CKV2_AZURE_1:Platform-managed keys (RISK-0003).
  name                     = "stgrcevid${random_string.suffix.result}"
  resource_group_name      = local.evidence_rg
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # The store's front door has one kind of lock: identity.
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false

  # FAFO hardening (all in-place changes; nothing here forces replacement).
  default_to_oauth_authentication  = true
  cross_tenant_replication_enabled = false
  local_user_enabled               = false
  https_traffic_only_enabled       = true

  blob_properties {
    versioning_enabled  = true
    change_feed_enabled = true

    delete_retention_policy {
      days = 30
    }

    container_delete_retention_policy {
      days = 30
    }
  }

  tags = local.common_tags
}

resource "azurerm_storage_container" "reports" {
  #checkov:skip=CKV2_AZURE_21:Blob read logging is configured on the blob service in integrity.tf (diagnostic setting), which this check does not resolve.
  name               = "reports"
  storage_account_id = azurerm_storage_account.evidence.id
}

# WORM: write once, read many. Not access control — a platform guarantee.
resource "azurerm_storage_container_immutability_policy" "reports_worm" {
  # resource_manager_id was deprecated on azurerm_storage_container; id now returns the
  # resource-manager ID this argument expects.
  storage_container_resource_manager_id = azurerm_storage_container.reports.id
  immutability_period_in_days           = var.reports_retention_days
  # Unlocked for the course so teardown works. Production locks it — after which
  # nobody, including Microsoft, can shorten or remove it.
}

# The deployer needs blob DATA-plane access to verify WORM behavior and upload seeds —
# Owner is control-plane only (the 01_02 lesson, in production form).
data "azurerm_client_config" "current" {}

resource "azurerm_role_assignment" "deployer_blob_data" {
  scope                = azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

# The deployer also seeds the frameworks/mappings containers (labs/04's seed script),
# so it gets the Cosmos data-plane contributor role. Same reasoning as the blob role above.
resource "azurerm_cosmosdb_sql_role_assignment" "deployer_cosmos_write" {
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  role_definition_id  = "${azurerm_cosmosdb_account.evidence.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = data.azurerm_client_config.current.object_id
  scope               = azurerm_cosmosdb_account.evidence.id
}
