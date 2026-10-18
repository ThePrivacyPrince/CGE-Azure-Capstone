#!/usr/bin/env bash
# Harden the Terraform state account so it is treated like the evidence store it is.
# Idempotent: safe on the account bootstrap.sh created during Lab 3, and safe to re-run.
#
# Why: whoever can write state can make Terraform believe something false about the
# environment, and the starter account still accepted shared keys (one leaked key =
# full read/write of every stage's state) and had no soft delete or delete lock.
#   * shared keys OFF      -> Entra ID only; every state read/write is attributable
#   * soft delete 30 days  -> a deleted state blob or container is recoverable
#   * change feed          -> an ordered log of every state change
#   * CanNotDelete lock    -> deleting the state RG is a deliberate two-step act
# stages/07-detection re-checks the first three on every drift run (postconditions).
set -euo pipefail

RG_STATE="rg-grc-tfstate"
SUB_ID=$(az account show --query id -o tsv)
SA_NAME="stgrctfstate$(echo "$SUB_ID" | tr -d '-' | cut -c1-8)"

echo ">> $SA_NAME: disabling shared key access (Entra ID only)"
az storage account update -g "$RG_STATE" -n "$SA_NAME" \
  --allow-shared-key-access false --https-only true --min-tls-version TLS1_2 \
  --allow-blob-public-access false --output none

echo ">> $SA_NAME: soft delete (blobs + containers, 30 days), versioning, change feed"
az storage account blob-service-properties update -g "$RG_STATE" --account-name "$SA_NAME" \
  --enable-versioning true \
  --enable-delete-retention true --delete-retention-days 30 \
  --enable-container-delete-retention true --container-delete-retention-days 30 \
  --enable-change-feed true --output none

echo ">> $RG_STATE: CanNotDelete lock"
az lock create --name lock-tfstate --lock-type CanNotDelete --resource-group "$RG_STATE" \
  --notes "Terraform state is a controlled record. Remove only through a reviewed change." \
  --output none 2>/dev/null || echo "   (lock already present)"

echo "Done. terraform init/plan keep working: every stage already uses use_azuread_auth = true."
