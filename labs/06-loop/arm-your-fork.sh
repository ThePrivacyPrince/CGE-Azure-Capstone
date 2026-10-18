#!/usr/bin/env bash
# Arm YOUR fork's CI workflows against YOUR sandbox subscription.
#
# Creates an OIDC app registration federated to your fork, grants it the roles the
# plan-only workflows need, and prints the five repository VARIABLES to add in your
# fork's UI: Settings -> Secrets and variables -> Actions -> Variables tab.
#
# Why variables and not secrets? With OIDC there is no credential to protect —
# client/tenant/subscription IDs are identifiers, and possessing them grants nothing
# without a matching federation subject. The security boundary is the federation:
# it names YOUR fork, so only workflows running in YOUR fork can exchange tokens.
#
# Why never arm the upstream repo? On a public repo, the pull_request OIDC subject
# matches PRs from ANY fork, and pull_request runs the workflow file AS MODIFIED BY
# THE PR. Arming a public upstream hands every fork PR a path toward the subscription
# behind it. Your fork is low-traffic and yours; the course subscription is neither.
# (This reasoning is exam-relevant. You just read a trust-boundary analysis.)
set -euo pipefail

GH_USER="${1:?usage: ./arm-your-fork.sh <your-github-username-or-org>}"
REPO="${2:-cgeaz}"
SUB_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

echo ">> App registration: github-${REPO}-${GH_USER}"
APP_ID=$(az ad app create --display-name "github-${REPO}-${GH_USER}" --query appId -o tsv)
APP_OBJ=$(az ad app show --id "$APP_ID" --query id -o tsv)
az ad sp create --id "$APP_ID" --output none 2>/dev/null || true
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)

echo ">> Federated credentials for repo:${GH_USER}/${REPO} (pull_request + main)"
for sub in "repo:${GH_USER}/${REPO}:pull_request|pr" "repo:${GH_USER}/${REPO}:ref:refs/heads/main|main"; do
  SUBJECT="${sub%|*}"; NAME="${sub#*|}"
  az ad app federated-credential create --id "$APP_OBJ" --parameters "{
    \"name\": \"${REPO}-${NAME}\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"${SUBJECT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" --output none 2>/dev/null || echo "   (${REPO}-${NAME} already exists)"
done

# --- Capstone change: read-only planner instead of Contributor -------------------------
# Lab 6, step 3: "plan-only" was the workflow's intent, but the identity held Contributor
# at mg-grc (could change anything) and Storage Blob Data Contributor on state (could
# rewrite it). A PR that edited the workflow could have used both. The identity below can
# READ everything terraform plan needs and change nothing:
#   * custom role tf-grc-ci-planner at mg-grc: */read plus the list actions azurerm's
#     refresh calls. Residual risk, stated plainly: listKeys returns the Y1 runtime
#     storage key (which also sits in state). Flex Consumption removes that key entirely
#     (docs/DECISIONS.md ADR-007). If a plan fails with AuthorizationFailed, the error
#     names the one missing action: add exactly that action, nothing broader.
#   * Storage Blob Data READER on the state container: plans run with -lock=false.
# Applies stay human-run from your terminal (docs/DECISIONS.md ADR-006).
MG_SCOPE="/providers/Microsoft.Management/managementGroups/mg-grc"
ROLE_NAME="tf-grc-ci-planner"
echo ">> Custom role ${ROLE_NAME} at mg-grc (read + refresh list actions; no writes)"
if ! az role definition list --name "$ROLE_NAME" --scope "$MG_SCOPE" --query "[0].name" -o tsv | grep -q .; then
  az role definition create --role-definition "{
    \"Name\": \"${ROLE_NAME}\",
    \"Description\": \"CI terraform plan / drift detection. Read-only: refresh needs these list actions, nothing writes.\",
    \"Actions\": [
      \"*/read\",
      \"Microsoft.Web/sites/config/list/action\",
      \"Microsoft.Storage/storageAccounts/listKeys/action\",
      \"Microsoft.DocumentDB/databaseAccounts/readonlykeys/action\",
      \"Microsoft.DocumentDB/databaseAccounts/listKeys/action\",
      \"Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action\",
      \"Microsoft.PolicyInsights/policyStates/queryResults/action\"
    ],
    \"NotActions\": [],
    \"AssignableScopes\": [\"${MG_SCOPE}\"]
  }" --output none
fi
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "$ROLE_NAME" --scope "$MG_SCOPE" --output none 2>/dev/null || true

STATE_RG="rg-grc-tfstate"
STATE_SA_NAME=$(grep storage_account_name "$(dirname "$0")/../03-foundation/backend.hcl" | tr -d ' "' | cut -d= -f2)
echo ">> Storage Blob Data Reader on the tfstate container only (plans run with -lock=false)"
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Reader" \
  --scope "/subscriptions/$SUB_ID/resourceGroups/$STATE_RG/providers/Microsoft.Storage/storageAccounts/$STATE_SA_NAME/blobServices/default/containers/tfstate" \
  --output none 2>/dev/null || true

# If you armed the fork with the starter version of this script, remove the old grants:
#   az role assignment delete --assignee "$SP_ID" --role Contributor --scope "$MG_SCOPE"
#   az role assignment delete --assignee "$SP_ID" --role "Storage Blob Data Contributor" \
#     --scope "/subscriptions/$SUB_ID/resourceGroups/$STATE_RG"

STATE_SA=$(grep storage_account_name "$(dirname "$0")/../03-foundation/backend.hcl" 2>/dev/null | tr -d ' "' | cut -d= -f2 || echo "<from backend.hcl>")

cat <<EOF

Done. Add these VARIABLES (not secrets — see header comment) in YOUR fork:
Settings -> Secrets and variables -> Actions -> Variables -> New repository variable

  AZURE_CLIENT_ID        $APP_ID
  AZURE_TENANT_ID        $TENANT_ID
  AZURE_SUBSCRIPTION_ID  $SUB_ID
  STATE_STORAGE_ACCOUNT  $STATE_SA
  OWNER_EMAIL            <your email>          (PII: lives in repo settings, never in code)
  ALERT_EMAIL            <tripwire alert inbox>
  APPROVED_CHANGE_CALLERS ["<your UPN as shown in Activity Log caller>"]

Then enable the workflows in your fork's Actions tab, and make the gate's
"static checks" and "plan" jobs required status checks on main (docs/RUNBOOK.md). Never add these to the
upstream GRCEngClub/cgeaz repo — its workflows are intentionally unarmed.
EOF
