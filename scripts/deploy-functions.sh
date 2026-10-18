#!/usr/bin/env bash
# Package and deploy both Function Apps from the repo root.
#   ./scripts/deploy-functions.sh
# Copies the single source-of-truth crosswalk into the collector package, stamps the git
# SHA as APP_VERSION (it lands on every evidence document and report), and uses the same
# remote-build zip deploy the labs used.
set -euo pipefail
cd "$(dirname "$0")/.."

SHA=$(git rev-parse --short HEAD)
RG=rg-grc-evidence-dev
COLLECTOR_APP=$(terraform -chdir=stages/03-evidence-store output -raw collector_function_app)
REPORT_APP=$(terraform -chdir=stages/04-reporting output -raw reporting_function_app)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cp frameworks/mappings.json functions/collect_assessments/mappings.json

deploy() {  # app, source dir
  local app=$1 src=$2 zip="$WORK/$1.zip"
  (cd "$src" && zip -qr "$zip" . -x '__pycache__/*' '*.pyc')
  az functionapp config appsettings set -g "$RG" -n "$app" --settings "APP_VERSION=$SHA" -o none
  az functionapp deployment source config-zip -g "$RG" -n "$app" --src "$zip" --build-remote true --timeout 600 -o none
  echo "deployed $app @ $SHA"
}

deploy "$COLLECTOR_APP" functions/collect_assessments
deploy "$REPORT_APP" functions/reports
echo "Timers will fire on schedule. Check run history with docs/RUNBOOK.md 'Prove the timers'."
