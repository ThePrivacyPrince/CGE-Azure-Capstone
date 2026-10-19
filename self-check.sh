#!/usr/bin/env bash
# Run your own capstone rubric before the grader does (docs/RUBRIC.md).
# This covers the mechanical half: if any check is red here, it will be red there.
# It cannot judge run history or writing quality — those need time and a human eye.
set -uo pipefail

PASS=0; FAIL=0
ok()   { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "== Docs =="
[ -f README.md ] && ok "README.md exists" || bad "README.md missing (auto-fail trigger)"
[ -f docs/CONTROLS.md ] && ok "docs/CONTROLS.md exists" || bad "docs/CONTROLS.md missing"
for f in docs/ARCHITECTURE.md docs/BLAST-RADIUS.md docs/DECISIONS.md docs/RUNBOOK.md; do
  [ -f "$f" ] && ok "$f exists" || bad "$f missing"
done
grep -qi "blast radius" stages/06-enforcement/*.tf 2>/dev/null \
  && ok "blast-radius notes present in enforcement stage" \
  || bad "no blast-radius documentation in stages/06-enforcement"

echo "== IaC quality (Tier 0 mirrors) =="
if terraform fmt -check -recursive stages/ >/dev/null 2>&1; then
  ok "terraform fmt clean across stages/"
else
  bad "terraform fmt -check has diffs (run: terraform fmt -recursive stages/)"
fi
# init records this machine's provider hashes in the lock files; validating must not edit them.
LOCK_BACKUP=$(mktemp -d)
for d in stages/*/; do cp "$d/.terraform.lock.hcl" "$LOCK_BACKUP/$(basename "$d").hcl" 2>/dev/null || true; done
for d in stages/*/; do
  name=$(basename "$d")
  if (cd "$d" && terraform init -backend=false -input=false >/dev/null 2>&1 \
      && terraform validate >/dev/null 2>&1); then
    ok "terraform validate: $name"
  else
    bad "terraform validate fails: $name"
  fi
done
for d in stages/*/; do [ -f "$LOCK_BACKUP/$(basename "$d").hcl" ] && cp "$LOCK_BACKUP/$(basename "$d").hcl" "$d/.terraform.lock.hcl"; done
rm -rf "$LOCK_BACKUP"

echo "== Evidence integrity config =="
grep -rq "azurerm_storage_container_immutability_policy" stages/ \
  && ok "WORM immutability policy present" \
  || bad "no immutability policy resource found"
grep -rq "shared_access_key_enabled *= *false" stages/ \
  && ok "shared keys disabled on evidence storage" \
  || bad "shared_access_key_enabled=false not found"
grep -rq "runId" functions/collect_assessments/*.py \
  && ok "collector stamps run lineage" \
  || bad "collector has no runId stamping"
grep -q '"findings"' stages/03-evidence-store/main.tf && grep -q '"rbac"' stages/03-evidence-store/main.tf && grep -q '"runs"' stages/03-evidence-store/main.tf \
  && ok "history (findings), own collector (rbac) and run-manifest containers declared" \
  || bad "findings/rbac/runs containers missing"
python3 -c "import json;json.load(open('frameworks/mappings.json'))" 2>/dev/null \
  && ok "framework crosswalk is valid JSON data" || bad "frameworks/mappings.json missing or invalid"
if python3 -c "import pytest, openpyxl, jsonschema" 2>/dev/null; then
  python3 -m pytest -q tests >/dev/null 2>&1 && ok "pytest: collector + reports" || bad "pytest failures (python3 -m pytest tests)"
else
  echo "  (pytest/openpyxl/jsonschema not installed - pip install pytest openpyxl jsonschema)"
fi

echo "== Identity design =="
if grep -rqE 'role_definition_name *= *"(Owner|Contributor)"' stages/; then
  bad 'a pipeline identity holds Owner/Contributor (whitelist roles only)'
else
  ok "no broad roles granted in Terraform"
fi
grep -q "azurerm_management_group_policy_remediation" stages/06-enforcement/main.tf \
  && ok "human approval gate codified (approved_remediations)" \
  || bad "remediation approval not codified"
grep -rq "identity {" stages/01-foundation/policies.tf stages/06-enforcement/*.tf 2>/dev/null \
  && ok "policy assignments carry identity blocks" \
  || bad "a remediation-effect assignment may be missing its identity block"

echo "== Operations =="
[ -f .github/workflows/gate.yml ] && ok "CI gate workflow present" || bad "gate workflow missing"
[ -f .github/workflows/drift.yml ] && ok "drift workflow present" || bad "drift workflow missing"
ls policy/*.rego >/dev/null 2>&1 && ok "OPA gate rules present" || bad "no policy/*.rego rules"
[ -f stages/07-detection/main.tf ] && ok "who-is-touching-reality tripwires codified (stage 07)" || bad "stage 07 tripwires missing"
if command -v opa >/dev/null 2>&1; then
  opa test policy/ >/dev/null 2>&1 && ok "OPA unit tests pass" || bad "OPA unit tests fail (opa test policy/ -v)"
fi
if command -v conftest >/dev/null 2>&1; then
  if conftest test tests/gate-fixtures/bad-plan.json -p policy >/dev/null 2>&1; then
    bad "gate PASSED the known-bad fixture - a rule is broken"
  else
    ok "gate blocks tests/gate-fixtures/bad-plan.json"
  fi
else
  echo "  (conftest not installed locally — CI still runs it)"
fi
if command -v checkov >/dev/null 2>&1; then
  checkov -d stages --config-file .checkov.yaml >/dev/null 2>&1 && ok "checkov: no unjustified findings" || bad "checkov findings (checkov -d stages --config-file .checkov.yaml)"
fi
if command -v tflint >/dev/null 2>&1; then
  tflint --recursive --config "$PWD/.tflint.hcl" >/dev/null 2>&1 && ok "tflint clean" || bad "tflint errors"
fi

echo "== Scale by scope (graded: no hardcoded IDs, MG assignments, discovery, partition keys) =="
# Any GUID in Terraform that is not a documented platform constant (built-in role/policy IDs).
KNOWN_GUIDS='8e3af657-a8ff-443c-a75c-2fe8c4bcb635|b24988ac-6180-42a0-ab88-20f7382dd24c|749f88d5-cbae-40b8-bcfc-e573ddc772fa|17d1049b-9a84-46fb-8f53-869881c3d3ab|179d1daa-458f-4e47-8086-2a68d0d6c38f|00000000-0000-0000-0000-00000000000[12]'
HARDCODED=$(grep -rhoE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' stages/ --include=*.tf | grep -viE "^($KNOWN_GUIDS)$" | sort -u)
[ -z "$HARDCODED" ] && ok "no hardcoded subscription/tenant IDs in stages/" || bad "hardcoded GUIDs in stages/: $HARDCODED"
if grep -rqE --include=*.tf 'resource "azurerm_(subscription|resource_group)_policy_assignment"' stages/; then
  bad "a policy assignment below management-group scope"
else
  ok "every policy assignment is at management-group scope"
fi
grep -q 'azapi_resource_action" "out_of_region"' stages/01-foundation/discovery.tf && grep -q 'all_subscription_ids' stages/02-activation/main.tf \
  && ok "discovery is data-source driven across the management group" || bad "discovery is not MG-wide / data-source driven"
grep -A6 '"findings"\|"rbac"' stages/03-evidence-store/main.tf | grep -q '"/subscriptionId", "/runId"' \
  && ok "evidence partition keys start with /subscriptionId" || bad "evidence partition keys do not include the subscription"
grep -rq 'SUBSCRIPTION_ID' functions/ stages/03-evidence-store/collector.tf \
  && bad "the collector is pinned to one subscription (SUBSCRIPTION_ID)" || ok "collector discovers subscriptions from its MG-scoped roles"

echo "== Federal track: own controls, catalog, OSCAL =="
DEFS=$(grep -c 'resource "azurerm_policy_definition"' stages/01-foundation/policies.tf)
BLAST=$(grep -c '# blast radius:' stages/01-foundation/policies.tf)
[ "$BLAST" -ge "$DEFS" ] && ok "every stage 01 policy carries a blast-radius block ($BLAST/$DEFS)" || bad "policies without a blast-radius block ($BLAST/$DEFS)"
OWN=$(grep -oE 'name += "fafo-[a-z0-9-]+"' stages/01-foundation/policies.tf | wc -l)
[ "$OWN" -ge 3 ] && ok "$OWN custom policies of FAFO's own (>= 3 required)" || bad "fewer than 3 own policies ($OWN)"
MISSING_DOC=""
# Policy definition names only (roles also use the fafo- prefix).
for n in $( { grep -hoE '^  name += "(cge|fafo)-[a-z0-9-]+"' stages/01-foundation/policies.tf; grep -hoE 'definition_name = "(cge|fafo)-[a-z0-9-]+"' stages/06-enforcement/main.tf; } | grep -oE '(cge|fafo)-[a-z0-9-]+' | grep -v cge-grc-baseline | sort -u); do
  grep -q "$n" docs/CONTROLS.md || MISSING_DOC="$MISSING_DOC $n"
done
[ -z "$MISSING_DOC" ] && ok "every policy in code is in docs/CONTROLS.md" || bad "in code but missing from CONTROLS.md:$MISSING_DOC"
OWNKQL=$(ls kql/*.kql 2>/dev/null | grep -vc unexpected-writer)
[ "$OWNKQL" -ge 2 ] && ok "$OWNKQL KQL queries of FAFO's own (>= 2 required)" || bad "fewer than 2 own KQL queries"
python3 scripts/generate_ssp.py --check >/dev/null 2>&1 && ok "oscal/ssp.json is current with frameworks/ssp-implementation.json" || bad "oscal/ssp.json is stale (python3 scripts/generate_ssp.py)"

echo "== Submission bundle (what the grader reads) =="
if [ -d submission ]; then
  if python3 scripts/verify_submission.py >/tmp/verify-submission.txt 2>&1; then
    ok "verify_submission.py: $(tail -1 /tmp/verify-submission.txt)"
  else
    bad "verify_submission.py: $(tail -1 /tmp/verify-submission.txt) - see python3 scripts/verify_submission.py"
  fi
else
  bad "submission/ missing: python3 scripts/export_submission.py, then commit it"
fi

echo "== Secrets (auto-fail trigger) =="
if command -v gitleaks >/dev/null 2>&1; then
  if gitleaks detect --no-banner --exit-code 1 >/dev/null 2>&1; then
    ok "gitleaks: no secrets detected"
  else
    bad "gitleaks found potential secrets — fix and rotate BEFORE submitting"
  fi
else
  echo "  (gitleaks not installed — the grader WILL run it; brew install gitleaks)"
fi

echo
echo "self-check: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  echo "Fix the ✗ items before submitting. The grader checks all of this and more."
  exit 1
fi
echo "Mechanical checks green. Now verify the two things this script can't:"
echo "  1. Your timers have real run history (not a burst from last night)."
echo "  2. Every number in your reports traces to a stored document."
