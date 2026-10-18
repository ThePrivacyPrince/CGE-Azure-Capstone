# The approval gate. Every change to this file is a reviewed escalation step
# (CODEOWNERS). Workflow: read the POA&M, open a PR that adds the control key and a
# ticket id, get it reviewed, merge, apply. After the task succeeds, open a second PR
# that removes the key. docs/BLAST-RADIUS.md has what each key changes.
remediation_mode          = "dry-run"
approved_remediations     = []
remediation_change_ticket = "none"
