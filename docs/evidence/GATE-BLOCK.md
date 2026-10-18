# Gate blocks a non-compliant plan

_Template: fill from RUNBOOK C3 and commit. Delete this line when done._

- Test PR: <link to the closed, unmerged PR>
- Failing job: `plan + OPA gate (03-evidence-store)` - <link to the run>
- Change attempted: storage account with public nested items and TLS 1.0

## Gate output
```
<paste the FAIL lines, e.g. TF-STG-001 ..., TF-STG-003 ...>
```

## Locally reproducible
```
$ conftest test tests/gate-fixtures/bad-plan.json -p policy
13 tests, 7 passed, 0 warnings, 6 failures, 0 exceptions
```
