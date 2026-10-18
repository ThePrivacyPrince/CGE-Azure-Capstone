# WORM failed-delete proof

_Template: fill from RUNBOOK C2 and commit. Delete this line when done._

- Date (UTC):
- Account / container: `<evidence account>` / `reports`
- Immutability policy (`az storage container immutability-policy show`): retention ___ days, state ___
- Blob targeted: `<folder>/manifest.json`

## Delete attempt
```
<paste az storage blob delete output - expect an immutability error>
```

## Overwrite attempt
```
<paste az storage blob upload --overwrite output - expect refusal>
```

## The attempt in the logs (StorageBlobLogs)
```
<paste KQL result: TimeGenerated, OperationName, StatusCode, StatusText>
```

**Verified:** the platform refused both. **Not claimed:** the policy is unlocked for course teardown (DECISIONS ADR-001/BLAST-RADIUS); locked policies cannot be shortened or removed by anyone.
