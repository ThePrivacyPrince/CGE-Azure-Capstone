# Gate exceptions: explicit, per resource address, ticketed, and time-boxed.
# Changing this file requires CODEOWNERS review. An expired exception stops matching and
# the underlying rule fails the plan again - exceptions decay instead of accumulating.
# (NIST CSF 2.0 GV.RM-04 · 800-53 CA-7, PM-4 · PCI DSS 4.0.1 12.3.1-style documented risk acceptance)
package main

import rego.v1

exceptions := {"TF-STG-002": {# account holds only the Functions host's scratch data, never evidence. Exit plan: # The Y1 Consumption runtime needs a key-based AzureWebJobsStorage connection. This
# move to Flex Consumption with identity-based host storage (docs/DECISIONS.md ADR-007).
"azurerm_storage_account.func_internal": {"ticket": "RISK-0001", "expires": "2027-04-30"}}}

excepted(address, rule) if {
	e := exceptions[rule][address]
	time.now_ns() < time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [e.expires]))
}
