# Detection Catalog

This catalog describes the SPL searches included with the project. They are hunting queries for the documented lab environment, not production-ready universal detections.

## DET-001 — Suspicious PowerShell execution

- **Source:** Windows Security Event ID 4688
- **Fields:** `New_Process_Name`, `Process_Command_Line`, `Creator_Process_Name`, `Account_Name`
- **Indicators:** encoded-command options, hidden-window execution, execution-policy bypass, `DownloadString`, `FromBase64String`
- **Lab validation:** controlled hidden-window test detected; normal test not flagged by the selected terms
- **Caveat:** indicators can appear in legitimate administration and software activity. Investigate parent process, command line, user context, executable location, signature and surrounding events before assigning malicious intent.

See [`suspicious-powershell-execution.spl`](../detections/suspicious-powershell-execution.spl).

## DET-002 — Failed-login burst

- **Source:** Windows Security Event ID 4625
- **Lab condition:** at least five failed-logon events within a five-minute bucket
- **Lab validation:** six failed attempts were identified in approximately three minutes
- **Caveat:** the generic query groups at host and time-bucket level. The captured event data exposed subject and target account context in the extracted account field; per-account grouping requires validating target-user field extraction in the particular Splunk parsing configuration.

See [`failed-login-burst.spl`](../detections/failed-login-burst.spl).

## Severity and alerting

The PowerShell query labels matches `Medium` as a demonstration field. It is not an automatically computed risk score. Splunk Free was used and alert scheduling was unavailable in the lab instance; searches were run manually.

## Investigation query collection

Case-specific evidence, timeline, successful-logon and lockout searches are provided as separate runnable SPL files in [`detections/investigations/`](../detections/investigations/).
