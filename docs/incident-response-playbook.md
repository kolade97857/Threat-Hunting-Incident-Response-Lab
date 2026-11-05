# SOC Incident Response Playbook

**Project:** Threat Hunting & Incident Response Lab  
**Platform:** Splunk Enterprise Free  
**Endpoint:** Windows 10 VM (`DESKTOP-T0FDBKJ`)  
**Log collector:** Splunk Universal Forwarder

## 1. Purpose and scope

This playbook provides a repeatable workflow for investigating Windows process-creation and authentication activity in the lab. It is based on two controlled cases: SOC-IR-001 (hidden PowerShell test) and SOC-IR-002 (repeated failed-logon test).

The playbook is educational and should be adapted to an organisation's approved incident response policies before operational use.

## 2. Response lifecycle

1. Preparation
2. Detection and identification
3. Triage and analysis
4. Containment decision
5. Recovery
6. Post-incident review and closure

## 3. Preparation

Before starting an investigation:

- Confirm Splunk Enterprise and the Universal Forwarder are running.
- Confirm Windows Security events are arriving in the `main` index.
- Confirm the Security channel is being collected as `WinEventLog:Security`.
- Confirm the endpoint hostname and investigation time zone.
- Preserve relevant searches, raw events, timestamps, record numbers and screenshots.
- Confirm the required Windows audit policies are configured.

Useful event identifiers:

| Event ID | Meaning | Use |
|---:|---|---|
| 4624 | Successful logon | Correlate authentication outcomes |
| 4625 | Failed logon | Investigate failed authentication |
| 4688 | Process creation | Investigate process path, command line and lineage |
| 4740 | Account locked out | Verify lockout evidence |

## 4. Detection and identification

### 4.1 Repeated failed logons

Start with Event ID 4625. Aggregate activity by host and time window, then inspect the target account, source address, logon type, status and substatus.

A burst of failures is an investigative signal. It is not, by itself, proof of brute-force activity or compromise.

### 4.2 Suspicious PowerShell execution

Start with Event ID 4688 and inspect:

- `New_Process_Name`
- `Process_Command_Line`
- `Creator_Process_Name`
- `Creator_Process_ID`
- `New_Process_ID`
- `Account_Name`

Review indicators such as hidden-window execution, encoded commands, policy bypasses, download methods and decoding methods. These are not conclusive on their own.

## 5. Triage and analysis

### Endpoint and account

- Identify the host and account context.
- Establish the event timestamp and record number.
- Determine whether the account is a subject, target or service identity in the event.

### Authentication investigation

- Count the failed attempts and establish first/last timestamps.
- Interpret the logon type.
- Inspect Status and SubStatus.
- Identify whether the source is local (`127.0.0.1` / `::1`) or remote.
- Search for a successful logon for the same target account after the failures.
- Search for Event ID 4740 and inspect the account-lockout policy.
- Distinguish the account's current state from its historical state at the time of the event.

### Process investigation

- Identify the executable and full path.
- Inspect the full command line.
- Identify parent/creator process and process IDs.
- Correlate adjacent events.
- Check the executable's Authenticode status and signer identity.
- Treat signature status as one data point; a valid signature does not prove a command or its use is benign.

## 6. Containment decision

Containment must be evidence-based and authorised.

### Suspicious PowerShell

If malicious execution is substantiated:

1. Preserve the process-creation event and command line.
2. Scope related processes, accounts and hosts.
3. Escalate according to the organisation's response process.
4. Isolate an endpoint only when the evidence and risk justify it and the action is authorised.
5. Terminate or quarantine confirmed malicious artifacts only after verifying identity and impact.

Do not terminate a legitimate Windows or security-monitoring process solely because it launches PowerShell.

### Repeated failed logons

If authentication activity is unexpected or persistent:

1. Identify the targeted account and source.
2. Correlate failed attempts with successful logons.
3. Check for lockout evidence.
4. Escalate and reset credentials or disable an account only when justified and authorised.
5. Preserve relevant Security events and supporting endpoint evidence.

Do not label `127.0.0.1` as an external attacker address; it is the local loopback address.

## 7. Recovery

For a confirmed incident:

- Verify that unauthorised access or execution has been stopped.
- Remediate the affected endpoint or account.
- Reset credentials where required.
- Confirm that Windows auditing and Splunk collection remain operational.
- Monitor for repeated activity.
- Record the actions taken and the verification results.

For the two controlled cases in this project, destructive containment and recovery actions were not appropriate because the activity was deliberately generated for testing.

## 8. Evidence preservation

For every case, retain:

- Raw Windows Security event details
- SPL search used
- Timestamp and event record number
- Host, account, source address and process context
- Command line and process lineage, where applicable
- Signature-verification output, if performed
- Account policy and account-state checks, where applicable
- Screenshots and report
- Decision, limitations and closure rationale

## 9. Case application

### SOC-IR-001 — Hidden PowerShell simulation

Event ID 4688 at `2026-11-04 12:23:00.720` captured a child `powershell.exe` launched by a parent PowerShell process. The command used `-WindowStyle Hidden` and wrote the harmless marker `Project5 detection test`. The process lineage and executable signature were inspected. The event was intentionally generated; no compromise was established.

### SOC-IR-002 — Repeated failed-logon simulation

Six Event ID 4625 records involving `SOCTestUser` were identified between `09:09:13.662` and `09:12:13.966`. The source was `127.0.0.1`; Logon Type was 2; Status/SubStatus were `0xC000006D` / `0xC000006A`. No matching successful logon or Event ID 4740 was found in the examined window. The account was later observed enabled and unlocked. The historical lockout state is unconfirmed because the current state does not establish the earlier state and no lockout event was found.

## 10. Severity guidance

| Level | Working interpretation |
|---|---|
| Informational | Routine activity; no immediate action indicated |
| Low | Unusual activity with limited risk evidence |
| Medium | Suspicious activity requiring further investigation |
| High | Strong evidence of malicious activity or significant risk |
| Critical | Severe or active compromise requiring immediate escalation |

These are lab working labels, not an automated Splunk risk score.

## 11. Closure criteria

Close a case only after:

- The alert or suspicious activity has been investigated.
- Relevant evidence is preserved.
- Host and account context are identified.
- The conclusion is supported by observed evidence.
- Containment/escalation decision is documented.
- Any unresolved discrepancy or limitation is explicitly recorded.

Possible dispositions: **benign activity**, **confirmed malicious activity**, or **inconclusive / further investigation required**.

## 12. Platform limitation

Splunk Enterprise Free was used. The lab instance did not expose alert creation or scheduled alerting, so the documented detections were run manually. This project demonstrates analyst-driven hunting and investigation, not automated production alert delivery.
