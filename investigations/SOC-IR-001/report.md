# SOC-IR-001 — Simulated Hidden PowerShell Execution

| Case field | Value |
|---|---|
| Project | Threat Hunting & Incident Response Lab |
| Investigation date | November 4, 2026 |
| Endpoint | `DESKTOP-T0FDBKJ` (Windows 10 VM) |
| Platform | Splunk Enterprise Free |
| Primary event | Windows Security Event ID 4688 |
| Account | `mn943` |
| Disposition | **Benign controlled simulation — closed** |

## 1. Executive summary

This investigation tested the collection and detection of potentially suspicious PowerShell execution using Windows Security Event ID 4688 and Splunk Enterprise. A hidden-window PowerShell process was deliberately launched with a harmless marker command. Splunk collected the process-creation event, exposed the command line and process lineage, and matched the hidden-window indicator in the SPL detection search.

The activity was intentionally generated for the lab. No actual compromise or malicious payload was established.

## 2. Event evidence

| Field | Observed value |
|---|---|
| Timestamp | `2026-11-04 12:23:00.720` |
| Event ID | `4688` |
| Record number | `66675` |
| Host | `DESKTOP-T0FDBKJ` |
| Account | `mn943` |
| Creator process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Creator process ID | `0x1f04` |
| New process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| New process ID | `0x209c` |
| Indicator | `-WindowStyle Hidden` |

Observed command line:

```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -WindowStyle Hidden -Command "Write-Output 'Project5 detection test'"
```

The parent and child process were both PowerShell. The event is a process-creation record, not a proof of malicious execution.

## 3. Detection logic and validation

The detection search inspected Event ID 4688 command lines for selected indicators:

- `encodedcommand`
- `-enc`
- `windowstyle hidden`
- `executionpolicy bypass`
- `downloadstring`
- `frombase64string`

**Test results:**

| Test | Result |
|---|---|
| Hidden PowerShell test | Matched the `-WindowStyle Hidden` indicator |
| Normal PowerShell test (`Project5 normal execution test`) | Not flagged by the selected indicators |

The search assigned `Medium` severity in SPL as a lab label. This is not a calculated risk score. An indicator match requires analyst review.

## 4. Process lineage

The 4688 event showed:

- Creator process: PowerShell (`0x1f04`)
- New process: PowerShell (`0x209c`)
- Account: `mn943`

The result is consistent with the controlled command launching a child PowerShell instance.

## 5. Executable signature observation

`Get-AuthenticodeSignature` was run against:

`%windir%\System32\WindowsPowerShell\v1.0\powershell.exe`

The recorded PowerShell output reported:

- `Status: Valid`
- Signer subject: `CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US`

**Caveat:** The certificate details displayed a `Not After` date of June 17, 2026, earlier than the November 4, 2026 investigation date. This report preserves the cmdlet output as observed but does not independently reconcile timestamp/certificate-validity semantics. A trusted signature-verification workflow should revalidate the executable before using this result as a standalone trust decision.

A separate `CompatTelRunner.exe` check also returned `Status: Valid` and a Microsoft Windows signer subject. The observed telemetry command lines were consistent with Windows compatibility/telemetry activity, but a valid signature alone does not determine whether every process invocation is benign.

## 6. Timeline correlation

A 60-second correlation search around the test showed several Splunk Universal Forwarder child processes immediately before the test, followed by the controlled PowerShell event at `12:23:00.720`. The visible correlated events did not establish a malicious chain.

## 7. Impact assessment

No evidence was established for unauthorized access, a malicious payload, persistence, lateral movement, data exfiltration or system compromise. The command was deliberately created by the lab operator and wrote only a harmless text marker.

## 8. Response decision

Because this was a controlled simulation:

1. The event and command line were preserved.
2. The user, parent process, child process and process IDs were recorded.
3. The executable signature output was collected with its date caveat.
4. No process termination, quarantine, account disablement or endpoint isolation was performed.
5. The case was closed as a benign simulation.

## 9. Conclusion

SOC-IR-001 demonstrated Windows process-creation collection, indicator-based PowerShell hunting, process-lineage analysis and executable-signature inspection. The controlled event was detected and investigated successfully. No actual compromise was established.

**Final disposition: BENIGN CONTROLLED SIMULATION — CLOSED.**

## References

- [Microsoft: Event 4688 — A new process has been created](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)

## Evidence screenshots

See the [evidence index](../../evidence/README.md), especially the process-creation / PowerShell captures and signature-verification captures.
