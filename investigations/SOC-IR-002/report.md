# SOC-IR-002 — Repeated Failed Login Attempts

| Case field | Value |
|---|---|
| Project | Threat Hunting & Incident Response Lab |
| Investigation date | November 4, 2026 |
| Endpoint | `DESKTOP-T0FDBKJ` (Windows 10 VM) |
| Platform | Splunk Enterprise Free |
| Primary event | Windows Security Event ID 4625 |
| Target account | `SOCTestUser` |
| Disposition | **Benign controlled simulation — investigation completed** |

## 1. Executive summary

This investigation examined repeated failed authentication attempts against the local `SOCTestUser` test account. Splunk identified six Event ID 4625 records over approximately three minutes. The source address was `127.0.0.1` and Logon Type was `2` (Interactive). All six events carried Status `0xC000006D` and SubStatus `0xC000006A`.

No matching successful logon for `SOCTestUser` was returned in the November 4, 2026, 09:05–09:20 investigation window. No Event ID 4740 record was found in the examined local Security logs or Splunk search. A later check showed the account enabled and not currently locked out. Its historical lockout state during the earlier sequence remains unconfirmed.

The events were generated as part of a controlled local lab exercise. No external attacker or successful compromise was established.

## 2. Failed-logon evidence

| Field | Observed value |
|---|---|
| Total failed attempts | `6` |
| First attempt | `2026-11-04 09:09:13.662` |
| Last attempt | `2026-11-04 09:12:13.966` |
| Endpoint | `DESKTOP-T0FDBKJ` |
| Target account observed in event data | `SOCTestUser` |
| Source address | `127.0.0.1` |
| Logon Type | `2` — Interactive |
| Status | `0xC000006D` |
| SubStatus | `0xC000006A` |
| Failure reason text | `Unknown user name or bad password.` |

The extracted `Account_Name` values also showed the machine account (`DESKTOP-T0FDBKJ$`) as subject context. The failed target account was identified as `SOCTestUser` in the event data and search results.

`0xC000006A` is the wrong-password status code. Microsoft documents `127.0.0.1` as the localhost address in Event ID 4625 details and Logon Type 2 as an interactive logon.

## 3. Successful-authentication correlation

Event ID 4624 was searched for `SOCTestUser` during the same `09:05–09:20` window. The query returned no matching successful login for this target account.

Other 4624 records were present for system or Windows session identities, but these did not establish successful authentication for `SOCTestUser`.

This finding is limited to the searched endpoint and time window; it does not prove that the account never authenticated successfully at another time.

## 4. Account-lockout investigation

The endpoint's account policy was checked with `net accounts`:

| Policy | Observed value |
|---|---:|
| Lockout threshold | 5 failed attempts |
| Lockout duration | 10 minutes |
| Lockout observation window | 10 minutes |

Six failed attempts occurred within approximately three minutes, which exceeds the reported threshold if all attempts were counted by the applicable policy.

The User Account Management audit policy was inspected with `auditpol /get /subcategory:"User Account Management"` and showed `Success`.

Two lockout searches were performed:

- Splunk search for Event ID 4740 and `SOCTestUser` in the `09:05–09:20` window: no results.
- Local PowerShell `Get-WinEvent` query for Event ID 4740 in the same window and a separate latest-ten-events query: no records found.

A later CIM check returned:

```text
Name        Lockout    Disabled    Status
SOCTestUser False      False       OK
```

This confirms the account was enabled and not locked out at the time of the later check. It does **not** establish the account's historical lockout state at 09:09–09:12. A temporary lockout could have expired before the later status check; however, no Event ID 4740 record was found in the available logs.

**Unresolved discrepancy:** The configured five-attempt threshold and six observed failures suggest that lockout should be investigated, but the available evidence does not confirm that a lockout event occurred. The report does not claim that it did.

## 5. Source and logon analysis

`127.0.0.1` is the IPv4 loopback address (localhost), not an external attacker IP. Logon Type `2` represents an interactive logon attempt. The evidence therefore supports local interactive failed-logon activity generated on the endpoint.

The case should not be labelled a remote brute-force attack.

## 6. Impact assessment

The available evidence did not establish:

- successful unauthorized access to `SOCTestUser`;
- external attacker involvement;
- account compromise;
- data access or exfiltration;
- confirmed account lockout during the historical attempt window.

## 7. Response decision

Because the attempts were part of a controlled lab simulation:

1. The six failed-logon events and status fields were preserved.
2. The source address and logon type were recorded.
3. Successful-logon correlation was performed.
4. Lockout policy and audit configuration were inspected.
5. Event ID 4740 was searched in Splunk and the local Security log.
6. Current account state was verified, with historical-state limitations retained.
7. No password reset, account disablement or destructive containment action was performed.

## 8. Lessons learned

- Event ID 4625 can be aggregated to identify repeated authentication failures.
- Status and SubStatus provide more useful failure detail than the generic failure text alone.
- Source address and logon type help distinguish local from network authentication.
- Failed attempts should be correlated with Event ID 4624 for the same target account.
- Event ID 4740, the configured lockout policy and the account's current state must be interpreted together.
- Current account state must not be used as proof of historical account state.

## 9. Conclusion

SOC-IR-002 demonstrated investigation of repeated local failed logons using Splunk and Windows Security auditing. Six failed attempts against `SOCTestUser` were observed in approximately three minutes, all with wrong-password substatus `0xC000006A`. No matching successful logon or Event ID 4740 was found in the examined evidence. The account was enabled and unlocked at the later verification time; its historical lockout state remains unconfirmed.

**Final disposition: BENIGN CONTROLLED SIMULATION — INVESTIGATION COMPLETED; HISTORICAL LOCKOUT STATE UNCONFIRMED.**

## References

- [Microsoft: Event 4625 — An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft: Event 4740 — A user account was locked out](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740)
- [Microsoft: `STATUS_WRONG_PASSWORD` (`0xC000006A`)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/7440cfac-6052-4925-84e4-c32e417de300)

## Evidence screenshots

See the [evidence index](../../evidence/README.md), especially authentication-hunting and policy-verification captures.
