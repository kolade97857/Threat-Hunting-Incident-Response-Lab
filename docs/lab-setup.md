# Lab Setup and Data Collection

## 1. Lab topology

The lab used a Windows 10 virtual machine in Oracle VirtualBox and a Splunk Enterprise instance on the host. A VirtualBox host-only network provided the path between the Windows VM and the Splunk receiver. The VM also had a separate NAT interface during the setup session.

Observed values during the recorded session:

- Windows VM hostname: `DESKTOP-T0FDBKJ`
- Windows VM host-only IPv4 address: `192.168.56.109`
- Splunk receiver: `192.168.56.1:9997`
- Splunk index: `main`
- Windows Security sourcetype: `WinEventLog:Security`

These are lab-session values and may differ in another VirtualBox configuration.

## 2. Splunk Universal Forwarder

The Universal Forwarder was installed on the Windows VM. Its Windows Event Log input configuration included the Security channel, with the `main` index and XML rendering enabled. The installation and input selection screenshots are retained in `evidence/01-lab-setup-and-forwarder/`.

Representative `inputs.conf` configuration:

```ini
[WinEventLog://Security]
disabled = 0
index = main
renderXml = true
```

The session also displayed Application and Sysmon Operational input stanzas. The investigations in this repository are based primarily on the Security channel.

Representative `outputs.conf` configuration:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.56.1:9997

[tcpout-server://192.168.56.1:9997]
```

Use the receiver address and configuration that match your own isolated lab. Do not copy the example IP if your host-only adapter uses a different subnet.

## 3. Network connectivity verification

From the Windows VM, the following command was executed:

```powershell
Test-NetConnection 192.168.56.1 -Port 9997
```

The captured result showed `TcpTestSucceeded : True`, confirming that the VM could establish a TCP connection to the Splunk receiver port at the time of testing.

## 4. Windows auditing

The lab inspected and enabled auditing for authentication and account-management activity. Commands used during validation included:

```powershell
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"User Account Management"
```

The captured Logon audit policy showed Success and Failure. User Account Management showed Success. Process creation records (Event ID 4688) were also present in the Security log, including command-line data.

To inspect the current account-lockout policy:

```powershell
net accounts
```

Recorded policy values in this session:

- Lockout threshold: 5 attempts
- Lockout duration: 10 minutes
- Lockout observation window: 10 minutes

These values are observations from the lab endpoint, not universal defaults.

## 5. Verify events in Splunk

Start with a broad Security event search:

```spl
index=main host="DESKTOP-T0FDBKJ" sourcetype="WinEventLog:Security"
| stats count by EventCode
```

Check recent process creation events:

```spl
index=main host="DESKTOP-T0FDBKJ" sourcetype="WinEventLog:Security" EventCode=4688
| table _time Account_Name Creator_Process_Name New_Process_Name Process_Command_Line
| sort -_time
```

Check failed logon events:

```spl
index=main host="DESKTOP-T0FDBKJ" sourcetype="WinEventLog:Security" EventCode=4625
| table _time Account_Name Status Sub_Status Logon_Type Source_Network_Address
| sort -_time
```

## 6. Test activity used in this project

### Hidden PowerShell test

The controlled command was:

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output 'Project5 detection test'"
```

### Normal PowerShell test

The comparison command was:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Project5 normal execution test'"
```

Both commands write harmless output. The first was detected by the selected hidden-window indicator; the second was not flagged by that detection search.

### Failed-logon test

Six failed logon events involving the `SOCTestUser` target account were observed in the recorded investigation window. The source address was `127.0.0.1`, and the logon type was Interactive (2). The repository treats this as a local controlled simulation, not a remote brute-force attack.

## 7. Splunk Free limitation

This project used Splunk Enterprise Free. The lab instance did not provide the Alert option in the Search page's Save As menu and the License page showed Free. Therefore, detection searches were saved/documented as searches or reports and were run manually. The project does not claim automated alert delivery or scheduled correlation.
