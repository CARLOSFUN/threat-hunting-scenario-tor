# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/CARLOSFUN/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file with the string “tor” created by user misawa on device misawa. This confirmed Tor artifacts on the profile, including payloads/shortcuts and the creation of tor-shopping-list.txt on the Desktop. File activity starts shortly after install at 2025-09-11T17:40:50Z (Tor payload present), with additional “shopping-list” artifacts between 2025-09-12T06:44:34Z and 06:46:27Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "misawa"
| where InitiatingProcessAccountName == "misawa"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-09-11T17:40:00Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName
```

<img width="1011" height="425" alt="image" src="https://github.com/user-attachments/assets/29ee72c2-45e9-465d-90b2-5d6a94585eac" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine indicating a Tor Browser installer execution. At 2025-09-11T17:40:26Z the user executed tor-browser-windows-x86_64-portable-14.5.6.exe /S from the Downloads folder, indicating a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "misawa"
| where ProcessCommandLine startswith "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine

```
<img width="1011" height="425" alt="image" src="https://github.com/user-attachments/assets/2c15afbb-534a-4149-86b3-79c07cb7a447" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for evidence of Tor runtime processes. Although runtime process logs were sparse in the export, subsequent telemetry shows activity consistent with tor.exe and Tor Browser’s firefox.exe executing from the Tor Browser directory.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "misawa"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
   or FolderPath has @"\Tor Browser\"
   or ProcessCommandLine has_any ("TorBrowser", @"\Browser\firefox.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256

```
<img width="1240" height="615" alt="image" src="https://github.com/user-attachments/assets/d494dab2-0487-4bf8-9c1f-5a24628fe1b8" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

**Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`**.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "misawa"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in~ ("tor.exe","tor-browser.exe","firefox.exe")
   or LocalPort in (9050,9150,9151)
   or RemotePort in (9001,9030,9050,9150,9151,443)
   or RemoteUrl has_any ("torproject.org","snowflake","torbrowser")
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl

```
<img width="1240" height="615" alt="image" src="https://github.com/user-attachments/assets/82b9de97-3349-4cf6-a867-b0c028b8b524" />


---

## Chronological Event Timeline 

## 1. Policy Violation – Unauthorized Privacy Software Installation

Timestamp: 2025-09-11T17:40:26Z

Event: User “misawa” executed the Tor Browser portable installer in silent mode.

Action: Process creation detected.

Command: tor-browser-windows-x86_64-portable-14.5.6.exe /S

File Path: C:\Users\misawa\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe

## 2. Execution Risk – Portable Tor Payload Dropped to User Profile

Timestamp: 2025-09-11T17:40:50Z

Event: Tor binary written to the user profile (payload unpacked).

Action: File creation detected.

File Path: C:\Users\misawa\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

## 3. User Launch Evidence – Desktop Shortcut Created

Timestamp: 2025-09-11T17:41:13Z

Event: Tor Browser desktop shortcut created.

Action: File creation detected.

File Path: C:\Users\misawa\Desktop\Tor Browser\Tor Browser.lnk

## 4. Evasion Infrastructure – Tor Control Channel Established

Timestamp: 2025-09-11T17:41:23Z

Event: Local control connection (Tor control port).

Action: Connection success (loopback).

Process: firefox.exe

Endpoint: 127.0.0.1:9151

## 5. Proxy Enablement – Local SOCKS Listener Active

Timestamp: 2025-09-11T17:41:50Z

Event: Local SOCKS proxy connection (Tor Browser).

Action: Connection success (loopback).

Process: firefox.exe

Endpoint: 127.0.0.1:9150

## 6. Anonymity Network Communications – Outbound to Tor Relays (TLS/443)

Timestamp: 2025-09-11T17:41:52Z

Event: Outbound encrypted connection consistent with Tor infrastructure.

Action: Connection success.

Process: tor.exe

Remote: 199.58.81.140:443

Process Path: C:\Users\misawa\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

## 7. Anonymity Network Communications – Outbound to Tor Relay (Port 9001)

Timestamp: 2025-09-11T17:41:52Z

Event: Outbound connection to Tor relay port.

Action: Connection success.

Remote: 88.99.193.108:9001

## 8. Sustained Anonymized Traffic – Continued Tor Activity

Timestamps: 2025-09-11T17:41:52Z → 2025-09-11T23:01:57Z

Event: Ongoing Tor-pattern network activity (multiple events on 443/9001 with local 9150/9151 present).

Action: Multiple successful connections detected.

## 9. User Intent Indicator – Tor-Named Documents Created

Timestamps: 2025-09-12T06:44:34Z → 2025-09-12T06:46:27Z

Event: Creation of tor-shopping-list.txt and related .lnk items under the user profile, indicating interactive use.

Action: File creation detected.

File Path (example): C:\Users\misawa\Desktop\tor-shopping-list\tor-shopping-list.txt
---

## Summary

Evidence shows a silent portable installation of Tor Browser by user misawa, followed by application launch, establishment of local control/SOCKS endpoints (9151/9150), and outbound connections to Tor relays (443/9001) for several hours. Subsequent creation of Tor-named documents indicates interactive use. This sequence confirms unauthorized anonymized browsing activity on host misawa that bypasses standard monitoring controls.

---

## Response Taken

TOR usage was confirmed on the endpoint `misawa` by the user `misawa`. The device was isolated, and the user's direct manager was notified.

---
