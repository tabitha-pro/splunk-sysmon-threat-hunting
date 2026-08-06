# 🛡️ Splunk & Sysmon Threat Hunting Lab

## Project Overview
This project demonstrates end-to-end endpoint detection engineering and threat hunting. Using a Windows 11 virtual environment, I deployed System Monitor (Sysmon) to capture granular system events, configured custom Splunk ingestion stanzas via `inputs.conf`, and executed targeted SPL queries to identify simulated attacker behavior.

## Lab Architecture & Technical Setup
* **Virtualization:** VirtualBox (Windows 11 VM)
* **Telemetry Engine:** Sysmon v15.x
* **SIEM Platform:** Splunk Enterprise
* **Log Ingestion Path:** `C:\Program Files\Splunk\etc\system\local\inputs.conf`
* **Indexed Telemetry:** 15,000+ real-time Sysmon endpoint events mapped to `WinEventLog:Microsoft-Windows-Sysmon/Operational` in the `main` index.

## 🔎 Threat Hunting Scenarios & Detections

### Scenario 1: Process Execution & Command-Line Analysis
> **Telemetry Focus:** Sysmon Event ID 1 (Process Creation)

**SPL Detection Query:**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| table _time Image CommandLine ParentImage ParentCommandLine User
```
<img width="1129" height="919" alt="image" src="https://github.com/user-attachments/assets/a90efcd3-ab5d-4030-8644-a2b635bf5e27" />

### Scenario 2: Network Connection Tracking
> **Telemetry Focus:** Sysmon Event ID 3 (Network Connection)

**SPL Detection Query:**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
| table _time Image SourceIp SourcePort DestinationIp DestinationPort DestinationHostname
```
<img width="1128" height="914" alt="image" src="https://github.com/user-attachments/assets/119309a4-3d06-41d0-a76c-ea5e2e25ac46" />
