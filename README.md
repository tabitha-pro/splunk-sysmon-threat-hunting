# 🛡️ Splunk & Sysmon Threat Hunting Lab

## Project Overview
This project demonstrates end-to-end endpoint detection engineering and threat hunting. Using a Windows 11 virtual environment, I deployed System Monitor (Sysmon) to capture granular system events, configured custom Splunk ingestion stanzas via `inputs.conf`, and executed targeted SPL queries to identify simulated attacker behavior.

## Lab Architecture & Technical Setup
* **Virtualization:** VirtualBox (Windows 11 VM)
* **Telemetry Engine:** Sysmon v15.x
* **SIEM Platform:** Splunk Enterprise
* **Log Ingestion Path:** `C:\Program Files\Splunk\etc\system\local\inputs.conf`
* **Indexed Telemetry:** 15,000+ real-time Sysmon endpoint events mapped to `WinEventLog:Microsoft-Windows-Sysmon/Operational` in the `main` index.

---

## 🔎 Threat Hunting Scenarios & Detections

### 1. Process Execution & Command-Line Analysis (Sysmon Event ID 1)

**SPL Detection Query:**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| table _time Image CommandLine ParentImage ParentCommandLine User
