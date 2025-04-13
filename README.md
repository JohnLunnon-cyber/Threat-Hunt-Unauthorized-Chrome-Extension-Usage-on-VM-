# <img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Chrome Extension Icon (Replace with actual image if available)"/>

# Threat Hunt Report: Unauthorized Chrome Extension Installation
- [Scenario Creation](link-to-scenario-creation-if-applicable.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Google Chrome Browser

## Scenario

Management has raised concerns regarding the potential installation of unauthorized Chrome extensions by employees, which could pose security risks or violate company policies. The goal of this threat hunt is to identify any instances of Chrome extension downloads on employee devices and analyze the findings to determine the nature and potential impact of these extensions. If any unauthorized or suspicious extensions are identified, further investigation and remediation steps will be necessary.

### High-Level Chrome Extension Discovery Plan

- **Check `DeviceFileEvents`** for any `.crx` file downloads, specifically those initiated by `chrome.exe`.
- **Analyze the download paths** to understand the source of the extensions (e.g., Web Store, external websites).
- **Correlate download times** with Chrome browser installation and usage events.
- **Further investigation (manual or automated)** may be required to identify the names and purposes of the downloaded extensions.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table for Chrome Browser Download

Searched for the download of the Chrome browser installer to establish a baseline.

**Query used to locate event:**

```kql
DeviceFileEvents
| where DeviceName == "lucky-man"
| where FileName startswith "chrome" and FileName endswith ".exe"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessAccountName
