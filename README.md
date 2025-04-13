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

Threat Hunt Report: Chrome Browser and Extension Activity on "lucky-man"

1. Chrome Download Event

Query Used:

DeviceFileEvents
| where DeviceName == "lucky-man"
| where FileName startswith "chrome" and FileName endswith ".exe"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessAccountName



Findings: At 12 Apr 2025 12:38:53, the user "lucky-man" downloaded the Chrome browser installer (ChromeSetup.exe) to C:\Users\lucky-man\Downloads\.

2. Chrome Installation Event

Query Used:

DeviceProcessEvents
| where DeviceName == "lucky-man"
| where FileName startswith "chrome" and FileName endswith ".exe"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessAccountName



Findings: At 12 Apr 2025 12:40:59, the Chrome browser was installed to C:\Program Files\Google\Chrome\Application\chrome.exe. The command line --from-installer indicates it was launched post-installation.

3. First Chrome Usage Event

Query Used:

DeviceProcessEvents
| where DeviceName == "lucky-man"
| where FileName == "chrome.exe"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessAccountName



Findings: The first recorded instance of Chrome being opened for browsing was at 12 Apr 2025 12:40:59, coinciding with the installation completion.

4. Chrome Extension Download Events

Query Used:

DeviceFileEvents
| where DeviceName == "lucky-man"
| where FileName endswith ".crx"
| where InitiatingProcessFileName == "chrome.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc



Findings:

12 Apr 2025 12:48:52

1.0.0.17_llkgjffcdpffmhiakmfcdcblohccpfmo.crx

Path: C:\Users\lucky-man\AppData\Local\Temp\chrome_BITS_2768_1563824855\

Analysis: Via Chrome BITS

12 Apr 2025 12:50:12

modkgipgommbdobanfinadelfafeiadk_21012.crx

Path: C:\Users\lucky-man\AppData\Local\Google\Chrome\User Data\Webstore Downloads\

Analysis: From Chrome Web Store

12 Apr 2025 13:06:44

mpnfoddkacdjocmjaobmkcphfncdoogp_23869.crx

Path: C:\Users\lucky-man\AppData\Local\Google\Chrome\User Data\Webstore Downloads\

Analysis: From Chrome Web Store

13 Apr 2025 11:34:59

qualification_win32.crx

Path: C:\Windows\SystemTemp\chrome_url_fetcher_5104_804268295\

Analysis: Via chrome_url_fetcher

📋 Chronological Event Timeline

Timestamp

Event

Action Type

File Path

12 Apr 2025 12:38:53

Chrome browser installer downloaded

File Download

C:\Users\lucky-man\Downloads\ChromeSetup.exe

12 Apr 2025 12:40:59

Chrome browser installed

Process Creation

C:\Program Files\Google\Chrome\Application\chrome.exe

12 Apr 2025 12:40:59

Chrome browser first opened

Process Creation

C:\Program Files\Google\Chrome\Application\chrome.exe

12 Apr 2025 12:48:52

Extension downloaded (BITS)

File Created

C:\Users\lucky-man\AppData\Local\Temp...

12 Apr 2025 12:50:12

Extension downloaded (Web Store)

File Created

C:\Users\lucky-man\AppData\Local\Google...\modkgip...

12 Apr 2025 13:06:44

Extension downloaded (Web Store)

File Created

C:\Users\lucky-man\AppData\Local\Google...\mpnfod...

13 Apr 2025 11:34:59

Extension downloaded (chrome_url_fetcher)

File Created

C:\Windows\SystemTemp\chrome_url_fetcher_...\qualification_win32.crx

Summary

The user "lucky-man" downloaded the Chrome browser and subsequently downloaded four distinct Chrome extension files. Two extensions were downloaded from the Chrome Web Store, while others came from temporary or automated locations. These downloads occurred shortly after the browser installation.

🔍 Recommendations

Investigate Installed Extensions: On the "lucky-man" VM, navigate to chrome://extensions/ to identify the installed extensions.

Assess Risk: Evaluate the legitimacy and permissions of each extension.

User Education: If unauthorized or risky extensions are present, educate the user about approved extension usage.

Extension Management: Implement Chrome management policies to control allowed extensions.

Ongoing Monitoring: Continue surveillance for unusual browser-related behavior.

✅ This investigation indicates a need for further review into the legitimacy and intent of downloaded Chrome extensions to protect the organization's endpoint security.


