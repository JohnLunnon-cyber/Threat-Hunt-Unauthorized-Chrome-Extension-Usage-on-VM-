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

<img width="1552" alt="Screenshot of Chrome Download Event (Replace with actual screenshot if available)" src="link-to-screenshot-1.png" />

Findings: At 12 Apr 2025 12:38:53, the user "lucky-man" downloaded the Chrome browser installer (ChromeSetup.exe) to C:\Users\lucky-man\Downloads\.

2. Searched the DeviceProcessEvents Table for Chrome Browser Installation
Searched for the execution of the Chrome installer.

Query used to locate event:

Code snippet

DeviceProcessEvents
| where DeviceName == "lucky-man"
| where FileName startswith "chrome" and FileName endswith ".exe"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessAccountName
<img width="1619" alt="Screenshot of Chrome Installation Event (Replace with actual screenshot if available)" src="link-to-screenshot-2.png" />

Findings: At 12 Apr 2025 12:40:59, the Chrome browser was installed to C:\Program Files\Google\Chrome\Application\chrome.exe. The command line "--from-installer" indicates it was launched post-installation.

3. Searched the DeviceProcessEvents Table for First Chrome Browser Usage
Searched for the initial launch of the Chrome browser for browsing.

Query used to locate event:

Code snippet

DeviceProcessEvents
| where DeviceName == "lucky-man"
| where FileName == "chrome.exe"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessAccountName
<img width="1454" alt="Screenshot of First Chrome Usage Event (Replace with actual screenshot if available)" src="link-to-screenshot-3.png" />

Findings: The first recorded instance of Chrome being opened for browsing was at 12 Apr 2025 12:40:59, coinciding with the installation completion.

4. Searched the DeviceFileEvents Table for Chrome Extension Downloads
Searched for downloaded files with the .crx extension, indicating Chrome extension packages.

Query used to locate events:

Code snippet

DeviceFileEvents
| where DeviceName == "lucky-man"
| where FileName endswith ".crx"
| where InitiatingProcessFileName == "chrome.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
<img width="1534" alt="Screenshot of Chrome Extension Download Events (Replace with actual screenshot if available)" src="link-to-screenshot-4.png" />

Findings: The following Chrome extension files were downloaded:

Timestamp: 12 Apr 2025 12:48:52

File Name: 1.0.0.17_llkgjffcdpffmhiakmfcdcblohccpfmo.crx
File Path: C:\Users\lucky-man\AppData\Local\Temp\chrome_BITS_2768_1563824855\ (Initially)
Analysis: Downloaded via Chrome's Background Intelligent Transfer Service (BITS).
Timestamp: 12 Apr 2025 12:50:12

File Name: modkgipgommbdobanfinadelfafeiadk_21012.crx
File Path: C:\Users\lucky-man\AppData\Local\Google\Chrome\User Data\Webstore Downloads\
Analysis: Downloaded from the Chrome Web Store.
Timestamp: 12 Apr 2025 13:06:44

File Name: mpnfoddkacdjocmjaobmkcphfncdoogp_23869.crx
File Path: C:\Users\lucky-man\AppData\Local\Google\Chrome\User Data\Webstore Downloads\
Analysis: Downloaded from the Chrome Web Store.
Timestamp: 13 Apr 2025 11:34:59

File Name: qualification_win32.crx
File Path: C:\Windows\SystemTemp\chrome_url_fetcher_5104_804268295\
Analysis: Downloaded via chrome_url_fetcher, likely through the browser.
Chronological Event Timeline
1. File Download - Chrome Browser
Timestamp: 12 Apr 2025 12:38:53
Event: The user "lucky-man" downloaded the Chrome browser installer.
Action: File Download.
File Path: C:\Users\lucky-man\Downloads\ChromeSetup.exe
2. Process Execution - Chrome Browser Installation
Timestamp: 12 Apr 2025 12:40:59
Event: The Chrome browser was installed.
Action: Process Creation.
File Path: C:\Program Files\Google\Chrome\Application\chrome.exe
3. Process Execution - First Chrome Browser Usage
Timestamp: 12 Apr 2025 12:40:59
Event: The Chrome browser was first opened for browsing.
Action: Process Creation.
File Path: C:\Program Files\Google\Chrome\Application\chrome.exe
4. File Download - Chrome Extension
Timestamp: 12 Apr 2025 12:48:52
Event: Chrome extension 1.0.0.17_llkgjffcdpffmhiakmfcdcblohccpfmo.crx was downloaded.
Action: File Created (Renamed).
File Path (Initial): C:\Users\lucky-man\AppData\Local\Temp\chrome_BITS_2768_1563824855\
5. File Download - Chrome Extension
Timestamp: 12 Apr 2025 12:50:12
Event: Chrome extension modkgipgommbdobanfinadelfafeiadk_21012.crx was downloaded.
Action: File Created.
File Path: C:\Users\lucky-man\AppData\Local\Google\Chrome\User Data\Webstore Downloads\modkgipgommbdobanfinadelfafeiadk_21012.crx
6. File Download - Chrome Extension
Timestamp: 12 Apr 2025 13:06:44
Event: Chrome extension mpnfoddkacdjocmjaobmkcphfncdoogp_23869.crx was downloaded.
Action: File Created.
File Path: C:\Users\lucky-man\AppData\Local\Google\Chrome\User Data\Webstore Downloads\mpnfoddkacdjocmjaobmkcphfncdoogp_23869.crx
7. File Download - Chrome Extension
Timestamp: 13 Apr 2025 11:34:59
Event: Chrome extension qualification_win32.crx was downloaded.
Action: File Created.
File Path: C:\Windows\SystemTemp\chrome_url_fetcher_5104_804268295\qualification_win32.crx
Summary
The user "lucky-man" downloaded the Chrome browser and subsequently downloaded four distinct Chrome extension files. Two extensions were downloaded from the Chrome Web Store, while the others were downloaded to temporary locations. The download of these extensions occurred within a relatively short timeframe after the browser installation.

Recommendations
Investigate Installed Extensions: Access the Chrome browser on "lucky-man"'s VM and navigate to chrome://extensions/. Identify the names and purposes of the installed extensions and correlate them with the downloaded .crx filenames.
Assess Extension Legitimacy and Risk: Evaluate the identified extensions for their legitimacy and potential security risks based on their names, permissions, and sources.
User Education: If any unauthorised or high-risk extensions are found, educate the user on company policies regarding browser extensions.
Implement Extension Management Policies: Consider implementing Chrome browser management policies to control which extensions can be installed within the organizational environment.
Further Monitoring: Continue to monitor the device for any unusual activity related to browser extensions.
This threat hunt has identified the download of multiple Chrome extensions, warranting further investigation to determine their nature and potential impact on the security posture of the organization.
