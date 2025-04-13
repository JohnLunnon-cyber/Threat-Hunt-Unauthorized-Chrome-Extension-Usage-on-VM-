# Threat Hunt Report: Unauthorized Chrome Extension Installation

**Date:** April 13, 2025
**Time:** 13:00 BST
**Target Device:** lucky-man
**Analyst:** John Lunnon
**Objective:** Investigate potential unauthorized Chrome extension installations on a new employee's device.

**Executive Summary:**

During the onboarding check of a new employee's device ("lucky-man"), suspicious activity related to Chrome extension downloads was detected. This report outlines the timeline of Chrome browser download and installation, followed by the identification of several downloaded Chrome extension files. The purpose and legitimacy of these extensions require further investigation to ensure compliance with security policies and prevent potential risks.

---

## Detailed Findings:

### 1. Chrome Browser Download:

**Query used to locate:**

```kql
DeviceFileEvents
| where DeviceName == "lucky-man"
| where FileName startswith "chrome" and FileName endswith ".exe"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessAccountName

```

<img width="639" alt="Screenshot 2025-04-13 at 16 27 29" src="https://github.com/user-attachments/assets/6482026f-447b-491b-93a7-fbd00734f16b" />

----
***Result:***

Timestamp: 12 Apr 2025 12:38:53 (BST)
File Name: ChromeSetup.exe
File Path: C:\Users\lucky-man\Downloads\
Action Type: FileCreated
Initiating Process Account Name: lucky-man

**Analysis:** The user "lucky-man" downloaded the Chrome browser installer (ChromeSetup.exe) to their virtual machine's downloads folder. This action itself is not necessarily malicious but serves as the precursor to browser usage and potential extension installations.

----
**2. Chrome Browser Installation:**

**Query used to locate:**

```kql
DeviceFileEvents
| where DeviceName == "lucky-man"
| where FileName startswith "chrome" and FileName endswith ".exe"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessAccountName

```
<img width="643" alt="Screenshot 2025-04-13 at 16 28 02" src="https://github.com/user-attachments/assets/a7dfd51b-3a71-4d8a-872e-12e0f7c29b2e" />

**Result:**

**Timestamp:** 12 Apr 2025 12:40:59 (BST)
**File Name:** chrome.exe
**File Path:** `C:\Program Files\Google\Chrome\Application\`
**Process Command Line:** `"chrome.exe" --from-installer`
**Initiating Process Account Name:** lucky-man

**Analysis:** The Chrome browser was installed to the standard program files directory. The command-line argument `--from-installer` indicates that the browser was launched immediately following the installation process.

----

###: Chrome Extension Downloads on lucky-man

This report details the identified Chrome extension downloads on the target device "lucky-man" based on the provided `DeviceFileEvents` log data. The analysis focuses on files with the `.crx` extension, which is the standard package format for Chrome extensions.
----
### 3. Unauthorized Chrome Extension Downloads:
**Query Used to locate the extensions being installed:**

//This shows chrome extensions being installed
```kql
DeviceFileEvents
| where DeviceName == "lucky-man"
| where FolderPath contains "Chrome"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ActionType

```
<img width="631" alt="Screenshot 2025-04-13 at 16 28 30" src="https://github.com/user-attachments/assets/44b6bad3-dc7f-44c7-98cd-d47c01f1ed15" />
---
**Result:**

**Timestamp:** 12 Apr 2025 12:40:59 (BST)
**File Name:** chrome.exe
**File Path:** `C:\Program Files\Google\Chrome\Application\`
**Process Command Line:** `"chrome.exe" --from-installer`
**Initiating Process Account Name:** lucky-man


**The following Chrome extension files (`.crx`) were downloaded to the target device:**

**12 Apr 2025 12:48:52 (BST)**
**File Name:** `1.0.0.17_llkgjffcdpffmhiakmfcdcblohccpfmo.crx`
**Analysis:** This extension file was initially located in a temporary directory (`C:\Users\lucky-man\AppData\Local\Temp\chrome_BITS_2768_1563824855\`) and subsequently renamed. The involvement of Chrome's Background Intelligent Transfer Service (BITS) suggests this download might have occurred in the background, possibly initiated by the browser without direct user interaction at the time of download.

**12 Apr 2025 12:50:12 (BST)** 
**File Name:** `modkgipgommbdobanfinadelfafeiadk_21012.crx`
**Analysis:** The creation of this `.crx` file directly within the Chrome Web Store downloads directory (`C:\Users\lucky-man\AppData\Local\Google\Chrome\User Data\Webstore Downloads\`) strongly indicates that this extension was downloaded directly from the Chrome Web Store by the user.

**12 Apr 2025 13:06:44 (BST)** 
**File Name:** `mpnfoddkacdjocmjaobmkcphfncdoogp_23869.crx`
**Analysis:** Similar to the previous entry, the presence of this `.crx` file in the Chrome Web Store downloads directory confirms that it was also downloaded via the Chrome Web Store.

**13 Apr 2025 11:34:59 (BST)** 
**File Name:** `qualification_win32.crx`
**Analysis:** This extension file was created in a temporary directory (`C:\Windows\SystemTemp\chrome_url_fetcher_5104_804268295\`). The `chrome_url_fetcher` process is often responsible for handling URL-based downloads within Chrome, suggesting this extension was likely downloaded through the browser, although not directly to the Web Store downloads folder.





