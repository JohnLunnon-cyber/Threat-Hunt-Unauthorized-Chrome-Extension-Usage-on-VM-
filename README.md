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
***Result:***

Timestamp: 12 Apr 2025 12:38:53 (BST)
File Name: ChromeSetup.exe
File Path: C:\Users\lucky-man\Downloads\
Action Type: FileCreated
Initiating Process Account Name: lucky-man

**Analysis:** The user "lucky-man" downloaded the Chrome browser installer (ChromeSetup.exe) to their virtual machine's downloads folder. This action itself is not necessarily malicious but serves as the precursor to browser usage and potential extension installations.
