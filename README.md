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

**Query:**

```kql
DeviceFileEvents
| where DeviceName == "lucky-man"
| where FileName startswith "chrome" and FileName endswith ".exe"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessAccountName

