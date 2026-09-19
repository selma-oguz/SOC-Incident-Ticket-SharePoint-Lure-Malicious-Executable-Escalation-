<img width="597" height="317" alt="original 18" src="https://github.com/user-attachments/assets/7f35ff51-5148-489b-97c2-984dfa889fd7" />

SOC Incident Ticket: SharePoint Lure & Malicious Executable (Escalation)

**Ticket ID:** INC-PHISH-006
**Date:** 30.9.2026
**Analyst:** Selma Oguz

SECTION 1: Incident Summary


**Header Analysis Link:** [MXToolBox Analysis](https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx?huid=54a406d7-b160-488a-bfc3-a884f505c9dd)

On September 8, 2026, a highly deceptive phishing email was intercepted. The threat actor utilized a business email compromise (BEC) or spoofed charity domain (`greatplaces.org.uk`) to distribute a malicious payload. The email masquerades as an internal notification requiring the recipient to read and sign an updated "Security Policy Update September 2026" document.

**Analyst Observations & Red Flags:**
* **SharePoint Spoofing:** The email visualizes a fake SharePoint document link disguised as "greatplaces.sharepoint-com". It uses a false sense of urgency, stating the policy changes will take effect by next week (Monday 14th September 2026). It also includes visually convincing buttons to "Get the SharePoint Mobile App".
* **Malicious Sandbox Execution:** The attached `.eml` file was analyzed in the ANY.RUN sandbox. The analysis revealed that interacting with the attachment triggers the execution of an unrecognized binary, `ai.exe`.
* **Credential Harvesting Links:** Embedded URLs point to typosquatted domains (e.g., `login.ms-complaints.com`) designed to steal Microsoft 365 credentials.

**Impact Assessment:** 
**Critical / Action Required.** Unlike previous cases, this email contains an active, executable payload that initiates a rogue process (`ai.exe`). The ticket is escalated to Tier 2 (L2) for immediate Endpoint Detection and Response (EDR) telemetry review to hunt for active execution or outbound C2 connections.

A) Email Artifacts (Observables)

* **Sender Address:** `Cathy McCormick <Cathy.McCormick[@]greatplaces[.]org[.]uk>`
* **Subject Line:** `Security Policy Update July 2026`
* **Recipients:** `dfa652e-34fe-458e-b0ff-98765f4d0fb5@uk.phisher.knowbe4.com` *(Note: This appears to be a KnowBe4 phishing testing/reporting address).*
* **Sending Server IP:** `185[.]58[.]86[.]177` (Mimecast)
* **Return Path:** `<cathy.mccormick[@]greatplaces[.]org[.]uk>`
* **Date and Time:** Tue, 8 Sep 2026 10:33:19 +0000

B) Web Artifacts (Observables)

* **Full URL Links (Defang-sanitized):** 
  * `hxxps[://]login[.]ms-complaints[.]com/CtLfCAeg`
  * `hxxps[://]portal[.]rmicyber[.]com/view/2850F427-3C45-4BE7-A15E-871875E124D5`
* **Root Domains (Defanged):** 
  * `ms-complaints[.]com`
  * `rmicyber[.]com`

C) File (Attachment) Artifacts

* **File Name:** `phishing_alet_sp2_2.0.0.0.eml`
* **File Hash (SHA256):** `3F7CA11E1AD1F969B805B38E97E06C901D24777A639B9FC5673B37C069791E2A`


SECTION 2: Artifact Analysis

* **ANY.RUN Sandbox:** Analysis of `phish_alert_sp2_2.0.0.0.eml` (MD5: 455A0D4FDB69240A9D13A19D59AECAB2) confirmed malicious activity. The attachment initiates a rogue process (`ai.exe`), indicating a malware dropper or execution sequence. 
* **Domain Analysis:** The sender domain (`greatplaces.org.uk`) belongs to a legitimate UK charity, suggesting the account was likely compromised (Account Takeover - ATO) to bypass email reputation filters like Mimecast.


SECTION 3: Suggested Defensive Measures & Escalation


* **Declaration:** **True Positive – Issue (Escalated to L2)**

* **Immediate Remediation Actions:**
  * **Block Malicious File Hash:** `3F7CA11E1AD1F969B805B38E97E06C901D24777A639B9FC5673B37C069791E2A` (Add to EDR blocklist globally).
  * **Block the Domains:** 
    * `ms-complaints[.]com`
    * `rmicyber[.]com`
  * **Block the Sender:** `Cathy.McCormick[@]greatplaces[.]org[.]uk`

* **L2 Escalation Notes / Hunt Instructions:**
  * Query EDR platform (e.g., CrowdStrike/SentinelOne) for execution of `ai.exe` or the SHA256 hash across the environment.
  * Investigate network logs for outbound connections to the blocked domains.
  * Purge unread instances of this email from the Exchange/O365 environment.

**Disclaimer:** *This ticket is based on a real-world phishing sample analyzed within a controlled lab environment for educational and portfolio demonstration purposes.*
