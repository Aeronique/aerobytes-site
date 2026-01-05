---
layout: writeup
title: "KC7: Convoy Street Interactive - APT41 Threat Hunt"
date: 2025-07-28
category: THREAT INTELLIGENCE
tags: [KQL, Threat Hunting, DFIR, CTF, APT41, MITRE ATT&CK]
excerpt: "Threat hunting investigation tracking APT41 (Brass Typhoon) from initial reconnaissance through data exfiltration in a gaming company breach. Participated in KC7's Threat Hunting in Action workshop."
---

![KC7 Convoy Street Banner](/assets/images/kc7-convoy-street/1.png)

*Participating in KC7's Threat Hunting in Action workshop provided hands-on training for blue team operations. During the four-hour session I developed practical skills in authoring KQL queries within Azure Data Explorer to sift through large-scale telemetry and detect anomalous activity. I applied the Diamond Model methodology to correlate threat intelligence with network events and completed capture-the-flag exercises modeled on real world ransomware scenarios. Offered at no cost, this workshop has significantly enhanced my threat-hunting capabilities and accelerated my development as a blue team analyst.*

## Background

You've just logged into your workstation at Convoy Street Interactive.

The company's come a long way since its early days above 🍚🍖Tita's Comfort Food🍳 in San Diego's Convoy District. What started with late-night coffee-fueled brainstorms turned into *The Hamburger Hustle*, a fast-paced multiplayer strategy game that rewards creativity, bold moves, and serious resource management. Players earn, trade, and hustle their way to burger empire domination. And as the player base grew, so did the stakes.

Fame brings attention. And not just from gamers.

Convoy Street Interactive has become a fixture in the gaming world. With that kind of growth comes interest in more than just gameplay. Here are just a few of the company's most valuable systems:

- **HustleShield**: a proprietary anti-cheat engine built in-house, now licensed by several other studios to protect competitive multiplayer environments

- **HeatmapVision**: an internal tool for analyzing player behavior across maps and scenarios, often used to guide design decisions

- **Greasy Tender (GT)**: the in-game currency at the core of Hamburger Hustle's economy, with real-world value tied to virtual transactions

- **Limited-Edition Skins**: rare cosmetic items that players can unlock or trade, some of which have gained collector status

- **DevNet Sync**: the company's private sync and telemetry infrastructure used to test unreleased features across distributed teams

Hard to say who might be watching. Rival studios? Disgruntled players? Or someone with a deeper interest in what's under the hood?

Whatever it is, something's not sitting right. And if they're after anything on the 🍔🍔Secret Menu, it's your job to make sure they don't get it.

📡 You receive a message from a partner company that licenses **HustleShield**:

*"Hey, just a heads-up. We've been seeing a lot of recon traffic coming from IP 185.210.94.2. Thought you might want to check your side."*

Let's take a look.

## Case Summary

Between 2024/03/04 and 2024/03/21, Convoy Interactive was targeted by a threat actor attributed to APT41 (Brass Typhoon), a China-based group known for blending espionage and financially motivated attacks. The attacker used website reconnaissance, spearphishing with spoofed company emails, credential harvesting, and living-off-the-land techniques to escalate privileges, maintain persistence, and exfiltrate sensitive data. MITRE ATT&CK mapping throughout the report highlights observed adversary TTPs.

## Initial Access

### Reconnaissance

On 2024/03/04, suspicious activity from IP address 185[.]210[.]94[.]2 was observed. The actor performed 24 targeted searches on the public company website, using queries such as "Greasy Tender admin," "database admin credentials," and "internal game economy documentation." Domain analysis of this IP and its associates (185[.]210[.]94[.]3, 185[.]210[.]94[.]4) revealed ties to telemetryfinancegaming[.]net and other .cn domains.

![Targeted search queries](/assets/images/kc7-convoy-street/2.png)

*Targeted search queries from reconnaissance activity*

**MITRE ATT&CK:**

- [T1596](https://attack.mitre.org/techniques/T1596/) Search Open Websites/Domains
- [T1589](https://attack.mitre.org/techniques/T1589/) Gather Victim Identity Information

### Phishing and Initial Compromise

Between 2024/03/08 and 2024/03/13, ten employees received targeted phishing emails from spoofed company addresses such as financial-reports@convoyinteractive.com and audit-team@convoyinteractive.com. The emails included attachments titled *GreasyTender_Audit_Report.pdf* and *GT_TelemetrySync.log.pdf*, as well as links to the attacker's infrastructure. Employees in roles related to fraud prevention and game economy opened these attachments, triggering malware execution.

![Phishing emails](/assets/images/kc7-convoy-street/3.png)

*Phishing emails sent to employees from spoofed company addresses*

**MITRE ATT&CK:**

- [T1566.001](https://attack.mitre.org/techniques/T1566/001/) Spearphishing Attachment
- [T1598](https://attack.mitre.org/techniques/T1598/) Phishing for Information
- [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution

## Execution and C2

Opening the attachments resulted in the deployment of *output_beacon_monitor.exe*, which executed a hex-encoded PowerShell script. This script established a connection to a command and control (C2) server at hustlefinance[.]cn (185[.]210[.]94[.]1). Process events showed the malware immediately scanning for sensitive data files (\*.db, \*.sqlite, \*.csv, \*.xlsx).

![File creation of malicious attachment and beacon](/assets/images/kc7-convoy-street/4.png)

*File creation events showing malicious attachment and beacon deployment*

![Process events showing C2 connection script](/assets/images/kc7-convoy-street/5.png)

*Process events showing C2 connection script execution*

![Hex decoded script](/assets/images/kc7-convoy-street/6.png)

*Decoded PowerShell script revealing C2 communication and file discovery commands*

**MITRE ATT&CK:**

- [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell
- [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer
- [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery

## Credential Access, Lateral Movement, and Persistence

On 2024/03/13, the threat actor harvested credentials by exfiltrating *stolen_chrome_creds.db* and *stolen_browser_creds.sqlite*. Persistence was established via a scheduled task set with PowerShell to re-establish C2 at logon. The actor brute-forced 468 employee credentials, resulting in 236 successful logins. Lateral movement was observed via RDP from employee Wes Mantooth's machine to GreasyTenderVault.

![Credential exfiltration](/assets/images/kc7-convoy-street/7.png)

*Credential database files exfiltrated from compromised systems*

![Scheduled task manipulation](/assets/images/kc7-convoy-street/8.png)

*PowerShell scheduled task created for persistence*

![Authentication attempts made by threat actor](/assets/images/kc7-convoy-street/9.png)

*Authentication attempts showing unique user-agent used by threat actor*

![Successful threat actor login via RDP](/assets/images/kc7-convoy-street/10.png)

*Successful RDP connection from compromised account to GreasyTenderVault*

**MITRE ATT&CK:**

- [T1555](https://attack.mitre.org/techniques/T1555/) Credentials from Password Stores
- [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task/Job
- [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force
- [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote Services: RDP
- [T1087](https://attack.mitre.org/techniques/T1087/) Account Discovery

## Privilege Escalation, Exfiltration, and Defense Evasion

The attacker escalated privileges to SYSTEM on GreasyTenderVault. On 2024/03/18, four encoded commands were used for further persistence. The hustlecoin_main_blackmarket account was used to redirect funds, and data was exfiltrated to hxxp[:]//HambulgelerHustle[.]cn/exfil/. On 2024/03/21, the threat actor ran **'wevtutil cl'** to clear Windows event logs, attempting to erase evidence of their activity.

![Encoded PowerShell commands](/assets/images/kc7-convoy-street/11.png)

*Base64 encoded PowerShell commands used for persistence*

![Decoded Base64](/assets/images/kc7-convoy-street/12.png)

*First decoded command showing scheduled task creation*

![Decoded Base64](/assets/images/kc7-convoy-street/13.png)

*Second decoded command revealing exfiltration script*

![Evidence of log clearing attempts](/assets/images/kc7-convoy-street/14.png)

*Process events showing wevtutil command to clear event logs*

**MITRE ATT&CK:**

- [T1068](https://attack.mitre.org/techniques/T1068/) Privilege Escalation
- [T1567.002](https://attack.mitre.org/techniques/T1567/002/) Exfiltration Over Web Service
- [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal on Host
- [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information

## Indicators of Compromise (IoCs)

**Domains:**
```
telemetry-finance-gaming[.]net
gaming-telemetry-finance[.]cn
telemetryfinancegaming[.]net
gaming-telemetry-finance[.]com
gamingtelemetryfinance[.]cn
```

**External IP Addresses:**
```
185[.]210[.]94[.]2
185[.]210[.]94[.]3
185[.]210[.]94[.]4
```

**Command and Control Server:**
```
185[.]210[.]94[.]1
```

**Exfiltration Servers:**
```
hxxps[://]hustlefinance[.]cn/exfil/
hxxp[://]HambulgelerHustle[.]cn/exfil/
```

**Malicious URLs:**
```
hxxp[://]gamingtelemetryfinance[.]net/docs
hxxps[://]telemetryfinancegaming[.]cn/media/services/docs
hxxp[://]telemetryfinancegaming[.]net/api/media/api
hxxps[://]gamingtelemetryfinance[.]cn/support
hxxps[://]telemetry-finance-gaming[.]net/services/support/api
```

**User Agent:**
```
Opera/8.19.(Windows NT 5.0; xh-ZA) Presto/2.9.160 Version/12.00
```

**Malicious Files:**

```
Name: GreasyTender_Audit_Report.pdf
SHA256: aed59e28bda5e0c4bf0d7dc094c56348ea8ee0fe478201eac4110c37decc7d0e
Path: C:\Users\peorourke\Downloads\GreasyTender_Audit_Report.pdf
Created: 3/9/2024, 9:12:47 AM

Name: GT_TelemetrySync.log.pdf
SHA256: 03daaca897b44c99ec8622f79905c0cb0505ce97635b1dbcfa3361cb77c1afea
Path: C:\Users\damartin\Downloads\GT_TelemetrySync.log.pdf
Created: 3/11/2024, 4:31:00 PM

Name: output_beacon_monitor.exe
SHA256: dd053f38f5e60cd8750df450a13833c96d1285e78480323a54abab4a536f6317
Path: C:\ProgramData\output_beacon_monitor.exe
Created: 3/9/2024, 9:12:55 AM

Name: output_beacon_monitor.exe
SHA256: 582fb1a22cfa18dd496422a72eda806509d94ca1a6befef707973ea2a2be453c
Path: C:\ProgramData\output_beacon_monitor.exe
Created: 3/11/2024, 4:31:03 PM

Name: output_beacon_monitor.exe
SHA256: 1dc1dbfc1d636fed5cebe43787a7abf2df4fbb51e1beaec34ba72dd5152edc81
Path: C:\ProgramData\output_beacon_monitor.exe
Created: 3/12/2024, 4:14:20 PM
```

**Threat Actor Emails:**
```
financial-reports@convoyinteractive.com
audit-team@convoyinteractive.com
money-ops@convoyinteractive.com
finance-ops@convoyinteractive.com
```

## Observations

One thing that stands out in this case is we still don't know exactly how Brass Typhoon managed to send such convincing fake emails straight to our employees. The signs point to forged email headers, lookalike domains, and social engineering, but it's unclear if they took advantage of gaps in our email authentication (like missing or misconfigured SPF, DKIM, or DMARC), abused open mail relays, or sent emails through compromised third parties. This method of slipping malicious documents past defenses is typical for Brass Typhoon, but we need to dig deeper to figure out exactly how those emails got through.

## Recommendations

To help prevent attacks like this, email protections like SPF, DKIM, and DMARC need to be set up and working properly. Regular security training is necessary so people know what phishing looks like and feel comfortable reporting anything suspicious. Multi-factor authentication is a must for keeping accounts secure. It helps to stay on top of server updates, watch out for domains that look like yours, and limit admin access as much as possible. Tools like EDR can catch suspicious activity early, and running the occasional phishing drill keeps everyone aware of new tricks attackers might use.

## Lessons Learned

- This analysis reinforced the importance of defense-in-depth and the need for layered security.
- Even sophisticated attackers like Brass Typhoon often exploit basic weaknesses such as insufficient email authentication or user awareness gaps to gain initial access.
- Consistent monitoring, regular user training, and strong credential management are essential for defense.
- Technical controls like EDR, server hardening, and robust email protections must be implemented and maintained.
- Understanding both the attacker's techniques and our own operational blind spots is necessary for building a stronger security posture.
