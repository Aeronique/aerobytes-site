---
layout: writeup
title: "KC7: Krusty Krab - Threat Intelligence Investigation"
date: 2025-05-01
category: THREAT INTELLIGENCE
tags: [KQL, Phishing, DFIR, CTF, Threat Intelligence, MITRE ATT&CK]
excerpt: "My first cybersecurity investigation report analyzing a multi-stage phishing campaign, credential harvesting, malware deployment, and data exfiltration using KustoQL (KQL) database queries."
---

[![KC7 Krusty Krab Banner](/assets/images/kc7-krusty-krab/1.png)](/assets/images/kc7-krusty-krab/1.png)

## Background

In March 2025, I attended the [SANS New2Cyber Summit](https://www.sans.org/cyber-security-training-events/) virtual summit hosted by [SANS Institute](https://www.sans.org/). One of the events was a Capture The Flag (CTF) hosted by [KC7](https://kc7cyber.com/). It was my first introduction to threat intelligence in cybersecurity and the database query language [KustoQL (KQL)](https://learn.microsoft.com/en-us/kusto/query/).

I completed the CTF in two hours and enjoyed it so much that I started looking for more. Since then, I've completed 16 rooms through KC7. Through their gamified learning platform, I've gained skills in database querying, digital forensics, and developed an investigative mindset.

This report does not provide KQL queries or specific answers. All IP addresses and links have been de-fanged, but use caution around potentially malicious IPs or links.

## Disclaimer

I am not a professional in the cybersecurity field. I'm a beginner with a passion for learning, information technology, and keeping systems secure. This report is my first attempt at cybersecurity report writing, inspired by the structure of [The DFIR Report](https://thedfirreport.com/). I'm open to constructive feedback.

## Problem Statement

The Krusty Krab is a mid-sized quick-service restaurant chain operating within the greater Bikini Bottom metropolitan area. The establishment has achieved market recognition for its flagship products, including Krabby Patties™, kelp shakes, and sea dogs. Due to considerable market share, several competing entities have expressed interest in obtaining the proprietary formula.

Our cybersecurity team identified anomalous activity originating from external email addresses not associated with Krusty Krab, raising concerns about attempts to obtain unauthorized access.

## Case Summary

On **2023/03/01**, four employees from Krusty Krab **(Zenaida Warren, Julie Hong, Jon Layman, and Toni Jones)** received a malicious email from **nosferatu.hash@hotmail.com** with the subject line **"[EXTERNAL] RE: Krabby Patty Worm Detected"**. Each email contained an identical URL from the domain **scarynight[.]net**, which requested login credentials once opened. Two of four emails were marked **SUSPICIOUS** by TDR tools, the others marked **CLEAN**. Each employee clicked the malicious link.

[![Malicious phishing emails](/assets/images/kc7-krusty-krab/2.png)](/assets/images/kc7-krusty-krab/2.png)

*Initial malicious emails targeting Krusty Krab employees*

Upon further investigation, the threat actor used additional email addresses: **nosferatu@gmail.com**, **graveyard@hotmail.com**, and **slasher.graveyard@hotmail.com**. Between **2023/03/01** and **2023/03/15**, there were **26** malicious emails sent to 25 Krusty Krab employees, with one employee (**Les Costain**) targeted twice.

These emails contained links to multiple domains:
- sleeve-dark[.]net
- sleevedark[.]org
- dark-flicker[.]net
- shiftdark[.]org
- night-shift[.]com
- nightshift[.]net
- nightshift[.]com
- legendflicker[.]org

These links led to a credential harvester designed to trick users into entering their credentials. Most domains resolved to eight distinct IP addresses.

The threat actor managed to compromise and download sensitive files from **ten** employee email accounts.

Threat actors performed reconnaissance on the company website beginning **2023/02/23**. Relevant search terms included: **"krabby patty"**, **"fry cook listings"**, **"a job any job"**, and **"im brooooookkeee"**.

## Malicious File Deployment

On **2023/03/28**, employee **Timothy Graham** received an email from **legal.vendor@protonmail.com** with subject line **"[EXTERNAL] Holographic meatloaf! The new hot trend!"** The email included a URL to domain **chumsecret[.]biz** containing the file **Jellyfish_Guide.pptx**. The user clicked the link and downloaded the malicious file.

Upon opening the .pptx file:
- Malicious executable **krabbypatty.exe** was automatically created
- File **CX3VBWML.dll** was injected into the system for privilege escalation and defense evasion
- Connection established to C2 server at IP address **59[.]240[.]32[.]173**
- Threat actor ran discovery commands: **nltest**, **netsvcs**, and **wbiosvcgroup**

On **2023/03/16**, a malicious link from domain **burgers-formula.biz** containing file **Free_Money.pdf** was sent from **legal@gmail.com** with subject **"[EXTERNAL] Your artistic talents are being wasted at the Krusty Krab"** to employee **Robert Vinson**. The employee downloaded and opened the file which:
- Contained hidden executable **krabbypatty.exe**
- Injected file **CW8VCRZ1.dll** into the system
- Opened connection to C2 server at IP **213[.]173[.]220[.]223**
- Used **SpyNetServiceDss** to gain elevated privileges with Windows Defender

On **2023/03/17**, the threat actor:
- Initiated PowerShell command to collect sensitive files into staging directory
- Manipulated firewall rule to "Block Outgoing Traffic"
- Used **rclone.exe** to exfiltrate data to domain **computer-wifesecret[.]com**

The firewall rule manipulation was observed on **eight** systems.

Two additional malicious files (**Free_Money.pdf** and **Secret_Formula.docx**) executed the same attack pattern.

In total, **26** systems were compromised by malicious file **krabbypatty.exe**.

## Indicators of Compromise (IoCs)

**Domains:**
```
scarynight.net
nightshift.com
legendflicker.org
sleeve-dark.net
dark-flicker.net
shiftdark.org
night-shift.com
sleevedark.org
nightshift.net
computer-wife-formula.net
burgers-formula.biz
eugene-secret.us
chumcomputer-wife.com
burgers-secret.us
chumsecret.biz
```

**External IP Addresses - Email Exfiltration:**
```
50[.]6[.]66[.]245
54[.]17[.]157[.]246
136[.]61[.]241[.]165
156[.]122[.]52[.]45
166[.]253[.]114[.]187
187[.]111[.]81[.]175
197[.]254[.]115[.]67
198[.]64[.]168[.]114
```

**Command and Control Servers:**
```
4[.]151[.]134[.]241
20[.]32[.]154[.]116
59[.]240[.]32[.]173
81[.]200[.]227[.]215
101[.]201[.]39[.]188
118[.]203[.]240[.]111
143[.]85[.]91[.]138
147[.]183[.]1[.]178
157[.]99[.]160[.]12
193[.]185[.]165[.]60
197[.]236[.]124[.]78
204[.]167[.]93[.]24
213[.]42[.]167[.]15
213[.]173[.]220[.]223
219[.]176[.]204[.]69
```

**Malicious Files:**
```
Jellyfish_Guide.pptx
Free_Money.pdf
Secret_Formula.docx
krabbypatty.exe
CX3VBWML.dll
CW8VCRZ1.dll
```

## Compromised Accounts

### Phishing Email Recipients

**Initial Wave (2023/03/01):**
- Zenaida Warren (Marketing Intern)
- Julie Hong (IT specialist)
- Jon Layman (Cook)
- Toni Jones (Cook)

**Complete List of Targeted Employees:**
- Zenaida Warren (Marketing Intern)
- Julie Hong (IT specialist)
- Jon Layman (Cook)
- Toni Jones (Cook)
- Luther Shearer (Waiter)
- Tina Morrow (Busser)
- James Jefferies (Communications specialist)
- Les Costain (Cook) - *targeted twice*
- Shane Pierce (Marketing)
- John Huffman (Cook)
- Hector Duncan (Cashier)
- Claudia Hoppe (IT specialist)

### Email Data Exfiltration

**Ten employees** had sensitive files downloaded from their email accounts:

[![Compromised email accounts](/assets/images/kc7-krusty-krab/3.png)](/assets/images/kc7-krusty-krab/3.png)

*List of compromised accounts seen in email data exfiltration*

**50[.]6[.]66[.]245**
- 2023/03/02 - Julie Hong - important.rar

**54[.]17[.]157[.]246**
- 2023/03/08 - Luther Shearer - contents.rar
- 2023/03/16 - Hector Duncan - email.7z (downloaded 2023/03/17)

**136[.]61[.]241[.]165**
- 2023/03/07 - Tina Morrow - important.zip
- 2023/03/15 - Claudia Hoppe - email.rar (downloaded 2023/03/16)

**156[.]122[.]52[.]45**
- 2023/03/13 - James Jefferies - contents.zip (downloaded 2023/03/14)

**166[.]253[.]114[.]187**
- 2023/03/02 - Toni Jones - important.rar

**187[.]111[.]81[.]175**
- 2023/03/15 - Les Costain - email.rar

**197[.]254[.]115[.]67**
- 2023/03/14 - Shane Pierce - messages.7z

**198[.]64[.]168[.]114**
- 2023/03/09 - John Huffman - contents.7z
- 2023/03/10 - Les Costain - contents.gzip (downloaded 2023/03/11)

### Malicious File Victims

**26** employees downloaded and opened malicious files, resulting in system compromise.

[![Employee systems compromised by malicious files](/assets/images/kc7-krusty-krab/4.png)](/assets/images/kc7-krusty-krab/4.png)

*List of employee IP addresses that downloaded the malicious files*

## MITRE ATT&CK Technique Mapping

### Reconnaissance

**[T1598.003](https://attack.mitre.org/techniques/T1598/003/) - Phishing for Information: Spearphishing Link**

The threat actor sent malicious links via email to harvest login credentials. Links redirected employees to external pages prompting them to input usernames and passwords.

[![Phishing emails for credential harvesting](/assets/images/kc7-krusty-krab/5.png)](/assets/images/kc7-krusty-krab/5.png)

*Phishing emails sent from threat actor for employee credentials*

**[T1598.002](https://attack.mitre.org/techniques/T1598/002/) - Phishing for Information: Spearphishing Attachment**

The threat actor sent malicious attachments via email to gain system access. Once opened, attachments launched malicious executables that compromised systems.

[![Phishing emails with malicious attachments](/assets/images/kc7-krusty-krab/6.png)](/assets/images/kc7-krusty-krab/6.png)

*Phishing emails sent from threat actor to compromise systems*

### Resource Development

**[T1586.002](https://attack.mitre.org/techniques/T1586/002/) - Compromise Accounts: Email Accounts**

The threat actor compromised email accounts through spearphishing links.

### Initial Access

**[T1566.001](https://attack.mitre.org/techniques/T1566/001/) - Phishing: Spearphishing Attachment**

The threat actor sent spearphishing emails with malicious attachments to gain access to employee systems. Attachments were disguised as .pptx and .pdf documents and deployed malicious executables.

[![Malicious file deployment](/assets/images/kc7-krusty-krab/7.png)](/assets/images/kc7-krusty-krab/7.png)

*FileCreationEvents: Employee downloads Jellyfish_Guide.pptx and krabbypatty.exe is deployed*

### Execution

**[T1204.002](https://attack.mitre.org/techniques/T1204/002/) - User Execution: Malicious File**

The threat actor used obfuscated files to disguise hidden malicious executables which deployed once .pptx or .pdf files were opened.

[![Malicious file execution](/assets/images/kc7-krusty-krab/8.png)](/assets/images/kc7-krusty-krab/8.png)

*ProcessEvents when malicious file Jellyfish_Guide.pptx was opened*

**[T1059.001](https://attack.mitre.org/techniques/T1059/001/) - Command and Scripting Interpreter: PowerShell**

The threat actor used PowerShell scripts to establish persistence with malicious C2 servers.

**[T1059.003](https://attack.mitre.org/techniques/T1059/003/) - Command and Scripting Interpreter: Windows Command Shell**

The threat actor used Windows Command Shell to establish firewall rules blocking outgoing traffic.

[![Firewall manipulation command](/assets/images/kc7-krusty-krab/9.png)](/assets/images/kc7-krusty-krab/9.png)

*ProcessEvents showing a command script to block outgoing traffic*

### Persistence

**[T1546.016](https://attack.mitre.org/techniques/T1546/016/) - Event Triggered Execution: Installer Packages**

The threat actor used malicious files to execute malicious content, running scripts for control and data exfiltration.

**[T1078.003](https://attack.mitre.org/techniques/T1078/003/) - Valid Accounts: Local Accounts**

The threat actor compromised accounts to access important email documents and establish access to employee systems.

### Defense Evasion

**[T1562.004](https://attack.mitre.org/techniques/T1562/004/) - Impair Defenses: Disable or Modify System Firewall**

The threat actor modified firewall rules to block outgoing network traffic, enabling C2 communications and data exfiltration.

[![Firewall manipulation timeline](/assets/images/kc7-krusty-krab/10.png)](/assets/images/kc7-krusty-krab/10.png)

*ProcessEvents showing commands executed immediately before and after the firewall rule manipulation*

### Collection

**[T1114.001](https://attack.mitre.org/techniques/T1114/001/) - Email Collection: Local Email Collection**

The threat actor downloaded sensitive files from email accounts of ten employees.

[![Email account compromise and data harvesting](/assets/images/kc7-krusty-krab/11.png)](/assets/images/kc7-krusty-krab/11.png)

*InboundNetworkEvents showing compromised email accounts and data harvesting*

### Command and Control

**[T1105](https://attack.mitre.org/techniques/T1105/) - Ingress Tool Transfer**

Threat actor transferred files from external systems into compromised environments using PowerShell strings.

### Exfiltration

**[T1041](https://attack.mitre.org/techniques/T1041/) - Exfiltration Over C2 Channel**

The threat actor established connections to multiple C2 servers to exfiltrate data.

## Lessons Learned and Remediation

The threat actor managed to steal critical information from Krusty Krab employees. Further investigation will determine if the company Krabby Patty recipe has been compromised.

**Immediate Actions:**
- Reset compromised passwords
- Block malicious domains and IP addresses
- Begin malware removal from affected systems
- Remove malicious firewall rules
- Conduct remedial cybersecurity training for all employees

**Preventative Measures:**
- Basic cybersecurity awareness training for all employees
- Training on phishing, malicious files, and social engineering
- Education on inspecting links and attachments before clicking
- Utilize resources like [VirusTotal](https://www.virustotal.com/) to scan suspicious links and attachments
- Verify with security team when asked to enter credentials on non-company sites

## Conclusion

This KC7 scenario was involved and required significant time to document everything relevant for resolution. I'm excited to create more reports and further my education as I learn what it takes to become a blue team cybersecurity professional.

This investigation used KQL queries to analyze email logs, network events, file creation events, and process events to reconstruct the full attack chain from initial reconnaissance through data exfiltration.

## Resources

- [KC7 Cyber](https://kc7cyber.com/)
- [SANS New2Cyber Summit](https://www.sans.org/cyber-security-training-events/)
- [KustoQL Documentation](https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric)
- [The DFIR Report](https://thedfirreport.com/)
