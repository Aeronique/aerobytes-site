---
layout: writeup
title: "KC7: Encryptodera - Multi-Stage Insider Threat & Ransomware Investigation"
date: 2025-08-10
category: THREAT INTELLIGENCE
tags: [KQL, Insider Threat, Ransomware, DFIR, Credential Dumping, MITRE ATT&CK]
excerpt: "Technical analysis of three connected security incidents: insider data theft, ransomware deployment via compromised account, and cryptocurrency exfiltration over FTP spanning 40+ days."
---

*Technical report of KC7's [Encryptodera](https://kc7cyber.com/challenges/145) challenge.*

## Case Summary

Between **2024/01/16** and **2024/02/26**, **Encryptodera** experienced three significant security incidents. The first was an insider threat in which StackOverflow Copy Paster **Barry Shmelly** intentionally stole confidential data days before he resigned due to impending company layoffs. The second incident occurred when Barry's account was compromised by an external threat actor and was used to deliver **ransomware** to **306** corporate systems. The third case involved another insider threat, Blockchain Contractor **Jane Smith**, who exfiltrated cryptocurrency cold storage information undetected to an external **FTP server** over an extended period of time.

During all three events, the attackers relied on a combination of valid account abuse, removable media exfiltration, malicious email attachments, and unmonitored outbound network activity. MITRE ATT&CK mapping is cited under each activity phase to indicate the adversary TTPs that were observed during the investigation.

## Incident 1 - Insider Threat: Barry Shmelly Data Theft

### Initial Access and Activity

On **2024/01/16**, Barry Shmelly sent a series of increasingly hostile emails to colleagues and the company CEO, stating dissatisfaction and intent to leave the company. His resignation email on **2024/01/18** included personal contact information and an openly disgruntled attitude.

Network monitoring of Barry's corporate IP address (**10[.]10[.]0[.]1**) during this period revealed reconnaissance activity. He searched for whistleblower services, how to quit his job, and file transfer tools. He also downloaded the 7-Zip utility, researched cryptocurrency, and file transfer techniques. This activity matched with attempts to prepare and hide the movement of sensitive company data outside the corporate environment.

**MITRE ATT&CK Mapping:**
- **T1078** - Use of valid accounts to access corporate resources

### Data Exfiltration

Barry accessed and combined many high-value corporate files into several compressed file archives: *Personal_Memos.7z*, *Company_Secrets.7z*, *DigitalWallet_SourceCode.zip*, and *Encryptodera_Proprietary_Algorithm.zip*. These archives were protected with the password **securePass123** and transferred to a personally owned USB drive labeled **"SchmellyDrive"**. The file transfer happened shortly before his resignation on **2024/01/18**, and the files left the organization with him.

**MITRE ATT&CK Mapping:**
- **T1567.002** - Exfiltration of data to removable media devices
- **T1020** - Automated exfiltration to streamline data theft
- **T1048.002** - Use of alternative protocols for transferring data

## Incident 2 - Ransomware via Compromised Former Employee Account

### Phishing and Compromise

On **2024/02/01**, nine Encryptodera employees received an email from **barry_shmelly@encryptoderafinancial.com**. This account should have been deactivated following Barry's resignation but remained active. Each email contained an executable with a double file extension: *Company_Financials_Q1_2024_Review.xlsx.exe*, *Employee_Contact_List_Updated_March_2024.docx.exe*, and *VPN_Access_Instructions.pdf.exe*. Opening the files resulted in the installation of *screenconnect_client.exe*, a legitimate remote access tool used in this case for persistence.

Authentication logs showed the account had been accessed earlier that day from **143[.]38[.]175[.]105**, an company-unrelated IP address. This was the only user account accessed from that IP, indicating a targeted compromise.

**MITRE ATT&CK Mapping:**
- **T1566.001** - Spear-phishing with malicious attachments
- **T1078** - Abuse of valid accounts for persistence
- **T1204.002** - User execution of malicious files
- **T1105** - Transfer of malicious or administrative tools into the environment

### Discovery and Lateral Movement

On **2024/02/02**, the threat actor began testing the environment. Commands such as **"systeminfo"** and **"nltest /dclist:encryptoderafinancial.com"** were used to identify the domain controller and learn about the system configuration.

The attacker then moved laterally, accessing systems assigned to both IT and non-IT staff, including Lynda Smith (**10[.]10[.]0[.]138**) and Robin Kirby (**10[.]10[.]1[.]104**). Robin Kirby's account access login is suspicious because they are not affiliated with any IT role in the company. On *GJ95-LAPTOP* (Valerie Orozco), the threat actor executed *totally_not_mimikatz.exe* with the argument **"sekurlsa::logonpasswords"**, successfully dumping credentials from LSASS memory.

**MITRE ATT&CK Mapping:**
- **T1087** - Discovery of accounts and network resources
- **T1003.001** - Credential dumping from LSASS memory
- **T1021.001** - Use of Remote Desktop Protocol for lateral movement

### Privilege Escalation and Ransomware Deployment

With the stolen domain admin credentials, the threat actor accessed the domain controller. They executed a **"gpupdate /force"** command to push a malicious **Group Policy Object (GPO)** across the domain from an encoded PowerShell command originating from notification-finance-services[.]com, to deploy *files_go_byebye.exe* to the targeted employee endpoints. This binary was run with the parameters **"start /b C:\ProgramData\files_go_byebye.exe -encrypt -target C:\Users\ -ext .umadbro"**. The threat actor then disabled phishing detection on MS Edge.

On **2024/02/17**, ransom notes titled *YOU_GOT_CRYTOED_SO_GIMME_CRYPTO.txt* appeared on **306** systems, and over 50 files on each system were encrypted with the **.umadbro** extension.

**MITRE ATT&CK Mapping:**
- **T1486** - Encryption of data for impact
- **T1484.001** - Abuse of Group Policy for domain-wide deployment
- **T1059.001** - PowerShell used for execution

## Incident 3 - Insider Threat: Jane Smith Cryptocurrency Exfiltration

### Detection of Anomalous Network Activity

During network forensics related to the ransomware incident, analysts discovered a separate pattern of unrelated suspicious outbound traffic. A number of large-sized data transfers were observed from internal company IP **10[.]10[.]0[.]2**, which was assigned to **Jane Smith**, a Blockchain Contractor, to **182[.]56[.]23[.]121** on port **21**. This traffic occurred daily at **13:28:33** for a total of **37** consecutive days, beginning on **2024/01/21**.

**MITRE ATT&CK Mapping:**
- **T1041** - Exfiltration of data over an existing command-and-control channel

### Malicious Intent and Execution

A review of Jane's web and email activity revealed searches for **company cold storage cryptocurrency wallet locations** and direct communications with **elboss@westealurcrypto.com**. In one email, she claimed to have infiltrated the company and requested the FTP server IP address.

On **2024/01/21**, Jane downloaded two executable files: *ftp_client.exe* and *crypto_stealer.exe*. A decoded Base64 command indicated a stolen file named *Crypto_Wallet_Storage_Locations*, which was moved to a local folder on Jane's system named **"ToTheMoon"** before being exfiltrated to a server over **FTP**.

**MITRE ATT&CK Mapping:**
- **T1048.003** - Use of unencrypted, non-C2 protocols for data exfiltration
- **T1105** - Download of tools from an external source to facilitate the attack

## Indicators of Compromise (IoCs)

### Domains

**Insider Threat/Phishing/Ransomware:**
```
update-finance-security[.]biz
updatenoticefinance[.]net
updatesecurityfinance[.]biz
```

**Insider Threat 2:**
```
westealurcrypto[.]com
```

### IP Addresses

**Internal Compromised IPs:**
```
10[.]10[.]0[.]138
10[.]10[.]1[.]104
10[.]10[.]0[.]2
```

**External IPs:**
```
143[.]38[.]175[.]105
```

**FTP Exfiltration IP:**
```
182[.]56[.]23[.]121
```

### Malicious Links

```
hxxp[://]update-finance-security[.]biz/public/images/files/Employee_Contact_List_Updated_March_2024[.]docx[.]exe
hxxp[://]updatenoticefinance[.]net/images/published/modules/VPN_Access_Instructions[.]pdf[.]exe
hxxp[://]update-finance-security[.]biz/public/public/Company_Financials_Q1_2024_Review[.]xlsx[.]exe
```

### User-Agents

**Insider Threat/Phishing/Ransomware:**
```
Mozilla/5.0 (Windows 95; nl-NL; rv:1.9.2.20) Gecko/2021-11-26 20:08:12 Firefox/3.6.20
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.3; Trident/5.0)
Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 10.0; WOW64; Trident/4.0)
```

**Insider Threat 2:**
```
Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.117 Safari/537.36
Mozilla/5.0 (Linux; Android 4.0.4) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/30.0.878.0 Safari/532.0
```

### Files - Insider Threat/Phishing/Ransomware

**Employee_Contact_List_Updated_March_2024.docx.exe**
```
SHA256: c8d3b022919e9c2e72ce0401bda3d42d05651edd98d5dbff7a1fc2c8a617b056
Path: C:\Users\robriggs\Downloads\Employee_Contact_List_Updated_March_2024.docx.exe
Created: 2/1/2024, 7:44:54 AM
```

**screenconnect_client.exe**
```
SHA256: 4c199019661ef7ef79023e2c960617ec9a2f275ad578b1b1a027adb201c165f3
Path: C:\ProgramFiles(x86)\ScreenConnect Client\screenconnect_client.exe
Created: 2/1/2024, 7:45:42 AM
```

**Company_Financials_Q1_2024_Review.xlsx.exe**
```
SHA256: 067b8277d6519aa3fb6d49d80845de211542f974d16912a6823f8d8521124254
Path: C:\Users\eufoster\Downloads\Company_Financials_Q1_2024_Review.xlsx.exe
Created: 2/1/2024, 8:49:40 AM
```

**totally_not_mimikatz.exe**
```
SHA256: 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f
Command: totally_not_mimikatz.exe "sekurlsa::logonpasswords"
Executed: 2/2/2024, 8:03:29 AM
```

**files_go_byebye.exe**
```
SHA256: 6dd9c107a0aa81529ec3283fd893a254ff7a838729f5da9cd851dcfd3b0f3496
Path: C:\ProgramData\files_go_byebye.exe
Created: 2/17/2024, 2:30:50 AM
```

**YOU_GOT_CRYTOED_SO_GIMME_CRYPTO.txt**
```
SHA256: ba27663412c659dd6c9ae18e00e649cbfb310570d47be9a87a6cbe7d5e4950eb
Path: C:\Users\Public\Desktop\YOU_GOT_CRYTOED_SO_GIMME_CRYPTO.txt
Created: 2/17/2024, 2:34:54 AM
```

### Files - Insider Threat 2

**ftp_client.exe**
```
SHA256: 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce
Path: C:\Users\jasmith\Downloads\ftp_client.exe
Created: 1/21/2024, 12:36:03 PM
```

**crypto_stealer.exe**
```
SHA256: c1a589f488f6e2d3e09098e8a4a92f2cda85b0db8c5c309d763d5b4eae85b37b
Path: C:\Users\jasmith\Downloads\crypto_stealer.exe
Created: 1/21/2024, 12:36:43 PM
```

### Threat Actor Emails

```
barry_shmelly@encryptoderafinancial.com (compromised employee account)
jane_smith@encryptoderafinancial.com (insider threat 2)
elboss@westealurcrypto.com (external threat actor)
```

## Observations

- Barry's account remained active for two weeks after he quit which allowed his account to be used in a later ransomware attack
- Outbound FTP transfers from Jane's workstation went undetected for more than a month, showing that egress monitoring and alerts were not being watched
- Employees could connect USB drives to company systems without any restrictions which made it easy for sensitive files to be removed
- Malicious email attachments were delivered successfully as CLEAN which indicated that email security controls were not configured properly
- Credential dumping and domain controller access were achieved without being stopped, which showed there were large gaps in endpoint monitoring

## Recommendations

- Disable user accounts immediately upon employee departure and verify that no active sessions remain
- Apply controls to block or monitor the use of USB storage devices on systems that handle sensitive data
- Monitor outbound network traffic for unusual protocols, destinations, or patterns, and set alerts for anomalies
- Provide regular phishing awareness training for all employees, with realistic simulated tests to measure effectiveness
- Deploy and maintain EDR and DLP solutions to detect credential theft, privilege escalation, and data exfiltration in real time

## Lessons Learned

- Accounts must be disabled immediately when an employee leaves. Delays create openings that can be exploited
- Insider threats are just as damaging as external ones because insiders often know exactly where sensitive data is stored
- Allowing unrestricted use of USB drives or failing to monitor outbound traffic makes it easier for data to leave undetected
- Slow and consistent data theft can be just as harmful as rapid destructive attacks
- Effective security comes from consistent processes such as account management, email filtering, and employee awareness
- Quick detection and response reduce the time and effort needed to recover from an incident

## Conclusion

This KC7 Encryptodera challenge demonstrated how multiple security incidents can be interconnected. A disgruntled employee's data theft led to account compromise that enabled ransomware deployment, while a separate insider threat operated undetected for over a month. The investigation required correlating email logs, network traffic, file creation events, and process execution across multiple timelines to piece together three distinct but overlapping attack chains.

## Resources

- [KC7 Encryptodera Challenge](https://kc7cyber.com/challenges/145)
- [KustoQL Documentation](https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric)
