---
layout: writeup
title: "2 Million Attacks, 31 Days, Three CVEs Worth Talking About"
date: 2026-02-06
category: THREAT INTELLIGENCE
series: "31 Days Exposed"
entry: "01"
tags: [CVE Analysis, Honeypot, Threat Intelligence, VNC, VoIP, WebLogic]
---

*31 Days Exposed // Entry 01*

**Report Date:** February 6, 2026  
**Analysis Period:** December 31, 2025 to January 30, 2026 (31 days)  
**Analyst:** Michelle Duell  
**Total Attack Events:** ~2,000,000  
**Statistical & Mathematical Analysis:** Assisted by Claude AI

---

## Executive Summary

This report analyzes the three most frequently exploited vulnerabilities observed during a 31-day T-Pot honeypot deployment on Google Cloud Platform. The results show that vulnerabilities from 2005 and 2006 are still being actively exploited alongside newer enterprise vulnerabilities from 2020.

**Key Findings:**

- CVE-2006-2369 (RealVNC): 20,759 total events (20 years old)
- CVE-2005-4050 (MultiTech VoIP): 11,621 events on Day 27 (19 years old)
- CVE-2020-2551 (Oracle WebLogic): 5,291 events peak on Day 17 (6 years old)

All three vulnerabilities allow remote attackers to compromise systems without authentication.

---

## CVE-2006-2369: RealVNC Authentication Bypass

### Vulnerability Information

**CVE ID:** CVE-2006-2369  
**Published:** May 15, 2006 (Source: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2006-2369))  
**Age:** 20 years old  
**CVSS Score:** HIGH 7.5 (CVSS 2.0)  
**Affected Software:** RealVNC 4.1.0 and 4.1.1  

**NIST Description:**  
"RealVNC 4.1.1, and other products that use RealVNC such as AdderLink IP and Cisco CallManager, allows remote attackers to bypass authentication via a request in which the client specifies an insecure security type such as 'Type 1 - None', which is accepted even if it is not offered by the server, as originally demonstrated using a long password." (Source: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2006-2369))

### Honeypot Observations

**Total Events Observed:** 20,759  
**Peak Activity:** Days 6-9 (January 5-8, 2026)  
**Peak Single Day:** 19,745 events  
**Activity Pattern:** Sustained targeting across multiple days

Source: T-Pot Honeypot deployment data, Days 1-31 analysis

### Technical Details

**Vulnerability:**

The vulnerability exists in the VNC authentication handshake process. According to security researchers, the client can force the server to accept "Type 1 - None" authentication (no password) even when the server only offers password-based authentication.

**VNC Security Types:**
- Type 1: None (no authentication)
- Type 2: VNC Authentication (password required)

**Attack Method:**

The attacker connects to a VNC server and tells it to use Type 1 authentication. The vulnerable RealVNC versions accept this request even though they should require a password. (Source: [CVE Details](https://www.cvedetails.com/cve/CVE-2006-2369/))

**Affected Products Beyond RealVNC:**
- AdderLink IP (KVM switches)
- Cisco CallManager (VoIP systems)
- Other products using RealVNC libraries

Source: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2006-2369)

### Available Exploits

**Metasploit Module:** `auxiliary/admin/vnc/realvnc_41_bypass`

The Metasploit Framework has a publicly available module for this vulnerability. According to the module documentation:

```
Module: auxiliary/admin/vnc/realvnc_41_bypass
Target Port: 5900
```

Source: [InfosecMatter](https://www.infosecmatter.com/metasploit-module-library/?mm=auxiliary/admin/vnc/realvnc_41_bypass)

**Nmap Detection Script:**

Nmap has a script to detect this vulnerability: `realvnc-auth-bypass`

```
nmap -sV --script=realvnc-auth-bypass <target>
```

Source: [Vulmon](https://vulmon.com/vulnerabilitydetails?qid=CVE-2006-2369)

### Defensive Recommendations

**Immediate Actions:**

1. **Upgrade RealVNC:** Update to version 4.1.2 or later (released June 2006)

2. **Block VNC Ports:** Restrict access to ports 5900-5910 to trusted networks only

### Assessment

This vulnerability is 20 years old, yet the honeypot recorded 20,759 exploitation attempts over the 31-day deployment. Many systems are still running unpatched VNC versions, attackers know it, and the exploit is publicly available and easy to run.

---

## CVE-2005-4050: MultiTech VoIP Buffer Overflow

### Vulnerability Information

**CVE ID:** CVE-2005-4050  
**Published:** December 7, 2005 (Source: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2005-4050))  
**Age:** 19 years old  
**CVSS Score:** HIGH 7.5 (CVSS 2.0)  
**Affected Products:** Multiple Multi-Tech Systems MultiVOIP devices  

**NIST Description:**  
"Buffer overflow in multiple Multi-Tech Systems MultiVOIP devices with firmware before x.08 allows remote attackers to execute arbitrary code via a long INVITE field in a Session Initiation Protocol (SIP) packet." (Source: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2005-4050))

### Honeypot Observations

**Total Events:** 11,621  
**Peak Activity:** Day 27 (January 26, 2026)  
**Pattern:** All events concentrated in a single 24-hour period  
**Associated Signature:** SID 2003237 - ET VOIP MultiTech SIP UDP Overflow

**Campaign Details:**
- Source IP: 213.136.91.138 (AS51396 velia.net, Germany)
- Total campaign volume: 132,469 events (68% of Day 27 traffic)
- Port: UDP 5060 (SIP protocol)
- Tool used: Sipsak (professional SIP testing tool)
- Sipsak signature events: 120,855 (SID 2008598)

Source: T-Pot Honeypot Day 27 Logs

### Technical Details

**SIP Definition:**

SIP (Session Initiation Protocol) is used for VoIP phone calls. It uses text-based messages to set up calls. One of these messages is called INVITE which starts a call.

**Vulnerability:**

The MultiTech VoIP gateways have a buffer overflow when processing SIP INVITE messages. If an attacker sends an INVITE message with a very long field, it overflows the buffer and can let them execute code on the device.

Source: [CVE Details](https://www.cvedetails.com/cve/CVE-2005-4050/)

**Normal SIP INVITE:**
```
INVITE sip:user@domain.com SIP/2.0
```

**Malicious INVITE:**
```
INVITE sip:[long string of 1000+ characters]@domain.com SIP/2.0
```

The long string overflows the buffer and can execute attacker code.

**Affected Devices:**
- MultiVOIP FX Series (analog VoIP gateways)
- MultiVOIP MVP Series
- MultiVOIP BRI/PRI Series (ISDN gateways)

All devices with firmware before version x.08 are vulnerable.

Source: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2005-4050)

### Sipsak Tool Detection

The honeypot detected Sipsak, a legitimate SIP testing tool that can be repurposed for attacks. Often called the "SIP Swiss Army Knife," it is widely used for testing VoIP systems.

The Day 27 campaign showed deliberate VoIP targeting using this tool, with 120,855 Sipsak signature detections.

Source: T-Pot Honeypot Day 27 Logs

### Defensive Recommendations

**Immediate Actions:**

1. **Update Firmware:** Upgrade to firmware version x.08 or later (released 2006)

2. **Restrict SIP Access:** Block UDP port 5060 from internet, allow only from trusted SIP providers

3. **Message Size Limits:** Configure firewalls to block SIP INVITE messages over 512 characters

4. **Monitor for Sipsak:** Watch for Sipsak user-agent strings in SIP traffic

### Assessment

A 19-year-old vulnerability produced a single-day spike of 11,621 events on Day 27. The attacker used professional VoIP testing tools and targeted port 5060 exclusively, which points to VoIP infrastructure being actively scanned, old MultiTech gateways still being deployed in the wild, and professional tooling being used rather than opportunistic scanning.

---

## CVE-2020-2551: Oracle WebLogic Server RCE

### Vulnerability Information

**CVE ID:** CVE-2020-2551  
**Published:** January 15, 2020 (Source: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-2551))  
**Age:** 6 years old  
**CVSS Score:** 9.8 CRITICAL (CVSS 3.0)  
**Affected Versions:**
- Oracle WebLogic Server 10.3.6.0.0
- Oracle WebLogic Server 12.1.3.0.0
- Oracle WebLogic Server 12.2.1.3.0
- Oracle WebLogic Server 12.2.1.4.0

**NIST Description:**  
"Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)." (Source: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-2551))

**Discovery:**

The vulnerability was discovered by Stefano Ciccone of Aon's Cyber Solutions and disclosed to Oracle on September 26, 2019. Oracle confirmed and reproduced the issue on October 21, 2019, and released patches on January 14, 2020. (Source: [LevelBlue SpiderLabs](https://levelblue.com/blogs/spiderlabs-blog/cve-2020-2551-unauthenticated-rce-in-oracle-weblogic/))

### Honeypot Observations

**CVE-2020-2551 Events:** 44,927 total events over 31 days  
**Ranking:** Third most exploited vulnerability in dataset

**Attack Pattern:**
- Primary target: TCP port 7001 (default IIOP port)
- Consistent scanning activity throughout deployment period
- Part of broader WebLogic targeting campaigns

Source: T-Pot Honeypot Logs

### Technical Details

**IIOP Definition:**

IIOP (Internet Inter-ORB Protocol) is a protocol used by CORBA (Common Object Request Broker Architecture) objects to communicate over the internet. IIOP enables servers and browsers to exchange complex objects. WebLogic Server supports RMI over IIOP, combining the advantages of both technologies. WebLogic Server has IIOP enabled by default, and the IIOP service listens on an external interface. The transmission of objects in IIOP is carried out through serialization and deserialization. (Source: [Qualys ThreatPROTECT](https://threatprotect.qualys.com/2020/04/27/oracle-weblogic-insecure-deserialization-with-iiopcve-2020-2551/))

**Vulnerability Mechanism:**

The vulnerability involves improper filtering of the JtaTransactionManager class. The JtaTransactionManager plays an important role in JNDI injection attacks. JNDI is a Java API (such as InitialContext.lookup) that takes one string parameter, and if this parameter comes from an untrusted source, it can lead to remote code execution.

The WLInitialContextFactory class creates initial contexts for accessing the naming service and uses IIOP protocol for data interaction. IIOP automatically serializes and deserializes objects during transmission. When a malicious serialized object is sent to port 7001 of the WebLogic server, it can result in remote code execution. (Source: [Qualys ThreatPROTECT](https://threatprotect.qualys.com/2020/04/27/oracle-weblogic-insecure-deserialization-with-iiopcve-2020-2551/))

**Attack Flow:**

Using the WebLogic libraries, it is possible to create a payload that causes a remote IIOP server to initialize a Java object that invokes a JNDI lookup to an attacker controlled server, leading to code execution. (Source: [LevelBlue SpiderLabs](https://levelblue.com/blogs/spiderlabs-blog/cve-2020-2551-unauthenticated-rce-in-oracle-weblogic/))

The complete proof of concept involves:
1. Setting java.naming.provider.url to iiop://127.0.0.1:7001 to get the corresponding InitialContext object
2. Binding the serialized object and sending it to the IIOP server
3. When the WebLogic server receives the requested byte stream, it performs deserialization, triggering the vulnerability

(Source: [Qualys ThreatPROTECT](https://threatprotect.qualys.com/2020/04/27/oracle-weblogic-insecure-deserialization-with-iiopcve-2020-2551/))

**CVSS 9.8 Breakdown:**

- **AV:N** (Network): Remotely exploitable over a network
- **AC:L** (Low Complexity): Easily exploitable
- **PR:N** (No Privileges Required): No authentication needed
- **UI:N** (No User Interaction): Fully automated exploitation
- **S:U** (Unchanged Scope): Vulnerability confined to vulnerable component
- **C:H** (High Confidentiality Impact): Complete information disclosure
- **I:H** (High Integrity Impact): Complete data modification capability
- **A:H** (High Availability Impact): Complete denial of service capability

(Source: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-2551))

### Defensive Recommendations

**Immediate Actions:**

1. **Apply Oracle Patches:** Install the January 2020 Critical Patch Update for affected WebLogic Server versions.
   - Source: [Oracle Security Alerts](https://www.oracle.com/security-alerts/cpujan2020.html)

2. **Network Segmentation:** Restrict access to IIOP port 7001 to only trusted management networks. The IIOP service should not be exposed to untrusted networks.

**Detection Capabilities:**

Security vendors have released IPS signatures to detect exploitation attempts:
- **Qualys:** QID 372334 and QID 87411 (Source: [Qualys ThreatPROTECT](https://threatprotect.qualys.com/2020/04/27/oracle-weblogic-insecure-deserialization-with-iiopcve-2020-2551/))
- **Fortinet:** IPS Signature 48725 with default action of drop (Source: [Fortinet FortiGuard](https://www.fortiguard.com/encyclopedia/ips/48725))

### Assessment

CVE-2020-2551 carries a CVSS score of 9.8, which is about as bad as it gets. No credentials required, no user interaction needed, default configuration exposed, complete server takeover on successful exploitation. The honeypot recorded 44,927 attempts over the 31-day period. This is not theoretical targeting. Attackers are actively and consistently scanning for unpatched WebLogic servers.

Organizations running affected versions should treat this as a patching priority, not a backlog item.

---

## Comparative Analysis

### Vulnerability Age vs. Event Volume

| CVE | Year | Age | Total Events | Events Per Year |
|-----|------|-----|--------------|-----------------|
| CVE-2006-2369 | 2006 | 20 years | 20,759 | 1,038 |
| CVE-2005-4050 | 2005 | 19 years | 11,621 | 612 |
| CVE-2020-2551 | 2020 | 6 years | 5,291 | 882 |

The two oldest vulnerabilities generated more total events than the newer enterprise vulnerability. Old vulnerabilities stay in active rotation because many systems never get patched, exploits are publicly available, and automated scanners carry these CVEs as standard targets.

### Common Characteristics

All three CVEs share these characteristics:

1. **No Authentication Required:** All can be exploited remotely without credentials
2. **Network Exploitable:** All can be attacked over the network/internet
3. **Complete Compromise:** All lead to full system control or code execution
4. **Default Configurations:** All affect default or common configurations
5. **Public Exploits:** All have publicly available exploit code

### Attack Patterns Observed

**Legacy CVEs (2005-2006):**
- Sustained baseline scanning over multiple days
- Integrated into standard scanning tools
- Opportunistic mass scanning
- **High success rate due to unpatched systems**

**Modern CVE (2020):**
- Coordinated campaigns with cloud infrastructure
- A defined start/end point through tactical operations
- Reconnaissance before peak attack

---

### Strategic Recommendations

1. **Asset Inventory:** Maintain up-to-date inventory of all software versions
2. **Patch Management:** Establish 30-day patch cycle for CRITICAL vulnerabilities
3. **Network Segmentation:** Isolate legacy systems from internet
4. **Monitoring:** Deploy IDS/IPS with recommended signatures for these CVEs
5. **Legacy System Replacement:** Plan future migration for 19/20 year old systems

---

## Conclusion

This analysis of our 31-day honeypot deployment shows that both old and new vulnerabilities are actively being exploited. The three most common CVEs we observed were:

1. **CVE-2006-2369** (20 years old): 20,759 events - RealVNC authentication bypass
2. **CVE-2005-4050** (19 years old): 11,621 events - MultiTech VoIP buffer overflow
3. **CVE-2020-2551** (6 years old): 5,291 events - Oracle WebLogic deserialization RCE

**What I Learned:**

- Old vulnerabilities are still dangerous (32,380 combined events from 19-20 year old CVEs)
- All three allow remote exploitation without authentication
- Public exploits are available for all three
- Professional attackers use cloud infrastructure for campaigns (Day 17 Google Cloud surge)
- VoIP systems are being professionally targeted (Sipsak tool, Day 27 campaign)

---

## Sources and References

### NIST NVD Official CVE Pages
- [CVE-2006-2369](https://nvd.nist.gov/vuln/detail/CVE-2006-2369)
- [CVE-2005-4050](https://nvd.nist.gov/vuln/detail/CVE-2005-4050)
- [CVE-2020-2551](https://nvd.nist.gov/vuln/detail/CVE-2020-2551)

### Exploit Databases
- [Exploit-DB CVE-2006-2369](https://www.exploit-db.com/exploits/17719)
- [CVE Details CVE-2006-2369](https://www.cvedetails.com/cve/CVE-2006-2369/)
- [CVE Details CVE-2005-4050](https://www.cvedetails.com/cve/CVE-2005-4050/)

### Vendor Security Advisories
- [Oracle Critical Patch Update January 2020](https://www.oracle.com/security-alerts/cpujan2020.html)

### Metasploit Modules
- [Metasploit VNC Module](https://www.infosecmatter.com/metasploit-module-library/?mm=auxiliary/admin/vnc/realvnc_41_bypass)
- [Rapid7 WebLogic Module](https://www.rapid7.com/db/modules/exploit/multi/misc/weblogic_deserialize/)

### Security Research
- [Qualys CVE-2020-2551 Analysis](https://threatprotect.qualys.com/2020/04/27/oracle-weblogic-insecure-deserialization-with-iiopcve-2020-2551/)
- [SonicWall WebLogic Analysis](https://blog.sonicwall.com/en-us/2020/05/oracle-weblogic-insecure-deserialization-vulnerability-actively-being-exploited-in-the-wild/)
- [Sangfor CVE-2020-2551 Technical Analysis](https://www.sangfor.com/blog/cybersecurity/weblogic-remote-code-execution-vulnerability-cve-2020-2551)
- [Fortinet IPS Signature](https://www.fortiguard.com/encyclopedia/ips/48725)

### Additional Resources
- [HackTricks VoIP Pentesting Guide](https://book.hacktricks.xyz/network-services-pentesting/pentesting-voip)
- [Vulmon CVE-2006-2369](https://vulmon.com/vulnerabilitydetails?qid=CVE-2006-2369)
