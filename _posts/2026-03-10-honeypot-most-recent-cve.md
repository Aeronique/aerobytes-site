---
layout: writeup
title: "T-Pot Honeypot: Most Recently Disclosed CVE Observed - February 2026"
date: 2026-03-10
category: THREAT INTELLIGENCE
tags: ["honeypot", "threat-intelligence", "T-Pot", "GCP", "CVE", "telnet"]
permalink: /writeups/honeypot-threat-research/02
excerpt: "Analysis of CVE-2026-24061, the most recently disclosed CVE observed in the February 2026 T-Pot honeypot deployment, including observed activity, scoring data, and defender guidance."
back_url: /honeypot-threat-research/
back_label: Back to 28 Days Exposed
---

# CVE-2026-24061: GNU InetUtils telnetd Authentication Bypass

**Deployment Period:** 2026/02/01 to 2026/02/28

**Honeypot:** T-Pot Community Edition, Google Cloud Platform

**Data Source:** Elasticsearch DSL queries, Kibana Dev Tools

**TLP:** TLP:CLEAR

---

## About This Report

This report is part of a hands-on project focused on building practical skills in threat data analysis and CVE research. It is one report in an ongoing series covering the February 2026 T-Pot deployment. 

---

## Summary

CVE-2026-24061 is the most recently disclosed CVE observed in this dataset. It was published on 2026/01/21, less than two weeks before this deployment began. The honeypot recorded **9 events** across **4 days**. The numbers are small, but the timing stood out to me. Scanners were already looking for this vulnerability before the month even started.

---

## CVE-2026-24061: GNU InetUtils telnetd Authentication Bypass

Telnet is an old remote access protocol, largely replaced by SSH. `telnetd` is the server-side component that handles incoming Telnet connections. This vulnerability exists in the GNU InetUtils version of `telnetd`.

The flaw comes down to a missing input check. When a client connects, it can send a username as part of the connection. `telnetd` passes that username directly to the system's login program without checking it first. An attacker can send `-f root` as the username, which tells the login program to skip the password check and log in as root. No password needed. The bug was introduced in a 2015 code change and went unnoticed for over 10 years.

**Affected products:** GNU InetUtils `telnetd` versions 1.9.3 through 2.7. Fixed in 2.7-2, patches released 2026/01/20.

| Metric | Value | Source |
|--------|-------|--------|
| CVSS v3.1 | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | NVD |
| EPSS | 75.27% | Shodan CVEDB |
| CISA KEV | Yes, added 2026/01/26 | CISA |
| Ransomware | Unknown | Shodan CVEDB |

**Observed activity:** **9 total events** across 4 active days. The first hit came on 2026/02/01, 11 days after disclosure. Six of the nine events happened on that first day. The remaining 3 were spread across 2026/02/04, 2026/02/06, and 2026/02/20.

**Assessment:** What I found interesting here is the speed at which this flaw was found and exploited. GreyNoise documented exploitation attempts starting within 18 hours of the original disclosure. CISA added it to the KEV catalog on 2026/01/26, six days after the patch dropped. By the time my honeypot went live, scanners had already been active for nearly two weeks. The low event count makes sense too. Telnet is uncommon on modern internet-facing systems, so there are fewer targets to scan for compared to something like a web application vulnerability.

**Defender note:** Patch to GNU InetUtils 2.7-2 or later, or disable `telnetd` entirely if you are not using it. This one is worth checking on older or embedded Linux systems where Telnet may still be running and easy to overlook. CISA's remediation deadline for federal agencies was 2026/02/16.

---

## Data Reference

### Table 1: CVE-2026-24061 Daily Event Counts

| Day | Date | Events |
|-----|------|--------|
| 01 | 2026/02/01 | 6 |
| 02 | 2026/02/02 | 0 |
| 03 | 2026/02/03 | 0 |
| 04 | 2026/02/04 | 1 |
| 05 | 2026/02/05 | 0 |
| 06 | 2026/02/06 | 1 |
| 07-19 | 2026/02/07 to 2026/02/19 | 0 |
| 20 | 2026/02/20 | 1 |
| 21-28 | 2026/02/21 to 2026/02/28 | 0 |
| **Total** | | **9** |

---

## Methodology Notes

**Event counts reflect IDS alerts, not confirmed exploitation.** Suricata flagged traffic that matched a known attack pattern for this CVE. The honeypot is not a real `telnetd` host, so none of these attempts could have succeeded. The counts show inbound probe volume only.

**Days with 0 events are omitted from the main table rows** but retained in the collapsed row above for completeness.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in [honeypot-threat-research/data](https://github.com/Aeronique/honeypot-threat-research/tree/main/data).*

---

## References

| Source | URL |
|--------|-----|
| NVD: CVE-2026-24061 | https://nvd.nist.gov/vuln/detail/CVE-2026-24061 |
| CVE Record: CVE-2026-24061 | https://www.cve.org/CVERecord?id=CVE-2026-24061 |
| CISA KEV Catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| oss-security: GNU InetUtils telnetd disclosure | https://www.openwall.com/lists/oss-security/2026/01/20/2 |
| GNU bug-inetutils: Patch announcement | https://lists.gnu.org/archive/html/bug-inetutils/2026-01/msg00004.html |
| Codeberg: Fix commit (sanitize USER variable) | https://codeberg.org/inetutils/inetutils/commit/fd702c02497b2f398e739e3119bed0b23dd7aa7b |
| Shodan CVEDB: CVE-2026-24061 | https://cvedb.shodan.io/cve/CVE-2026-24061 |
| GreyNoise Labs: 18 Hours of Unsolicited Telnet Houseguests | https://www.labs.greynoise.io/grimoire/2026-01-22-f-around-and-find-out-18-hours-of-unsolicited-houseguests/ |
| The Hacker News: Critical GNU InetUtils telnetd Flaw | https://thehackernews.com/2026/01/critical-gnu-inetutils-telnetd-flaw.html |
| Horizon3.ai: CVE-2026-24061 Rapid Response | https://horizon3.ai/attack-research/vulnerabilities/cve-2026-24061/ |
| Ubuntu Security: CVE-2026-24061 | https://ubuntu.com/security/CVE-2026-24061 |
