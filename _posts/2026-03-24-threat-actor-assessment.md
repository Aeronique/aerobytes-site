---
layout: writeup
title: "Threat Actor Assessment"
date: 2026-03-24
category: research
tags: ["honeypot", "threat-intelligence", "T-Pot", "GCP", "threat-actors", "attribution", "behavioral-analysis", "TTPs", "Iran-nexus", "China-nexus", "ELEVEN11", "UNC5454", "operational-patterns", "28-days-exposed"]
permalink: /writeups/honeypot-threat-research/05
excerpt: "Three CVEs, three distinct operational patterns. Burst scanning, steady botnet activity, and post-disclosure opportunistic scanning each point to different infrastructure behind the top threats in this dataset."
back_url: /honeypot-threat-research/
back_label: Back to 28 Days Exposed
---

# Threat Actor Assessment

**Deployment Period:** 2026/02/01 to 2026/02/28

**Honeypot:** T-Pot Community Edition, Google Cloud Platform

**Data Source:** Elasticsearch DSL queries, Kibana Dev Tools

**TLP:** TLP:CLEAR

---

## About This Report

This report is part of a hands-on project focused on building practical skills in threat data analysis. It is one report in an ongoing series covering the February 2026 T-Pot deployment.

---

## Summary

This deployment did not produce data that can definitively attribute attacks to named threat groups. IP addresses can be spoofed, rented, or reused. A honeypot sitting on Google Cloud sees whatever hits its ports, with no way to confirm who is behind a given source.

The data does show three distinct operational patterns across the top CVEs. Each points to a different type of actor or infrastructure.

---

## CVE-2018-13379: Burst Scanning

CVE-2018-13379 generated **29,938 events** across 28 days, but 15 of those days recorded zero activity. Two days alone accounted for 56.9% of the total: **9,338 events** on 2026/02/15 and **7,684 events** on 2026/02/21.

The pattern is long gaps followed by sudden high-volume days. This points to automated infrastructure that activates, runs through a target list, and stops, not a persistent scanner probing continuously.

CVE-2018-13379 was patched in 2019 and hit CISA KEV in 2021. Unpatched Fortinet SSL VPN devices are still reachable on the internet. Successful exploitation reads the `sslvpn_websession` file and returns credentials in cleartext, which has direct monetization value. CISA and FBI have documented APT groups, including Iran-nexus actors, using this CVE for initial access, alongside financially motivated groups using it as a stepping stone to ransomware.

Two Suricata rules for this CVE fired on identical counts every active day, meaning both matched the same traffic. This is consistent with a single fixed payload being sent repeatedly.

---

## CVE-2024-14007: Botnet Activity

CVE-2024-14007 (TVT NVMS-9000 authentication bypass) produced **1,878 events** with activity on all 28 days. Daily counts ranged from 38 to 174, averaging 67 per day.

The NVMS-9000 firmware is used across many rebranded DVR, NVR, and IP camera products. Successful exploitation returns admin credentials in cleartext. The likely goal is device recruitment for DDoS operations, which matches ELEVEN11's documented activity against telecoms and gaming platforms.

The steady daily activity is consistent with a Mirai-family botnet operation. Attribution beyond that is not supported by this data.

---

## CVE-2025-55182: Post-Disclosure Scanning

CVE-2025-55182 (React Server Components RCE, also called React2Shell) was disclosed on 2025/12/03, about two months before this deployment started. It produced **1,527 events**, active all 28 days but declining. The first two weeks averaged around 65 events per day. The final week averaged 28, ending at 8 on 2026/02/28.

The downward trend is consistent with post-disclosure scanning, where activity peaks when the vulnerability is new and drops as patches are applied. CVE-2025-55182 was added to CISA KEV on 2025/12/05. Google GTIG and Amazon AWS both documented exploitation by multiple China-nexus clusters, including UNC5454, UNC6586, UNC6588, UNC6595, and UNC6600, as well as Iran-nexus actors and the RondoDox botnet. Post-exploitation activity in the wild included XMRig miners, Cobalt Strike, and backdoors including SNOWLIGHT, MINOCAT, HISONIC, and COMPOOD. Cloudflare observed scanner tooling identifying itself via user-agent strings as `React2ShellScanner/1.0.0` and Nuclei templates labeled `CVE-2025-55182`.

---

## Summary Table

Each CVE showed a different operational pattern, pointing to different infrastructure behind each one.

| CVE | Events | Pattern | Suggested Infrastructure |
|-----|--------|---------|--------------------------|
| CVE-2018-13379 | 29,938 | Periodic bursts, long gaps | Periodic automated scanner |
| CVE-2024-14007 | 1,878 | Flat, daily, no gaps | Botnet (Mirai-family, likely ELEVEN11) |
| CVE-2025-55182 | 1,527 | Active daily, declining trend | Opportunistic post-disclosure scanning |

These are likely different actors or different types of infrastructure. The burst-scanning for CVE-2018-13379 and the steady botnet activity for CVE-2024-14007 do not share timing patterns. The React2Shell activity runs independently of both.

One thing all three have in common: none of them appear to be targeted. This honeypot was a generic GCP instance with nothing on it. The traffic it received reflects mass internet scanning, not someone trying to compromise this specific system.

---

## Limitations

This assessment is based on Suricata IDS signature matches against a single honeypot. IP geolocation and ASN data inform some context but cannot confirm actor identity. Source IPs in this dataset are frequently hosted on cloud providers and VPS services, which are routinely used to obscure origin. Attribution in this report stops at behavioral pattern and suggested infrastructure type.

---

## Methodology Notes

Event counts reflect Suricata signature matches, not confirmed exploitation. The honeypot is not a real FortiOS device, TVT DVR, or React application. Nothing in this dataset could be exploited. Counts represent inbound attempt volume only.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in `/data/`.*

---

## References

| Source | URL |
|--------|-----|
| NVD: CVE-2018-13379 | https://nvd.nist.gov/vuln/detail/CVE-2018-13379 |
| CISA KEV Catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| CISA/FBI Joint Advisory: FortiOS Exploitation | https://www.cisa.gov/news-events/alerts/2021/04/02/fbi-cisa-joint-advisory-exploitation-fortinet-fortios-vulnerabilities |
| NVD: CVE-2024-14007 | https://nvd.nist.gov/vuln/detail/CVE-2024-14007 |
| VulnCheck Advisory: CVE-2024-14007 | https://www.vulncheck.com/advisories/tvt-nvms9000-unauthenticated-admin-queries-and-information-disclosure |
| SSD Advisory: NVMS-9000 Information Disclosure | https://ssd-disclosure.com/ssd-advisory-nvms9000-information-disclosure/ |
| GreyNoise: TVT DVR Exploitation Surge | https://www.greynoise.io/blog/surge-exploitation-attempts-tvt-dvrs |
| Cybersecurity Dive: ELEVEN11 Botnet Analysis | https://www.cybersecuritydive.com/news/eleven11bot-revised-downward-mirai/741923/ |
| NVD: CVE-2025-55182 | https://nvd.nist.gov/vuln/detail/CVE-2025-55182 |
| React Official Advisory: CVE-2025-55182 | https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components |
| Amazon AWS: China-Nexus Exploitation of React2Shell | https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/ |
| Google GTIG: React2Shell Threat Actor Analysis | https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182 |
| Cloudflare: React2Shell Exploitation Threat Brief | https://blog.cloudflare.com/react2shell-rsc-vulnerabilities-exploitation-threat-brief/ |
| Microsoft Security: CVE-2025-55182 Defense | https://www.microsoft.com/en-us/security/blog/2025/12/15/defending-against-the-cve-2025-55182-react2shell-vulnerability-in-react-server-components/ |
| Wiz: React2Shell Analysis | https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182 |
| Unit 42: CVE-2025-55182 Exploitation | https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/ |
