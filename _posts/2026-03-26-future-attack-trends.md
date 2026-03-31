---
layout: writeup
title: "Future Attack Trends"
date: 2026-03-26
category: research
tags: ["honeypot", "threat-intelligence", "T-Pot", "GCP", "trends", "CVE", "Fortinet", "IoT-botnet", "RondoDox", "Verizon-DBIR", "exploitation-trends", "Vite", "PHP-CGI", "CVE-2024-4577", "28-days-exposed"]
permalink: /writeups/honeypot-threat-research/06
excerpt: "Three patterns from this deployment align with broader reporting from early 2026: a 2019-patched Fortinet flaw still leading by volume, IoT botnet scanning running every single day, and a critical RCE active within two months of disclosure."
back_url: /honeypot-threat-research/
back_label: Back to 28 Days Exposed
---

**Deployment Period:** February 1, 2026 to February 28, 2026

**Honeypot:** T-Pot Community Edition, Google Cloud Platform

**Data Source:** Elasticsearch DSL queries, Kibana Dev Tools

**TLP:** TLP:CLEAR

---

## About This Report

This report is part of a hands-on project focused on building practical skills in cyber threat intelligence and honeypot analysis. It is one report in an ongoing series covering a 28-day T-Pot honeypot deployment on Google Cloud Platform during February 2026.

---

## Summary

Three patterns from this deployment align with broader reporting from early 2026. CVE-2018-13379, a Fortinet SSL VPN flaw patched in 2019, was still the highest-volume CVE in the dataset with 29,938 events. IoT botnet scanning for DVR and camera firmware flaws was daily and uninterrupted throughout February. CVE-2025-55182, disclosed two months before this deployment started, was active on every one of the 28 days.

---

## Findings

### Fortinet VPN Scanning

CVE-2018-13379 generated **29,938 events** across 28 days, the most of any CVE in this dataset. The CISA KEV remediation deadline passed in May 2022. Scanning continues because unpatched devices remain reachable.

The burst pattern here, zero activity on 13 days followed by **9,338 events** on 2026/02/15 and **7,684** on 2026/02/21, points to automated scanning campaigns activating periodically.

New Fortinet disclosures are being weaponized faster than older ones were. CVE-2025-59718 and CVE-2025-59719, two authentication bypass flaws disclosed on 2025/12/09, were confirmed under active exploitation by December 12 and added to the CISA KEV catalog on December 16. CVE-2026-24858, a FortiCloud SSO zero-day affecting FortiAnalyzer, FortiManager, FortiOS, and FortiProxy, was observed under active exploitation before public disclosure in January 2026.

**Defender note:** Patch or decommission any FortiOS or FortiProxy instance with SSL VPN exposed to the internet. Monitor Fortinet PSIRT advisories on a short cycle. Shodan and Shadowserver both surface internet-exposed Fortinet instances by version.

---

### IoT Botnet Activity

CVE-2024-14007, an authentication bypass in TVT NVMS-9000 DVR and NVR firmware, was active all 28 days with **1,878 total events** and a daily average of 67. GreyNoise linked exploitation of this CVE to ELEVEN11bot, a Mirai variant. Nokia Deepfield observed approximately 30,000 devices involved in active DDoS operations at the botnet's peak.

CVE-2024-3721, a command injection in TBK DVR devices, also appeared daily in this dataset. Kaspersky confirmed active exploitation of CVE-2024-3721 in their honeypot data in mid-2025, attributing it to a Mirai variant targeting internet-connected CCTV DVRs.

The RondoDox botnet, first observed in spring 2025, expanded by October 2025 to target nearly 60 vulnerabilities across routers, DVRs, NVRs, and web servers in a single pass, while deploying Mirai and Morte IoT malware as secondary payloads. CVE-2025-34036, another TVT command injection flaw, appeared in this dataset's daily logs before February ended.

**Defender note:** Update firmware on any TVT-based or white-labeled DVR or NVR to versions addressing CVE-2024-14007 and CVE-2024-3721. Restrict management ports from internet exposure. Default credentials on surveillance hardware are a reliable botnet entry point regardless of patch status.

---

### Web Framework Exploitation

CVE-2025-55182, a remote code execution flaw in React Server Components, was disclosed on 2025/12/03. It was active every day of this deployment with **1,527 total events**. China-nexus threat groups deployed cryptocurrency miners and Cobalt Strike beacons within hours of that December disclosure. Researchers estimated approximately 90,300 exposed vulnerable Next.js instances globally, with the majority in the US.

Vite (CVE-2025-30208, **318 events**) and PHP-CGI (CVE-2024-4577, **162 events**) followed similar patterns in this dataset. According to the Verizon DBIR 2025, known vulnerability exploitation accounts for 20% of all breaches, a 34% year-over-year increase, and served as the initial access vector in 32% of ransomware incidents.

**Defender note:** Treat web framework and open-source dependency patches with the same urgency as OS and network device patches. For CVE-2025-55182, update react-server-dom-webpack, react-server-dom-parcel, and react-server-dom-turbopack, and patch Next.js if running the App Router on any affected minor version.

---

## Methodology Notes

Event counts are Suricata IDS signature matches against inbound traffic. Counts represent scanning and exploitation attempt volume only.

External statistics (botnet device counts, breach percentages, exposure figures) come from the referenced sources.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in `/data/`.*

---

## References

| Source | URL |
|--------|-----|
| NVD: CVE-2018-13379 | https://nvd.nist.gov/vuln/detail/CVE-2018-13379 |
| CISA KEV Catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Shadowserver: Unpatched Fortinet Devices (Jan 2026) | https://thehackernews.com/2025/12/fortinet-warns-of-active-exploitation.html |
| CISA: CVE-2025-59718 Advisory | https://www.cisa.gov/news-events/alerts/2025/12/16/cisa-adds-one-known-exploited-vulnerability-catalog |
| Rapid7: CVE-2025-59718 and CVE-2025-59719 ETR | https://www.rapid7.com/blog/post/etr-critical-vulnerabilities-in-fortinet-cve-2025-59718-cve-2025-59719-exploited-in-the-wild/ |
| CISA: CVE-2026-24858 Fortinet SSO Advisory | https://www.cisa.gov/news-events/alerts/2026/01/28/fortinet-releases-guidance-address-ongoing-exploitation-authentication-bypass-vulnerability-cve-2026 |
| GreyNoise: TVT DVR Exploitation Surge | https://www.greynoise.io/blog/surge-exploitation-attempts-tvt-dvrs |
| Cybersecurity Dive: Eleven11bot Revised Estimates | https://www.cybersecuritydive.com/news/eleven11bot-revised-downward-mirai/741923/ |
| Kaspersky Securelist: Mirai Variant Targets DVR via CVE-2024-3721 | https://securelist.com/mirai-botnet-variant-targets-dvr-devices-with-cve-2024-3721/116742/ |
| Dark Reading: RondoDox Botnet React2Shell Exploitation | https://www.darkreading.com/vulnerabilities-threats/rondodox-botnet-scope-react2shell-exploitation |
| React Official Advisory: CVE-2025-55182 | https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components |
| Verizon DBIR 2025 | https://www.verizon.com/business/resources/reports/dbir/ |
| NVD: CVE-2024-14007 | https://nvd.nist.gov/vuln/detail/CVE-2024-14007 |
| NVD: CVE-2025-55182 | https://nvd.nist.gov/vuln/detail/CVE-2025-55182 |
| NVD: CVE-2025-30208 | https://nvd.nist.gov/vuln/detail/CVE-2025-30208 |
