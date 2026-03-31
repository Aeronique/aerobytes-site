---
layout: writeup
title: "Campaign Report: ELEVEN11 Botnet and TVT DVR Probing"
date: 2026-03-15
category: research
tags: ["honeypot", "threat-intelligence", "CVE", "T-Pot", "GCP", "botnet", "IoT", "Mirai", "CVE-2024-14007", "TVT-NVMS", "ELEVEN11", "DVR", "NVR", "authentication-bypass", "DDoS", "campaign-analysis", "GreyNoise", "28-days-exposed"]
permalink: /writeups/honeypot-threat-research/03b
excerpt: "28 days of flat, uninterrupted scanning tied to the ELEVEN11 botnet targeting TVT NVMS-9000 DVRs via CVE-2024-14007."
back_url: /honeypot-threat-research/
back_label: Back to 28 Days Exposed
---

**Deployment Period:** 2026/02/01 to 2026/02/28

**Honeypot:** T-Pot Community Edition, Google Cloud Platform

**Data Source:** Elasticsearch DSL queries, Kibana Dev Tools

**TLP:** TLP:CLEAR

---

## About This Report

This report is part of a hands-on project focused on building practical skills in threat data analysis and CVE research. It is one report in an ongoing series covering the February 2026 T-Pot deployment.

---

## Summary

CVE-2024-14007 is an authentication bypass in TVT NVMS-9000 DVR firmware. It produced **1,878 events** across all 28 days of the deployment, averaging **67 events per day** with no spikes and no silent days. That unbroken pattern points to botnet infrastructure, and not manual scanning. External reporting ties this activity to ELEVEN11, a Mirai-based botnet that has been actively targeting TVT devices.

---

## Background

The NVMS-9000 is a DVR firmware platform made by Shenzhen TVT Digital Technology. The same firmware ships inside many rebranded security recorders sold under different brand names, so the actual number of affected devices is difficult to pin down.

The flaw was first disclosed in May 2024 by SSD Secure Disclosure. An attacker sends a single TCP payload to an open control port. No login is needed. A vulnerable device responds with admin credentials and network details in cleartext. The CVE was formally assigned in November 2025.

Mirai is malware that targets internet-connected devices, recruits them into a botnet, and uses them for attacks like large-scale DDoS. ELEVEN11 is a Mirai variant specifically linked to TVT DVR targeting.

---

## Findings

### Emergence

Activity started on 2026/02/01 and ran every day without interruption. There was no build-up period. The probing was present from the first day of the deployment to the last.

### Targeting

The scanner sends a TCP payload to the device's control port (commonly 6036, 17000, 17001, or 8000) and requests the `queryBasicCfg` command. On a real vulnerable device, that returns admin credentials and hardware information in cleartext. The honeypot is not a real NVMS-9000, so nothing was returned. These are probing attempts.

### Activity Pattern

Daily counts ranged from **38** (2026/02/14) to **174** (2026/02/07). No silent days. No spikes. The consistency across the full 28 days is the defining feature of this campaign.

### Broader Context

GreyNoise, tracking the same activity across many IPs, logged over **6,600 distinct malicious IPs** targeting this flaw in a 30-day window around the same period. Their peak was **2,500 unique IPs in a single day**. Most source IPs came from Taiwan, Japan, and South Korea. Primary targets were in the US, UK, and Germany.

---

## Analysis

The flat daily pattern here is consistent with botnet infrastructure running on its own. That contrasts sharply with the burst-and-silence pattern of CVE-2018-13379 (FortiOS) activity in this same dataset.

ELEVEN11 reportedly compromised around 400,000 devices globally and was connected to a DDoS attack against a major social media platform. The TVT firmware is an desirable target because it appears in so many rebranded products. An owner running a device under a different brand name may not realise it is running vulnerable NVMS-9000 firmware.

---

## Defender Notes

Update NVMS-9000 firmware to version 1.3.4 or later. If you manage rebranded DVR or NVR equipment, verify whether it uses TVT firmware.

Do not expose the control port to the internet. Restrict access by IP or put the device behind a VPN.

---

## Data Reference

### Table 1: Monthly Summary

| Metric | Value |
|--------|-------|
| Total events | 1,878 |
| Active days | 28 of 28 |
| Silent days | 0 |
| Daily average | 67 events |
| Lowest day | 2026/02/14 (38 events) |
| Peak day | 2026/02/07 (174 events) |

### Table 2: Daily Event Counts

| Date | Events |
|------|--------|
| 2026/02/01 | 77 |
| 2026/02/02 | 74 |
| 2026/02/03 | 56 |
| 2026/02/04 | 42 |
| 2026/02/05 | 102 |
| 2026/02/06 | 62 |
| 2026/02/07 | 174 |
| 2026/02/08 | 75 |
| 2026/02/09 | 69 |
| 2026/02/10 | 49 |
| 2026/02/11 | 47 |
| 2026/02/12 | 51 |
| 2026/02/13 | 43 |
| 2026/02/14 | 38 |
| 2026/02/15 | 53 |
| 2026/02/16 | 50 |
| 2026/02/17 | 51 |
| 2026/02/18 | 48 |
| 2026/02/19 | 68 |
| 2026/02/20 | 68 |
| 2026/02/21 | 77 |
| 2026/02/22 | 74 |
| 2026/02/23 | 79 |
| 2026/02/24 | 80 |
| 2026/02/25 | 74 |
| 2026/02/26 | 82 |
| 2026/02/27 | 64 |
| 2026/02/28 | 51 |

### Table 3: Vulnerability Scoring

| Metric | Value | Source |
|--------|-------|--------|
| CVSS v3 | Not published | NVD (analysis pending) |
| CVSS v4.0 | 8.7 (AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N) | VulnCheck |
| EPSS | 0.07% (top 20.3rd percentile) | Shodan CVEDB |
| CISA KEV | No | CISA |
| VulnCheck KEV | Yes | VulnCheck |
| Ransomware association | None confirmed | Shodan CVEDB |

---

## Methodology Notes

**Event counts reflect IDS alerts, not confirmed exploitation.** The honeypot is not a real NVMS-9000 device. Counts represent inbound probing attempts only.

**EPSS score:** The 0.07% score reflects how recently this CVE was added to NVD, not how actively it is being targeted. VulnCheck KEV is a more reliable signal for this CVE at this point in time.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in [honeypot-threat-research/data](https://github.com/Aeronique/honeypot-threat-research/tree/main/data).*

---

## References

| Source | URL |
|--------|-----|
| NVD: CVE-2024-14007 | https://nvd.nist.gov/vuln/detail/CVE-2024-14007 |
| SSD Advisory: NVMS9000 Information Disclosure | https://ssd-disclosure.com/ssd-advisory-nvms9000-information-disclosure/ |
| GreyNoise: Surge in TVT DVR Exploitation | https://www.greynoise.io/blog/surge-exploitation-attempts-tvt-dvrs |
| BleepingComputer: New Mirai Botnet Behind TVT DVR Surge | https://www.bleepingcomputer.com/news/security/new-mirai-botnet-behind-surge-in-tvt-dvr-exploitation/ |
| VulnCheck Advisory: CVE-2024-14007 | https://www.vulncheck.com/advisories/tvt-nvms9000-unauthenticated-admin-queries-and-information-disclosure |
| Shodan CVEDB: CVE-2024-14007 | https://cvedb.shodan.io/dashboard/cve/CVE-2024-14007 |
