---
layout: writeup
title: "Campaign Report: Fortinet FortiOS SSL VPN Scanning"
date: 2026-03-14
category: research
tags: ["honeypot", "threat-intelligence", "T-Pot", "FortiOS", "CVE-2018-13379", "GCP", "Fortinet", "SSL-VPN", "path-traversal", "CISA-KEV", "campaign-analysis", "burst-scanning", "credential-theft", "Metasploit", "28-days-exposed"]
permalink: /writeups/honeypot-threat-research/03a
excerpt: "Analysis of 29,938 scanning events targeting CVE-2018-13379 across a 28-day T-Pot honeypot deployment on Google Cloud Platform."
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

Scanning activity targeting CVE-2018-13379, a path traversal flaw in Fortinet's FortiOS SSL VPN, produced **29,938 events** during the deployment. It was the most scanned CVE in the dataset by a wide margin. The activity did not run continuously. It came in short, high-volume bursts with long quiet periods in between, which points to automated scanning running in waves rather than one persistent actor probing the same target.

---

## Background

CVE-2018-13379 was disclosed in 2019. It affects the SSL VPN web portal in several older versions of FortiOS and FortiProxy. An attacker with no credentials can send a specially crafted HTTP request to read files off the server. The file most commonly targeted is `sslvpn_websession`, which stores active VPN session data including usernames and passwords in cleartext.

Fortinet released patches in 2019. CISA added this to their Known Exploited Vulnerabilities catalog in November 2021. The remediation deadline for federal agencies passed in May 2022.

Public exploit code has existed since shortly after the initial disclosure. A Metasploit module is also available. That means this vulnerability is accessible to a wide range of attackers, not just experienced ones.

---

## Findings

### Emergence

No CVE-2018-13379 activity appeared on 2026/02/01 or 2026/02/02. The first events hit on 2026/02/03 with **1,271 events**, followed by **1,316** on 2026/02/04 and **2,483** on 2026/02/05. Then it dropped off again and went silent on 2026/02/08.

### Targeting

Scanning for this CVE typically involves sending GET requests to a path like `/remote/fgt_lang` with traversal characters added to point to the `sslvpn_websession` file. The honeypot logged these as Suricata IDS signature matches. Because the honeypot is not an actual FortiOS device, nothing could be extracted from it. These are reconnaissance attempts.

### Peak Activity

Two days produced more than half of the month's total events. On **2026/02/15** there were **9,338 events**, which is 31.2% of the monthly total. On **2026/02/21** there were **7,684 events**, another 25.7%. Both of those days came after long quiet periods, which suggests something was actively launched rather than running in the background the whole time.

### Withdrawal

The last active stretch was lighter. The honeypot recorded **1,019 events** on 2026/02/27 and **534** on 2026/02/28. Eight of the 28 days recorded zero events.

---

## Analysis

The burst pattern is the most telling feature of this campaign. Long gaps followed by sudden spikes suggest automated scanning infrastructure that gets switched on for a run and then goes quiet again. This is different from the steady, uninterrupted daily probing we see with something like the TVT DVR botnet activity in this dataset.

CVE-2018-13379 was patched in 2019 and has had a CISA KEV listing since 2021. The reason it keeps showing up in scans is that unpatched Fortinet devices are still reachable on the internet. Scanning for them costs nothing, and when one responds correctly, the payoff is VPN credentials in cleartext.

This data only shows reconnaissance. Whether those scans are successfully reaching real FortiOS devices elsewhere is outside the scope of what a single honeypot can tell us.

---

## Defender Notes

The affected versions are FortiOS 5.4.6 through 5.4.12, 5.6.3 through 5.6.7, and 6.0.0 through 6.0.4, and FortiProxy 1.0.0 through 2.0.0. Any device still running these versions with SSL VPN enabled should be patched or taken offline.

If patching is not immediately possible, Fortinet's own advisory suggests disabling the SSL VPN service entirely as a temporary measure. Enabling two-factor authentication for SSL VPN users also reduces the impact of stolen credentials, though it does not fix the underlying flaw.

---

## Data Reference

### Table 1: Monthly Summary

| Metric | Value |
|--------|-------|
| Total events | 29,938 |
| Active days | 15 of 28 |
| Silent days | 13 of 28 |
| Peak day | 2026/02/15 (9,338 events) |
| Second peak | 2026/02/21 (7,684 events) |
| Combined peak share | 56.9% of monthly total |

### Table 2: Daily Event Counts

| Date | Events |
|------|--------|
| 2026/02/01 | 0 |
| 2026/02/02 | 0 |
| 2026/02/03 | 1,271 |
| 2026/02/04 | 1,316 |
| 2026/02/05 | 2,483 |
| 2026/02/06 | 1,384 |
| 2026/02/07 | 941 |
| 2026/02/08 | 0 |
| 2026/02/09 | 0 |
| 2026/02/10 | 0 |
| 2026/02/11 | 1,638 |
| 2026/02/12 | 1,167 |
| 2026/02/13 | 0 |
| 2026/02/14 | 356 |
| 2026/02/15 | 9,338 |
| 2026/02/16 | 0 |
| 2026/02/17 | 807 |
| 2026/02/18 | 0 |
| 2026/02/19 | 0 |
| 2026/02/20 | 0 |
| 2026/02/21 | 7,684 |
| 2026/02/22 | 0 |
| 2026/02/23 | 0 |
| 2026/02/24 | 0 |
| 2026/02/25 | 0 |
| 2026/02/26 | 0 |
| 2026/02/27 | 1,019 |
| 2026/02/28 | 534 |

### Table 3: Vulnerability Scoring

| Metric | Value | Source |
|--------|-------|--------|
| CVSS v3.1 | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | NVD |
| CVSS v3 (alt) | 9.1 | Shodan CVEDB |
| CVSS v3 (vendor) | 8.9 | Fortinet PSIRT FG-IR-18-384 |
| EPSS | 94.47% (top 100th percentile) | Shodan CVEDB |
| CISA KEV | Yes, added 2021/11/03 | CISA KEV Catalog |
| Ransomware association | Known | Shodan CVEDB |

---

## Methodology Notes

**Event counts reflect IDS alerts, not confirmed exploitation.** Suricata fired two signatures for CVE-2018-13379 with identical per-day counts, meaning both rules matched the same traffic. This report uses one signature's count (29,938). The combined total across both signatures is 59,876.

**CVSS score discrepancy:** NVD publishes 9.8. Shodan CVEDB returns 9.1. Fortinet's own PSIRT advisory lists 8.9. All three scores are included in Table 3. Differences between vendor, NVD, and third-party scores are common. The NVD score is used as the primary reference throughout this report.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in [honeypot-threat-research/data](https://github.com/Aeronique/honeypot-threat-research/tree/main/data).*

---

## References

| Source | URL |
|--------|-----|
| NVD: CVE-2018-13379 | https://nvd.nist.gov/vuln/detail/CVE-2018-13379 |
| Fortinet PSIRT Advisory FG-IR-18-384 | https://www.fortiguard.com/psirt/FG-IR-18-384 |
| Fortinet Blog: FortiOS SSL Vulnerability (2019) | https://www.fortinet.com/blog/psirt-blogs/fortios-ssl-vulnerability |
| CISA Known Exploited Vulnerabilities Catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| CISA Advisory AA21-209A: Top Routinely Exploited Vulnerabilities | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-209a |
| AttackerKB: CVE-2018-13379 | https://attackerkb.com/topics/VEc81wfDS7/cve-2018-13379-path-traversal-in-fortinet-fortios |
| Shodan CVEDB: CVE-2018-13379 | https://cvedb.shodan.io/dashboard/cve/CVE-2018-13379 |
