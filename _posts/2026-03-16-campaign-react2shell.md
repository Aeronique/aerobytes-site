---
layout: writeup
title: "Campaign Report: React Server Components RCE Scanning (CVE-2025-55182)"
date: 2026-03-16
category: THREAT INTELLIGENCE
tags: ["honeypot", "threat-intelligence", "CVE", "T-Pot", "GCP", "React", "RCE", "web"]
permalink: /writeups/honeypot-threat-research/03c
excerpt: "28 days of declining RCE scanning targeting CVE-2025-55182, a critical flaw in React Server Components disclosed two months before this deployment."
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

CVE-2025-55182 is a remote code execution flaw in React Server Components, disclosed on 2025/12/03. It produced **1,527 events** across all 28 days of the deployment. Activity was highest in the first two weeks and steadily declined through the end of February, ending at just **8 events** on 2026/02/28. That pattern fits with opportunistic scanning that followed a high-profile public disclosure and slowed as patches were applied.

---

## Background

CVE-2025-55182, nicknamed React2Shell, is a remote code execution flaw in React Server Components. An attacker sends a single HTTP POST request with no credentials and the server runs their code. Default configurations are affected. It was disclosed on 2025/12/03 with patches available the same day. CISA added it to their Known Exploited Vulnerabilities catalog two days later on 2025/12/05.

A second CVE, CVE-2025-66478, was initially assigned for the same flaw as it appears in Next.js but was rejected as a duplicate. Both IDs point to the same issue.

---

## Findings

### Emergence and Peak

Activity was present from day one. The vulnerability was already two months old by 2026/02/01. The first week averaged around **58 events per day**. The highest single day was **2026/02/07 with 140 events**, with a second rise to 103 on 2026/02/19.

### Decline

The second half of the month was quieter. The final week averaged **26 events per day** and the last day recorded just **8 events**. The downward trend suggests patch uptake reduced the number of reachable targets, though this honeypot alone cannot confirm that.

---

## Analysis

When this CVE was disclosed in December 2025, exploitation started within hours. Google Threat Intelligence Group documented multiple attacker clusters including cybercriminals and suspected espionage groups. Microsoft confirmed exploitation by 2025/12/05. Post-exploitation payloads in the wild included cryptocurrency miners, Cobalt Strike, and backdoors including SNOWLIGHT and COMPOOD.

By February the wave had settled. The honeypot data shows the tail end of that activity declining as patches spread. These are Suricata IDS matches, not confirmed exploitation. The honeypot does not run React Server Components.

---

## Defender Notes

Patch to the fixed versions: react-server 19.0.1, 19.1.2, or 19.2.1. For Next.js, see the patch version for your release line on the React advisory page.

CVE-2025-66478 was rejected as a duplicate of CVE-2025-55182. If your detection tooling references either ID, it is flagging the same vulnerability.

---

## Data Reference

### Table 1: Monthly Summary

| Metric | Value |
|--------|-------|
| Total events | 1,527 |
| Active days | 28 of 28 |
| Peak day | 2026/02/07 (140 events) |
| First week average | ~58 events/day |
| Final week average | ~26 events/day |
| Last day | 2026/02/28 (8 events) |

### Table 2: Daily Event Counts

| Date | Events |
|------|--------|
| 2026/02/01 | 44 |
| 2026/02/02 | 45 |
| 2026/02/03 | 35 |
| 2026/02/04 | 41 |
| 2026/02/05 | 78 |
| 2026/02/06 | 105 |
| 2026/02/07 | 140 |
| 2026/02/08 | 81 |
| 2026/02/09 | 50 |
| 2026/02/10 | 38 |
| 2026/02/11 | 55 |
| 2026/02/12 | 85 |
| 2026/02/13 | 69 |
| 2026/02/14 | 53 |
| 2026/02/15 | 42 |
| 2026/02/16 | 61 |
| 2026/02/17 | 43 |
| 2026/02/18 | 70 |
| 2026/02/19 | 103 |
| 2026/02/20 | 40 |
| 2026/02/21 | 50 |
| 2026/02/22 | 40 |
| 2026/02/23 | 34 |
| 2026/02/24 | 30 |
| 2026/02/25 | 14 |
| 2026/02/26 | 47 |
| 2026/02/27 | 26 |
| 2026/02/28 | 8 |

### Table 3: Vulnerability Scoring

| Metric | Value | Source |
|--------|-------|--------|
| CVSS v3 | 10.0 | CNA (Meta); NVD assessment pending |
| EPSS | 59.56% (top 98.2nd percentile) | Shodan CVEDB |
| CISA KEV | Yes, added 2025/12/05 | CISA |
| Ransomware association | Known | Shodan CVEDB |

---

## Methodology Notes

**Event counts reflect IDS alerts, not confirmed exploitation.** The honeypot does not run React Server Components. These are inbound probing attempts only.

**CVSS sourcing:** NVD had not completed its analysis at the time of this deployment. The score of 10.0 comes from the CNA, which is Meta. This is standard practice when NVD analysis is pending.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in [honeypot-threat-research/data](https://github.com/Aeronique/honeypot-threat-research/tree/main/data).*

---

## References

| Source | URL |
|--------|-----|
| NVD: CVE-2025-55182 | https://nvd.nist.gov/vuln/detail/CVE-2025-55182 |
| React Official Advisory | https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components |
| CISA KEV Catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Google Threat Intelligence: React2Shell Exploitation | https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182 |
| Microsoft Security: CVE-2025-55182 Defense | https://www.microsoft.com/en-us/security/blog/2025/12/15/defending-against-the-cve-2025-55182-react2shell-vulnerability-in-react-server-components/ |
| AWS Security Bulletin: CVE-2025-55182 | https://aws.amazon.com/security/security-bulletins/AWS-2025-030/ |
| Wiz: React2Shell Analysis | https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182 |
| Rapid7 ETR: CVE-2025-55182 | https://www.rapid7.com/blog/post/etr-react2shell-cve-2025-55182-critical-unauthenticated-rce-affecting-react-server-components/ |
| Unit 42: CVE-2025-55182 Exploitation | https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/ |
| Shodan CVEDB: CVE-2025-55182 | https://cvedb.shodan.io/dashboard/cve/CVE-2025-55182 |
