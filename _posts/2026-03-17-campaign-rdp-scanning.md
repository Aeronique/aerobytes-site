---
layout: writeup
title: "Campaign Report: RDP Scanning and Authentication Bypass Attempts"
date: 2026-03-17
category: research
tags: ["honeypot", "threat-intelligence", "T-Pot", "GCP", "RDP", "scanning", "Remote-Desktop", "authentication-bypass", "port-3389", "brute-force", "ransomware", "Windows", "campaign-analysis", "mass-scanning", "28-days-exposed"]
permalink: /writeups/honeypot-threat-research/03d
excerpt: "321,116 RDP-related events in February 2026, with over 60% occurring in a single day on 2026/02/17."
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

Two Suricata signatures tracked RDP activity across the deployment. One flagged RDP traffic hitting non-standard ports, the other flagged authentication bypass patterns. Together they produced **321,116 events**. For most of February the numbers were low and unremarkable. Then 2026/02/17 happened, and both signatures lit up with **195,111 events in a single day**, more than 60% of the month's total.

---

## Background

RDP (Remote Desktop Protocol) is how Windows machines allow remote access. Port 3389 is the default. A successful login over RDP gives an attacker a live session on the machine, which is why it gets scanned so aggressively.

The non-standard port signature fires when RDP traffic shows up on ports other than 3389, which can mean scanners are looking for services running on unexpected ports. The auth bypass signature fires when a connection attempt looks like it is testing login behaviour rather than actually trying to log in.

RDP has been a consistent target for years. GreyNoise documented a 30,000+ IP scanning wave in August 2025, then a separate 100,000+ IP botnet campaign in October 2025 focused on US RDP endpoints. By February 2026 this was already well-established territory for attackers.

---

## Findings

### Daily Background Activity

Most days saw between **601 and 8,755 combined events**. That low, persistent scanning never stopped across the full 28 days. Any exposed RDP service on the internet gets this kind of attention constantly, so it is not surprising to see it here.

### The 2026/02/17 Spike

Then there was 2026/02/17. The non-standard port signature fired **134,200 times**, the auth bypass signature fired **60,911 times**, and the day totalled **195,111 events**. The day before was 2,043. The day after was 36,190, still elevated, and then it was back to normal by 2026/02/19.

This all points to a deliberate scan run.

---

## Analysis

The baseline scanning is consistent with what has been documented as ongoing mass internet scanning for RDP.

The 2026/02/17 spike is harder to explain from this dataset alone. The scale and the quick drop suggest infrastructure that was switched on for a run and then went quiet. The auth bypass signature accounting for 60,911 of those events is worth noting. Those are not open port checks. They are probes testing how the login process responds, which lines up with the timing attacks and login enumeration techniques GreyNoise documented in 2025.

Whether the February spike connects to those earlier campaigns is speculative. The pattern fits, but this honeypot alone cannot confirm attribution.

---

## Defender Notes

Do not expose RDP directly to the internet and put it behind a VPN or RD Gateway. Enable Network Level Authentication, which requires a valid login before a full session is established. Restrict access by IP where possible.

---

## Data Reference

### Table 1: Monthly Summary

| Metric | Value |
|--------|-------|
| Total events | 321,116 |
| Non-standard port signature | 242,279 |
| Auth bypass signature | 78,837 |
| Peak day | 2026/02/17 (195,111 events) |
| Peak share of monthly total | 60.8% |

### Table 2: Daily Event Counts

| Date | Non-standard Port | Auth Bypass | Total |
|------|-------------------|-------------|-------|
| 2026/02/01 | 3,717 | 1,691 | 5,408 |
| 2026/02/02 | 6,034 | 2,721 | 8,755 |
| 2026/02/03 | 3,659 | 1,649 | 5,308 |
| 2026/02/04 | 3,309 | 1,461 | 4,770 |
| 2026/02/05 | 1,541 | 504 | 2,045 |
| 2026/02/06 | 1,155 | 0 | 1,155 |
| 2026/02/07 | 1,968 | 773 | 2,741 |
| 2026/02/08 | 1,365 | 329 | 1,694 |
| 2026/02/09 | 1,252 | 328 | 1,580 |
| 2026/02/10 | 1,305 | 279 | 1,584 |
| 2026/02/11 | 1,186 | 0 | 1,186 |
| 2026/02/12 | 2,138 | 824 | 2,962 |
| 2026/02/13 | 601 | 0 | 601 |
| 2026/02/14 | 1,316 | 457 | 1,773 |
| 2026/02/15 | 2,105 | 830 | 2,935 |
| 2026/02/16 | 1,513 | 530 | 2,043 |
| **2026/02/17** | **134,200** | **60,911** | **195,111** |
| 2026/02/18 | 35,619 | 571 | 36,190 |
| 2026/02/19 | 3,255 | 1,069 | 4,324 |
| 2026/02/20 | 3,101 | 926 | 4,027 |
| 2026/02/21 | 2,321 | 280 | 2,601 |
| 2026/02/22 | 3,077 | 723 | 3,800 |
| 2026/02/23 | 1,601 | 364 | 1,965 |
| 2026/02/24 | 1,647 | 315 | 1,962 |
| 2026/02/25 | 3,159 | 813 | 3,972 |
| 2026/02/26 | 3,006 | 220 | 3,226 |
| 2026/02/27 | 7,921 | 269 | 8,190 |
| 2026/02/28 | 9,208 | 0 | 9,208 |

---

## Methodology Notes

**Event counts reflect IDS alerts, not confirmed exploitation.** The honeypot does not run a real Windows RDP service. These are inbound traffic pattern matches only.

**Auth bypass zero days:** On six days the auth bypass signature recorded zero events while the non-standard port signature remained active. This likely reflects traffic that matched the port scan pattern but not the bypass pattern.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in [honeypot-threat-research/data](https://github.com/Aeronique/honeypot-threat-research/tree/main/data).*

---

## References

| Source | URL |
|--------|-----|
| GreyNoise: Malicious IPs Probe Microsoft RDP | https://www.greynoise.io/blog/surge-malicious-ips-probe-microsoft-remote-desktop |
| Dark Reading: Malicious Scanning Waves Slam RDP | https://www.darkreading.com/cyber-risk/malicious-scanning-remote-desktop-services |
