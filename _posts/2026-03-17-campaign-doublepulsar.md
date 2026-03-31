---
layout: writeup
title: "Campaign Report: DoublePulsar Backdoor Communication"
date: 2026-03-17
category: research
tags: ["honeypot", "threat-intelligence", "T-Pot", "GCP", "DoublePulsar", "EternalBlue", "SMB", "legacy", "CVE-2017-0144", "MS17-010", "NSA-tools", "Shadow-Brokers", "WannaCry", "NotPetya", "Windows", "implant", "campaign-analysis", "28-days-exposed"]
permalink: /writeups/honeypot-threat-research/03e
excerpt: "13,522 events flagging DoublePulsar backdoor communication across February 2026, nearly a decade after the NSA implant was leaked."
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

One Suricata signature flagged DoublePulsar backdoor communication across February 2026, producing **13,522 events** across 14 of 28 days, with long silent gaps between active bursts. DoublePulsar is an NSA-developed implant that was leaked in 2017 and has been circulating ever since. Nearly a decade later, something is still actively scanning for it.

---

## Background

In April 2017, a group called the Shadow Brokers leaked a collection of NSA hacking tools. Two stood out: EternalBlue, which exploits a flaw in Windows file sharing (SMBv1), and DoublePulsar, the backdoor implant EternalBlue installs. Microsoft had patched the underlying flaw (CVE-2017-0144) a month earlier, but millions of systems went unpatched. DoublePulsar hides in kernel memory, listens on port 445, and accepts commands without requiring any authentication.

WannaCry and NotPetya, both of which caused billions in damage, used EternalBlue to spread. Threat intelligence from 2024 and early 2025 confirms these tools are still being used in campaigns targeting unpatched Windows systems, particularly in Southeast Asia and Eastern Europe.

---

## Findings

DoublePulsar activity showed up on **14 of 28 days**, with the other 14 recording nothing. The busiest day was **2026/02/16 with 2,677 events**, and three other days crossed 1,000. The bursts and gaps closely mirror the pattern seen with CVE-2018-13379 in this dataset, which suggests automated scan runs rather than someone actively watching the results.

The Suricata signature here fires specifically on traffic matching a known DoublePulsar handshake over SMB. Scanners using this technique are checking whether a host will respond the way an already-infected machine would, which would let them access it without running EternalBlue at all.

---

## Analysis

CVE-2017-0144 has had a patch since March 2017 and has been in the CISA KEV catalog for years. The fact that scanners are still probing for DoublePulsar in 2026 reflects how many legacy Windows systems remain reachable and unpatched on the internet.

The 14 silent days suggest the scanning infrastructure cycles through target lists and this IP was simply not in scope on those days.

---

## Defender Notes

Apply MS17-010, disable SMBv1, and block port 445 at the perimeter unless there is a clear need for it. If you manage older Windows systems, patching the vulnerability does not remove an implant that is already installed. Memory analysis tools like Volatility can scan for DoublePulsar if an infection is suspected.

---

## Data Reference

### Table 1: Monthly Summary

| Metric | Value |
|--------|-------|
| Total events | 13,522 |
| Active days | 14 of 28 |
| Silent days | 14 of 28 |
| Peak day | 2026/02/16 (2,677 events) |

### Table 2: Daily Event Counts

| Date | Events |
|------|--------|
| 2026/02/01 | 554 |
| 2026/02/02 | 0 |
| 2026/02/03 | 0 |
| 2026/02/04 | 0 |
| 2026/02/05 | 1,308 |
| 2026/02/06 | 2,048 |
| 2026/02/07 | 0 |
| 2026/02/08 | 682 |
| 2026/02/09 | 1,402 |
| 2026/02/10 | 936 |
| 2026/02/11 | 0 |
| 2026/02/12 | 0 |
| 2026/02/13 | 0 |
| 2026/02/14 | 0 |
| 2026/02/15 | 0 |
| 2026/02/16 | 2,677 |
| 2026/02/17 | 0 |
| 2026/02/18 | 1,375 |
| 2026/02/19 | 0 |
| 2026/02/20 | 0 |
| 2026/02/21 | 1,152 |
| 2026/02/22 | 0 |
| 2026/02/23 | 0 |
| 2026/02/24 | 0 |
| 2026/02/25 | 0 |
| 2026/02/26 | 0 |
| 2026/02/27 | 0 |
| 2026/02/28 | 1,388 |

---

## Methodology Notes

**Event counts reflect IDS alerts, not confirmed exploitation.** The honeypot does not run a real Windows SMB service. These are inbound traffic pattern matches only.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in [honeypot-threat-research/data](https://github.com/Aeronique/honeypot-threat-research/tree/main/data).*

---

## References

| Source | URL |
|--------|-----|
| NVD: CVE-2017-0144 (EternalBlue / MS17-010) | https://nvd.nist.gov/vuln/detail/CVE-2017-0144 |
| CISA KEV: CVE-2017-0144 | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Rapid7: DoublePulsar Implant Analysis | https://www.rapid7.com/blog/post/2019/10/02/open-source-command-and-control-of-the-doublepulsar-implant/ |
| Hunter Strategy: EternalBlue Persistent Threat | https://blog.hunterstrategy.net/eternalblue-the-persistent-threat-of-a-leaked-nsa-exploit/ |
