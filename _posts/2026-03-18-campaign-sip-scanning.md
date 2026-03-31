---
layout: writeup
title: "Campaign Report: SIP Scanning with sipsak"
date: 2026-03-18
category: research
tags: ["honeypot", "threat-intelligence", "T-Pot", "GCP", "SIP", "VoIP", "scanning", "sipsak", "toll-fraud", "port-5060", "campaign-analysis", "28-days-exposed"]
permalink: /writeups/honeypot-threat-research/03f
excerpt: "6,213 SIP scan events across just 3 days in February 2026, with 73.5% occurring on a single day."
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

One Suricata signature flagged sipsak SIP scanning across February 2026, producing **6,213 events** on just **3 of 28 days**. The other 25 days recorded nothing. On **2026/02/21 alone, 4,568 events fired**, which is 73.5% of the month's total. SIP scanning stands out as the only VoIP-related activity in this dataset and points to a different goal than the server and device scanning seen elsewhere.

---

## Background

SIP (Session Initiation Protocol) handles call setup and signalling in most internet-based phone systems. Attackers scan for exposed SIP services because a misconfigured or unauthenticated server can be abused to place calls at the victim's expense, a type of fraud known as toll fraud. Extension numbers and passwords can also be brute-forced once a server is found.

`sipsak` is an open-source SIP testing tool used legitimately by VoIP engineers to check whether a SIP server is responding. It works by sending an OPTIONS request to a target, which is the SIP equivalent of a ping. The Suricata signature here fires when inbound traffic matches that known `sipsak` request pattern.

---

## Findings

Activity appeared on three days spread across the month. The first two, 2026/02/07 with 1,187 events and 2026/02/09 with 458, were moderate. Then on 2026/02/21 the signature fired 4,568 times in a single day before going completely silent for the rest of the month.

The extreme concentration into three isolated days, with long gaps between them, points to automated scan runs cycling through IP ranges rather than interest in this host.

---

## Analysis

SIP scanning is mostly financially motivated. Attackers look for servers they can use to route calls to premium-rate numbers, running up charges that the server owner ends up paying. Honeypot research has shown that SIP services get discovered quickly after going online and attract both credential guessing and unauthenticated call attempts.

The 2026/02/21 spike, nearly four times larger than the other two active days combined, suggests a bigger scan run than the earlier two. It is unclear whether the scanning originated from the same source.

---

## Defender Notes

Keep SIP services off the public internet wherever possible. Require authentication on all extensions, use strong credentials, and monitor for unexpected OPTIONS requests. Rate limiting or IP-based access controls on port 5060 will stop most automated scanning.

---

## Data Reference

### Table 1: Monthly Summary

| Metric | Value |
|--------|-------|
| Total events | 6,213 |
| Active days | 3 of 28 |
| Silent days | 25 of 28 |
| Peak day | 2026/02/21 (4,568 events) |
| Peak share of monthly total | 73.5% |

### Table 2: Active Day Counts

| Date | Events |
|------|--------|
| 2026/02/07 | 1,187 |
| 2026/02/09 | 458 |
| 2026/02/21 | 4,568 |

---

## Methodology Notes

**Event counts reflect IDS alerts, not confirmed exploitation.** The honeypot does not run a SIP service. These are inbound traffic pattern matches only.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in [honeypot-threat-research/data](https://github.com/Aeronique/honeypot-threat-research/tree/main/data).*

---

## References

| Source | URL |
|--------|-----|
| CellStream: SIP Testing with sipsak | https://www.cellstream.com/2025/06/24/sip-testing-and-troubleshooting-with-sipsak/ |
| Shuffling Bytes: SIP Honeypot Research | https://shufflingbytes.com/posts/sip-honeypot/ |
