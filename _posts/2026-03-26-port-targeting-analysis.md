---
layout: writeup
title: "Port Targeting Analysis"
date: 2026-03-26
category: THREAT INTELLIGENCE
tags: ["honeypot", "threat-intelligence", "T-Pot", "GCP", "ports", "scanning"]
permalink: /writeups/honeypot-threat-research/10
excerpt: "Three ports accounted for 88% of all inbound traffic across 28 days. HTTPS, VNC, and an alternate HTTPS port dominated, with a concentrated SNMP burst hitting 1.3 million events in just 48 hours before going completely silent."
back_url: /honeypot-threat-research/
back_label: Back to 28 Days Exposed
---

**Deployment Period:** 2026/02/01 to 2026/02/28

**Honeypot:** T-Pot Community Edition, Google Cloud Platform

**Data Source:** Elasticsearch DSL queries, Kibana Dev Tools

**TLP:** TLP:CLEAR

---

## About This Report

This report is part of a hands-on project focused on building practical skills in cyber threat intelligence. It is one report in an ongoing series covering a 28-day T-Pot honeypot deployment on Google Cloud Platform during February 2026. I'm open to constructive feedback.

---

## Summary

Three ports, 443 (HTTPS), 5900 (VNC), and 8443 (HTTPS alternate), accounted for **88%** of all inbound traffic over 28 days. Port 443 led overall at **29.3 million** events, but volume distribution shifted as the month progressed. VNC scanning peaked mid-month and dropped sharply in the final week. Port 8443 spiked heavily across days 4 through 15, then went nearly silent. A concentrated SNMP burst appeared on exactly two consecutive days and did not recur.

---

## Background

The T-Pot honeypot exposes simulated services on common ports. Elasticsearch logs each inbound connection's destination port. This report uses the `top_ports` aggregation from each daily query file to track activity across all 28 days.

Counts represent all inbound connections, including automated scans and probes. They do not represent confirmed exploitation events.

---

## Findings

### HTTPS (Ports 443 and 8443)

Port 443 received **29,321,017** events, **49.1%** of all traffic. Daily volume ranged from **87,419** (2026/02/15) to **2,911,839** (2026/02/05). The first ten days accounted for **16.7 million** events on this port; the final eight days produced **9.7 million**.

Port 8443 added **7,945,536** events. Together, the two HTTPS ports account for **62.4%** of all inbound traffic. Port 8443 was not steady. Six days each produced over 900,000 events while seven days produced fewer than 5,000. It went nearly silent after 2026/02/17.

### VNC (Port 5900 and Display Range)

Port 5900 received **15,273,533** events. Volume peaked during days 11 through 20 at **7.0 million**, compared to **6.2 million** in days 1 through 10 and **1.9 million** in the final eight days. The adjacent display ports 5901, 5902, 5903, 5910, and 5925 added roughly **682,000** combined events. Scanners probing VNC frequently step through multiple display numbers in sequence, which accounts for the spread.

### SSH (Port 22)

Port 22 received **2,127,074** events across all 28 days, averaging approximately **76,000 per day**. It appeared in the top ports list every day, making it the most consistent port in the dataset.

### SNMP (Port 161)

Port 161 produced **1,328,119** events, but all traffic arrived on two consecutive days: **312,927** on 2026/02/03 and **1,015,192** on 2026/02/04. Every remaining day recorded zero. SNMP is used to enumerate device configurations. A burst of this scale concentrated into 48 hours, followed by complete silence, is consistent with a targeted sweep rather than background scanning.

### SIP/VoIP (Port 5060)

Port 5060 totaled **630,716** events. Three days produced the majority: **171,772** on 2026/02/02, **190,998** on 2026/02/26, and **33,028** on 2026/02/19. Activity was near zero on all other days.

### SMB (Port 445)

Port 445 totaled **198,881** events. Most days recorded zero. Spikes above 25,000 appeared on 2026/02/05, 2026/02/20, and 2026/02/25.

---

## Analysis

The top three ports reflect what automated scanners prioritize: widely deployed services that are frequently misconfigured or unpatched. HTTPS on 443 and 8443 covers both general web traffic and management interfaces on network appliances. VNC on 5900 and nearby display ports targets remote desktop access.

The VNC decline in the final week and the port 8443 drop-off after 2026/02/17 suggest the scanning infrastructure behind those campaigns changed. One possible explanation is that source ASNs rotated or were blocked upstream. A single-node honeypot cannot confirm this.

The SNMP pulse stands out. Over 1.3 million hits on a port that was otherwise silent for 26 days points to a specific campaign. SNMP is a known reconnaissance vector for enumerating network device configurations before further targeting.

---

## Defender Notes

CISA BOD 23-02 explicitly covers SNMP, VNC, SSH, SMB, HTTP, and HTTPS as protocols that should not be internet-exposed on management interfaces. The traffic patterns here are consistent with active scanning against all of them.

Port 161 should not be reachable from the internet. Any SNMP traffic from external IPs warrants investigation.

Port 8443 hosting network appliance management interfaces saw significant scanning pressure during the first half of the deployment. It should receive the same review applied to port 443.

---

## Data Reference

### Top 15 Ports by Total Events (2026/02/01 to 2026/02/28)

| Port | Service | Total Events | % of Traffic |
|------|---------|-------------|-------------|
| 443 | HTTPS | 29,321,017 | 49.1% |
| 5900 | VNC | 15,273,533 | 25.6% |
| 8443 | HTTPS (alternate) | 7,945,536 | 13.3% |
| 22 | SSH | 2,127,074 | 3.6% |
| 161 | SNMP | 1,328,119 | 2.2% |
| 5060 | SIP/VoIP | 630,716 | 1.1% |
| 80 | HTTP | 355,537 | 0.6% |
| 8728 | MikroTik API | 221,873 | 0.4% |
| 445 | SMB | 198,881 | 0.3% |
| 5902 | VNC (display 2) | 197,716 | 0.3% |
| 5910 | VNC (display 10) | 192,640 | 0.3% |
| 5038 | Asterisk AMI | 190,712 | 0.3% |
| 7070 | Various | 163,306 | 0.3% |
| 8000 | HTTP alternate | 137,330 | 0.2% |
| 5925 | VNC (display 25) | 135,729 | 0.2% |

### Phase Breakdown for Key Ports

| Port | Days 1-10 | Days 11-20 | Days 21-28 |
|------|----------|-----------|-----------|
| 443 | 16,698,522 | 2,912,199 | 9,710,296 |
| 5900 | 6,241,873 | 7,046,039 | 1,985,621 |
| 8443 | 4,846,418 | 3,070,021 | 29,097 |
| 22 | 1,010,310 | 828,072 | 288,692 |
| 161 | 1,328,119 | 0 | 0 |
| 5060 | 288,043 | 77,102 | 265,571 |

### Port 8443 High-Volume Days

| Date | Events |
|------|--------|
| 2026/02/04 | 1,204,896 |
| 2026/02/07 | 1,497,461 |
| 2026/02/08 | 988,283 |
| 2026/02/10 | 907,582 |
| 2026/02/13 | 752,864 |
| 2026/02/15 | 2,069,854 |
| 2026/02/17 | 110,202 |

---

## Methodology Notes

Port counts are drawn from the `top_ports` Elasticsearch aggregation in each daily query file. This aggregation returns the top 20 ports by event count per day. Ports that fell outside the top 20 on a given day are not captured; totals for lower-volume ports may be slightly undercounted.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in `/data/`.*

---

| Source | URL |
|--------|-----|
| T-Pot Community Edition | https://github.com/telekom-security/tpotce |
| IANA Port Registry | https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml |
| CISA BOD 23-02: Internet-Exposed Management Interfaces | https://www.cisa.gov/news-events/alerts/2023/06/13/cisa-issues-bod-23-02-mitigating-risk-internet-exposed-management-interfaces |
| CISA BOD 23-02: Implementation Guidance | https://www.cisa.gov/news-events/directives/bod-23-02-implementation-guidance-mitigating-risk-internet-exposed-management-interfaces |
| CISA: Enhanced Visibility and Hardening Guidance (Dec 2024) | https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure |
