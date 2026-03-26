---
layout: writeup
title: "Cloud Infrastructure Abuse: February 2026 Honeypot Deployment"
date: 2026-03-23
category: THREAT INTELLIGENCE
tags: ["honeypot", "threat-intelligence", "T-Pot", "GCP", "cloud", "attribution"]
permalink: /writeups/honeypot-threat-research/09
excerpt: "Three major cloud providers contributed 17.4 million events across 28 days, accounting for 18.1% of all inbound attack traffic. DigitalOcean alone was responsible for 14.3%."
back_url: /honeypot-threat-research/
back_label: Back to 28 Days Exposed
---

# Cloud Infrastructure Abuse

**Deployment Period:** February 1, 2026 to February 28, 2026 
 
**Honeypot:** T-Pot Community Edition, Google Cloud Platform 
 
**Data Source:** Elasticsearch DSL queries, Kibana Dev Tools  

**TLP:** TLP:CLEAR  

---

## Summary

Three major cloud providers contributed **17,485,217 events** across the 28-day deployment, accounting for **18.1% of all inbound attack traffic**. DigitalOcean was the dominant source at 14.3% of total events. Google Cloud and Amazon combined added another 3.9%. These are not compromised home users or botnet-infected devices. They are VMs rented specifically to run attack tooling, which makes them easy to spin up and easy to abandon.

---

## Background

When attackers use cloud infrastructure, the IP address in the log does not point to a home country, a hacking group, or even a consistent threat actor. It points to a data center. This is why geographic attribution breaks down for a large share of honeypot traffic because the source IP tells you which cloud provider a VM was rented from, not where the person who rented it is located.

Cloud providers have abuse teams and respond to reports. Because of that, attackers tend to use cloud infrastructure for short campaigns, rotate IPs frequently, or run persistent low-volume scanning that stays below abuse thresholds. All three patterns appeared in this deployment.

---

## Findings

### DigitalOcean: 13,767,116 Events

DigitalOcean was the **second-largest attack source** across the entire deployment, behind only Alsycon B.V. at 24,045,125 events. It accounted for **14.3% of total traffic**.

Volume was high for the first 18 days, averaging 663,000 events per day. On 2026/02/17 it peaked at **972,638 events**. Then it dropped sharply. Days 19 through 28 averaged 183,000 per day, a reduction of about 72% from the first-half average.

Five distinct IP addresses in the top 20 source IPs for the full deployment belong to DigitalOcean ranges. Their combined total across all 28 days was **8,161,131 events**, meaning a small number of VMs accounted for the majority of DigitalOcean traffic.

| IP Address | Total Events |
|---|---|
| 134.199.202.110 | 1,258,592 |
| 159.89.117.122 | 1,216,500 |
| 134.199.197.11 | 1,228,109 |
| 138.197.152.232 | 1,004,148 |
| 134.199.195.17 | 1,036,491 |
| 165.227.47.158 | 808,944 |
| 159.203.58.78 | 804,302 |
| 134.199.203.119 | 804,045 |

The 134.199.x.x addresses in particular cluster tightly and generated consistent high-volume traffic. This pattern points to a coordinated scanning operation running across multiple VMs in the same DigitalOcean region.

### Google Cloud: 3,064,962 Events

Google Cloud (AS396982 / Google LLC) generated **3,064,962 events**, or **3.2% of total traffic**. One IP, 129.212.176.30, appeared in the top 20 source IPs for the full deployment with 1,039,948 events. Daily volume was steady throughout February, averaging 109,463 events per day with no significant spikes or drop-offs.

The consistent daily pattern differs from DigitalOcean's first-half surge. It points to a persistent scanner running on a single VM, maintaining steady output for the full 28 days without escalating or withdrawing.

### Amazon: 653,139 Events

Amazon (AS16509, Amazon.com, Inc.) contributed **653,139 events**, or **0.7% of total traffic**. Daily counts were mostly in the 12,000 to 30,000 range. Two brief spikes appeared on 2026/02/04 (58,357 events) and 2026/02/05 (55,877 events), after which volume returned to baseline. No Amazon IPs appeared in the top 20 source IPs for the full deployment, which means the traffic was distributed across a larger number of addresses.

---

## Analysis

### Cloud Infrastructure as Attack Tooling

Renting a VM takes minutes. Most cloud providers offer hourly billing. An attacker running a scanning campaign can spin up a VM, run it for a few days, and discard it before an abuse report results in a suspension. The IP is then gone, and the campaign moves to a new address.

This also means that blocking a single cloud IP is often a temporary measure. The same campaign can resume from a different address within the same ASN.

### DigitalOcean Volume Shift

The sharp drop after 2026/02/17 suggests the campaign running through DigitalOcean either completed its objective, rotated to other infrastructure, or was disrupted. A drop of 72% in average daily volume over ten days appears to be a deliberate stop.

The clustering of high-volume IPs in the same subnet range (134.199.x.x) suggests the attacker used several VMs in the same region simultaneously. This is a common approach for scanning campaigns that need to cover large IP ranges quickly.

### Attribution limits

These event counts cannot be tied to a specific threat actor. DigitalOcean, Google Cloud, and Amazon are used by criminals, security researchers, bot operators, and legitimate businesses. The data shows which networks the traffic came from. It does not show who rented the VMs or what they were ultimately trying to accomplish beyond scanning for vulnerable services.

---

## Defender Notes

Blocking entire cloud provider ASN ranges is usually not practical. A better approach is to track IP reputation at the address level and block or rate-limit individual addresses that generate sustained scanning volume.

If you are seeing high-volume traffic from a specific cloud IP, filing an abuse report with the provider is worth it. Cloud providers do act on reports. It may not stop the actor, but it does impose a cost on them in the form of having to rotate infrastructure.

For Google Cloud and Amazon traffic specifically, their own threat intelligence teams actively investigate abuse on their platforms. Both publish guidance on how to report malicious use of their infrastructure.

---

## Data Reference

### Table 1: Cloud Provider Summary

| Provider | ASN | Total Events | % of All Events |
|---|---|---|---|
| DigitalOcean, LLC | AS14061 | 13,767,116 | 14.3% |
| Google LLC | AS396982 | 3,064,962 | 3.2% |
| Amazon.com, Inc. | AS16509 | 653,139 | 0.7% |
| **Combined** | | **17,485,217** | **18.1%** |

*Total deployment events: 96,408,585*

### Table 2: Daily Event Counts by Provider

| Day | Date | DigitalOcean | Google Cloud | Amazon |
|---|---|---|---|---|
| 01 | 2026/02/01 | 744,860 | 117,254 | 16,927 |
| 02 | 2026/02/02 | 640,103 | 106,386 | 12,920 |
| 03 | 2026/02/03 | 624,021 | 101,740 | 17,108 |
| 04 | 2026/02/04 | 711,193 | 95,291 | 58,357 |
| 05 | 2026/02/05 | 733,314 | 117,272 | 55,877 |
| 06 | 2026/02/06 | 696,847 | 116,855 | 20,375 |
| 07 | 2026/02/07 | 771,454 | 117,514 | 31,722 |
| 08 | 2026/02/08 | 820,320 | 111,462 | 26,475 |
| 09 | 2026/02/09 | 684,732 | 96,743 | 11,619 |
| 10 | 2026/02/10 | 396,447 | 105,726 | 23,914 |
| 11 | 2026/02/11 | 666,147 | 102,884 | 15,187 |
| 12 | 2026/02/12 | 494,775 | 117,445 | 12,087 |
| 13 | 2026/02/13 | 570,702 | 117,828 | 14,213 |
| 14 | 2026/02/14 | 560,912 | 129,966 | 31,582 |
| 15 | 2026/02/15 | 550,086 | 119,451 | 14,856 |
| 16 | 2026/02/16 | 831,547 | 102,638 | 13,819 |
| 17 | 2026/02/17 | 972,638 | 101,202 | 29,008 |
| 18 | 2026/02/18 | 463,784 | 98,243 | 17,100 |
| 19 | 2026/02/19 | 283,357 | 121,257 | 19,367 |
| 20 | 2026/02/20 | 230,178 | 114,690 | 24,370 |
| 21 | 2026/02/21 | 107,208 | 115,315 | 12,854 |
| 22 | 2026/02/22 | 161,636 | 108,774 | 43,855 |
| 23 | 2026/02/23 | 184,594 | 71,447 | 17,638 |
| 24 | 2026/02/24 | 132,538 | 100,594 | 16,931 |
| 25 | 2026/02/25 | 169,562 | 107,175 | 27,685 |
| 26 | 2026/02/26 | 195,765 | 121,885 | 20,681 |
| 27 | 2026/02/27 | 183,474 | 109,536 | 19,371 |
| 28 | 2026/02/28 | 184,922 | 118,389 | 27,241 |

---

## Methodology Notes

ASN totals are taken from the final full-dataset Elasticsearch query run on 2026/03/01, which covers all 28 days of indexed data. Daily counts per provider are extracted from per-day ASN aggregations in the daily JSON files. The daily totals for each provider will not sum to the final totals exactly in all cases due to the top-20 bucket limit on daily aggregations and the `doc_count_error_upper_bound` margins in Elasticsearch term aggregations.

Internal Google Cloud VM traffic (10.128.0.2) was excluded from all queries.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, February 1 through February 28, 2026. Raw query output is preserved in `/data/`.*

---

## References

| Source | URL |
|---|---|
| DigitalOcean IP Ranges (AS14061) | https://docs.digitalocean.com/platform/ |
| Google Cloud IP Ranges (AS396982) | https://cloud.google.com/compute/docs/faq#find_ip_range |
| Amazon AWS IP Ranges (AS16509) | https://ip-ranges.amazonaws.com/ip-ranges.json |
| DigitalOcean Abuse Reporting | https://www.digitalocean.com/company/contact/abuse |
| Google Cloud Abuse Reporting | https://docs.cloud.google.com/docs/security/respond-to-abuse-misuse |
| AWS Trust and Safety | https://aws.amazon.com/premiumsupport/knowledge-center/report-aws-abuse/ |
| Shodan ASN Search: AS14061 | https://www.shodan.io/search?query=asn%3AAS14061 |
