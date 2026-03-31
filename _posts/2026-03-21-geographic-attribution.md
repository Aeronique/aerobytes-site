---
layout: writeup
title: "Geographic Attribution"
date: 2026-03-21
category: research
tags: ["honeypot", "threat-intelligence", "T-Pot", "GCP", "geographic-attribution", "ASN-analysis", "DigitalOcean", "MaxMind", "cloud-attribution", "Netherlands", "Brazil", "Ukraine", "botnet", "28-days-exposed"]
permalink: /writeups/honeypot-threat-research/04
excerpt: "Where attack traffic originated during a 28-day T-Pot honeypot deployment, and why cloud provider and VPN exit node usage limits attribution confidence."
back_url: /honeypot-threat-research/
back_label: Back to 28 Days Exposed
---

# Geographic Attribution: February 2026 Honeypot Deployment

**Deployment Period:** February 1, 2026 to February 28, 2026

**Honeypot:** T-Pot Community Edition, Google Cloud Platform

**Data Source:** Elasticsearch DSL queries, Kibana Dev Tools

**TLP:** TLP:CLEAR

---

## Summary

The Netherlands, Brazil, Ukraine, and the United States were the top source countries across the 28-day deployment. A single Dutch ASN (Alsycon B.V.) produced nearly a third of all traffic in the top-20 ASN totals. Country labels in this dataset reflect where source IPs are registered, which is often a cloud datacenter or hosting provider, not the attacker's actual location.

---

## Background

T-Pot resolves each source IP to a country and ASN using MaxMind's GeoIP database. The country shown is where the IP is registered. Attackers frequently rent servers from cloud providers to run their tools, so the geographic label often reflects infrastructure location rather than operator location.

---

## Findings

### The Netherlands led by a wide margin

Alsycon B.V., a small Dutch hosting provider, was the largest source ASN across the full deployment with 24,045,125 events, over 32% of the top-20 ASN total. Its consistent, high-volume presence throughout February suggests one or a small number of actors used Alsycon-hosted servers as persistent attack infrastructure.

### Brazil appeared across many ASNs

Nine Brazilian ISPs appeared in the top 20 ASNs, spread across different states and IP ranges. Traffic was distributed across many sources rather than concentrated, which is more consistent with compromised endpoints or botnet activity than a focused campaign.

### DigitalOcean was the largest cloud provider source

DigitalOcean ranked second overall with 13,767,116 events and appeared on nearly every day of the deployment. Google LLC contributed 3,064,962 events. Together they account for roughly 23% of the top-20 ASN total. Google Cloud traffic is notable given this honeypot ran on GCP, meaning some attackers were using the same provider.

### Ukraine was a persistent mid-tier source

Two Ukrainian ASNs appeared across the full deployment: FOP Dmytro Nedilskyi (5,436,292 events) and LLC Vash Kredit Bank (1,704,237 events). FOP Dmytro Nedilskyi is a small hosting provider. Both showed up on multiple days at consistent volume.

---

## Analysis

Most of the top-country volume comes from hosting providers and cloud infrastructure, not residential networks. The Netherlands ranking first is a function of one hosting provider being heavily used. Brazil's spread across many small ISPs points to botnet or compromised-device activity rather than a single operator. Cloud provider traffic from the US reflects attacker preference for disposable VPS infrastructure.

Nation-state attribution is not possible from this data. Infrastructure location and operator location are different things, and this dataset has no signals to bridge that gap.

MaxMind's database has documented accuracy limitations for cloud provider ranges and VPN exit nodes, so some country labels may be incorrect. This is a known limitation.

---

## Defender Notes

Country-level blocks would be ineffective. The same actors appear across multiple countries and providers. Blocking specific ASNs that show persistent high-volume scanning with no legitimate use case is a better course of action.

---

## Data Reference

### Top ASNs, Full Deployment (28 Days)

| ASN | Events | Notes |
|-----|--------|-------|
| Alsycon B.V. | 24,045,125 | Dutch hosting provider |
| DigitalOcean, LLC | 13,767,116 | Cloud provider |
| FOP Dmytro Nedilskyi | 5,436,292 | Ukrainian hosting provider |
| Smart Servico de Internet Ltda | 3,332,596 | Brazilian ISP |
| Google LLC | 3,064,962 | Cloud provider |
| OXMAN TECNOLOGIA LTDA | 3,032,659 | Brazilian ISP |
| BITNET TELECOM | 2,986,685 | Brazilian ISP |
| BERTONCELLO PROVEDOR DE INTERNET LTDA ME | 2,603,657 | Brazilian ISP |
| GA Telecom | 2,398,612 | Brazilian ISP |
| DGNETSP EIRELI | 2,161,650 | Brazilian ISP |
| LLC Vash Kredit Bank | 1,704,237 | Ukrainian provider |
| HostPapa | 1,458,267 | Canadian hosting |
| Sinal do Ceu Telecom | 1,374,599 | Brazilian ISP |
| JL INFORMATICA E TELECOM LTDA - ME | 1,213,548 | Brazilian ISP |
| JK TELECOMUNICACOES LTDA | 1,065,785 | Brazilian ISP |
| TOTAL PLAY TELECOMUNICACIONES SA DE CV | 1,035,003 | Mexican ISP |
| Flyservers S.A. | 979,512 | Hosting provider |
| Enoki & Ruiz Ltda - ME | 862,730 | Brazilian ISP |
| GTT Communications Inc. | 845,983 | US transit provider |
| FATIMA VIDEO ELETRONICA LTDA ME | 665,865 | Brazilian ISP |

### Top Countries by Volume (T-Pot Dashboard, Full Period)

| Rank | Country |
|------|---------|
| 1 | Netherlands |
| 2 | United States |
| 3 | Ukraine |
| 4 | Romania |
| 5 | France |

*Dashboard country attribution is based on MaxMind GeoIP. Cloud and hosting provider IPs may resolve to the country of the datacenter, not the operator.*

---

## Methodology Notes

Geographic attribution in this report is based on ASN data returned by Elasticsearch's GeoIP enrichment (MaxMind database) and the T-Pot Kibana dashboard's country histogram. MaxMind has documented accuracy limitations for cloud provider ranges and VPN exit nodes. Country labels should be treated as infrastructure location, not attacker origin. Full methodology is in `DATA_COLLECTION_METHODOLOGY.md`.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, February 1 through February 28, 2026. Raw query output is preserved in `/data/`.*

---

## References

| Source | URL |
|--------|-----|
| MaxMind GeoIP2 Database | https://www.maxmind.com/en/geoip2-databases |
| MaxMind GeoIP Accuracy | https://www.maxmind.com/en/geoip2-city-database-accuracy |
| T-Pot Community Edition | https://github.com/telekom-security/tpotce |
| Alsycon B.V. (AS49870) | https://bgp.he.net/AS49870 |
| DigitalOcean ASN (AS14061) | https://bgp.he.net/AS14061 |
| FOP Dmytro Nedilskyi (AS211736) | https://bgp.he.net/AS211736 |
