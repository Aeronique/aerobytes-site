---
layout: writeup
title: "Credential Attack Patterns"
date: 2026-03-24
category: research
tags: ["honeypot", "threat-intelligence", "T-Pot", "GCP", "credentials", "SSH", "Cowrie", "brute-force", "default-credentials", "password-spraying", "IoT", "Telnet", "coinminer", "Polycom", "28-days-exposed"]
permalink: /writeups/honeypot-threat-research/07
excerpt: "28 days of Cowrie credential logs show root as the top username and two IoT device defaults accounting for roughly 30% of global SSH brute-force attempts embedded in scanning tooling worldwide."
back_url: /honeypot-threat-research/
back_label: Back to 28 Days Exposed
---

**Deployment Period:** February 1, 2026 to February 28, 2026

**Honeypot:** T-Pot Community Edition, Google Cloud Platform

**Data Source:** T-Pot Kibana Dashboard, Cowrie credential logs

**TLP:** TLP:CLEAR

---

## Summary

Cowrie logged credential attempts across the full 28-day deployment. `root` was the top username. The two highest-frequency passwords, `3245gs5662d34` and `345gs5662d34`, are default credentials for IP cameras and Polycom VoIP phones. They appear in virtually every SSH scan at internet scale.

---

## Background

Cowrie is the SSH and Telnet honeypot in T-Pot. It logs every username and password submitted during login attempts. Credential data here comes from the Kibana dashboard tagclouds. Font size reflects relative frequency. Exact counts were not available, so rankings are approximate.

---

## Findings

### Usernames

`root` was the dominant username. `admin` and `user` followed. The remaining attempts targeted service account names that ship as defaults with specific software and platforms.

### Passwords

Most passwords were standard weak credentials: numeric sequences, keyboard patterns, and common defaults like `password` and `admin`.

The two highest-frequency passwords were `3245gs5662d34` and `345gs5662d34`. These are default credentials for IP camera systems and the Polycom CX600 IP phone respectively, documented by SANS ISC and Aalborg University research. Both strings appear as usernames and passwords because scanning tools submit them in both fields. SANS and TEHTRIS data puts these two credentials at roughly 30% of global SSH brute-force attempts.

### Blank Credentials

Blank usernames and passwords both appeared. These are probes for unauthenticated access.

---

## Analysis

All usernames observed are published defaults for Linux, cloud images, or software packages. The service account names (`docker`, `zabbix`, `elastic`, `postgres`, `hadoop`) indicate targeting of exposed management interfaces.

The Polycom and camera default passwords are embedded in widely distributed scanning tooling. Post-login behavior documented in external honeypot research shows two patterns: some sessions execute no commands after access, likely marking targets for later, while others immediately pull coinminer payloads via `curl` or `wget`.

`solana` appeared as both a username and a password, consistent with targeting of internet-facing cryptocurrency nodes.

---

## Defender Notes

**SSH and Telnet:** Disabling password authentication in favor of key-based authentication removes the attack surface this report covers.

**Service accounts:** `docker`, `elastic`, `postgres`, and `zabbix` should not be reachable from the internet. Restrict by source IP or put management interfaces behind a VPN.

---

## Data Reference

**Top Usernames (approximate, by relative frequency)**

| Rank | Username | Default For |
|------|----------|-------------|
| 1 | root | Linux superuser |
| 2 | admin | Generic |
| 3 | user | Generic |
| 4 | ubuntu | Ubuntu cloud image |
| 5 | test | Generic |
| 6 | guest | Generic |
| 7 | oracle | Oracle DB |
| 8 | ftpuser | FTP services |
| 9 | deploy | Deployment tooling |
| 10 | docker | Docker |
| 11 | hadoop | Apache Hadoop |
| 12 | sol / solana | Solana node |
| 13 | ec2-user | AWS EC2 |
| 14 | ubnt | Ubiquiti devices |
| 15 | pi | Raspberry Pi |
| 16 | elastic | Elasticsearch |
| 17 | postgres | PostgreSQL |
| 18 | zabbix | Zabbix |
| 19 | tomcat | Apache Tomcat |
| — | (blank) | Unauthenticated probe |

**Top Passwords (approximate, by relative frequency)**

| Rank | Password | Type |
|------|----------|------|
| 1 | 3245gs5662d34 | IP camera default |
| 2 | 123456 | Numeric sequence |
| 3 | 345gs5662d34 | Polycom CX600 default |
| 4 | password | Common default |
| 5 | 1234 | Numeric sequence |
| 6 | qwerty | Keyboard pattern |
| 7 | 12345 | Numeric sequence |
| 8 | 123456789 | Numeric sequence |
| 9 | admin | Common default |
| 10 | 1234567890 | Numeric sequence |
| 11 | (blank) | Unauthenticated probe |
| 12 | admin123 | Common default |
| 13 | 123123 | Numeric sequence |
| 14 | 12345678 | Numeric sequence |
| 15 | 000000 | Repeated digit |
| 16 | 1qa2wsx | Keyboard pattern |
| 17 | test | Common default |
| 18 | root | Common default |
| 19 | welcome | Common default |
| 20 | P@ssw0rd | Common default |

---

## Methodology Notes

Exact credential counts were not part of the daily query set. Rankings are based on tagcloud font size. Cowrie-logged SSH and Telnet attempts only. Credentials submitted to other honeypot components are not included.

---

*All data sourced from T-Pot Kibana dashboard, Cowrie credential logs, February 1 through February 28, 2026. Raw Elasticsearch query output is preserved in `/data/`.*

---

| Source | URL |
|--------|-----|
| T-Pot Community Edition | https://github.com/telekom-security/tpotce |
| Cowrie SSH/Telnet Honeypot | https://github.com/cowrie/cowrie |
| SANS ISC: Password Brute Forcing Evolution Statistics | https://isc.sans.edu/diary/32068 |
| SANS ISC: Top Not-So-Common SSH Usernames and Passwords | https://isc.sans.edu/diary/31360 |
| Aalborg University: SweetCam IP Camera Honeypot (2023) | https://vbn.aau.dk/ws/portalfiles/portal/573748244/sweetcam_honeypot_paper_1_.pdf |
| IMC 2025: Long-Term SSH Honeynet Observations | https://gsmaragd.github.io/publications/IMC2025-Honeynet/IMC2025-Honeynet.pdf |

