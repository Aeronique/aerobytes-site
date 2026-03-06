---
layout: writeup
title: "T-Pot Honeypot: Legacy Vulnerability Exploitation - February 2026"
date: 2026-03-07
category: THREAT INTELLIGENCE
tags:tags: ["honeypot", "threat-intelligence", "CVE", "T-Pot", "suricata", "GCP", "cve-analysis", "vulnerability-research", "legacy-vulnerabilities"]
permalink: /writeups/honeypot-threat-research/08
excerpt: "Pre-2017 CVEs that still generated inbound scanning activity during a 28-day honeypot deployment, and what the patterns suggest about long-unpatched systems."
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

Six CVEs from 2013 to 2016 each generated 8 or more Suricata IDS alerts during the 28-day deployment. The oldest observed CVE was CVE-2009-5156, a command injection flaw in ASMAX router firmware, though it fell below the reporting threshold at 2 events. All had patches available years before this deployment. The traffic shows that scanners are still actively probing for them.

---

## Findings

### CVE-2014-6271: Shellshock (GNU Bash)

A remote code execution flaw in GNU Bash where a crafted environment variable in an HTTP request triggers arbitrary command execution on the server. Disclosed on 2014/09/24 and patched in the same week.

**Observed activity:** **36 events**, all on 2026/02/27. One spike, no other activity across the deployment.

---

### CVE-2013-2251: Apache Struts OGNL Command Execution

An OGNL injection flaw allowing remote code execution via crafted HTTP parameters in Struts-based web applications.

**Observed activity:** **12 events**, all on 2026/02/27. Three Suricata signatures fired on the same traffic. The raw sum across all three signatures is 36, but each signature matched the same 12 requests. This report uses 12 as the event count.

---

### CVE-2013-4810: HP ProCurve Manager / JBoss Invoker Servlet RCE

A remote code execution flaw in HP ProCurve Manager and related products that expose unauthenticated JBoss servlet interfaces. Sending a crafted marshalled object to `EJBInvokerServlet` or `JMXInvokerServlet` allows an unauthenticated attacker to execute arbitrary code. 

**Observed activity:** **8 events**, all on 2026/02/27.

---

### CVE-2014-3704: Drupalgeddon (Drupal SQL Injection)

A SQL injection flaw in Drupal's database abstraction layer where an unauthenticated attacker can modify queries to create admin accounts or execute arbitrary PHP.

**Observed activity:** **8 events**, all on 2026/02/27.

---

### CVE-2016-20016: MVPower CCTV DVR RCE

An unauthenticated remote command execution flaw in the JAWS web server used by MVPower CCTV DVR devices where attackers send shell commands via a crafted HTTP request to `/shell`.

**Observed activity:** **9 events** across 4 days. Activity on 2026/02/02 (5), 2026/02/08 (2), 2026/02/14 (1), and 2026/02/20 (1).

---

### CVE-2016-20017: D-Link DSL-2750B / Korenix Command Injection

A command injection flaw in D-Link DSL-2750B routers, firmware versions 1.01 through 1.03. Attackers can inject shell commands via the `cli` parameter in `login.cgi` without authentication. The same CVE ID covers Korenix JetWave and Edimax devices via the `formSysCmd` parameter. CISA added this to the KEV catalog. Exploited in the wild from 2016 through 2022 according to NVD.

**Observed activity:** **9 events** across 8 days, with no more than 2 events on any single day.

---

## Assessment

Five of the six CVEs in this report generated all of their events on a single day, 2026/02/27. That pattern points to one automated tool or scanner running a probable broad vulnerability sweep across many CVEs in a single pass. CVE-2016-20016 and CVE-2016-20017 were the exceptions, appearing on multiple days in small number, which is more consistent with probable routine background scanning.

The event counts here are very small compared to the CVEs highlighted in the top three overall. Even so, Shellshock, Drupalgeddon, and a 2013 Apache Struts flaw are still worth including in a modern scanner's checklist. Unpatched systems exist, and scanners know to look for it.

---

## Data Reference

| CVE | Year | Total Events | Active Days | Peak Day | Peak Count |
|-----|------|-------------|-------------|----------|------------|
| CVE-2014-6271 | 2014 | 12 | 1 | 2026/02/27 | 36 |
| CVE-2013-2251 | 2013 | 12 | 1 | 2026/02/27 | 12 |
| CVE-2016-20016 | 2016 | 9 | 4 | 2026/02/02 | 5 |
| CVE-2016-20017 | 2016 | 9 | 8 | 2026/02/03 | 2 |
| CVE-2013-4810 | 2013 | 8 | 1 | 2026/02/27 | 8 |
| CVE-2014-3704 | 2014 | 8 | 1 | 2026/02/27 | 8 |

---

## Methodology Notes

**Reporting threshold:** This report covers CVEs with 8 or more total events. CVE-2009-5156, CVE-2013-7471, CVE-2013-1599, CVE-2014-2321, and CVE-2014-9118 each had fewer than 8 events and are excluded.

---

*All data sourced from Elasticsearch DSL queries against T-Pot honeypot logs, 2026/02/01 through 2026/02/28. Raw query output is preserved in [honeypot-threat-research/data](https://github.com/Aeronique/honeypot-threat-research/tree/main/data).*

---

## References

| Source | URL |
|--------|-----|
| NVD: CVE-2014-6271 | https://nvd.nist.gov/vuln/detail/CVE-2014-6271 |
| CISA Alert: Shellshock CVE-2014-6271 | https://www.cisa.gov/news-events/alerts/2014/09/25/gnu-bourne-again-shell-bash-shellshock-vulnerability-cve-2014-6271 |
| NVD: CVE-2013-2251 | https://nvd.nist.gov/vuln/detail/CVE-2013-2251 |
| NVD: CVE-2013-4810 | https://nvd.nist.gov/vuln/detail/CVE-2013-4810 |
| Red Hat: CVE-2013-4810 and JBoss exposure | https://access.redhat.com/articles/545183 |
| CISA KEV: CVE-2013-4810 | https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2013-4810 |
| NVD: CVE-2014-3704 | https://nvd.nist.gov/vuln/detail/CVE-2014-3704 |
| Drupal Security Advisory SA-CORE-2014-005 | https://www.drupal.org/forum/newsletters/security-advisories-for-drupal-core/2014-10-15/sa-core-2014-005-drupal-core-sql |
| NVD: CVE-2016-20016 | https://nvd.nist.gov/vuln/detail/CVE-2016-20016 |
| NVD: CVE-2016-20017 | https://nvd.nist.gov/vuln/detail/CVE-2016-20017 |
| CISA KEV: CVE-2016-20017 | https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2016-20017 |
