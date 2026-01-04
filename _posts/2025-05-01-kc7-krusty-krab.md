---
layout: writeup
title: "KC7: Krusty Krab - Threat Intelligence Investigation"
date: 2025-05-01
category: THREAT INTELLIGENCE
tags: [KQL, Phishing, DFIR, CTF, Threat Intelligence, MITRE ATT&CK]
excerpt: "My first cybersecurity investigation report analyzing a multi-stage phishing campaign, credential harvesting, malware deployment, and data exfiltration using KustoQL (KQL) database queries."
---

![KC7 Krusty Krab Banner](/assets/images/kc7-krusty-krab/1.png)

## Background

In March 2025, I attended the [New2Cyber](https://www.sans.org/cyber-security-training-events/?location=americas%2Clatin-america%2Cusa-and-canada) virtual summit hosted by [SANS Institute](https://www.sans.org/). One of the events was a Capture The Flag (CTF) hosted by [KC7](https://kc7cyber.com/). It was my first introduction to threat intelligence in cybersecurity and the database query language [KustoQL (KQL)](https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric).

I completed the CTF in two hours and enjoyed it so much that I started looking for more. Since then, I've completed 16 rooms through KC7. Through their gamified learning platform, I've gained skills in database querying, digital forensics, and developed an investigative mindset.

This report does not provide KQL queries or specific answers. All IP addresses and links have been de-fanged, but use caution around potentially malicious IPs or links.

## Disclaimer

I am not a professional in the cybersecurity field. I'm a beginner with a passion for learning, information technology, and keeping systems secure. This report is my first attempt at cybersecurity report writing, inspired by the structure of [The DFIR Report](https://thedfirreport.com/). I'm open to constructive feedback.

## Problem Statement

The Krusty Krab is a mid-sized quick-service restaurant chain operating within the greater Bikini Bottom metropolitan area. The establishment has achieved market recognition for its flagship products, including Krabby Patties™, kelp shakes, and sea dogs. Due to considerable market share, several competing entities have expressed interest in obtaining the proprietary formula.

Our cybersecurity team identified anomalous activity originating from external email addresses not associated with Krusty Krab, raising concerns about attempts to obtain unauthorized access.
