---
layout: writeup
title: "Target x WiCyS Cyber Defense Challenge - Lessons from 2nd Place"
date: 2025-12-12
category: "COMPETITION"
tags: ["blue-team", "incident-response", "red-team", "career-transition"]
permalink: /writeups/target-tier-3-retrospective/
excerpt: "Reflections on placing 2nd in the national cyber defense competition. What I learned working through both offensive and defensive scenarios, how it shaped my career transition, and the lessons I'm taking forward."
---

# 2025 Target x WiCyS Cyber Defense Challenge

## Tier 3 Presentation Summary

**2nd Place Overall**

---

## Overview of the 2025 Target x WiCyS Cyber Defense Challenge

The challenge centered around a fictional breach at Personalyz.io, walking participants through both sides of the attack. Tier 1 put me on defense, responding to an extortion threat. I tracked down the sender through email headers, dug through logs for evidence, and even had to negotiate with the threat actor to figure out if the breach was legit. From there it was full forensics work: Wireshark to identify the compromised host and C2 server, decoding DNS exfiltration, combing through process and command history to find the malicious program, and discovering a tampered backup app plus remnants of a wiped system.

Tier 2 switched perspectives entirely and put me in the attacker role. I got in through a weaponized resume, exploited a template engine vulnerability, moved laterally using file inclusion and command execution, escalated out of a restricted shell, and pulled sensitive files by enumerating LDAP and SMB. The final challenge had me reverse engineer a DNS-over-HTTPS exfiltration client that was smuggling data out in encrypted traffic. Once I saw how it actually worked, everything I'd been piecing together defensively in Tier 1 suddenly clicked.

## What I Learned

Working through both tiers gave me a much better understanding of how real attacks actually unfold. Tier 1 taught me to be methodical about incident response. I learned to slow down, build timelines from different data sources (email headers, logs, packet captures, endpoint artifacts), and let the technical details tell the story instead of jumping to conclusions. Even the negotiation part was valuable. Knowing how to communicate clearly and present evidence ended up being just as important as the technical work.

But Tier 2 is where I learned the most. I'd spent almost all my time on the defensive side before this, so offensive work was completely new territory. Getting hands-on with exploiting vulnerabilities, moving through a network, escalating privileges, and enumerating services taught me how attackers actually think and move. Reversing that DoH exfiltration client was the moment everything came together. I finally understood exactly how the attacker had engineered what I'd been analyzing from the defensive side in Tier 1.

Seeing both perspectives changed how I approach security. I understand now how small misconfigurations can be chained together, what kind of traces attackers leave (even when they're trying not to), and how to spot those traces faster. It's made me a better analyst.

## How This Will Help in My Career

This challenge came at a good time for me career-wise. My path into tech has been anything but traditional. I've always been a gamer/techie at heart (aka unofficial family tech support), but I studied music in college and started out as a band director. Then I joined the Army as a geospatial intelligence analyst, and now I'm making the jump into cybersecurity. Each step taught me different things about discipline, how to communicate clearly, and how to break down complex problems. This challenge showed me those skills transfer well to cybersecurity work.

Tier 1 felt familiar in a lot of ways. The analytical work of digging through logs, connecting scattered clues, verifying evidence, and building a clear picture from messy data closely mirrors what I did in intelligence work. It was good to see that the problem-solving approach I developed there works just as well for incident response.

Tier 2 pushed me the most. Coming from a defensive background with basically zero offensive experience, learning to think like an attacker was completely new. But understanding how an intrusion actually happens from the attacker's perspective made everything click. Now I know what attackers are looking for and how they exploit things, which makes me better at defense.

Getting through both tiers proved something important to me: I can pick up new technical skills quickly, adapt when things get hard, and handle challenges I've never seen before. It also gave me something concrete to point to when I'm explaining my career transition. My background might not be traditional, but that's turned out to be an advantage. This challenge gave me the experience and confidence I needed to keep pushing forward in cybersecurity.

## Things I Wish I Knew Before Starting

I underestimated how quickly the difficulty would ramp up. The first few challenges are approachable, but the technical complexity increases fast once you hit network forensics and reverse engineering. When I got stuck, I found that stepping away and coming back with fresh eyes was often the best strategy to break through a problem, even if I thought I was close to the solution.

Time commitment was another factor. Many of these challenges required significant stretches of focused work (looking at you, D4, and my thousands of failed attempts). As a stay-at-home mom, I was fortunate to have the flexibility to block out uninterrupted time when I needed it, which made a real difference in my ability to work through the more complex problems and achieve the success I did in the challenge.

## Feedback for the Target Team

The challenge was really well designed. The scenario felt realistic, the skills built on each other in a way that made sense, and getting to work through both the defensive and offensive sides made it way more valuable than a typical CTF. You can tell a lot of thought went into making something that actually teaches you instead of just testing you.

The Slack community was honestly one of the best parts. The Target team was patient and helpful, providing sanity checks when I was stuck on the harder challenges. Special shoutout to Geoff (Zeke) for entertaining my wild, overcomplicated approaches to some of these challenges.

Overall, this was exactly what I needed at this point in my career. It pushed me hard, taught me a great deal, and gave me skills I'll be using for a long time.

---

**Related:** For a deep technical dive into one of the most challenging parts of this competition, check out my [O5: Tunnel Vision writeup](/writeups/tunnel-vision-o5/), where I reverse engineered the DNS exfiltration protocol from scratch.
