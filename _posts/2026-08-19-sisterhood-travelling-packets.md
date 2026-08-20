---
layout: writeup
title: "Sisterhood of the Travelling Packets: Walking the Pantalones Leak Site"
date: 2026-08-19
category: ctf
tags: [flare, sans, wicys, web, recon, Tor, broken-access-control, idor, credential-reuse, darkweb, ransomware]
excerpt: "A Flare, SANS, and WiCyS speed CTF built around a fictional ransomware crew's leak site. The solve chains the gang's own OPSEC failures: an unauthenticated API, an IDOR that leaks their internal chat logs, a password shared in plaintext, and admin credentials reused since 2011."
back_url: /writeups/
back_label: writeups
---

Flare, SANS, and WiCyS ran Sisterhood of the Travelling Packets over three days in August 2026. One flag, one target, and speed decided the standings. I solved it in the top 250 and plenty early enough to earn a shirt!

The target was a leak site for a fictional ransomware crew that calls itself pantalones, hosted as a Tor hidden service. The challenge is offline now, so the address is redacted throughout. The whole solve runs on the crew's own OPSEC failures. The gang that robs everyone else guards its own systems poorly, and every step below turns one of those mistakes back on it.

The front page set a trap, and many players walked into it. Two of the six victims were marked leaked, each with a downloadable archive of convincing stolen data: SQL dumps, chat exports, API keys, customer records. An archive that size is the obvious place to hunt, so a lot of people spent the event grinding through gigabytes. The flag was not in the archives. It surfaced only after treating the site as a whole and reading the page source.

Entry point: a Tor hidden service, address `[REDACTED]`.

## The Target

The landing page follows the standard leak site layout: a crew banner, then a victim list. Two victims are already leaked, each with a downloadable archive (QuantumCore, AetherFlow). Four sit on countdown timers (Sisterhood of the Travelling Packets, NexaVista, StratifyTech, Lumenisys). The first entry is the CTF listing itself as a victim.

![The pantalones leak site landing page listing six victims, two leaked and four on release countdowns](/assets/images/sisterhood-travelling-packets/1.png)

The page pushes you toward the archives. Read the source first.

## The Comment in the Source

Tucked between the page content and the closing script tags is a lone HTML comment.

```
<!-- bm90X3RoZV9mbGFnX2tlZXBfbG9va2luZw== -->
```

![Page source showing a base64 HTML comment sitting above the victim data array](/assets/images/sisterhood-travelling-packets/2.png)

That is base64. Decode it:

```
echo "bm90X3RoZV9mbGFnX2tlZXBfbG9va2luZw==" | base64 -d
```

```
not_the_flag_keep_looking
```

None of the victim data holds the flag: not the archives, not the timers, not the tables. The comment marks the front page as a dead end and points elsewhere on the site. Reading it before downloading a large archive saved a lot of wasted time.

## robots.txt Hands Over the Map

When a site hides endpoints, `robots.txt` often lists them anyway, because the owner still wants crawlers to skip them. This one actually does.

![robots.txt disallowing /api.php and /admin.php](/assets/images/sisterhood-travelling-packets/3.png)

Two paths the crew wanted kept quiet: a backend API and an admin login. Both go on the list.

One point worth stating for anyone new: `robots.txt` is only a request to crawlers, and it enforces nothing. Every path listed there is readable by anyone who asks, which makes the file a standard first stop in recon. The OWASP Web Security Testing Guide covers it under webserver metafile review (WSTG-INFO-03).

## The API Documents Itself

Hitting `/api.php` with no parameters returns an error that lists every action it accepts.

```
/api.php
```

![api.php returning its full list of valid actions inside a JSON error](/assets/images/sisterhood-travelling-packets/4.png)

`api.php` is a single PHP script that routes on its query string. The first parameter follows a `?`, and each parameter after that is joined with an `&`. The `action` parameter selects the operation, and the sections below build the call up one parameter at a time.

Seven actions, none of them gated by authentication: `upload`, `status`, `messages`, `decrypt`, `wallets`, `payloads`, `exfil`. An endpoint that runs sensitive actions without confirming the caller is broken access control, the risk that has held the top spot on the OWASP Top 10 since the 2021 edition. `messages` was the most promising, so I started there.

## Reading the Crew's Chat Logs

`/api.php?action=messages` returns a similar error.

```
/api.php?action=messages
```

![The messages action asking for a conversation_id parameter](/assets/images/sisterhood-travelling-packets/5.png)

It wants a `conversation_id`. That is the second parameter, so it joins the string with an `&`, and the endpoint returns a full chat log:

```
/api.php?action=messages&conversation_id=0
```

Conversation IDs are sequential integers. IDs 0 through 4 each return a full internal chat log. Anything past 4 returns "conversation not found" with a hint that a valid ID looks like `conversation_id=0`. Changing a predictable ID to read records that belong to someone else is an Insecure Direct Object Reference, or IDOR. The OWASP API Security Top 10 ranks it first, under the name Broken Object Level Authorization (API1:2023). The object here is a private conversation, and the server never checks whether the caller may read it. Five conversations came back, and the crew talks like no one is listening:

- **0**: uploading the AetherFlow data, ransom priced at 4.5 BTC
- **1**: payload staging for StratifyTech, and vex shrugging off the `.exfil.sh` file left inside the AetherFlow archive ("its a dotfile tho so nobody will see it probably")
- **2**: hitting the Sisterhood as payback for tracking them, a Lumenisys phish, and a password slip
- **3**: vex clocking someone walking the API with sequential `conversation_id` values, the crew starting to sweat, crypt telling everyone to rotate the panel key, vex replying "ill do it tomorrow its 4am"
- **4**: the NexaVista intrusion, phish to backup service account to domain admin, then an AD dump of 847 accounts

Conversation 3 is the crew reacting to the enumeration in real time. **Conversation 2 holds the solution.**

## The Password Slip

At `2026-06-08 03:17`, mora asks crypt for her FTP password again. crypt, plainly done with the question, sends it back "encoded":

> `UGFudGFsMG4zc19SdWwzeiE=` - thats YOUR password mora. i encoded it this time, figure it out yourself. stop asking me for it every week

mora's reply is the part worth remembering:

> ive been using this password since 2011 and nobody has cracked it yet so i think im good lol

![The crew chat log showing crypt sending mora her base64 password](/assets/images/sisterhood-travelling-packets/6.png)

The string is base64. Decode it:

```
echo "UGFudGFsMG4zc19SdWwzeiE=" | base64 -d
```

```
Pantal0n3s_Rul3z!
```

Base64 is an encoding defined in RFC 4648. It moves binary data across channels that only accept text, and it reverses for anyone, so it provides no secrecy. Any terminal with `base64 -d` decodes it, and CyberChef does the same in a browser. Treating an encoding as if it were encryption is common enough to carry its own weakness IDs, CWE-261 and CWE-312.

That gives me a password mora has reused since 2011, pulled from a chat log served by an API that never asked who I was. Next step is finding where it works.

## The Admin Panel

That leaves the second path from `robots.txt`. `/admin.php` is a login form under a banner reading "no researchers allowed beyond this point."

![The pantalones admin login panel](/assets/images/sisterhood-travelling-packets/7.png)

mora is crew, so her name paired with her recycled password is the natural first guess. I typed the two values straight into the login form and submitted:

```
username: mora
password: Pantal0n3s_Rul3z!
```

The panel loads. This is credential reuse working the way it does outside a CTF: one password recovered in one place opens a second, unrelated system because the same secret protected both. The same behavior drives credential stuffing (MITRE ATT&CK T1110.004) and a large share of real account takeovers under Valid Accounts (T1078). The dashboard opens straight to a victim table with a Decryption Key column. The Sisterhood row's key is the flag, listed in plain view.

![The admin dashboard with the Sisterhood decryption key highlighted](/assets/images/sisterhood-travelling-packets/8.png)

```
flare{pantal0n3s_g0t_pantsed_2026}
```

Flag confirmed. The crew that named itself after pants got pantsed.

## What the Panel Held

The dashboard laid out the full operation on one screen:

| Target | Status | Ransom | Decryption Key |
|--------|--------|--------|----------------|
| Sisterhood of the Travelling Packets | negotiating | 99.9 BTC | `flare{pantal0n3s_g0t_pantsed_2026}` |
| NexaVista Solutions | negotiating | 3.2 BTC | `7d2f8a41c6e9b035d1f74a82e9c360b5` |
| StratifyTech Inc. | negotiating | 5.0 BTC | `e4b19c73f5a208d6c3e71b94a5f8d2c0` |
| Lumenisys Global | no response | 2.8 BTC | `5c8e2d91a0b7f346d8e12c59f4a07b63` |
| QuantumCore Systems | leaked | 6.0 BTC | `b83a1f7e420d9c56a3e81b2f7d064c95` |
| AetherFlow Enterprises | leaked | 4.5 BTC | `a9c3f7e2b1d84f60923c5e8a1b7d4f09` |

An activity log showed logins from vex, crypt, and skid, a panel running v0.4.2 across three nodes, 847 GB of stolen data, a wallet mixer set to four rounds, and 27.84 BTC received.

## The Faster Path I Skipped

There was a second way in. The AetherFlow leak archive carried a hidden `.exfil.sh` dotfile holding the panel onion address and an API key (`pantalonesgroup`). It reaches the same API, but only after you download and extract the archive first. The `robots.txt` route gets there in two GET requests, so that is the one I took. The base64 comment in the source was pointing people away from the archives for exactly this reason.

## The OPSEC Ledger

The challenge is a checklist of mistakes that would compromise a real crew:

1. `robots.txt` advertised the private API and admin panel.
2. `api.php` required no auth for any action, including reading every internal message.
3. The crew passed a password in plaintext over their own open chat and called base64 "encoding."
4. mora reused one password everywhere since 2011.
5. vex left `.exfil.sh`, holding the panel URL and API key, inside a published leak archive.
6. Every warning crypt raised got waved off ("its behind tor who cares," "ill do it tomorrow its 4am").

This plays out well beyond CTFs. In February 2024, a task force called Operation Cronos, led by the UK National Crime Agency alongside the FBI, Europol, and other partners, seized the infrastructure of LockBit, at the time the most active ransomware group in the world. Investigators took the leak site, the affiliate panel, the source code, internal chat logs, victim records, and decryption keys, and by LockBit's own account they got in through an unpatched PHP flaw on the group's public servers. The crew that squeezed thousands of victims over weak security lost its whole operation to weak security of its own. pantalones is that same story played for laughs.

The setup is comedic, but the failures under it are ordinary. Access control and credential hygiene stop most intrusions of this kind, and they are the first controls to slip when an operator assumes no one is looking.

## Concepts and References

Every step in this solve maps to a named weakness class. If you want to carry the ideas past the challenge, these are the references I would point a newcomer to.

- **Sensitive data in page content.** The base64 comment is a note left in the page source. CWE-615, Inclusion of Sensitive Information in Source Code Comments (https://cwe.mitre.org/data/definitions/615.html). OWASP WSTG, Review Webpage Content for Information Leakage (WSTG-INFO-05).
- **Metafiles as recon.** `robots.txt` disclosing private paths. OWASP WSTG, Review Webserver Metafiles for Information Leakage (WSTG-INFO-03), https://owasp.org/www-project-web-security-testing-guide/.
- **Broken access control.** An API running sensitive actions without checking the caller. OWASP Top 10 2021 A01, Broken Access Control (https://owasp.org/Top10/A01_2021-Broken_Access_Control/), and API2:2023, Broken Authentication in the OWASP API Security Top 10.
- **IDOR / BOLA.** Enumerating `conversation_id` to read other people's messages. API1:2023, Broken Object Level Authorization (https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).
- **Encoding treated as a secret.** Base64 defined in RFC 4648 (https://datatracker.ietf.org/doc/html/rfc4648). CWE-261, Weak Encoding for Password (https://cwe.mitre.org/data/definitions/261.html), and CWE-312, Cleartext Storage of Sensitive Information (https://cwe.mitre.org/data/definitions/312.html).
- **Credentials in the open.** A password passed through internal chat and served by an open API. CWE-319, Cleartext Transmission of Sensitive Information (https://cwe.mitre.org/data/definitions/319.html), and MITRE ATT&CK T1552.001, Unsecured Credentials: Credentials In Files (https://attack.mitre.org/techniques/T1552/001/).
- **Password reuse.** One 2011 password unlocking the panel. MITRE ATT&CK T1110.004, Credential Stuffing (https://attack.mitre.org/techniques/T1110/004/), and T1078, Valid Accounts (https://attack.mitre.org/techniques/T1078/).

## Credits

Thanks to Flare, SANS, and WiCyS for the challenge! It was quick, well built, and a good reminder that the fastest route through a web target is often reading what the other side left in the open! I'm excited for my fancy hacker shirt!
