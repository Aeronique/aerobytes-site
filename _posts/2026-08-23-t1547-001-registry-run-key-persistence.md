---
layout: writeup
title: "Registry Run Key Persistence: What Live Registry Hunting Misses"
date: 2026-08-23
category: aerolab
technique: T1547.001
technique_name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"
tactic: Persistence
platform: Windows
sigma: "yes"
tags: [velociraptor, sysmon, elastic, sigma, persistence, registry, windows, purple-team, aerolab]
excerpt: "Planting Run key persistence on a domain controller, then showing the exact point a live registry search goes blind. Four detection methods compared, ending in a Sigma rule built from the collected evidence."
back_url: /aerolab/
back_label: AeroLab
---

**Technique:** T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
**Target:** aero-dc.aerolab.lan (Windows Server 2022, domain controller)
**Tooling:** Velociraptor 0.75.6, Sysmon with SwiftOnSecurity configuration, Winlogbeat 9.0.3, Elastic Stack 9.x

---

*This is a guided project using Claude Code and my homelab, AeroLab v2.*

## 1. Summary

An attacker who plants a startup entry inside a user's part of the registry can disappear from a live search the moment that user logs off. The entry stays on disk. It still runs at the next logon. The search finds nothing.

This exercise plants that persistence on a domain controller, detects it four different ways, and shows the exact point where the most obvious detection method fails. It ends with a Sigma rule built from the collected evidence.

The finding held across three collections. With the user signed in, the startup entry showed up. With the user signed out, the same query missed it. Reading the registry file directly off disk found it again in 282 milliseconds.

---

## 2. Objective

1. Record a verified baseline of startup entries on the target.
2. Run T1547.001 two ways: a registry Run key and a Startup folder drop.
3. Detect it using live collection, offline file parsing, and a fleet-wide hunt.
4. Compare what the endpoint tool sees against what the log pipeline recorded.
5. Write a detection rule and document where it would produce false alarms.
6. Return the host to its baseline and confirm it.

---

## 3. Environment

| Component | Value |
|---|---|
| Target host | aero-dc.aerolab.lan, 10.10.20.10 |
| Velociraptor client ID | `C.77d6e46908a115c9` |
| Velociraptor server | `https://192.168.0.163:8889` (pfSense NAT forward) |
| Kibana | `http://192.168.0.163:5601` |
| Elastic index | `.ds-winlogbeat-9.0.3-2026.08.23-000002` |
| Analyst workstation | Linux Mint, RDP through Remmina to `192.168.0.163:3389` |

Every Windows account has a SID, a long unique identifier the system uses instead of a username. The domain SID for aerolab.lan is `S-1-5-21-3205830668-3599923109-2036419528`. The number on the end is the RID, and RID 500 is always the built-in Administrator on any Windows machine. That makes the full SID `S-1-5-21-3205830668-3599923109-2036419528-500`, and it means you can name the account from the SID alone.

---

## 4. How the technique works

Windows runs whatever it finds in certain registry locations every time someone logs on. The two most commonly abused are:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

The first one applies to the whole machine and needs admin rights to write. The second one applies to a single user and needs nothing beyond that user's own access, which is why it turns up so often in everyday malware and in the early stages of a hands-on intrusion.

There is a matching trick on the filesystem. Anything dropped in a user's Startup folder runs at logon with no registry involved:

```
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

This exercise uses both, because they behave differently once you go looking for them.

---

## 5. Baseline

Before touching anything, the `Windows.Sys.StartupItems` artifact was collected from the target. It checks the standard Run key locations and both Startup folders.

Three rows came back.

| Name | Path |
|---|---|
| SecurityHealth | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth` |
| desktop.ini | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini` |
| desktop.ini | `C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini` |

The two `desktop.ini` files are Windows display settings that sit in every Startup folder. `SecurityHealth` ships with the operating system. Three rows is very clean for a real server, which is a benefit of a purpose-built lab. The results were exported to CSV for later comparison.

---

## 6. Execution

All commands ran in an elevated PowerShell window on aero-dc, in RDP session ID 2, as `AEROLAB\Administrator`.

A reference time was recorded first:

```powershell
[DateTime]::UtcNow.ToString("o")
```

```
2026-08-23T01:15:13.8947197Z
```

### 6.1 Payload

The payload is a batch file that writes the current time to a log. It does nothing harmful and leaves proof that it ran.

```powershell
$payload = @'
@echo off
powershell -NoProfile -WindowStyle Hidden -Command "Add-Content -Path C:\Users\Public\beacon.log -Value (Get-Date)"
'@
Set-Content -Path C:\Users\Public\updater.bat -Value $payload
```

`C:\Users\Public` can be written to by any logged-in user and sits outside the folders most scanners focus on, which makes it a realistic place to stage a file.

### 6.2 Registry Run key

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveUpdater /t REG_SZ /d "C:\Users\Public\updater.bat" /f
```

`reg.exe` was used on purpose. It is a signed Microsoft program that exists on every Windows system, and it leaves a clean record showing the full command that was typed.

The name `OneDriveUpdater` imitates a real Microsoft component. Picking an innocent-looking name is something attackers actually do, so it belongs in the simulation.

### 6.3 Startup folder drop

```powershell
Copy-Item C:\Users\Public\updater.bat "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.bat"
```

### 6.4 Verification

```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveUpdater
Get-ChildItem "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
Get-Item C:\Users\Public\updater.bat
```

Both pieces were confirmed in place. Windows Defender left the file alone, which fits, since a plain batch file contains nothing Defender recognizes as malicious.

One useful detail turned up here. Both copies of `updater.bat` showed a LastWriteTime of 9:15 PM local. Windows keeps the original write time when a file is copied, so the timestamp on the Startup folder copy shows when the file was written rather than when it was placed there. File write times tell you when something was created, not when it arrived.

---

## 7. Detection

### 7.1 Live collection, user signed in

`Windows.Sys.StartupItems` was collected again with the Administrator session active. The result went from three rows to eight.

Two rows were the planted persistence:

| Name | Path | Payload |
|---|---|---|
| OneDriveUpdater | `HKEY_USERS\S-1-5-21-...-500\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdater` | `C:\Users\Public\updater.bat` |
| updater.bat | `C:\Users\Administrator\...\Startup\updater.bat` | Batch contents shown in the Details column |

The Startup folder row included the full script text in the results, so the payload could be read and judged without going back to the host.

Three more rows were noise. The artifact searches for `CurrentVersion\Run*\*`, and that wildcard also matches a key called `RunNotification`. Those rows are explained in section 7.5.

**A note on the Enabled column.** The planted Run key showed as `disabled`, and it would have run at the next logon anyway. That column reads the `StartupApproved` keys, which track what a user has switched off in Task Manager. An entry with no `StartupApproved` record gets reported as `disabled` rather than as unknown. Treat the column as a hint and confirm against the key itself.

### 7.2 The disconnected session

The collection was repeated after closing the RDP window. The results were identical, registry rows included. The user's registry file had not unloaded.

```
query user
```

```
 USERNAME     SESSIONNAME    ID  STATE   IDLE TIME  LOGON TIME
 administrator                2  Disc    11         8/22/2026 9:03 PM
```

```
reg query HKU
```

```
HKEY_USERS\.DEFAULT
HKEY_USERS\S-1-5-19
HKEY_USERS\S-1-5-20
HKEY_USERS\S-1-5-21-3205830668-3599923109-2036419528-500
HKEY_USERS\S-1-5-21-3205830668-3599923109-2036419528-500_Classes
HKEY_USERS\S-1-5-18
```

Closing an RDP window only drops the connection. The Windows session keeps running in a disconnected state, and the user's registry file stays loaded for as long as that session lives.

This cuts both ways in practice. Persistence belonging to a disconnected user is still visible to a live search, which helps the analyst. At the same time, a machine with nobody apparently logged in can still be holding user registry files open, so any conclusion drawn from `HKEY_USERS` needs the session state checked alongside it.

The session was then ended properly:

```
logoff 2
```

### 7.3 Live collection, user signed out

With session 2 gone and the registry file unloaded, `Windows.Sys.StartupItems` was collected a fourth time. Four rows came back.

| Collection | Administrator session | Run key found | Startup folder found |
|---|---|---|---|
| 1, baseline | Active | Not present | Not present |
| 2, after execution | Active | Yes | Yes |
| 3, after execution | Disconnected | Yes | Yes |
| 4, after execution | Signed out | **No** | Yes |

Nothing about the persistence changed between collections 2 and 4. Only what the tool could see changed.

Scale that to a real network and it becomes a serious gap. On a fleet where most people are signed out at any given time, a live search for user Run keys only inspects the handful of registry files that happen to be loaded. The Startup folder drop survived every collection, because files on disk stay put no matter who is logged in.

### 7.4 Reading the registry file off disk

The `Windows.Registry.NTUser` artifact solves this. It finds each user's `NTUSER.DAT` file, reads it straight from the disk to get around the lock Windows normally holds on it, and then searches inside. Every user profile on the machine, whether anyone is logged in or not.

The default search path targets file dialog history. It was replaced with:

```
Software\Microsoft\Windows\CurrentVersion\Run\*
```

Collected with Administrator signed out, it found the key:

```json
{
  "OSPath": {
    "DelegateAccessor": "ntfs",
    "DelegatePath": "C:\\Users\\Administrator\\NTUSER.DAT",
    "Path": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdater"
  },
  "Data": {
    "type": "REG_SZ",
    "data_len": 56,
    "value": "C:\\Users\\Public\\updater.bat"
  },
  "Mtime": "2026-08-23T01:16:02Z",
  "Username": "Administrator",
  "Uid": "500",
  "UUID": "S-1-5-21-3205830668-3599923109-2036419528-500",
  "Directory": "C:\\Users\\Administrator"
}
```

This gives more than the live query did:

- **A clear source.** `OSPath` names the exact file that was read and the position inside it.
- **A timestamp.** `Mtime` is the last time the key was written, `2026-08-23T01:16:02Z`. The live artifact returns no timestamp at all. In a real case this single field often anchors the whole timeline.
- **A name.** Velociraptor looked the SID up in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` and returned `Administrator` directly.

The `data_len` of 56 for a 27-character path reflects how Windows stores registry text, at two bytes per character plus a two-byte end marker.

### 7.5 Fleet hunt

The same artifact was then run as a hunt, which is how it would be used during a real incident. Hunt results arrive already tagged with the client ID, hostname, and flow ID, and land in one combined result set across every machine that answers.

From the client-side log:

```
INFO   Starting query execution for Windows.Registry.NTUser.
INFO   Collection Windows.Registry.NTUser is done after 282.0316ms
DEBUG  Query Stats: {"RowsScanned":15,"PluginsCalled":12,"FunctionsCalled":11}
```

Opening the registry file, searching the key, looking up the SID, and returning the answer took 282 milliseconds. Running this across a whole fleet costs almost nothing on the endpoint. What actually slows a hunt down is how many machines are powered on, which is why Velociraptor hunts stay open for a week by default and pick up machines as they come back.

### 7.6 Comparing against the logs

Velociraptor describes the host as it is now. Sysmon and Winlogbeat captured the moment it changed. Both were compared in Kibana.

**Sysmon Event ID 1, process created, `2026-08-23T01:16:02.496Z`:**

```
Image: C:\Windows\System32\reg.exe
CommandLine: "C:\Windows\system32\reg.exe" add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v OneDriveUpdater /t REG_SZ /d C:\Users\Public\updater.bat /f
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
User: AEROLAB\Administrator
IntegrityLevel: High
TerminalSessionId: 2
LogonId: 0x1eb1fc
ProcessGuid: {153CABC0-49D2-6A8A-E601-000000000500}
```

**Sysmon Event ID 13, registry value set, `2026-08-23T01:16:02.522Z`:**

```
RuleName: T1060,RunKey
TargetObject: HKU\S-1-5-21-3205830668-3599923109-2036419528-500\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdater
Details: C:\Users\Public\updater.bat
Image: C:\Windows\system32\reg.exe
User: AEROLAB\Administrator
ProcessGuid: {153CABC0-49D2-6A8A-E601-000000000500}
```

Twenty-two milliseconds separate the two, and the shared `ProcessGuid` ties them together for certain.

Four things stand out.

**The path gets rewritten.** The command line says `HKCU`. The registry event says `HKU\S-1-5-21-...-500`. Sysmon expands the shorthand into the real path before writing the log. Any rule looking for the text `HKCU` in `TargetObject` will never fire.

**The user field is a trap.** `winlog.user.name` reads `SYSTEM` on both records. That is the account Sysmon itself runs under, and it says SYSTEM no matter who caused the activity. The real actor is in `winlog.event_data.User`, which reads `AEROLAB\Administrator`.

**Technique tags are inherited, and can be out of date.** The SwiftOnSecurity configuration labeled the registry event `T1060,RunKey`. T1060 is the old ID for this technique, replaced by T1547.001. The label reflects what the configuration author mapped at the time. Event ID 1 carried `RuleName: -`, meaning no tag at all. Searching by tag finds only what the configuration author thought to label.

**Two sources agree.** Velociraptor read `Mtime: 2026-08-23T01:16:02Z` from the registry file. Sysmon logged the write at `01:16:02.518`. Two separate methods, same second.

**The RunNotification rows explained.** A third Event ID 13 fired at `01:16:12.562Z`, ten seconds after the persistence was created:

```
Image: C:\Windows\system32\sihost.exe
TargetObject: HKU\S-1-5-21-...-500\Software\Microsoft\Windows\CurrentVersion\RunNotification\OneDriveUpdater
Details: DWORD (0x00000001)
```

Shell Infrastructure Host noticed a new startup item and made a note to tell the user about it. The three unexplained rows in section 7.1 were Windows reacting to the intrusion, and now the process and time behind them are known.

This feeds straight into rule design. A rule matching `CurrentVersion\*Run*` fires on the attacker and on `sihost.exe` doing normal housekeeping.

**Available but not done.** `LogonId: 0x1eb1fc` links to the Security log 4624 event that created session 2, which would give the source IP of the RDP connection. Sysmon Event ID 11 records for the two file drops were also in the index but were not looked at. Both are follow-up work.

---

## 8. Detection rule

Built from the events collected here rather than adapted from an existing rule.

```yaml
title: Run Key Persistence Pointing To User Writable Path
id: d739de1b-2c15-403a-b081-f9c72886483d
status: experimental
description: |
  Detects a value written to a CurrentVersion\Run key where the payload sits in a
  user writable location or is a script file type. Legitimate software normally
  registers Run entries pointing at signed programs under Program Files or System32,
  so a Run value referencing Public, AppData, ProgramData or Windows\Temp is a common
  and low effort persistence method.
references:
  - https://attack.mitre.org/techniques/T1547/001/
author: Aeronique
date: 2026-08-23
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  product: windows
  category: registry_set
detection:
  selection_key:
    TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\'
  selection_payload_path:
    Details|contains:
      - '\Users\Public\'
      - '\AppData\Local\Temp\'
      - '\AppData\Roaming\'
      - '\ProgramData\'
      - '\Windows\Temp\'
  selection_payload_ext:
    Details|endswith:
      - '.bat'
      - '.cmd'
      - '.vbs'
      - '.js'
      - '.jse'
      - '.wsf'
      - '.hta'
      - '.ps1'
      - '.scr'
  condition: selection_key and 1 of selection_payload_*
fields:
  - TargetObject
  - Details
  - Image
  - User
falsepositives:
  - Installers and updaters that place a helper script under AppData or ProgramData
  - Backup and sync agents that register a launcher from a user profile folder
level: medium
```

### 8.1 Why it is written this way

**The trailing backslash in `\CurrentVersion\Run\`** It rules out `RunNotification` and `RunOnce` automatically, so the `sihost.exe` housekeeping never reaches the rest of the logic. No exclusion block needed.

**No filter on `Image`.** Skipping anything in `System32` looks like an easy way to cut noise, and it would switch this detection off completely, since `reg.exe` lives there. Signed built-in Windows programs are the preferred tools of most intrusions. The location of the payload is what carries the signal.

**Payload location over which program wrote it.** A Run value pointing at a signed program in Program Files is ordinary. The same key pointing at a batch file in a folder anyone can write to is worth a look. The rule is built around that difference.

### 8.2 Testing it

Tested in Kibana against the full index:

```
event.code:13 and winlog.event_data.TargetObject:*\\CurrentVersion\\Run\\* and (winlog.event_data.Details:*\\Users\\Public\\* or winlog.event_data.Details:*.bat)
```

One result, `record_id: 11070`, the planted persistence. Nothing else matched.

Two limits on that. The index covers one lightly used domain controller with a short history, so a clean result shows the rule is accurate on this data rather than proven at scale. The KQL also tests only part of what the rule covers, since checking every payload path and file type in Discover would take a dozen queries. The full rule matches more, and would produce more false alarms on a busy fleet of workstations, especially around `\AppData\Roaming\`, where real sync software often registers a launcher.

---

## 9. Findings

1. **Live searching of user Run keys is unreliable by design.** It only looks at registry files that are currently loaded. On a fleet where most people are signed out, most files are not loaded, and the persistence is invisible without anyone hiding it.

2. **Check session state before trusting HKEY_USERS.** A disconnected RDP session keeps a user's registry file loaded indefinitely. No interactive user does not mean no loaded profile.

3. **Reading the file off disk closes the gap for almost nothing.** `Windows.Registry.NTUser` returned complete results in 282 milliseconds and supplied a timestamp and a username the live method could not.

4. **Filesystem persistence shows up more consistently than registry persistence.** The Startup folder drop appeared in all three collections after execution. The Run key appeared in two of three.

5. **Endpoint tools and logs answer different questions.** Velociraptor showed what exists on the host. Sysmon showed when it was created, by which program, launched from where, and under which account. Neither one alone supports a complete finding.

6. **Sysmon rewrites `HKCU` as `HKU\<SID>` before logging.** Rules written against the command-line version of the path fail silently.

7. **Inherited technique tags need checking.** The configuration in use labels this technique with a retired ATT&CK ID and does not tag the matching process-create event.

---

## 10. Cleanup

```powershell
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveUpdater /f
Remove-Item "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.bat" -Force
Remove-Item C:\Users\Public\updater.bat -Force
Remove-Item C:\Users\Public\beacon.log -Force -ErrorAction SilentlyContinue

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunNotification" /v OneDriveUpdater /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunNotification" /v updater.bat /f
```

If `beacon.log` exists before deletion, the payload ran at least once, which confirms the persistence worked rather than only looked like it would.

To verify, collect `Windows.Sys.StartupItems` once more and compare against the section 5 baseline. Three rows means a clean return.

The Sysmon records stay, and should. The delete commands generate their own Event ID 1 and Event ID 13 entries, so the index now holds the whole story from creation to removal. An intruder cleaning up after themselves leaves exactly this pattern.

---

## 11. Timeline

All times UTC.

| Time | Event | Source |
|---|---|---|
| 01:03 (21:03 local) | Administrator logs on, RDP session ID 2 | `query user` |
| 01:15:13.894 | Reference time recorded | PowerShell |
| 01:15:xx | `updater.bat` written to `C:\Users\Public` | Filesystem |
| 01:16:02.496 | `reg.exe` starts, launched by `powershell.exe` | Sysmon EID 1 |
| 01:16:02.518 | Run key value written | Sysmon EID 13 |
| 01:16:02 | `NTUSER.DAT` Run key last write time | Velociraptor `Mtime` |
| 01:16:12.562 | `sihost.exe` writes RunNotification entry | Sysmon EID 13 |
| 01:43 | Hunt run, 282 ms on the client | Velociraptor hunt log |

---

## 12. Follow-up work

- Look at the Sysmon Event ID 11 records for the two file drops.
- Follow `LogonId: 0x1eb1fc` to the 4624 in the Security log to get the RDP source address.
- Repeat the exercise against a second endpoint once aero-w11 is built, so the hunt covers more than one client.
- Write a companion rule for Startup folder file creation using Event ID 11.
- Measure how many false alarms `\AppData\Roaming\` produces on a workstation with normal software installed.
- Deploy the Sigma rule as a scheduled Elastic detection rule and track alert volume for a week.

---

## Appendix A: Artifacts used

| Artifact | Purpose |
|---|---|
| `Windows.Sys.StartupItems` | Live listing of Run keys and Startup folders |
| `Windows.Registry.NTUser` | Reads each user's `NTUSER.DAT` file directly from disk |

## Appendix B: Collection reference

| Flow | Artifact | Result |
|---|---|---|
| Baseline | `Windows.Sys.StartupItems` | 3 rows |
| After execution, session active | `Windows.Sys.StartupItems` | 8 rows |
| After execution, session disconnected | `Windows.Sys.StartupItems` | 8 rows |
| After execution, session ended | `Windows.Sys.StartupItems` | 4 rows |
| `F.DA54VEIU61NB0.H` | `Windows.Registry.NTUser` (hunt) | 1 row, 282 ms |

*AI Disclaimer: The method, writing, execution, and collections are my own. AI is used to edit for clarity, and format data into the report.*
