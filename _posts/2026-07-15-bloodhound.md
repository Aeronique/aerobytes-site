---
layout: writeup
title: "BloodHound"
date: 2026-07-15
category: hacksmarter
tags: [active-directory, bloodhound, sharphound, netexec, dcsync]
excerpt: "Collecting Active Directory data with five different ingestors, mapping the attack paths in BloodHound, and walking one low-privilege account all the way to domain compromise through a DCSync attack on a Hack Smarter lab."
permalink: /writeups/bloodhound/
---

BloodHound is one of those tools that makes Active Directory finally make sense. It takes the tangled pile of users, groups, and permissions inside a domain, works out who can reach whom, and draws the whole thing as a graph you can follow. This Hack Smarter lab, over at [www.hacksmarter.org](https://www.hacksmarter.org), is a friendly introduction to it. You begin with a single set of low-privilege credentials, and the job is to collect the domain data, load it into BloodHound, and follow the paths it lays out until you reach the domain administrator.

```
Username: pentest
Password: HackSmarter123!
```

---

## Collecting the data

BloodHound is only ever as good as the data you hand it, so before any of the fun graphing happens, you have to pull that data out of the domain. A handful of ingestors all produce the same JSON, and picking one really comes down to the platform you are working from and how the target is set up. I worked through five of them here, since it helps to know your options for the moments when one tool stalls and another gets the job done.

### NetExec

NetExec is where I like to start. It checks that the credentials work and then runs the collection in the same session, so you get your confirmation and your data without hopping between tools. First, make sure the credentials are valid over SMB.

`nxc smb [DC] -u '[USERNAME]' -p '[PASSWORD]' --shares`

![NetExec confirming the pentest credentials are valid over SMB](/assets/images/bloodhound/1.png)

*The `+` beside the credentials is what tells you they are good, and taking that half a second to confirm saves you from chasing errors later that were never really there.*

Once you know the login works, point NetExec at LDAP and let its built-in BloodHound collector do the gathering.

`nxc ldap [DC-IP] -u '[USERNAME]' -p '[PASSWORD]' --bloodhound --collection All --dns-server [DC-IP]`

![NetExec running BloodHound collection over LDAP](/assets/images/bloodhound/2.png)

*One command runs the collector across every collection method, which is a big part of why NetExec is such a comfortable place to begin.*

The run drops a zip file, and unzipping it hands you the JSON documents you will load into BloodHound a little later.

![Unzipping the NetExec output to reveal the collected JSON files](/assets/images/bloodhound/3.png)

*Everything BloodHound needs is sitting inside that archive once it is unzipped.*

### SharpHound

SharpHound is the C# collector that runs right on a Windows target, and it is the one Defender is quick to flag, so do not be surprised when it gets caught as malware the moment it touches disk. You can grab it from [SpecterOps' GitHub releases](https://github.com/SpecterOps/SharpHound/releases).

To get it onto the box, open a session on the domain controller with evil-winrm using the same credentials you already have.

`evil-winrm -i [DC] -u '[USERNAME]' -p '[PASSWORD]'`

![evil-winrm session opened against the domain controller](/assets/images/bloodhound/4.png)

*evil-winrm gives you a proper interactive session on the domain controller, all from the credentials you started with.*

From inside that session, upload SharpHound to the target.

`upload /path/to/SharpHound.exe`

![Uploading SharpHound.exe to the target through evil-winrm](/assets/images/bloodhound/5.png)

*The `upload` command drops SharpHound.exe straight onto the target for you.*

Give it a quick `dir` to make sure the file really landed.

![Confirming the SharpHound upload with dir](/assets/images/bloodhound/6.png)

*There it is, sitting on the target and ready to run.*

Now run SharpHound and let it collect across every method.

`.\SharpHound.exe -c All`

![Running SharpHound with the All collection method](/assets/images/bloodhound/7.png)

*The `-c All` flag tells SharpHound to gather everything it knows how to gather.*

When it finishes, SharpHound writes the results to a zip file in whatever directory you are working from on the target.

![SharpHound saving its collection output to a zip file on the target](/assets/images/bloodhound/8.png)

*The collection saves as a zip right there on the compromised machine.*

Pull that zip back to your own machine with `download`.

`download [FILE]`

![Downloading the SharpHound zip back to the attacking machine](/assets/images/bloodhound/9.png)

*The `download` command brings the archive back to your local system.*

And with that, the collected files are ready to go.

![The collected JSON files after extracting the SharpHound output](/assets/images/bloodhound/10.png)

*The extracted documents, waiting to be loaded into BloodHound.*

### RustHound

RustHound is a cross-platform ingestor written in Rust, and it is a lovely little tool to have on hand. It compiles down to one small, quick binary for either Linux or Windows, and since it leans on no .NET at all, it stays light enough to drop onto almost any host without a second thought.

Run it against the domain controller with your credentials and let it collect.

`./rusthound -d [DC] -u 'username' -p 'password' -n [DC-IP] -o ./rusthound_output`

![RustHound collecting data from the domain controller](/assets/images/bloodhound/11.png)

*RustHound reaches out to the domain controller and writes everything into an output directory.*

Change into that output directory and you will find the data already in its original JSON form, saved for you without any zipping to deal with first.

![The RustHound output directory holding the collected JSON files](/assets/images/bloodhound/12.png)

*RustHound leaves the data plain and unzipped, which is one less step before ingestion.*

### bloodhound-python

When you are working entirely from Linux, bloodhound-python is a comfortable choice. It is a Python ingestor that queries the domain controller over LDAP and asks for nothing you would not already have on a Linux box.

`bloodhound-python -u 'username' -p 'password' -d [DOMAIN] -dc [DC-HOSTNAME] -c All -ns [DC-IP]`

![bloodhound-python querying the domain controller over LDAP](/assets/images/bloodhound/13.png)

*bloodhound-python queries the domain controller over LDAP straight from your Linux terminal.*

Once it finishes, the output saves into whatever directory you happened to be working in.

![The JSON files produced by bloodhound-python](/assets/images/bloodhound/14.png)

*The freshly collected JSON, sitting in the current working directory.*

### bloodyad

bloodyad takes a little patience the first time, since its syntax is a bit particular, but it earns that patience quickly. It reliably pulls data from Windows Server 2025 even in the moments where NetExec and bloodhound-python come up short, so it is a good one to have ready for stubborn targets.

`bloodyad -H [DC-HOSTNAME] -d [DOMAIN] -u 'username' -p 'password' get bloodhound`

![bloodyad collecting BloodHound data from Windows Server 2025](/assets/images/bloodhound/15.png)

*bloodyad saves its output locally as a zip file in your working directory.*

Whichever route you take, you end up in the same place, with a full set of data ready to load into BloodHound.

---

## Launching BloodHound

BloodHound ships with a CLI distribution from SpecterOps, written in Go, that quietly handles the container setup, the configuration, and the log wrangling so you do not have to. It runs happily on Windows, Linux, and macOS.

Grab the build that matches your system, unzip it, add `bloodhound-cli` to your path, then start up a local instance and open it in your browser.

![Starting a local BloodHound instance with bloodhound-cli](/assets/images/bloodhound/16.png)

*bloodhound-cli spins up a local instance that you reach through the browser.*

### Loading the data

Head to Administration > File Ingest and upload the JSON files from whichever collector you used. BloodHound takes them all the same way, so it does not care which tool did the gathering.

![Uploading the collected JSON files through Administration then File Ingest](/assets/images/bloodhound/17.png)

*File Ingest happily accepts the JSON from any of the collectors above.*

### Built-in queries

Under Explore > CYPHER, BloodHound gives you a whole set of prewritten queries you can fire off with a single click, which means you can get straight to the interesting findings without having to write any Cypher by hand.

![The built-in Cypher queries under Explore then Cypher](/assets/images/bloodhound/18.png)

*The prewritten queries waiting under Explore > CYPHER.*

The queries I reach for first:

- **Paths from Domain Users to Tier Zero / High Value Targets.** This is the big one, the query that traces every known relationship from the lower-privileged objects all the way up to the highest tier of administrative control.
- **Shortest paths to Domain Admins.** This one narrows things down to the quickest route to a Domain Admin account, and reaching one of those means the entire domain is yours.
- **Find AS-REP Roastable / Kerberoastable Users.** This surfaces the accounts that are exposed to offline credential cracking, which often gives you an easy early foothold.

BloodHound draws the answer as a live map, laying the targets out on the right and the starting points you can use over on the left, so the route between them is easy to trace.

![BloodHound drawing an attack path from low-privilege users to high value targets](/assets/images/bloodhound/19.png)

*Targets on the right, usable starting points on the left, and the path drawn in between.*

### User nodes

Clicking on a user node opens a side panel packed with the account's properties and its relationships, and that panel quickly becomes the thing you spend most of your time reading.

![The side panel that opens when selecting a user node](/assets/images/bloodhound/20.png)

*The side panel holds all the useful detail for whichever account you select.*

### Outbound Object Control

Outbound Object Control is the view I keep coming back to. It lays out every account a given user can act against, and that list is exactly the trail an attacker follows when they are looking for lateral movement and a way to climb.

![The Outbound Object Control view for a user showing accounts it can act against](/assets/images/bloodhound/21.png)

*Outbound Object Control shows every account this user is able to act against.*

### ACLs

Active Directory leans on ACLs to decide who is allowed to modify what, and BloodHound lets you click on any edge to see the explicit control one object holds over another.

![Clicking an edge to see the explicit ACL control between two objects](/assets/images/bloodhound/22.png)

*Each edge spells out exactly what control one object has over the next.*

That same view is useful whichever side you are on. An attacker reads it to find their next target, and a defender reads it to spot the rights that were never supposed to be there in the first place.

---

## The challenge

With the domain mapped out, the challenge is to recover the flag tucked away at `C:\Users\Administrator\Desktop\root.txt`, and you get to do it starting from the very same low-privilege credentials the lab handed you at the beginning.

```
username: pentest
password: HackSmarter123!
```

Start by tracking down the `pentest` user inside BloodHound.

![Searching for the pentest user in BloodHound](/assets/images/bloodhound/23.png)

*Finding the `pentest` user to work forward from.*

It turns out `pentest` has Outbound Object Control over the `backup_svc` user, and BloodHound is kind enough to spell out every way you can abuse that control.

![The pentest user's Outbound Object Control over the backup_svc account](/assets/images/bloodhound/24.png)

*`pentest` can act against `backup_svc`, and BloodHound lays every option out for you.*

Since I was running this lab on Linux, I followed the Linux Abuse path and used it to change the `backup_svc` account password.

`net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"`

![Changing the backup_svc account password with net rpc](/assets/images/bloodhound/25.png)

*The Linux Abuse path resets the `backup_svc` password with a single `net rpc` command.*

No output at all is the good sign here, since it means the password change went through cleanly. Confirm you really do have the account by checking the SMB shares with NetExec.

![NetExec confirming access to backup_svc after the password change](/assets/images/bloodhound/26.png)

*NetExec confirms the freshly set `backup_svc` credentials are working over SMB.*

Back in BloodHound, right click the user and mark it as Owned now that the account belongs to you, which keeps the map honest as your path grows.

![Marking backup_svc as Owned in BloodHound](/assets/images/bloodhound/27.png)

*Marking the account as Owned keeps the picture accurate as you move forward.*

We are still short of any real admin rights, so the enumeration keeps going from this new account, and the first thing to read is its Outbound Object Control.

![The backup_svc account's Outbound Object Control over the domain controller](/assets/images/bloodhound/28.png)

*`backup_svc` turns out to carry rights against the domain controller itself.*

This is the moment the lab gets exciting. `backup_svc` holds `GetChanges` and `GetChangesAll` over the domain controller, and reading the description on those rights points straight at a DCSync attack.

![The GetChanges and GetChangesAll rights that enable a DCSync attack](/assets/images/bloodhound/29.png)

*`GetChanges` and `GetChangesAll` together are what open the door to DCSync.*

A DCSync attack asks the domain controller to replicate its directory data and, in doing so, dumps the password hashes for every account it holds. Pulling the krbtgt hash along the way can also set you up for a Golden Ticket attack down the line. NetExec handles the DCSync for you.

`nxc smb [DOMAIN CONTROLLER] -u 'username' -p 'password' --ntds`

![NetExec dumping the domain hashes with the ntds option](/assets/images/bloodhound/30.png)

*The DCSync pulls every user hash straight off the domain controller.*

With all of those hashes in hand, grab the NTLM hash for the `tyler_adm` account and pass it to evil-winrm to open an administrative session.

`evil-winrm -i [DOMAIN CONTROLLER] -u 'username' -H 'NTLM HASH'`

![Passing the tyler_adm NTLM hash to evil-winrm for access](/assets/images/bloodhound/31.png)

*Passing the `tyler_adm` hash to evil-winrm lands you an administrative session.*

That drops you into an administrative shell, and the flag is sitting right there on the desktop waiting for you.

![Reading root.txt from the administrator desktop](/assets/images/bloodhound/32.png)

*root.txt, recovered from the administrator's desktop.*

What I really enjoyed about this lab is how far plain enumeration carried the whole thing. Reading Outbound Object Control at each step was enough to turn one low-privilege account into control of the entire domain, first by resetting a forgotten service account password, and then by using that account's replication rights to run a DCSync and walk away with everything.

---

## Defensive takeaways

- **Audit Outbound Object Control and dangerous ACLs.** The entire path here rode on write and replication rights that reached a good deal further than they ever needed to. Take a regular look at who holds `GenericAll`, `GenericWrite`, and write access over your service and privileged accounts, and quietly pull back anything that is not doing real work.
- **Watch for service account password resets.** The very first move was a `net rpc password` reset against `backup_svc`, so Event ID 4724 (a password reset attempt) and 4738 (an account being changed) on service accounts are both well worth alerting on.
- **Detect DCSync.** Replication rights like `GetChanges` and `GetChangesAll` really only belong to domain controllers, so a replication request coming from anything else is a strong sign of DCSync in progress. You can catch it through directory service access auditing and Event ID 4662 with the replication GUIDs.
- **Run BloodHound against your own domain.** The same collectors and queries an attacker would use will happily show you the shortest paths to Tier Zero inside your own environment, which gives you the chance to close them before anyone else goes looking.
