---
layout: writeup
title: "Teaching Ghidra to Name glibc in Stripped Static Binaries"
date: 2026-07-18
category: research
tags: [ghidra, reverse-engineering, function-id, bsim, glibc, static-analysis]
excerpt: "Building reusable Function ID and BSim databases for Ghidra so it names the glibc functions in stripped, statically linked binaries on its own, which leaves the program's own code as the only thing left to read."
permalink: /writeups/ghidra-glibc-fid/
---

A stripped, statically linked Linux binary contains the entire C library with all symbol names removed. Ghidra loads it as a large set of functions named `FUN_<address>`, with no imports to identify them. Most of those functions are library code. A few are the program's own.

If you've opened one of these, you know the feeling. You came for one function and the disassembler hands you a thousand, every one named after its address and nothing else to go on.

The scripts and full recipe are in [`ghidra-glibc-fid`](https://github.com/Aeronique/ghidra-glibc-fid).

A few terms first, so the rest reads cleanly:

- A symbol is a name bound to an address, like `main` or `printf`. Compilers emit them. A stripped binary has had them removed.
- Statically linked means the C library was copied into the binary at build time. A dynamically linked binary loads the library at run time and keeps its import names, so library calls stay labeled. A static binary keeps no such labels once it's stripped.
- glibc is the GNU C Library. Linked statically, it can add well over a thousand functions to a binary.

On a test target, a CTF binary named "printf to pay respects," Ghidra found 1,161 functions. After full analysis, 7 had names, all from the loader. One of the rest was the program's own code. The other 1,153 were glibc, taking up space and giving me nothing to work with.

## Why a Reusable Database

You can identify library functions by hand, by reading their code and their calls. That work doesn't persist. It covers one binary and has to be redone on the next, because nothing carries between files. Do it a few times and it gets old.

A reusable database fixes that. Ghidra can fingerprint known library functions once, store the fingerprints with their names, and apply them automatically to every binary you analyze afterward. Whatever stays unnamed is the program's own code, which is the part you came for.

## Function ID

Function ID (FID) is a Ghidra feature. It computes a hash of each function's instructions and stores the hash with the function's name in a database. During analysis it hashes every function in your target and checks for a matching hash. A match applies the name.

Ghidra ships with FID databases, but they lean toward Windows software and carry little Linux glibc. On the test target they matched nothing, which is how I ended up with 1,160 anonymous functions to sort out.

### Source Libraries

Fingerprinting glibc needs copies of glibc that still have symbols. Docker images are the clean source, one version per image. I used four Ubuntu releases:

- Ubuntu 18.04: glibc 2.27
- Ubuntu 20.04: glibc 2.31
- Ubuntu 22.04: glibc 2.35
- Ubuntu 24.04: glibc 2.39

The files you want are the static library archives, the `.a` files. A `.a` archive holds many object files, each with one or a few functions. FID works on individual functions, so that granularity is the whole point.

### Building the Database

Three steps:

1. Import each `.a` archive into a Ghidra project with recursion enabled, so the archive expands into its member object files. Forget the recursion and it imports as one blob with nothing to fingerprint, which I mention because I did exactly that the first time.
2. Analyze the imported programs, so each function has disassembled instructions to hash.
3. Populate the database, hashing every function and storing the hash with its name and glibc version.

Each step is scripted, so the whole thing is repeatable and menu-free. The scripts are in the repo. The first build held 29,578 functions across the four glibc versions, in 32-bit and 64-bit.

## Matching the Target Toolchain

I attached the database, ran FID on the test target, and the named count went from 7 to 144. Good, except the three functions I wanted, the `fopen`, `fgets`, and `printf` calls in the target, were not among them, which sent me looking for why.

Here's the part I wish someone had told me before I spent an afternoon on it. Read the compiler string first. Every binary records the compiler that built it, and one command shows it:

```
strings -a <binary> | grep -iE 'glibc|release version|GCC:'
```

The target said `GCC 15.2.1 20250813`. That's a rolling-release compiler version, newer than anything the four Ubuntu releases ship.

FID matches on exact instruction bytes. The same glibc function compiled by a different GCC produces different bytes, the hashes differ, and no match happens. The 144 hits were mostly dynamic-linker functions that stay identical across builds. The rest of glibc had been built by a newer compiler and sailed right past my database. My four Ubuntu versions were the wrong library, and one string at the start would have saved the afternoon.

## Getting the Exact Match

The binary was built on Arch, and Arch keeps a dated archive of every package it has ever shipped, so there was no guessing. I pulled the glibc that was live on Arch on the compiler's build date, August 13, 2025, which is the exact library the author linked against. It was glibc 2.42.

A database built from that one library, attached beside the first, took the named count from 144 to 656, and `puts` resolved correctly. The exact match worked, which is the payoff for reading the string I should have read on day one.

## Function ID Limitations

Three functions in the target were still wrong or missing after the exact match. These are structural limits of hash matching, worth knowing so you don't chase them.

- `printf` matched as `wscanf`. The variadic wrapper functions, `printf`, `fprintf`, `scanf`, `wscanf`, set up their arguments with identical instructions and differ only in one internal pointer. Their hashes are the same, so FID can't tell them apart and picks a name. This time it picked one and got it wrong.
- `fopen` didn't match. It's a 13-byte stub that jumps to an internal function, under the size FID bothers to fingerprint.
- `fgets` didn't match either.

You fix this handful by hand, which is normal. FID names the bulk, you clean up the stragglers. Each wrapper gives itself away through the internal function it calls, which FID does name. `fopen`'s stub calls `__fopen_internal`, so it's easy to identify by hand.

## BSim

BSim is Ghidra's second matcher. It compares the structure of the decompiled function and the data it references, so it can match functions across compiler versions and separate functions that look byte-identical to FID. It picks up where exact matching gives out.

You drive it differently. FID names things on its own during analysis. BSim you query. You open a binary, run a search over its functions, and apply the matches, one query and one apply per file.

I built the BSim database from the same glibc programs I'd already imported, so there was nothing extra to download. Running BSim Overview on the test target reported matches across all 843 functions.

Two numbers tell you what to trust:

- Hit count: how many database functions resemble the one you're looking at. A high count means generic, weak evidence.
- Significance: how distinctive the function is. High significance with a low hit count means distinctive, and a strong similarity match there is solid.

Sort by significance and work down from the standouts. BSim returned nothing for the one function I wrote, which is exactly what you'd want, since it means that function isn't in any library. By the same logic, the functions with no matches are your shortlist to read.

## When to Use Each

- Function ID: automatic naming during analysis, for library builds already in your database.
- BSim: manual per-binary queries, for the larger functions FID missed and for binaries whose exact build you don't have.
- Small variadic wrappers and stub functions dodge both. Those you name yourself.

## Adding a New Build

When a binary comes up empty, its build isn't in your database yet. Adding it is the same routine every time:

1. Read the compiler string: `strings -a <binary> | grep -iE 'glibc|GCC:'`.
2. Get that glibc version. For a rolling-release distro, use the dated package archive.
3. Import and populate it.
4. Re-attach and run again.

The scripts for all of it are in the repo. Take them, and when a stubborn binary shows up, fix them, because that's half the fun of building your own.

## Resources

- [ghidra-glibc-fid](https://github.com/Aeronique/ghidra-glibc-fid), the scripts and build for this project
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Arch Linux Archive](https://archive.archlinux.org/)
- [Ubuntu images on Docker Hub](https://hub.docker.com/_/ubuntu)
- [My GitHub](https://github.com/Aeronique)
