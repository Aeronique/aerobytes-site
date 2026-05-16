---
layout: writeup
title: "PowerAnalysis: Warmup"
date: 2026-02-03
category: picoctf
tags: [picoctf, cryptography, side-channel, power-analysis, correlation-attack]
back_url: /writeups/
back_label: "Writeups"
---

**Category**: Cryptography
**Points**: 400
**Difficulty**: Hard

![Power Analysis Warmup](/assets/images/picoctf/poweranalysis-warmup/power-analysis-warmup.png)

## Challenge Description

> This encryption algorithm leaks a "bit" of data every time it does a computation. Use this to figure out the encryption key. Download the encryption program here `encrypt.py`. Access the running server with `nc saturn.picoctf.net 52735`. The flag will be of the format `picoCTF{<encryption key>}` where `<encryption key>` is 32 lowercase hex characters comprising the 16-byte encryption key being used by the program.

**Given files**: `encrypt.py`
**Challenge server**: `nc saturn.picoctf.net 52735`

## Initial Reconnaissance

The challenge title "PowerAnalysis" immediately points to side-channel attacks. Let's examine the provided encryption script to understand exactly what information is leaking.

```python
#!/usr/bin/env python3
import random, sys, time

with open("key.txt", "r") as f:
    SECRET_KEY = bytes.fromhex(f.read().strip())

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    # ... (AES S-box values)
)

leak_buf = []
def leaky_aes_secret(data_byte, key_byte):
    out = Sbox[data_byte ^ key_byte]
    leak_buf.append(out & 0x01)  # Leaks the lowest bit!
    return out

def encrypt(plaintext, key):
    global leak_buf
    leak_buf = []
    ciphertext = [leaky_aes_secret(plaintext[i], key[i]) for i in range(16)]
    return ciphertext

def encrypt_and_leak(plaintext):
    ciphertext = encrypt(plaintext, SECRET_KEY)
    ciphertext = None
    time.sleep(0.01)
    return leak_buf.count(1)  # Returns count of '1' bits
```

### Understanding the Vulnerability

The server performs a simplified AES operation:
1. XORs each plaintext byte with the corresponding key byte
2. Looks up the result in the AES S-box
3. Leaks the lowest bit of each S-box output
4. Returns the total count of how many leaked bits were '1'

This is our side channel. Instead of revealing nothing about the internal state, the server tells us exactly how many S-box outputs had their lowest bit set to 1.

Testing manually:

```bash
echo "00000000000000000000000000000000" | nc saturn.picoctf.net 52735
```

Output:
```
Please provide 16 bytes of plaintext encoded as hex: leakage result: 4
```

So with an all-zeros plaintext, we get a leak count of 4. This means 4 of the 16 S-box outputs had their lowest bit set to 1.

## Approach

### The Attack Strategy

Since we can send arbitrary plaintext and observe the leak count, we can recover each key byte independently using a correlation attack.

The plan:
1. For each of the 16 key byte positions, send 256 different plaintexts (varying only that byte position) and record the leak count for each plaintext
2. For each possible key byte value (0x00 to 0xFF), calculate what the leaked bit *should* be for each plaintext and score how well this prediction correlates with actual observations
3. The key byte with the highest correlation score is the correct one

The leak reveals information specific to each byte position. When we vary `plaintext[i]` while keeping all other bytes constant:

```
Sbox[plaintext[i] ^ key[i]] & 0x01
```

The contribution from position `i` to the total leak changes based on our plaintext choice. The other 15 positions contribute constant "noise" that doesn't affect our correlation analysis since we're not varying those bytes.

### Correlation Scoring

For each key guess, we build a correlation score:

```python
for key_guess in range(256):
    for plaintext_value, observed_leak in observations:
        predicted_bit = Sbox[plaintext_value ^ key_guess] & 0x01
        
        if predicted_bit == 1:
            scores[key_guess] += observed_leak
        else:
            scores[key_guess] -= observed_leak
```

If our key guess is correct, the predicted bit will align with the leak patterns. When we predict a '1' bit and the actual leak count is high, we add to the score. When we predict a '0' bit and the leak is high (meaning other positions contributed those '1' bits), we subtract.

The correct key byte produces the highest absolute correlation score because its predictions consistently match reality.

### Building the Exploit

```python
from pwn import *
from collections import defaultdict

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

def query_server(plaintext):
    conn = remote('saturn.picoctf.net', 52735)
    conn.recvuntil(b'hex: ')
    conn.sendline(plaintext.hex().encode())
    response = conn.recvline().decode()
    conn.close()
    leak = int(response.split('leakage result:')[1].strip())
    return leak

def recover_key():
    key = []
    
    for pos in range(16):
        print(f"[*] Recovering key byte {pos}...")
        
        observations = []
        for pt_val in range(256):
            pt = bytearray([0] * 16)
            pt[pos] = pt_val
            leak = query_server(bytes(pt))
            observations.append((pt_val, leak))
        
        scores = defaultdict(int)
        for key_guess in range(256):
            for pt_val, actual_leak in observations:
                predicted_bit = Sbox[pt_val ^ key_guess] & 0x01
                if predicted_bit == 1:
                    scores[key_guess] += actual_leak
                else:
                    scores[key_guess] -= actual_leak
        
        best = max(scores.items(), key=lambda x: abs(x[1]))[0]
        key.append(best)
        print(f"    Found: 0x{best:02x}")
    
    return bytes(key)

if __name__ == '__main__':
    print("[*] Starting attack (4096 queries total)...\n")
    recovered_key = recover_key()
    flag = f"picoCTF{{{recovered_key.hex()}}}"
    print(f"\n[+] Key: {recovered_key.hex()}")
    print(f"[+] Flag: {flag}")
```

## Solution

Running the exploit against the server:

```bash
python3 solve.py
```

The attack makes 4,096 queries (16 bytes x 256 plaintexts) and recovers the key byte by byte:

```
[*] Starting attack (4096 queries total)...

[*] Recovering key byte 0...
    Found: 0x81
[*] Recovering key byte 1...
    Found: 0x80
[*] Recovering key byte 2...
    Found: 0x8c
[*] Recovering key byte 3...
    Found: 0x36
[*] Recovering key byte 4...
    Found: 0xfc
[*] Recovering key byte 5...
    Found: 0xa7
[*] Recovering key byte 6...
    Found: 0x28
[*] Recovering key byte 7...
    Found: 0x8b
[*] Recovering key byte 8...
    Found: 0x8a
[*] Recovering key byte 9...
    Found: 0x57
[*] Recovering key byte 10...
    Found: 0xf9
[*] Recovering key byte 11...
    Found: 0x09
[*] Recovering key byte 12...
    Found: 0x07
[*] Recovering key byte 13...
    Found: 0xcc
[*] Recovering key byte 14...
    Found: 0xba
[*] Recovering key byte 15...
    Found: 0xe6

[+] Key: 81808c36fca7288b8a57f90907ccbae6
[+] Flag: picoCTF{81808c36fca7288b8a57f90907ccbae6}
```

<details>
<summary><b>Flag</b> (click to reveal)</summary>

`picoCTF{81808c36fca7288b8a57f90907ccbae6}`

</details>

## Tools Used

- **pwntools** - Python library for network interaction and CTF automation
- **Python 3** - Scripting and statistical analysis

## References

- [Introduction to Power Analysis Attacks](https://en.wikipedia.org/wiki/Power_analysis)
- [Differential Power Analysis (DPA)](https://paulkocher.com/doc/DifferentialPowerAnalysis.pdf) - The original DPA paper by Paul Kocher
- [Side-Channel Attacks on Cryptographic Implementations](https://www.rambus.com/blogs/side-channel-attacks/)
- [AES S-box](https://en.wikipedia.org/wiki/Rijndael_S-box)
