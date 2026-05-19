# Wireshark & Network Traffic Analysis

**Environment:** Local Machine or Azure VM  
**Estimated Cost:** $0 — Wireshark is permanently free and open source  

---

## Project Goals

This lab builds the foundational packet analysis skills every network and security professional needs. By the end of it you can:

- Capture live network traffic from a real interface
- Apply display filters to isolate specific protocols and hosts
- Read a TCP three-way handshake and diagnose connection failures
- Identify DNS queries and responses at the packet level
- Extract cleartext credentials from unencrypted HTTP traffic
- Reconstruct a full TCP stream from raw packet fragments

---

## The Problem This Lab Solves

Every network event; a slow app, a failed login, a security alert, a service outage, leaves a trail in the packets. Without the ability to read that trail, you are guessing. With it, you have evidence.

The specific problems this lab addresses:

| Symptom | What Wireshark Shows |
|---|---|
| "The website isn't loading" | Missing SYN-ACK: server is unreachable or the port is closed |
| "DNS is broken" | Query goes out, no response returns: DNS server is down or blocked |
| "Someone might have my password" | HTTP POST packet with credentials visible in plaintext |
| "Something is calling out to the internet" | Unexpected DNS queries to unusual domains: potential C2 traffic |
| "I can't tell if it's client-side or server-side" | TCP stream shows which side sent malformed or missing data |

---

## Tools & Tech Stack

| Tool | Version | Purpose | Why This Tool |
|---|---|---|---|
| **Wireshark** | Latest stable | Packet capture and analysis | Industry standard. Free. Used in every security and network role. No alternative comes close for interactive traffic analysis. |
| **Npcap** (Windows) / **libpcap** (Linux/macOS) | Bundled with Wireshark | Kernel-level packet capture driver | Required for Wireshark to access raw network interfaces. Npcap is the modern, maintained replacement for WinPcap. |
| **tshark** | Bundled with Wireshark | Command-line packet capture | Enables headless captures on remote machines and servers where a GUI is not available. Same engine as Wireshark. |
| **nslookup** | OS built-in | Generate DNS traffic on demand | Built into every OS. No install required. Lets you trigger a DNS query at an exact moment during a capture. |

### Optional: Azure VM as Capture Host

If your local network is too restricted (corporate firewalls, managed switches that block promiscuous mode), you can run this lab on an Azure VM. The traffic profile is different but the skills are identical.

---

## Architecture

### How Wireshark Captures Traffic

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                │
│         Web Servers · DNS Servers · Remote Hosts               │
│         DNS:53 · HTTP:80 · HTTPS:443 · ICMP · TCP/UDP          │
└─────────────────────┬───────────────────────────────────────────┘
                      │  all frames
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ROUTER / SWITCH                               │
│         Home network or lab network — forwards all frames       │
└─────────────────────┬───────────────────────────────────────────┘
                      │  raw packets
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│               NETWORK INTERFACE CARD (NIC)                      │
│   Promiscuous mode — captures ALL packets on the segment,       │
│   not just packets addressed to your machine                    │
└─────────────────────┬───────────────────────────────────────────┘
                      │  decoded frames
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                       WIRESHARK                                 │
│   Decodes every packet · applies display filters                │
│   reassembles streams · reads every layer from                  │
│   Ethernet frame to application payload                         │
└──────┬──────────────┬───────────────┬───────────────┬───────────┘
       │              │               │               │
       ▼              ▼               ▼               ▼
  ┌─────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
  │ CAPTURE │   │  FILTER  │   │ ANALYSE  │   │  EXPORT  │
  │  Live   │   │ dns /    │   │Protocols │   │ .pcapng  │
  │ traffic │   │ ip.addr  │   │& streams │   │   file   │
  │   or    │   │ tcp/http │   │          │   │portfolio │
  │.pcapng  │   │          │   │          │   │          │
  └─────────┘   └──────────┘   └──────────┘   └──────────┘
```

### DNS Resolution Flow (Exercise A)

```
Your Machine                 DNS Server (e.g. 8.8.8.8)
     │                               │
     │── DNS Query (A record) ──────►│
     │   "What is the IP for         │
     │    google.com?"               │
     │                               │
     │◄─ DNS Response ───────────────│
     │   "google.com = 142.250.80.46"│
     │                               │
     │── TCP SYN ──────────────────► 142.250.80.46
     │   (Now connecting to the IP)
```

### TCP Three-Way Handshake (Exercise B)

```
Your Machine                      Remote Server
     │                                  │
     │──── SYN ────────────────────────►│
     │     Seq=0  "I want to connect"   │
     │                                  │
     │◄─── SYN-ACK ────────────────────│
     │     Seq=0, Ack=1  "Confirmed"    │
     │                                  │
     │──── ACK ────────────────────────►│
     │     Ack=1  "Ready to send data"  │
     │                                  │
     │    [Data transfer begins]        │

 ✅ All three packets present  = successful connection
 ❌ SYN with no SYN-ACK        = server unreachable or port closed
 ❌ RST after SYN              = connection forcibly refused
```

### HTTP vs HTTPS — Why Cleartext Matters (Exercise C)

```
HTTP (unencrypted) — anyone on the path can read this:
─────────────────────────────────────────────────────
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=SuperSecret123   ← VISIBLE TO WIRESHARK

─────────────────────────────────────────────────────
HTTPS (TLS encrypted) — packet contents are opaque:
─────────────────────────────────────────────────────
TLSv1.3 Record Layer: Application Data
  Encrypted Application Data: a3f2b8c1d4e5...  ← UNREADABLE
```

---

## Lab Exercises

### Exercise A — DNS Lookup Capture

  1. Start capture in Wireshark on your active interface
  2. In a separate terminal, run:
  `nslookup google.com`
  3. Stop the capture in Wireshark
  4. Apply filter:
  `dns`

<img width="1084" height="763" alt="dns filter" src="https://github.com/user-attachments/assets/31e2c917-1d20-437e-b05e-18f6335a5a02" />
<br>

### What to find:
  - Query packet:    Info column reads "Standard query A google.com"
  - Response packet: Info column reads "Standard query response A google.com"
  - Expand the response → Answers section → confirm IP matches nslookup output

---

### Exercise B — TCP Three-Way Handshake

  1. Get the IP for example.com first:
  `nslookup example.com`
  2. Start capture, navigate to http://example.com, stop capture
  3. Apply filter (replace with actual IP):
  `tcp and ip.addr == [ip address]`

<img width="1091" height="638" alt="tcp" src="https://github.com/user-attachments/assets/fa826b5c-cfe3-48bd-9f47-57f4ae512fd2" />
<br>

### What to find:
  - Packet 1: Flags = SYN        — your machine initiating the connection
  - Packet 2: Flags = SYN, ACK   — server acknowledging
  - Packet 3: Flags = ACK        — connection established

### Failure patterns:
  - SYN with no SYN-ACK = server unreachable or port blocked
  - RST after SYN       = connection refused by application

---

### Exercise C — Cleartext Credential Capture

> ⚠️ **Only perform this on systems and networks you own or have explicit written permission to test.**

  1. Start capture
  2. Submit a login form over HTTP (test site only)
  3. Stop capture
  4. Apply filter:
  `http.request.method == POST`

### In the packet detail pane:
  - Expand "HTML Form URL Encoded"
  - username and password are visible in plaintext

<img width="957" height="593" alt="cleartext credential" src="https://github.com/user-attachments/assets/08795c58-c22a-42ee-8e64-c525c3efc430" />
<br>

---

### Exercise D — Follow a TCP Stream

  1. Capture any HTTP traffic
  2. Find any HTTP packet in the list
  3. Right-click → Follow → TCP Stream

<img width="957" height="720" alt="tcp stream" src="https://github.com/user-attachments/assets/6e5ec219-3318-4509-961b-c90036f4e0ab" />
<br>

  - Red  = your browser's request
  - Blue = server's response
  
  This view shows the complete conversation reassembled from individual packets

---

### Essential Display Filters (Reference)

| Filter | What It Shows |
|---|---|
| `dns` | All DNS queries and responses |
| `http` | Unencrypted HTTP traffic only |
| `tcp` | All TCP traffic |
| `tcp.flags.syn == 1` | Connection attempts (SYN packets only) |
| `tcp.flags.reset == 1` | Refused or forcibly closed connections |
| `icmp` | Ping and network diagnostics |
| `ip.addr == 192.168.1.1` | All traffic to or from a specific IP |
| `ip.src == 10.0.0.5` | Outbound traffic from one host |
| `tcp.port == 443` | HTTPS traffic by port |
| `http.request.method == POST` | Form submissions — look for credential data |

---

## Architectural Decisions & Trade-offs

### Decision 1: Display Filters Instead of Capture Filters

**What I chose:** Always start an unconstrained capture and apply display filters after the fact.

**Why:** Display filters are non-destructive — they change what you see without discarding anything from the underlying capture. A capture filter, by contrast, throws away packets that don't match before they're recorded. If you applied a capture filter for `dns` and later wanted to look at the TCP handshakes for those same DNS-resolved hosts, the TCP packets would be gone.

**Trade-off:** Unconstrained captures on a busy network can grow large quickly. A 30-second capture on a typical workstation can produce 5,000–50,000 packets. Storage and memory are cheap enough that this isn't a problem for lab use, but in a production environment with sustained 10 Gbps traffic, capture filters become necessary — you simply cannot store everything.


### Decision 2: HTTP for the Credential Exercise

**What I chose:** Use plain HTTP (not HTTPS) to demonstrate credential exposure.

**Why:** The entire point of Exercise C is to prove that unencrypted HTTP exposes credentials in plaintext. Using HTTP is the correct choice here because it's the vulnerable scenario that security engineers need to recognise and remediate. Demonstrating the attack on a controlled test site you own is the ethical way to build this skill.

**Trade-off:** In 2025, finding real HTTP login forms in the wild is increasingly difficult because browsers, CDNs, and hosting platforms have pushed HTTPS adoption close to 100%. Students may need to spin up a local HTTP test server (a simple Flask or Python `http.server` instance) to complete this exercise reliably.


### Decision 3: .pcapng Format for Saved Captures

**What I chose:** Save all captures in `.pcapng` format rather than the older `.pcap` format.

**Why:** `.pcapng` is the current standard. It supports multiple interfaces in a single file, stores interface metadata, allows comments on individual packets, and has better timestamp precision. Wireshark defaults to it.

**Trade-off:** Some older tools and certain SIEM integrations still expect `.pcap`. If you're exporting captures for ingestion into a SIEM or sharing with a tool that doesn't support `.pcapng`, export a copy in legacy `.pcap` format. Keep the `.pcapng` as the primary record.

---

## What I'd Do Differently in Production

This lab is designed for learning. A production network monitoring or incident response environment has different requirements, and the architectural choices would change accordingly.

### 1. Replace Interactive Capture with Centralised Flow Logging

Wireshark captures full packet payloads on a single interface. In production, full packet capture at scale is expensive and raises privacy and compliance concerns. The production equivalent is **flow logging;** summary records that capture source IP, destination IP, port, protocol, bytes transferred, and timestamp without storing the actual payload.

- **AWS:** VPC Flow Logs → S3 or CloudWatch Logs
- **Azure:** Network Watcher Flow Logs → Storage Account or Log Analytics
- **GCP:** VPC Flow Logs → Cloud Logging

Wireshark remains useful in production for targeted deep-dives on specific hosts or incidents, but it's not the primary monitoring mechanism.

### 2. Centralise Logs in a SIEM

Individual `.pcapng` files sitting on an analyst's workstation don't scale. In production, flow logs feed into a SIEM (Microsoft Sentinel, Splunk, Elastic) where they can be correlated across thousands of hosts, searched with structured query languages, and used to trigger automated alerts.

The display filter skills from this lab translate directly to SIEM query languages. The logic is identical, only the syntax changes.

### 3. Automate Threat Detection

Manually looking for suspicious DNS queries or unexpected outbound connections doesn't scale. Production environments use:

- **DNS filtering and logging** (Cisco Umbrella, Cloudflare Gateway) to block and alert on known-bad domains automatically
- **IDS/IPS** (Suricata, Zeek, Azure Network Watcher's IDS feature) to apply signature-based detection against traffic in real time
- **UEBA** (User and Entity Behaviour Analytics) to detect anomalous traffic patterns without requiring a known signature

Wireshark teaches you *what* these tools are detecting. Understanding packet-level behaviour is what lets you write effective IDS rules and tune SIEM queries.

### 4. Enforce HTTPS Everywhere — Don't Rely on Detection

Exercise C demonstrates that HTTP exposes credentials. In production, the mitigation is not better monitoring. It's eliminating HTTP entirely. Production controls include:

- TLS certificates on every service (Let's Encrypt eliminates the cost barrier)
- HTTP Strict Transport Security (HSTS) headers to force HTTPS at the browser level
- Azure Application Gateway or AWS ALB configured to redirect all HTTP to HTTPS
- Content Security Policy headers to prevent mixed-content requests

Wireshark is how you *prove* a misconfiguration exists. The fix is TLS, not more monitoring.

### 5. Restrict Packet Capture Permissions

In this lab, promiscuous mode and packet capture run under your user account. In production, the ability to capture packets is a privileged operation, a malicious insider with Wireshark access could capture credentials, session tokens, and sensitive data. Production controls include:

- Restricting the `wireshark` group membership to named security personnel
- Logging all packet capture sessions with the identity of who ran the capture, when, and on which interface
- Using read-only access to flow logs in the SIEM rather than granting direct packet capture capability to analysts by default

---
