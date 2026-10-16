# ja4p4: JA4+ fingerprinting in P4

Status: project definition, for review. No code yet.
Target: PerCom 2027 workshop paper, deadline 17 November 2026.

## 1. Goal

Before most protocols start their real (often encrypted) session, the two sides exchange a few messages in the
clear: the TCP handshake, the TLS ClientHello and ServerHello, the SSH banner, a plain HTTP request, a DHCP request.
These messages differ between clients, libraries and servers, and the JA4+ suite turns them into short, stable
fingerprints.

This project computes the JA4+ fingerprints of the traffic passing through a P4 switch, correctly: the same value
FoxIO's reference tool gives on the same packets. The contribution is doing this in P4. Nothing else.

## 2. Setup

```
   h1 (client) ---- s1 (BMv2, our P4 program) ---- h2 (server)
                          |
                    controller (Python)
```

* Mininet (root is available), one BMv2 `simple_switch_grpc` switch, two hosts.
* h2 runs servers (TLS, HTTP, SSH, DHCP); h1 runs clients (openssl, curl, ssh, a DHCP client) and crafted traffic.
* The controller connects to the switch over P4Runtime, installs the forwarding rules, receives what the switch
  sends up, and prints and logs one fingerprint record per connection.

## 3. Division of work

| Switch (P4) | Controller (Python) |
|---|---|
| Forwards h1 <-> h2 | Installs forwarding rules at start |
| Recognises the packets that carry fingerprint data | Receives their fields (digest) or a copy (packet-in) |
| Extracts fixed fields itself: TCP window, options, MSS, window scale, TTL, timestamps, SSH packet sizes | Joins split data and orders reordered pieces |
| Sends the variable-length messages (ClientHello, ServerHello, HTTP request, certificate, DHCP options) up | Sorts, hashes (SHA-256, first 12 hex) and builds the JA4+ strings |

Rule of thumb: the switch does whatever P4 can do simply and per packet; the controller does what needs memory
across packets or a cryptographic hash. The P4 code says clearly which part of each fingerprint it produced.

## 4. Fingerprints

| Name | Taken from | Clear text? | Notes |
|---|---|---|---|
| JA4T | client SYN | yes | window, options, MSS, window scale |
| JA4TS | server SYN-ACK | yes | same, server side |
| JA4L (-C, -S) | handshake timing and TTL | yes (timing) | needs switch timestamps |
| JA4 | TLS ClientHello | yes | may be split over packets |
| JA4S | TLS ServerHello | yes | often shares packets with the certificate |
| JA4X | X.509 certificate | TLS 1.2 only | encrypted in TLS 1.3, so not visible there |
| JA4H | HTTP request | yes (plain HTTP only) | headers and cookies; may be split |
| JA4SSH | SSH packet sizes and directions | sizes only | uses the encrypted session's packet sizes, not its content |
| JA4D / JA4D6 | DHCP / DHCPv6 options | yes | UDP, no splitting |
| JA4 over QUIC | QUIC Initial | needs decryption | later, if time allows |

Two of these are not "clear text messages": JA4L measures timing and JA4SSH counts packet sizes during the
encrypted session. Both are still computable at the switch.

Planned order: JA4T, JA4TS, JA4L, then JA4 and JA4S (with splitting and reordering), then JA4H, JA4SSH, JA4D,
JA4X last.

## 5. Hard cases (the focus)

* **Split messages.** A ClientHello, ServerHello, certificate or HTTP request can span two or more TCP segments.
  Pieces are placed by TCP sequence number and the fingerprint is computed once the message is complete (its
  length is known from the TLS record / handshake header, or the HTTP header end).
* **Reordering.** The second piece may arrive first, e.g. the server's 2nd packet before its 1st. Pieces are held
  by position until the gap is filled.
* **Duplicates and retransmissions.** They do not change the result.
* **Never wrong.** If a message never completes, the record is reported as incomplete, not given a guessed value.

## 6. Correctness

For every test the traffic is captured on the hosts, and FoxIO's `ja4` tool runs on the same capture. The switch +
controller output must match it exactly. Tests cover normal connections from real tools, plus crafted traffic:
splits at many offsets, reordering, duplicates and retransmissions. Each new test is shown failing before the
feature and passing after it.

## 7. Out of scope

Flood protection, entry classes, meters, alerts, multiple switches, Tofino, performance tuning. Basic timing and
throughput are measured only to report the cost of fingerprinting in the paper.

## 8. Ideas reused from the earlier ja4p4 work (ideas, not code)

Comparison against FoxIO's tools, reference captures, the controller structure (P4Runtime, digests), the
generated sorting idea, red-then-green tests.

## 9. Open points

* Exact paper story and evaluation (which tables and figures).
* Whether high-level programs should later drive the switch (plug-in fingerprints on the controller), left for
  later.
