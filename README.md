# dns-rs

A simple DNS library and CLI tool (`sdig`) implemented for learning purposes.

---

## Overview

- Implements DNS message encoding / decoding from scratch
- Zero external dependencies (no third-party crates)
- Mostly `no_std` compatible (CLI uses `std`)
- Designed to understand core DNS protocol structures

---

## Components

### Library (dns-rs)

- DNS message construction and parsing
- Name compression (decode support)
- Basic record types (A, NS, MX, SOA, etc.)

### CLI Tool (sdig)

- Minimal `dig`-like tool
- Sends DNS queries over UDP
- Pretty-prints responses
- Colored output (only when running in a TTY)
- Displays query elapsed time

---

## Features

- Zero dependencies
- Lightweight and easy to read
- RFC-aligned core implementation
- DNS name compression support
- Simple and readable output format

---

## Limitations

- Default DNS server is hardcoded:
  - `8.8.8.8:53`
- No EDNS support
- No DNSSEC support
- No TCP fallback
- Limited IPv6 support for name servers

---

## Usage (sdig)

Basic query:

```
sdig - simple DNS client
Usage:
  sdig [@server] <name> [type] [class] [+rec|+norec]
Examples:
  sdig example.com
  sdig example.com A
  sdig @8.8.8.8 example.com AAAA
  sdig example.com TXT +norec
Options:
  -h, --help     Show this help
  -v             Show version
```

```
sdig www.google.com
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; REQUEST
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; id             : 36864
;; recursive req  : true
;; query          : www.google.com (A)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; ANSWER
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; id             : 36864
;; opcode         : 0
;; authoritative  : false
;; truncated      : false
;; recursive req  : true
;; recursive avail: true
;; status         : NoError

;; ANSWERS
www.google.com	155	IN	A	142.251.154.119
www.google.com	155	IN	A	142.251.156.119
www.google.com	155	IN	A	142.251.150.119
www.google.com	155	IN	A	142.251.155.119
www.google.com	155	IN	A	142.251.153.119
www.google.com	155	IN	A	142.251.151.119
www.google.com	155	IN	A	142.251.152.119
www.google.com	155	IN	A	142.251.157.119
;; AUTHORITIES
;; ADDITIONALS
```

## Future Work

- EDNS (OPT record) support
- DNSSEC (RRSIG, DNSKEY, DS)
- TCP fallback
- System resolver integration (resolv.conf, etc.)
- More record types
- Output formatting improvements

---

## Purpose

This project is intended for:

- Learning the DNS protocol
- Understanding binary encoding/decoding
- Practicing `no_std` design
- Building systems without external dependencies
