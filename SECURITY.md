# Security Policy & Vulnerability Disclosure

## Overview

RouteX is an autonomous, stateless HTTP/HTTPS web gateway built for Cloudflare Workers with optional Daytona sandbox compute capabilities. Security, strict resource isolation, and Server-Side Request Forgery (SSRF) defense are foundational architectural principles of this project.

---

## Threat Model & Security Architecture

### 1. Multi-Layer Server-Side Request Forgery (SSRF) Defense

Before any upstream network connection is dispatched by the Cloudflare Worker or scheduled in a Daytona compute sandbox, destination URLs must pass rigorous validation in `normalizeTarget()`:

- **Loopback Blocking**:
  - IPv4: `127.0.0.0/8`, `0.0.0.0/8`
  - Hostnames: `localhost`, `localhost.localdomain`, `.localhost`
  - IPv6: `::1`, `::`
- **Private RFC 1918 Ranges**:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
- **Carrier-Grade NAT (CGNAT)**:
  - `100.64.0.0/10`
- **Cloud Metadata & Link-Local**:
  - `169.254.0.0/16` (including AWS/GCP/Azure instance metadata at `169.254.169.254`)
  - `metadata.google.internal`, `instance-data`
- **Multicast, Broadcast & Reserved**:
  - `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255`
- **IPv6 Restricted Ranges**:
  - Link-Local (`fe80::/10`)
  - Unique Local Addresses / ULA (`fc00::/7`)
  - Deprecated Site-Local (`fec0::/10`)
  - IPv4-mapped IPv6 ranges (`::ffff:127.0.0.1`, `::ffff:10.0.0.1`, etc.)
- **Obfuscated Encodings & Representations**:
  - Octal representations with leading zeros (e.g., `0177.0.0.1`)
  - Hexadecimal representations (e.g., `0x7f000001`)
  - Decimal integer representations (e.g., `2130706433`)
- **Internal / Non-Routable Domains**:
  - Unqualified single-label hostnames without dots (e.g., `intranet`, `router`, `corp`, `nas`)
  - Internal TLDs: `.local`, `.internal`, `.lan`, `.home.arpa`, `.onion`

---

### 2. Protocol & HTTP Method Controls

- **Allowed Protocols**: Strictly `http:` and `https:`.
- **Prohibited Schemes**: `file://`, `ftp://`, `gopher://`, `javascript:`, `data:`, `blob:`, `ws://`, `wss://` are rejected at the edge.
- **HTTP Methods**: Strictly `GET`, `HEAD`, and `OPTIONS`. Arbitrary state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) are rejected on `/proxy` with `405 Method Not Allowed`.
- **Credential Stripping**: Target URLs containing user credentials (`http://user:pass@host`) are rejected and stripped.
- **Length Limits**: Target URLs exceeding 4,096 characters are rejected with `400 Bad Request`.

---

### 3. Daytona Compute Isolation & Predefined Operations

Daytona provides optional, isolated compute sandboxes for browser automation (Playwright rendering, screenshots, and PDFs):

- **Zero Arbitrary Command Execution**:
  - External callers can **never** submit shell commands (`command: "..."`), bash scripts, Python code, or arbitrary binaries.
  - The API exclusively accepts target URLs, which must first pass RouteX's full SSRF policy.
  - The Worker generates and executes strictly predefined, hardcoded Playwright scripts inside the sandbox.
- **Ephemeral Sandbox Lifecycle**:
  - Sandboxes are created on-demand with `ephemeral: true` and `autoDeleteInterval: 0`.
  - Every sandbox is destroyed in a guaranteed `finally` block (`daytona.delete(sandbox)`), preventing lingering instances.
- **Strict Timeouts & Payload Bounds**:
  - Maximum task duration: 45 seconds.
  - Maximum output size: 5 MB.
- **Core Isolation**:
  - Standard `/proxy` web traffic is completely independent of Daytona. If Daytona is down or unconfigured, RouteX continues functioning normally.

---

### 4. Privacy & Data Handling

- **No Application Datastores**: RouteX does not use Cloudflare D1, KV, R2, Durable Objects, or external databases.
- **No Browsing History**: Target URLs, request bodies, and proxy payloads are processed in memory and never persisted.
- **No User Accounts**: No sessions, passwords, or authentication profiles exist.
- **Header Isolation**: Upstream `Set-Cookie` and dangerous framing headers (`Content-Security-Policy`, `X-Frame-Options`) are stripped to prevent session bleeding and framing attacks.

---

## Reporting a Vulnerability

If you discover a security vulnerability or SSRF bypass in RouteX, please report it responsibly:

1. **Do not create public GitHub issues** for undisclosed security vulnerabilities.
2. Email the maintainer directly:
   - **Maintainer**: JOJIN JOHN
   - **GitHub Profile**: [@jojin1709](https://github.com/jojin1709)
   - **Repository**: [jojin1709/RouteX](https://github.com/jojin1709/RouteX)
3. Please include:
   - Detailed description of the vulnerability.
   - Proof of Concept (PoC) or reproduction steps.
   - Impact assessment.
   - Proposed remediation (if available).

We will acknowledge receipt within 48 hours and work with you on a coordinated fix and disclosure timeline.
