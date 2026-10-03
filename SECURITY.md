# Security Policy

RouteX takes security seriously. As a public web gateway with built-in SSRF protection, maintaining strict defense-in-depth is essential to protecting both internal infrastructure and edge networks.

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.x` | ✅ Supported |

## Reporting a Vulnerability

If you discover a security vulnerability or SSRF bypass:

1. **Do NOT open a public GitHub issue.**
2. Please report the issue privately using [GitHub Private Vulnerability Reporting](https://github.com/jojin1709/RouteX/security/advisories/new).
3. If private reporting is unavailable, reach out directly to the maintainer via GitHub: [@jojin1709](https://github.com/jojin1709).

### Please Include:
- A detailed description of the vulnerability.
- Steps to reproduce or proof-of-concept (PoC) target URL.
- The affected endpoint (e.g. `/proxy`, `/api/tools/dns`, etc.).
- Potential impact and recommended mitigation.

### Our Commitment:
- We acknowledge reports within **48 hours**.
- We assess and deploy patches promptly to the live Cloudflare Workers edge.
- We credit security researchers in release notes upon coordinated disclosure.

## SSRF Threat Model

RouteX enforces strict SSRF protections against:
- Loopback addresses (`127.0.0.0/8`, `::1`, shorthand notations e.g. `127.1`).
- Private RFC 1918 CIDRs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- Alternative numerical encodings (Decimal, Hex, Octal).
- Non-HTTP/HTTPS protocols (`file://`, `gopher://`, `ftp://`).
- Embedded credentials (`https://user:pass@host`).
