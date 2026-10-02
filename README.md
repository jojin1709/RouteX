> [!NOTE]
> **[RouteX Production Gateway is Live](https://routex-web-gateway.apkscope.workers.dev):** Hardened stateless HTTP/HTTPS web gateway with multi-layered SSRF defense, automated URL & resource rewriting, 9 stateless inspector tools, and multi-probe compatibility diagnostics.

<div align="center">

# ⚡ RouteX
### High-Performance Stateless HTTP/HTTPS Web Gateway for Cloudflare Workers

Developed by **[JOJIN JOHN](https://github.com/jojin1709)**

[![Cloudflare Workers](https://img.shields.io/badge/Platform-Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Storage](https://img.shields.io/badge/Storage-100%25%20Stateless-success.svg)](#privacy-model)
[![Tests Passing](https://img.shields.io/badge/Tests-90%2F90%20Passing-brightgreen.svg)](#automated-testing)
[![SSRF Protected](https://img.shields.io/badge/Security-Multi--Layer%20SSRF%20Defense-red.svg)](#security-model--ssrf-defense)

<br/>

**RouteX is an autonomous, stateless web gateway that fetches, rewrites, and sanitizes web content on Cloudflare's global edge network.**

No persistent databases. No cookies saved. No browsing history logs. **Pure stateless execution.**

<p><strong>Quick Launch</strong></p>

```bash
npx wrangler deploy
```

<sub>Deploys directly to your Cloudflare Workers Free Tier environment in seconds.</sub>

---

<a href="https://routex-web-gateway.apkscope.workers.dev"><img src="https://img.shields.io/badge/Live%20Gateway-routex--web--gateway.apkscope.workers.dev-orange?style=for-the-badge&logo=cloudflare" height="38" alt="Live Demo"></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="https://github.com/jojin1709/RouteX"><img src="https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github" height="38" alt="GitHub Repository"></a>

---

</div>

> [!TIP]
> **Need automated compatibility evaluation?** Try `GET /diagnostics?url=https://example.com` for a factual 9-probe technical audit of DNS, HTTPS, HTML, CSS, fonts, images, and client-side SPA routing signals.

---

## Table of Contents

- [What is RouteX?](#what-is-routex)
  - [Why RouteX Exists](#why-routex-exists)
  - [Zero Application Persistence](#zero-application-persistence)
  - [What RouteX is NOT](#what-routex-is-not)
- [RouteX in Action](#routex-in-action)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Installation & Local Testing](#installation--local-testing)
  - [Deploy to Cloudflare Workers](#deploy-to-cloudflare-workers)
- [Key Capabilities](#key-capabilities)
- [Architecture](#architecture)
- [Security Model & SSRF Defense](#security-model--ssrf-defense)
  - [Prohibited Destinations](#prohibited-destinations)
  - [Allowed Protocols & Methods](#allowed-protocols--methods)
  - [Resource & Size Limits](#resource--size-limits)
- [Content-Type Routing & Rewriting](#content-type-routing--rewriting)
- [Stateless Inspector Tools](#stateless-inspector-tools)
- [Optional Cloudflare Browser Rendering](#optional-cloudflare-browser-rendering)
- [Privacy Model & Platform Transparency](#privacy-model--platform-transparency)
- [Automated Testing](#automated-testing)
- [About the Developer](#about-the-developer)
- [Common Questions (FAQ)](#common-questions-faq)
- [License](#license)

---

## What is RouteX?

RouteX is a production-grade, stateless HTTP/HTTPS web gateway designed from the ground up to run entirely within the serverless limits of **Cloudflare Workers Free Tier**.

It accepts destination URLs, verifies them against a strict multi-layer Server-Side Request Forgery (SSRF) policy, fetches upstream resources, and dynamically rewrites HTML, CSS, and resource attributes so that links and assets continue seamlessly through the gateway.

<a id="why-routex-exists"></a>
<details>
<summary><strong>Why RouteX Exists</strong></summary>

Most self-hosted proxies require persistent virtual private servers (VPS), Docker daemons, or databases with ongoing maintenance costs. RouteX rethinks the web gateway pattern:
1. **Serverless & Instant**: Boots in under 2ms on Cloudflare's global edge network.
2. **Zero Maintenance**: No servers to patch, no databases to back up, and no persistent state to corrupt.
3. **Free Tier Native**: Designed specifically to operate within Cloudflare's standard free allocation without requiring paid add-ons.

</details>

<a id="zero-application-persistence"></a>
<details>
<summary><strong>Zero Application Persistence</strong></summary>

RouteX enforces complete statelessness at the application level:
- **No Database**: Does not use Cloudflare D1, KV, R2, Durable Objects, or external databases.
- **No Browsing History**: Target URLs, requests, and proxy payloads are discarded immediately after streaming.
- **No User Profiles**: No accounts, authentication sessions, or telemetry identifiers.
- **Header Isolation**: Upstream `Set-Cookie` and dangerous frame headers are stripped to prevent session bleeding.

</details>

<a id="what-routex-is-not"></a>
<details>
<summary><strong>What RouteX is NOT</strong></summary>

To maintain technical accuracy and clear expectations:
- **NOT a VPN**: RouteX is an application-layer HTTP/HTTPS gateway, not a Virtual Private Network or system TUN/TAP driver.
- **NOT a WireGuard/OpenVPN server**: It does not route raw TCP/UDP packets or mobile operating system network interfaces.
- **NOT an Anti-Bot Bypass Tool**: RouteX does not circumvent CAPTCHAs, Cloudflare Turnstile, or device-fingerprinting systems (such as TikTok, dynamic SPA bot checks, or Canvas/WebGL verifications).
- **NOT an Unrestricted SOCKS Proxy**: It only supports safe, publicly routable `http://` and `https://` web targets.

</details>

---

## RouteX in Action

### Live Gateway Verification Matrix

All tests executed live against the production deployment at `https://routex-web-gateway.apkscope.workers.dev`:

| Target Domain | Category | Gateway Behavior | Status |
| :--- | :--- | :--- | :---: |
| **example.com** | Standard HTML/CSS | HTML links and assets automatically rewritten to `/proxy?url=...` | **Pass** |
| **Python Documentation** | Rich Technical Docs | Multi-level stylesheets, navigation links, and search assets routed cleanly | **Pass** |
| **Wikipedia** | Wikimedia Foundation | Content, vector skins, lazy-loaded thumbnails, and external links handled | **Pass** |
| **W3C Standards** | Specifications & CSS | Strict HTML5 specs, nested CSS imports, and media assets preserved | **Pass** |
| **127.0.0.1 / Loopback** | SSRF Vector | Blocked at edge before request dispatch (`400 Bad Request`) | **Blocked** |
| **169.254.169.254** | Cloud Metadata Vector | AWS/GCP/Azure instance metadata blocked at edge (`400 Bad Request`) | **Blocked** |
| **TikTok (Remix SPA)** | Client-Side SPA | Initial HTML loads; dynamic client-side hydration remains limited | **Documented Limitation** |

---

## Quick Start

### Prerequisites
- **Node.js**: v20+ or v22+ LTS
- **Cloudflare Wrangler CLI**: Installed automatically via `devDependencies`

### Installation & Local Testing

```bash
# 1. Clone repository
git clone https://github.com/jojin1709/RouteX.git
cd RouteX

# 2. Install dependencies
npm install

# 3. Validate TypeScript types
npm run typecheck

# 4. Execute the automated 90-test suite
npm test

# 5. Start local development server
npm run dev
```

### Deploy to Cloudflare Workers

> [!WARNING]
> Never deploy to production if local tests fail. Ensure `npm test` passes 100% of test cases before initiating deployment.

```bash
# Authenticate with Cloudflare
npx wrangler login

# Deploy live to Cloudflare Workers
npm run deploy
```

---

## Key Capabilities

- **Automated HTML Resource Rewriting**: Conservatively rewrites `<a href>`, `<link href>`, `<script src>`, `<img src>`, `<source src>`, `<video src poster>`, `<audio src>`, `<iframe src>`, GET `<form action>`, inline `style` attributes, and `<style>` blocks.
- **Responsive Multi-Candidate `srcset` Parsing**: Parses and rewrites candidate URL lists while preserving pixel density and viewport width descriptors (e.g. `pic-1x.jpg 1x, pic-2x.jpg 2x`).
- **Relative CSS Engine**: Resolves `url(...)` and `@import` statements relative to the stylesheet's own origin, preventing broken assets on CDN-hosted styles.
- **Double-Proxy Prevention**: Detects existing gateway prefixes and relative proxy query parameters to prevent recursive infinite proxy loops.
- **Enterprise-Grade SSRF Shield**: Comprehensive IP range checking against loopback, private RFC1918, CGNAT, link-local metadata, IPv6 ULA, IPv4-mapped IPv6, and obfuscated octal/hex/decimal representations.
- **Factual Compatibility Diagnostics Engine**: `GET /diagnostics` runs 9 independent technical probes to report factual compatibility (Full, Partial, or Limited).
- **9 Stateless Web Inspector Tools**: Standalone endpoints for headers, security headers, redirect tracer, link extractor, robots.txt viewer, sitemap parser, JSON formatter, XML viewer, and response metadata.
- **Decoupled Cloudflare Browser Rendering**: Optional add-on integration with graceful 501 fallback when `env.BROWSER` is absent, protecting Free tier quotas.
- **Zero Persistent Datastores**: Absolutely no D1, KV, R2, Durable Objects, or external databases.

---

## Architecture

RouteX executes entirely within the Cloudflare Worker lifecycle, handling incoming requests through isolated, specialized processing stages:

```mermaid
flowchart TD
    REQ["Incoming Client Request"] --> ROUTER{"RouteX Router"}

    ROUTER -- "/health" --> HEALTH["Health Status & Capabilities"]
    ROUTER -- "/api/tools/*" --> TOOLS["9 Stateless Inspector Tools"]
    ROUTER -- "/diagnostics" --> DIAG["9-Probe Diagnostics Engine"]
    ROUTER -- "/api/browser/*" --> BROWSER{"Browser Rendering Binding?"}
    ROUTER -- "/proxy?url=..." --> SSRF{"SSRF & Security Shield"}

    BROWSER -- "Available" --> BR_EXEC["Execute Browser Headless Session"]
    BROWSER -- "Absent" --> BR_501["501 Graceful Fallback (Free Tier)"]

    SSRF -- "Blocked (127.0.0.1, Private IP, etc.)" --> ERR_400["400 Bad Request (Policy Violation)"]
    SSRF -- "Approved Public Target" --> UPSTREAM["Upstream HTTP/HTTPS Fetch"]

    UPSTREAM --> MIME{"Content-Type Evaluation"}

    MIME -- "text/html" --> HTML_RW["HTML & srcset Rewriter"]
    MIME -- "text/css" --> CSS_RW["CSS url() & @import Rewriter"]
    MIME -- "Binary / Media / JSON / JS" --> PASS["Pass-Through Stream"]

    HTML_RW --> SANITIZE["Header Sanitizer (Strip CSP/XFO/Cookies)"]
    CSS_RW --> SANITIZE
    PASS --> SANITIZE

    SANITIZE --> RES["Client Response + Access-Control-Allow-Origin: *"]
```

---

## Security Model & SSRF Defense

RouteX implements a comprehensive multi-layered Server-Side Request Forgery defense before any network connection is attempted.

### Prohibited Destinations

Requests to any of the following are terminated at the edge with `400 Bad Request`:

| Category | Patterns & Ranges Blocked |
| :--- | :--- |
| **Loopback** | `127.0.0.0/8`, `localhost`, `localhost.localdomain`, `::1` |
| **Current / Unspecified** | `0.0.0.0/8`, `::` |
| **Private RFC1918** | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| **Carrier-Grade NAT (CGNAT)** | `100.64.0.0/10` |
| **Cloud Metadata & Link-Local** | `169.254.0.0/16` (`169.254.169.254`), `metadata.google.internal`, `instance-data` |
| **IPv6 Restricted** | Link-Local (`fe80::/10`), Unique Local (`fc00::/7`), IPv4-mapped IPv6 (`::ffff:127.0.0.1`) |
| **Obfuscated Encodings** | Octal (e.g. `0177.0.0.1`), Hex (e.g. `0x7f.0.0.1`), Decimal integer (e.g. `2130706433`) |
| **Internal TLDs** | `.local`, `.internal`, `.localhost`, `.onion` |
| **Unsupported Schemes** | `file://`, `ftp://`, `gopher://`, `javascript:`, `data:`, `ws://`, `wss://` |
| **Embedded Credentials** | `http://user:pass@host` (rejected & stripped) |

### Allowed Protocols & Methods
- **Protocols**: Strictly `http:` and `https:`.
- **HTTP Methods**: Strictly `GET`, `HEAD`, and `OPTIONS`. Arbitrary state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) are rejected with `405 Method Not Allowed`.

### Resource & Size Limits
- **Maximum Target URL Length**: 4,096 characters.
- **Maximum Processing Buffer**: 2 MB for in-memory HTML and CSS stream transformation.
- **Redirect Limit**: Maximum 5 hops to prevent redirect-loop resource exhaustion.

---

## Content-Type Routing & Rewriting

| MIME Type / Category | Gateway Behavior |
| :--- | :--- |
| `text/html` | Rewrites attributes (`href`, `src`, `poster`, `action`, `srcset`, inline CSS, `<style>`) to route through `/proxy?url=`. |
| `text/css` | Rewrites `url(...)` and `@import` resolved strictly against the stylesheet's own URL origin. |
| `application/javascript` | Transparent pass-through. JavaScript source code is not modified. |
| `application/json` | Pass-through with `Access-Control-Allow-Origin: *` injected. |
| `image/*` | Binary pass-through with upstream caching headers (`ETag`, `Cache-Control`) preserved. |
| `font/*`, `.woff2` | Binary pass-through. |
| `video/*`, `audio/*` | Binary streaming with HTTP `Range` request support. |
| `application/pdf` | Binary pass-through. |

---

## Stateless Inspector Tools

RouteX includes 9 independent inspection tools accessible via REST endpoints:

| Endpoint | Tool Name | Description |
| :--- | :--- | :--- |
| `GET /api/tools/headers?url=...` | **HTTP Header Inspector** | Returns raw upstream HTTP response headers and status codes. |
| `GET /api/tools/security-headers?url=...` | **Security Header Checker** | Objective assessment of HSTS, CSP, X-Frame-Options, Referrer-Policy, and Permissions-Policy. |
| `GET /api/tools/redirects?url=...` | **Redirect Tracer** | Traces up to 5 HTTP redirect hops with status codes and location targets. |
| `GET /api/tools/links?url=...` | **Link Extractor** | Parses HTML anchor tags and returns resolved destination links. |
| `GET /api/tools/robots?url=...` | **robots.txt Viewer** | Fetches and returns raw directives from `/robots.txt`. |
| `GET /api/tools/sitemap?url=...` | **sitemap.xml Parser** | Fetches and extracts URLs listed in `/sitemap.xml`. |
| `GET /api/tools/json?url=...` | **JSON Formatter** | Formats and validates JSON payloads. |
| `GET /api/tools/xml?url=...` | **XML Viewer** | Inspects and validates XML feeds and documents. |
| `GET /api/tools/response-info?url=...` | **Response Info** | Analyzes response size, content type, transfer encoding, and HTTP status. |

---

## Optional Cloudflare Browser Rendering

RouteX includes hooks for Cloudflare Workers Browser Rendering:
- `GET /api/browser/info` — Checks if headless browser execution is enabled.
- `GET /api/browser/screenshot?url=...` — Captures a full-page snapshot.
- `GET /api/browser/pdf?url=...` — Generates a print-ready PDF document.
- `GET /api/browser/rendered-html?url=...` — Returns post-JavaScript DOM.

> [!NOTE]
> **Free Tier Isolation**: Browser Rendering is strictly an optional diagnostic tool with platform quotas. The core RouteX proxy functions completely independently and never requires Browser Rendering. If unconfigured, the endpoint returns `501 Not Implemented` with setup instructions.

---

## Privacy Model & Platform Transparency

> **Accurate Privacy Policy**:
> RouteX does not intentionally persist browsing history, target URLs, proxy content, cookies, request bodies, or user profiles in an application database.

**Platform Transparency**:
Do not claim that "nothing anywhere is stored." Cloudflare as the underlying edge infrastructure provider processes network packets, HTTP metadata, and operational telemetry under its standard platform privacy and security policies. RouteX simply avoids creating any application-specific storage layer.

---

## Automated Testing

RouteX is backed by an automated 90-test verification suite covering URL rewriting, SSRF matrix validation, header handling, tools, and diagnostics:

```bash
npm test
```

### Raw Test Execution Summary
```text
==================================================
  RouteX Production Test Suite
==================================================

--- Section 1: Core URL & Resource Rewriting ---
  [PASS] Relative ../ resolution
  [PASS] Relative ./ resolution
  [PASS] Root-relative / resolution
  [PASS] Protocol-relative // resolution
  [PASS] Absolute https:// resolution
  [PASS] Query string and fragment preserved in target
  [PASS] Fragment-only anchor untouched
  [PASS] javascript: URL untouched
  [PASS] data: URI untouched
  [PASS] mailto: link untouched
  [PASS] tel: link untouched
  [PASS] Double-proxy prevention (relative /proxy?url=)
  [PASS] Double-proxy prevention (absolute gateway URL)
  [PASS] srcset multi-candidate rewriting
  [PASS] CSS @import string relative to CSS file
  [PASS] CSS url(...) relative ../img/pattern.png resolved relative to CSS file
  [PASS] CSS root-relative /shared/icon.svg resolved to CSS origin
  [PASS] CSS data: URL preserved untouched
  [PASS] HTML <link href> rewritten
  [PASS] HTML <script src> rewritten
  [PASS] HTML <a href> rewritten
  [PASS] HTML fragment <a href='#section'> untouched
  [PASS] HTML <img src> rewritten
  [PASS] HTML <video src and poster> rewritten
  [PASS] HTML <source src> rewritten
  [PASS] HTML <audio src> rewritten
  [PASS] HTML <iframe src> rewritten
  [PASS] HTML GET <form action> rewritten
  [PASS] HTML POST <form action> left untouched
  [PASS] HTML inline style attribute rewritten
  [PASS] HTML <style> block rewritten
  [PASS] Response headers: content-type preserved
  [PASS] Response headers: etag preserved
  [PASS] Response headers: cache-control preserved
  [PASS] Response headers: dangerous CSP stripped
  [PASS] Response headers: X-Frame-Options stripped
  [PASS] Response headers: Set-Cookie stripped
  [PASS] Response headers: content-encoding stripped on rewritten text
  [PASS] Response headers: content-length stripped on rewritten text
  [PASS] Response headers: Access-Control-Allow-Origin: * injected
  [PASS] Response headers: X-RouteX-Gateway: 1 injected

--- Section 2: Security & SSRF Protection ---
  [PASS] SSRF Block: 127.0.0.1 Loopback
  [PASS] SSRF Block: 127.x.x.x Loopback CIDR
  [PASS] SSRF Block: 0.0.0.0 Current network
  [PASS] SSRF Block: 10.0.0.1 Private Class A
  [PASS] SSRF Block: 10.255.255.255 Private Class A
  [PASS] SSRF Block: 172.16.0.1 Private Class B
  [PASS] SSRF Block: 172.31.255.255 Private Class B
  [PASS] SSRF Block: 192.168.0.1 Private Class C
  [PASS] SSRF Block: 192.168.1.254 Private Class C
  [PASS] SSRF Block: 169.254.169.254 Link-local AWS metadata
  [PASS] SSRF Block: 100.64.0.1 CGNAT
  [PASS] SSRF Block: 224.0.0.1 Multicast
  [PASS] SSRF Block: 240.0.0.1 Reserved
  [PASS] SSRF Block: 255.255.255.255 Broadcast
  [PASS] SSRF Block: localhost
  [PASS] SSRF Block: localhost.localdomain
  [PASS] SSRF Block: .local mDNS
  [PASS] SSRF Block: .internal internal hostname
  [PASS] SSRF Block: .localhost domain
  [PASS] SSRF Block: .onion Tor hidden service
  [PASS] SSRF Block: GCP metadata hostname
  [PASS] SSRF Block: AWS instance-data alias
  [PASS] SSRF Block: IPv6 Loopback [::1]
  [PASS] SSRF Block: IPv6 Unspecified [::]
  [PASS] SSRF Block: IPv6 Link-Local [fe80::1]
  [PASS] SSRF Block: IPv6 ULA [fc00::1]
  [PASS] SSRF Block: IPv6 ULA [fd12::1]
  [PASS] SSRF Block: IPv4-mapped IPv6 loopback
  [PASS] SSRF Block: IPv4-mapped IPv6 private
  [PASS] SSRF Block: Decimal integer representation of 127.0.0.1
  [PASS] SSRF Block: Hex representation of 127.0.0.1
  [PASS] SSRF Block: Octal leading-zero representation
  [PASS] SSRF Block: file:// scheme
  [PASS] SSRF Block: ftp:// scheme
  [PASS] SSRF Block: gopher:// scheme
  [PASS] SSRF Block: javascript: scheme
  [PASS] SSRF Block: data: scheme
  [PASS] SSRF Block: ws:// scheme
  [PASS] SSRF Block: wss:// scheme
  [PASS] SSRF Block: Embedded credentials in URL
  [PASS] SSRF Block: Oversized URL (> 4096 chars)
  [PASS] Valid public target allowed (https://example.com/test)

--- Section 3: Stateless Tools & Diagnostics ---
  [PASS] JSON Inspector: Valid JSON parsing
  [PASS] Security Header Checker: Objective observations returned
  [PASS] Diagnostics: example.com returns Full compatibility rating
  [PASS] Diagnostics: Report includes technical probes
  [PASS] Diagnostics: SSRF target correctly flagged as Limited with fail probe
  [PASS] Browser Tools: Correctly reports unavailable when env.BROWSER is absent
  [PASS] Turnstile: Cleanly handles unconfigured secret key

==================================================
  TEST SUMMARY
==================================================
  TOTAL:  90 tests
  PASSED: 90
  FAILED: 0

All automated tests passed successfully!
```

---

## About the Developer

**RouteX** was engineered and architected by:

### **JOJIN JOHN**
*Software Engineer & Security Researcher*  
- **GitHub**: [@jojin1709](https://github.com/jojin1709)  
- **Repository**: [jojin1709/RouteX](https://github.com/jojin1709/RouteX)

---

## Common Questions (FAQ)

### Can I self-host RouteX?
Yes. You can fork or clone this repository, configure your own Cloudflare account via `npx wrangler login`, and deploy your own private gateway using `npx wrangler deploy`.

### Is RouteX a VPN?
No. RouteX is an application-level HTTP/HTTPS web gateway and URL-rewriting proxy. It does not provide TUN/TAP virtual network adapters, WireGuard routing, or device-wide traffic forwarding.

### Does RouteX store my browsing logs?
No. RouteX is completely stateless at the application level. It has no database bindings (no KV, D1, R2, or Durable Objects) and does not store browsing histories, target URLs, or user accounts.

### How does SSRF protection work?
Before fetching any destination, RouteX validates the hostname, scheme, and IP address. Any attempt to access loopback (`127.0.0.0/8`, `::1`), private ranges (`10.x`, `172.16.x`, `192.168.x`), cloud metadata services (`169.254.169.254`), or obfuscated IP encodings is immediately blocked with `400 Bad Request`.

### Why do some single-page apps (like TikTok) show hydration warnings?
Client-side SPAs (such as Remix or Next.js) often compare the browser's `window.location.pathname` with server hydration data. When proxied under `/proxy?url=...`, client hydration mismatches can occur. RouteX does not bypass or alter target anti-bot or device-fingerprinting scripts.

---

## License

RouteX is open source software licensed under the [MIT License](LICENSE).
