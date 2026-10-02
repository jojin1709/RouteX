# RouteX — Cloudflare Stateless Web Gateway

RouteX is a production-ready, stateless HTTP/HTTPS web gateway built exclusively on Cloudflare Workers (Free Tier compatible).

---

## What RouteX Is and Is NOT

### RouteX IS:
- A **stateless HTTP/HTTPS web gateway** and URL-rewriting intermediary.
- An application-level proxy that fetches publicly available web content on behalf of clients.
- A technical diagnostics and inspector toolkit (security headers, redirects, links, robots.txt, sitemaps).
- 100% stateless at the application layer with zero application-level databases, caches, or persistent disk storage.

### RouteX IS NOT:
- A **VPN** (Virtual Private Network).
- A **device-level proxy** or system TUN/TAP driver.
- A **WireGuard** or OpenVPN server.
- An **unrestricted TCP/UDP proxy** or SOCKS tunnel.
- An anti-bot, CAPTCHA, or fingerprinting bypass tool.

---

## Architectural Principles

1. **Stateless by Design**:
   - Zero application-level persistence.
   - No Cloudflare KV, D1, R2, Durable Objects, Queues, or Vectorize bindings.
   - No user accounts, authentication sessions, or browsing history logs.
2. **Safe Resource Isolation**:
   - Strict upstream and downstream header sanitization.
   - Rejection of state-changing HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`). Only `GET`, `HEAD`, and `OPTIONS` are supported.
3. **Cloudflare Free Tier Friendly**:
   - Runs cleanly within standard Cloudflare Workers free plan CPU and memory execution limits.
   - Optional tools (such as Cloudflare Browser Rendering) remain decoupled and fail gracefully when bindings are not present.

---

## Privacy Model & Transparency

> **Accurate Privacy Policy**:
> RouteX does not intentionally persist browsing history, target URLs, proxy content, cookies, or user profiles in an application database.

**Platform Transparency**:
Do not claim or assume that "nothing anywhere is stored or processed." Cloudflare as the underlying edge infrastructure provider processes network packets, HTTP request metadata, and operational telemetry under its standard platform privacy and security policies. RouteX simply avoids creating any application-specific storage layer.

---

## Security Model & SSRF Protection

RouteX implements a multi-layered Server-Side Request Forgery (SSRF) defense before any upstream connection is attempted:

### Prohibited Destinations (Blocked with 400 Bad Request):
- **Loopback**: `127.0.0.0/8`, `localhost`, `localhost.localdomain`, `::1`.
- **Zero / Current Network**: `0.0.0.0`, `0.0.0.0/8`.
- **Private RFC1918 Ranges**:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
- **Carrier-Grade NAT (CGNAT)**: `100.64.0.0/10`.
- **Link-Local & Cloud Metadata Services**:
  - `169.254.0.0/16` (including `169.254.169.254` AWS/GCP/Azure instance metadata)
  - `metadata.google.internal`, `instance-data`
- **Multicast, Broadcast & Reserved**:
  - `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255`
- **IPv6 Restricted Ranges**:
  - Unspecified `::`
  - Link-Local `fe80::/10`
  - Unique Local Addresses (ULA) `fc00::/7`
  - IPv4-mapped IPv6 representations (`::ffff:127.0.0.1`, `::ffff:10.0.0.1`, etc.)
- **Alternative Hostname Encodings**:
  - Octal representations (e.g. `0177.0.0.1`)
  - Hexadecimal representations (e.g. `0x7f.0.0.1`)
  - Decimal integer representations (e.g. `2130706433`)
- **Internal / Non-Routable TLDs**: `.local`, `.internal`, `.localhost`, `.onion`.
- **Non-HTTP Protocols**: `file:`, `ftp:`, `gopher:`, `javascript:`, `data:`, `ws:`, `wss:`, etc.
- **Embedded Credentials**: URLs containing `user:pass@host` are stripped and rejected.
- **Payload Limits**: Target URLs exceeding 4,096 characters are rejected.

---

## Supported Content Types & Rewriting

| MIME Type / Content Category | Gateway Behavior |
| :--- | :--- |
| `text/html` | Conservative URL rewriting of tags (`<a>`, `<link>`, `<script>`, `<img>`, `<source>`, `<video>`, `<audio>`, `<iframe>`, `GET <form>`, `srcset`, inline styles, `<style>` blocks) to route through `/proxy?url=`. |
| `text/css` | Rewriting of `url(...)` and `@import` statements resolved strictly relative to the stylesheet's own URL. |
| JavaScript / Web Workers | Pass-through (not parsed or dynamically executed by the Worker). |
| JSON / XML / REST APIs | Pass-through with CORS headers. |
| Images (`image/*`) | Binary pass-through with upstream caching headers preserved. |
| Web Fonts (`font/*`, `.woff2`) | Binary pass-through. |
| Audio / Video (`audio/*`, `video/*`) | Pass-through with range requests supported. |
| PDF & Generic Binary | Binary pass-through. |

---

## Known Compatibility Limitations

RouteX is a generic HTTP gateway, not a browser runtime. Certain web architectures exhibit natural limitations:
1. **Client-Side SPA Routing & Hydration**:
   - Modern SPAs (such as Remix, Next.js, and client-heavy frameworks like TikTok) often validate `window.location.pathname` against hardcoded server hydration payloads (`window.__remixContext` or `__NEXT_DATA__`). When loaded under a proxy path like `/proxy?url=...`, client hydration mismatches or loader runtime errors may occur.
2. **Dynamic Client API Calls**:
   - Single-page apps that construct API URLs dynamically at runtime via JavaScript variables (rather than HTML attributes) will send requests relative to the gateway unless intercepted by a client-side service worker.
3. **Anti-Bot & Device Fingerprinting**:
   - Websites that require Canvas/WebGL fingerprinting, device sensors, signed browser tokens, or CAPTCHA solving are protected by the target website's defenses. RouteX does not bypass or tamper with anti-bot mechanisms.
4. **WebSocket & Persistent TCP Streaming**:
   - RouteX is designed for request-response HTTP/HTTPS proxying; persistent stateful bidirectional sockets are not forwarded.

---

## API Endpoints Reference

### Core Proxy
- `GET /health` — Gateway status and platform capability verification.
- `GET /proxy?url=<target_url>` — Fetch and proxy a target URL.
- `GET /diagnostics?url=<target_url>` — Factual compatibility audit report (DNS, HTTPS, HTML, CSS, Images, Fonts, Redirects, JavaScript, Dynamic APIs).

### Stateless Inspector Tools
- `GET /api/tools/headers?url=<target_url>` — Upstream HTTP response headers inspector.
- `GET /api/tools/security-headers?url=<target_url>` — Technical evaluation of HSTS, CSP, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- `GET /api/tools/redirects?url=<target_url>` — Redirect chain tracer (up to 5 hops).
- `GET /api/tools/links?url=<target_url>` — Extracts anchor links from HTML.
- `GET /api/tools/robots?url=<target_url>` — Fetches and displays `/robots.txt`.
- `GET /api/tools/sitemap?url=<target_url>` — Fetches and parses `/sitemap.xml`.
- `GET /api/tools/json?url=<target_url>` — Formatted JSON inspector.
- `GET /api/tools/xml?url=<target_url>` — Formatted XML inspector.
- `GET /api/tools/response-info?url=<target_url>` — Upstream metadata (TLS, status, content-type, encoding, sizing).

### Abuse Control & Turnstile (Optional)
- `POST /api/turnstile/verify?token=<token>` — Validates Cloudflare Turnstile CAPTCHA tokens against `https://challenges.cloudflare.com/turnstile/v0/siteverify`.
  - Configured via Worker secret: `npx wrangler secret put TURNSTILE_SECRET_KEY`

### Browser Rendering Tools (Optional Add-on)
- `GET /api/browser/info` — Checks if `env.BROWSER` binding is available.
- `GET /api/browser/screenshot?url=<target_url>` — Browser-rendered snapshot (requires `[browser]` binding).
- `GET /api/browser/pdf?url=<target_url>` — Browser-rendered PDF.
- `GET /api/browser/rendered-html?url=<target_url>` — Post-JavaScript DOM output.

---

## Local Development & Testing

### 1. Requirements
- Node.js LTS (v20+ or v22+)
- Cloudflare Wrangler CLI

### 2. Install Dependencies
```bash
npm install
```

### 3. Run Typecheck
```bash
npm run typecheck
```

### 4. Run Automated Test Suite
The automated test suite runs 90 end-to-end tests covering URL rewriting, SSRF matrix, header handling, tools, and diagnostics:
```bash
npm test
```

### 5. Local Dev Server
```bash
npm run dev
```

---

## Deployment to Cloudflare Workers

### 1. Authenticate with Cloudflare
```bash
npx wrangler login
```

### 2. Deploy
```bash
npm run deploy
```

The Worker will be deployed and accessible at:
```text
https://<your-worker-subdomain>.workers.dev
```

### 3. Optional: Configure Cloudflare Turnstile
To use Turnstile for rate/abuse control:
1. Create a Turnstile widget in Cloudflare Dashboard.
2. Store the secret key securely in the Worker environment:
   ```bash
   npx wrangler secret put TURNSTILE_SECRET_KEY
   ```

### 4. Optional: Configure Cloudflare WAF
In Cloudflare Dashboard -> Security -> WAF -> Custom Rules, you can add rate-limiting rules (e.g. limit requests to `/proxy` to 100 requests per minute per IP) to prevent external abuse of the free tier.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
