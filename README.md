# RouteX — Cloudflare Stateless Web Gateway

RouteX is a small, Cloudflare Workers-only web gateway. The core project uses no D1, KV, R2, authentication system, or application database. It accepts HTTP/HTTPS URLs, fetches them through a Worker, and returns compatible responses.

## Important scope

RouteX is a **web gateway**, not a device-level VPN. It does not provide WireGuard, WARP, arbitrary UDP forwarding, or transparent routing for mobile apps.

The project intentionally supports only `GET` and `HEAD` requests. HTML navigation/resource URLs are rewritten conservatively so common links continue through the gateway.

## Privacy model

The application does not intentionally persist:

- browsing history
- target URLs
- page contents
- cookies
- request/response bodies
- user accounts
- application analytics

There is no database binding in this project. `/health` is a static health endpoint and does not write data.

**Do not describe this as “nothing anywhere is stored.”** Cloudflare can process operational/security information under its own platform policies. This repository only avoids deliberately creating an application datastore for user browsing activity.

## Security measures included

- Only HTTP/HTTPS targets are accepted.
- Localhost and common internal hostnames are rejected.
- Private/reserved IPv4 ranges are rejected.
- Userinfo in target URLs is stripped.
- Only GET/HEAD are accepted.
- Upstream response headers are allowlisted.
- The Worker does not expose an arbitrary TCP tunnel.

## Deploy

### 1. Install Node.js

Use a current Node.js LTS release.

### 2. Install dependencies

```bash
npm install
```

### 3. Authenticate Wrangler

```bash
npx wrangler login
```

### 4. Test locally

```bash
npm run dev
```

Then open the local URL shown by Wrangler.

### 5. Deploy

```bash
npm run deploy
```

Wrangler will create/update the Worker and serve the `public/` directory through the Worker Assets binding.

## Configuration

`wrangler.toml` deliberately contains no D1, KV, R2, Durable Objects, or secrets.

If you later add Turnstile or another abuse-control mechanism, keep its secret in a Worker secret rather than committing it to Git.

## Example

After deployment:

```text
https://YOUR-DOMAIN.example/proxy?url=https%3A%2F%2Fexample.com
```

Or simply open the home page and enter the destination URL.

## Limitations

Many modern websites will not render perfectly because a generic HTTP proxy cannot transparently reproduce every browser behavior. Sites can depend on JavaScript, WebSockets, CORS, CSP, absolute URLs, cookies, service workers, anti-bot systems, or browser/device signals. RouteX does not attempt to bypass those systems.

Large video/media workloads are also not the intended use case for the Free Worker deployment. Cloudflare platform limits and the target site's behavior still apply.

## License

MIT — see `LICENSE`.
