interface Env {
  ASSETS: Fetcher;
}

const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "metadata.google.internal",
  "metadata",
]);

function isIPv4(host: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
}

function ipv4ToInt(host: string): number | null {
  if (!isIPv4(host)) return null;
  const parts = host.split(".").map(Number);
  if (parts.some((n) => n < 0 || n > 255)) return null;
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
}

function isPrivateIPv4(host: string): boolean {
  const n = ipv4ToInt(host);
  if (n === null) return false;
  const ranges: Array<[number, number]> = [
    [0x00000000, 0x00ffffff], // 0.0.0.0/8
    [0x0a000000, 0x0affffff], // 10.0.0.0/8
    [0x64400000, 0x647fffff], // 100.64.0.0/10
    [0x7f000000, 0x7fffffff], // 127.0.0.0/8
    [0xa9fe0000, 0xa9feffff], // 169.254.0.0/16
    [0xac100000, 0xac1fffff], // 172.16.0.0/12
    [0xc0000000, 0xc0ffffff], // 192.0.0.0/24
    [0xc0a80000, 0xc0a8ffff], // 192.168.0.0/16
    [0xc6120000, 0xc613ffff], // 198.18.0.0/15
    [0xe0000000, 0xffffffff], // multicast/reserved
  ];
  return ranges.some(([start, end]) => n >= start && n <= end);
}

function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (BLOCKED_HOSTS.has(host)) return true;
  if (isPrivateIPv4(host)) return true;
  if (host.includes(":") && host.startsWith("[")) return true; // IPv6 literals: reject for SSRF safety.
  if (host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".localhost")) return true;
  return false;
}

function normalizeTarget(raw: string): URL {
  if (!raw || raw.length > 4096) throw new Error("Invalid URL.");
  const candidate = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const url = new URL(candidate);
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Only HTTP and HTTPS URLs are supported.");
  if (isBlockedHostname(url.hostname)) throw new Error("This destination is not allowed.");
  url.username = "";
  url.password = "";
  return url;
}

function gatewayUrl(target: URL): string {
  return `/proxy?url=${encodeURIComponent(target.toString())}`;
}

function rewriteHtml(html: string, target: URL): string {
  const base = target.toString();
  const origin = target.origin;

  // Rewrite common absolute/protocol-relative/relative resource and navigation URLs.
  // Supports both quoted ("...", '...') and unquoted attribute values.
  // javascript:, data:, blob:, mailto:, tel: and fragments are untouched.
  const attrPattern = /\b(href|src|action|poster|formaction)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  const rewritten = html.replace(
    attrPattern,
    (m, attr: string, valDouble?: string, valSingle?: string, valUnquoted?: string) => {
      const rawVal = valDouble ?? valSingle ?? valUnquoted ?? "";
      const v = rawVal.trim();
      if (!v || v.startsWith("#") || /^(?:javascript|data|blob|mailto|tel):/i.test(v)) return m;
      try {
        const resolved = new URL(v, base);
        if (resolved.protocol !== "http:" && resolved.protocol !== "https:") return m;
        return `${attr}="${gatewayUrl(resolved)}"`;
      } catch {
        return m;
      }
    }
  );

  let withBase = rewritten;
  if (!/<base\b/i.test(withBase)) {
    withBase = withBase.replace(/<head([^>]*)>/i, `<head$1><base href="${origin}/">`);
  }
  return withBase;
}

function responseHeaders(source: Response): Headers {
  const h = new Headers();
  const allowed = [
    "content-type",
    "content-language",
    "content-encoding",
    "cache-control",
    "etag",
    "last-modified",
    "expires",
    "vary",
  ];
  for (const name of allowed) {
    const value = source.headers.get(name);
    if (value) h.set(name, value);
  }
  h.set("X-RouteX-Gateway", "1");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Referrer-Policy", "no-referrer");
  return h;
}

async function proxy(request: Request): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method not allowed. RouteX supports GET and HEAD requests.", { status: 405 });
  }

  const incoming = new URL(request.url);
  const raw = incoming.searchParams.get("url");
  if (!raw) return new Response("Missing url parameter.", { status: 400 });

  let target: URL;
  try {
    target = normalizeTarget(raw);
  } catch (error) {
    return new Response(error instanceof Error ? error.message : "Invalid URL.", { status: 400 });
  }

  const headers = new Headers();
  const accept = request.headers.get("Accept");
  if (accept) headers.set("Accept", accept);
  const language = request.headers.get("Accept-Language");
  if (language) headers.set("Accept-Language", language);
  headers.set("User-Agent", "RouteX-Web-Gateway/1.0");

  let upstream: Response;
  try {
    upstream = await fetch(target.toString(), {
      method: request.method,
      headers,
      redirect: "follow",
      cf: { cacheTtl: 0, cacheEverything: false },
    });
  } catch {
    return new Response("The destination could not be reached.", { status: 502 });
  }

  const outHeaders = responseHeaders(upstream);
  const contentType = upstream.headers.get("content-type") || "";

  if (contentType.includes("text/html") && request.method === "GET") {
    const html = await upstream.text();
    return new Response(rewriteHtml(html, target), {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: outHeaders,
    });
  }

  return new Response(request.method === "HEAD" ? null : upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: outHeaders,
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({ ok: true, service: "RouteX", storage: "none" });
    }

    if (url.pathname === "/proxy") {
      return proxy(request);
    }

    if (url.pathname.startsWith("/api/")) {
      return Response.json({
        service: "RouteX",
        stateless: true,
        storage: "none",
        endpoints: ["/health", "/proxy?url=https://example.com"],
      });
    }

    return env.ASSETS.fetch(request);
  },
};
