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
  if (host.includes(":") && host.startsWith("[")) return true; // IPv6 literals
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

/**
 * Resolves a raw URL against a base URL and converts to gateway proxy URL.
 * Prevents double-proxying and ignores non-http(s) schemes.
 */
function resolveAndProxy(rawUrl: string, baseUrl: URL): string {
  if (!rawUrl) return rawUrl;
  const v = rawUrl.trim();
  if (!v || v.startsWith("#") || /^(?:javascript|data|blob|mailto|tel|about|urn):/i.test(v)) {
    return v;
  }

  // Prevent double-proxying for relative gateway paths
  if (v.startsWith("/proxy?url=") || v.startsWith("proxy?url=")) {
    return v.startsWith("/") ? v : `/${v}`;
  }

  try {
    const resolved = new URL(v, baseUrl);
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") {
      return v;
    }
    // Prevent double-proxying for absolute gateway URLs
    if (resolved.pathname === "/proxy" && resolved.searchParams.has("url")) {
      return `/proxy?url=${encodeURIComponent(resolved.searchParams.get("url")!)}`;
    }
    if (isBlockedHostname(resolved.hostname)) {
      return v;
    }
    resolved.username = "";
    resolved.password = "";
    return gatewayUrl(resolved);
  } catch {
    return v;
  }
}

/**
 * Rewrites srcset attributes containing comma-separated URLs with optional descriptors.
 */
function rewriteSrcset(srcsetValue: string, baseUrl: URL): string {
  if (!srcsetValue) return srcsetValue;
  const candidates = srcsetValue.split(/,(?=\s*\S)/);
  return candidates
    .map((candidate) => {
      const trimmed = candidate.trim();
      if (!trimmed) return trimmed;
      const parts = trimmed.split(/\s+/);
      const urlPart = parts[0];
      const descriptor = parts.slice(1).join(" ");
      const proxiedUrl = resolveAndProxy(urlPart, baseUrl);
      return descriptor ? `${proxiedUrl} ${descriptor}` : proxiedUrl;
    })
    .join(", ");
}

/**
 * Rewrites url(...) and @import in CSS content relative to the CSS file's own URL.
 */
function rewriteCss(css: string, cssUrl: URL): string {
  if (!css) return css;

  // 1. url(...) with optional quotes
  const urlPattern = /\burl\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)/gi;
  let rewritten = css.replace(urlPattern, (m, dQuote, sQuote, unquoted) => {
    const rawVal = (dQuote ?? sQuote ?? unquoted ?? "").trim();
    if (!rawVal || rawVal.startsWith("#") || /^(?:data|blob):/i.test(rawVal)) {
      return m;
    }
    const proxied = resolveAndProxy(rawVal, cssUrl);
    return `url("${proxied}")`;
  });

  // 2. @import "..." and @import '...' (excluding @import url(...) already handled)
  const importPattern = /@import\s+(?:"([^"]+)"|'([^']+)')/gi;
  rewritten = rewritten.replace(importPattern, (_m, dQuote, sQuote) => {
    const rawVal = (dQuote ?? sQuote ?? "").trim();
    if (!rawVal) return _m;
    const proxied = resolveAndProxy(rawVal, cssUrl);
    return `@import "${proxied}"`;
  });

  return rewritten;
}

/**
 * Rewrites HTML navigation and resource links.
 */
function rewriteHtml(html: string, pageUrl: URL): string {
  let activeBase = pageUrl;

  // 1. Check for existing <base href="...">
  const baseTagMatch = html.match(/<base\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/i);
  if (baseTagMatch) {
    const rawBase = (baseTagMatch[1] ?? baseTagMatch[2] ?? baseTagMatch[3] ?? "").trim();
    if (rawBase) {
      try {
        activeBase = new URL(rawBase, pageUrl);
      } catch {}
    }
  }

  // 2. Rewrite <style>...</style> blocks
  let rewritten = html.replace(/<style\b([^>]*)>([\s\S]*?)<\/style>/gi, (_m, attrs, content) => {
    return `<style${attrs}>${rewriteCss(content, activeBase)}</style>`;
  });

  // 3. Rewrite inline style="..." attributes
  rewritten = rewritten.replace(/\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, (_m, dQuote, sQuote) => {
    const rawStyle = dQuote ?? sQuote ?? "";
    const quote = dQuote !== undefined ? '"' : "'";
    return `style=${quote}${rewriteCss(rawStyle, activeBase)}${quote}`;
  });

  // 4. Rewrite srcset attributes
  rewritten = rewritten.replace(/\bsrcset\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi, (_m, dQuote, sQuote, unquoted) => {
    const rawVal = dQuote ?? sQuote ?? unquoted ?? "";
    return `srcset="${rewriteSrcset(rawVal, activeBase)}"`;
  });

  // 5. Rewrite form action ONLY for GET forms (or forms with unspecified method)
  rewritten = rewritten.replace(/<form\b([^>]*?)>/gi, (formTag, attrs) => {
    if (/\bmethod\s*=\s*["']?post\b/i.test(attrs)) {
      return formTag;
    }
    const rewrittenAttrs = attrs.replace(/\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi, (_a: string, d: string, s: string, u: string) => {
      const rawVal = (d ?? s ?? u ?? "").trim();
      return `action="${resolveAndProxy(rawVal, activeBase)}"`;
    });
    return `<form${rewrittenAttrs}>`;
  });

  // 6. Rewrite standard resource and navigation attributes: href, src, poster
  const attrPattern = /\b(href|src|poster)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  rewritten = rewritten.replace(attrPattern, (m, attr: string, dQuote?: string, sQuote?: string, unquoted?: string) => {
    const rawVal = (dQuote ?? sQuote ?? unquoted ?? "").trim();
    if (!rawVal || rawVal.startsWith("#") || /^(?:javascript|data|blob|mailto|tel):/i.test(rawVal)) {
      return m;
    }
    return `${attr}="${resolveAndProxy(rawVal, activeBase)}"`;
  });

  // 7. Patch Remix context to prevent client hydration reload loop
  rewritten = rewritten.replace(
    /(<script\b[^>]*\b(?:data-ttark|id)=["']__remixContext["'][^>]*>)([\s\S]*?)(<\/script>)/gi,
    (_m, openTag, content, closeTag) => {
      try {
        const decoded = decodeURIComponent(content);
        const ctx = JSON.parse(decoded);
        ctx.url = "/proxy";
        ctx.isSpaMode = true;
        return `${openTag}${encodeURIComponent(JSON.stringify(ctx))}${closeTag}`;
      } catch {
        return _m;
      }
    }
  );

  // 8. Inject client-side runtime shim for SPA hydration and fetch interception
  const targetBase = pageUrl.toString();
  const shim = `<script id="__routex_shim__">
(function(){
  var TB = ${JSON.stringify(targetBase)};
  var reloads = 0;
  var _r = window.location.reload;
  window.location.reload = function(){
    reloads++;
    if (reloads > 1) {
      console.warn("RouteX: Suppressed client reload loop.");
      return;
    }
    return _r.apply(this, arguments);
  };

  // Intercept window.__remixContext assignments to guarantee url matches pathname
  var _rcVal = undefined;
  try {
    Object.defineProperty(window, '__remixContext', {
      configurable: true,
      enumerable: true,
      get: function() { return _rcVal; },
      set: function(v) {
        if (v && typeof v === 'object') {
          v.url = window.location.pathname;
          v.isSpaMode = true;
        }
        _rcVal = v;
      }
    });
  } catch(e){}

  var _f = window.fetch;
  if (_f) {
    window.fetch = function(input, init) {
      try {
        if (typeof input === 'string') {
          if (!input.startsWith('/proxy?url=') && !input.startsWith('data:') && !input.startsWith('blob:') && !input.startsWith('javascript:')) {
            input = '/proxy?url=' + encodeURIComponent(new URL(input, TB).toString());
          }
        } else if (input && input.url && !input.url.includes('/proxy?url=')) {
          input = new Request('/proxy?url=' + encodeURIComponent(new URL(input.url, TB).toString()), input);
        }
      } catch(e){}
      return _f.call(this, input, init);
    };
  }
  var _xhr = window.XMLHttpRequest;
  if (_xhr && _xhr.prototype) {
    var _o = _xhr.prototype.open;
    _xhr.prototype.open = function(m, u) {
      try {
        if (typeof u === 'string' && !u.startsWith('/proxy?url=') && !u.startsWith('data:') && !u.startsWith('blob:')) {
          u = '/proxy?url=' + encodeURIComponent(new URL(u, TB).toString());
          arguments[1] = u;
        }
      } catch(e){}
      return _o.apply(this, arguments);
    };
  }
})();
</script>`;

  if (/<head\b[^>]*>/i.test(rewritten)) {
    rewritten = rewritten.replace(/<head\b([^>]*)>/i, `<head$1>${shim}`);
  } else {
    rewritten = shim + rewritten;
  }

  return rewritten;
}

/**
 * Filter and augment upstream response headers safely.
 */
function responseHeaders(source: Response, isRewrittenText: boolean): Headers {
  const h = new Headers();
  const allowed = [
    "content-type",
    "content-language",
    "cache-control",
    "etag",
    "last-modified",
    "expires",
    "vary",
    "accept-ranges",
  ];
  for (const name of allowed) {
    const value = source.headers.get(name);
    if (value) h.set(name, value);
  }

  // Preserve content-length and content-encoding only when the body is untouched
  if (!isRewrittenText) {
    const cl = source.headers.get("content-length");
    if (cl) h.set("content-length", cl);
    const ce = source.headers.get("content-encoding");
    if (ce) h.set("content-encoding", ce);
  }

  h.set("X-RouteX-Gateway", "1");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Referrer-Policy", "no-referrer");

  // Allow cross-origin asset loading for proxied sub-resources
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
  h.set("Access-Control-Allow-Headers", "*");

  return h;
}

async function proxy(request: Request): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400",
        "X-RouteX-Gateway": "1",
      },
    });
  }

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
  const forwardHeaders = [
    "Accept",
    "Accept-Language",
    "Sec-CH-UA",
    "Sec-CH-UA-Mobile",
    "Sec-CH-UA-Platform",
    "Sec-Fetch-Dest",
    "Sec-Fetch-Mode",
    "Sec-Fetch-Site",
  ];
  for (const name of forwardHeaders) {
    const val = request.headers.get(name);
    if (val) headers.set(name, val);
  }

  const clientUa = request.headers.get("User-Agent");
  headers.set(
    "User-Agent",
    clientUa && !clientUa.includes("RouteX")
      ? clientUa
      : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
  );
  headers.set("Referer", `${target.origin}/`);

  let upstream: Response;
  try {
    upstream = await fetch(target.toString(), {
      method: request.method,
      headers,
      redirect: "manual",
      cf: { cacheTtl: 0, cacheEverything: false },
    });
  } catch {
    return new Response("The destination could not be reached.", { status: 502 });
  }

  // Handle redirects (301, 302, 303, 307, 308)
  if ([301, 302, 303, 307, 308].includes(upstream.status)) {
    const loc = upstream.headers.get("Location");
    if (loc) {
      try {
        const resolvedLoc = new URL(loc, target);
        const redHeaders = responseHeaders(upstream, false);
        redHeaders.set("Location", gatewayUrl(resolvedLoc));
        return new Response(null, {
          status: upstream.status,
          statusText: upstream.statusText,
          headers: redHeaders,
        });
      } catch {
        return new Response("Invalid redirect location from upstream.", { status: 502 });
      }
    }
  }

  const contentType = (upstream.headers.get("content-type") || "").toLowerCase();

  // HTML Rewriting
  if ((contentType.includes("text/html") || contentType.includes("application/xhtml+xml")) && request.method === "GET") {
    const html = await upstream.text();
    const rewritten = rewriteHtml(html, target);
    const outHeaders = responseHeaders(upstream, true);
    outHeaders.set("Content-Type", "text/html; charset=utf-8");
    return new Response(rewritten, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: outHeaders,
    });
  }

  // CSS Rewriting
  if (contentType.includes("text/css") && request.method === "GET") {
    const css = await upstream.text();
    const rewritten = rewriteCss(css, target);
    const outHeaders = responseHeaders(upstream, true);
    outHeaders.set("Content-Type", "text/css; charset=utf-8");
    return new Response(rewritten, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: outHeaders,
    });
  }

  // Binary, JavaScript, fonts, media, and JSON: return untouched stream directly
  const outHeaders = responseHeaders(upstream, false);
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

    // Serve known static assets
    if (url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/styles.css" || url.pathname === "/app.js") {
      return env.ASSETS.fetch(request);
    }

    // Fallback: If a client-side SPA or browser sends a relative request without /proxy,
    // check the Referer header to identify the parent proxied target.
    const referer = request.headers.get("Referer");
    if (referer) {
      try {
        const refUrl = new URL(referer);
        const parentTarget = refUrl.searchParams.get("url");
        if (parentTarget) {
          const resolved = new URL(url.pathname + url.search, parentTarget);
          const proxiedUrl = new URL(request.url);
          proxiedUrl.pathname = "/proxy";
          proxiedUrl.search = `?url=${encodeURIComponent(resolved.toString())}`;
          return proxy(new Request(proxiedUrl.toString(), request));
        }
      } catch {}
    }

    return env.ASSETS.fetch(request);
  },
};
