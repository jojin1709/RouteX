/**
 * RouteX Content Rewriter Engine
 * Handles generic HTML URL rewriting, CSS @import / url(...) resolution,
 * srcset candidates, and safe response header filtering.
 */

import { isBlockedHostname } from "./security.ts";

export function gatewayUrl(target: URL): string {
  return `/proxy?url=${encodeURIComponent(target.toString())}`;
}

/**
 * Resolves a raw URL against a base URL and converts to gateway proxy URL.
 * Prevents double-proxying and ignores non-http(s) schemes.
 */
export function resolveAndProxy(rawUrl: string, baseUrl: URL): string {
  if (!rawUrl) return rawUrl;
  const v = rawUrl.trim();

  // Ignore fragment anchors, javascript:, data:, blob:, mailto:, tel:, about:
  if (!v || v.startsWith("#") || /^(?:javascript|data|blob|mailto|tel|about|urn):/i.test(v)) {
    return v;
  }

  // Prevent double-proxying for relative gateway paths
  if (v.startsWith("/proxy?url=") || v.startsWith("proxy?url=")) {
    return v.startsWith("/") ? v : `/${v}`;
  }

  try {
    const resolved = new URL(v, baseUrl);

    // Only proxy http: and https: protocols
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") {
      return v;
    }

    // Prevent double-proxying for absolute gateway URLs
    if (resolved.pathname === "/proxy" && resolved.searchParams.has("url")) {
      return `/proxy?url=${encodeURIComponent(resolved.searchParams.get("url")!)}`;
    }

    // Skip destinations blocked by SSRF policy
    if (isBlockedHostname(resolved.hostname)) {
      return v;
    }

    // Strip credentials
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
export function rewriteSrcset(srcsetValue: string, baseUrl: URL): string {
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
export function rewriteCss(css: string, cssUrl: URL): string {
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

  // 2. @import "..." and @import '...' (excluding @import url(...) already handled above)
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
export function rewriteHtml(html: string, pageUrl: URL): string {
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

  // 7. Inject client-side SPA navigation shim so Next.js/React router stays inside gateway
  const shim = buildSpaNavigationShim(activeBase);
  if (/<head\b[^>]*>/i.test(rewritten)) {
    rewritten = rewritten.replace(/<head\b[^>]*>/i, (m) => `${m}\n${shim}`);
  } else if (/<html\b[^>]*>/i.test(rewritten)) {
    rewritten = rewritten.replace(/<html\b[^>]*>/i, (m) => `${m}\n<head>${shim}</head>`);
  } else {
    rewritten = `${shim}\n${rewritten}`;
  }

  return rewritten;
}

/**
 * Builds lightweight, non-invasive client-side navigation shim.
 * Intercepts history.pushState, window.fetch, and link clicks so Single Page Applications
 * (Next.js App Router, React, Vue, Remix) stay seamlessly inside the RouteX gateway.
 */
export function buildSpaNavigationShim(pageUrl: URL): string {
  const safeOrigin = pageUrl.origin.replace(/"/g, '\\"');
  const safeUrl = pageUrl.toString().replace(/"/g, '\\"');

  return `<script id="__routex_spa_shim">
(function() {
  if (window.__routex_shim_installed) return;
  window.__routex_shim_installed = true;

  var targetOrigin = "${safeOrigin}";
  var targetUrl = "${safeUrl}";
  var gatewayOrigin = window.location.origin;

  function wrapUrl(url) {
    if (!url || typeof url !== "string") return url;
    var trimmed = url.trim();
    if (!trimmed || trimmed.startsWith("#") || /^(?:javascript|data|blob|mailto|tel):/i.test(trimmed)) return url;
    if (trimmed.startsWith("/proxy?url=") || trimmed.startsWith(gatewayOrigin + "/proxy?url=")) return url;
    try {
      var resolved = new URL(trimmed, targetUrl);
      if (resolved.origin === targetOrigin) {
        return gatewayOrigin + "/proxy?url=" + encodeURIComponent(resolved.toString());
      }
    } catch(e) {}
    return url;
  }

  // 1. Intercept SPA routing (Next.js, Remix, React Router, Vue, Nuxt)
  var origPushState = history.pushState;
  var origReplaceState = history.replaceState;
  history.pushState = function(state, title, url) {
    return origPushState.call(history, state, title, wrapUrl(url));
  };
  history.replaceState = function(state, title, url) {
    return origReplaceState.call(history, state, title, wrapUrl(url));
  };

  // 2. Intercept window.fetch from client components and RSC payloads
  var origFetch = window.fetch;
  window.fetch = function(input, init) {
    if (typeof input === "string") {
      input = wrapUrl(input);
    } else if (input && typeof input.url === "string") {
      try {
        var wrapped = wrapUrl(input.url);
        if (wrapped !== input.url) {
          input = new Request(wrapped, input);
        }
      } catch(e) {}
    }
    return origFetch.call(this, input, init);
  };

  // 3. Intercept XMLHttpRequest for dynamic client requests
  var origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    arguments[1] = wrapUrl(url);
    return origOpen.apply(this, arguments);
  };

  // 4. Intercept clicks on links that may be dynamically rendered
  document.addEventListener("click", function(e) {
    var a = e.target && e.target.closest ? e.target.closest("a") : null;
    if (a) {
      var rawHref = a.getAttribute("href");
      if (rawHref) {
        var wrapped = wrapUrl(rawHref);
        if (wrapped && wrapped !== rawHref) {
          a.setAttribute("href", wrapped);
        }
      }
    }
  }, true);
})();
</script>`;
}

/**
 * Filter and augment upstream response headers safely.
 */
export function buildResponseHeaders(source: Response, isRewrittenText: boolean): Headers {
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

  // Preserve non-standard upstream HTTP status code (e.g. LinkedIn 999)
  if (source.status < 200 || source.status > 599) {
    h.set("X-Upstream-Status", String(source.status));
  }

  h.set("X-RouteX-Gateway", "1");
  h.set("X-Content-Type-Options", "nosniff");
  // Use same-origin Referrer-Policy so gateway subresource & SPA fallback routing works
  h.set("Referrer-Policy", "same-origin");

  // Allow cross-origin asset loading for proxied sub-resources
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
  h.set("Access-Control-Allow-Headers", "*");

  return h;
}
