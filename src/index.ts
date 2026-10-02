/**
 * RouteX — Stateless Cloudflare Web Gateway
 *
 * Architecture:
 * - Stateless HTTP/HTTPS proxy running on Cloudflare Workers + Workers Assets.
 * - Comprehensive SSRF protection (private/loopback IPv4/IPv6, internal hosts, protocol restrictions).
 * - Full HTML/CSS URL rewriting (links, scripts, images, srcset, media, GET forms, CSS @import & url()).
 * - Direct binary streaming for images, fonts, scripts, audio, video, PDFs, and JSON/XML.
 * - Multi-hop redirect handling with location header rewriting.
 * - Integrated diagnostics engine and stateless inspector tools.
 * - Optional Cloudflare Workers Browser Rendering hooks.
 * - Optional Cloudflare Turnstile token validation hooks.
 * - Zero persistent storage (No D1, KV, R2, Durable Objects, cookies, or user logs).
 */

import { handleBrowserTool, isBrowserRenderingAvailable } from "./browser.ts";
import { runDiagnostics } from "./diagnostics.ts";
import { buildResponseHeaders, gatewayUrl, rewriteCss, rewriteHtml } from "./rewriter.ts";
import { MAX_HTML_SIZE_BYTES, normalizeTarget } from "./security.ts";
import {
  checkSecurityHeaders,
  extractLinks,
  formatJson,
  inspectHeaders,
  parseSitemap,
  responseInfo,
  traceRedirects,
  viewRobots,
  viewXml,
} from "./tools.ts";
import { verifyTurnstileToken } from "./turnstile.ts";
import type { Env } from "./types.ts";

/**
 * Handles incoming web proxy requests.
 */
async function proxy(request: Request, _env: Env): Promise<Response> {
  // 1. CORS Preflight
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

  // 2. HTTP Method restriction
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method not allowed. RouteX supports GET, HEAD, and OPTIONS requests.", {
      status: 405,
      headers: {
        Allow: "GET, HEAD, OPTIONS",
        "Content-Type": "text/plain; charset=utf-8",
        "X-RouteX-Gateway": "1",
      },
    });
  }

  // 3. Extract and validate target URL
  const incoming = new URL(request.url);
  const rawTarget = incoming.searchParams.get("url");
  if (!rawTarget) {
    return new Response("Missing required 'url' parameter. Example: /proxy?url=https://example.com", {
      status: 400,
      headers: { "Content-Type": "text/plain; charset=utf-8", "X-RouteX-Gateway": "1" },
    });
  }

  let target: URL;
  try {
    target = normalizeTarget(rawTarget);
  } catch (error) {
    return new Response(error instanceof Error ? error.message : "Invalid destination URL.", {
      status: 400,
      headers: { "Content-Type": "text/plain; charset=utf-8", "X-RouteX-Gateway": "1" },
    });
  }

  // 4. Construct sanitized upstream request headers
  const forwardHeaders = new Headers();
  const safeHeaderNames = [
    "Accept",
    "Accept-Language",
    "Sec-CH-UA",
    "Sec-CH-UA-Mobile",
    "Sec-CH-UA-Platform",
    "Sec-Fetch-Dest",
    "Sec-Fetch-Mode",
    "Sec-Fetch-Site",
  ];
  for (const name of safeHeaderNames) {
    const val = request.headers.get(name);
    if (val) forwardHeaders.set(name, val);
  }

  // Forward client User-Agent or default to standard desktop browser
  const clientUa = request.headers.get("User-Agent");
  forwardHeaders.set(
    "User-Agent",
    clientUa && !clientUa.includes("RouteX")
      ? clientUa
      : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
  );

  // Set Referer to target origin to avoid anti-hotlinking CDN blocks
  forwardHeaders.set("Referer", `${target.origin}/`);

  // 5. Fetch upstream target with manual redirect handling
  let upstream: Response;
  try {
    upstream = await fetch(target.toString(), {
      method: request.method,
      headers: forwardHeaders,
      redirect: "manual",
      cf: { cacheTtl: 0, cacheEverything: false },
    });
  } catch {
    return new Response("The destination could not be reached or timed out.", {
      status: 502,
      headers: { "Content-Type": "text/plain; charset=utf-8", "X-RouteX-Gateway": "1" },
    });
  }

  // 6. Upstream redirect handling (301, 302, 303, 307, 308)
  if ([301, 302, 303, 307, 308].includes(upstream.status)) {
    const location = upstream.headers.get("Location");
    if (location) {
      try {
        const resolvedLocation = new URL(location, target);
        const redirectHeaders = buildResponseHeaders(upstream, false);
        redirectHeaders.set("Location", gatewayUrl(resolvedLocation));
        return new Response(null, {
          status: upstream.status,
          statusText: upstream.statusText,
          headers: redirectHeaders,
        });
      } catch {
        return new Response("Invalid redirect location returned by upstream destination.", {
          status: 502,
          headers: { "Content-Type": "text/plain; charset=utf-8", "X-RouteX-Gateway": "1" },
        });
      }
    }
  }

  const rawContentType = (upstream.headers.get("content-type") || "").toLowerCase();

  // 7. HTML URL Rewriting
  if ((rawContentType.includes("text/html") || rawContentType.includes("application/xhtml+xml")) && request.method === "GET") {
    const contentLength = Number(upstream.headers.get("content-length") || 0);

    // If document exceeds max processing size, stream directly to prevent worker memory exhaustion
    if (contentLength > MAX_HTML_SIZE_BYTES) {
      const outHeaders = buildResponseHeaders(upstream, false);
      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: outHeaders,
      });
    }

    const htmlText = await upstream.text();
    const rewrittenHtml = rewriteHtml(htmlText, target);
    const outHeaders = buildResponseHeaders(upstream, true);
    outHeaders.set("Content-Type", "text/html; charset=utf-8");

    return new Response(rewrittenHtml, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: outHeaders,
    });
  }

  // 8. CSS URL Rewriting
  if (rawContentType.includes("text/css") && request.method === "GET") {
    const contentLength = Number(upstream.headers.get("content-length") || 0);

    if (contentLength > MAX_HTML_SIZE_BYTES) {
      const outHeaders = buildResponseHeaders(upstream, false);
      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: outHeaders,
      });
    }

    const cssText = await upstream.text();
    const rewrittenCss = rewriteCss(cssText, target);
    const outHeaders = buildResponseHeaders(upstream, true);
    outHeaders.set("Content-Type", "text/css; charset=utf-8");

    return new Response(rewrittenCss, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: outHeaders,
    });
  }

  // 9. Binary, JavaScript, fonts, media, PDF, and JSON: direct passthrough stream
  const outHeaders = buildResponseHeaders(upstream, false);
  return new Response(request.method === "HEAD" ? null : upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: outHeaders,
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // --- Core Endpoints ---
    if (pathname === "/health") {
      return Response.json({
        ok: true,
        service: "RouteX Web Gateway",
        stateless: true,
        storage: "none",
        browserRenderingAvailable: isBrowserRenderingAvailable(env),
      });
    }

    if (pathname === "/proxy") {
      return proxy(request, env);
    }

    // --- Phase 4: RouteX Diagnostics ---
    if (pathname === "/diagnostics" || pathname === "/api/diagnostics") {
      const target = url.searchParams.get("url");
      if (!target) {
        return Response.json(
          { ok: false, error: "Missing required 'url' query parameter. Example: /diagnostics?url=https://example.com" },
          { status: 400 }
        );
      }
      const report = await runDiagnostics(target);
      return Response.json(report);
    }

    // --- Phase 5: Stateless Inspector Tools ---
    if (pathname.startsWith("/api/tools/")) {
      const target = url.searchParams.get("url");
      if (!target) {
        return Response.json({ ok: false, error: "Missing required 'url' parameter." }, { status: 400 });
      }

      try {
        switch (pathname) {
          case "/api/tools/headers":
            return Response.json(await inspectHeaders(target));
          case "/api/tools/security-headers":
            return Response.json(await checkSecurityHeaders(target));
          case "/api/tools/redirects":
            return Response.json(await traceRedirects(target));
          case "/api/tools/links":
            return Response.json(await extractLinks(target));
          case "/api/tools/robots":
            return Response.json(await viewRobots(target));
          case "/api/tools/sitemap":
            return Response.json(await parseSitemap(target));
          case "/api/tools/json":
            return Response.json(await formatJson(target));
          case "/api/tools/xml":
            return Response.json(await viewXml(target));
          case "/api/tools/response-info":
            return Response.json(await responseInfo(target));
          default:
            return Response.json({ ok: false, error: "Unknown inspector tool endpoint." }, { status: 404 });
        }
      } catch (err) {
        return Response.json(
          { ok: false, error: err instanceof Error ? err.message : "Tool processing error." },
          { status: 400 }
        );
      }
    }

    // --- Phase 3: Turnstile Verification Endpoint ---
    if (pathname === "/api/turnstile/verify") {
      if (request.method !== "POST" && request.method !== "GET") {
        return new Response("Method not allowed. Use GET or POST.", { status: 405 });
      }
      const token = url.searchParams.get("token") || request.headers.get("cf-turnstile-response");
      if (!token) {
        return Response.json({ ok: false, error: "Missing Turnstile challenge token." }, { status: 400 });
      }
      const clientIp = request.headers.get("cf-connecting-ip");
      const result = await verifyTurnstileToken(token, clientIp, env);
      return Response.json(result);
    }

    // --- Phase 6: Optional Browser Tools ---
    if (pathname.startsWith("/api/browser/")) {
      if (pathname === "/api/browser/info") {
        return Response.json({
          available: isBrowserRenderingAvailable(env),
          note: "Optional diagnostic tool with Free-tier platform quotas.",
        });
      }
      if (pathname === "/api/browser/screenshot") {
        return handleBrowserTool(request, env, "screenshot");
      }
      if (pathname === "/api/browser/pdf") {
        return handleBrowserTool(request, env, "pdf");
      }
      if (pathname === "/api/browser/rendered-html") {
        return handleBrowserTool(request, env, "rendered-html");
      }
    }

    // --- API Directory ---
    if (pathname === "/api" || pathname === "/api/") {
      return Response.json({
        service: "RouteX Web Gateway",
        stateless: true,
        storage: "none",
        endpoints: {
          core: ["/health", "/proxy?url=https://example.com"],
          diagnostics: ["/diagnostics?url=https://example.com"],
          inspectorTools: [
            "/api/tools/headers?url=https://example.com",
            "/api/tools/security-headers?url=https://example.com",
            "/api/tools/redirects?url=https://example.com",
            "/api/tools/links?url=https://example.com",
            "/api/tools/robots?url=https://example.com",
            "/api/tools/sitemap?url=https://example.com",
            "/api/tools/json?url=https://httpbin.org/json",
            "/api/tools/xml?url=https://httpbin.org/xml",
            "/api/tools/response-info?url=https://example.com",
          ],
          abuseControl: ["/api/turnstile/verify?token=..."],
          browserTools: [
            "/api/browser/info",
            "/api/browser/screenshot?url=https://example.com",
            "/api/browser/pdf?url=https://example.com",
            "/api/browser/rendered-html?url=https://example.com",
          ],
        },
      });
    }

    // --- Static Frontend Assets in public/ ---
    if (
      pathname === "/" ||
      pathname === "/index.html" ||
      pathname === "/styles.css" ||
      pathname === "/app.js" ||
      pathname === "/favicon.ico"
    ) {
      return env.ASSETS.fetch(request);
    }

    // --- Fallback: Dynamic subresource request routing via HTTP Referer ---
    const referer = request.headers.get("Referer");
    if (referer) {
      try {
        const refUrl = new URL(referer);
        const parentTarget = refUrl.searchParams.get("url");
        if (parentTarget) {
          const resolved = new URL(pathname + url.search, parentTarget);
          const proxiedUrl = new URL(request.url);
          proxiedUrl.pathname = "/proxy";
          proxiedUrl.search = `?url=${encodeURIComponent(resolved.toString())}`;
          return proxy(new Request(proxiedUrl.toString(), request), env);
        }
      } catch {}
    }

    return env.ASSETS.fetch(request);
  },
};
