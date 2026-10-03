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
import { getDaytonaStatus, handleDaytonaTool } from "./daytona.ts";
import { runDiagnostics } from "./diagnostics.ts";
import { buildResponseHeaders, gatewayUrl, rewriteCss, rewriteHtml } from "./rewriter.ts";
import { MAX_HTML_SIZE_BYTES, normalizeTarget } from "./security.ts";
import {
  checkSecurityHeaders,
  executeBatch,
  extractLinks,
  extractMarkdown,
  extractMetadata,
  formatJson,
  inspectHeaders,
  inspectTls,
  lookupArchive,
  lookupCert,
  lookupDns,
  lookupWhois,
  parseFeed,
  parseSitemap,
  responseInfo,
  traceRedirects,
  viewRobots,
  viewXml,
} from "./tools.ts";
import { handleMcpRequest } from "./mcp.ts";
import { openApiSpec } from "./openapi.ts";
import { verifyTurnstileToken } from "./turnstile.ts";
import type { Env } from "./types.ts";

/**
 * Ensures an HTTP status code is valid for standard Response construction (200-599).
 * Non-standard status codes returned by upstream servers (e.g. LinkedIn 999 Request Denied,
 * Cloudflare 520-526 edge codes, or legacy custom codes) are mapped safely to 502 Bad Gateway
 * so the Worker never crashes with a RangeError.
 */
export function sanitizeHttpStatus(status: number): number {
  if (Number.isInteger(status) && status >= 200 && status <= 599) {
    return status;
  }
  return 502;
}

/**
 * Sanitizes statusText to conform to HTTP Reason-Phrase production.
 * Prevents TypeError if upstream returns non-standard or control characters.
 */
export function sanitizeStatusText(statusText: string | null | undefined): string | undefined {
  if (!statusText) return undefined;
  const cleaned = statusText.replace(/[\r\n\x00-\x1F\x7F-\xFF]/g, "").trim();
  return cleaned.length > 0 && cleaned !== "<none>" ? cleaned : undefined;
}

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

  // User-Agent selection: check ?ua=mobile or ?ua=desktop
  const uaMode = incoming.searchParams.get("ua");
  if (uaMode === "mobile") {
    forwardHeaders.set(
      "User-Agent",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
    );
  } else if (uaMode === "desktop") {
    forwardHeaders.set(
      "User-Agent",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    );
  } else {
    // Forward client User-Agent or default to standard desktop browser
    const clientUa = request.headers.get("User-Agent");
    forwardHeaders.set(
      "User-Agent",
      clientUa && !clientUa.includes("RouteX")
        ? clientUa
        : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    );
  }

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

  const safeStatus = sanitizeHttpStatus(upstream.status);
  const safeStatusText = sanitizeStatusText(upstream.statusText);

  // 6. Upstream redirect handling (301, 302, 303, 307, 308)
  if ([301, 302, 303, 307, 308].includes(upstream.status)) {
    const location = upstream.headers.get("Location");
    if (location) {
      try {
        const resolvedLocation = new URL(location, target);
        const redirectHeaders = buildResponseHeaders(upstream, false);
        redirectHeaders.set("Location", gatewayUrl(resolvedLocation));
        return new Response(null, {
          status: safeStatus,
          statusText: safeStatusText,
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
  const isDownload = incoming.searchParams.get("download") === "1" || incoming.searchParams.get("download") === "true";

  function applyDownload(h: Headers): Headers {
    if (isDownload) {
      const pathParts = target.pathname.split("/").filter(Boolean);
      const last = pathParts[pathParts.length - 1];
      let filename = "download";
      if (last && last.includes(".")) {
        filename = last.replace(/[^a-zA-Z0-9._-]/g, "_");
      } else {
        filename = `${target.hostname.replace(/[^a-zA-Z0-9.-]/g, "_")}.html`;
      }
      h.set("Content-Disposition", `attachment; filename="${filename}"`);
    }
    return h;
  }

  // 7. Raw Passthrough Mode: bypass rewriting if ?raw=true or ?raw=1
  const isRaw = incoming.searchParams.get("raw") === "true" || incoming.searchParams.get("raw") === "1";
  if (isRaw) {
    const outHeaders = buildResponseHeaders(upstream, false);
    applyDownload(outHeaders);
    outHeaders.set("X-RouteX-Mode", "raw-passthrough");
    if (safeStatus !== upstream.status) {
      outHeaders.set("X-Upstream-Status", String(upstream.status));
    }
    return new Response(request.method === "HEAD" ? null : upstream.body, {
      status: safeStatus,
      statusText: safeStatusText,
      headers: outHeaders,
    });
  }

  // 8. HTML URL Rewriting
  if ((rawContentType.includes("text/html") || rawContentType.includes("application/xhtml+xml")) && request.method === "GET") {
    const contentLength = Number(upstream.headers.get("content-length") || 0);

    // If document exceeds max processing size, stream directly to prevent worker memory exhaustion
    if (contentLength > MAX_HTML_SIZE_BYTES) {
      const outHeaders = buildResponseHeaders(upstream, false);
      applyDownload(outHeaders);
      if (safeStatus !== upstream.status) {
        outHeaders.set("X-Upstream-Status", String(upstream.status));
      }
      return new Response(upstream.body, {
        status: safeStatus,
        statusText: safeStatusText,
        headers: outHeaders,
      });
    }

    const htmlText = await upstream.text();
    const rewrittenHtml = rewriteHtml(htmlText, target);
    const outHeaders = buildResponseHeaders(upstream, true);
    applyDownload(outHeaders);
    outHeaders.set("Content-Type", "text/html; charset=utf-8");
    outHeaders.set("Set-Cookie", `__routex_target=${encodeURIComponent(target.origin)}; Path=/; SameSite=Lax`);
    if (safeStatus !== upstream.status) {
      outHeaders.set("X-Upstream-Status", String(upstream.status));
    }

    return new Response(rewrittenHtml, {
      status: safeStatus,
      statusText: safeStatusText,
      headers: outHeaders,
    });
  }

  // 8. CSS URL Rewriting
  if (rawContentType.includes("text/css") && request.method === "GET") {
    const contentLength = Number(upstream.headers.get("content-length") || 0);

    if (contentLength > MAX_HTML_SIZE_BYTES) {
      const outHeaders = buildResponseHeaders(upstream, false);
      applyDownload(outHeaders);
      if (safeStatus !== upstream.status) {
        outHeaders.set("X-Upstream-Status", String(upstream.status));
      }
      return new Response(upstream.body, {
        status: safeStatus,
        statusText: safeStatusText,
        headers: outHeaders,
      });
    }

    const cssText = await upstream.text();
    const rewrittenCss = rewriteCss(cssText, target);
    const outHeaders = buildResponseHeaders(upstream, true);
    applyDownload(outHeaders);
    outHeaders.set("Content-Type", "text/css; charset=utf-8");
    if (safeStatus !== upstream.status) {
      outHeaders.set("X-Upstream-Status", String(upstream.status));
    }

    return new Response(rewrittenCss, {
      status: safeStatus,
      statusText: safeStatusText,
      headers: outHeaders,
    });
  }

  // 9. Binary, JavaScript, fonts, media, PDF, and JSON: direct passthrough stream
  const outHeaders = buildResponseHeaders(upstream, false);
  applyDownload(outHeaders);
  if (safeStatus !== upstream.status) {
    outHeaders.set("X-Upstream-Status", String(upstream.status));
  }
  return new Response(request.method === "HEAD" ? null : upstream.body, {
    status: safeStatus,
    statusText: safeStatusText,
    headers: outHeaders,
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
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

    // --- Edge Client IP & Datacenter / Colo Inspector ---
    if (pathname === "/ip" || pathname === "/my-ip") {
      const clientIp = request.headers.get("cf-connecting-ip") || "127.0.0.1";
      const cf = (request as any).cf || {};
      return Response.json(
        {
          ip: clientIp,
          colo: cf.colo || "unknown",
          country: cf.country || "unknown",
          city: cf.city || "unknown",
          region: cf.region || "unknown",
          postalCode: cf.postalCode || "unknown",
          asn: cf.asn || 0,
          asOrganization: cf.asOrganization || "unknown",
          timezone: cf.timezone || "unknown",
          httpProtocol: cf.httpProtocol || "HTTP/1.1",
          tlsVersion: cf.tlsVersion || "TLSv1.3",
          tlsCipher: cf.tlsCipher || "unknown",
        },
        {
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store, no-cache",
          },
        }
      );
    }

    // --- Developer Request Echo Endpoint ---
    if (pathname === "/echo") {
      const headersObj: Record<string, string> = {};
      request.headers.forEach((val, key) => {
        headersObj[key] = val;
      });
      let bodyPreview: string | null = null;
      if (request.method === "POST" || request.method === "PUT") {
        try {
          bodyPreview = (await request.text()).slice(0, 4096);
        } catch {
          // ignore
        }
      }
      return Response.json(
        {
          method: request.method,
          url: request.url,
          pathname,
          headers: headersObj,
          body: bodyPreview,
          clientIp: request.headers.get("cf-connecting-ip") || "127.0.0.1",
          cf: (request as any).cf || {},
        },
        {
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store",
          },
        }
      );
    }

    // --- Model Context Protocol (MCP) Server Endpoint ---
    if (pathname === "/mcp" || pathname === "/mcp/") {
      return handleMcpRequest(request);
    }

    if (pathname === "/proxy") {
      return proxy(request, env);
    }

    // --- Direct Raw Markdown Reader (like r.jina.ai) ---
    if (pathname === "/r" || pathname.startsWith("/r/")) {
      let rawTarget = "";
      if (pathname === "/r") {
        rawTarget = url.searchParams.get("url") || "";
      } else {
        const fullUrlStr = request.url;
        const rIndex = fullUrlStr.indexOf("/r/");
        if (rIndex !== -1) {
          rawTarget = fullUrlStr.slice(rIndex + 3);
          // If browser normalized https:/domain to single slash, fix it
          if (/^https?:\/[^\/]/i.test(rawTarget)) {
            rawTarget = rawTarget.replace(/^(https?):\/+/i, "$1://");
          }
        }
      }

      if (!rawTarget) {
        return new Response("Missing target URL. Example: /r/https://example.com or /r?url=https://example.com", {
          status: 400,
          headers: { "Content-Type": "text/plain; charset=utf-8", "X-RouteX-Gateway": "1" },
        });
      }

      try {
        const report = await extractMarkdown(rawTarget);
        const md = typeof report.markdown === "string" ? report.markdown : "";
        return new Response(md, {
          status: 200,
          headers: {
            "Content-Type": "text/markdown; charset=utf-8",
            "X-RouteX-Gateway": "1",
            "Access-Control-Allow-Origin": "*",
          },
        });
      } catch (err) {
        return new Response(err instanceof Error ? err.message : "Markdown extraction failed.", {
          status: 400,
          headers: { "Content-Type": "text/plain; charset=utf-8", "X-RouteX-Gateway": "1" },
        });
      }
    }

    // --- Interactive Scalar OpenAPI Documentation ---
    if (pathname === "/docs" || pathname === "/docs/") {
      if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
        const docsReq = new Request(new URL("/docs.html", request.url), request);
        return env.ASSETS.fetch(docsReq);
      }
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

    // --- Daytona Integration Status Endpoint ---
    if (pathname === "/api/daytona/status" || pathname === "/api/tools/daytona/status") {
      return Response.json(getDaytonaStatus(env));
    }

    // --- Optional Daytona Sandboxed Tools (Render, Screenshot, PDF) ---
    if (pathname === "/api/tools/render") {
      return handleDaytonaTool(request, env, "render");
    }
    if (pathname === "/api/tools/screenshot") {
      return handleDaytonaTool(request, env, "screenshot");
    }
    if (pathname === "/api/tools/pdf") {
      return handleDaytonaTool(request, env, "pdf");
    }

    // --- Phase 5: Stateless Inspector Tools ---
    if (pathname.startsWith("/api/tools/")) {
      if (pathname === "/api/tools/batch") {
        if (request.method !== "POST") {
          return new Response("Method not allowed. Use POST with JSON body: { urls: [...] }", {
            status: 405,
            headers: { Allow: "POST", "Content-Type": "text/plain; charset=utf-8" },
          });
        }
        try {
          const body = (await request.json()) as any;
          const urls = Array.isArray(body?.urls) ? body.urls : [];
          const result = await executeBatch(urls);
          return Response.json(result, {
            headers: { "Access-Control-Allow-Origin": "*" },
          });
        } catch (err) {
          return Response.json(
            { ok: false, error: err instanceof Error ? err.message : "Batch execution error." },
            { status: 400 }
          );
        }
      }

      const target = url.searchParams.get("url") || url.searchParams.get("domain");
      if (!target) {
        return Response.json({ ok: false, error: "Missing required 'url' or 'domain' parameter." }, { status: 400 });
      }

      try {
        switch (pathname) {
          case "/api/tools/dns":
            return Response.json(await lookupDns(target));
          case "/api/tools/tls":
            return Response.json(await inspectTls(target));
          case "/api/tools/cert":
            return Response.json(await lookupCert(target));
          case "/api/tools/archive":
            return Response.json(await lookupArchive(target));
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
          case "/api/tools/markdown":
            return Response.json(await extractMarkdown(target));
          case "/api/tools/metadata":
          case "/api/tools/meta":
            return Response.json(await extractMetadata(target));
          case "/api/tools/whois":
            return Response.json(await lookupWhois(target));
          case "/api/tools/feed":
            return Response.json(await parseFeed(target));
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
    if (pathname === "/api/turnstile/config") {
      return Response.json({
        enabled: Boolean(env.TURNSTILE_SECRET_KEY && env.TURNSTILE_SITE_KEY),
        siteKey: env.TURNSTILE_SITE_KEY || null,
      });
    }

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

    // --- OpenAPI 3.1 Specification JSON ---
    if (pathname === "/openapi.json" || pathname === "/api/openapi.json") {
      return Response.json(openApiSpec, {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    // --- API Directory & Interactive Reference ---
    if (pathname === "/api" || pathname === "/api/" || pathname === "/api.json" || pathname === "/api/endpoints") {
      const accept = request.headers.get("accept") || "";
      const format = url.searchParams.get("format");
      const isJsonExplicit = pathname === "/api.json" || pathname === "/api/endpoints" || format === "json";
      const isHtmlExplicit = format === "html";
      const isBrowser = !isJsonExplicit && (isHtmlExplicit || accept.includes("text/html"));

      if (isBrowser && env.ASSETS && typeof env.ASSETS.fetch === "function") {
        const assetReq = new Request(new URL("/api.html", request.url), request);
        return env.ASSETS.fetch(assetReq);
      }

      return Response.json(
        {
          service: "RouteX Web Gateway",
          version: "2.1.0",
          stateless: true,
          storage: "none",
          docs: `${url.origin}/api`,
          openapi: `${url.origin}/openapi.json`,
          endpoints: {
            core: ["/health", "/ip", "/echo", "/mcp", "/proxy?url=https://example.com", "/cors?url=https://example.com", "/r/https://example.com", "/docs", "/openapi.json"],
            diagnostics: ["/diagnostics?url=https://example.com"],
            inspectorTools: [
              "/api/tools/dns?domain=example.com",
              "/api/tools/whois?domain=example.com",
              "/api/tools/tls?url=https://example.com",
              "/api/tools/cert?domain=example.com",
              "/api/tools/archive?url=https://example.com",
              "/api/tools/security-headers?url=https://example.com",
              "/api/tools/headers?url=https://example.com",
              "/api/tools/redirects?url=https://example.com",
              "/api/tools/links?url=https://example.com",
              "/api/tools/robots?url=https://example.com",
              "/api/tools/sitemap?url=https://example.com",
              "/api/tools/feed?url=https://blog.cloudflare.com/rss/",
              "/api/tools/json?url=https://httpbin.org/json",
              "/api/tools/xml?url=https://httpbin.org/xml",
              "/api/tools/markdown?url=https://example.com",
              "/api/tools/metadata?url=https://example.com",
              "/api/tools/response-info?url=https://example.com",
              "/api/tools/batch (POST { urls: ['https://example.com'] })",
            ],
            browserTools: [
              "/api/browser/info",
              "/api/browser/screenshot?url=https://example.com",
              "/api/browser/pdf?url=https://example.com",
              "/api/browser/rendered-html?url=https://example.com",
            ],
            daytonaTools: [
              "/api/daytona/status",
              "/api/tools/render (POST { url: 'https://example.com' })",
              "/api/tools/screenshot (POST { url: 'https://example.com' })",
              "/api/tools/pdf (POST { url: 'https://example.com' })",
            ],
            abuseControl: ["/api/turnstile/verify?token=..."],
          },
        },
        {
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }

    if (pathname === "/cors") {
      const proxiedUrl = new URL(request.url);
      proxiedUrl.pathname = "/proxy";
      if (!proxiedUrl.searchParams.has("raw")) {
        proxiedUrl.searchParams.set("raw", "true");
      }
      return proxy(new Request(proxiedUrl.toString(), request), env);
    }

    // --- Static Frontend Assets in public/ ---
    if (
      pathname === "/" ||
      pathname === "/index.html" ||
      pathname === "/api.html" ||
      pathname === "/docs.html" ||
      pathname === "/styles.css" ||
      pathname === "/app.js" ||
      pathname === "/favicon.ico" ||
      pathname === "/favicon.svg" ||
      pathname === "/robots.txt"
    ) {
      if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
        return env.ASSETS.fetch(request);
      }
      return new Response("Not Found", { status: 404 });
    }

    // --- Fallback: Dynamic subresource and SPA navigation routing via Referer or target cookie ---
    const referer = request.headers.get("Referer");
    const cookieHeader = request.headers.get("Cookie") || "";
    const cookieMatch = cookieHeader.match(/__routex_target=([^;]+)/);
    const cookieTarget = cookieMatch ? decodeURIComponent(cookieMatch[1].trim()) : null;

    let parentTarget: string | null = null;
    if (referer) {
      try {
        const refUrl = new URL(referer);
        parentTarget = refUrl.searchParams.get("url");
      } catch {}
    }
    if (!parentTarget && cookieTarget) {
      parentTarget = cookieTarget;
    }
    if (parentTarget) {
      try {
        const resolved = new URL(pathname + url.search, parentTarget);
        const isHtmlNav = (request.headers.get("Accept") || "").includes("text/html");

        // For browser top-level HTML navigation, redirect to /proxy?url=... so address bar updates
        if (isHtmlNav && request.method === "GET") {
          return new Response(null, {
            status: 302,
            headers: {
              Location: `/proxy?url=${encodeURIComponent(resolved.toString())}`,
              "X-RouteX-Gateway": "1",
            },
          });
        }

        // For subresources (JS, CSS, RSC payloads, fonts, API calls), proxy directly
        const proxiedUrl = new URL(request.url);
        proxiedUrl.pathname = "/proxy";
        proxiedUrl.search = `?url=${encodeURIComponent(resolved.toString())}`;
        return proxy(new Request(proxiedUrl.toString(), request), env);
      } catch {}
    }

    return env.ASSETS.fetch(request);
    } catch (fatalError) {
      console.error("RouteX Uncaught Gateway Exception:", fatalError);
      return new Response(
        JSON.stringify({
          ok: false,
          error: "Internal Gateway Error",
          message: fatalError instanceof Error ? fatalError.message : "An unexpected error occurred in RouteX gateway.",
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "X-RouteX-Gateway": "1",
          },
        }
      );
    }
  },
};
