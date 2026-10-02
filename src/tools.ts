/**
 * RouteX Stateless Inspector Tools
 * Provides independent analysis endpoints for headers, security headers,
 * redirects, links, robots.txt, sitemaps, JSON/XML, and response metadata.
 */

import { normalizeTarget } from "./security.ts";

const TOOL_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 RouteX-Tool/1.0";

/**
 * 1. HTTP Header Inspector
 */
export async function inspectHeaders(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  const startTime = Date.now();

  const res = await fetch(target.toString(), {
    method: "GET",
    headers: { "User-Agent": TOOL_USER_AGENT },
    redirect: "manual",
  });
  const latencyMs = Date.now() - startTime;

  const rawHeaders: Record<string, string> = {};
  res.headers.forEach((val, key) => {
    rawHeaders[key] = val;
  });

  return {
    target: target.toString(),
    status: res.status,
    statusText: res.statusText,
    latencyMs,
    headerCount: Object.keys(rawHeaders).length,
    headers: rawHeaders,
  };
}

/**
 * 2. Security Header Checker
 * Reports technical observations only without subjective safety assertions.
 */
export async function checkSecurityHeaders(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  const res = await fetch(target.toString(), {
    method: "HEAD",
    headers: { "User-Agent": TOOL_USER_AGENT },
    redirect: "follow",
  });

  const headers = res.headers;
  const securityChecks = [
    {
      header: "Strict-Transport-Security",
      present: headers.has("strict-transport-security"),
      value: headers.get("strict-transport-security"),
      description: "Instructs browsers to strictly use HTTPS connections.",
    },
    {
      header: "Content-Security-Policy",
      present: headers.has("content-security-policy"),
      value: headers.get("content-security-policy"),
      description: "Restricts resource loading domains to reduce XSS impact.",
    },
    {
      header: "X-Content-Type-Options",
      present: headers.has("x-content-type-options"),
      value: headers.get("x-content-type-options"),
      description: "Prevents MIME-type sniffing by browsers.",
    },
    {
      header: "X-Frame-Options",
      present: headers.has("x-frame-options"),
      value: headers.get("x-frame-options"),
      description: "Controls whether the document can be embedded in frame/iframe.",
    },
    {
      header: "Referrer-Policy",
      present: headers.has("referrer-policy"),
      value: headers.get("referrer-policy"),
      description: "Determines how much referrer information is included with requests.",
    },
    {
      header: "Permissions-Policy",
      present: headers.has("permissions-policy"),
      value: headers.get("permissions-policy"),
      description: "Controls browser features and APIs (e.g. geolocation, camera).",
    },
    {
      header: "Cross-Origin-Opener-Policy",
      present: headers.has("cross-origin-opener-policy"),
      value: headers.get("cross-origin-opener-policy"),
      description: "Isolates the browsing context from cross-origin documents.",
    },
    {
      header: "Cross-Origin-Resource-Policy",
      present: headers.has("cross-origin-resource-policy"),
      value: headers.get("cross-origin-resource-policy"),
      description: "Blocks others from loading your resources cross-origin.",
    },
  ];

  const presentCount = securityChecks.filter((c) => c.present).length;

  return {
    target: target.toString(),
    observation: `${presentCount} of ${securityChecks.length} standard security headers are present.`,
    headersChecked: securityChecks,
  };
}

/**
 * 3. Redirect Checker
 * Traces each redirect hop manually up to 10 hops.
 */
export async function traceRedirects(rawUrl: string): Promise<Record<string, unknown>> {
  let current = normalizeTarget(rawUrl);
  const hops: Array<{
    hop: number;
    url: string;
    status: number;
    statusText: string;
    location: string | null;
  }> = [];

  const maxHops = 10;
  for (let i = 1; i <= maxHops; i++) {
    const res = await fetch(current.toString(), {
      method: "HEAD",
      headers: { "User-Agent": TOOL_USER_AGENT },
      redirect: "manual",
    });

    const location = res.headers.get("location");
    hops.push({
      hop: i,
      url: current.toString(),
      status: res.status,
      statusText: res.statusText,
      location,
    });

    if ([301, 302, 303, 307, 308].includes(res.status) && location) {
      try {
        current = normalizeTarget(new URL(location, current).toString());
      } catch {
        break;
      }
    } else {
      break;
    }
  }

  return {
    initialUrl: rawUrl,
    totalHops: hops.length - 1,
    finalUrl: hops[hops.length - 1].url,
    hops,
  };
}

/**
 * 4. Link Extractor
 */
export async function extractLinks(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  const res = await fetch(target.toString(), {
    headers: { "User-Agent": TOOL_USER_AGENT },
    redirect: "follow",
  });

  const html = await res.text();
  const internal: string[] = [];
  const external: string[] = [];
  const resources: string[] = [];

  const linkRegex = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let match: RegExpExecArray | null;
  while ((match = linkRegex.exec(html)) !== null) {
    const rawHref = (match[1] ?? match[2] ?? match[3] ?? "").trim();
    if (!rawHref || rawHref.startsWith("#") || /^(?:javascript|mailto|tel):/i.test(rawHref)) continue;

    try {
      const resolved = new URL(rawHref, target);
      if (resolved.origin === target.origin) {
        internal.push(resolved.toString());
      } else {
        external.push(resolved.toString());
      }
    } catch {}
  }

  const assetRegex = /\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  while ((match = assetRegex.exec(html)) !== null) {
    const rawAsset = (match[1] ?? match[2] ?? match[3] ?? "").trim();
    if (/\.(?:css|js|png|jpg|jpeg|gif|svg|webp|woff2|woff|ttf|mp4|webm)/i.test(rawAsset)) {
      try {
        resources.push(new URL(rawAsset, target).toString());
      } catch {}
    }
  }

  return {
    target: target.toString(),
    counts: {
      internalLinks: new Set(internal).size,
      externalLinks: new Set(external).size,
      resourceLinks: new Set(resources).size,
    },
    internalLinks: [...new Set(internal)].slice(0, 100),
    externalLinks: [...new Set(external)].slice(0, 100),
    resources: [...new Set(resources)].slice(0, 100),
  };
}

/**
 * 5. robots.txt Viewer
 */
export async function viewRobots(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  const robotsUrl = new URL("/robots.txt", target.origin);

  const res = await fetch(robotsUrl.toString(), {
    headers: { "User-Agent": TOOL_USER_AGENT },
    redirect: "follow",
  });

  if (res.status === 404) {
    return {
      target: target.origin,
      robotsUrl: robotsUrl.toString(),
      status: 404,
      found: false,
      message: "No robots.txt found on target origin.",
    };
  }

  const content = await res.text();
  const sitemaps: string[] = [];
  const lines = content.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (/^Sitemap:\s*/i.test(trimmed)) {
      sitemaps.push(trimmed.replace(/^Sitemap:\s*/i, "").trim());
    }
  }

  return {
    target: target.origin,
    robotsUrl: robotsUrl.toString(),
    status: res.status,
    found: res.status === 200,
    sitemaps,
    rawContent: content.slice(0, 20000), // Sane length limit
  };
}

/**
 * 6. sitemap.xml Parser / Viewer
 */
export async function parseSitemap(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  let sitemapUrl = target.toString();
  if (!sitemapUrl.endsWith(".xml")) {
    sitemapUrl = new URL("/sitemap.xml", target.origin).toString();
  }

  const res = await fetch(sitemapUrl, {
    headers: { "User-Agent": TOOL_USER_AGENT },
    redirect: "follow",
  });

  if (res.status !== 200) {
    return {
      sitemapUrl,
      status: res.status,
      found: false,
      message: `Failed to retrieve sitemap. Server returned HTTP ${res.status}.`,
    };
  }

  const xml = await res.text();
  const locs: string[] = [];
  const locRegex = /<loc>([^<]+)<\/loc>/gi;
  let match: RegExpExecArray | null;
  while ((match = locRegex.exec(xml)) !== null) {
    locs.push(match[1].trim());
  }

  return {
    sitemapUrl,
    status: res.status,
    found: true,
    totalEntries: locs.length,
    entries: locs.slice(0, 100),
  };
}

/**
 * 7. JSON Formatter / Inspector
 */
export async function formatJson(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  const res = await fetch(target.toString(), {
    headers: { "User-Agent": TOOL_USER_AGENT, Accept: "application/json" },
    redirect: "follow",
  });

  const text = await res.text();
  try {
    const parsed = JSON.parse(text);
    return {
      target: target.toString(),
      status: res.status,
      isValidJson: true,
      dataType: Array.isArray(parsed) ? "array" : typeof parsed,
      entryCount: typeof parsed === "object" && parsed !== null ? Object.keys(parsed).length : 1,
      data: parsed,
    };
  } catch (err) {
    return {
      target: target.toString(),
      status: res.status,
      isValidJson: false,
      error: err instanceof Error ? err.message : "Invalid JSON",
      rawPreview: text.slice(0, 500),
    };
  }
}

/**
 * 8. XML Viewer / Formatter
 */
export async function viewXml(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  const res = await fetch(target.toString(), {
    headers: { "User-Agent": TOOL_USER_AGENT, Accept: "application/xml, text/xml" },
    redirect: "follow",
  });

  const text = await res.text();
  const rootTagMatch = text.match(/<([a-zA-Z0-9_-]+)[\s>]/);
  return {
    target: target.toString(),
    status: res.status,
    contentType: res.headers.get("content-type"),
    lengthBytes: text.length,
    rootElement: rootTagMatch ? rootTagMatch[1] : null,
    snippet: text.slice(0, 2000),
  };
}

/**
 * 9. Comprehensive Response Information
 */
export async function responseInfo(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  const start = Date.now();

  const res = await fetch(target.toString(), {
    method: "GET",
    headers: { "User-Agent": TOOL_USER_AGENT },
    redirect: "manual",
  });
  const durationMs = Date.now() - start;

  return {
    target: target.toString(),
    status: res.status,
    statusText: res.statusText,
    durationMs,
    contentType: res.headers.get("content-type"),
    contentEncoding: res.headers.get("content-encoding") || "none",
    contentLength: res.headers.get("content-length") || "chunked",
    server: res.headers.get("server") || "unspecified",
    cacheControl: res.headers.get("cache-control") || "none",
    etag: res.headers.get("etag") || "none",
    lastModified: res.headers.get("last-modified") || "none",
  };
}
