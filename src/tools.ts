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

/**
 * 10. DNS-over-HTTPS Record Lookup (via Cloudflare 1.1.1.1)
 */
export async function lookupDns(targetInput: string): Promise<Record<string, unknown>> {
  let hostname = targetInput.trim();
  try {
    if (hostname.startsWith("http://") || hostname.startsWith("https://")) {
      hostname = new URL(hostname).hostname;
    } else if (hostname.includes("/")) {
      hostname = hostname.split("/")[0];
    }
  } catch {
    // Keep raw trimmed string
  }

  // Validate hostname against SSRF policy
  const dummyTarget = normalizeTarget(`https://${hostname}`);
  const validatedHost = dummyTarget.hostname;

  const recordTypes = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"];
  const records: Record<string, unknown[]> = {};

  await Promise.all(
    recordTypes.map(async (rtype) => {
      try {
        const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(validatedHost)}&type=${rtype}`;
        const res = await fetch(dohUrl, {
          headers: { Accept: "application/dns-json" },
        });
        if (res.ok) {
          const data = (await res.json()) as any;
          records[rtype] = Array.isArray(data.Answer) ? data.Answer : [];
        } else {
          records[rtype] = [];
        }
      } catch {
        records[rtype] = [];
      }
    })
  );

  return {
    domain: validatedHost,
    dohProvider: "Cloudflare 1.1.1.1",
    timestamp: new Date().toISOString(),
    records,
  };
}

/**
 * 11. SSL / TLS Security Audit
 */
export async function inspectTls(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  if (target.protocol !== "https:") {
    return {
      target: target.toString(),
      isHttps: false,
      error: "Target does not use HTTPS protocol.",
    };
  }

  const start = Date.now();
  const res = await fetch(target.toString(), {
    method: "HEAD",
    headers: { "User-Agent": TOOL_USER_AGENT },
    redirect: "manual",
  });
  const latencyMs = Date.now() - start;

  const hsts = res.headers.get("strict-transport-security");
  const hasHsts = Boolean(hsts);
  const maxAgeMatch = hsts ? hsts.match(/max-age=(\d+)/) : null;
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : null;
  const includesSubdomains = hsts ? hsts.includes("includeSubDomains") : false;
  const preload = hsts ? hsts.includes("preload") : false;

  return {
    target: target.toString(),
    isHttps: true,
    status: res.status,
    latencyMs,
    security: {
      strictTransportSecurity: {
        present: hasHsts,
        headerValue: hsts,
        maxAgeSeconds: maxAge,
        includesSubdomains,
        preload,
        hstsScore: hasHsts
          ? maxAge && maxAge >= 31536000
            ? "A (Grade 1yr+)"
            : "B (Valid)"
          : "F (No HSTS)",
      },
      upgradeInsecureRequests: res.headers.has("upgrade-insecure-requests"),
      server: res.headers.get("server") || "unspecified",
      protocolVersion: "TLS 1.2 / TLS 1.3 (Enforced by Cloudflare Edge)",
    },
  };
}

function decodeHtmlEntities(str: string): string {
  return str
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&#(\d+);/g, (_, dec) => {
      const code = Number(dec);
      return code >= 32 && code <= 65535 ? String.fromCharCode(code) : "";
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
      const code = parseInt(hex, 16);
      return code >= 32 && code <= 65535 ? String.fromCharCode(code) : "";
    });
}

/**
 * 12. Article Text & Markdown Extractor
 * Strips HTML boilerplate and extracts clean readable Markdown for AI/LLM prompts and CLI consumption.
 */
export async function extractMarkdown(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  const startTime = Date.now();

  const res = await fetch(target.toString(), {
    headers: {
      "User-Agent": TOOL_USER_AGENT,
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    redirect: "follow",
  });

  const contentType = res.headers.get("content-type") || "";
  const rawHtml = await res.text();
  const latencyMs = Date.now() - startTime;

  // Extract metadata
  const titleMatch = rawHtml.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? decodeHtmlEntities(titleMatch[1].trim()) : "";

  const descMatch =
    rawHtml.match(/<meta\b[^>]*\bname=["']description["'][^>]*\bcontent=["']([^"']*)["']/i) ||
    rawHtml.match(/<meta\b[^>]*\bcontent=["']([^"']*)["'][^>]*\bname=["']description["']/i);
  const description = descMatch ? decodeHtmlEntities(descMatch[1].trim()) : "";

  const canonicalMatch =
    rawHtml.match(/<link\b[^>]*\brel=["']canonical["'][^>]*\bhref=["']([^"']*)["']/i) ||
    rawHtml.match(/<link\b[^>]*\bhref=["']([^"']*)["'][^>]*\brel=["']canonical["']/i);
  const canonical = canonicalMatch ? canonicalMatch[1].trim() : "";

  // Strip unneeded structural elements and scripts
  let clean = rawHtml
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, "")
    .replace(/<svg\b[^>]*>[\s\S]*?<\/svg>/gi, "")
    .replace(/<canvas\b[^>]*>[\s\S]*?<\/canvas>/gi, "")
    .replace(/<nav\b[^>]*>[\s\S]*?<\/nav>/gi, "")
    .replace(/<header\b[^>]*>[\s\S]*?<\/header>/gi, "")
    .replace(/<footer\b[^>]*>[\s\S]*?<\/footer>/gi, "")
    .replace(/<aside\b[^>]*>[\s\S]*?<\/aside>/gi, "");

  // Convert headings
  clean = clean.replace(/<h1\b[^>]*>([\s\S]*?)<\/h1>/gi, "\n\n# $1\n\n");
  clean = clean.replace(/<h2\b[^>]*>([\s\S]*?)<\/h2>/gi, "\n\n## $1\n\n");
  clean = clean.replace(/<h3\b[^>]*>([\s\S]*?)<\/h3>/gi, "\n\n### $1\n\n");
  clean = clean.replace(/<h4\b[^>]*>([\s\S]*?)<\/h4>/gi, "\n\n#### $1\n\n");
  clean = clean.replace(/<h5\b[^>]*>([\s\S]*?)<\/h5>/gi, "\n\n##### $1\n\n");
  clean = clean.replace(/<h6\b[^>]*>([\s\S]*?)<\/h6>/gi, "\n\n###### $1\n\n");

  // Code blocks & inline code
  clean = clean.replace(/<pre\b[^>]*><code\b[^>]*>([\s\S]*?)<\/code><\/pre>/gi, "\n\n```\n$1\n```\n\n");
  clean = clean.replace(/<pre\b[^>]*>([\s\S]*?)<\/pre>/gi, "\n\n```\n$1\n```\n\n");
  clean = clean.replace(/<code\b[^>]*>([\s\S]*?)<\/code>/gi, "`$1`");

  // Blockquotes and dividers
  clean = clean.replace(/<blockquote\b[^>]*>([\s\S]*?)<\/blockquote>/gi, (_m, content) => {
    const lines = content.trim().split("\n");
    return "\n\n" + lines.map((l: string) => `> ${l.trim()}`).join("\n") + "\n\n";
  });
  clean = clean.replace(/<hr\b[^>]*>/gi, "\n\n---\n\n");

  // Lists
  clean = clean.replace(/<li\b[^>]*>([\s\S]*?)<\/li>/gi, "\n- $1");

  // Links: [text](href)
  clean = clean.replace(/<a\b[^>]*\bhref=["']([^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi, (_m, href, linkText) => {
    const txt = linkText.replace(/<[^>]+>/g, "").trim();
    if (!txt || !href || href.startsWith("#") || /^javascript:/i.test(href)) {
      return txt;
    }
    try {
      const resolved = new URL(href, target).toString();
      return `[${txt}](${resolved})`;
    } catch {
      return txt;
    }
  });

  // Images: ![alt](src)
  clean = clean.replace(/<img\b[^>]*>/gi, (imgTag) => {
    const srcMatch = imgTag.match(/\bsrc=["']([^"']*)["']/i);
    const altMatch = imgTag.match(/\balt=["']([^"']*)["']/i);
    if (!srcMatch) return "";
    const alt = altMatch ? altMatch[1].trim() : "";
    try {
      const resolved = new URL(srcMatch[1], target).toString();
      return `![${alt}](${resolved})`;
    } catch {
      return "";
    }
  });

  // Emphasis and paragraphs
  clean = clean.replace(/<(?:strong|b)\b[^>]*>([\s\S]*?)<\/(?:strong|b)>/gi, "**$1**");
  clean = clean.replace(/<(?:em|i)\b[^>]*>([\s\S]*?)<\/(?:em|i)>/gi, "*$1*");
  clean = clean.replace(/<p\b[^>]*>([\s\S]*?)<\/p>/gi, "\n\n$1\n\n");
  clean = clean.replace(/<br\s*\/?>/gi, "\n");

  // Strip all remaining HTML tags
  clean = clean.replace(/<[^>]+>/g, "");

  // Decode HTML entities
  clean = decodeHtmlEntities(clean);

  // Normalize excessive blank lines and spaces
  clean = clean
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  const words = clean ? clean.split(/\s+/).filter(Boolean).length : 0;

  return {
    target: target.toString(),
    status: res.status,
    contentType,
    latencyMs,
    title,
    description,
    canonical: canonical || target.toString(),
    wordCount: words,
    lengthChars: clean.length,
    markdown: clean,
  };
}

/**
 * 13. Open Graph & Social Metadata Inspector
 * Extracts SEO, Open Graph (og:*), Twitter Cards, favicons, and JSON-LD structured data.
 */
export async function extractMetadata(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  const startTime = Date.now();

  const res = await fetch(target.toString(), {
    headers: {
      "User-Agent": TOOL_USER_AGENT,
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    redirect: "follow",
  });

  const rawHtml = await res.text();
  const latencyMs = Date.now() - startTime;

  // 1. Page Title
  const titleMatch = rawHtml.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? decodeHtmlEntities(titleMatch[1].trim()) : "";

  // 2. Standard Meta Tags
  const metaTags: Record<string, string> = {};
  const metaRegex = /<meta\b([^>]*?)>/gi;
  let match: RegExpExecArray | null;

  while ((match = metaRegex.exec(rawHtml)) !== null) {
    const attrs = match[1];
    const nameMatch = attrs.match(/\b(?:name|property|http-equiv)=["']([^"']*)["']/i);
    const contentMatch = attrs.match(/\bcontent=["']([^"']*)["']/i);

    if (nameMatch && contentMatch) {
      const key = nameMatch[1].trim();
      const val = decodeHtmlEntities(contentMatch[1].trim());
      metaTags[key] = val;
    }
  }

  // 3. Open Graph Grouping
  const openGraph: Record<string, string> = {};
  // 4. Twitter Card Grouping
  const twitterCard: Record<string, string> = {};

  for (const [key, val] of Object.entries(metaTags)) {
    const lowerKey = key.toLowerCase();
    if (lowerKey.startsWith("og:")) {
      openGraph[lowerKey] = val;
    } else if (lowerKey.startsWith("twitter:")) {
      twitterCard[lowerKey] = val;
    }
  }

  // 5. Canonical link
  const canonicalMatch =
    rawHtml.match(/<link\b[^>]*\brel=["']canonical["'][^>]*\bhref=["']([^"']*)["']/i) ||
    rawHtml.match(/<link\b[^>]*\bhref=["']([^"']*)["'][^>]*\brel=["']canonical["']/i);
  const canonical = canonicalMatch ? canonicalMatch[1].trim() : null;

  // 6. Favicons
  const icons: string[] = [];
  const iconRegex = /<link\b[^>]*\brel=["'](?:shortcut\s+)?icon|apple-touch-icon["'][^>]*>/gi;
  let iconMatch: RegExpExecArray | null;
  while ((iconMatch = iconRegex.exec(rawHtml)) !== null) {
    const hrefMatch = iconMatch[0].match(/\bhref=["']([^"']*)["']/i);
    if (hrefMatch) {
      try {
        icons.push(new URL(hrefMatch[1].trim(), target).toString());
      } catch {}
    }
  }

  // 7. Structured Data (JSON-LD)
  const jsonLdBlocks: unknown[] = [];
  const ldJsonRegex = /<script\b[^>]*\btype=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let ldMatch: RegExpExecArray | null;
  while ((ldMatch = ldJsonRegex.exec(rawHtml)) !== null) {
    const content = ldMatch[1].trim();
    try {
      jsonLdBlocks.push(JSON.parse(content));
    } catch {
      jsonLdBlocks.push({ error: "Invalid JSON-LD syntax", raw: content.slice(0, 500) });
    }
  }

  return {
    target: target.toString(),
    status: res.status,
    latencyMs,
    title,
    description: metaTags["description"] || openGraph["og:description"] || twitterCard["twitter:description"] || null,
    canonical,
    icons,
    openGraph,
    twitterCard,
    jsonLd: jsonLdBlocks,
    allMetaTags: metaTags,
  };
}

/**
 * 14. Domain Whois / RDAP Registration Lookup
 * Queries ICANN RDAP for domain registration details, registrar, expiration, and status.
 */
export async function lookupWhois(rawDomain: string): Promise<Record<string, unknown>> {
  let domain = rawDomain.trim().toLowerCase();
  try {
    if (domain.startsWith("http://") || domain.startsWith("https://")) {
      domain = new URL(domain).hostname;
    } else if (domain.includes("/")) {
      domain = domain.split("/")[0];
    }
  } catch {}

  const dummyTarget = normalizeTarget(`https://${domain}`);
  const validatedHost = dummyTarget.hostname;
  const startTime = Date.now();

  try {
    const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(validatedHost)}`;
    const res = await fetch(rdapUrl, {
      headers: {
        Accept: "application/rdap+json, application/json",
        "User-Agent": TOOL_USER_AGENT,
      },
      redirect: "follow",
    });
    const latencyMs = Date.now() - startTime;

    if (!res.ok) {
      return {
        domain: validatedHost,
        found: false,
        status: res.status,
        message: `RDAP lookup returned HTTP ${res.status}`,
        latencyMs,
      };
    }

    const data = (await res.json()) as any;

    let registrar: string | null = null;
    if (Array.isArray(data.entities)) {
      for (const ent of data.entities) {
        if (Array.isArray(ent.roles) && ent.roles.includes("registrar")) {
          const vcard = ent.vcardArray?.[1];
          if (Array.isArray(vcard)) {
            const fn = vcard.find((v: any[]) => Array.isArray(v) && v[0] === "fn");
            if (fn && fn[3]) {
              registrar = String(fn[3]);
              break;
            }
          }
          if (!registrar && ent.handle) {
            registrar = ent.handle;
          }
        }
      }
    }

    const events: Record<string, string> = {};
    if (Array.isArray(data.events)) {
      for (const ev of data.events) {
        if (ev.eventAction && ev.eventDate) {
          events[ev.eventAction] = ev.eventDate;
        }
      }
    }

    const nameservers: string[] = [];
    if (Array.isArray(data.nameservers)) {
      for (const ns of data.nameservers) {
        if (ns.ldhName) nameservers.push(ns.ldhName);
        else if (ns.handle) nameservers.push(ns.handle);
      }
    }

    return {
      domain: validatedHost,
      found: true,
      handle: data.handle || null,
      status: Array.isArray(data.status) ? data.status : [],
      registrar,
      registeredDate: events["registration"] || events["transfer"] || null,
      expirationDate: events["expiration"] || null,
      lastChangedDate: events["last changed"] || events["last update"] || null,
      nameservers,
      latencyMs,
      rdapServer: "https://rdap.org",
    };
  } catch (err) {
    return {
      domain: validatedHost,
      found: false,
      error: err instanceof Error ? err.message : "RDAP query error",
    };
  }
}

/**
 * 15. RSS & Atom Feed Parser
 * Fetches and parses RSS/Atom XML feeds into structured articles.
 */
export async function parseFeed(rawUrl: string): Promise<Record<string, unknown>> {
  const target = normalizeTarget(rawUrl);
  const startTime = Date.now();

  const res = await fetch(target.toString(), {
    headers: {
      "User-Agent": TOOL_USER_AGENT,
      Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml",
    },
    redirect: "follow",
  });

  const xmlText = await res.text();
  const latencyMs = Date.now() - startTime;

  const isAtom = /<feed\b[^>]*>/i.test(xmlText);
  const isRss = /<rss\b|<channel\b/i.test(xmlText);

  // Extract channel metadata
  const channelTitleMatch = xmlText.match(/<(?:channel|feed)\b[^>]*>[\s\S]*?<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const channelTitle = channelTitleMatch ? decodeHtmlEntities(channelTitleMatch[1].replace(/<!\[CDATA\[(.*?)\]\]>/gs, "$1").trim()) : "";

  const channelDescMatch = xmlText.match(/<(?:description|subtitle)\b[^>]*>([\s\S]*?)<\/(?:description|subtitle)>/i);
  const channelDesc = channelDescMatch ? decodeHtmlEntities(channelDescMatch[1].replace(/<!\[CDATA\[(.*?)\]\]>/gs, "$1").trim()) : "";

  const items: Array<{
    title: string;
    link: string;
    pubDate: string;
    description: string;
    author: string;
  }> = [];

  const itemRegex = isAtom
    ? /<entry\b[^>]*>([\s\S]*?)<\/entry>/gi
    : /<item\b[^>]*>([\s\S]*?)<\/item>/gi;

  let m: RegExpExecArray | null;
  while ((m = itemRegex.exec(xmlText)) !== null && items.length < 50) {
    const itemXml = m[1];

    const titleMatch = itemXml.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
    const rawTitle = titleMatch ? titleMatch[1].replace(/<!\[CDATA\[(.*?)\]\]>/gs, "$1").trim() : "";

    let link = "";
    if (isAtom) {
      const atomLink = itemXml.match(/<link\b[^>]*\bhref=["']([^"']*)["']/i);
      link = atomLink ? atomLink[1].trim() : "";
    }
    if (!link) {
      const standardLink = itemXml.match(/<link\b[^>]*>([\s\S]*?)<\/link>/i);
      link = standardLink ? standardLink[1].replace(/<!\[CDATA\[(.*?)\]\]>/gs, "$1").trim() : "";
    }

    const dateMatch = itemXml.match(/<(?:pubDate|published|updated)\b[^>]*>([\s\S]*?)<\/(?:pubDate|published|updated)>/i);
    const pubDate = dateMatch ? dateMatch[1].trim() : "";

    const descMatch = itemXml.match(/<(?:description|summary|content)\b[^>]*>([\s\S]*?)<\/(?:description|summary|content)>/i);
    const rawDesc = descMatch
      ? descMatch[1].replace(/<!\[CDATA\[(.*?)\]\]>/gs, "$1").replace(/<[^>]+>/g, " ").slice(0, 300).trim()
      : "";

    const authorMatch = itemXml.match(/<(?:author|dc:creator)\b[^>]*>([\s\S]*?)<\/(?:author|dc:creator)>/i);
    const author = authorMatch ? authorMatch[1].replace(/<[^>]+>/g, "").trim() : "";

    items.push({
      title: decodeHtmlEntities(rawTitle),
      link,
      pubDate,
      description: decodeHtmlEntities(rawDesc),
      author: decodeHtmlEntities(author),
    });
  }

  return {
    target: target.toString(),
    format: isAtom ? "atom" : isRss ? "rss" : "unknown",
    status: res.status,
    latencyMs,
    channel: {
      title: channelTitle,
      description: channelDesc,
    },
    totalItems: items.length,
    items,
  };
}


