/**
 * RouteX Diagnostics Engine
 * Evaluates target websites across multiple technical dimensions and reports
 * factual compatibility information.
 */

import { normalizeTarget } from "./security.ts";
import type { CompatibilityRating, DiagnosticProbe, DiagnosticReport } from "./types.ts";

export async function runDiagnostics(rawUrl: string): Promise<DiagnosticReport> {
  const probes: DiagnosticProbe[] = [];
  const recommendations: string[] = [];

  let target: URL;
  try {
    target = normalizeTarget(rawUrl);
  } catch (err) {
    return {
      target: rawUrl,
      timestamp: new Date().toISOString(),
      compatibility: "Limited",
      summary: "Target URL rejected by security or syntax validation.",
      probes: [
        {
          name: "URL Validation",
          category: "Security",
          status: "fail",
          message: err instanceof Error ? err.message : "Invalid URL",
        },
      ],
      recommendations: ["Ensure the URL is a valid public HTTP or HTTPS address."],
    };
  }

  probes.push({
    name: "Security & SSRF Check",
    category: "Security",
    status: "pass",
    message: "Destination is permitted under RouteX SSRF policy.",
  });

  // Probe 1: Primary fetch probe
  let response: Response | null = null;
  let htmlText = "";
  const startTime = Date.now();

  try {
    response = await fetch(target.toString(), {
      method: "GET",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      redirect: "manual",
    });

    const elapsed = Date.now() - startTime;
    probes.push({
      name: "HTTPS Reachability",
      category: "Network",
      status: response.status < 400 ? "pass" : "warn",
      message: `Target responded with HTTP ${response.status} in ${elapsed}ms`,
      details: { status: response.status, latencyMs: elapsed },
    });
  } catch (err) {
    probes.push({
      name: "HTTPS Reachability",
      category: "Network",
      status: "fail",
      message: err instanceof Error ? err.message : "Target could not be reached over network.",
    });

    return {
      target: target.toString(),
      timestamp: new Date().toISOString(),
      compatibility: "Limited",
      summary: "Upstream target is unreachable or timed out.",
      probes,
      recommendations: ["Check if the destination server is online and allows public inbound connections."],
    };
  }

  // Probe 2: Redirect behavior
  const isRedirect = [301, 302, 303, 307, 308].includes(response.status);
  const locationHeader = response.headers.get("location");
  if (isRedirect && locationHeader) {
    probes.push({
      name: "Redirect Handling",
      category: "Routing",
      status: "pass",
      message: `Target returns HTTP ${response.status} redirect to: ${locationHeader}`,
      details: { redirectStatus: response.status, location: locationHeader },
    });
  } else {
    probes.push({
      name: "Redirect Handling",
      category: "Routing",
      status: "pass",
      message: "Target serves content directly without initial redirect.",
    });
  }

  // Probe 3: Content-Type & HTML extraction
  const contentType = (response.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html") || contentType.includes("application/xhtml+xml");

  if (isHtml) {
    try {
      htmlText = await response.text();
      probes.push({
        name: "HTML Markup",
        category: "Content",
        status: "pass",
        message: `Received valid HTML document (${Math.round(htmlText.length / 1024)} KB).`,
      });
    } catch {
      probes.push({
        name: "HTML Markup",
        category: "Content",
        status: "warn",
        message: "Failed reading response body as text.",
      });
    }
  } else {
    probes.push({
      name: "HTML Markup",
      category: "Content",
      status: "warn",
      message: `Target responded with non-HTML content type: ${contentType || "unknown"}`,
    });
  }

  // Probe 4: CSS Detection
  const hasCssLink = /<link[^>]+rel=["']?stylesheet["']?[^>]*>/i.test(htmlText);
  const hasInlineStyle = /<style\b[^>]*>/i.test(htmlText);
  if (hasCssLink || hasInlineStyle) {
    probes.push({
      name: "CSS Stylesheets",
      category: "Styling",
      status: "pass",
      message: `Detected ${hasCssLink ? "external stylesheets" : ""}${hasCssLink && hasInlineStyle ? " and " : ""}${hasInlineStyle ? "inline styles" : ""}. RouteX rewrites CSS url() and @import.`,
    });
  } else {
    probes.push({
      name: "CSS Stylesheets",
      category: "Styling",
      status: "pass",
      message: "No prominent stylesheet tags detected in initial markup.",
    });
  }

  // Probe 5: Images & Media
  const hasImages = /<img\b[^>]*>/i.test(htmlText) || /<picture\b[^>]*>/i.test(htmlText);
  const hasVideoAudio = /<video\b[^>]*>/i.test(htmlText) || /<audio\b[^>]*>/i.test(htmlText);
  if (hasImages || hasVideoAudio) {
    probes.push({
      name: "Media & Images",
      category: "Media",
      status: "pass",
      message: `Detected static media elements (${hasImages ? "Images" : ""}${hasImages && hasVideoAudio ? ", " : ""}${hasVideoAudio ? "Audio/Video" : ""}).`,
    });
  } else {
    probes.push({
      name: "Media & Images",
      category: "Media",
      status: "pass",
      message: "No static media tags in initial HTML.",
    });
  }

  // Probe 6: Fonts
  const hasFontHints = /format\(["']?(?:woff2|woff|truetype)["']?\)/i.test(htmlText) || /<link[^>]+rel=["']?preload["']?[^>]+as=["']?font["']?/i.test(htmlText);
  probes.push({
    name: "Web Fonts",
    category: "Styling",
    status: "pass",
    message: hasFontHints ? "Web font references detected in document." : "Standard web font usage or system fonts.",
  });

  // Probe 7: Client JavaScript & SPA Hydration Detection
  const scriptTags = (htmlText.match(/<script\b[^>]*>/gi) || []).length;
  const isReact = /react|data-reactroot/i.test(htmlText) || /_next\/static/i.test(htmlText);
  const isRemix = /__remixContext/i.test(htmlText);
  const isVue = /data-v-|vue/i.test(htmlText) || /_nuxt/i.test(htmlText);

  let spaName = "";
  if (isRemix) spaName = "Remix";
  else if (/next/i.test(htmlText)) spaName = "Next.js";
  else if (isReact) spaName = "React";
  else if (isVue) spaName = "Vue/Nuxt";

  if (spaName) {
    probes.push({
      name: "JavaScript & Hydration",
      category: "Client Execution",
      status: "warn",
      message: `Detected ${spaName} client-side SPA architecture. Strict client-side hydration or path-based router state may limit dynamic features.`,
      details: { framework: spaName, scriptCount: scriptTags },
    });
    recommendations.push(`Target uses ${spaName}. While initial HTML and styles load, client-side SPA routing may expect its native origin.`);
  } else if (scriptTags > 15) {
    probes.push({
      name: "JavaScript & Hydration",
      category: "Client Execution",
      status: "warn",
      message: `High script density (${scriptTags} script tags). Dynamic features depend on browser environment.`,
      details: { scriptCount: scriptTags },
    });
  } else {
    probes.push({
      name: "JavaScript & Hydration",
      category: "Client Execution",
      status: "pass",
      message: `Lightweight script footprint (${scriptTags} script tags). Standard progressive enhancement compatible.`,
      details: { scriptCount: scriptTags },
    });
  }

  // Probe 8: Dynamic APIs & Anti-Bot
  const hasAntiBot = /cf-turnstile|g-recaptcha|hcaptcha|challenge-running|datadome|perimeterx/i.test(htmlText);
  if (hasAntiBot) {
    probes.push({
      name: "Dynamic APIs & Bot Protection",
      category: "Security",
      status: "warn",
      message: "Target uses anti-bot, CAPTCHA, or challenge verification systems.",
    });
    recommendations.push("Target employs anti-bot protection which may challenge automated or proxied client traffic.");
  } else {
    probes.push({
      name: "Dynamic APIs & Bot Protection",
      category: "Security",
      status: "pass",
      message: "No overt client challenge barriers detected.",
    });
  }

  // Compute overall compatibility rating
  let compatibility: CompatibilityRating = "Full";
  if (hasAntiBot || (isRemix && hasAntiBot)) {
    compatibility = "Limited";
  } else if (spaName || scriptTags > 15 || !isHtml) {
    compatibility = "Partial";
  }

  let summary = "Website is standard HTML/CSS and is fully compatible with RouteX stateless gateway.";
  if (compatibility === "Partial") {
    summary = "Website renders core layout, styles, and images. Advanced client-side SPA interactions may have partial fidelity.";
  } else if (compatibility === "Limited") {
    summary = "Website utilizes heavy client-side SPA hydration or anti-bot mechanisms, limiting proxy rendering fidelity.";
  }

  return {
    target: target.toString(),
    timestamp: new Date().toISOString(),
    compatibility,
    summary,
    probes,
    recommendations,
  };
}
