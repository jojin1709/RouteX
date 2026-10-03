/**
 * RouteX OpenAPI 3.1 Specification
 * Complete documentation of all endpoints, parameters, and responses.
 */

export const openApiSpec = {
  openapi: "3.1.0",
  info: {
    title: "RouteX Stateless Web Gateway API",
    version: "2.1.0",
    description:
      "Production-grade, 100% stateless HTTP/HTTPS web gateway, security diagnostics, and edge inspection suite running on Cloudflare Workers edge network.",
    contact: {
      name: "JOJIN JOHN",
      url: "https://github.com/jojin1709/RouteX",
    },
    license: {
      name: "MIT",
      url: "https://opensource.org/licenses/MIT",
    },
  },
  servers: [
    {
      url: "https://routex-web-gateway.apkscope.workers.dev",
      description: "Live Cloudflare Workers Edge Production Gateway",
    },
    {
      url: "http://localhost:8787",
      description: "Local Wrangler Dev Server",
    },
  ],
  paths: {
    "/health": {
      get: {
        summary: "Gateway Health and Platform Readiness",
        description: "Returns gateway operational status, stateless architecture flags, and Cloudflare Browser Rendering availability.",
        responses: {
          "200": {
            description: "Service is healthy and operating at edge",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean", example: true },
                    service: { type: "string", example: "RouteX Web Gateway" },
                    stateless: { type: "boolean", example: true },
                    storage: { type: "string", example: "none" },
                    browserRenderingAvailable: { type: "boolean", example: false },
                  },
                },
              },
            },
          },
        },
      },
    },
    "/proxy": {
      get: {
        summary: "Stateless HTTP/HTTPS Web Gateway",
        description:
          "Fetches upstream destination, verifies SSRF safety, rewrites HTML/CSS/subresources, and streams sanitized content directly.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target URL to proxy (http:// or https://)",
            schema: { type: "string", example: "https://example.com" },
          },
          {
            name: "raw",
            in: "query",
            required: false,
            description: "Pass ?raw=true to bypass HTML/CSS URL rewriting and stream upstream bytes untouched.",
            schema: { type: "boolean", example: false },
          },
          {
            name: "ua",
            in: "query",
            required: false,
            description: "Simulate specific User-Agent client ('desktop' or 'mobile')",
            schema: { type: "string", enum: ["desktop", "mobile"], example: "desktop" },
          },
          {
            name: "download",
            in: "query",
            required: false,
            description: "Pass ?download=1 to force browser attachment download via Content-Disposition header.",
            schema: { type: "boolean", example: false },
          },
        ],
        responses: {
          "200": { description: "Proxied resource stream (HTML, CSS, Image, Script, etc.)" },
          "400": { description: "Invalid URL or blocked by SSRF policy" },
          "502": { description: "Destination could not be reached or timed out" },
        },
      },
    },
    "/diagnostics": {
      get: {
        summary: "9-Probe Technical Compatibility Evaluation",
        description: "Executes technical probes verifying DNS, HTTPS, stylesheets, images, fonts, redirect chains, and SPA client-side routing signals.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Destination URL to audit",
            schema: { type: "string", example: "https://example.com" },
          },
        ],
        responses: {
          "200": {
            description: "Diagnostic report including compatibility grade and probe observations",
          },
          "400": { description: "Target URL rejected by SSRF or syntax validation" },
        },
      },
    },
    "/api/tools/dns": {
      get: {
        summary: "DNS-over-HTTPS (DoH) Record Lookup",
        description: "Queries Cloudflare 1.1.1.1 DNS over HTTPS for A, AAAA, MX, TXT, NS, and CNAME records.",
        parameters: [
          {
            name: "domain",
            in: "query",
            required: true,
            description: "Domain name or URL to query",
            schema: { type: "string", example: "cloudflare.com" },
          },
        ],
        responses: {
          "200": { description: "DNS records returned from DoH" },
          "400": { description: "SSRF or invalid host rejected" },
        },
      },
    },
    "/api/tools/tls": {
      get: {
        summary: "SSL/TLS Security Audit",
        description: "Audits target HTTPS configuration, HSTS header presence, max-age grade, and protocol compliance.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target HTTPS URL to evaluate",
            schema: { type: "string", example: "https://example.com" },
          },
        ],
        responses: {
          "200": { description: "TLS and HSTS audit results" },
        },
      },
    },
    "/api/tools/security-headers": {
      get: {
        summary: "Security Headers Evaluation",
        description: "Audits 8 defensive HTTP headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, etc.).",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target URL",
            schema: { type: "string", example: "https://example.com" },
          },
        ],
        responses: { "200": { description: "Security headers report" } },
      },
    },
    "/api/tools/headers": {
      get: {
        summary: "HTTP Response Headers Inspector",
        description: "Inspects raw HTTP response headers, latency, status code, and reason phrase from upstream server.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target URL",
            schema: { type: "string", example: "https://example.com" },
          },
        ],
        responses: { "200": { description: "Response headers map and metadata" } },
      },
    },
    "/api/tools/redirects": {
      get: {
        summary: "Redirect Chain Tracer",
        description: "Traces manual redirect hops (301, 302, 303, 307, 308) up to 10 consecutive hops.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target URL",
            schema: { type: "string", example: "http://example.com" },
          },
        ],
        responses: { "200": { description: "List of hops with HTTP status codes and Location headers" } },
      },
    },
    "/api/tools/links": {
      get: {
        summary: "HTML Link & Resource Extractor",
        description: "Extracts and categorizes internal links, external hyperlinks, and sub-resource assets.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "HTML page target URL",
            schema: { type: "string", example: "https://example.com" },
          },
        ],
        responses: { "200": { description: "Arrays of internal links, external links, and resources" } },
      },
    },
    "/api/tools/robots": {
      get: {
        summary: "robots.txt Directives Inspector",
        description: "Fetches and displays robots.txt crawling directives and extracted sitemap locations.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target URL or origin",
            schema: { type: "string", example: "https://example.com" },
          },
        ],
        responses: { "200": { description: "Parsed robots.txt content and sitemap URLs" } },
      },
    },
    "/api/tools/sitemap": {
      get: {
        summary: "sitemap.xml Parser",
        description: "Fetches XML sitemaps and extracts canonical location entries.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Sitemap XML URL or website origin",
            schema: { type: "string", example: "https://example.com/sitemap.xml" },
          },
        ],
        responses: { "200": { description: "List of URLs parsed from sitemap" } },
      },
    },
    "/api/tools/json": {
      get: {
        summary: "JSON Formatter & Validator",
        description: "Fetches, validates, and pretty-prints JSON payloads from any REST API endpoint.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target JSON endpoint",
            schema: { type: "string", example: "https://httpbin.org/json" },
          },
        ],
        responses: { "200": { description: "Parsed JSON payload and structural metadata" } },
      },
    },
    "/api/tools/xml": {
      get: {
        summary: "XML Document Viewer",
        description: "Fetches and parses upstream XML payloads, identifying root elements and length.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target XML URL",
            schema: { type: "string", example: "https://httpbin.org/xml" },
          },
        ],
        responses: { "200": { description: "XML structure and snippet" } },
      },
    },
    "/api/tools/markdown": {
      get: {
        summary: "Article Text & Markdown Extractor",
        description: "Strips HTML boilerplate, scripts, styles, and navigation, returning clean Markdown for AI prompts and CLI usage.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target HTML webpage",
            schema: { type: "string", example: "https://en.wikipedia.org/wiki/Cloudflare" },
          },
        ],
        responses: {
          "200": {
            description: "Extracted article title, description, word count, and clean Markdown text",
          },
          "400": { description: "Invalid URL or blocked by SSRF" },
        },
      },
    },
    "/api/tools/metadata": {
      get: {
        summary: "Open Graph & Social Metadata Inspector",
        description: "Extracts SEO title, meta descriptions, canonical URLs, Open Graph (og:*), Twitter Cards, favicons, and JSON-LD structured data.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target webpage URL",
            schema: { type: "string", example: "https://github.com" },
          },
        ],
        responses: {
          "200": { description: "Comprehensive metadata object" },
        },
      },
    },
    "/api/tools/response-info": {
      get: {
        summary: "Response Diagnostic Metadata",
        description: "Returns status, content-type, encoding, cache-control, server, and latency.",
        parameters: [
          {
            name: "url",
            in: "query",
            required: true,
            description: "Target URL",
            schema: { type: "string", example: "https://example.com" },
          },
        ],
        responses: { "200": { description: "Performance and response metadata" } },
      },
    },
    "/api/daytona/status": {
      get: {
        summary: "Daytona Sandboxed Compute Status",
        description: "Reports configuration status of optional Daytona ephemeral compute containers.",
        responses: {
          "200": { description: "Daytona service availability" },
        },
      },
    },
    "/api/tools/screenshot": {
      post: {
        summary: "Sandboxed Playwright Screenshot (Daytona)",
        description: "Runs headless Chromium in an isolated Daytona container and captures a full-page PNG screenshot.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["url"],
                properties: {
                  url: { type: "string", example: "https://example.com" },
                  viewport: { type: "string", enum: ["desktop", "mobile"], default: "desktop" },
                },
              },
            },
          },
        },
        responses: {
          "200": { description: "Base64-encoded PNG screenshot" },
          "501": { description: "Daytona API key not configured" },
        },
      },
    },
    "/api/tools/render": {
      post: {
        summary: "Sandboxed Playwright Rendered DOM (Daytona)",
        description: "Executes client-side JavaScript in an isolated Daytona container and captures fully hydrated DOM HTML.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["url"],
                properties: {
                  url: { type: "string", example: "https://example.com" },
                },
              },
            },
          },
        },
        responses: {
          "200": { description: "Rendered DOM HTML string and console logs" },
          "501": { description: "Daytona API key not configured" },
        },
      },
    },
    "/api/tools/pdf": {
      post: {
        summary: "Sandboxed Playwright Vector PDF (Daytona)",
        description: "Generates high-fidelity vector PDF in an isolated Daytona container.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["url"],
                properties: {
                  url: { type: "string", example: "https://example.com" },
                },
              },
            },
          },
        },
        responses: {
          "200": { description: "Base64-encoded PDF document" },
          "501": { description: "Daytona API key not configured" },
        },
      },
    },
    "/openapi.json": {
      get: {
        summary: "OpenAPI 3.1 Specification JSON",
        description: "Returns this OpenAPI 3.1 schema definition for Swagger UI, Postman, and MCP integrations.",
        responses: {
          "200": { description: "OpenAPI 3.1 schema JSON" },
        },
      },
    },
  },
};
