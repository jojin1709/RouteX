/**
 * RouteX Automated Test Suite
 * Covers Core Rewriter, SSRF & Security Engine, Inspector Tools, Diagnostics, and Endpoints.
 */

import { isBlockedHostname, isIPv4, isPrivateIPv4, normalizeTarget, MAX_URL_LENGTH } from "../src/security.ts";
import { resolveAndProxy, rewriteSrcset, rewriteCss, rewriteHtml, buildResponseHeaders, gatewayUrl } from "../src/rewriter.ts";
import { runDiagnostics } from "../src/diagnostics.ts";
import { checkSecurityHeaders, extractMarkdown, extractMetadata, formatJson, lookupWhois, parseFeed, viewXml } from "../src/tools.ts";
import { openApiSpec } from "../src/openapi.ts";
import { isBrowserRenderingAvailable } from "../src/browser.ts";
import {
  getDaytonaStatus,
  isDaytonaConfigured,
  handleDaytonaTool,
  parseAndValidateTarget,
  parseAndValidateRequest,
  MAX_DAYTONA_OUTPUT_BYTES,
  DEFAULT_DAYTONA_TIMEOUT_SECONDS,
} from "../src/daytona.ts";
import { verifyTurnstileToken } from "../src/turnstile.ts";
import worker, { sanitizeHttpStatus, sanitizeStatusText } from "../src/index.ts";
import type { Env } from "../src/types.ts";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

interface TestResult {
  name: string;
  status: "PASS" | "FAIL";
  errorMsg: string;
}

const results: TestResult[] = [];

function test(name: string, condition: boolean, errorMsg: string = "") {
  if (condition) {
    results.push({ name, status: "PASS", errorMsg: "" });
    console.log(`  [PASS] ${name}`);
  } else {
    results.push({ name, status: "FAIL", errorMsg });
    console.error(`  [FAIL] ${name}: ${errorMsg}`);
  }
}

async function runAllTests() {
  console.log("==================================================");
  console.log("  RouteX Production Test Suite");
  console.log("==================================================\n");

  // ----------------------------------------------------
  // SECTION 1: CORE REWRITER TESTS
  // ----------------------------------------------------
  console.log("--- Section 1: Core URL & Resource Rewriting ---");
  const baseHtmlUrl = new URL("https://example.com/blog/article.html");

  // 1.1 Relative paths
  const relParent = resolveAndProxy("../assets/style.css", baseHtmlUrl);
  test(
    "Relative ../ resolution",
    relParent === `/proxy?url=${encodeURIComponent("https://example.com/assets/style.css")}`,
    `Got: ${relParent}`
  );

  const relCurrent = resolveAndProxy("./thumbnail.jpg", baseHtmlUrl);
  test(
    "Relative ./ resolution",
    relCurrent === `/proxy?url=${encodeURIComponent("https://example.com/blog/thumbnail.jpg")}`,
    `Got: ${relCurrent}`
  );

  const rootRel = resolveAndProxy("/images/logo.png", baseHtmlUrl);
  test(
    "Root-relative / resolution",
    rootRel === `/proxy?url=${encodeURIComponent("https://example.com/images/logo.png")}`,
    `Got: ${rootRel}`
  );

  // 1.2 Protocol-relative //
  const protoRel = resolveAndProxy("//cdn.example.org/lib.js", baseHtmlUrl);
  test(
    "Protocol-relative // resolution",
    protoRel === `/proxy?url=${encodeURIComponent("https://cdn.example.org/lib.js")}`,
    `Got: ${protoRel}`
  );

  // 1.3 Absolute URLs
  const absUrl = resolveAndProxy("https://other.org/font.woff2", baseHtmlUrl);
  test(
    "Absolute https:// resolution",
    absUrl === `/proxy?url=${encodeURIComponent("https://other.org/font.woff2")}`,
    `Got: ${absUrl}`
  );

  // 1.4 Query strings and fragments
  const queryFrag = resolveAndProxy("/main.css?v=3.2.1#nav", baseHtmlUrl);
  test(
    "Query string and fragment preserved in target",
    queryFrag === `/proxy?url=${encodeURIComponent("https://example.com/main.css?v=3.2.1#nav")}`,
    `Got: ${queryFrag}`
  );

  // 1.5 Fragments, javascript, data, mailto untouched
  test("Fragment-only anchor untouched", resolveAndProxy("#top", baseHtmlUrl) === "#top");
  test("javascript: URL untouched", resolveAndProxy("javascript:void(0)", baseHtmlUrl) === "javascript:void(0)");
  test("data: URI untouched", resolveAndProxy("data:image/png;base64,ABC", baseHtmlUrl) === "data:image/png;base64,ABC");
  test("mailto: link untouched", resolveAndProxy("mailto:info@example.com", baseHtmlUrl) === "mailto:info@example.com");
  test("tel: link untouched", resolveAndProxy("tel:+123456789", baseHtmlUrl) === "tel:+123456789");

  // 1.6 Double-proxy prevention
  const alreadyProxiedRel = `/proxy?url=${encodeURIComponent("https://example.com/file.png")}`;
  test("Double-proxy prevention (relative /proxy?url=)", resolveAndProxy(alreadyProxiedRel, baseHtmlUrl) === alreadyProxiedRel);

  const alreadyProxiedAbs = `https://routex-web-gateway.workers.dev/proxy?url=${encodeURIComponent("https://example.com/file.png")}`;
  test("Double-proxy prevention (absolute gateway URL)", resolveAndProxy(alreadyProxiedAbs, baseHtmlUrl) === alreadyProxiedRel);

  // 1.7 srcset rewriting
  const rawSrcset = "small.jpg 300w, /medium.jpg 600w, ../large.jpg 2x";
  const rewrittenSrcset = rewriteSrcset(rawSrcset, baseHtmlUrl);
  test(
    "srcset multi-candidate rewriting",
    rewrittenSrcset.includes("300w") &&
      rewrittenSrcset.includes("600w") &&
      rewrittenSrcset.includes("2x") &&
      rewrittenSrcset.includes(`/proxy?url=${encodeURIComponent("https://example.com/large.jpg")}`),
    `Got: ${rewrittenSrcset}`
  );

  // 1.8 CSS rewriting with CSS-relative base
  const cssUrl = new URL("https://cdn.example.com/themes/dark/style.css");
  const rawCss = `
    @import "reset.css";
    @import url("fonts.css");
    .bg { background: url("../img/pattern.png"); }
    .icon { background-image: url('/shared/icon.svg'); }
    .inline { background: url('data:image/svg+xml,...'); }
  `;
  const rewrittenCss = rewriteCss(rawCss, cssUrl);
  test(
    "CSS @import string relative to CSS file",
    rewrittenCss.includes(`@import "${resolveAndProxy("reset.css", cssUrl)}"`)
  );
  test(
    "CSS url(...) relative ../img/pattern.png resolved relative to CSS file",
    rewrittenCss.includes(`url("${resolveAndProxy("../img/pattern.png", cssUrl)}")`)
  );
  test(
    "CSS root-relative /shared/icon.svg resolved to CSS origin",
    rewrittenCss.includes(`url("${resolveAndProxy("/shared/icon.svg", cssUrl)}")`)
  );
  test("CSS data: URL preserved untouched", rewrittenCss.includes("url('data:image/svg+xml,...')"));

  // 1.9 HTML Tags & Elements
  const fullHtml = `
    <!DOCTYPE html>
    <html>
      <head>
        <link rel="stylesheet" href="../theme.css">
        <script src="/bundle.js"></script>
        <style>.box { background: url('box.png'); }</style>
      </head>
      <body>
        <a href="/about">About</a>
        <a href="#section">Section</a>
        <img src="pic.jpg" srcset="pic.jpg 1x, /pic-2x.jpg 2x">
        <video src="/vid.mp4" poster="/poster.jpg">
          <source src="/vid.webm" type="video/webm">
        </video>
        <audio src="/song.mp3"></audio>
        <iframe src="/embed.html"></iframe>
        <form action="/search" method="get"></form>
        <form action="/login" method="post"></form>
        <meta http-equiv="refresh" content="5; url=/new-page.html">
        <object data="/docs/spec.pdf"></object>
        <div style="background-image: url('inline.png');"></div>
      </body>
    </html>
  `;
  const rewrittenHtml = rewriteHtml(fullHtml, baseHtmlUrl);
  test("HTML <link href> rewritten", rewrittenHtml.includes(`href="${resolveAndProxy("../theme.css", baseHtmlUrl)}"`));
  test("HTML <script src> rewritten", rewrittenHtml.includes(`src="${resolveAndProxy("/bundle.js", baseHtmlUrl)}"`));
  test("HTML <a href> rewritten", rewrittenHtml.includes(`href="${resolveAndProxy("/about", baseHtmlUrl)}"`));
  test("HTML fragment <a href='#section'> untouched", rewrittenHtml.includes('href="#section"'));
  test("HTML <img src> rewritten", rewrittenHtml.includes(`src="${resolveAndProxy("pic.jpg", baseHtmlUrl)}"`));
  test("HTML <object data> rewritten", rewrittenHtml.includes(`data="${resolveAndProxy("/docs/spec.pdf", baseHtmlUrl)}"`));
  test("HTML <meta http-equiv='refresh'> rewritten", rewrittenHtml.includes(`url=${resolveAndProxy("/new-page.html", baseHtmlUrl)}`));
  test("HTML <video src and poster> rewritten", rewrittenHtml.includes(`poster="${resolveAndProxy("/poster.jpg", baseHtmlUrl)}"`) && rewrittenHtml.includes(`src="${resolveAndProxy("/vid.mp4", baseHtmlUrl)}"`));
  test("HTML <source src> rewritten", rewrittenHtml.includes(`src="${resolveAndProxy("/vid.webm", baseHtmlUrl)}"`));
  test("HTML <audio src> rewritten", rewrittenHtml.includes(`src="${resolveAndProxy("/song.mp3", baseHtmlUrl)}"`));
  test("HTML <iframe src> rewritten", rewrittenHtml.includes(`src="${resolveAndProxy("/embed.html", baseHtmlUrl)}"`));
  test("HTML GET <form action> rewritten", rewrittenHtml.includes(`action="${resolveAndProxy("/search", baseHtmlUrl)}"`));
  test("HTML POST <form action> left untouched", rewrittenHtml.includes('action="/login"'));
  test("HTML inline style attribute rewritten", rewrittenHtml.includes(resolveAndProxy("inline.png", baseHtmlUrl)));
  test("HTML <style> block rewritten", rewrittenHtml.includes(resolveAndProxy("box.png", baseHtmlUrl)));
  test("HTML SPA navigation shim injected", rewrittenHtml.includes('id="__routex_spa_shim"'));

  // 1.10 Response Header Sanitization
  const mockHeaders = new Headers({
    "content-type": "text/html; charset=utf-8",
    "content-encoding": "gzip",
    "content-length": "12345",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "set-cookie": "session=secret",
    etag: '"abc123"',
    "cache-control": "public, max-age=3600",
  });
  const mockResponse = new Response("mock", { headers: mockHeaders });
  const sanitized = buildResponseHeaders(mockResponse, true); // body was rewritten

  test("Response headers: content-type preserved", sanitized.get("content-type") === "text/html; charset=utf-8");
  test("Response headers: etag preserved", sanitized.get("etag") === '"abc123"');
  test("Response headers: cache-control preserved", sanitized.get("cache-control") === "public, max-age=3600");
  test("Response headers: dangerous CSP stripped", !sanitized.has("content-security-policy"));
  test("Response headers: X-Frame-Options stripped", !sanitized.has("x-frame-options"));
  test("Response headers: Set-Cookie stripped", !sanitized.has("set-cookie"));
  test("Response headers: content-encoding stripped on rewritten text", !sanitized.has("content-encoding"));
  test("Response headers: content-length stripped on rewritten text", !sanitized.has("content-length"));
  test("Response headers: Access-Control-Allow-Origin: * injected", sanitized.get("access-control-allow-origin") === "*");
  test("Response headers: X-RouteX-Gateway: 1 injected", sanitized.get("x-routex-gateway") === "1");

  // ----------------------------------------------------
  // SECTION 2: SECURITY & SSRF PROTECTION TESTS
  // ----------------------------------------------------
  console.log("\n--- Section 2: Security & SSRF Protection ---");

  // Helper to assert normalizeTarget throws
  function assertBlocked(raw: string, label: string) {
    try {
      normalizeTarget(raw);
      test(`SSRF Block: ${label}`, false, `Expected error, but allowed: ${raw}`);
    } catch {
      test(`SSRF Block: ${label}`, true);
    }
  }

  // 2.1 IPv4 blocked ranges
  assertBlocked("http://127.0.0.1", "127.0.0.1 Loopback");
  assertBlocked("http://127.100.50.1", "127.x.x.x Loopback CIDR");
  assertBlocked("http://0.0.0.0", "0.0.0.0 Current network");
  assertBlocked("http://10.0.0.1", "10.0.0.1 Private Class A");
  assertBlocked("http://10.255.255.255", "10.255.255.255 Private Class A");
  assertBlocked("http://172.16.0.1", "172.16.0.1 Private Class B");
  assertBlocked("http://172.31.255.255", "172.31.255.255 Private Class B");
  assertBlocked("http://192.168.0.1", "192.168.0.1 Private Class C");
  assertBlocked("http://192.168.1.254", "192.168.1.254 Private Class C");
  assertBlocked("http://169.254.169.254", "169.254.169.254 Link-local AWS metadata");
  assertBlocked("http://100.64.0.1", "100.64.0.1 CGNAT");
  assertBlocked("http://224.0.0.1", "224.0.0.1 Multicast");
  assertBlocked("http://240.0.0.1", "240.0.0.1 Reserved");
  assertBlocked("http://255.255.255.255", "255.255.255.255 Broadcast");

  // 2.2 Hostnames blocked
  assertBlocked("http://localhost", "localhost");
  assertBlocked("http://localhost.localdomain", "localhost.localdomain");
  assertBlocked("http://app.local", ".local mDNS");
  assertBlocked("http://service.internal", ".internal internal hostname");
  assertBlocked("http://myhost.localhost", ".localhost domain");
  assertBlocked("http://hidden.onion", ".onion Tor hidden service");
  assertBlocked("http://metadata.google.internal", "GCP metadata hostname");
  assertBlocked("http://instance-data", "AWS instance-data alias");

  // 2.3 IPv6 blocked ranges
  assertBlocked("http://[::1]", "IPv6 Loopback [::1]");
  assertBlocked("http://[::]", "IPv6 Unspecified [::]");
  assertBlocked("http://[fe80::1]", "IPv6 Link-Local [fe80::1]");
  assertBlocked("http://[fc00::1]", "IPv6 ULA [fc00::1]");
  assertBlocked("http://[fd12:3456:789a::1]", "IPv6 ULA [fd12::1]");
  assertBlocked("http://[::ffff:127.0.0.1]", "IPv4-mapped IPv6 loopback");
  assertBlocked("http://[::ffff:192.168.1.1]", "IPv4-mapped IPv6 private");

  // 2.4 Decimal and Hex notation IP bypasses
  assertBlocked("http://2130706433", "Decimal integer representation of 127.0.0.1");
  assertBlocked("http://0x7f000001", "Hex representation of 127.0.0.1");
  assertBlocked("http://0177.0.0.1", "Octal leading-zero representation");
  assertBlocked("http://127.1", "Shorthand IPv4 representation of 127.0.0.1");
  assertBlocked("http://10.1", "Shorthand IPv4 representation of 10.0.0.1");

  // 2.5 Unsupported protocols
  assertBlocked("file:///etc/passwd", "file:// scheme");
  assertBlocked("ftp://ftp.example.com", "ftp:// scheme");
  assertBlocked("gopher://gopher.floodgap.com", "gopher:// scheme");
  assertBlocked("javascript:alert(1)", "javascript: scheme");
  assertBlocked("data:text/html,<h1>test</h1>", "data: scheme");
  assertBlocked("ws://echo.websocket.org", "ws:// scheme");
  assertBlocked("wss://echo.websocket.org", "wss:// scheme");

  // 2.6 Credentials & Oversized URL
  assertBlocked("http://admin:secret@example.com", "Embedded credentials in URL");
  const oversized = "https://example.com/path?" + "a=".repeat(2500);
  assertBlocked(oversized, `Oversized URL (> ${MAX_URL_LENGTH} chars)`);

  // 2.7 Sane valid target succeeds
  try {
    const valid = normalizeTarget("https://example.com/test");
    test("Valid public target allowed (https://example.com/test)", valid.hostname === "example.com");
  } catch (err: any) {
    test("Valid public target allowed", false, err.message);
  }

  // ----------------------------------------------------
  // SECTION 3: INSPECTOR TOOLS & DIAGNOSTICS
  // ----------------------------------------------------
  console.log("\n--- Section 3: Stateless Tools & Diagnostics ---");

  // 3.1 JSON Formatter
  const jsonReport = await formatJson("https://httpbin.org/json");
  test("JSON Inspector: Valid JSON parsing", jsonReport.isValidJson === true && jsonReport.status === 200);

  // 3.2 Security Header Checker on example.com
  const secReport = await checkSecurityHeaders("https://example.com");
  test("Security Header Checker: Objective observations returned", Array.isArray(secReport.headersChecked) && typeof secReport.observation === "string");

  // 3.3 Diagnostics Engine on example.com
  const diagReport = await runDiagnostics("https://example.com");
  test("Diagnostics: example.com returns Full compatibility rating", diagReport.compatibility === "Full");
  test("Diagnostics: Report includes technical probes", diagReport.probes.length >= 6);

  // 3.4 Diagnostics Engine SSRF Protection
  const ssrfDiag = await runDiagnostics("http://127.0.0.1");
  test("Diagnostics: SSRF target correctly flagged as Limited with fail probe", ssrfDiag.compatibility === "Limited" && ssrfDiag.probes[0].status === "fail");

  // 3.5 Optional Browser Tools & Turnstile Availability Check
  const mockEnv: Env = { ASSETS: {} as any };
  test("Browser Tools: Correctly reports unavailable when env.BROWSER is absent", isBrowserRenderingAvailable(mockEnv) === false);

  const turnstileCheck = await verifyTurnstileToken("dummy-token", null, mockEnv);
  test("Turnstile: Cleanly handles unconfigured secret key", turnstileCheck.success === false && Boolean(turnstileCheck.errorCodes?.[0]?.includes("missing")));

  // ----------------------------------------------------
  // SECTION 4: OPTIONAL DAYTONA INTEGRATION & SECURITY
  // ----------------------------------------------------
  console.log("\n--- Section 4: Optional Daytona Integration & Security ---");

  // 4.1 Configuration state detection
  test("Daytona Disabled: Correctly reports disabled when DAYTONA_API_KEY is absent", isDaytonaConfigured(mockEnv) === false);
  const statusDisabled = getDaytonaStatus(mockEnv);
  test("Daytona Disabled: getDaytonaStatus reports configured=false and enabled=false", statusDisabled.configured === false && statusDisabled.enabled === false);

  const mockDaytonaEnv: Env = { ASSETS: {} as any, DAYTONA_API_KEY: "dtn_test_secret_key" };
  test("Daytona Configured: Correctly reports configured when key present", isDaytonaConfigured(mockDaytonaEnv) === true);
  const statusConfigured = getDaytonaStatus(mockDaytonaEnv);
  test("Daytona Configured: getDaytonaStatus reports configured=true and enabled=true", statusConfigured.configured === true && statusConfigured.enabled === true);

  // 4.2 Missing API Key execution returns 501
  const renderUnconfiguredReq = new Request("https://gateway/api/tools/render", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://example.com" }),
  });
  const resUnconfigured = await handleDaytonaTool(renderUnconfiguredReq, mockEnv, "render");
  test("Daytona Unconfigured: Tool request returns 501 Not Implemented", resUnconfigured.status === 501);

  // 4.3 Target URL validation & SSRF protection inside Daytona tool handler
  const invalidUrlReq = new Request("https://gateway/api/tools/render", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "not-a-valid-domain" }),
  });
  const resInvalid = await handleDaytonaTool(invalidUrlReq, mockDaytonaEnv, "render");
  test("Daytona Security: Invalid URL is rejected with 400 Bad Request", resInvalid.status === 400);

  const ssrfReq = new Request("https://gateway/api/tools/render", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "http://127.0.0.1/admin" }),
  });
  const resSSRF = await handleDaytonaTool(ssrfReq, mockDaytonaEnv, "render");
  test("Daytona Security: SSRF loopback target is rejected with 400", resSSRF.status === 400);

  const metadataReq = new Request("https://gateway/api/tools/screenshot", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "http://169.254.169.254/latest/meta-data" }),
  });
  const resMetadata = await handleDaytonaTool(metadataReq, mockDaytonaEnv, "screenshot");
  test("Daytona Security: Cloud metadata target is rejected with 400", resMetadata.status === 400);

  const unsupportedProtoReq = new Request("https://gateway/api/tools/pdf", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "file:///etc/passwd" }),
  });
  const resProto = await handleDaytonaTool(unsupportedProtoReq, mockDaytonaEnv, "pdf");
  test("Daytona Security: file:// protocol is rejected with 400", resProto.status === 400);

  // 4.4 Arbitrary command execution prevention
  const commandInjectionReq = new Request("https://gateway/api/tools/render", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command: "rm -rf /" }),
  });
  const resCommand = await handleDaytonaTool(commandInjectionReq, mockDaytonaEnv, "render");
  test("Daytona Security: Arbitrary command parameter without url is rejected with 400", resCommand.status === 400);

  // 4.5 Tool target extraction & parameter validation
  const validRenderReq = new Request("https://gateway/api/tools/render", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://example.com/page" }),
  });
  const parsedRender = await parseAndValidateTarget(validRenderReq);
  test("Daytona Parser: Render tool target correctly parsed and validated", parsedRender.hostname === "example.com" && parsedRender.pathname === "/page");

  const validScreenshotReq = new Request("https://gateway/api/tools/screenshot", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://example.com/dashboard" }),
  });
  const parsedScreenshot = await parseAndValidateTarget(validScreenshotReq);
  test("Daytona Parser: Screenshot tool target correctly parsed and validated", parsedScreenshot.hostname === "example.com");

  const validPdfReq = new Request("https://gateway/api/tools/pdf?url=https%3A%2F%2Fexample.com%2Fdoc", {
    method: "GET",
  });
  const parsedPdf = await parseAndValidateTarget(validPdfReq);
  test("Daytona Parser: PDF tool target correctly parsed from query string", parsedPdf.pathname === "/doc");

  // 4.6 Strict limits
  test("Daytona Limits: Max output bytes limit enforced at 5MB", MAX_DAYTONA_OUTPUT_BYTES === 5 * 1024 * 1024);
  test("Daytona Limits: Default timeout capped at 45 seconds", DEFAULT_DAYTONA_TIMEOUT_SECONDS === 45);

  // 4.7 Gateway independence: Normal RouteX proxy remains fully functional
  const proxyIndependenceCheck = resolveAndProxy("/test", new URL("https://example.com"));
  test("Gateway Independence: Normal RouteX proxy functions completely independently of Daytona", proxyIndependenceCheck.includes("/proxy?url=https%3A%2F%2Fexample.com%2Ftest"));

  // 4.8 Viewport configuration testing (Desktop vs Mobile)
  const mobileViewportReq = new Request("https://gateway/api/tools/screenshot", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://example.com", viewport: "mobile" }),
  });
  const parsedMobile = await parseAndValidateRequest(mobileViewportReq);
  test("Daytona Viewport: Mobile mode parsed correctly", parsedMobile.viewport === "mobile" && parsedMobile.target.hostname === "example.com");

  const desktopDefaultReq = new Request("https://gateway/api/tools/render", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://example.com" }),
  });
  const parsedDefault = await parseAndValidateRequest(desktopDefaultReq);
  test("Daytona Viewport: Desktop mode defaulted when omitted", parsedDefault.viewport === "desktop");

  const queryViewportReq = new Request("https://gateway/api/tools/pdf?url=https%3A%2F%2Fexample.com&viewport=mobile", {
    method: "GET",
  });
  const parsedQueryViewport = await parseAndValidateRequest(queryViewportReq);
  test("Daytona Viewport: Query string viewport parameter parsed correctly", parsedQueryViewport.viewport === "mobile");

  // 4.9 Prepared Snapshot configuration testing (Phase 3)
  const snapshotEnv: Env = { ASSETS: {} as any, DAYTONA_API_KEY: "dtn_key", DAYTONA_SNAPSHOT: "routex-playwright-snapshot" };
  const snapshotStatus = getDaytonaStatus(snapshotEnv);
  test("Daytona Snapshot: Snapshot configured flag set when DAYTONA_SNAPSHOT present", snapshotStatus.snapshotConfigured === true);

  const noSnapshotStatus = getDaytonaStatus(mockDaytonaEnv);
  test("Daytona Snapshot: Snapshot configured flag false when DAYTONA_SNAPSHOT absent", noSnapshotStatus.snapshotConfigured === false);

  // 4.10 Daytona error handling (Unavailable / invalid target network)
  const unavailableReq = new Request("https://gateway/api/tools/render", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://nonexistent-domain-for-unit-test-12345.com" }),
  });
  const resUnavailable = await handleDaytonaTool(unavailableReq, mockDaytonaEnv, "render");
  test("Daytona Error Handling: Unreachable target or client failure returns 502 Bad Gateway without crashing", resUnavailable.status === 502);

  // ----------------------------------------------------
  // SECTION 5: HTTP STATUS SANITIZATION & REGRESSION TESTS
  // ----------------------------------------------------
  console.log("\n--- Section 5: HTTP Status Sanitization & Gateway Resilience ---");
  test("Status Sanitization: Standard 200 OK preserved", sanitizeHttpStatus(200) === 200);
  test("Status Sanitization: Standard 301 Redirect preserved", sanitizeHttpStatus(301) === 301);
  test("Status Sanitization: Standard 404 Not Found preserved", sanitizeHttpStatus(404) === 404);
  test("Status Sanitization: Standard 500 Server Error preserved", sanitizeHttpStatus(500) === 500);
  test("Status Sanitization: Non-standard status 999 (LinkedIn Request Denied) safely mapped to 502", sanitizeHttpStatus(999) === 502);
  test("Status Sanitization: Non-standard status < 200 mapped to 502", sanitizeHttpStatus(100) === 502);
  test("Status Sanitization: Non-standard status > 599 mapped to 502", sanitizeHttpStatus(600) === 502);
  test("StatusText Sanitization: Normal ASCII reason phrase preserved", sanitizeStatusText("OK") === "OK");
  test("StatusText Sanitization: Empty or <none> string returns undefined", sanitizeStatusText("<none>") === undefined);
  test("StatusText Sanitization: Control characters and newlines stripped", sanitizeStatusText("OK\r\nInjected: Header") === "OKInjected: Header");

  // Regression test: LinkedIn returns HTTP 999 which previously caused RangeError (Cloudflare Error 1101)
  const linkedInReq = new Request("https://gateway/proxy?url=https%3A%2F%2Fwww.linkedin.com%2Fin%2Fjojin-john-74386b34a%2F", {
    method: "GET",
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    }
  });
  const regressionEnv: Env = { ASSETS: {} as any };
  const linkedInRes = await worker.fetch(linkedInReq, regressionEnv);
  test("Regression Test: Worker /proxy handles non-standard upstream status 999 without throwing RangeError (Error 1101)", linkedInRes.status === 502);
  test("Regression Test: Worker preserves original non-standard upstream code in X-Upstream-Status", linkedInRes.headers.get("X-Upstream-Status") === "999");
  test("Regression Test: Gateway identifier X-RouteX-Gateway present on sanitized error response", linkedInRes.headers.get("X-RouteX-Gateway") === "1");

  // SPA navigation test: Direct /tools?category=Image should 302 redirect to /proxy?url=...
  const spaCatReq = new Request("https://gateway/tools?category=Image", {
    method: "GET",
    headers: {
      "Cookie": "__routex_target=https%3A%2F%2Ftoolify-we.vercel.app",
      "Accept": "text/html,application/xhtml+xml",
    },
  });
  const spaCatRes = await worker.fetch(spaCatReq, regressionEnv);
  test("SPA Navigation: Direct unproxied route redirected to /proxy?url=... via cookie", spaCatRes.status === 302 && Boolean(spaCatRes.headers.get("Location")?.includes("/proxy?url=")));

  // --- Section 6: API Catalog & Documentation ---
  const apiJsonReq = new Request("https://gateway/api", {
    method: "GET",
    headers: { "Accept": "application/json" }
  });
  const apiJsonRes = await worker.fetch(apiJsonReq, regressionEnv);
  const apiJsonData = await apiJsonRes.json() as any;
  test("API Catalog: Returns JSON when requested via Accept: application/json", apiJsonRes.status === 200 && apiJsonData.service === "RouteX Web Gateway");
  test("API Catalog: Includes core, diagnostics and inspector endpoint groups", Boolean(apiJsonData.endpoints?.core && apiJsonData.endpoints?.inspectorTools));

  const apiHtmlEnv: Env = {
    ASSETS: {
      fetch: async (req: Request) => {
        const u = new URL(req.url);
        return new Response(`<html>${u.pathname}</html>`, { status: 200, headers: { "Content-Type": "text/html" } });
      }
    } as any
  };
  const apiHtmlReq = new Request("https://gateway/api", {
    method: "GET",
    headers: { "Accept": "text/html,application/xhtml+xml" }
  });
  const apiHtmlRes = await worker.fetch(apiHtmlReq, apiHtmlEnv);
  const apiHtmlText = await apiHtmlRes.text();
  test("API Catalog: Serves api.html when requested from a browser with Accept: text/html", apiHtmlRes.status === 200 && apiHtmlText.includes("/api.html"));

  const apiDotJsonReq = new Request("https://gateway/api.json", { method: "GET" });
  const apiDotJsonRes = await worker.fetch(apiDotJsonReq, regressionEnv);
  const apiDotJsonData = await apiDotJsonRes.json() as any;
  test("API Catalog: Returns JSON directly via /api.json", apiDotJsonRes.status === 200 && apiDotJsonData.service === "RouteX Web Gateway");

  // --- Section 7: DNS-over-HTTPS, TLS Audit & Raw Mode ---
  const dnsLoopbackReq = new Request("https://gateway/api/tools/dns?domain=127.0.0.1", { method: "GET" });
  const dnsLoopbackRes = await worker.fetch(dnsLoopbackReq, regressionEnv);
  test("DNS Tool: SSRF loopback target rejected with 400 Bad Request", dnsLoopbackRes.status === 400);

  const dnsPublicReq = new Request("https://gateway/api/tools/dns?domain=example.com", { method: "GET" });
  const dnsPublicRes = await worker.fetch(dnsPublicReq, regressionEnv);
  const dnsPublicData = (await dnsPublicRes.json()) as any;
  test("DNS Tool: Returns DNS records structure for public domain", dnsPublicRes.status === 200 && dnsPublicData.domain === "example.com" && Boolean(dnsPublicData.records));

  const tlsHttpReq = new Request("https://gateway/api/tools/tls?url=http%3A%2F%2Fexample.com", { method: "GET" });
  const tlsHttpRes = await worker.fetch(tlsHttpReq, regressionEnv);
  const tlsHttpData = (await tlsHttpRes.json()) as any;
  test("TLS Tool: Non-HTTPS target flags isHttps=false", tlsHttpRes.status === 200 && tlsHttpData.isHttps === false);

  const rawReq = new Request("https://gateway/proxy?url=https%3A%2F%2Fexample.com&raw=true", { method: "GET" });
  const rawRes = await worker.fetch(rawReq, regressionEnv);
  test("Raw Passthrough: Attaches X-RouteX-Mode: raw-passthrough header", rawRes.headers.get("X-RouteX-Mode") === "raw-passthrough");

  // ----------------------------------------------------
  // SECTION 8: NEW ENHANCEMENTS & TOOLS
  // ----------------------------------------------------
  console.log("\n--- Section 8: OpenAPI 3.1, Markdown, Metadata & Downloads ---");

  // 8.1 OpenAPI 3.1 Schema Endpoint
  const openApiReq = new Request("https://gateway/openapi.json", { method: "GET" });
  const openApiRes = await worker.fetch(openApiReq, regressionEnv);
  const openApiData = (await openApiRes.json()) as any;
  test("OpenAPI 3.1: Serves valid schema via /openapi.json", openApiRes.status === 200 && openApiData.openapi === "3.1.0");
  test("OpenAPI 3.1: Spec includes all core and inspector endpoints", Boolean(openApiData.paths?.["/proxy"] && openApiData.paths?.["/api/tools/markdown"] && openApiData.paths?.["/api/tools/metadata"]));

  // 8.2 Force Download Header
  const downloadReq = new Request("https://gateway/proxy?url=https%3A%2F%2Fexample.com%2Freport.pdf&download=1", { method: "GET" });
  const downloadRes = await worker.fetch(downloadReq, regressionEnv);
  test("Proxy Download Mode: Sets Content-Disposition attachment header", downloadRes.headers.get("Content-Disposition")?.includes("attachment; filename=") === true);

  // 8.3 XML Tool Endpoint
  const xmlReq = new Request("https://gateway/api/tools/xml?url=https%3A%2F%2Fexample.com", { method: "GET" });
  const xmlRes = await worker.fetch(xmlReq, regressionEnv);
  const xmlData = (await xmlRes.json()) as any;
  test("XML Inspector Tool: Returns HTTP 200 with structured parsing info", xmlRes.status === 200 && Boolean(xmlData.target));

  // 8.4 Markdown Extractor Tool
  const markdownReq = new Request("https://gateway/api/tools/markdown?url=https%3A%2F%2Fexample.com", { method: "GET" });
  const markdownRes = await worker.fetch(markdownReq, regressionEnv);
  const markdownData = (await markdownRes.json()) as any;
  test("Markdown Extractor Tool: Returns 200 with title and markdown content", markdownRes.status === 200 && typeof markdownData.markdown === "string" && typeof markdownData.wordCount === "number");

  // 8.5 Open Graph & SEO Metadata Extractor Tool
  const metadataReq2 = new Request("https://gateway/api/tools/metadata?url=https%3A%2F%2Fexample.com", { method: "GET" });
  const metadataRes2 = await worker.fetch(metadataReq2, regressionEnv);
  const metadataData2 = (await metadataRes2.json()) as any;
  test("Metadata Tool: Returns 200 with title, canonical and openGraph object", metadataRes2.status === 200 && Boolean(metadataData2.openGraph !== undefined) && Boolean(metadataData2.twitterCard !== undefined));

  // 8.6 CORS Proxy Alias
  const corsReq = new Request("https://gateway/cors?url=https%3A%2F%2Fexample.com", { method: "GET" });
  const corsRes = await worker.fetch(corsReq, regressionEnv);
  test("CORS Proxy Endpoint: Automatically activates raw mode with CORS headers", corsRes.headers.get("X-RouteX-Mode") === "raw-passthrough" && corsRes.headers.get("Access-Control-Allow-Origin") === "*");

  // 8.7 Static Asset Robots & Favicon
  const staticEnv: Env = {
    ASSETS: {
      fetch: async (req: Request) => {
        const u = new URL(req.url);
        return new Response(`content of ${u.pathname}`, { status: 200, headers: { "Content-Type": "text/plain" } });
      }
    } as any
  };
  const robotsReq = new Request("https://gateway/robots.txt", { method: "GET" });
  const robotsRes = await worker.fetch(robotsReq, staticEnv);
  test("Static Assets: Serves /robots.txt from ASSETS binding", robotsRes.status === 200);

  const faviconSvgReq = new Request("https://gateway/favicon.svg", { method: "GET" });
  const faviconSvgRes = await worker.fetch(faviconSvgReq, staticEnv);
  test("Static Assets: Serves /favicon.svg from ASSETS binding", faviconSvgRes.status === 200);

  // 8.8 Turnstile Config Endpoint
  const turnstileConfigReq = new Request("https://gateway/api/turnstile/config", { method: "GET" });
  const turnstileConfigRes = await worker.fetch(turnstileConfigReq, regressionEnv);
  const turnstileConfigData = (await turnstileConfigRes.json()) as any;
  test("Turnstile Config: Reports disabled when secret key not configured", turnstileConfigRes.status === 200 && turnstileConfigData.enabled === false);

  const turnstileConfigEnv: Env = {
    ...regressionEnv,
    TURNSTILE_SECRET_KEY: "0x4AAAAAA",
    TURNSTILE_SITE_KEY: "0x4BBBBBB",
  };
  const turnstileConfigReq2 = new Request("https://gateway/api/turnstile/config", { method: "GET" });
  const turnstileConfigRes2 = await worker.fetch(turnstileConfigReq2, turnstileConfigEnv);
  const turnstileConfigData2 = (await turnstileConfigRes2.json()) as any;
  test("Turnstile Config: Reports enabled and exposes siteKey when keys present", turnstileConfigRes2.status === 200 && turnstileConfigData2.enabled === true && turnstileConfigData2.siteKey === "0x4BBBBBB");

  // 8.9 Direct Raw Markdown Reader
  const rSlashReq = new Request("https://gateway/r/https://example.com", { method: "GET" });
  const rSlashRes = await worker.fetch(rSlashReq, regressionEnv);
  const rSlashText = await rSlashRes.text();
  test("Direct Markdown Reader (/r/:url): Returns raw text/markdown", rSlashRes.status === 200 && rSlashRes.headers.get("Content-Type")?.includes("text/markdown") === true && rSlashText.includes("Example Domain"));

  const rParamReq = new Request("https://gateway/r?url=https%3A%2F%2Fexample.com", { method: "GET" });
  const rParamRes = await worker.fetch(rParamReq, regressionEnv);
  test("Direct Markdown Reader (/r?url=...): Returns 200 with text/markdown", rParamRes.status === 200 && rParamRes.headers.get("Content-Type")?.includes("text/markdown") === true);

  // 8.10 Scalar Docs Endpoint (/docs)
  const docsReq = new Request("https://gateway/docs", { method: "GET" });
  const docsRes = await worker.fetch(docsReq, staticEnv);
  const docsText = await docsRes.text();
  test("Scalar Docs (/docs): Serves docs.html from ASSETS binding", docsRes.status === 200 && docsText.includes("/docs.html"));

  // 8.11 Whois & RDAP Lookup Tool
  const whoisLoopbackReq = new Request("https://gateway/api/tools/whois?domain=127.0.0.1", { method: "GET" });
  const whoisLoopbackRes = await worker.fetch(whoisLoopbackReq, regressionEnv);
  test("Whois Tool: SSRF loopback target rejected with 400 Bad Request", whoisLoopbackRes.status === 400);

  const whoisPublicReq = new Request("https://gateway/api/tools/whois?domain=example.com", { method: "GET" });
  const whoisPublicRes = await worker.fetch(whoisPublicReq, regressionEnv);
  const whoisPublicData = (await whoisPublicRes.json()) as any;
  test("Whois Tool: Returns structured domain details", whoisPublicRes.status === 200 && whoisPublicData.domain === "example.com");

  // 8.12 Feed Parser Tool
  const feedReq = new Request("https://gateway/api/tools/feed?url=https%3A%2F%2Fexample.com", { method: "GET" });
  const feedRes = await worker.fetch(feedReq, regressionEnv);
  const feedData = (await feedRes.json()) as any;
  test("Feed Parser: Returns structured feed analysis object", feedRes.status === 200 && Boolean(feedData.channel !== undefined) && Array.isArray(feedData.items));

  // 8.13 Edge Client IP & Datacenter Inspector (/ip)
  const ipReq = new Request("https://gateway/ip", {
    method: "GET",
    headers: { "cf-connecting-ip": "203.0.113.195" },
  });
  const ipRes = await worker.fetch(ipReq, regressionEnv);
  const ipData = (await ipRes.json()) as any;
  test("Edge Client IP (/ip): Returns client IP and Cloudflare edge metadata", ipRes.status === 200 && ipData.ip === "203.0.113.195" && typeof ipData.colo === "string");

  // 8.14 Developer Request Echo (/echo)
  const echoReq = new Request("https://gateway/echo", {
    method: "GET",
    headers: { "X-Custom-Echo-Header": "RouteX-Echo-Test" },
  });
  const echoRes = await worker.fetch(echoReq, regressionEnv);
  const echoData = (await echoRes.json()) as any;
  test("Request Echo (/echo): Echoes client headers and request details", echoRes.status === 200 && echoData.method === "GET" && echoData.headers["x-custom-echo-header"] === "RouteX-Echo-Test");

  // 8.15 Model Context Protocol Server (/mcp)
  const mcpGetReq = new Request("https://gateway/mcp", { method: "GET" });
  const mcpGetRes = await worker.fetch(mcpGetReq, regressionEnv);
  const mcpGetData = (await mcpGetRes.json()) as any;
  test("MCP Server (GET /mcp): Returns MCP capabilities and tools spec", mcpGetRes.status === 200 && mcpGetData.protocolVersion === "2024-11-05" && Array.isArray(mcpGetData.tools));

  const mcpInitReq = new Request("https://gateway/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  });
  const mcpInitRes = await worker.fetch(mcpInitReq, regressionEnv);
  const mcpInitData = (await mcpInitRes.json()) as any;
  test("MCP Server (initialize): Responds with JSON-RPC 2.0 handshake", mcpInitRes.status === 200 && mcpInitData.result?.protocolVersion === "2024-11-05");

  const mcpListReq = new Request("https://gateway/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
  });
  const mcpListRes = await worker.fetch(mcpListReq, regressionEnv);
  const mcpListData = (await mcpListRes.json()) as any;
  test("MCP Server (tools/list): Returns tool declarations for LLM agents", mcpListRes.status === 200 && Array.isArray(mcpListData.result?.tools) && mcpListData.result.tools.length >= 6);

  const mcpCallReq = new Request("https://gateway/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "routex_dns_lookup", arguments: { domain: "example.com" } },
    }),
  });
  const mcpCallRes = await worker.fetch(mcpCallReq, regressionEnv);
  const mcpCallData = (await mcpCallRes.json()) as any;
  test("MCP Server (tools/call): Executes tool and returns content array", mcpCallRes.status === 200 && Array.isArray(mcpCallData.result?.content) && mcpCallData.result.content[0].type === "text");

  // 8.16 SSL Certificate Transparency Tool (/api/tools/cert)
  const certLoopbackReq = new Request("https://gateway/api/tools/cert?domain=127.0.0.1", { method: "GET" });
  const certLoopbackRes = await worker.fetch(certLoopbackReq, regressionEnv);
  test("Cert Tool: SSRF loopback target rejected with 400 Bad Request", certLoopbackRes.status === 400);

  // 8.17 Wayback Machine Archive Tool (/api/tools/archive)
  const archiveLoopbackReq = new Request("https://gateway/api/tools/archive?url=http%3A%2F%2F169.254.169.254", { method: "GET" });
  const archiveLoopbackRes = await worker.fetch(archiveLoopbackReq, regressionEnv);
  test("Archive Tool: SSRF cloud metadata target rejected with 400 Bad Request", archiveLoopbackRes.status === 400);

  // 8.18 Batch URL Multi-Probe (/api/tools/batch)
  const batchInvalidReq = new Request("https://gateway/api/tools/batch", { method: "GET" });
  const batchInvalidRes = await worker.fetch(batchInvalidReq, regressionEnv);
  test("Batch Tool: GET method rejected with 405 Method Not Allowed", batchInvalidRes.status === 405);

  const batchValidReq = new Request("https://gateway/api/tools/batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ urls: ["https://example.com"] }),
  });
  const batchValidRes = await worker.fetch(batchValidReq, regressionEnv);
  const batchValidData = (await batchValidRes.json()) as any;
  test("Batch Tool: Executes parallel probes and returns summary", batchValidRes.status === 200 && batchValidData.total === 1 && Array.isArray(batchValidData.probes));

  // ----------------------------------------------------
  // TEST SUMMARY
  // ----------------------------------------------------
  console.log("\n==================================================");
  console.log("  TEST SUMMARY");
  console.log("==================================================");
  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;

  console.log(`  TOTAL:  ${results.length} tests`);
  console.log(`  PASSED: ${passed}`);
  console.log(`  FAILED: ${failed}`);

  if (failed > 0) {
    console.error("\nSome tests failed. Aborting deployment.");
    process.exitCode = 1;
  } else {
    console.log("\nAll automated tests passed successfully!");
    process.exitCode = 0;
  }
}

runAllTests().catch((err) => {
  console.error("Fatal test runner error:", err);
  process.exitCode = 1;
});
