/**
 * RouteX Automated Test Suite
 * Covers Core Rewriter, SSRF & Security Engine, Inspector Tools, Diagnostics, and Endpoints.
 */

import { isBlockedHostname, isIPv4, isPrivateIPv4, normalizeTarget, MAX_URL_LENGTH } from "../src/security.ts";
import { resolveAndProxy, rewriteSrcset, rewriteCss, rewriteHtml, buildResponseHeaders, gatewayUrl } from "../src/rewriter.ts";
import { runDiagnostics } from "../src/diagnostics.ts";
import { checkSecurityHeaders, formatJson, viewXml } from "../src/tools.ts";
import { isBrowserRenderingAvailable } from "../src/browser.ts";
import { verifyTurnstileToken } from "../src/turnstile.ts";
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
  test("HTML <video src and poster> rewritten", rewrittenHtml.includes(`poster="${resolveAndProxy("/poster.jpg", baseHtmlUrl)}"`) && rewrittenHtml.includes(`src="${resolveAndProxy("/vid.mp4", baseHtmlUrl)}"`));
  test("HTML <source src> rewritten", rewrittenHtml.includes(`src="${resolveAndProxy("/vid.webm", baseHtmlUrl)}"`));
  test("HTML <audio src> rewritten", rewrittenHtml.includes(`src="${resolveAndProxy("/song.mp3", baseHtmlUrl)}"`));
  test("HTML <iframe src> rewritten", rewrittenHtml.includes(`src="${resolveAndProxy("/embed.html", baseHtmlUrl)}"`));
  test("HTML GET <form action> rewritten", rewrittenHtml.includes(`action="${resolveAndProxy("/search", baseHtmlUrl)}"`));
  test("HTML POST <form action> left untouched", rewrittenHtml.includes('action="/login"'));
  test("HTML inline style attribute rewritten", rewrittenHtml.includes(resolveAndProxy("inline.png", baseHtmlUrl)));
  test("HTML <style> block rewritten", rewrittenHtml.includes(resolveAndProxy("box.png", baseHtmlUrl)));

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
