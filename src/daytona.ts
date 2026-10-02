/**
 * RouteX Optional Daytona Integration Module
 *
 * Architecture:
 * - Cloudflare Worker remains the primary RouteX gateway.
 * - Daytona provides optional isolated compute sandboxes for browser automation,
 *   Playwright rendering, screenshots, and PDF generation.
 * - RouteX NEVER depends on Daytona for standard web proxy requests.
 * - If Daytona is unconfigured, unreachable, or errors, RouteX continues operating normally.
 * - Zero database/storage persistence.
 * - No arbitrary shell commands or code execution allowed from user input.
 * - Strictly ephemeral sandboxes with guaranteed cleanup in finally blocks.
 */

import { CodeLanguage, Daytona } from "@daytona/sdk";
import { normalizeTarget } from "./security.ts";
import type { Env } from "./types.ts";

export type DaytonaTool = "render" | "screenshot" | "pdf";

export const MAX_DAYTONA_OUTPUT_BYTES = 5 * 1024 * 1024; // 5 MB output limit
export const DEFAULT_DAYTONA_TIMEOUT_SECONDS = 45; // 45s max task duration

/**
 * Returns true if the Daytona API key is configured in the environment.
 */
export function isDaytonaConfigured(env: Env): boolean {
  return Boolean(env.DAYTONA_API_KEY && env.DAYTONA_API_KEY.trim().length > 0);
}

/**
 * Health / configuration status for Daytona.
 * Never exposes the API key, organization ID, or secrets.
 */
export function getDaytonaStatus(env: Env) {
  const configured = isDaytonaConfigured(env);
  return {
    enabled: configured,
    provider: "daytona",
    configured,
  };
}

/**
 * Creates an authenticated Daytona SDK client.
 */
export function createDaytonaClient(env: Env): Daytona {
  if (!isDaytonaConfigured(env)) {
    throw new Error("Daytona API key (DAYTONA_API_KEY) is not configured.");
  }

  return new Daytona({
    apiKey: env.DAYTONA_API_KEY!.trim(),
    apiUrl: env.DAYTONA_SERVER_URL?.trim() || undefined,
    target: env.DAYTONA_TARGET?.trim() || undefined,
  });
}

/**
 * Extracts and strictly validates target URL from request body or query params.
 */
export async function parseAndValidateTarget(request: Request): Promise<URL> {
  let rawUrl: string | null = null;

  if (request.method === "POST" || request.method === "PUT") {
    try {
      const body = await request.clone().json() as { url?: string };
      if (body && typeof body.url === "string") {
        rawUrl = body.url;
      }
    } catch {
      // Fall through to query parameter
    }
  }

  if (!rawUrl) {
    const reqUrl = new URL(request.url);
    rawUrl = reqUrl.searchParams.get("url");
  }

  if (!rawUrl || rawUrl.trim().length === 0) {
    throw new Error("Missing required 'url' parameter in JSON body { \"url\": \"...\" } or query string.");
  }

  // Validate URL against RouteX SSRF & security policy
  return normalizeTarget(rawUrl);
}

/**
 * Predefined, safe Playwright / headless script generator.
 * User cannot inject arbitrary shell commands or code.
 */
function buildPredefinedScript(tool: DaytonaTool, targetUrl: string): string {
  const safeTarget = targetUrl.replace(/"/g, '\\"');

  switch (tool) {
    case "render":
      return `
const { chromium } = require('playwright');
(async () => {
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto("${safeTarget}", { waitUntil: 'domcontentloaded', timeout: 25000 });
    const html = await page.content();
    console.log('---ROUTEX_START---' + html + '---ROUTEX_END---');
  } catch (err) {
    console.error('RenderError:', err.message);
    process.exit(1);
  } finally {
    if (browser) await browser.close();
  }
})();
`.trim();

    case "screenshot":
      return `
const { chromium } = require('playwright');
(async () => {
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });
    await page.goto("${safeTarget}", { waitUntil: 'networkidle', timeout: 25000 });
    const buffer = await page.screenshot({ type: 'png' });
    console.log('---ROUTEX_START---' + buffer.toString('base64') + '---ROUTEX_END---');
  } catch (err) {
    console.error('ScreenshotError:', err.message);
    process.exit(1);
  } finally {
    if (browser) await browser.close();
  }
})();
`.trim();

    case "pdf":
      return `
const { chromium } = require('playwright');
(async () => {
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto("${safeTarget}", { waitUntil: 'networkidle', timeout: 25000 });
    const buffer = await page.pdf({ format: 'A4', printBackground: true });
    console.log('---ROUTEX_START---' + buffer.toString('base64') + '---ROUTEX_END---');
  } catch (err) {
    console.error('PdfError:', err.message);
    process.exit(1);
  } finally {
    if (browser) await browser.close();
  }
})();
`.trim();
  }
}

/**
 * Handles an optional Daytona tool invocation (render, screenshot, pdf).
 *
 * Ephemeral sandbox lifecycle:
 * Create -> Execute predefined task -> Collect result -> Cleanup (delete) -> Return result
 */
export async function handleDaytonaTool(
  request: Request,
  env: Env,
  tool: DaytonaTool
): Promise<Response> {
  // 1. Check configuration
  if (!isDaytonaConfigured(env)) {
    return Response.json(
      {
        ok: false,
        error: "Daytona integration is not configured in this deployment.",
        note: "Daytona is an optional compute sandbox and is not required for standard RouteX proxying.",
        setup: "Set the DAYTONA_API_KEY secret in Cloudflare Workers using `npx wrangler secret put DAYTONA_API_KEY`.",
      },
      { status: 501 }
    );
  }

  // 2. Validate target URL through RouteX SSRF & security policy
  let target: URL;
  try {
    target = await parseAndValidateTarget(request);
  } catch (err) {
    return Response.json(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Invalid or prohibited destination URL.",
      },
      { status: 400 }
    );
  }

  const startTime = Date.now();
  let daytona: Daytona | null = null;
  let sandbox: any = null;

  try {
    daytona = createDaytonaClient(env);

    // 3. Create an isolated ephemeral sandbox
    sandbox = await daytona.create(
      {
        language: CodeLanguage.TYPESCRIPT,
        ephemeral: true,
        autoDeleteInterval: 0,
        labels: {
          service: "routex-web-gateway",
          tool,
        },
      },
      { timeout: DEFAULT_DAYTONA_TIMEOUT_SECONDS }
    );

    // 4. Predefined task script (no arbitrary user commands permitted)
    const script = buildPredefinedScript(tool, target.toString());

    // Write script to sandbox
    await sandbox.fs.uploadFile("/tmp/routex_task.js", Buffer.from(script, "utf-8"));

    // Execute predefined node task with strict timeout
    const execResponse = await sandbox.process.executeCommand(
      "npx -y playwright install --with-deps chromium && node /tmp/routex_task.js",
      "/tmp",
      undefined,
      DEFAULT_DAYTONA_TIMEOUT_SECONDS
    );

    const stdout = execResponse.result || "";
    const startIdx = stdout.indexOf("---ROUTEX_START---");
    const endIdx = stdout.indexOf("---ROUTEX_END---");

    if (startIdx === -1 || endIdx === -1) {
      const exitCode = execResponse.exitCode ?? 1;
      return Response.json(
        {
          ok: false,
          tool,
          target: target.toString(),
          error: "Predefined tool task did not produce expected output.",
          exitCode,
          logs: stdout.slice(0, 1000),
        },
        { status: 502 }
      );
    }

    const payload = stdout.slice(startIdx + "---ROUTEX_START---".length, endIdx);

    // 5. Size check
    if (payload.length > MAX_DAYTONA_OUTPUT_BYTES) {
      return Response.json(
        {
          ok: false,
          tool,
          target: target.toString(),
          error: `Output size (${payload.length} bytes) exceeds maximum allowed limit (${MAX_DAYTONA_OUTPUT_BYTES} bytes).`,
        },
        { status: 413 }
      );
    }

    const durationMs = Date.now() - startTime;

    if (tool === "render") {
      return Response.json({
        ok: true,
        tool: "render",
        target: target.toString(),
        renderedHtml: payload,
        durationMs,
      });
    }

    if (tool === "screenshot") {
      return Response.json({
        ok: true,
        tool: "screenshot",
        target: target.toString(),
        format: "png",
        screenshotBase64: payload,
        durationMs,
      });
    }

    if (tool === "pdf") {
      return Response.json({
        ok: true,
        tool: "pdf",
        target: target.toString(),
        format: "pdf",
        pdfBase64: payload,
        durationMs,
      });
    }

    return Response.json({ ok: false, error: "Unknown tool" }, { status: 400 });
  } catch (err) {
    const durationMs = Date.now() - startTime;
    return Response.json(
      {
        ok: false,
        tool,
        target: target.toString(),
        error: err instanceof Error ? err.message : "Daytona compute task error.",
        durationMs,
      },
      { status: 502 }
    );
  } finally {
    // 6. Guaranteed sandbox cleanup: delete ephemeral sandbox immediately
    if (sandbox && daytona) {
      try {
        await daytona.delete(sandbox);
      } catch {
        // Cleanup failure is non-fatal to client response
      }
    }
  }
}
