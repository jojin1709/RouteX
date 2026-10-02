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
 * - Optional prepared snapshot acceleration via DAYTONA_SNAPSHOT.
 */

import type { CodeLanguage, Daytona } from "@daytona/sdk";
import { normalizeTarget } from "./security.ts";
import type { Env } from "./types.ts";

export type DaytonaTool = "render" | "screenshot" | "pdf";
export type ViewportMode = "desktop" | "mobile";

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
  const snapshotConfigured = Boolean(env.DAYTONA_SNAPSHOT && env.DAYTONA_SNAPSHOT.trim().length > 0);
  return {
    enabled: configured,
    provider: "daytona",
    configured,
    snapshotConfigured,
  };
}

/**
 * Creates an authenticated Daytona SDK client lazily on demand.
 * Daytona SDK is only loaded when an actual Daytona tool endpoint is called.
 */
export async function createDaytonaClient(env: Env): Promise<Daytona> {
  if (!isDaytonaConfigured(env)) {
    throw new Error("Daytona API key (DAYTONA_API_KEY) is not configured.");
  }

  const { Daytona } = await import("@daytona/sdk");
  return new Daytona({
    apiKey: env.DAYTONA_API_KEY!.trim(),
    apiUrl: env.DAYTONA_SERVER_URL?.trim() || undefined,
    target: env.DAYTONA_TARGET?.trim() || undefined,
  });
}

/**
 * Request options for Daytona browser operations.
 */
export interface DaytonaToolOptions {
  target: URL;
  viewport: ViewportMode;
}

/**
 * Extracts and strictly validates target URL and options from request body or query params.
 */
export async function parseAndValidateRequest(request: Request): Promise<DaytonaToolOptions> {
  let rawUrl: string | null = null;
  let viewport: ViewportMode = "desktop";

  if (request.method === "POST" || request.method === "PUT") {
    try {
      const body = await request.clone().json() as { url?: string; viewport?: string };
      if (body && typeof body.url === "string") {
        rawUrl = body.url;
      }
      if (body && (body.viewport === "mobile" || body.viewport === "desktop")) {
        viewport = body.viewport;
      }
    } catch {
      // Fall through to query parameter
    }
  }

  if (!rawUrl) {
    const reqUrl = new URL(request.url);
    rawUrl = reqUrl.searchParams.get("url");
    const v = reqUrl.searchParams.get("viewport");
    if (v === "mobile" || v === "desktop") {
      viewport = v;
    }
  }

  if (!rawUrl || rawUrl.trim().length === 0) {
    throw new Error("Missing required 'url' parameter in JSON body { \"url\": \"...\" } or query string.");
  }

  // Validate URL against RouteX SSRF & security policy
  const target = normalizeTarget(rawUrl);
  return { target, viewport };
}

/**
 * Convenience helper for URL-only target extraction.
 */
export async function parseAndValidateTarget(request: Request): Promise<URL> {
  const { target } = await parseAndValidateRequest(request);
  return target;
}

/**
 * Predefined, safe Playwright / headless script generator.
 * User cannot inject arbitrary shell commands or code.
 */
function buildPredefinedScript(tool: DaytonaTool, targetUrl: string, viewport: ViewportMode): string {
  const safeTarget = targetUrl.replace(/"/g, '\\"');
  const isMobile = viewport === "mobile";
  const viewportConfig = isMobile
    ? "{ width: 375, height: 667, isMobile: true, hasTouch: true }"
    : "{ width: 1280, height: 720 }";

  return `
const { chromium } = require('playwright');

(async () => {
  let browser;
  const consoleLogs = [];
  let requestCount = 0;
  const startTime = Date.now();

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: ${viewportConfig} });

    page.on('console', msg => {
      if (consoleLogs.length < 25) {
        consoleLogs.push({ type: msg.type(), text: msg.text().slice(0, 300) });
      }
    });

    page.on('request', () => { requestCount++; });

    const waitCondition = '${tool}' === 'render' ? 'domcontentloaded' : 'networkidle';
    await page.goto("${safeTarget}", { waitUntil: waitCondition, timeout: 25000 });

    let payload = '';
    if ('${tool}' === 'render') {
      payload = await page.content();
    } else if ('${tool}' === 'screenshot') {
      const buf = await page.screenshot({ type: 'png' });
      payload = buf.toString('base64');
    } else if ('${tool}' === 'pdf') {
      const buf = await page.pdf({ format: 'A4', printBackground: true });
      payload = buf.toString('base64');
    }

    const durationMs = Date.now() - startTime;
    const output = JSON.stringify({
      payload,
      consoleLogs,
      requestCount,
      durationMs,
      viewport: '${viewport}'
    });

    console.log('---ROUTEX_START---' + output + '---ROUTEX_END---');
  } catch (err) {
    console.error('TaskError:', err.message);
    process.exit(1);
  } finally {
    if (browser) await browser.close();
  }
})();
`.trim();
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

  // 2. Validate target URL and options through RouteX SSRF & security policy
  let parsedOpts: DaytonaToolOptions;
  try {
    parsedOpts = await parseAndValidateRequest(request);
  } catch (err) {
    return Response.json(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Invalid or prohibited destination URL.",
      },
      { status: 400 }
    );
  }

  const { target, viewport } = parsedOpts;
  const startTime = Date.now();
  let daytona: Daytona | null = null;
  let sandbox: any = null;

  try {
    daytona = await createDaytonaClient(env);
    const { CodeLanguage } = await import("@daytona/sdk");

    // 3. Create an isolated ephemeral sandbox (using prepared snapshot if configured)
    const snapshotName = env.DAYTONA_SNAPSHOT?.trim();
    const createParams: any = snapshotName
      ? {
          snapshot: snapshotName,
          ephemeral: true,
          autoDeleteInterval: 0,
          labels: {
            service: "routex-web-gateway",
            tool,
            viewport,
          },
        }
      : {
          language: CodeLanguage.TYPESCRIPT,
          ephemeral: true,
          autoDeleteInterval: 0,
          labels: {
            service: "routex-web-gateway",
            tool,
            viewport,
          },
        };

    sandbox = await daytona.create(createParams, { timeout: DEFAULT_DAYTONA_TIMEOUT_SECONDS });

    // 4. Predefined task script (no arbitrary user commands permitted)
    const script = buildPredefinedScript(tool, target.toString(), viewport);

    // Write script to sandbox safely via sandbox process (bypasses serverless 'fs' requirement)
    const base64Script = Buffer.from(script, "utf-8").toString("base64");
    const writeResult = await sandbox.process.executeCommand(
      `sh -c 'echo "${base64Script}" | base64 -d > /tmp/routex_task.js'`,
      "/tmp",
      undefined,
      15
    );
    if (writeResult.exitCode !== 0 && writeResult.exitCode !== undefined) {
      throw new Error(`Failed to initialize task script in sandbox: ${writeResult.result || "exit " + writeResult.exitCode}`);
    }

    // Execute predefined node task with strict timeout
    // If snapshot is used, chromium/playwright are pre-installed; otherwise install on the fly
    const execCommand = snapshotName
      ? "node /tmp/routex_task.js"
      : "npx -y playwright install --with-deps chromium && node /tmp/routex_task.js";

    const execResponse = await sandbox.process.executeCommand(
      execCommand,
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
          viewport,
          error: "Predefined tool task did not produce expected output.",
          exitCode,
          logs: stdout.slice(0, 1000),
        },
        { status: 502 }
      );
    }

    const rawJson = stdout.slice(startIdx + "---ROUTEX_START---".length, endIdx);

    // 5. Size check
    if (rawJson.length > MAX_DAYTONA_OUTPUT_BYTES) {
      return Response.json(
        {
          ok: false,
          tool,
          target: target.toString(),
          error: `Output size (${rawJson.length} bytes) exceeds maximum allowed limit (${MAX_DAYTONA_OUTPUT_BYTES} bytes).`,
        },
        { status: 413 }
      );
    }

    let parsedResult: {
      payload: string;
      consoleLogs: Array<{ type: string; text: string }>;
      requestCount: number;
      durationMs: number;
      viewport: string;
    };

    try {
      parsedResult = JSON.parse(rawJson);
    } catch {
      return Response.json(
        {
          ok: false,
          tool,
          target: target.toString(),
          error: "Failed to parse tool execution response.",
        },
        { status: 502 }
      );
    }

    const totalDurationMs = Date.now() - startTime;

    if (tool === "render") {
      return Response.json({
        ok: true,
        tool: "render",
        target: target.toString(),
        viewport,
        renderedHtml: parsedResult.payload,
        consoleLogs: parsedResult.consoleLogs,
        networkRequests: parsedResult.requestCount,
        durationMs: totalDurationMs,
      });
    }

    if (tool === "screenshot") {
      return Response.json({
        ok: true,
        tool: "screenshot",
        target: target.toString(),
        viewport,
        format: "png",
        screenshotBase64: parsedResult.payload,
        consoleLogs: parsedResult.consoleLogs,
        networkRequests: parsedResult.requestCount,
        durationMs: totalDurationMs,
      });
    }

    if (tool === "pdf") {
      return Response.json({
        ok: true,
        tool: "pdf",
        target: target.toString(),
        viewport,
        format: "pdf",
        pdfBase64: parsedResult.payload,
        consoleLogs: parsedResult.consoleLogs,
        networkRequests: parsedResult.requestCount,
        durationMs: totalDurationMs,
      });
    }

    return Response.json({ ok: false, error: "Unknown tool" }, { status: 400 });
  } catch (err) {
    const totalDurationMs = Date.now() - startTime;
    return Response.json(
      {
        ok: false,
        tool,
        target: target.toString(),
        viewport,
        error: err instanceof Error ? err.message : "Daytona compute task error.",
        durationMs: totalDurationMs,
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
