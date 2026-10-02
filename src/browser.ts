/**
 * RouteX Optional Browser Tools Engine
 * Provides integration hooks for Cloudflare Workers Browser Rendering.
 *
 * NOTE: Browser Rendering is strictly an optional diagnostic tool with free-tier
 * limits and is NEVER required for standard RouteX proxying.
 */

import { normalizeTarget } from "./security.ts";
import type { Env } from "./types.ts";

export function isBrowserRenderingAvailable(env: Env): boolean {
  return Boolean(env.BROWSER);
}

export async function handleBrowserTool(
  request: Request,
  env: Env,
  toolType: "screenshot" | "pdf" | "rendered-html"
): Promise<Response> {
  const url = new URL(request.url);
  const targetRaw = url.searchParams.get("url");

  if (!targetRaw) {
    return Response.json({ ok: false, error: "Missing required 'url' parameter." }, { status: 400 });
  }

  let target: URL;
  try {
    target = normalizeTarget(targetRaw);
  } catch (err) {
    return Response.json(
      { ok: false, error: err instanceof Error ? err.message : "Invalid target URL." },
      { status: 400 }
    );
  }

  if (!isBrowserRenderingAvailable(env)) {
    return Response.json(
      {
        ok: false,
        error: "Cloudflare Browser Rendering (env.BROWSER) is not configured in this deployment.",
        note: "Browser Rendering is an optional diagnostic add-on with Free-tier platform quotas and is not required for standard RouteX proxying.",
        setup: {
          step1: "Enable Workers Browser Rendering in Cloudflare Dashboard (Workers & Pages -> Browser Rendering).",
          step2: "Add [browser] binding = 'BROWSER' to your wrangler.toml.",
          step3: "Re-deploy with `npm run deploy`.",
        },
      },
      { status: 501 }
    );
  }

  // When env.BROWSER binding is present, interact with the Cloudflare Browser Rendering session
  try {
    // Forward request to Cloudflare Browser Rendering endpoint if session fetch is supported
    const browserResponse = await env.BROWSER!.fetch(request);
    return browserResponse;
  } catch (err) {
    return Response.json(
      {
        ok: false,
        tool: toolType,
        target: target.toString(),
        error: err instanceof Error ? err.message : "Browser execution error.",
      },
      { status: 502 }
    );
  }
}
