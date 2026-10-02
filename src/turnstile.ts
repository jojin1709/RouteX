/**
 * RouteX Cloudflare Turnstile Abuse Protection Integration
 *
 * Provides optional CAPTCHA/challenge token verification via Cloudflare's
 * siteverify API without enforcing it on standard proxy traffic.
 */

import type { Env } from "./types.ts";

export interface TurnstileVerificationResult {
  success: boolean;
  timestamp?: string;
  hostname?: string;
  errorCodes?: string[];
}

/**
 * Validates a Turnstile token against Cloudflare's siteverify API.
 */
export async function verifyTurnstileToken(
  token: string,
  clientIp: string | null,
  env: Env
): Promise<TurnstileVerificationResult> {
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    // If not configured, verification cannot proceed
    return {
      success: false,
      errorCodes: ["missing-turnstile-secret-key-configuration"],
    };
  }

  const formData = new FormData();
  formData.append("secret", secret);
  formData.append("response", token);
  if (clientIp) {
    formData.append("remoteip", clientIp);
  }

  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: formData,
    });

    const outcome = (await res.json()) as {
      success: boolean;
      "error-codes"?: string[];
      challenge_ts?: string;
      hostname?: string;
    };

    return {
      success: outcome.success,
      timestamp: outcome.challenge_ts,
      hostname: outcome.hostname,
      errorCodes: outcome["error-codes"],
    };
  } catch {
    return {
      success: false,
      errorCodes: ["turnstile-siteverify-network-error"],
    };
  }
}
