export interface Env {
  ASSETS: Fetcher;
  BROWSER?: Fetcher; // Optional Cloudflare Browser Rendering binding
  TURNSTILE_SECRET_KEY?: string; // Optional Cloudflare Turnstile secret key
  TURNSTILE_SITE_KEY?: string; // Optional Cloudflare Turnstile site key
  DAYTONA_API_KEY?: string; // Optional Daytona API key secret
  DAYTONA_SERVER_URL?: string; // Optional Daytona Server URL
  DAYTONA_TARGET?: string; // Optional Daytona target identifier
}

export type CompatibilityRating = "Full" | "Partial" | "Limited";

export interface DiagnosticProbe {
  name: string;
  category: string;
  status: "pass" | "warn" | "fail";
  message: string;
  details?: Record<string, unknown>;
}

export interface DiagnosticReport {
  target: string;
  timestamp: string;
  compatibility: CompatibilityRating;
  summary: string;
  probes: DiagnosticProbe[];
  recommendations: string[];
}
