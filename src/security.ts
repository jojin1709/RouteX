/**
 * RouteX Security & SSRF Protection Engine
 * Implements strict host, IP (IPv4 & IPv6), scheme, and credential validation.
 */

const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "metadata.google.internal",
  "metadata",
  "instance-data",
  "169.254.169.254",
]);

const BLOCKED_SUFFIXES = [
  ".local",
  ".internal",
  ".localhost",
  ".onion",
  ".lan",
  ".home.arpa",
];

const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

export const MAX_URL_LENGTH = 4096;
export const MAX_HTML_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB processing ceiling to protect Free Worker memory
export const MAX_REDIRECT_HOPS = 5;

/**
 * Checks if a string is a standard dotted-quad IPv4 address (digits only, 0-255 per octet).
 * Explicitly rejects octal leading zeros, hexadecimal notation, or non-decimal characters.
 */
export function isIPv4(host: string): boolean {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return false;
  const parts = host.split(".");
  for (const part of parts) {
    if (part.length > 1 && part.startsWith("0")) return false; // Reject octal representation
    const n = Number(part);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

/**
 * Converts valid dotted-quad IPv4 address to unsigned 32-bit integer.
 */
export function ipv4ToInt(host: string): number | null {
  if (!isIPv4(host)) return null;
  const parts = host.split(".").map(Number);
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
}

/**
 * Checks if an integer IPv4 address falls within private, reserved, or special ranges.
 */
export function isPrivateIPv4(host: string): boolean {
  const n = ipv4ToInt(host);
  if (n === null) return false;

  const blockedRanges: Array<[number, number]> = [
    [0x00000000, 0x00ffffff], // 0.0.0.0/8 (Current network)
    [0x0a000000, 0x0affffff], // 10.0.0.0/8 (Private Class A)
    [0x64400000, 0x647fffff], // 100.64.0.0/10 (Shared CGNAT)
    [0x7f000000, 0x7fffffff], // 127.0.0.0/8 (Loopback)
    [0xa9fe0000, 0xa9feffff], // 169.254.0.0/16 (Link-local)
    [0xac100000, 0xac1fffff], // 172.16.0.0/12 (Private Class B)
    [0xc0000000, 0xc00000ff], // 192.0.0.0/24 (IETF Protocol Assignments)
    [0xc0000200, 0xc00002ff], // 192.0.2.0/24 (TEST-NET-1)
    [0xc0a80000, 0xc0a8ffff], // 192.168.0.0/16 (Private Class C)
    [0xc6120000, 0xc613ffff], // 198.18.0.0/15 (Benchmarking)
    [0xc6336400, 0xc63364ff], // 198.51.100.0/24 (TEST-NET-2)
    [0xcb007100, 0xcb0071ff], // 203.0.113.0/24 (TEST-NET-3)
    [0xe0000000, 0xefffffff], // 224.0.0.0/4 (Multicast)
    [0xf0000000, 0xffffffff], // 240.0.0.0/4 & 255.255.255.255 (Reserved/Broadcast)
  ];

  return blockedRanges.some(([start, end]) => n >= start && n <= end);
}

/**
 * Validates IPv6 literal addresses to block loopback, link-local, ULA, and IPv4-mapped private IPv6.
 */
export function isBlockedIPv6(rawHost: string): boolean {
  let host = rawHost.trim().toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) {
    host = host.slice(1, -1);
  }

  // Loopback and unspecified
  if (host === "::1" || host === "::" || host === "0:0:0:0:0:0:0:1" || host === "0:0:0:0:0:0:0:0") {
    return true;
  }

  // IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1)
  const v4MappedMatch = host.match(/^(?:::ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (v4MappedMatch) {
    return isPrivateIPv4(v4MappedMatch[1]);
  }

  // Unique Local Address (fc00::/7 - fc00:: through fdff::)
  if (/^f[cd][0-9a-f]{2}:/i.test(host)) return true;

  // Link-Local (fe80::/10 - fe80:: through febf::)
  if (/^fe[89ab][0-9a-f]:/i.test(host)) return true;

  // Deprecated Site-Local (fec0::/10)
  if (/^fe[c-f][0-9a-f]:/i.test(host)) return true;

  // Reject all raw IPv6 literal targets by default for SSRF safety
  if (host.includes(":")) return true;

  return false;
}

/**
 * Validates whether a hostname is safe to fetch through the gateway.
 */
export function isBlockedHostname(hostname: string): boolean {
  if (!hostname) return true;
  const host = hostname.toLowerCase().replace(/\.$/, "");

  if (BLOCKED_HOSTS.has(host)) return true;
  if (BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) return true;

  if (isIPv4(host)) {
    return isPrivateIPv4(host);
  }

  // Check IPv6 addresses
  if (host.includes(":") || (host.startsWith("[") && host.endsWith("]"))) {
    return isBlockedIPv6(host);
  }

  // Suspicious decimal integers passed as hostnames (e.g. 2130706433 for 127.0.0.1)
  if (/^\d+$/.test(host)) return true;

  // Suspicious hexadecimal numbers (e.g. 0x7f000001)
  if (/^0x[0-9a-f]+$/i.test(host)) return true;

  // Reject single-label hostnames without dots (internal/local network names e.g. 'intranet', 'corp')
  if (!host.includes(".")) return true;

  return false;
}

/**
 * Normalizes an incoming raw target string into a secure, validated URL object.
 * Rejects non-HTTP(S) schemes, credentials, oversized URLs, and SSRF destinations.
 */
export function normalizeTarget(raw: string): URL {
  if (!raw || typeof raw !== "string") {
    throw new Error("Missing or invalid target URL.");
  }

  const trimmed = raw.trim();
  if (trimmed.length > MAX_URL_LENGTH) {
    throw new Error(`Target URL exceeds maximum length of ${MAX_URL_LENGTH} characters.`);
  }

  let candidate = trimmed;
  // If no URI scheme is present, default to https://
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)) {
    if (candidate.startsWith("//")) {
      candidate = `https:${candidate}`;
    } else {
      candidate = `https://${candidate}`;
    }
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw new Error("Malformed URL syntax.");
  }

  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    throw new Error(`Unsupported protocol: ${url.protocol}. Only HTTP and HTTPS are permitted.`);
  }

  if (url.username || url.password) {
    throw new Error("Target URLs containing embedded credentials are not allowed.");
  }

  if (isBlockedHostname(url.hostname)) {
    throw new Error("Target destination is restricted by RouteX SSRF policy.");
  }

  // Clean trailing userinfo artifacts if any
  url.username = "";
  url.password = "";

  return url;
}
