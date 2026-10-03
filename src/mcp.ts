/**
 * RouteX Model Context Protocol (MCP) Server
 * Implements standard JSON-RPC 2.0 MCP interface for AI agents (Cursor, Claude, Antigravity).
 */

import {
  extractMarkdown,
  lookupDns,
  lookupWhois,
  extractMetadata,
  checkSecurityHeaders,
  lookupArchive,
} from "./tools.ts";

export const MCP_TOOLS_SPEC = [
  {
    name: "routex_fetch_markdown",
    description: "Fetch any public webpage, strip boilerplate HTML/scripts, and return clean Markdown optimized for LLM prompts.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The HTTP or HTTPS URL to fetch." },
      },
      required: ["url"],
    },
  },
  {
    name: "routex_dns_lookup",
    description: "Query Cloudflare 1.1.1.1 DoH for DNS records (A, AAAA, MX, TXT, NS, CNAME) of a domain.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "The domain name to query (e.g. example.com)." },
      },
      required: ["domain"],
    },
  },
  {
    name: "routex_whois_lookup",
    description: "Lookup domain registration details via official ICANN RDAP (registrar, dates, nameservers).",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "The domain name to lookup (e.g. cloudflare.com)." },
      },
      required: ["domain"],
    },
  },
  {
    name: "routex_metadata",
    description: "Extract Open Graph, Twitter Cards, canonical link, and JSON-LD structured metadata from a webpage.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to extract metadata from." },
      },
      required: ["url"],
    },
  },
  {
    name: "routex_security_headers",
    description: "Audit security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy) of a target URL.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to audit." },
      },
      required: ["url"],
    },
  },
  {
    name: "routex_archive_lookup",
    description: "Check Wayback Machine (archive.org) availability and find closest historical snapshot of a URL.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The target URL to check in the archive." },
      },
      required: ["url"],
    },
  },
];

export async function handleMcpRequest(request: Request): Promise<Response> {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Content-Type": "application/json; charset=utf-8",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // GET /mcp provides endpoint metadata and configuration guide
  if (request.method === "GET") {
    return new Response(
      JSON.stringify(
        {
          name: "RouteX MCP Server",
          version: "1.0.0",
          protocolVersion: "2024-11-05",
          description: "Model Context Protocol JSON-RPC endpoint for AI assistants (Cursor, Claude, Antigravity).",
          endpoint: "/mcp",
          toolsAvailable: MCP_TOOLS_SPEC.length,
          tools: MCP_TOOLS_SPEC.map((t) => t.name),
          usage: {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            sampleRequest: {
              jsonrpc: "2.0",
              id: 1,
              method: "tools/call",
              params: {
                name: "routex_fetch_markdown",
                arguments: { url: "https://example.com" },
              },
            },
          },
        },
        null,
        2
      ),
      { status: 200, headers: corsHeaders }
    );
  }

  if (request.method !== "POST") {
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Method Not Allowed. Use POST or GET." } }),
      { status: 405, headers: corsHeaders }
    );
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error: Invalid JSON." } }),
      { status: 400, headers: corsHeaders }
    );
  }

  const { jsonrpc, id, method, params } = body;
  const requestId = id !== undefined ? id : null;

  if (jsonrpc !== "2.0") {
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: requestId, error: { code: -32600, message: "Invalid Request: jsonrpc must be '2.0'." } }),
      { status: 400, headers: corsHeaders }
    );
  }

  switch (method) {
    case "initialize":
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: requestId,
          result: {
            protocolVersion: "2024-11-05",
            capabilities: {
              tools: {},
            },
            serverInfo: {
              name: "routex-gateway",
              version: "1.0.0",
            },
          },
        }),
        { status: 200, headers: corsHeaders }
      );

    case "notifications/initialized":
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: requestId, result: {} }),
        { status: 200, headers: corsHeaders }
      );

    case "tools/list":
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: requestId,
          result: {
            tools: MCP_TOOLS_SPEC,
          },
        }),
        { status: 200, headers: corsHeaders }
      );

    case "tools/call": {
      const toolName = params?.name;
      const args = params?.arguments || {};

      try {
        let toolOutput: any;

        if (toolName === "routex_fetch_markdown") {
          const res = await extractMarkdown(args.url || "");
          toolOutput = res.markdown;
        } else if (toolName === "routex_dns_lookup") {
          toolOutput = await lookupDns(args.domain || "");
        } else if (toolName === "routex_whois_lookup") {
          toolOutput = await lookupWhois(args.domain || "");
        } else if (toolName === "routex_metadata") {
          toolOutput = await extractMetadata(args.url || "");
        } else if (toolName === "routex_security_headers") {
          toolOutput = await checkSecurityHeaders(args.url || "");
        } else if (toolName === "routex_archive_lookup") {
          toolOutput = await lookupArchive(args.url || "");
        } else {
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: requestId,
              error: { code: -32601, message: `Tool not found: ${toolName}` },
            }),
            { status: 404, headers: corsHeaders }
          );
        }

        const textContent = typeof toolOutput === "string" ? toolOutput : JSON.stringify(toolOutput, null, 2);

        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: requestId,
            result: {
              content: [
                {
                  type: "text",
                  text: textContent,
                },
              ],
            },
          }),
          { status: 200, headers: corsHeaders }
        );
      } catch (err) {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: requestId,
            result: {
              isError: true,
              content: [
                {
                  type: "text",
                  text: err instanceof Error ? err.message : String(err),
                },
              ],
            },
          }),
          { status: 200, headers: corsHeaders }
        );
      }
    }

    default:
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: requestId,
          error: { code: -32601, message: `Method not found: ${method}` },
        }),
        { status: 404, headers: corsHeaders }
      );
  }
}
