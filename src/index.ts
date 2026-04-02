import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { VaultClient } from "./vault.js";

const client = new VaultClient();

const server = new McpServer({
  name: "mcp-vault",
  version: "1.0.0",
});

server.tool(
  "health",
  "Check Vault server health status, version, and seal state.",
  {},
  async () => {
    try {
      const result = await client.getHealth();
      return { content: [{ type: "text", text: result }] };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Error: ${msg}` }], isError: true };
    }
  },
);

server.tool(
  "list_mounts",
  "List all secret engines mounted in Vault.",
  {},
  async () => {
    try {
      const result = await client.listMounts();
      return { content: [{ type: "text", text: result }] };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Error: ${msg}` }], isError: true };
    }
  },
);

server.tool(
  "list_secrets",
  "List secret keys/folders at a path. Use empty path for the engine root.",
  {
    path: z.string().default("").describe("Path to list (e.g., 'shared', 'shared/jwt'). Empty for engine root."),
    engine: z.string().default("ci").describe("Secrets engine mount (default: 'ci')"),
  },
  async ({ path, engine }) => {
    try {
      const result = await client.listSecrets(path, engine);
      return { content: [{ type: "text", text: result }] };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Error: ${msg}` }], isError: true };
    }
  },
);

server.tool(
  "read_secret",
  "Read a secret's key-value pairs from Vault (KV v2). Returns all keys and their values.",
  {
    path: z.string().describe("Secret path (e.g., 'shared/jwt', 'shared/globaldbconn')"),
    engine: z.string().default("ci").describe("Secrets engine mount (default: 'ci')"),
    version: z.number().optional().describe("Specific version to read (omit for latest)"),
  },
  async ({ path, engine, version }) => {
    try {
      const result = await client.readSecret(path, engine, version);
      return { content: [{ type: "text", text: result }] };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Error: ${msg}` }], isError: true };
    }
  },
);

server.tool(
  "write_secret",
  "Write or update a secret in Vault (KV v2). Creates a new version.",
  {
    path: z.string().describe("Secret path (e.g., 'shared/frontend')"),
    data: z.record(z.string()).describe("Key-value pairs to write"),
    engine: z.string().default("ci").describe("Secrets engine mount (default: 'ci')"),
  },
  async ({ path, data, engine }) => {
    try {
      const result = await client.writeSecret(path, data, engine);
      return { content: [{ type: "text", text: result }] };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Error: ${msg}` }], isError: true };
    }
  },
);

server.tool(
  "delete_secret",
  "Delete a secret or specific versions from Vault (KV v2).",
  {
    path: z.string().describe("Secret path to delete"),
    engine: z.string().default("ci").describe("Secrets engine mount (default: 'ci')"),
    versions: z.array(z.number()).optional().describe("Specific versions to soft-delete (omit to delete latest)"),
  },
  async ({ path, engine, versions }) => {
    try {
      const result = await client.deleteSecret(path, engine, versions);
      return { content: [{ type: "text", text: result }] };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Error: ${msg}` }], isError: true };
    }
  },
);

server.tool(
  "secret_metadata",
  "Get metadata for a secret including version history.",
  {
    path: z.string().describe("Secret path (e.g., 'shared/jwt')"),
    engine: z.string().default("ci").describe("Secrets engine mount (default: 'ci')"),
  },
  async ({ path, engine }) => {
    try {
      const result = await client.getSecretMetadata(path, engine);
      return { content: [{ type: "text", text: result }] };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Error: ${msg}` }], isError: true };
    }
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
