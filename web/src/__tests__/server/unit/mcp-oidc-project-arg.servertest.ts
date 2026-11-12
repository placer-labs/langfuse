import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { defineTool } from "@/src/features/mcp/core/define-tool";
import { createMcpServer } from "@/src/features/mcp/server/mcpServer";
import { toolRegistry } from "@/src/features/mcp/server/registry";
import { __dangerouslySkipAuthz } from "@/src/features/public-api/server/enforceAuth";
import type { ServerContext } from "@/src/features/mcp/types";

vi.mock("@/src/features/mcp/server/registry", () => ({
  toolRegistry: { getEnabledTool: vi.fn(), getToolDefinitions: vi.fn() },
}));

const baseContext: ServerContext = {
  projectId: "project-1",
  orgId: "org-1",
  userId: "user-1",
  apiKeyId: "oidc:user-1",
  accessLevel: "project",
  publicKey: "oidc",
  plan: "oss",
  rateLimitOverrides: [],
  accessAuditLogEnabled: false,
  authMethod: "oidc",
};

const received = vi.fn();
const schema = z.object({ name: z.string() }).strict();
const [echoDefinition, echoHandler] = defineTool({
  name: "echo",
  description: "test",
  action: __dangerouslySkipAuthz,
  baseSchema: schema,
  inputSchema: schema,
  handler: async (input) => {
    received(input);
    return "ok";
  },
});
const [listProjectsDefinition, listProjectsHandler] = defineTool({
  name: "listProjects",
  description: "test",
  action: __dangerouslySkipAuthz,
  baseSchema: z.object({}),
  inputSchema: z.object({}),
  handler: async () => "projects",
});
const tools = [
  { definition: echoDefinition, handler: echoHandler },
  { definition: listProjectsDefinition, handler: listProjectsHandler },
];

async function withClient(
  context: ServerContext,
  fn: (client: Client) => Promise<void>,
) {
  vi.mocked(toolRegistry.getToolDefinitions).mockResolvedValue(
    tools.map((t) => t.definition),
  );
  vi.mocked(toolRegistry.getEnabledTool).mockImplementation(async (name) =>
    tools.find((t) => t.definition.name === name),
  );
  const server = createMcpServer(context);
  const client = new Client({ name: "test", version: "1.0.0" });
  const [serverTransport, clientTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    await fn(client);
  } finally {
    await client.close();
    await server.close();
  }
}

describe("MCP OIDC projectId argument", () => {
  it("advertises projectId on every tool but listProjects for OIDC only", async () => {
    await withClient(baseContext, async (client) => {
      const { tools: listed } = await client.listTools();
      const props = (name: string) =>
        Object.keys(
          listed.find((t) => t.name === name)?.inputSchema.properties ?? {},
        );
      expect(props("echo")).toEqual(["name", "projectId"]);
      expect(props("listProjects")).toEqual([]);
    });
    await withClient(
      { ...baseContext, authMethod: "api-key" },
      async (client) => {
        const { tools: listed } = await client.listTools();
        expect(
          listed.find((t) => t.name === "echo")?.inputSchema.properties,
        ).not.toHaveProperty("projectId");
      },
    );
  });

  it("strips projectId before the tool validates its input", async () => {
    received.mockClear();
    await withClient(baseContext, async (client) => {
      const result = await client.callTool({
        name: "echo",
        arguments: { name: "a", projectId: "project-1" },
      });
      expect(result.isError).toBeUndefined();
      expect(received).toHaveBeenCalledWith({ name: "a" });
    });
  });

  it("asks for projectId when the user has several projects", async () => {
    received.mockClear();
    await withClient(
      { ...baseContext, projectDefaulted: true },
      async (client) => {
        const result = await client.callTool({
          name: "echo",
          arguments: { name: "a" },
        });
        expect(result.isError).toBe(true);
        expect(result.content).toEqual([
          { type: "text", text: expect.stringContaining("listProjects") },
        ]);
        expect(received).not.toHaveBeenCalled();
        const projects = await client.callTool({
          name: "listProjects",
          arguments: {},
        });
        expect(projects.content).toEqual([{ type: "text", text: "projects" }]);
      },
    );
  });

  it("rejects a projectId other than the one the request was authorized for", async () => {
    await withClient(baseContext, async (client) => {
      await expect(
        client.callTool({
          name: "echo",
          arguments: { name: "a", projectId: "project-2" },
        }),
      ).rejects.toMatchObject({ code: ErrorCode.InvalidParams });
    });
  });
});
