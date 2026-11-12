/**
 * Unit tests for MCP OIDC bearer-token verification.
 *
 * These tests exercise the JWT verification + claim extraction logic in
 * isolation: they generate keys and sign tokens in-memory with `jose`, then
 * stub `createRemoteJWKSet` so the verifier resolves the local JWK without a
 * network round-trip. DB-backed user/membership resolution is covered by the
 * dispatcher integration test surface, not here.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import type * as Jose from "jose";
import type { NextApiRequest } from "next";

const ISSUER = "https://idp.example.com";
const AUDIENCE = "langfuse-mcp";

vi.mock("@/src/env.mjs", () => ({
  env: {
    MCP_AUTH_OIDC_ENABLED: "true",
    MCP_AUTH_OIDC_ISSUER: ISSUER,
    MCP_AUTH_OIDC_AUDIENCE: AUDIENCE,
    MCP_AUTH_OIDC_JWKS_URI: `${ISSUER}/.well-known/jwks.json`,
    API_AUTH_MIGRATION: "enforce",
  },
}));

vi.mock("@langfuse/shared/src/db", () => ({
  prisma: {
    user: { findUnique: vi.fn() },
    project: { findUnique: vi.fn() },
    organizationMembership: { findUnique: vi.fn(), findMany: vi.fn() },
  },
}));

// Stub out the heavyweight server module so importing the OIDC module under
// test does not trigger env validation for Clickhouse/S3 etc. The test
// teardown re-imports redis/logger/ClickHouseClientManager from this module,
// so provide minimal no-op shapes for those.
vi.mock("@langfuse/shared/src/server", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
  redis: { status: "end", disconnect: vi.fn() },
  ClickHouseClientManager: {
    getInstance: () => ({
      closeAllConnections: vi.fn().mockResolvedValue(undefined),
    }),
  },
}));

vi.mock("jose", async () => {
  const actual = await vi.importActual<typeof Jose>("jose");
  return {
    ...actual,
    createRemoteJWKSet: vi.fn(),
  };
});

// jose's generateKeyPair returns KeyLike (KeyObject | CryptoKey), not a bare
// CryptoKey; derive the exact type so this stays correct across jose versions.
type PrivateKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

type Keys = {
  privateKey: PrivateKey;
  publicJwk: Awaited<ReturnType<typeof exportJWK>>;
};

async function makeKeys(): Promise<Keys> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", {
    extractable: true,
  });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.alg = "RS256";
  publicJwk.kid = "test-kid";
  return { privateKey, publicJwk };
}

async function signToken(
  privateKey: PrivateKey,
  payload: Record<string, unknown>,
  opts: { issuer?: string; audience?: string; expiresIn?: string } = {},
) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
    .setIssuedAt()
    .setIssuer(opts.issuer ?? ISSUER)
    .setAudience(opts.audience ?? AUDIENCE)
    .setExpirationTime(opts.expiresIn ?? "5m")
    .sign(privateKey);
}

describe("MCP OIDC auth — token verification", () => {
  let keys: Keys;

  beforeEach(async () => {
    keys = await makeKeys();
    const jose = await import("jose");
    const actual = await vi.importActual<typeof Jose>("jose");
    // Resolve every kid to our test public key so jwtVerify succeeds.
    vi.mocked(jose.createRemoteJWKSet).mockReturnValue(
      // jose's JWKSet is a function: (header) => Promise<KeyLike>.
      (async () => actual.importJWK(keys.publicJwk, "RS256")) as never,
    );
  });

  afterEach(() => {
    vi.resetModules();
  });

  it("verifies a valid token and returns the payload", async () => {
    const { verifyOidcToken } =
      await import("@/src/features/mcp/server/auth/oidc");
    const token = await signToken(keys.privateKey, {
      email: "user@example.com",
    });
    const payload = await verifyOidcToken(token);
    expect(payload.email).toBe("user@example.com");
    expect(payload.iss).toBe(ISSUER);
    expect(payload.aud).toBe(AUDIENCE);
  });

  it("rejects a token signed by a different issuer", async () => {
    const { verifyOidcToken } =
      await import("@/src/features/mcp/server/auth/oidc");
    const token = await signToken(
      keys.privateKey,
      { email: "u@x.com" },
      {
        issuer: "https://attacker.example.com",
      },
    );
    await expect(verifyOidcToken(token)).rejects.toThrow(/Invalid OIDC token/);
  });

  it("rejects a token whose audience does not match", async () => {
    const { verifyOidcToken } =
      await import("@/src/features/mcp/server/auth/oidc");
    const token = await signToken(
      keys.privateKey,
      { email: "u@x.com" },
      {
        audience: "some-other-app",
      },
    );
    await expect(verifyOidcToken(token)).rejects.toThrow(/Invalid OIDC token/);
  });

  it("rejects an expired token", async () => {
    const { verifyOidcToken } =
      await import("@/src/features/mcp/server/auth/oidc");
    const token = await new SignJWT({ email: "u@x.com" })
      .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(keys.privateKey);
    await expect(verifyOidcToken(token)).rejects.toThrow(/Invalid OIDC token/);
  });
});

describe("MCP OIDC auth — bearer-token extraction & enablement", () => {
  it("extracts the token from `Bearer <jwt>` (case-insensitive)", async () => {
    const { extractBearerToken } =
      await import("@/src/features/mcp/server/auth/oidc");
    expect(extractBearerToken("Bearer abc.def.ghi")).toBe("abc.def.ghi");
    expect(extractBearerToken("bearer abc.def.ghi")).toBe("abc.def.ghi");
  });

  it("returns null for a Basic auth header", async () => {
    const { extractBearerToken } =
      await import("@/src/features/mcp/server/auth/oidc");
    expect(extractBearerToken("Basic abc==")).toBeNull();
  });

  it("returns null when the header is absent", async () => {
    const { extractBearerToken } =
      await import("@/src/features/mcp/server/auth/oidc");
    expect(extractBearerToken(undefined)).toBeNull();
  });

  it("recognises only JWT-shaped bearer tokens", async () => {
    const { isJwt } = await import("@/src/features/mcp/server/auth/oidc");
    expect(isJwt("aaa.bbb.ccc")).toBe(true);
    expect(isJwt("sk-lf-1234")).toBe(false);
  });

  it("discovers the JWKS URI from the issuer when none is configured", async () => {
    const { env } = await import("@/src/env.mjs");
    const jose = await import("jose");
    const jwksUri = `${ISSUER}/protocol/openid-connect/certs`;
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(JSON.stringify({ jwks_uri: jwksUri }), { status: 200 }),
      );
    const configured = env.MCP_AUTH_OIDC_JWKS_URI;
    (env as Record<string, unknown>).MCP_AUTH_OIDC_JWKS_URI = undefined;
    vi.mocked(jose.createRemoteJWKSet).mockReturnValue((async () => {
      throw new Error("no keys");
    }) as never);
    try {
      const { verifyOidcToken } =
        await import("@/src/features/mcp/server/auth/oidc");
      await expect(verifyOidcToken("a.b.c")).rejects.toThrow();
      expect(fetchMock).toHaveBeenCalledWith(
        `${ISSUER}/.well-known/openid-configuration`,
        expect.anything(),
      );
      expect(jose.createRemoteJWKSet).toHaveBeenCalledWith(new URL(jwksUri));
    } finally {
      (env as Record<string, unknown>).MCP_AUTH_OIDC_JWKS_URI = configured;
      fetchMock.mockRestore();
      vi.resetModules();
    }
  });

  it("reports OIDC enabled when env is configured", async () => {
    const { isOidcEnabled } =
      await import("@/src/features/mcp/server/auth/oidc");
    expect(isOidcEnabled()).toBe(true);
  });

  it("reports OIDC disabled when no audience is configured", async () => {
    const { env } = await import("@/src/env.mjs");
    const { isOidcEnabled } =
      await import("@/src/features/mcp/server/auth/oidc");
    const audience = env.MCP_AUTH_OIDC_AUDIENCE;
    (env as Record<string, unknown>).MCP_AUTH_OIDC_AUDIENCE = undefined;
    try {
      expect(isOidcEnabled()).toBe(false);
    } finally {
      (env as Record<string, unknown>).MCP_AUTH_OIDC_AUDIENCE = audience;
    }
  });
});

describe("MCP OIDC auth — user and project resolution", () => {
  const PROJECT_ID = "prj_1";
  const ORG_ID = "org_1";
  let keys: Keys;

  const orgMembership = (
    overrides: { orgRole?: string; projectRole?: string } = {},
  ) => ({
    orgId: ORG_ID,
    role: overrides.orgRole ?? "VIEWER",
    ProjectMemberships: overrides.projectRole
      ? [{ role: overrides.projectRole }]
      : [],
    organization: {
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      cloudConfig: null,
      cloudFreeTierUsageThresholdState: null,
      accessAuditLogEnabled: true,
    },
  });

  // Shaped like an access token forwarded by an MCP gateway: no `aud`,
  // verified email, groups claim.
  const gatewayToken = (claims: Record<string, unknown> = {}) =>
    signToken(keys.privateKey, {
      email: "user@example.com",
      email_verified: true,
      groups: ["R&D"],
      ...claims,
    });

  const request = (headers: Record<string, string>) =>
    ({ headers }) as unknown as NextApiRequest;

  beforeEach(async () => {
    vi.clearAllMocks();
    keys = await makeKeys();
    const jose = await import("jose");
    const actual = await vi.importActual<typeof Jose>("jose");
    vi.mocked(jose.createRemoteJWKSet).mockReturnValue((async () =>
      actual.importJWK(keys.publicJwk, "RS256")) as never);
    const { prisma } = await import("@langfuse/shared/src/db");
    vi.mocked(prisma.user.findUnique).mockResolvedValue({
      id: "user_1",
    } as never);
    vi.mocked(prisma.project.findUnique).mockResolvedValue({
      orgId: ORG_ID,
      deletedAt: null,
    } as never);
    vi.mocked(prisma.organizationMembership.findUnique).mockResolvedValue(
      orgMembership() as never,
    );
  });

  afterEach(() => {
    vi.resetModules();
  });

  it("resolves a project-scoped user context the policy core enforces", async () => {
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    const { shadowAuthorize } =
      await import("@/src/features/public-api/server/shadowAuth");
    const context = await resolveOidcContextFromRequest(
      request({ "x-langfuse-project-id": PROJECT_ID }),
      await gatewayToken(),
    );

    expect(context).toMatchObject({
      projectId: PROJECT_ID,
      orgId: ORG_ID,
      userId: "user_1",
      authMethod: "oidc",
      accessAuditLogEnabled: true,
    });
    expect(context.auth?.principal).toMatchObject({
      kind: "user",
      userId: "user_1",
    });

    const check = (action: string, projectId = PROJECT_ID) =>
      shadowAuthorize({
        ctx: context.auth,
        action: action as never,
        resource: { projectId },
        legacyDecision: {
          success: true,
          scope: { accessLevel: "project" },
        },
      }).success;
    expect(check("prompts:read")).toBe(true);
    expect(check("prompts:CUD")).toBe(false);
    expect(check("prompts:read", "prj_other")).toBe(false);
  });

  it.each([
    ["an org role", { orgRole: "MEMBER" }, "write"],
    ["a read-only org role", { orgRole: "VIEWER" }, "read"],
    [
      "a project role over the org role",
      { orgRole: "VIEWER", projectRole: "MEMBER" },
      "write",
    ],
    [
      "a project role of NONE",
      { orgRole: "MEMBER", projectRole: "NONE" },
      "denied",
    ],
    ["an AI_GATEWAY-only org role", { orgRole: "AI_GATEWAY" }, "denied"],
  ] as const)("resolves access from %s", async (_label, roles, expected) => {
    const { prisma } = await import("@langfuse/shared/src/db");
    vi.mocked(prisma.organizationMembership.findUnique).mockResolvedValue(
      orgMembership(roles) as never,
    );
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    const { shadowAuthorize } =
      await import("@/src/features/public-api/server/shadowAuth");
    const result = resolveOidcContextFromRequest(
      request({ "x-langfuse-project-id": PROJECT_ID }),
      await gatewayToken(),
    );
    if (expected === "denied") {
      await expect(result).rejects.toThrow("OIDC authentication failed");
      return;
    }
    const context = await result;
    const can = (action: string) =>
      shadowAuthorize({
        ctx: context.auth,
        action: action as never,
        resource: { projectId: PROJECT_ID },
        legacyDecision: { success: true, scope: { accessLevel: "project" } },
      }).success;
    expect(can("prompts:read")).toBe(true);
    expect(can("prompts:CUD")).toBe(expected === "write");
  });

  it("rejects an email with no Langfuse user", async () => {
    const { prisma } = await import("@langfuse/shared/src/db");
    vi.mocked(prisma.user.findUnique).mockResolvedValue(null as never);
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    await expect(
      resolveOidcContextFromRequest(
        request({ "x-langfuse-project-id": PROJECT_ID }),
        await gatewayToken(),
      ),
    ).rejects.toThrow("OIDC authentication failed");
  });

  it("looks the user up by the lowercased email", async () => {
    const { prisma } = await import("@langfuse/shared/src/db");
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    await resolveOidcContextFromRequest(
      request({ "x-langfuse-project-id": PROJECT_ID }),
      await gatewayToken({ email: "User@Example.COM" }),
    );
    expect(prisma.user.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { email: "user@example.com" } }),
    );
  });

  it("rejects a usage-suspended organization", async () => {
    const { prisma } = await import("@langfuse/shared/src/db");
    const blocked = orgMembership({ orgRole: "MEMBER" });
    blocked.organization.cloudFreeTierUsageThresholdState = "BLOCKED" as never;
    vi.mocked(prisma.organizationMembership.findUnique).mockResolvedValue(
      blocked as never,
    );
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    await expect(
      resolveOidcContextFromRequest(
        request({ "x-langfuse-project-id": PROJECT_ID }),
        await gatewayToken(),
      ),
    ).rejects.toThrow(/Access suspended/);
  });

  it("rejects a user outside the project's organization", async () => {
    const { prisma } = await import("@langfuse/shared/src/db");
    vi.mocked(prisma.organizationMembership.findUnique).mockResolvedValue(
      null as never,
    );
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    await expect(
      resolveOidcContextFromRequest(
        request({ "x-langfuse-project-id": PROJECT_ID }),
        await gatewayToken(),
      ),
    ).rejects.toThrow("OIDC authentication failed");
  });

  it("rejects a soft-deleted project", async () => {
    const { prisma } = await import("@langfuse/shared/src/db");
    vi.mocked(prisma.project.findUnique).mockResolvedValue({
      orgId: ORG_ID,
      deletedAt: new Date(),
    } as never);
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    await expect(
      resolveOidcContextFromRequest(
        request({ "x-langfuse-project-id": PROJECT_ID }),
        await gatewayToken(),
      ),
    ).rejects.toThrow("OIDC authentication failed");
  });

  it("rejects an unverified email", async () => {
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    await expect(
      resolveOidcContextFromRequest(
        request({ "x-langfuse-project-id": PROJECT_ID }),
        await gatewayToken({ email_verified: false }),
      ),
    ).rejects.toThrow(/not verified/);
  });

  it.each([
    ["user@example.com", true],
    ["user@EXAMPLE.com", true],
    ["user@attacker.test", false],
    ["user@example.com.attacker.test", false],
  ])(
    "restricts %s to the allowed email domains (allowed: %s)",
    async (email, allowed) => {
      const { env } = await import("@/src/env.mjs");
      const { resolveOidcContextFromRequest } =
        await import("@/src/features/mcp/server/auth/oidc");
      (env as Record<string, unknown>).MCP_AUTH_OIDC_ALLOWED_EMAIL_DOMAINS = [
        "example.com",
      ];
      try {
        const result = resolveOidcContextFromRequest(
          request({ "x-langfuse-project-id": PROJECT_ID }),
          await gatewayToken({ email }),
        );
        if (allowed) {
          await expect(result).resolves.toMatchObject({ userId: "user_1" });
        } else {
          await expect(result).rejects.toThrow(/domain is not allowed/);
        }
      } finally {
        (env as Record<string, unknown>).MCP_AUTH_OIDC_ALLOWED_EMAIL_DOMAINS =
          undefined;
      }
    },
  );

  const memberships = (
    orgs: {
      orgId?: string;
      role: string;
      projects: string[];
      projectRoles?: Record<string, string>;
    }[],
  ) =>
    orgs.map(({ orgId = ORG_ID, role, projects, projectRoles = {} }) => ({
      orgId,
      role,
      ProjectMemberships: Object.entries(projectRoles).map(
        ([projectId, projectRole]) => ({ projectId, role: projectRole }),
      ),
      organization: {
        projects: projects.map((name) => ({ id: `prj_${name}`, name })),
      },
    }));

  const toolCall = (args: Record<string, unknown>) =>
    ({
      headers: {},
      body: {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "listPrompts", arguments: args },
      },
    }) as unknown as NextApiRequest;

  it("takes the project from the tool call's projectId over the header", async () => {
    const { prisma } = await import("@langfuse/shared/src/db");
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    const req = toolCall({ projectId: "prj_arg" });
    req.headers["x-langfuse-project-id"] = PROJECT_ID;
    const context = await resolveOidcContextFromRequest(
      req,
      await gatewayToken(),
    );
    expect(context.projectId).toBe("prj_arg");
    expect(context.projectDefaulted).toBe(false);
    expect(prisma.project.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: "prj_arg" } }),
    );
  });

  it.each([
    ["one accessible project", [["alpha"]], "prj_alpha", false],
    [
      "several, picking the first by name",
      [["zulu", "bravo"]],
      "prj_bravo",
      true,
    ],
  ] as const)(
    "defaults the project with %s",
    async (_label, [projects], expectedProject, defaulted) => {
      const { prisma } = await import("@langfuse/shared/src/db");
      vi.mocked(prisma.organizationMembership.findMany).mockResolvedValue(
        memberships([{ role: "VIEWER", projects: [...projects] }]) as never,
      );
      const { resolveOidcContextFromRequest } =
        await import("@/src/features/mcp/server/auth/oidc");
      const context = await resolveOidcContextFromRequest(
        request({}),
        await gatewayToken(),
      );
      expect(context.projectId).toBe(expectedProject);
      expect(context.projectDefaulted).toBe(defaulted);
      expect(prisma.project.findUnique).not.toHaveBeenCalled();
    },
  );

  it("denies a user with no accessible projects", async () => {
    const { prisma } = await import("@langfuse/shared/src/db");
    vi.mocked(prisma.organizationMembership.findMany).mockResolvedValue(
      memberships([
        { role: "MEMBER", projects: ["a"], projectRoles: { prj_a: "NONE" } },
        { orgId: "org_2", role: "AI_GATEWAY", projects: ["b"] },
      ]) as never,
    );
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    await expect(
      resolveOidcContextFromRequest(request({}), await gatewayToken()),
    ).rejects.toThrow("OIDC authentication failed");
  });

  it("lists projects across orgs with the effective role", async () => {
    const { prisma } = await import("@langfuse/shared/src/db");
    vi.mocked(prisma.organizationMembership.findMany).mockResolvedValue(
      memberships([
        {
          role: "VIEWER",
          projects: ["b", "a", "hidden"],
          projectRoles: { prj_a: "ADMIN", prj_hidden: "NONE" },
        },
        { orgId: "org_2", role: "MEMBER", projects: ["c"] },
      ]) as never,
    );
    const { listAccessibleProjects } =
      await import("@/src/features/mcp/server/auth/oidc");
    expect(await listAccessibleProjects("user_1")).toEqual([
      { id: "prj_a", name: "a", orgId: ORG_ID, role: "ADMIN" },
      { id: "prj_b", name: "b", orgId: ORG_ID, role: "VIEWER" },
      { id: "prj_c", name: "c", orgId: "org_2", role: "MEMBER" },
    ]);
  });

  it("refuses OIDC outside enforce mode", async () => {
    const { env } = await import("@/src/env.mjs");
    const { resolveOidcContextFromRequest } =
      await import("@/src/features/mcp/server/auth/oidc");
    (env as Record<string, unknown>).API_AUTH_MIGRATION = "legacy";
    try {
      await expect(
        resolveOidcContextFromRequest(
          request({ "x-langfuse-project-id": PROJECT_ID }),
          await gatewayToken(),
        ),
      ).rejects.toThrow(/API_AUTH_MIGRATION=enforce/);
    } finally {
      (env as Record<string, unknown>).API_AUTH_MIGRATION = "enforce";
    }
  });
});
