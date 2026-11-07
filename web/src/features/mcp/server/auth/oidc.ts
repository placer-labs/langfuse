/**
 * OIDC bearer-token auth for the MCP endpoint: verifies the JWT against the
 * issuer's JWKS, maps its verified email to a Langfuse user, and authorizes
 * the `X-Langfuse-Project-Id` project by the user's project or org role.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { type NextApiRequest } from "next";
import { prisma } from "@langfuse/shared/src/db";
import {
  CloudConfigSchema,
  ForbiddenError,
  UnauthorizedError,
  type Role,
} from "@langfuse/shared";
import {
  OrganizationId,
  ProjectId,
  SystemRoleId,
  systemRoleAccessRights,
} from "@langfuse/shared/rbac";
import { env } from "@/src/env.mjs";
import { logger } from "@langfuse/shared/src/server";
import { type ServerContext } from "@/src/features/mcp/types";
import { OIDC_API_KEY_ID_PREFIX } from "@/src/features/audit-logs/auditLog";
import { getOrganizationPlanServerSide } from "@/src/features/entitlements/server/getPlan";
import {
  type AuthorizationContext,
  type PrincipalOrganization,
} from "@/src/features/auth/policy/types";

const PROJECT_ID_HEADER = "x-langfuse-project-id";

type CachedJwks = {
  issuer: string;
  jwks: ReturnType<typeof createRemoteJWKSet>;
};

let cachedJwks: CachedJwks | null = null;

async function discoverJwksUri(issuer: string): Promise<string> {
  const url = `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) {
    throw new Error(`OIDC discovery failed: ${res.status} from ${url}`);
  }
  const { jwks_uri: jwksUri } = (await res.json()) as { jwks_uri?: unknown };
  if (typeof jwksUri !== "string" || jwksUri.length === 0) {
    throw new Error(`OIDC discovery document at ${url} has no jwks_uri`);
  }
  return jwksUri;
}

async function getJwks(issuer: string) {
  if (cachedJwks?.issuer === issuer) return cachedJwks.jwks;
  const jwksUri = env.MCP_AUTH_OIDC_JWKS_URI ?? (await discoverJwksUri(issuer));
  const jwks = createRemoteJWKSet(new URL(jwksUri));
  cachedJwks = { issuer, jwks };
  return jwks;
}

export function isJwt(token: string): boolean {
  return token.split(".").length === 3;
}

let warnedMisconfigured = false;

export function isOidcEnabled(): boolean {
  if (env.MCP_AUTH_OIDC_ENABLED !== "true") return false;
  const configured =
    Boolean(env.MCP_AUTH_OIDC_ISSUER) && Boolean(env.MCP_AUTH_OIDC_AUDIENCE);
  if (!configured && !warnedMisconfigured) {
    warnedMisconfigured = true;
    logger.warn(
      "MCP_AUTH_OIDC_ENABLED is true but MCP_AUTH_OIDC_ISSUER or MCP_AUTH_OIDC_AUDIENCE is unset; OIDC bearer auth is disabled",
    );
  }
  return configured;
}

export function extractBearerToken(
  authHeader: string | string[] | undefined,
): string | null {
  const value = Array.isArray(authHeader) ? authHeader[0] : authHeader;
  if (!value) return null;
  const match = /^Bearer\s+(.+)$/i.exec(value);
  return match ? match[1].trim() : null;
}

export async function verifyOidcToken(token: string): Promise<JWTPayload> {
  if (
    !isOidcEnabled() ||
    !env.MCP_AUTH_OIDC_ISSUER ||
    !env.MCP_AUTH_OIDC_AUDIENCE
  ) {
    throw new UnauthorizedError("OIDC authentication is not enabled");
  }

  const issuer = env.MCP_AUTH_OIDC_ISSUER;
  const jwks = await getJwks(issuer);

  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience: env.MCP_AUTH_OIDC_AUDIENCE,
    });
    return payload;
  } catch (err) {
    throw new UnauthorizedError(
      `Invalid OIDC token: ${err instanceof Error ? err.message : "unknown error"}`,
    );
  }
}

function extractVerifiedEmail(payload: JWTPayload): string {
  const value = payload.email;
  if (typeof value !== "string" || value.length === 0) {
    throw new UnauthorizedError("OIDC token missing required claim 'email'");
  }
  if (payload.email_verified !== true) {
    throw new UnauthorizedError("OIDC token email is not verified");
  }
  // Web sign-in stores emails lowercased.
  const email = value.toLowerCase();
  const allowedDomains = env.MCP_AUTH_OIDC_ALLOWED_EMAIL_DOMAINS ?? [];
  const domain = email.slice(email.lastIndexOf("@") + 1);
  if (allowedDomains.length > 0 && !allowedDomains.includes(domain)) {
    throw new UnauthorizedError("OIDC token email domain is not allowed");
  }
  return email;
}

// One message for unknown users and missing access, so a token holder cannot
// probe which users exist.
const OIDC_ACCESS_DENIED = "OIDC authentication failed";

// Binds the user's role to the requested project only.
function userAuthorizationContext(
  userId: string,
  role: Role,
  org: PrincipalOrganization,
  projectId: string,
): AuthorizationContext {
  const roleId = SystemRoleId(role);
  const tenantId = OrganizationId(org.orgId);
  return {
    principal: { kind: "user", userId, organizations: [org] },
    policies: systemRoleAccessRights[role].policies
      .filter((policy) => policy.resourceKind === "project")
      .map((policy) => ({
        id: `${roleId}:${policy.resourceKind}`,
        roleId,
        tenantId,
        effect: policy.effect,
        actions: policy.actions,
        resources: [ProjectId(projectId)],
      })),
  };
}

export async function resolveOidcContextFromRequest(
  req: NextApiRequest,
  token: string,
): Promise<ServerContext> {
  // Legacy and shadow modes fall back to the API-key decision, ignoring the role.
  if (env.API_AUTH_MIGRATION !== "enforce") {
    throw new UnauthorizedError(
      "OIDC authentication requires API_AUTH_MIGRATION=enforce",
    );
  }

  const payload = await verifyOidcToken(token);
  const email = extractVerifiedEmail(payload);

  const projectHeader = req.headers[PROJECT_ID_HEADER];
  const projectId = Array.isArray(projectHeader)
    ? projectHeader[0]
    : projectHeader;
  if (!projectId) {
    throw new UnauthorizedError(
      `OIDC authentication requires the '${PROJECT_ID_HEADER}' request header`,
    );
  }

  const [user, project] = await Promise.all([
    prisma.user.findUnique({ where: { email }, select: { id: true } }),
    prisma.project.findUnique({
      where: { id: projectId },
      select: { orgId: true, deletedAt: true },
    }),
  ]);

  if (!user) {
    logger.info("MCP OIDC auth: principal does not match a Langfuse user", {
      projectId,
    });
    throw new ForbiddenError(OIDC_ACCESS_DENIED);
  }

  // A project role overrides the org role, as in the web UI.
  const orgMembership = project
    ? await prisma.organizationMembership.findUnique({
        where: { orgId_userId: { orgId: project.orgId, userId: user.id } },
        select: {
          orgId: true,
          role: true,
          ProjectMemberships: {
            where: { projectId },
            select: { role: true },
          },
          organization: {
            select: {
              createdAt: true,
              cloudConfig: true,
              cloudFreeTierUsageThresholdState: true,
              accessAuditLogEnabled: true,
            },
          },
        },
      })
    : null;
  const role = orgMembership
    ? (orgMembership.ProjectMemberships[0]?.role ?? orgMembership.role)
    : undefined;

  if (
    !project ||
    project.deletedAt !== null ||
    !orgMembership ||
    !role ||
    role === "NONE" ||
    role === "AI_GATEWAY"
  ) {
    logger.info("MCP OIDC auth: user has no access to the requested project", {
      userId: user.id,
      projectId,
    });
    throw new ForbiddenError(OIDC_ACCESS_DENIED);
  }

  // Same usage-suspension gate as the BasicAuth path.
  const { orgId, organization } = orgMembership;
  if (organization.cloudFreeTierUsageThresholdState === "BLOCKED") {
    throw new ForbiddenError(
      "Access suspended: Usage threshold exceeded. Please upgrade your plan.",
    );
  }

  const cloudConfig = organization.cloudConfig
    ? CloudConfigSchema.parse(organization.cloudConfig)
    : undefined;
  const principalOrg: PrincipalOrganization = {
    orgId,
    organizationCreatedAt: organization.createdAt.toISOString(),
    plan: getOrganizationPlanServerSide(cloudConfig),
    rateLimitOverrides: cloudConfig?.rateLimitOverrides ?? [],
    projectIds: [projectId],
    isIngestionSuspended: false,
    accessAuditLogEnabled: organization.accessAuditLogEnabled,
  };

  logger.debug("MCP request authenticated via OIDC", {
    projectId,
    orgId,
    userId: user.id,
    role,
  });

  return {
    projectId,
    orgId,
    userId: user.id,
    apiKeyId: `${OIDC_API_KEY_ID_PREFIX}${user.id}`,
    accessLevel: "project",
    publicKey: "oidc",
    plan: principalOrg.plan,
    rateLimitOverrides: principalOrg.rateLimitOverrides,
    accessAuditLogEnabled: organization.accessAuditLogEnabled,
    userAgent: req.headers["user-agent"],
    auth: userAuthorizationContext(user.id, role, principalOrg, projectId),
    authMethod: "oidc",
  };
}
