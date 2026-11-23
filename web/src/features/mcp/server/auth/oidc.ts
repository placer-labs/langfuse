/**
 * OIDC bearer-token auth for the MCP endpoint: verifies the JWT against the
 * issuer's JWKS, maps its verified email to a Langfuse user, and authorizes
 * the requested project by the user's role assignments, the same policies a
 * web session carries. The project comes
 * from the tool call's `projectId` argument, then `X-Langfuse-Project-Id`,
 * then the user's first accessible project.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { type NextApiRequest } from "next";
import { prisma } from "@langfuse/shared/src/db";
import {
  CloudConfigSchema,
  ForbiddenError,
  UnauthorizedError,
} from "@langfuse/shared";
import { OrganizationId, ProjectId } from "@langfuse/shared/rbac";
import { env } from "@/src/env.mjs";
import {
  getOrganizationPlanServerSide,
  logger,
} from "@langfuse/shared/src/server";
import { type ServerContext } from "@/src/features/mcp/types";
import { getAuditRequestContext } from "@/src/features/audit-logs/server/getAuditRequestContext";
import { OIDC_API_KEY_ID_PREFIX } from "@/src/features/audit-logs/auditLog";
import { type PrincipalOrganization } from "@/src/features/auth/policy/types";
import { getPoliciesForUser } from "@/src/features/auth/policy/contextResolver";
import { authorize, rolesFor } from "@/src/features/rbac/authorize";
import { type Policy } from "@/src/features/rbac/types";

const ORG_PREFIX = "organization/";

const PROJECT_ID_HEADER = "x-langfuse-project-id";
export const PROJECT_ID_ARG = "projectId";

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

export type AccessibleProject = {
  id: string;
  name: string;
  orgId: string;
  /** Effective role ids in the project, e.g. "MEMBER", comma-joined if several. */
  role: string;
};

// The user's own role assignments, the same policy set web sessions use.
async function userPolicies(userId: string): Promise<Policy[][]> {
  return [await getPoliciesForUser(prisma, userId)];
}

function canReadProject(
  policies: Policy[][],
  orgId: string,
  projectId: string,
): boolean {
  return authorize(
    { policies },
    OrganizationId(orgId),
    "project:read",
    ProjectId(projectId),
  ).success;
}

export async function listAccessibleProjects(
  userId: string,
  policies?: Policy[][],
): Promise<AccessibleProject[]> {
  const sets = policies ?? (await userPolicies(userId));
  const orgIds = [
    ...new Set(
      sets
        .flat()
        .map((policy) => policy.tenantId.slice(ORG_PREFIX.length))
        .filter((orgId) => orgId !== "*"),
    ),
  ];
  if (orgIds.length === 0) return [];
  const projects = await prisma.project.findMany({
    where: { orgId: { in: orgIds }, deletedAt: null },
    select: { id: true, name: true, orgId: true },
  });
  return projects
    .filter((project) => canReadProject(sets, project.orgId, project.id))
    .map((project) => ({
      ...project,
      role: rolesFor(
        { policies: sets },
        OrganizationId(project.orgId),
        ProjectId(project.id),
      )
        .map((roleId) => roleId.replace(/^system\//, ""))
        .sort()
        .join(","),
    }))
    .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

// A single (non-batch) tools/call carries its project as a tool argument.
function requestedProjectId(req: NextApiRequest): string | undefined {
  const body = req.body as
    | { method?: unknown; params?: { arguments?: Record<string, unknown> } }
    | undefined;
  if (body && !Array.isArray(body) && body.method === "tools/call") {
    const arg = body.params?.arguments?.[PROJECT_ID_ARG];
    if (typeof arg === "string" && arg.length > 0) return arg;
  }
  const header = req.headers[PROJECT_ID_HEADER];
  return (Array.isArray(header) ? header[0] : header) || undefined;
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

  let projectId = requestedProjectId(req);

  const [user, requestedProject] = await Promise.all([
    prisma.user.findUnique({ where: { email }, select: { id: true } }),
    projectId
      ? prisma.project.findUnique({
          where: { id: projectId },
          select: { orgId: true, deletedAt: true },
        })
      : null,
  ]);

  if (!user) {
    logger.info("MCP OIDC auth: principal does not match a Langfuse user", {
      projectId,
    });
    throw new ForbiddenError(OIDC_ACCESS_DENIED);
  }

  const policies = await userPolicies(user.id);

  let project = requestedProject;
  let projectDefaulted = false;
  if (!projectId) {
    const [first, ...rest] = await listAccessibleProjects(user.id, policies);
    if (!first) {
      logger.info("MCP OIDC auth: user has no accessible projects", {
        userId: user.id,
      });
      throw new ForbiddenError(OIDC_ACCESS_DENIED);
    }
    projectId = first.id;
    project = { orgId: first.orgId, deletedAt: null };
    projectDefaulted = rest.length > 0;
  }

  const organization =
    project &&
    project.deletedAt === null &&
    canReadProject(policies, project.orgId, projectId)
      ? await prisma.organization.findUnique({
          where: { id: project.orgId },
          select: {
            id: true,
            createdAt: true,
            cloudConfig: true,
            cloudFreeTierUsageThresholdState: true,
            accessAuditLogEnabled: true,
          },
        })
      : null;

  if (!organization) {
    logger.info("MCP OIDC auth: user has no access to the requested project", {
      userId: user.id,
      projectId,
    });
    throw new ForbiddenError(OIDC_ACCESS_DENIED);
  }

  // Same usage-suspension gate as the BasicAuth path.
  const orgId = organization.id;
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
    auditRequest: getAuditRequestContext(req.headers, req.socket.remoteAddress),
    // The user's full policy set; MCP tools authorize against context.projectId.
    auth: {
      principal: {
        kind: "user",
        userId: user.id,
        organizations: [principalOrg],
      },
      policies,
    },
    authMethod: "oidc",
    projectDefaulted,
  };
}
