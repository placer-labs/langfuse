/** Authenticates an MCP request by OIDC bearer token when enabled, else by BasicAuth API key. */

import { type NextApiRequest } from "next";
import {
  addUserToSpan,
  type ApiAccessScope,
} from "@langfuse/shared/src/server";
import { ForbiddenError, safeJsonParse } from "@langfuse/shared";
import { shadowAuth } from "@/src/features/public-api/server/shadowAuth";
import { __dangerouslySkipAuthz } from "@/src/features/public-api/server/enforceAuth";
import { type ServerContext } from "@/src/features/mcp/types";
import { IN_APP_AGENT_MCP_TOOL_OVERRIDE_HEADER } from "@langfuse/shared/in-app-agent";
import { InAppAgentMcpRunOverrideSchema } from "@langfuse/shared/in-app-agent/server/mcpPolicy";
import {
  extractBearerToken,
  isJwt,
  isOidcEnabled,
  resolveOidcContextFromRequest,
} from "./oidc";

export type McpAuthResult = {
  context: ServerContext;
  scope: ApiAccessScope;
};

// In-app-agent keys get read-only tools unless a run override allowlists more.
export function getInAppAgentContext(
  req: NextApiRequest,
  isInAppAgentKey: boolean | undefined,
): ServerContext["inAppAgent"] {
  if (isInAppAgentKey !== true) {
    return undefined;
  }

  const headerValue = req.headers[IN_APP_AGENT_MCP_TOOL_OVERRIDE_HEADER];

  if (typeof headerValue !== "string") {
    return { permissions: "read" };
  }

  const parsedOverride = InAppAgentMcpRunOverrideSchema.safeParse(
    safeJsonParse(headerValue),
  );

  return parsedOverride.success
    ? {
        permissions: "tool-allowlist",
        allowedToolNames: parsedOverride.data.toolNames,
      }
    : { permissions: "read" };
}

export async function authenticateMcpRequest(
  req: NextApiRequest,
): Promise<McpAuthResult> {
  const bearerToken = extractBearerToken(req.headers.authorization);

  if (bearerToken && isJwt(bearerToken) && isOidcEnabled()) {
    const context = await resolveOidcContextFromRequest(req, bearerToken);
    const scope: ApiAccessScope = {
      projectId: context.projectId,
      orgId: context.orgId,
      accessLevel: "project",
      apiKeyId: context.apiKeyId,
      publicKey: context.publicKey,
      plan: context.plan,
      rateLimitOverrides: context.rateLimitOverrides,
      isIngestionSuspended: false,
      isInAppAgentKey: false,
      accessAuditLogEnabled: context.accessAuditLogEnabled,
    };

    addUserToSpan({
      userId: context.userId,
      apiKeyId: scope.apiKeyId,
      publicKey: scope.publicKey,
      projectId: context.projectId,
      orgId: scope.orgId,
      plan: scope.plan,
    });

    return { context, scope };
  }

  // BasicAuth + API key path (existing behavior). Each tool authorizes its
  // own action.
  const authResult = await shadowAuth({
    req,
    action: __dangerouslySkipAuthz,
    allowedAccessLevels: ["project"],
    allowInAppAgentKey: true,
  });

  if (!authResult.success) {
    throw authResult.error;
  }

  const { scope, ctx } = authResult;

  if (scope.accessLevel !== "project" || !scope.projectId) {
    throw new ForbiddenError(
      "Access denied: MCP requires project-scoped API keys with BasicAuth",
    );
  }

  addUserToSpan({
    apiKeyId: scope.apiKeyId,
    publicKey: scope.publicKey,
    projectId: scope.projectId,
    orgId: scope.orgId,
    plan: scope.plan,
  });

  if (scope.isIngestionSuspended) {
    throw new ForbiddenError(
      "Access suspended: Usage threshold exceeded. Please upgrade your plan.",
    );
  }

  const context: ServerContext = {
    projectId: scope.projectId,
    orgId: scope.orgId,
    userId: undefined,
    apiKeyId: scope.apiKeyId,
    accessLevel: "project",
    publicKey: scope.publicKey,
    plan: scope.plan,
    rateLimitOverrides: scope.rateLimitOverrides,
    accessAuditLogEnabled: scope.accessAuditLogEnabled,
    userAgent: req.headers["user-agent"],
    inAppAgent: getInAppAgentContext(req, scope.isInAppAgentKey),
    auth: ctx,
    authMethod: "api-key",
  };

  return { context, scope };
}
