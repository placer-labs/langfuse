import { randomUUID } from "crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  writesEnabled: undefined as string | undefined,
  accessEvents: "org",
}));

// Same approach as audit-log-license-gate.servertest.ts: run the real gate
// against a real database on an unlicensed self-hosted instance, overriding
// only the values under test. `undefined` falls through to the parsed env, so
// the default is exercised too.
vi.mock("@/src/env.mjs", async (importOriginal) => {
  const original = (await importOriginal()) as { env: Record<string, unknown> };
  return {
    ...original,
    env: new Proxy(original.env, {
      get: (target, prop) => {
        if (prop === "NEXT_PUBLIC_LANGFUSE_CLOUD_REGION") return undefined;
        if (prop === "LANGFUSE_EE_LICENSE_KEY") return undefined;
        if (prop === "LANGFUSE_AUDIT_LOG_STAGING_ENABLED") return "true";
        if (prop === "LANGFUSE_AUDIT_LOG_ACCESS_EVENTS")
          return mocks.accessEvents;
        if (
          prop === "PLACER_AUDIT_LOG_WRITES_ENABLED" &&
          mocks.writesEnabled !== undefined
        )
          return mocks.writesEnabled;
        return Reflect.get(target, prop);
      },
    }),
  };
});

import { auditLog } from "@/src/features/audit-logs/auditLog";
import { isAuditLogEnabled } from "@/src/features/audit-logs/isAuditLogEnabled";
import { canRecordAccessEvents } from "@/src/features/audit-logs/isAccessAuditLogEnabled";
import { prisma } from "@langfuse/shared/src/db";
import { createOrgProjectAndApiKey } from "@langfuse/shared/src/server";

/**
 * placer-labs runs Langfuse without an enterprise license. Upstream persists
 * audit_logs rows only with the audit-logs entitlement (#18285); the fork keeps
 * writing them so our audit trail, including trace-view reads, survives
 * upstream syncs. The EE features around audit logs must stay off.
 */
describe("placer-labs audit log writes", () => {
  let orgId: string;
  let projectId: string;
  const userId = randomUUID();

  beforeEach(async () => {
    mocks.writesEnabled = undefined;
    mocks.accessEvents = "org";
    ({ orgId, projectId } = await createOrgProjectAndApiKey());
  });

  const writeOne = async () => {
    const resourceId = randomUUID();
    await auditLog({
      action: "read",
      resourceType: "trace",
      resourceId,
      session: { user: { id: userId }, orgId, projectId },
    });
    return prisma.auditLog.count({ where: { resourceId } });
  };

  it("runs unlicensed, so upstream's gate alone would drop the record", () => {
    // If this fails, the instance under test is licensed and the cases below
    // no longer prove anything about the fork override.
    expect(isAuditLogEnabled()).toBe(false);
  });

  it("persists records by default", async () => {
    expect(await writeOne()).toBe(1);
  });

  it("restores upstream behavior when switched off", async () => {
    mocks.writesEnabled = "false";
    expect(await writeOne()).toBe(0);
  });

  it("does not turn on the EE read-access events", () => {
    // "enforced" mode follows the instance license; the fork override must not
    // count as one.
    mocks.accessEvents = "enforced";
    expect(canRecordAccessEvents()).toBe(false);
  });
});
