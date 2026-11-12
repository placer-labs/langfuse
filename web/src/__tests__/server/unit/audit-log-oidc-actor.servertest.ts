import { describe, expect, it, vi } from "vitest";

vi.mock("@/src/env.mjs", async (importOriginal) => {
  const original = (await importOriginal()) as { env: Record<string, unknown> };
  return {
    ...original,
    env: {
      ...original.env,
      NEXT_PUBLIC_LANGFUSE_CLOUD_REGION: undefined,
      PLACER_AUDIT_LOG_WRITES_ENABLED: "true",
    },
  };
});

import {
  auditLog,
  OIDC_API_KEY_ID_PREFIX,
} from "@/src/features/audit-logs/auditLog";

const fakeDb = () => {
  const create = vi
    .fn()
    .mockResolvedValue({ id: "al_1", createdAt: new Date() });
  const findUnique = vi.fn().mockResolvedValue(null);
  return {
    db: { auditLog: { create }, apiKey: { findUnique } } as never,
    create,
    findUnique,
  };
};

describe("auditLog OIDC actors", () => {
  it("records an OIDC MCP write as the user, not an api key", async () => {
    const { db, create, findUnique } = fakeDb();
    await auditLog(
      {
        apiKeyId: `${OIDC_API_KEY_ID_PREFIX}user_1`,
        orgId: "org_1",
        projectId: "prj_1",
        resourceType: "prompt",
        resourceId: "prompt_1",
        action: "create",
      },
      db,
    );
    expect(findUnique).not.toHaveBeenCalled();
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          type: "USER",
          userId: "user_1",
          orgId: "org_1",
          projectId: "prj_1",
        }),
      }),
    );
    expect(create.mock.calls[0][0].data).not.toHaveProperty("apiKeyId");
  });

  it("keeps real api key writes on the api key path", async () => {
    const { db, create, findUnique } = fakeDb();
    await auditLog(
      {
        apiKeyId: "key_1",
        orgId: "org_1",
        projectId: "prj_1",
        resourceType: "prompt",
        resourceId: "prompt_1",
        action: "create",
      },
      db,
    );
    expect(findUnique).toHaveBeenCalled();
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ type: "API_KEY", apiKeyId: "key_1" }),
      }),
    );
  });
});
