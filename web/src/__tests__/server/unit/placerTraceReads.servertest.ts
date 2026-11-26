import { beforeEach, describe, expect, it, vi } from "vitest";
import { type NextApiRequest } from "next";

const {
  envMock,
  isAuditLogEnabledMock,
  recordTraceViewAuditMock,
  stageAccessEventMock,
  canRecordAccessEventsMock,
} = vi.hoisted(() => ({
  envMock: { PLACER_AUDIT_LOG_WRITES_ENABLED: "true" },
  isAuditLogEnabledMock: vi.fn(),
  recordTraceViewAuditMock: vi.fn(),
  stageAccessEventMock: vi.fn(),
  canRecordAccessEventsMock: vi.fn(),
}));

vi.mock("@/src/env.mjs", () => ({ env: envMock }));

vi.mock("@/src/features/audit-logs/isAuditLogEnabled", () => ({
  isAuditLogEnabled: () => isAuditLogEnabledMock(),
}));

vi.mock("@/src/features/audit-logs/recordTraceViewAudit", () => ({
  recordTraceViewAudit: (...args: unknown[]) =>
    recordTraceViewAuditMock(...args),
}));

vi.mock("@/src/ee/features/access-audit-log/server/stageAccessEvent", () => ({
  stageAccessEvent: (...args: unknown[]) => stageAccessEventMock(...args),
}));

vi.mock("@/src/features/audit-logs/isAccessAuditLogEnabled", () => ({
  canRecordAccessEvents: () => canRecordAccessEventsMock(),
  isAccessAuditLogEnabled: () => true,
}));

vi.mock("@/src/features/audit-logs/server/getAuditRequestContext", () => ({
  getAuditRequestContext: () => undefined,
}));

vi.mock("@/src/features/audit-logs/auditLog", () => ({
  toApiKeyActor: (apiKeyId: string) => ({ type: "API_KEY", apiKeyId }),
  toUserActor: vi.fn(),
}));

vi.mock("@langfuse/shared/src/db", () => ({ prisma: {} }));

vi.mock("@langfuse/shared/src/server", () => ({
  getOrganizationPlanServerSide: vi.fn(),
  logger: { warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
  redis: { status: "end", disconnect: vi.fn() },
  ClickHouseClientManager: {
    getInstance: () => ({
      closeAllConnections: vi.fn().mockResolvedValue(undefined),
    }),
  },
}));

import {
  recordPublicApiAccess,
  tracesRead,
  type AccessRead,
} from "@/src/features/audit-logs/server/recordAccessEvent";

const scope = {
  orgId: "o1",
  projectId: "p1",
  apiKeyId: "k1",
  plan: "oss",
  accessAuditLogEnabled: false,
  isInAppAgentKey: false,
} as unknown as Parameters<typeof recordPublicApiAccess>[0]["scope"];

const req = { headers: {}, socket: {} } as unknown as NextApiRequest;

const listRead: AccessRead = {
  route: "GET /api/public/v2/observations",
  resourceType: "observation",
  action: "list",
  resourceRefs: [
    "observation:obs1",
    "trace:t1",
    "observation:obs2",
    "trace:t1",
    "trace:t2",
    "session:s1",
  ],
};

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("tracesRead", () => {
  it("returns the requested trace and each distinct trace ref", () => {
    expect(
      tracesRead({
        route: "GET /api/public/traces/{traceId}",
        resourceType: "trace",
        resourceId: "t0",
        action: "read",
        resourceRefs: ["trace:t0", "trace:t1", "score:x"],
      }),
    ).toEqual(["t0", "t1"]);
  });

  it("returns nothing for a read without trace refs", () => {
    expect(
      tracesRead({ ...listRead, resourceRefs: ["observation:obs1"] }),
    ).toEqual([]);
  });
});

describe("recordPublicApiAccess on an unlicensed instance", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    envMock.PLACER_AUDIT_LOG_WRITES_ENABLED = "true";
    isAuditLogEnabledMock.mockReturnValue(false);
    recordTraceViewAuditMock.mockResolvedValue(undefined);
    canRecordAccessEventsMock.mockReturnValue(true);
  });

  it("records one trace read per distinct trace", async () => {
    await recordPublicApiAccess({ scope, req }, () => listRead);
    await flush();

    expect(recordTraceViewAuditMock.mock.calls).toEqual([
      [{ apiKeyId: "k1", orgId: "o1", projectId: "p1", resourceId: "t1" }],
      [{ apiKeyId: "k1", orgId: "o1", projectId: "p1", resourceId: "t2" }],
    ]);
    expect(stageAccessEventMock).not.toHaveBeenCalled();
  });

  it("does not wait for the audit writes", async () => {
    recordTraceViewAuditMock.mockReturnValue(new Promise(() => {}));

    await recordPublicApiAccess({ scope, req }, listRead);

    expect(recordTraceViewAuditMock).toHaveBeenCalledTimes(1);
  });

  it("skips a refused read", async () => {
    await recordPublicApiAccess(
      { scope, req },
      { ...listRead, outcome: "denied" },
    );
    await flush();

    expect(recordTraceViewAuditMock).not.toHaveBeenCalled();
  });

  it("skips a key without a project", async () => {
    await recordPublicApiAccess(
      { scope: { ...scope, projectId: null } as typeof scope, req },
      listRead,
    );
    await flush();

    expect(recordTraceViewAuditMock).not.toHaveBeenCalled();
  });

  it("records nothing when PLACER_AUDIT_LOG_WRITES_ENABLED is off", async () => {
    envMock.PLACER_AUDIT_LOG_WRITES_ENABLED = "false";
    canRecordAccessEventsMock.mockReturnValue(false);

    await recordPublicApiAccess({ scope, req }, listRead);
    await flush();

    expect(recordTraceViewAuditMock).not.toHaveBeenCalled();
    expect(stageAccessEventMock).not.toHaveBeenCalled();
  });
});

describe("recordPublicApiAccess on a licensed instance", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    envMock.PLACER_AUDIT_LOG_WRITES_ENABLED = "true";
    isAuditLogEnabledMock.mockReturnValue(true);
    canRecordAccessEventsMock.mockReturnValue(true);
    stageAccessEventMock.mockResolvedValue(undefined);
  });

  it("stages the upstream access event and no trace read rows", async () => {
    await recordPublicApiAccess({ scope, req }, listRead);
    await flush();

    expect(stageAccessEventMock).toHaveBeenCalledTimes(1);
    expect(recordTraceViewAuditMock).not.toHaveBeenCalled();
  });
});
