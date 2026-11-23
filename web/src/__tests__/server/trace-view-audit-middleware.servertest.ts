import type { Session } from "next-auth";
import * as z from "zod";
import { TRPCError } from "@trpc/server";
import { createSession } from "@/src/__tests__/fixtures/session-factory";

const { recordTraceViewAuditMock } = vi.hoisted(() => ({
  recordTraceViewAuditMock: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@/src/features/audit-logs/recordTraceViewAudit", () => ({
  recordTraceViewAudit: recordTraceViewAuditMock,
}));

// Both trace lookups are mocked unconditionally. `enforceTraceAccess` picks
// between them by readSource and LANGFUSE_MIGRATION_V4_WRITE_MODE — the v4
// instantiation reads the events table, and the v3 one falls back to it under
// `dual`. Mocking both keeps the test independent of the env value.
vi.mock("@langfuse/shared/src/server", async () => {
  const originalModule = await vi.importActual("@langfuse/shared/src/server");
  return {
    ...originalModule,
    getTraceById: vi.fn(),
    getTraceByIdFromEventsTable: vi.fn(),
  };
});

import {
  createTRPCRouter,
  createInnerTRPCContext,
  protectedGetTraceProcedure,
  protectedGetEventsTraceProcedure,
} from "@/src/server/api/trpc";
import {
  getTraceById,
  getTraceByIdFromEventsTable,
} from "@langfuse/shared/src/server";

// Register under the real `traces.*` / `events.*` paths so the middleware sees
// the same `opts.path` it gates on in production (AUDITED_TRACE_VIEW_PROCEDURES).
// Both content-detail views are audited: `traces.byIdWithObservationsAndScores`
// (v3) and `events.byTraceId` (v4). The per-row table-cell fetch `traces.byId`
// must NOT be audited. That the audited paths still resolve to real prod
// procedures is guarded separately by recordTraceViewAudit.drift.servertest.ts.
//
// Each path uses the SAME procedure it uses in prod: `enforceTraceAccess` is a
// factory over readSource, so wiring the events path through the v3 procedure
// would pass while never exercising the v4 instantiation the audit actually
// runs in.
const traceViewInput = z.object({
  traceId: z.string(),
  projectId: z.string(),
});
const middlewareTestRouter = createTRPCRouter({
  traces: createTRPCRouter({
    byId: protectedGetTraceProcedure
      .input(traceViewInput)
      .query(() => ({ ok: true })),
    byIdWithObservationsAndScores: protectedGetTraceProcedure
      .input(traceViewInput)
      .query(() => ({ ok: true })),
  }),
  events: createTRPCRouter({
    byTraceId: protectedGetEventsTraceProcedure
      .input(traceViewInput)
      .query(() => ({ ok: true })),
  }),
});

const PROJECT_ID = "project-id";
const ORG_ID = "org-id";
const TRACE_ID = "trace-id";

const createMemberSession = () =>
  createSession({
    user: { id: "member-user-id", name: "Member User" },
    organizations: [
      {
        id: ORG_ID,
        role: "MEMBER",
        projects: [{ id: PROJECT_ID, role: "MEMBER" }],
      },
    ],
  });

// Signed in, but a member of nothing. Upstream removed the admin bypass
// (#19582), so membership is the only route to a private trace.
const createNonMemberSession = () =>
  createSession({ user: { id: "non-member-user-id" } });

// The middleware hands auditLog the request's session, which derives the
// actor's roles from its policies.
const expectedSessionAudit = (session: Session) => ({
  session: expect.objectContaining({
    user: expect.objectContaining({ id: session.user!.id }),
    policies: session.policies,
    orgId: ORG_ID,
    projectId: PROJECT_ID,
  }),
  resourceId: TRACE_ID,
});

const createTestCaller = (params: {
  session: Session;
  traceSession?: { public: boolean } | null;
}) => {
  const mockPrisma = {
    traceSession: {
      findFirst: vi
        .fn()
        .mockResolvedValue(params.traceSession ?? { public: false }),
    },
  };

  const context = createInnerTRPCContext({
    session: params.session,
    headers: {},
  });

  return {
    caller: middlewareTestRouter.createCaller({
      ...context,
      prisma: mockPrisma as any,
    }),
    mockPrisma,
  };
};

describe("trace-view audit in tRPC trace-access middleware", () => {
  const mockGetTraceById = vi.mocked(getTraceById);
  const mockGetTraceFromEvents = vi.mocked(getTraceByIdFromEventsTable);

  // Whichever lookup the middleware picks, it must see the same trace.
  const resolveTraceAs = (trace: unknown) => {
    mockGetTraceById.mockResolvedValue(trace as any);
    mockGetTraceFromEvents.mockResolvedValue(trace as any);
  };

  beforeEach(() => {
    vi.clearAllMocks();
    recordTraceViewAuditMock.mockResolvedValue(undefined);
    resolveTraceAs({
      id: TRACE_ID,
      input: "{}",
      output: "{}",
      public: false,
      sessionId: null,
    });
  });

  it("records a read audit when a project member views a trace", async () => {
    const session = createMemberSession();
    const { caller } = createTestCaller({ session });

    await caller.traces.byIdWithObservationsAndScores({
      traceId: TRACE_ID,
      projectId: PROJECT_ID,
    });

    expect(recordTraceViewAuditMock).toHaveBeenCalledTimes(1);
    expect(recordTraceViewAuditMock).toHaveBeenCalledWith(
      expectedSessionAudit(session),
    );
  });

  it("records a read audit for the v4 events-backed detail view (events.byTraceId)", async () => {
    // v4 beta fetches trace content via events.byTraceId, not
    // traces.byIdWithObservationsAndScores. It hits the same middleware and
    // must be audited too, or the audit guarantee silently fails for v4 users.
    const session = createMemberSession();
    const { caller } = createTestCaller({ session });

    await caller.events.byTraceId({
      traceId: TRACE_ID,
      projectId: PROJECT_ID,
    });

    // Proves the v4 instantiation actually ran: only enforceTraceAccess("v4")
    // resolves the trace through the events table. Without this the test would
    // still pass if the events path were wired to the v3 procedure.
    expect(mockGetTraceFromEvents).toHaveBeenCalled();
    expect(mockGetTraceById).not.toHaveBeenCalled();

    expect(recordTraceViewAuditMock).toHaveBeenCalledTimes(1);
    expect(recordTraceViewAuditMock).toHaveBeenCalledWith(
      expectedSessionAudit(session),
    );
  });

  it("does NOT record an audit when a logged-in non-member views a public trace", async () => {
    // Access is granted because the trace is public, but there is no
    // member org to attribute, so there is no actor to audit — the view must pass through without an audit row.
    resolveTraceAs({
      id: TRACE_ID,
      input: "{}",
      output: "{}",
      public: true,
      sessionId: null,
    });
    const { caller } = createTestCaller({ session: createNonMemberSession() });

    await caller.traces.byIdWithObservationsAndScores({
      traceId: TRACE_ID,
      projectId: PROJECT_ID,
    });

    expect(recordTraceViewAuditMock).not.toHaveBeenCalled();
  });

  it("does NOT record an audit for traces.byId (table IO/metadata cell fetch)", async () => {
    // byId backs the per-row input/output/metadata cells in the traces table,
    // fired for every visible row on list render — auditing it is a false
    // positive. Only the full detail view counts as a view.
    const { caller } = createTestCaller({ session: createMemberSession() });

    await caller.traces.byId({ traceId: TRACE_ID, projectId: PROJECT_ID });

    expect(recordTraceViewAuditMock).not.toHaveBeenCalled();
  });

  it("does not record an audit when access is denied (non-member, private trace)", async () => {
    // Non-member session on a private trace → UNAUTHORIZED.
    const { caller } = createTestCaller({ session: createNonMemberSession() });

    await expect(
      caller.traces.byIdWithObservationsAndScores({
        traceId: TRACE_ID,
        projectId: PROJECT_ID,
      }),
    ).rejects.toThrow(TRPCError);

    expect(recordTraceViewAuditMock).not.toHaveBeenCalled();
  });

  it("does not record an audit when the trace is not found", async () => {
    resolveTraceAs(null);
    const { caller } = createTestCaller({ session: createMemberSession() });

    await expect(
      caller.traces.byIdWithObservationsAndScores({
        traceId: TRACE_ID,
        projectId: PROJECT_ID,
      }),
    ).rejects.toThrow(TRPCError);

    expect(recordTraceViewAuditMock).not.toHaveBeenCalled();
  });
});
