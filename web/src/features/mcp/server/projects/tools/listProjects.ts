import { z } from "zod";
import { __dangerouslySkipAuthz } from "@/src/features/public-api/server/enforceAuth";
import { defineTool } from "../../../core/define-tool";
import { runMcpTool } from "../../../core/run-mcp-tool";
import { listAccessibleProjects } from "../../auth/oidc";

const ListProjectsInputSchema = z.object({});

export const LIST_PROJECTS_TOOL = "listProjects";

export const [listProjectsTool, handleListProjects] = defineTool({
  name: LIST_PROJECTS_TOOL,
  // Lists only the caller's own memberships.
  action: __dangerouslySkipAuthz,
  description:
    "List the Langfuse projects you can access, with your role in each. Pass a project's id as `projectId` to any other tool.",
  baseSchema: ListProjectsInputSchema,
  inputSchema: ListProjectsInputSchema,
  handler: async (_input, context) =>
    runMcpTool({
      spanName: "mcp.projects.list",
      context,
      fn: async () => {
        const projects = context.userId
          ? await listAccessibleProjects(context.userId)
          : [];
        return {
          projects: projects.map(({ id, name, role }) => ({ id, name, role })),
        };
      },
    }),
  readOnlyHint: true,
});
