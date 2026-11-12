import type { McpFeatureModule } from "../registry";
import { handleListProjects, listProjectsTool } from "./tools/listProjects";

export const projectsFeature = {
  name: "projects",
  description: "List the projects an OIDC user can access",
  tools: [
    {
      definition: listProjectsTool,
      handler: handleListProjects,
    },
  ],
  isEnabled: (context) => context.authMethod === "oidc",
} as const satisfies McpFeatureModule;
