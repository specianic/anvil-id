// MCP authorization e2e helpers: the agent tenant (DCR/CIMD settings through the admin API) and
// the mock MCP client and resource server from tests/mcp (zero-dependency Node modules, also
// runnable on their own; see tests/mcp/README.md).
//
// Nothing here holds a credential; callers pass an admin token (lib/anvil.ts adminToken).

import { anvilUrl } from './anvil';

export {
  authorizationUrl,
  callMcp,
  checkCallback,
  discoverAuthorizationServer,
  discoverProtectedResource,
  exchangeCode,
  jwtClaims,
  pkcePair,
  startCimdClient,
  type AuthorizationServer,
  type CimdClient,
} from '../../mcp/mock-mcp-client';
export { startMockMcpServer, type MockMcpServer } from '../../mcp/mock-mcp-server';

export type CimdPolicy = 'disabled' | 'allow_listed' | 'open';

/** The agent-facing tenant settings the MCP spec changes (PATCH merges field by field). */
export interface AgentPolicies {
  cimd?: CimdPolicy;
  /** `dcr.allowed_resources`: the RFC 8707 resources dynamic and CIMD clients may be granted. */
  allowedResources?: string[];
}

/** Applies `policies` to tenant `slug` (PATCH /tenants/{slug}); returns the settings in force. */
export async function setAgentPolicies(
  token: string,
  slug: string,
  policies: AgentPolicies,
): Promise<{ cimd: { policy: CimdPolicy }; dcr: { allowed_resources: string[] } }> {
  const settings: Record<string, unknown> = {};
  if (policies.cimd) settings.cimd = { policy: policies.cimd };
  if (policies.allowedResources) settings.dcr = { allowed_resources: policies.allowedResources };
  const path = `/tenants/${encodeURIComponent(slug)}`;
  const res = await fetch(`${anvilUrl()}/api/admin/v1${path}`, {
    method: 'PATCH',
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/json',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ settings }),
  });
  if (res.status !== 200) {
    throw new Error(`PATCH ${path} failed: HTTP ${res.status} ${await res.text()}`);
  }
  const view = (await res.json()) as {
    settings: { cimd: { policy: CimdPolicy }; dcr: { allowed_resources: string[] } };
  };
  return view.settings;
}
