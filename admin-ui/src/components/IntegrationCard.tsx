// Everything an app needs to sign users in (C-H7): issuer, discovery URL, client id, the secret
// (only right after creation or rotation, from the page's component state) and the redirect URIs,
// each with a Copy button, plus a `.env` snippet. Usage:
//
//   const view = useTenantView(tenant);
//   <IntegrationCard issuer={view.data.issuer} discoveryUrl={view.data.discovery_url}
//     clientId={client.client_id} redirectUris={client.redirect_uris} secret={secret} />
//
// The issuer and discovery URL come from the tenant view (the server's own values, the ones in the
// tenant's discovery document), never from string building in the console.
import { CopyField } from "@/components/CopyField";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface IntegrationCardProps {
  issuer: string;
  discoveryUrl: string;
  clientId: string;
  redirectUris: readonly string[];
  /** The client secret, only while it is shown once; never stored in a query cache. */
  secret?: string | null;
}

/** The `.env` lines for the app; the secret line only when the secret is on screen. */
export function envSnippet(issuer: string, clientId: string, secret?: string | null): string {
  const out = [`ANVILID_ISSUER=${issuer}`, `ANVILID_CLIENT_ID=${clientId}`];
  if (secret) out.push(`ANVILID_CLIENT_SECRET=${secret}`);
  return out.join("\n");
}

export function IntegrationCard({ issuer, discoveryUrl, clientId, redirectUris, secret }: IntegrationCardProps) {
  return (
    <Card data-testid="integration-card">
      <CardHeader>
        <CardTitle>
          <h2>Integration</h2>
        </CardTitle>
        <p className="text-muted-foreground text-sm">
          Configure your app with these values. Most OIDC libraries need only the issuer (or the discovery URL), the
          client ID and, for confidential clients, the secret.
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        <div data-testid="integration-issuer">
          <CopyField label="Issuer" value={issuer} mono />
        </div>
        <div data-testid="integration-discovery-url">
          <CopyField label="Discovery URL" value={discoveryUrl} mono />
        </div>
        <div data-testid="integration-client-id">
          <CopyField label="Client ID" value={clientId} mono />
        </div>
        {secret ? (
          <div data-testid="integration-client-secret">
            <CopyField label="Client secret" value={secret} mono />
          </div>
        ) : null}
        {redirectUris.map((uri, i) => (
          <CopyField
            key={uri}
            label={redirectUris.length === 1 ? "Redirect URI" : `Redirect URI ${i + 1}`}
            value={uri}
            mono
          />
        ))}
        <EnvSnippet value={envSnippet(issuer, clientId, secret)} />
      </CardContent>
    </Card>
  );
}

function EnvSnippet({ value }: { value: string }) {
  return (
    <div className="space-y-1.5" data-testid="integration-env">
      <pre className="bg-muted overflow-x-auto rounded-md border p-3 font-mono text-xs">{value}</pre>
      {/* The copy button copies the lines above exactly (with their line breaks). */}
      <CopyField label=".env snippet" value={value} mono />
    </div>
  );
}
