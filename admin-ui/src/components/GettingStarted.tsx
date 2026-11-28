// The getting-started checklist of a tenant's Overview page (C-M6): the steps from a fresh tenant
// to a first working app, each linking to the page that does it. Every "done" mark comes from real
// API state; a step that is a choice rather than a task (the sign-up mode) shows its current value
// instead of a done mark, and a step whose state could not be read says so.
//
//   <GettingStarted tenant={tenantView} />
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Circle, CircleCheck, CircleDot, CircleHelp, LoaderCircle } from "lucide-react";
import type { ReactNode } from "react";
import { api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { CONSOLE_CLIENT_ID } from "@/auth/oidc";
import { getBranding } from "@/components/ThemeEditor";
import { brandingQueryKey } from "@/components/ThemePreview";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchTenantSmtp, smtpQueryKey, smtpState, useSystemInfo } from "@/lib/smtp";
import { SYSTEM_TENANT } from "@/lib/tenant";

type TenantView = components["schemas"]["TenantView"];
type RegistrationMode = components["schemas"]["RegistrationMode"];

/** The role whose holders are console administrators (anvil-core SYSTEM_ADMIN_ROLE). */
const ADMIN_ROLE = "administrator";
/** Largest page the list endpoints return; the checklist only needs "none / some / how many". */
const PAGE = 200;

export const REGISTRATION_LABELS: Record<RegistrationMode, string> = {
  open: "Open: anyone can create an account",
  invite_only: "Invite only: people join through an invitation",
  disabled: "Disabled: administrators create users",
};

type ItemState = "done" | "todo" | "info" | "checking" | "unknown";

const STATE_TEXT: Record<ItemState, string> = {
  done: "Done",
  todo: "To do",
  info: "Current setting",
  checking: "Checking",
  unknown: "Could not be checked",
};

function StateIcon({ state }: { state: ItemState }) {
  const cls = "mt-0.5 size-5 shrink-0";
  switch (state) {
    case "done":
      return <CircleCheck aria-hidden="true" className={`${cls} text-success`} />;
    case "info":
      return <CircleDot aria-hidden="true" className={`${cls} text-link`} />;
    case "checking":
      return <LoaderCircle aria-hidden="true" className={`${cls} text-muted-foreground animate-spin`} />;
    case "unknown":
      return <CircleHelp aria-hidden="true" className={`${cls} text-muted-foreground`} />;
    default:
      return <Circle aria-hidden="true" className={`${cls} text-muted-foreground`} />;
  }
}

function Item({
  id,
  state,
  title,
  detail,
  children,
}: {
  id: string;
  state: ItemState;
  /** The link to the page that does the step. */
  title: ReactNode;
  /** What the API says right now ("2 apps", "Open: ..."). */
  detail?: ReactNode;
  children: ReactNode;
}) {
  return (
    <li className="flex gap-3 py-3" data-testid={`checklist-${id}`} data-state={state}>
      <StateIcon state={state} />
      <div className="min-w-0 space-y-0.5">
        <p className="font-medium">
          {title}{" "}
          <span className="text-muted-foreground text-xs font-normal" data-testid={`checklist-${id}-state`}>
            ({STATE_TEXT[state]})
          </span>
        </p>
        <p className="text-muted-foreground text-sm">{children}</p>
        {detail ? (
          <p className="text-sm" data-testid={`checklist-${id}-detail`}>
            {detail}
          </p>
        ) : null}
      </div>
    </li>
  );
}

const linkClass = "text-link underline underline-offset-4";

/** Pending → checking, error → unknown, otherwise done/todo from `done`. */
function stateOf(query: { isPending: boolean; isError: boolean }, done: () => boolean): ItemState {
  if (query.isPending) return "checking";
  if (query.isError) return "unknown";
  return done() ? "done" : "todo";
}

function count(n: number, more: boolean, one: string, many: string): string {
  return `${n}${more ? "+" : ""} ${n === 1 && !more ? one : many}`;
}

export function GettingStarted({ tenant }: { tenant: TenantView }) {
  const slug = tenant.slug;
  const isSystem = slug === SYSTEM_TENANT;

  // Apps an administrator created: static clients, without the built-in console client of the
  // system tenant. Dynamic (RFC 7591) and CIMD clients register themselves and do not count.
  const clients = useQuery({
    queryKey: ["clients", slug, "getting-started"],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/clients", {
          params: { path: { slug }, query: { limit: PAGE } },
          signal,
        }),
      ),
  });
  const apps = (clients.data?.items ?? []).filter(
    (c) => c.registration_source === "static" && !(isSystem && c.client_id === CONSOLE_CLIENT_ID),
  );

  const brandingScope = { kind: "tenant", tenant: slug } as const;
  const branding = useQuery({
    queryKey: brandingQueryKey(brandingScope),
    queryFn: ({ signal }) => getBranding(brandingScope, signal),
    refetchOnWindowFocus: false,
  });

  const tenantSmtp = useQuery({
    queryKey: smtpQueryKey(slug),
    queryFn: ({ signal }) => fetchTenantSmtp(slug, signal),
  });
  const info = useSystemInfo();
  const smtp = {
    isPending: tenantSmtp.isPending || (tenantSmtp.data === null && info.isPending),
    isError: tenantSmtp.isError || (tenantSmtp.data === null && info.isError),
  };
  const smtpNow = tenantSmtp.data !== undefined ? smtpState(tenantSmtp.data, info.data?.smtp_configured) : "unknown";

  const connections = useQuery({
    queryKey: ["connections", slug],
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/api/admin/v1/tenants/{slug}/connections", { params: { path: { slug } }, signal })),
  });
  const enabledConnections = (connections.data?.items ?? []).filter((c) => c.enabled);

  const admins = useQuery({
    queryKey: ["role-users", slug, ADMIN_ROLE, "getting-started"],
    enabled: isSystem,
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/roles/{name}/users", {
          params: { path: { slug, name: ADMIN_ROLE }, query: { limit: PAGE } },
          signal,
        }),
      ),
  });
  const adminCount = admins.data?.items.length ?? 0;

  return (
    <Card data-testid="getting-started">
      <CardHeader>
        <CardTitle>
          <h2 id="getting-started-heading">Getting started</h2>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ol aria-labelledby="getting-started-heading" className="divide-y">
          <Item
            id="first-app"
            state={stateOf(clients, () => apps.length > 0)}
            title={
              <Link to="/t/$tenant/clients/new" params={{ tenant: slug }} className={linkClass}>
                Create your first app
              </Link>
            }
            detail={
              clients.isSuccess && apps.length > 0
                ? `${count(apps.length, Boolean(clients.data.next_cursor), "app", "apps")} in this tenant.`
                : undefined
            }
          >
            Register the application that signs users in with this tenant (a single-page app, web app, native app
            or service).
          </Item>

          <Item
            id="sign-up"
            state="info"
            title={
              <Link to="/t/$tenant/settings" hash="sign-up" params={{ tenant: slug }} className={linkClass}>
                Choose who can sign up
              </Link>
            }
            detail={`Currently: ${REGISTRATION_LABELS[tenant.settings.registration]}.`}
          >
            Decide whether anyone may create an account on the sign-in page, only invited people, or nobody.
          </Item>

          <Item
            id="logo"
            state={stateOf(branding, () => Boolean(branding.data?.logo_url))}
            title={
              <Link to="/t/$tenant/branding" hash="logo" params={{ tenant: slug }} className={linkClass}>
                Add your logo and colours
              </Link>
            }
            detail={
              branding.isSuccess
                ? branding.data.logo_url
                  ? "A logo is set."
                  : branding.data.customized
                    ? "Colours are customised; no logo yet."
                    : "No logo yet; the default theme is used."
                : undefined
            }
          >
            Make the sign-in and consent pages look like your product.
          </Item>

          <Item
            id="smtp"
            state={stateOf(smtp, () => smtpNow === "tenant" || smtpNow === "installation")}
            title={
              <Link to="/t/$tenant/email/smtp" params={{ tenant: slug }} className={linkClass}>
                Set up email (SMTP)
              </Link>
            }
            detail={
              smtp.isPending || smtp.isError
                ? undefined
                : smtpNow === "tenant"
                  ? "This tenant uses its own SMTP server."
                  : smtpNow === "installation"
                    ? "This tenant uses the installation's SMTP server."
                    : "No SMTP server configured: verification, recovery and invitation emails can't be sent."
            }
          >
            Needed for email verification, password recovery, invitations and email sign-in codes.
          </Item>

          <Item
            id="connection"
            state={stateOf(connections, () => enabledConnections.length > 0)}
            title={
              <Link to="/t/$tenant/connections" params={{ tenant: slug }} className={linkClass}>
                Add a sign-in connection
              </Link>
            }
            detail={
              connections.isSuccess && connections.data.items.length > 0
                ? `${count(enabledConnections.length, false, "connection", "connections")} enabled of ${connections.data.items.length}.`
                : undefined
            }
          >
            Optional: let users sign in with Google, Microsoft, GitHub, Apple or another OpenID provider.
          </Item>

          {isSystem && (
            <Item
              id="second-admin"
              state={stateOf(admins, () => adminCount >= 2)}
              title={
                <Link
                  to="/t/$tenant/roles/$roleName"
                  params={{ tenant: slug, roleName: ADMIN_ROLE }}
                  className={linkClass}
                >
                  Add a second administrator
                </Link>
              }
              detail={
                admins.isSuccess
                  ? `${count(adminCount, Boolean(admins.data.next_cursor), "administrator", "administrators")}.`
                  : undefined
              }
            >
              So that someone else can still sign in to the console if you lose access. Give a user of the system
              tenant the <code>{ADMIN_ROLE}</code> role.
            </Item>
          )}
        </ol>
      </CardContent>
    </Card>
  );
}
