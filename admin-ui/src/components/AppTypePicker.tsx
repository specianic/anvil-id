// "What are you building?" (C-H5, C-M1, C-M2, C-M4): the first step of creating a client. Each app
// type preselects the client settings that make a working, safe setup for it. Usage:
//
//   <AppTypePicker value={appType} onChange={setAppType} />
//   const values = newClientValues(appType); // components/ClientForm.tsx, built from APP_TYPES
//
// The console only preselects: the server's client policy still decides (agents never skip
// consent, native headless eligibility, redirect URI rules).
import { AppWindow, Bot, Globe, type LucideIcon, Server, Smartphone } from "lucide-react";
import type { ClientFormValues } from "@/components/ClientForm";
import { cn } from "@/lib/utils";

export type AppTypeId = "web" | "spa" | "native" | "m2m" | "agent";

/** The settings an app type fixes; everything else comes from the shared base values. */
export type AppTypeDefaults = Pick<
  ClientFormValues,
  | "client_type"
  | "application_type"
  | "auth_method"
  | "grant_types"
  | "scopes"
  | "require_pkce"
  | "consent_mode"
  | "client_kind"
>;

export interface AppType {
  id: AppTypeId;
  title: string;
  description: string;
  icon: LucideIcon;
  defaults: AppTypeDefaults;
  /** Example shown in the empty Redirect URIs field. */
  redirectExample: string;
}

/**
 * The app types in display order, with their defaults (research 3.4). Web: confidential with a
 * secret; SPA and native: public with PKCE (a secret shipped to a browser or device is not secret);
 * machine-to-machine: client credentials only, API scopes; agent: consent always asked.
 */
export const APP_TYPES: readonly AppType[] = [
  {
    id: "web",
    title: "Web app",
    description: "Runs on a server (Rails, Django, Next.js server side) and can keep a secret.",
    icon: Globe,
    defaults: {
      client_type: "confidential",
      application_type: "web",
      auth_method: "client_secret_basic",
      grant_types: ["authorization_code", "refresh_token"],
      scopes: "openid profile email",
      require_pkce: true,
      consent_mode: "skip_first_party",
      client_kind: "application",
    },
    redirectExample: "https://app.example.com/callback",
  },
  {
    id: "spa",
    title: "Single-page app",
    description: "Runs in the browser (React, Vue, Angular). No secret; signs in with PKCE.",
    icon: AppWindow,
    defaults: {
      client_type: "public",
      application_type: "web",
      auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      scopes: "openid profile email",
      require_pkce: true,
      consent_mode: "skip_first_party",
      client_kind: "application",
    },
    redirectExample: "http://localhost:5173/callback",
  },
  {
    id: "native",
    title: "Native or mobile app",
    description: "iOS, Android or desktop. No secret; signs in through the system browser with PKCE.",
    icon: Smartphone,
    defaults: {
      client_type: "public",
      application_type: "native",
      auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      scopes: "openid profile email",
      require_pkce: true,
      consent_mode: "skip_first_party",
      client_kind: "application",
    },
    redirectExample: "com.example.app:/callback or http://127.0.0.1/callback",
  },
  {
    id: "m2m",
    title: "Machine-to-machine",
    description: "A backend service or script calling an API with its own credentials. No user signs in.",
    icon: Server,
    defaults: {
      client_type: "confidential",
      application_type: "web",
      auth_method: "client_secret_basic",
      grant_types: ["client_credentials"],
      scopes: "",
      require_pkce: true,
      consent_mode: "required",
      client_kind: "application",
    },
    redirectExample: "",
  },
  {
    id: "agent",
    title: "AI agent",
    description: "An agent or automated client acting for a user. Users always see the consent screen.",
    icon: Bot,
    defaults: {
      client_type: "confidential",
      application_type: "web",
      auth_method: "client_secret_basic",
      grant_types: ["authorization_code", "refresh_token"],
      scopes: "openid profile email",
      require_pkce: true,
      consent_mode: "required",
      client_kind: "agent",
    },
    redirectExample: "https://agent.example.com/callback",
  },
];

export function appType(id: AppTypeId): AppType {
  const found = APP_TYPES.find((t) => t.id === id);
  // AppTypeId is a closed union and APP_TYPES lists every member.
  if (!found) throw new Error(`unknown app type ${id}`);
  return found;
}

interface AppTypePickerProps {
  value: AppTypeId;
  onChange: (next: AppTypeId) => void;
}

/** Five cards with radio semantics (native radios in a fieldset: arrow keys move the choice). */
export function AppTypePicker({ value, onChange }: AppTypePickerProps) {
  return (
    <fieldset className="space-y-2" data-testid="app-type-picker">
      <legend className="mb-2 text-base font-semibold">What are you building?</legend>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {APP_TYPES.map((type) => {
          const Icon = type.icon;
          const checked = type.id === value;
          return (
            <label
              key={type.id}
              className={cn(
                "flex cursor-pointer gap-3 rounded-md border p-3 text-sm focus-within:ring-[3px] focus-within:ring-ring/50",
                checked ? "border-primary bg-muted" : "border-border hover:bg-muted/50",
              )}
            >
              <input
                type="radio"
                name="app_type"
                value={type.id}
                checked={checked}
                onChange={() => onChange(type.id)}
                className="mt-1 size-4 shrink-0 focus-visible:outline-none"
                aria-describedby={`app-type-${type.id}-description`}
              />
              <span className="space-y-1">
                <span className="flex items-center gap-2 font-medium">
                  <Icon aria-hidden="true" className="size-4" />
                  {type.title}
                </span>
                <span id={`app-type-${type.id}-description`} className="text-muted-foreground block text-xs">
                  {type.description}
                </span>
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}
