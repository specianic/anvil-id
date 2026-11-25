---
phase: 03-release-0-2-secure-by-default
plan: 03
subsystem: admin-ui
tags: [admin-console, react, vite, tanstack, oidc, openapi, ci]
requires:
  - Phase 2 management API (docs/openapi/admin-v1.json, 02-16)
provides:
  - admin-ui/ SPA (base /console/) with typed API client, OIDC sign-in as anvil-console, Users and Clients pages
  - npm scripts build / typecheck / gen:api / check:api; .br/.gz sidecars in admin-ui/dist
  - CI job `console` (Node 22); just console-build / console-check
affects:
  - 03-21 (console client upsert must match client_id/redirect/scopes used here)
  - 03-22 (embedding dist/ at /console/*, Accept-Encoding negotiation of sidecars, CSP)
  - 03-25 (Sessions/Audit/Email pages, Playwright spec)
  - 03-29 (may add console recipes to `just ci`)
tech-stack:
  added: [react 19.3.1, vite 8.3.8, typescript 5.9.3 (pinned), "@tanstack/react-router 1.170.46", "@tanstack/router-plugin 1.169.0", "@tanstack/react-query 5.108.4", "@tanstack/react-table 9.3.1", openapi-typescript 7.13.0, openapi-fetch 0.17.0, oidc-client-ts 3.5.0, tailwindcss 4.3.5, "@tailwindcss/vite 4.3.5", "@vitejs/plugin-react 6.3.0", radix-ui 1.8.1, class-variance-authority 0.7.1, clsx 2.1.1, tailwind-merge 3.7.1]
  patterns:
    - openapi-fetch middleware throws ApiError (RFC 9457 problem) for every non-2xx; unwrap() returns data
    - token provider registered by the auth layer; one refresh-and-retry on 401 (shared in-flight refresh)
    - TanStack Table v9 useTable with tableFeatures({}) (server-side paging, no client row models)
    - cursor stack over the API's `after` cursor for Previous/Next
key-files:
  created:
    - admin-ui/package.json
    - admin-ui/package-lock.json
    - admin-ui/vite.config.ts
    - admin-ui/tsconfig.json
    - admin-ui/components.json
    - admin-ui/scripts/compress.mjs
    - admin-ui/src/api/schema.d.ts
    - admin-ui/src/api/client.ts
    - admin-ui/src/auth/oidc.ts
    - admin-ui/src/auth/AuthProvider.tsx
    - admin-ui/src/components/AppShell.tsx
    - admin-ui/src/components/DataTable.tsx
    - admin-ui/src/components/ProblemAlert.tsx
    - admin-ui/src/lib/utils.ts
    - admin-ui/src/lib/format.ts
    - admin-ui/src/routeTree.gen.ts
    - admin-ui/src/routes/{__root,index,callback}.tsx
    - admin-ui/src/routes/users/{index,$userId}.tsx
    - admin-ui/src/routes/clients/{index,$clientId}.tsx
    - admin-ui/README.md
  modified:
    - .gitignore
    - .github/workflows/ci.yml
    - justfile
decisions:
  - "03-03: List paging uses the API's actual `after` query parameter (the plan said `cursor`); response field is `next_cursor`"
  - "03-03: src/routeTree.gen.ts is committed (fresh checkouts type-check before the router plugin runs); CI fails if a build changes it"
  - "03-03: Sign-in return target is a browser path restricted to /console/ (same origin); anything else falls back to /console/"
  - "03-03: Sign-out POSTs RFC 7009 revocation to {origin}/t/system/revoke with client_id=anvil-console; a 404 (endpoint not yet shipped, 03-18) is ignored explicitly; local session always cleared"
  - "03-03: Refresh uses oidc-client-ts signinSilent only when a refresh token exists (refresh_token grant, no iframe); otherwise the session is cleared and the auth gate restarts sign-in"
  - "03-03: No console component needs inline styles; CSP for /console can stay script-src 'self' and style-src 'self'"
metrics:
  duration: 40min
  completed: 2026-11-25
  tasks: 2
  files: 37
---

# Phase 3 Plan 03: Admin console scaffold Summary

React 19 + Vite 8 console SPA at `/console/` with openapi-typescript/openapi-fetch types from
`docs/openapi/admin-v1.json` (drift-checked), oidc-client-ts sign-in as the `anvil-console` public client
of the system tenant, an accessible app shell, TanStack Table v9 cursor-paged Users and Clients pages,
precompressed `.br`/`.gz` build output, and a Node 22 CI job.

## Tasks

| Task | Name | Commit |
| ---- | ---- | ------ |
| 1 | Project scaffold, codegen, compression, CI job | add9d17 |
| 2 | OIDC auth, app shell, Users and Clients pages | a121c06 |

## What was built

- **Tooling:** `npm run build` = `tsc -b && vite build && node scripts/compress.mjs`. `compress.mjs` writes
  `.br` (brotli max quality) and `.gz` (level 9) next to js/css/html/svg/json/txt/map files larger than 1 KiB.
  `check:api` regenerates into `node_modules/.schema-check.d.ts` and `diff`s against the committed schema.
  A test with an appended line confirmed it exits 1 on drift. `engines.node >=22.12`.
- **API client (`src/api/client.ts`):** `createClient<paths>({ baseUrl: '' })`. The middleware adds
  `Authorization: Bearer`, clones each request so a 401 can be retried once after a refresh (the retry uses
  plain fetch, so there is no loop), and turns any non-2xx response into `ApiError` with a typed `Problem`.
  Non-problem bodies get a synthesised problem.
- **Auth (`src/auth/oidc.ts`, `AuthProvider.tsx`):** the UserManager config is as specified (authority
  `{origin}/t/system`, redirect `{origin}/console/callback`, scope `openid admin:read admin:write`, user and
  state stores in sessionStorage, `automaticSilentRenew: false`). The code exchange is memoised so StrictMode
  cannot run it twice. AuthProvider gates every route except `/callback`.
- **UI:** AppShell has a skip link, `header`/`nav[aria-label=Main]`/`main#main` landmarks and visible focus
  rings. It links only to Users and Clients. DataTable (v9 `useTable`, `tableFeatures({})`) has
  loading skeletons, an empty row, a problem alert, and Previous/Next over a cursor stack. The Users list
  shows email, verified, status, created and last login, and the user detail page shows account fields plus
  the claims that are set, all read-only. The Clients list shows client_id, name, type and auth method, and
  the client detail page shows settings, redirect URIs, grant types and scopes. The console targets the
  `default` tenant.

## CSP notes (for 03-22)

- No component needs inline styles or inline scripts. `dist/index.html` has only an external module script,
  modulepreload links and an external stylesheet. React `style` props are not used anywhere.
- The bundle includes React DOM's `createElement("style")` path for `<style precedence>` resources. Nothing in
  the console renders that, so no `style-src 'unsafe-inline'` exception is needed today. Recheck under the
  real CSP in 03-25's Playwright spec. The only Radix code used is `Slot` (no scroll-lock or toasts).

## Exact npm versions resolved

react 19.3.1, react-dom 19.3.1, vite 8.3.8, @vitejs/plugin-react 6.3.0, typescript 5.9.3 (exact pin),
@tanstack/react-router 1.170.46, @tanstack/router-plugin 1.169.0, @tanstack/react-query 5.108.4,
@tanstack/react-table 9.3.1, openapi-typescript 7.13.0, openapi-fetch 0.17.0, oidc-client-ts 3.5.0,
tailwindcss 4.3.5, @tailwindcss/vite 4.3.5, radix-ui 1.8.1, class-variance-authority 0.7.1, clsx 2.1.1,
tailwind-merge 3.7.1, @types/react 19.3.1, @types/react-dom 19.3.0, @types/node 22.20.5. shadcn CLI 4.23.0
(used through npx only, not a dependency). Every lockfile entry resolves from registry.npmjs.org.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] shadcn CLI imported `cn` from an unrelated npm package**
- **Found during:** Task 1
- **Issue:** with no `src/lib/utils.ts` present (no `shadcn init`), `shadcn add` installed the npm package `cn`
  and generated `import { cn } from "cn"`.
- **Fix:** uninstalled `cn`, added `src/lib/utils.ts` (clsx + tailwind-merge), rewrote the imports to `@/lib/utils`,
  and added clsx, tailwind-merge and class-variance-authority. Added the shadcn theme tokens to `styles.css` by hand.
- **Files:** admin-ui/src/lib/utils.ts, admin-ui/src/components/ui/*.tsx, admin-ui/package.json
- **Commit:** add9d17

**2. [Rule 3 - Blocking] Generated route tree is needed before `tsc -b`**
- **Found during:** Task 1
- **Issue:** `tsc -b` runs before the router plugin generates `src/routeTree.gen.ts`, so a fresh checkout fails to type-check.
- **Fix:** committed `src/routeTree.gen.ts`. The CI `console` job runs `git diff --exit-code` on it after the build.
  Minimal `__root.tsx`/`index.tsx` were created in Task 1 and completed in Task 2.
- **Commit:** add9d17

**3. [Rule 1 - Spec mismatch] Pagination parameter is `after`, not `cursor`**
- The plan interface said `cursor`. The OpenAPI document (source of truth for the generated types) uses
  `after` and `next_cursor`. The console follows the spec.

**4. [Rule 3] Files outside the planned list**
- `src/lib/utils.ts` (shadcn helper), `src/lib/format.ts` (date formatting), `src/components/ProblemAlert.tsx`
  (problem-error state shared by the list and detail pages), `src/routeTree.gen.ts`. `.gitignore` also ignores
  `admin-ui/*.tsbuildinfo` (written by `tsc -b`).

## Deferred Issues

None. End-to-end behaviour (a real sign-in against anvilid) depends on 03-21 (console client upsert) and
03-22 (serving at /console/*). 03-25's Playwright spec covers it.

## Self-Check: PASSED
