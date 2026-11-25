---
phase: 04-release-0-3-real-world-logins
plan: 22
subsystem: admin-console
tags: [console, theming, branding, preview, iframe, react, tanstack-router, ui-03]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-18 branding admin API (tenant and client scopes, preview -> {preview_url, token, expires_at, warnings}, publish {token}, logo {data}); 04-19 console patterns (ProblemAlert, field errors, ConfirmDialog)"
provides:
  - "/branding (tenant scope) and /branding/$clientId (client scope) console routes"
  - "ThemeEditor (tokens incl. optional dark set, font family, radius, logo, custom CSS)"
  - "ThemePreview + useBrandingPreview (debounced draft POST, stale-response guard, same-origin iframe)"
  - "Branding nav entry; Branding link on the client detail page"
affects: [04-29]

tech-stack:
  added: []
  patterns:
    - "Draft preview hook: the draft is serialised with a refresh key; a 300 ms timer per change, request counter + AbortController so only the newest response is applied"
    - "Publish uses the token of the preview of the current draft, renewed by an immediate preview POST when it is within 15 s of expiry"
    - "Colour tokens: native <input type=color> (value attribute only, no inline style) and a hex text field edit the same value; empty = inherit/default, the default hex is shown as placeholder"

key-files:
  created:
    - admin-ui/src/components/ThemeEditor.tsx
    - admin-ui/src/components/ThemePreview.tsx
    - admin-ui/src/routes/branding/index.tsx
    - admin-ui/src/routes/branding/$clientId.tsx
  modified:
    - admin-ui/src/components/AppShell.tsx
    - admin-ui/src/routeTree.gen.ts
    - admin-ui/src/routes/clients/$clientId.tsx

key-decisions:
  - "Logo changes are applied immediately (PUT/DELETE …/branding/logo), not through the draft: the 04-18 draft has no logo of its own. The editor says so and reloads the preview after a logo change"
  - "Publish is enabled only when the preview of the current draft succeeded (no pending request, no 422), so the published theme is exactly what the iframe shows"
  - "The iframe is sandboxed with allow-same-origin only (no scripts, forms or navigation), referrerpolicy no-referrer"
  - "Opening the editor POSTs a preview of the stored branding (replacing any earlier draft of that scope), so the iframe always shows something"
  - "The Branding link of a client sits in routes/clients/$clientId.tsx (route component), not in ClientForm, as the plan asks"

requirements-completed: []

duration: about 40 min
completed: 2026-11-25
---

# Phase 4 Plan 22: Console theme editor with live preview Summary

**Admins can now brand the tenant, or a single client, from the console. They edit colours (with an optional dark set), the font family, the corner radius, custom CSS and the logo, and the login/consent preview in a same-origin iframe updates about 300 ms after each change. "Publish" makes the draft live and "Reset" deletes the scope's branding.**

No requirement checkbox was ticked (shared rule). This is the console half of UI-03; 04-18 delivered the backend.

## Routes
| Route | Content |
|---|---|
| `/branding` | Tenant scope editor + preview. Nav entry "Branding" (after Email). |
| `/branding/$clientId` | Client scope editor + preview, back link to the client, link to the tenant branding. Reached from the "Branding" link on `/clients/$clientId`. |

Layout: editor sections on the left. On the right, a sticky column with Publish, Reset, the status line, errors and warnings, and the iframe.

## Behaviour
- **Colours:** primary, text on primary, background, surface, text, muted, border, focus and danger. Each colour has a native colour picker and a hex text field (`#rgb`, `#rrggbb`, `#rrggbbaa`). An empty field means the default (light or dark palette), and its hex shows as placeholder and hint. A "Default" button clears the value.
- **Dark colours:** a checkbox enables `colors_dark`. When it is off, the console sends `colors_dark: null`.
- **Typography:** font family text field with a `<datalist>` of system stacks. Radius is a range slider from 0 to 32. Empty is `null` and shows "6 px (default)" plus a "Default" button.
- **Logo:** file input that accepts PNG, JPEG or WebP. Type and size (256 KiB) are checked client-side. The selected file is previewed as a data: URL (console `img-src 'self' data:`). The current logo comes from `logo_url`. "Upload logo" sends `{data}` as standard base64. "Remove logo" asks for confirmation.
- **Custom CSS:** a textarea with a caret indicator ("Line X of N, column Y") for locating the API's `line N: …` errors.
- **Preview:** each change is debounced 300 ms, then the draft is POSTed to `…/branding/preview` and the iframe `src` is set to `preview_url` (title "Theme preview"). A response to a superseded draft is aborted or ignored. A 422 keeps the last valid preview and shows the errors.
- **Errors:** `colors.*`, `colors_dark.*`, `font_family`, `radius_px` and `custom_css` appear under their controls. The contrast errors `colors` and `colors_dark` appear under their colour grid. Any other field is listed above the sections. Non-422 failures show in a ProblemAlert.
- **Warnings:** contrast warnings (scheme, pair, ratio, message) appear under the light or dark colour grid and in the preview column.
- **Publish:** `POST …/publish {token}` with the current draft's token (renewed if it is close to expiry). A success message appears and the preview restarts.
- **Reset:** a ConfirmDialog, then `DELETE …/branding`. The editor reloads the stored (inherited) state. Reset is disabled while `customized` is false.
- **CSP:** no inline styles anywhere. Sizes come from Tailwind classes (`h-[720px]` iframe). Every control has a label, the hint and error ids are linked through `aria-describedby`/`aria-invalid`, the range has `aria-valuetext`, and status changes go through live regions.

## Test ids for e2e (04-29)
- Page/editor: `theme-editor`, `branding-state`, `draft-invalid`
- Sections: `theme-colors`, `theme-colors-dark`, `theme-typography`, `theme-logo`, `theme-custom-css`
- Colours: `color-{colors|colors_dark}.{primary|primary_text|bg|surface|text|muted|border|focus|danger}` (hex text field), `color-picker-…` (native picker), `dark-enabled`
- Typography: `font-family`, `radius`, `radius-value`
- Logo: `logo-file`, `logo-upload`, `logo-remove`, `logo-current`, `logo-none`, `logo-selected`
- CSS: `custom-css`, `custom-css-caret`
- Warnings: `contrast-warnings-light`, `contrast-warnings-dark`, `preview-warnings`
- Preview: `theme-preview`, `preview-status` (text "Preview is up to date." once settled), `preview-errors`, `theme-preview-frame` (iframe, title "Theme preview")
- Actions: `publish-theme`, `reset-theme` (confirm button "Remove branding"), client page link `client-branding-link`
- Field errors render as `[data-field-error]` lists under the control. Accessible labels include "Primary", "Primary colour picker", "Font family", "Corner radius", "Logo image" and "Custom CSS".

## Task Commits
1. **Task 1:** `b60c976` feat(04-22): console theme editor with live preview

## Verification
- `npm run typecheck`: clean.
- `npm run build` (`tsc -b`, vite build, compression): passes. `admin-ui/dist` is gitignored, so no build output was committed.
- `npm run check:api`: schema.d.ts up to date (not edited).
- Route tree: regenerated by the vite build and committed. A second build left it byte-identical, and `git diff --exit-code -- admin-ui/src/routeTree.gen.ts` is clean.

## Not run
- **Browser / e2e:** there are no console unit tests, and the console e2e for branding belongs to 04-29. The editor was not run against a live `anvilid serve`, so the iframe framing (the preview page sends `frame-ancestors 'self'` and `X-Frame-Options: SAMEORIGIN`) and the sandbox attribute were not exercised in a real browser.
- **Lint:** admin-ui has no lint script.

## Deviations from Plan

### Auto-fixed Issues
**1. [Rule 3 - Blocking] Forced extra file `admin-ui/src/routes/clients/$clientId.tsx`**
- The plan asks for a "Branding" link on the client detail page, placed in the route component, but that file was not in `files_modified`. The change is additive: the heading row gains a `Link` to `/branding/$clientId`. Commit b60c976.

**2. [Build order] Route tree generation before `tsc -b`**
- `npm run build` runs `tsc -b` before vite, so the first build after adding the route files failed on the stale route tree. One `npx vite build` regenerated `routeTree.gen.ts`, and after that `npm run typecheck` and `npm run build` passed. This is a property of the existing build script; the script was not changed.

### Notes
- The scope API helpers live in the two components because the plan's file list has no lib file: preview and publish in ThemePreview.tsx, and get, logo and delete in ThemeEditor.tsx and the routes.
- Opening the editor creates a preview draft for the scope, and each preview replaces the scope's earlier draft (04-18 contract). Two admins editing the same scope at the same time replace each other's drafts. If that happens, Publish shows the API's 404 in a ProblemAlert.

## Self-Check: PASSED
