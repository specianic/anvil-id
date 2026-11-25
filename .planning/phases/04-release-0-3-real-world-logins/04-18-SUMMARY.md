---
phase: 04-release-0-3-real-world-logins
plan: 18
subsystem: theming
tags: [theming, branding, css, csp, preview, admin-api, openapi, ui-03]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-01 branding model/ports; 04-04/04-05 BrandingRepo; 04-02 pre-registered theme/preview/admin modules; 04-06 PageContext and catalogs; 04-09 policy::branding; 04-11 admin API conventions"
provides:
  - "anvil_core::service::branding::{BrandingService, BrandingInput, PreviewToken, EffectiveTheme, LogoRef, PREVIEW_TTL, validate_input, is_sha256_hex}"
  - "GET {tenant_base}/theme/theme.css[?flow={id}|?preview={token}] and GET {tenant_base}/theme/logo/{sha256}"
  - "PageContext.theme_css; Renderer::page appends ?flow= for flow-bound pages; base.html theme link + .anvil-logo element"
  - "GET /ui/preview?token= (the only page framable by self)"
  - "Branding admin API (14 operations, tag branding); OpenAPI 51 operations; console schema.d.ts regenerated"
  - "Per-request body limit: 64 KiB everywhere, 400 KiB only for the logo upload"
affects: [04-22, 04-29, 04-31]

tech-stack:
  added: []
  patterns:
    - "Page stylesheet = merged variables + generated logo rule + tenant custom CSS + client custom CSS; ETag = strong_etag(body)"
    - "Client scope of a page resolved server-side from ?flow= (flow -> auth request -> client_id); any failure falls back to the tenant theme silently"
    - "Logo URL in the generated CSS is relative (url(\"logo/{sha}\")), resolved against the stylesheet URL, so the same CSS works for root, path and host tenants"

key-files:
  created:
    - crates/anvil-web/tests/theme.rs
    - crates/anvil-web/tests/admin_branding.rs
    - crates/anvil-web/tests/security_theme.rs
    - themes/default/templates/preview.html
    - themes/default/locales/en/preview.ftl
  modified:
    - crates/anvil-core/src/service/branding.rs
    - crates/anvil-web/src/theme.rs
    - crates/anvil-web/src/render.rs
    - crates/anvil-web/src/ui/preview.rs
    - crates/anvil-web/src/admin/mod.rs
    - crates/anvil-web/src/admin/branding.rs
    - crates/anvil-web/src/lib.rs
    - crates/anvil-web/tests/openapi_drift.rs
    - themes/default/templates/base.html
    - themes/default/README.md
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts

key-decisions:
  - "Logo upload is JSON {data: standard base64} decoded with anvil_jose::encoding::b64std_decode (works with openapi-fetch from the console without a custom body serializer)"
  - "Publish takes the preview token ({token}); the draft must belong to the addressed scope, else 404. The port has no draft-by-scope read, and the console already holds the token"
  - "The global 64 KiB request limit became a per-request middleware: 400 KiB only for /api/admin/v1/tenants/*/branding/logo, BODY_LIMIT for everything else (stream and extractor limits both)"
  - "Branding routes use the admin:settings scope family like connections; system tenant writes also need admin:write"
  - "GET of an uncustomised scope answers 200 with customized:false (not 404), so the editor can always load"
  - "Contrast warnings and validation are per scope; a client's tokens are not re-checked against the merged tenant palette"
  - "Draft has no logo of its own: the preview shows the scope's live logo (client logo, else tenant logo)"

requirements-completed: []

duration: about 1h 30min (interrupted once)
completed: 2026-11-25
---

# Phase 4 Plan 18: Theming backend, branding API and preview Summary

**Tenants and clients can now be branded through the management API: theme tokens, custom CSS and a logo, all validated by `policy::branding`, audited as `branding_updated`, and served as one generated same-origin stylesheet per page under the unchanged strict CSP. The console can store a draft and frame a 15-minute preview page, then publish it.**

No requirement checkbox was ticked (shared rule). This plan delivers the backend of UI-03; the editor is 04-22.

## CSS route format

- `GET {tenant_base}/theme/theme.css` - tenant theme.
- `?flow={uuid}` - the flow's authorization request decides the client; client tokens override tenant tokens per field, client custom CSS follows the tenant's. Unknown, expired, malformed or other-tenant flows, and flows without a request, fall back to the tenant theme (no error, no oracle).
- `?preview={token}` - the draft (tenant draft alone, or client draft over the live tenant branding); unknown/expired/other-tenant token -> 404.
- Headers: `Content-Type: text/css; charset=utf-8`, `Cache-Control: no-cache`, `ETag` = quoted hex SHA-256 of the body (`http_cache::strong_etag`); `If-None-Match` -> 304.
- Body: `:root{…}` variables (omitted when nothing is customised), then `.anvil-logo{display:none}` or the logo rule with `background-image:url("logo/{sha256}")` (relative to the stylesheet), then custom CSS. An unbranded tenant gets exactly `.anvil-logo{display:none}\n`.
- `GET {tenant_base}/theme/logo/{sha256}`: stored type (png/jpeg/webp only), `Cache-Control: public, max-age=31536000, immutable`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`; other tenants' hashes and malformed hashes -> 404.
- Pages: `<link rel="stylesheet" href="{{ page.theme_css }}">` right after anvil.css and `<span class="anvil-logo" role="img" aria-label="{tenant name}">` before the tenant name, only when `page.theme_css` is set (tenant pages). `Renderer::page` adds `?flow={uuid}` when `form.action` or `action` carries `?flow=`; no UI handler was edited.

## API shapes (`/api/admin/v1/tenants/{slug}/branding` and `…/clients/{client_id}/branding`)

| Method | Suffix | Operation ids | Body | Response |
|---|---|---|---|---|
| GET | | getTenantBranding / getClientBranding | - | `BrandingView` |
| PUT | | putTenantBranding / putClientBranding | `PutBranding` | `BrandingView` (warnings) |
| DELETE | | deleteTenantBranding / deleteClientBranding | - | 204; 404 if none |
| PUT | `/logo` | putTenantBrandingLogo / putClientBrandingLogo | `{data: base64}` | `BrandingView` |
| DELETE | `/logo` | deleteTenantBrandingLogo / deleteClientBrandingLogo | - | `BrandingView`; 404 if no logo |
| POST | `/preview` | previewTenantBranding / previewClientBranding | `PutBranding` | `BrandingPreview` |
| POST | `/publish` | publishTenantBranding / publishClientBranding | `{token}` | `BrandingView` |

- `PutBranding { tokens: { colors: {primary, primary_text, bg, surface, text, muted, border, focus, danger}, colors_dark: same|null, font_family, radius_px }, custom_css }` (unknown fields refused).
- `BrandingView { scope: tenant|client, client_id, customized, tokens, custom_css, logo_url (/t/{slug}/theme/logo/{sha}), updated_at, warnings }`.
- `ThemeWarningDto { scheme: light|dark, pair: text_on_background|text_on_surface|primary_text, ratio, message }`.
- Errors: 422 problem with `errors[0].field` = `colors.primary` … `colors_dark.danger`, `radius_px`, `font_family`, `colors`/`colors_dark` (contrast < 3:1), `custom_css` (message `line N: …`), `logo`, `data` (bad base64), `body`. Unknown client -> 404.
- Scopes: read = `admin:settings:read|write`, `admin:read|write`; write = `admin:settings:write`, `admin:write`; system tenant writes need `admin:write`.

## Preview URL contract

- `preview_url` = `/t/{slug}/ui/preview?token={43-char base64url}` for every tenant (path form, same origin as the console), `expires_at` = now + 15 min, `token` is also returned (needed for publish).
- The page renders static sample sign-in and consent markup with the real classes, a "Preview" banner, and links `{base}/theme/theme.css?preview={token}`. Headers: page CSP with `frame-ancestors 'self'`, `X-Frame-Options: SAMEORIGIN`, `Cache-Control: no-store`. Bad/expired/other-tenant token -> 404 page with the default `frame-ancestors 'none'`.
- Each preview POST replaces the scope's previous draft (its old token stops working).

## Task Commits
1. `012e39a` feat(04-18): BrandingService, theme stylesheet and logo routes, theme link in pages
2. `192d258` feat(04-18): branding admin API, theme preview page, OpenAPI and console types

## Verification (main tree, SQLite)
- `cargo test -p anvil-core --lib service::branding`: 4 passed.
- `cargo test -p anvil-web --test theme --test admin_branding --test security_theme --test openapi_drift`: 6 + 6 + 6 + 3 passed.
- `cargo test -p anvil-web --lib --test render --test security_csp --test i18n --test shell --test consent --test flow_login --test security_ratelimit --test admin_api --test security_admin --test admin_connections --test admin_api_v03 --test security_csrf --test console --test security_tenant`: all green (render snapshots unchanged: the theme link and logo element only render when `page.theme_css` is set).
- `cargo clippy -p anvil-core --all-targets` and `-p anvil-web --lib --test theme --test security_theme --test admin_branding -D warnings`: clean for these files; `rustfmt --edition 2024` on every touched Rust file.
- `just openapi-update`, `npm run gen:api`, `npm run check:api` (up to date), `npm run typecheck` (clean).

## Not run
- Postgres (`ANVILID_TEST_DB=postgres …`): Docker not relied on; left for CI. No SQL was added (repositories are 04-04/04-05).
- `npm run build` and the full `cargo test -p anvil-web`: another plan's uncommitted `tests/backchannel.rs` did not compile during this session, so only targeted suites ran.
- `account_security::removing_a_passkey_works_without_javascript_and_only_for_its_owner` failed in the main tree (an extra `SessionRevoked` audit row) from another plan's in-progress account/MFA work; unrelated to theming.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Body limit for the logo upload (crates/anvil-web/src/lib.rs)**
- The installation-wide 64 KiB request limit made the plan's 256 KiB logo impossible. The two global layers were replaced by one middleware (`admin::branding::body_limit`) that applies the same `RequestBodyLimitLayer` and `DefaultBodyLimit` per request: 400 KiB only for `/api/admin/v1/tenants/*/branding/logo`, 64 KiB otherwise. A test proves another admin route still answers 413 above 64 KiB.

**2. [Rule 3] Forced extra files**
- `crates/anvil-web/tests/openapi_drift.rs`: operation count 37 -> 51.
- `themes/default/README.md`: documents `page.theme_css`.

**3. [Design] Publish identifies the draft by its preview token** (no draft-by-scope read in `BrandingRepo`).

**4. [Design] Relative logo URL in the CSS** (`url("logo/{sha}")` instead of `{tenant_base}/theme/logo/{sha}`) - same resolved URL, same bytes for every tenant base.

**5. Branding DTOs live in admin/branding.rs** (not dto.rs, which is outside this plan's files).

**6. TDD shape**: tests landed with the implementation in each task commit.

## Gate item: purge of replaced logos - NOT done (out of scope)
Replaced and cleared logos stay in `branding_logo`. Logos are content-addressed per tenant and can be shared by several scopes, so a purge has to delete rows that no published branding row references, and it has to run inside the storage transaction. `BrandingRepo` has no such intent, and the storage crates (`anvil-storage-{sqlite,postgres}` `purge_expired` and the `.sqlx` metadata) are outside this plan's `files_modified`. A follow-up has to add the storage work: either extend `purge_expired` in both backends with `DELETE FROM branding_logo l WHERE NOT EXISTS (SELECT 1 FROM branding b WHERE b.tenant_id = l.tenant_id AND b.logo_sha256 = l.sha256)`, plus a contract test, or add a `BrandingRepo::purge_unreferenced_logos` intent. Related: deleting a client leaves its branding row behind (the same follow-up should cascade or purge it).

## Next Phase Readiness
- 04-22 (console editor) can use the operations above; the preview iframe needs only `preview_url`, and publish needs the `token` from the last preview response.

## Self-Check: PASSED
- Files exist: crates/anvil-core/src/service/branding.rs, crates/anvil-web/src/theme.rs, crates/anvil-web/tests/{theme,admin_branding,security_theme}.rs, themes/default/templates/preview.html.
- Commits 012e39a and 192d258 are in the history.
