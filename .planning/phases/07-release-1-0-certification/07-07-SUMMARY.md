---
phase: 07-release-1-0-certification
plan: 07
subsystem: docs-site
tags: [docs, mdbook, ci, QUAL-03]
requires: []
provides:
  - "mdBook 0.5.4 site config (book.toml: src = docs, create-missing = false, build-dir = book, site-url /anvil-id/)"
  - "docs/SUMMARY.md over the existing public docs + docs/introduction.md"
  - "scripts/check-docs-site.sh: external-asset, tracking, research and broken-link rules, --self-test with 14 cases"
  - ".github/workflows/docs.yml: build + check + Pages artifact; deploy only on workflow_dispatch with publish: true"
  - "docs/*.md contain no ../ links (rewritten to absolute GitHub URLs on main)"
affects: [07-17 (OPERATIONS), 07-21 (UPGRADING), 07-22 (Phase 7 pages in SUMMARY, MCP), 07-23 (gate confirms docs.yml green), 07-27 (owner enables Pages, confirms site-url, dispatches publish)]
tech-stack:
  added: ["mdBook 0.5.4 (CI tool only, via taiki-e/install-action)"]
  patterns:
    - "Docs pages link outside docs/ only via absolute https://github.com/specianic/anvil-id/blob/main/... URLs"
key-files:
  created:
    - book.toml
    - docs/SUMMARY.md
    - docs/introduction.md
    - scripts/check-docs-site.sh
    - .github/workflows/docs.yml
  modified:
    - .gitignore
    - docs/MCP.md
    - docs/OPERATIONS.md
    - docs/RELEASING.md
    - docs/UPGRADING.md
key-decisions:
  - "mdBook installed in CI with taiki-e/install-action (pinned mdbook@0.5.4 release binary, checksum verified by the action), matching how the repo already installs just/cargo-fuzz"
  - "A local build from a tree that has docs/research/ copies that directory into the output; the check fails on purpose. Documented in book.toml: build from a copy of docs/ without research/. CI checkouts never contain it"
  - "Rule 3 is strict: any `research/` string anywhere in the output (including the search index) fails, not just file paths"
metrics:
  duration: ~25min
  completed: 2026-11-26
---

# Phase 7 Plan 07: Documentation site Summary

mdBook 0.5.4 site built from docs/ with create-missing = false, a check script that blocks remote assets, tracking, research leaks and broken internal links (with a self-test per rule), and a docs.yml workflow that builds, checks and uploads the site, publishing only on an owner dispatch.

## What was built

- **book.toml**: `[book] title = "AnvilID", src = "docs"`; `[build] build-dir = "book", create-missing = false`;
  `[output.html] site-url = "/anvil-id/"` (default, the owner confirms it in 07-27), `git-repository-url`;
  built-in search enabled. No google-analytics, no additional-js/css.
- **Fonts and search verified local** on the built output: mdBook 0.5.4 writes `fonts/fonts-<hash>.css` whose
  `url()`s point at `../fonts/open-sans-*.woff2` in the output; no `[output.html.font]` setting was needed. Search
  is `elasticlunr` + `searchindex-<hash>.js` in the output. The only `http(s)` hrefs in the built site are `<a>`
  links to GitHub and the Standard Webhooks spec; no `<script>`/`<link>` loads another origin.
- **docs/SUMMARY.md**: Introduction; Operate (OPERATIONS, CONFIG-YAML, UPGRADING); Integrate (MCP, WEBHOOKS,
  ORGANIZATIONS, SAML, social-login-checklist); Design (PRD, ARCHITECTURE); Project (RELEASING). 07-22 adds the
  Phase 7 pages.
- **docs/introduction.md**: what AnvilID is and where to start, no claims about other products.
- **scripts/check-docs-site.sh `<book-dir>`** rules:
  1. `[external-asset]` `<script src>` / `<link href>` to `http:`, `https:` or `//`, and remote `url()`/`@import` in CSS/HTML;
  2. `[tracking]` Google Analytics/Tag Manager, gtag(), analytics.js, Plausible, Matomo/Piwik, Segment, Hotjar, Clarity, the word `analytics`;
  3. `[research]` any output path containing `research`, or any `research/` reference;
  4. `[broken-link]` relative `href`/`src` in HTML pages that does not resolve in the output (ignores `#anchors`,
     query strings, `http(s):`, `mailto:`, `data:`, `javascript:`, `tel:`; honours `<base href>` on the 404 page;
     `dir/` resolves to `dir/index.html`).
  `--self-test` builds a mktemp site shaped like mdBook output: a clean case (exit 0) and 13 rejections, each
  asserted by exit code and by the rule tag (external script, external link, protocol-relative script, remote
  @import, tag-manager, gtag, research dir, research reference, broken link, missing script, `../` outside the site,
  broken link under `<base href>`, missing book dir = exit 2).
- **.github/workflows/docs.yml** triggers: `pull_request` and `push` to main with path filters (docs/**, book.toml,
  scripts/check-docs-site.sh, .github/workflows/docs.yml) and `workflow_dispatch` with `publish` (boolean, default
  false). Job `build`: checkout@v7, install-action mdbook@0.5.4, `mdbook build`, self-test, site check,
  `actions/upload-pages-artifact@v4`. Job `deploy`: `if: github.event_name == 'workflow_dispatch' && inputs.publish`,
  `needs: build`, environment `github-pages`, permissions `pages: write, id-token: write` only,
  `actions/deploy-pages@v4`. Workflow-level permissions `contents: read`.
- **../ links rewritten** to `https://github.com/specianic/anvil-id/blob/main/...`: MCP.md (tests/mcp/README.md),
  OPERATIONS.md (deploy/README.md, deploy/helm/anvilid/README.md), RELEASING.md (.github/workflows/release.yml),
  UPGRADING.md (deploy/README.md). Nothing else in those pages changed. `grep -rnE '\]\(\.\./' docs/*.md` is empty.

## Verification

- `scripts/check-docs-site.sh --self-test`: 14/14 cases pass.
- mdBook 0.5.4 installed with `cargo install --locked --root <scratch>`; built from a scratch copy of docs/ without
  research/; `scripts/check-docs-site.sh <scratch>/book`: ok.
- create-missing: adding `- [Ghost](GHOST.md)` to a scratch SUMMARY fails the build (`failed to read chapter`) and
  creates no file.
- Building from the real tree (which has the local docs/research/) makes the check fail with `[research]`: the
  guard works.
- Task 2 automated verify (YAML parse, jobs, workflow_dispatch, check script, inputs.publish, 0.5.4): pass.
  actionlint is not installed locally.
- `scripts/check-release-graph.sh`: OK.
- Not run here: the docs.yml workflow itself (CI; confirmed at the 07-23 gate). The `upload-pages-artifact@v4` /
  `deploy-pages@v4` majors could not be checked against a run locally; CI will flag them if a newer major is required.
- Scratch dir (mdbook install, builds) deleted.

## Deviations from Plan

- mdBook in CI comes from `taiki-e/install-action` (pinned release binary, checksum verified) rather than a cached
  `cargo install`; the plan allowed either.
- Otherwise none: plan executed as written.

## Commits

- 6dd6ddc feat(07-07): mdBook docs site config, SUMMARY and site check script
- 4336195 ci(07-07): docs workflow builds and checks the site; owner-dispatched publish

## Self-Check: PASSED
