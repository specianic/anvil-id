# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project status

AnvilID is being **rebuilt from scratch (v2)**. The goal: the easiest open-source identity platform
to self-host (Keycloak-class capability, single binary, zero-config start), growing into an
Ory/Okta-style suite.

This repository starts from a clean history. No code is carried over from earlier prototypes.

## Source of truth

- `docs/PRD.md` — what we build and why.
- `docs/ARCHITECTURE.md` — how we build it: stack, module layout, data model, milestones.
- `docs/research/` — background research (local only, gitignored; not published).

When code and these docs disagree, raise it rather than silently diverging.

## Non-negotiable engineering rules

- No test hooks, mock fallbacks or hardcoded users/tenants in production code paths. Test doubles live
  in test code only.
- No stubs that return success. Unimplemented features return an explicit error or don't exist.
- One implementation per concern. Don't add a second token endpoint, rate limiter, or auth middleware.
- Every security check (redirect URI, PKCE, client auth, code single-use) must have a test proving
  that it rejects bad input.
- Persistence goes through the storage traits only. Handlers never touch the database directly.

## Reminders

- This repository is public. Never commit secrets, keys, internal hostnames or personal data, and
  keep unverified claims about other products out of committed docs.
