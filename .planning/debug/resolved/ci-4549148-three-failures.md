---
status: resolved
trigger: "CI failures on main 4549148: healthcheck.rs:146 (sqlite), health_metrics.rs:535 (postgres), all console e2e specs (both backends). Runs ci 45755242931, e2e 45755242902."
created: 2026-11-26T00:00:00Z
updated: 2026-11-26T00:00:00Z
---

## Current Focus

hypothesis: all three root causes confirmed and fixed (commits 753ae4c, ed791a8, 8819d9d)
test: next CI run on main (ci + e2e, both backends)
expecting: green
next_action: human confirms CI green, then archive to resolved/

## Symptoms

expected: all three green in CI
actual:
  1. healthcheck_fails_when_not_ready_or_unreachable: "not ready: request failed: Broken pipe (os error 32)" instead of "503"
  2. request_span_carries_the_route_template_not_the_uri: http.request span found, but "no access log line"
  3. console e2e: toBeVisible failed ~5 s in, all console specs, both backends
errors: see above
reproduction: CI runs 45755242931 / 45755242902
started: 4549148 (main)

## Eliminated

## Evidence

- timestamp: 2026-11-26
  checked: healthcheck.rs probe() and test fake_server
  found: probe writes the request with write!() on an unbuffered TcpStream -> write_fmt issues one write(2) per fragment (~9 segments). fake_server does a single read() then responds and drops the socket with unread data (RST). Client's later fragment write -> EPIPE, probe returns "request failed" before reading the 503.
  implication: root cause of (1); timing-dependent (passes locally when all fragments arrive before read()).

- timestamp: 2026-11-26
  checked: tracing-core 0.1.36 callsite.rs
  found: Dispatchers::register_dispatch sets has_just_one = (len <= 1); with only the test's scoped Capture registered (no global), later callsite registrations use Rebuilder::JustOne -> get_default() of the registering thread. A callsite first hit by another test thread (NoSubscriber) after set_default is cached NEVER; no rebuild follows.
  implication: likely root cause of (2): access event callsite registered by a concurrent test's in-flight request (span callsite was registered before set_default and rebuilt, event callsite after).

- timestamp: 2026-11-26
  checked: strace of `anvilid healthcheck` against a fake server that reads 4 bytes then answers 503
  found: sendto "GET ", "/health/ready", then EPIPE -> exact CI message; after the fix one sendto and "status 503" (5/5)
  implication: (1) confirmed and fixed

- timestamp: 2026-11-26
  checked: request_span test with a thread that hits observe() on a fresh TestApp right after set_default
  found: deterministic failure (no spans/events captured); with the global thread-gated subscriber it passes; binary green 5/5
  implication: (2) confirmed and fixed

- timestamp: 2026-11-26
  checked: local e2e (release binary + console, fresh sqlite data dir), DB after console-tenants failure
  found: reproduced identical page (403 "requires read access to tenants"); the console-login user is a second system user with no role_assignment; only the setup admin holds `administrator`. Token family scope requested "admin:read admin:write openid"; 05-12 bounds issued admin scopes by roles -> none
  implication: (3) is the e2e helper: specs create role-less system users. Product behaviour is intended (security_rbac user_without_roles_gets_no_admin_scope)

## Resolution

root_cause: (1) probe sent the request with write!() on an unbuffered TcpStream (one syscall per fragment); fake server answered after one read and closed -> EPIPE. (2) scoped set_default capture + tracing-core has_just_one: callsite first registered on another test thread after set_default is cached never. (3) console e2e specs log in as a system user without the administrator role; since 05-12 such tokens get no admin scope.
fix: (1) single write_all in probe + fake server reads full head. (2) global subscriber gated by a thread-local Recording. (3) createConsoleAdmin helper assigns the administrator role.
verification: local runs as listed in Evidence; console.spec passes with only the Mailpit step skipped
files_changed: [crates/anvilid/src/healthcheck.rs, crates/anvilid/tests/healthcheck.rs, crates/anvil-web/tests/health_metrics.rs, tests/e2e/lib/anvil.ts, tests/e2e/lib/console.ts, tests/e2e/specs/console.spec.ts, tests/e2e/specs/console-tenants.spec.ts, tests/e2e/specs/console-connections.spec.ts, tests/e2e/specs/theme.spec.ts]
