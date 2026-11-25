#!/usr/bin/env bash
# scripts/check-console-embedded.sh: release artifacts always embed the admin console.
#
#   scripts/check-console-embedded.sh            admin-ui/dist/index.html exists (before a build)
#   scripts/check-console-embedded.sh <binary>   additionally, <binary> embeds that build: the
#                                                content-hashed entry script named by index.html
#                                                appears in the binary
#
# The console is embedded with rust-embed `allow_missing` (crates/anvil-web/src/console.rs), so a
# build without admin-ui/dist succeeds and serves a placeholder at /console/. That is fine for a
# contributor's debug build but never for a release. The binary check also catches a stale cached
# target/ that was compiled before admin-ui/dist existed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INDEX="$ROOT/admin-ui/dist/index.html"

if [[ ! -f "$INDEX" ]]; then
    echo "error: $INDEX is missing; build the console first (just console-build)" >&2
    exit 1
fi

entry=$(sed -nE 's#.*<script type="module"[^>]* src="/console/(assets/[^"]+\.js)".*#\1#p' "$INDEX" | head -n1)
if [[ -z "$entry" ]]; then
    echo "error: no /console/assets/*.js entry script in $INDEX" >&2
    exit 1
fi
if [[ ! -f "$ROOT/admin-ui/dist/$entry" ]]; then
    echo "error: entry script admin-ui/dist/$entry named by index.html does not exist" >&2
    exit 1
fi

if [[ $# -eq 0 ]]; then
    echo "check-console-embedded: admin-ui/dist present (entry $entry)"
    exit 0
fi

bin=$1
if [[ ! -f "$bin" ]]; then
    echo "error: binary $bin not found" >&2
    exit 1
fi
if ! LC_ALL=C grep -aqF "$entry" "$bin"; then
    echo "error: $bin does not embed the console build (no $entry); rebuild after the console" >&2
    exit 1
fi
echo "check-console-embedded: $bin embeds the console (entry $entry)"
