#!/usr/bin/env bash
# Provisions a freshly started anvilid for the OpenID conformance suite, using only public interfaces:
#
#   1. completes first-run setup through the /setup page (GET for the CSRF token and flow cookie, then
#      POST an admin email and a random password) and reads the management client credentials from
#      the result page (#mgmt-client-id, #mgmt-client-secret),
#   2. gets an admin access token from the system tenant's token endpoint (client_credentials),
#   3. creates the static clients the suite expects in the default tenant through the admin API: the
#      three Basic/Config/Form Post/RP-Initiated Logout clients plus a separate back-channel logout client,
#   4. creates a user with every standard claim,
#   5. renders tests/conformance/config.template.json into <out-config> (all plans except Back-Channel
#      Logout) and into <out-backchannel-config> (Back-Channel Logout plan; `client` is the back-channel
#      client there).
#
# Usage: setup.sh [--public] <setup-url> <out-config> <out-backchannel-config>
#
# Local mode (default, used by run.sh and CI): the setup URL's host is resolved to 127.0.0.1 (the suite
# reaches the same listener as host.docker.internal from inside Docker). The certificate is self-signed,
# so curl runs with -k. The suite callbacks point at the self-hosted suite
# (https://localhost.emobix.co.uk:8443).
#
# Public mode (--public, for the hosted suite used for certification, see docs/CERTIFICATION.md): the
# setup URL must be https and is reached through normal DNS resolution with normal TLS verification
# (no --resolve, no -k), so the deployment needs a publicly trusted certificate. The suite callbacks
# point at SUITE_URL (default https://www.certification.openid.net).
#
# Optional environment (both modes):
#   SUITE_URL    suite base URL for the client callbacks (local default https://localhost.emobix.co.uk:8443,
#                public default https://www.certification.openid.net)
#   SUITE_ALIAS  suite alias (default anvilid). The callbacks are SUITE_URL/test/a/SUITE_ALIAS/...; a
#                different alias is also written into the rendered configs.
#
# Secrets (admin password, management secret, client secrets, user password) are never printed; they
# only end up in the two config files, which the caller keeps in a temporary directory and deletes on exit.
set -euo pipefail

log() { printf '[conformance-setup] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

USAGE="usage: setup.sh [--public] <setup-url> <out-config> <out-backchannel-config>"
PUBLIC=0
if [[ "${1:-}" == "--public" ]]; then
  PUBLIC=1
  shift
fi
[[ $# -eq 3 ]] || die "$USAGE"
SETUP_URL="$1"
OUT_CONFIG="$2"
OUT_BACKCHANNEL_CONFIG="$3"
TEMPLATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.template.json"
[[ -f "$TEMPLATE" ]] || die "missing $TEMPLATE"

# Suite callback base. The self-hosted suite's public name is localhost.emobix.co.uk:8443, the hosted
# suite is www.certification.openid.net; each client alias gets /test/a/{alias}/callback.
if [[ "$PUBLIC" -eq 1 ]]; then
  SUITE_URL="${SUITE_URL:-https://www.certification.openid.net}"
  [[ "$SETUP_URL" == https://* ]] || die "--public needs an https setup URL"
else
  SUITE_URL="${SUITE_URL:-https://localhost.emobix.co.uk:8443}"
fi
SUITE_URL="${SUITE_URL%/}"
SUITE_ALIAS="${SUITE_ALIAS:-anvilid}"
[[ "$SUITE_ALIAS" =~ ^[A-Za-z0-9._-]+$ ]] || die "SUITE_ALIAS may only contain letters, digits, '.', '_' and '-'"
SUITE_BASE="${SUITE_URL}/test/a/${SUITE_ALIAS}"
SUITE_CALLBACK="${SUITE_BASE}/callback"
# Logout endpoints of the suite for the same alias (suite: CreatePostLogoutRedirectUri,
# CreateBackchannelLogoutUri, both `base_url` + fixed suffix).
SUITE_POST_LOGOUT="${SUITE_BASE}/post_logout_redirect"
SUITE_BACKCHANNEL="${SUITE_BASE}/backchannel_logout"

# Base URL (scheme://host:port) and the host:port pair to pin to loopback (local mode only).
BASE_URL=$(python3 -c 'import sys,urllib.parse as u;p=u.urlsplit(sys.argv[1]);print(f"{p.scheme}://{p.netloc}")' "$SETUP_URL")
HOSTPORT=$(python3 -c 'import sys,urllib.parse as u;p=u.urlsplit(sys.argv[1]);print(f"{p.hostname}:{p.port or 443}")' "$SETUP_URL")

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
JAR="$WORK/cookies"

curl_() {
  if [[ "$PUBLIC" -eq 1 ]]; then
    curl -sS --fail-with-body "$@"
  else
    curl -sS -k --fail-with-body --resolve "${HOSTPORT}:127.0.0.1" "$@"
  fi
}

rand() { python3 -c 'import secrets;print(secrets.token_urlsafe(24))'; }

# Extracts things from HTML with the standard library only.
html_get() {
  # $1 = mode (form-action | input-value:<name> | id-text:<id>), $2 = file
  python3 - "$1" "$2" <<'PY'
import html.parser, sys
mode, path = sys.argv[1], sys.argv[2]
class P(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = None
        self.capture = False
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if mode == "form-action" and tag == "form" and self.out is None:
            self.out = a.get("action", "")
        elif mode.startswith("input-value:") and tag == "input" and a.get("name") == mode.split(":", 1)[1]:
            self.out = a.get("value", "")
        elif mode.startswith("id-text:") and a.get("id") == mode.split(":", 1)[1]:
            self.capture = True
            self.out = ""
    def handle_endtag(self, tag):
        self.capture = False
    def handle_data(self, data):
        if self.capture:
            self.out += data
p = P()
p.feed(open(path, encoding="utf-8").read())
if not p.out:
    sys.exit(f"not found: {mode}")
print(p.out.strip())
PY
}

json_get() {
  # $1 = key, reads JSON from stdin
  python3 -c 'import json,sys;v=json.load(sys.stdin)[sys.argv[1]];print(v)' "$1"
}

# --- 1. First-run setup -------------------------------------------------------------------------
log "completing first-run setup"
curl_ -c "$JAR" -b "$JAR" -o "$WORK/setup.html" "$SETUP_URL"
action=$(html_get form-action "$WORK/setup.html")
csrf=$(html_get input-value:csrf_token "$WORK/setup.html")
token=$(html_get input-value:token "$WORK/setup.html")
admin_email="admin@example.com"
admin_password=$(rand)
curl_ -c "$JAR" -b "$JAR" -o "$WORK/setup_done.html" \
  --data-urlencode "csrf_token=$csrf" \
  --data-urlencode "token=$token" \
  --data-urlencode "email=$admin_email" \
  --data-urlencode "password=$admin_password" \
  "$action"
mgmt_id=$(html_get id-text:mgmt-client-id "$WORK/setup_done.html") \
  || die "setup did not complete (no #mgmt-client-id on the result page)"
mgmt_secret=$(html_get id-text:mgmt-client-secret "$WORK/setup_done.html")
token_endpoint=$(html_get id-text:token-endpoint "$WORK/setup_done.html")
admin_api=$(html_get id-text:admin-api-base "$WORK/setup_done.html")

# --- 2. Admin access token ------------------------------------------------------------------------
log "requesting an admin access token"
admin_at=$(curl_ -u "$mgmt_id:$mgmt_secret" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=admin:read admin:write" \
  "$token_endpoint" | json_get access_token)

admin_post() {
  # $1 = path below the admin API base, $2 = JSON body; prints the response body
  printf '%s' "$2" | curl_ -X POST -H "Authorization: Bearer $admin_at" \
    -H "Content-Type: application/json" --data-binary @- "${admin_api%/}$1"
}

# --- 3. Static clients ------------------------------------------------------------------------------
# require_pkce=false: the Basic OP plan does not send PKCE (confidential clients may opt out, C1).
# consent_mode=skip_first_party: the suite's browser automation signs in but does not answer a
# consent screen (new clients default to consent_mode=required).
# token_format=jwt: the default, stated explicitly so the suite always sees JWT access tokens.
# Logout metadata ($3, $4):
#   - post_logout_redirect_uris: the RP-Initiated Logout modules (static client) send the suite's
#     /post_logout_redirect and expect the OP to return there.
#   - backchannel_logout_uri (+ backchannel_logout_session_required): only on the dedicated back-channel
#     client. A suite module answers any request it does not expect with a FAILURE, so a back-channel
#     logout token POSTed while an RP-Initiated Logout (or Basic) module is running would fail it. The
#     Back-Channel plan therefore runs with its own config whose `client` is this client.
create_client() {
  # $1 = client name, $2 = auth method, $3 = post-logout redirect URI or "", $4 = back-channel
  # logout URI or ""; prints "client_id client_secret"
  local body
  body=$(python3 - "$1" "$2" "$SUITE_CALLBACK" "${3:-}" "${4:-}" <<'PY'
import json, sys
name, method, cb, post_logout, backchannel = sys.argv[1:6]
client = {
    "name": name,
    "client_type": "confidential",
    "auth_method": method,
    "require_pkce": False,
    "redirect_uris": [cb],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email", "address", "phone"],
    "consent_mode": "skip_first_party",
    "token_format": "jwt",
}
if post_logout:
    client["post_logout_redirect_uris"] = [post_logout]
if backchannel:
    client["backchannel_logout_uri"] = backchannel
    client["backchannel_logout_session_required"] = True
print(json.dumps(client))
PY
)
  admin_post "/tenants/default/clients" "$body" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["client_id"], d["client_secret"])'
}

log "creating static clients"
read -r client1_id client1_secret < <(create_client "conformance client" client_secret_basic "$SUITE_POST_LOGOUT")
read -r client2_id client2_secret < <(create_client "conformance client2" client_secret_basic)
read -r post_id post_secret < <(create_client "conformance client_secret_post" client_secret_post)
read -r bcl_id bcl_secret < <(create_client "conformance back-channel logout client" client_secret_basic \
  "$SUITE_POST_LOGOUT" "$SUITE_BACKCHANNEL")
[[ -n "${client1_id:-}" && -n "${client2_id:-}" && -n "${post_id:-}" && -n "${bcl_id:-}" ]] \
  || die "client creation failed"

# --- 4. User with every standard claim -----------------------------------------------------------------
log "creating the test user"
user_email="conformance.user@example.com"
user_password=$(rand)
user_body=$(python3 - "$user_email" "$user_password" <<'PY'
import json, sys
email, password = sys.argv[1:3]
print(json.dumps({
    "email": email,
    "email_verified": True,
    "password": password,
    "username": "conformance",
    "claims": {
        "name": "Conformance Tester",
        "given_name": "Conformance",
        "family_name": "Tester",
        "middle_name": "Q",
        "nickname": "conf",
        "preferred_username": "conformance",
        "profile": "https://example.com/conformance",
        "picture": "https://example.com/conformance.png",
        "website": "https://example.com",
        "gender": "other",
        "birthdate": "1990-01-01",
        "zoneinfo": "Europe/Berlin",
        "locale": "en-US",
        "phone_number": "+15555550100",
        "phone_number_verified": True,
        "address": {
            "formatted": "1 Example Street\n12345 Example City\nExample Country",
            "street_address": "1 Example Street",
            "locality": "Example City",
            "region": "Example Region",
            "postal_code": "12345",
            "country": "Example Country",
        },
    },
}))
PY
)
admin_post "/tenants/default/users" "$user_body" > /dev/null

# --- 5. Suite configuration ---------------------------------------------------------------------------------
log "writing the suite configurations"
mkdir -p "$(dirname "$OUT_CONFIG")" "$(dirname "$OUT_BACKCHANNEL_CONFIG")"
umask 077
render_config() {
  # $1 = output file, $2 = client_id, $3 = client_secret for the suite's `client` section
  BASE_URL="$BASE_URL" CLIENT_ID="$2" CLIENT_SECRET="$3" \
  CLIENT2_ID="$client2_id" CLIENT2_SECRET="$client2_secret" \
  POST_CLIENT_ID="$post_id" POST_CLIENT_SECRET="$post_secret" \
  USER_EMAIL="$user_email" USER_PASSWORD="$user_password" SUITE_ALIAS="$SUITE_ALIAS" \
  python3 - "$TEMPLATE" "$1" <<'PY'
import json, os, sys
template, out = sys.argv[1:3]
text = open(template, encoding="utf-8").read()
values = {
    "@BASE_URL@": "BASE_URL",
    "@CLIENT_ID@": "CLIENT_ID",
    "@CLIENT_SECRET@": "CLIENT_SECRET",
    "@CLIENT2_ID@": "CLIENT2_ID",
    "@CLIENT2_SECRET@": "CLIENT2_SECRET",
    "@POST_CLIENT_ID@": "POST_CLIENT_ID",
    "@POST_CLIENT_SECRET@": "POST_CLIENT_SECRET",
    "@USER@": "USER_EMAIL",
    "@PASSWORD@": "USER_PASSWORD",
}
for placeholder, env in values.items():
    # Values are JSON-escaped (without the surrounding quotes) before substitution.
    text = text.replace(placeholder, json.dumps(os.environ[env])[1:-1])
config = json.loads(text)  # must still be valid JSON
if config.get("alias") != os.environ["SUITE_ALIAS"]:
    # Only a non-default alias rewrites the file; the default keeps the template's formatting.
    config["alias"] = os.environ["SUITE_ALIAS"]
    text = json.dumps(config, indent=2) + "\n"
open(out, "w", encoding="utf-8").write(text)
PY
}
render_config "$OUT_CONFIG" "$client1_id" "$client1_secret"
render_config "$OUT_BACKCHANNEL_CONFIG" "$bcl_id" "$bcl_secret"
log "configurations written to $OUT_CONFIG and $OUT_BACKCHANNEL_CONFIG"
