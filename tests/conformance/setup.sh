#!/usr/bin/env bash
# Provisions a freshly started anvilid for the OpenID conformance suite, using only public interfaces:
#
#   1. completes first-run setup through the /setup page (GET for the CSRF token and flow cookie, then
#      POST an admin email and a random password) and reads the management client credentials from
#      the result page (#mgmt-client-id, #mgmt-client-secret),
#   2. gets an admin access token from the system tenant's token endpoint (client_credentials),
#   3. creates the three static clients the suite expects in the default tenant through the admin API,
#   4. creates a user with every standard claim,
#   5. renders tests/conformance/config.template.json into <out-config>.
#
# Usage: setup.sh <setup-url> <out-config>
#
# The setup URL's host is resolved to 127.0.0.1 (the suite reaches the same listener as
# host.docker.internal from inside Docker). The certificate is self-signed, so curl runs with -k.
# Secrets (admin password, management secret, client secrets, user password) are never printed; they
# only end up in <out-config>, which the caller keeps in a temporary directory and deletes on exit.
set -euo pipefail

log() { printf '[conformance-setup] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

[[ $# -eq 2 ]] || die "usage: setup.sh <setup-url> <out-config>"
SETUP_URL="$1"
OUT_CONFIG="$2"
TEMPLATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.template.json"
[[ -f "$TEMPLATE" ]] || die "missing $TEMPLATE"

# Suite callback base. The suite's public name is localhost.emobix.co.uk:8443; each client alias
# gets /test/a/{alias}/callback.
SUITE_ALIAS="anvilid"
SUITE_CALLBACK="https://localhost.emobix.co.uk:8443/test/a/${SUITE_ALIAS}/callback"

# Base URL (scheme://host:port) and the host:port pair to pin to loopback.
BASE_URL=$(python3 -c 'import sys,urllib.parse as u;p=u.urlsplit(sys.argv[1]);print(f"{p.scheme}://{p.netloc}")' "$SETUP_URL")
HOSTPORT=$(python3 -c 'import sys,urllib.parse as u;p=u.urlsplit(sys.argv[1]);print(f"{p.hostname}:{p.port or 443}")' "$SETUP_URL")

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
JAR="$WORK/cookies"

curl_() {
  curl -sS -k --fail-with-body --resolve "${HOSTPORT}:127.0.0.1" "$@"
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
create_client() {
  # $1 = client name, $2 = auth method; prints "client_id client_secret"
  local body
  body=$(python3 - "$1" "$2" "$SUITE_CALLBACK" <<'PY'
import json, sys
name, method, cb = sys.argv[1:4]
print(json.dumps({
    "name": name,
    "client_type": "confidential",
    "auth_method": method,
    "require_pkce": False,
    "redirect_uris": [cb],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email", "address", "phone"],
    "consent_mode": "skip_first_party",
    "token_format": "jwt",
}))
PY
)
  admin_post "/tenants/default/clients" "$body" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["client_id"], d["client_secret"])'
}

log "creating static clients"
read -r client1_id client1_secret < <(create_client "conformance client" client_secret_basic)
read -r client2_id client2_secret < <(create_client "conformance client2" client_secret_basic)
read -r post_id post_secret < <(create_client "conformance client_secret_post" client_secret_post)

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
log "writing the suite configuration"
mkdir -p "$(dirname "$OUT_CONFIG")"
umask 077
BASE_URL="$BASE_URL" CLIENT_ID="$client1_id" CLIENT_SECRET="$client1_secret" \
CLIENT2_ID="$client2_id" CLIENT2_SECRET="$client2_secret" \
POST_CLIENT_ID="$post_id" POST_CLIENT_SECRET="$post_secret" \
USER_EMAIL="$user_email" USER_PASSWORD="$user_password" \
python3 - "$TEMPLATE" "$OUT_CONFIG" <<'PY'
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
json.loads(text)  # must still be valid JSON
open(out, "w", encoding="utf-8").write(text)
PY
log "configuration written to $OUT_CONFIG"
