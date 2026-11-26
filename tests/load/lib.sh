# shellcheck shell=bash
# tests/load/lib.sh: helpers shared by run-perf.sh and run-ha.sh (sourced, not executed).
#
# Needs: bash, curl, python3 (HTML/JSON parsing, standard library only), docker compose, and k6
# (on PATH, or the pinned grafana/k6 image through docker). No secret is written to disk outside
# the caller's private temp dir ($LOAD_TMP, mode 700).

# k6 container image used when no k6 binary is on PATH (CI installs the binary; same version).
K6_VERSION=2.4.0
K6_IMAGE="grafana/k6:${K6_VERSION}@sha256:d41bb79cd8de5a7ad619b53570e3712633e8bff0937010a5c6c57a4747e7a276"

log() { echo "==> $*" >&2; }
die() {
    echo "error: $*" >&2
    exit 1
}

# require_tools <tool...>
require_tools() {
    local t
    for t in "$@"; do
        command -v "$t" >/dev/null 2>&1 || die "$t is required"
    done
}

# make_tmp: a private temp dir in $LOAD_TMP (removed by the caller's cleanup).
make_tmp() {
    LOAD_TMP=$(mktemp -d)
    chmod 700 "$LOAD_TMP"
    export LOAD_TMP
}

# random_kek: a fresh 32-byte KEK (base64), only ever kept in the environment.
random_kek() {
    head -c 32 /dev/urandom | base64 | tr -d '\n'
}

# wait_ready <base-url> [seconds]: polls /health/ready until 200.
wait_ready() {
    local base=$1 limit=${2:-120} i
    for ((i = 0; i < limit * 2; i++)); do
        if curl -fsS -o /dev/null "$base/health/ready" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    die "$base/health/ready did not answer 200 within ${limit}s"
}

# setup_url_from_logs <command...>: the one-time `Setup URL:` printed by the first node that
# installed the database (waits up to 60 s). The command prints the container logs.
setup_url_from_logs() {
    local i url
    for ((i = 0; i < 120; i++)); do
        url=$("$@" 2>&1 | sed -nE 's#.*Setup URL: (http[^ "]+/setup\?token=[A-Za-z0-9_-]+).*#\1#p' | head -1)
        if [[ -n "$url" ]]; then
            echo "$url"
            return 0
        fi
        sleep 0.5
    done
    die "no 'Setup URL:' line in the logs"
}

# redact: hides setup tokens and bearer/basic credentials in log output.
redact() {
    sed -E 's/(token=)[A-Za-z0-9_-]+/\1<redacted>/g; s/((Bearer|Basic) )[A-Za-z0-9._~+\/=-]+/\1<redacted>/g'
}

# json_get <file> <key>: prints a top-level string field of a JSON document.
json_get() {
    python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

# complete_setup <setup-url> <base-url> <out-json>: completes /setup with a random admin and
# writes the management credential shown once on the result page ({client_id, client_secret}) to
# <out-json> (mode 600). The base URL replaces the logged public URL's origin, so the request goes
# through the load balancer or published port the caller uses.
complete_setup() {
    local setup_url=$1 base=$2 out=$3 jar page form email password
    jar="$LOAD_TMP/setup.cookies"
    page="$LOAD_TMP/setup.html"
    form="$LOAD_TMP/setup.form"
    setup_url="${base}/setup?${setup_url#*\?}"
    curl -fsS -c "$jar" -b "$jar" -o "$page" "$setup_url" || die "GET /setup failed"
    email="load-admin-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')@example.com"
    password="L0ad-$(head -c 18 /dev/urandom | base64 | tr -d '\n/+=')"
    # The form's action and every hidden input (csrf_token, flow id, setup token), urlencoded,
    # plus the admin email and password.
    python3 -I - "$page" "$email" "$password" >"$form" <<'PY' || die "the setup page has no setup form"
import html.parser, sys, urllib.parse
class P(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.fields = []
        self.inside = False
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and a.get("id") == "setup":
            self.action = a.get("action") or ""
            self.inside = True
        elif tag == "input" and self.inside and a.get("type") == "hidden" and a.get("name"):
            self.fields.append((a["name"], a.get("value") or ""))
    def handle_endtag(self, tag):
        if tag == "form":
            self.inside = False
p = P()
p.feed(open(sys.argv[1], encoding="utf-8").read())
if p.action is None:
    sys.exit(1)
fields = p.fields + [("email", sys.argv[2]), ("password", sys.argv[3])]
print(p.action)
print(urllib.parse.urlencode(fields))
PY
    local action body
    action=$(sed -n 1p "$form")
    body=$(sed -n 2p "$form")
    rm -f "$form"
    case "$action" in
        http*) action="${base}/${action#*://*/}" ;;
        /*) action="${base}${action}" ;;
        *) action="${base}/setup${action}" ;;
    esac
    curl -fsS -c "$jar" -b "$jar" -o "$page" \
        -H 'content-type: application/x-www-form-urlencoded' \
        --data-binary @- "$action" <<<"$body" || die "POST /setup failed"
    python3 -I - "$page" "$out" <<'PY' || die "the setup result page did not show the management credential"
import html.parser, json, os, sys
class P(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.cur = None
        self.vals = {}
    def handle_starttag(self, tag, attrs):
        i = dict(attrs).get("id")
        if i in ("mgmt-client-id", "mgmt-client-secret"):
            self.cur = i
            self.vals[i] = ""
    def handle_endtag(self, tag):
        self.cur = None
    def handle_data(self, data):
        if self.cur:
            self.vals[self.cur] += data
p = P()
p.feed(open(sys.argv[1], encoding="utf-8").read())
cid = p.vals.get("mgmt-client-id", "").strip()
sec = p.vals.get("mgmt-client-secret", "").strip()
if not cid or not sec:
    sys.exit(1)
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump({"client_id": cid, "client_secret": sec}, f)
PY
    rm -f "$page" "$jar"
}

# client_token <token-endpoint> <credential-json> [scope]: a client_credentials access token
# (client_secret_basic).
client_token() {
    local endpoint=$1 cred=$2 scope=${3:-} resp
    resp="$LOAD_TMP/token.json"
    curl -fsS -o "$resp" -u "$(json_get "$cred" client_id):$(json_get "$cred" client_secret)" \
        -H 'accept: application/json' \
        --data-urlencode grant_type=client_credentials \
        ${scope:+--data-urlencode "scope=$scope"} \
        "$endpoint" || die "token request to $endpoint failed"
    json_get "$resp" access_token
    rm -f "$resp"
}

# create_client <base-url> <admin-token> <tenant-slug> <json-body> <out-json>: creates a client
# through the admin API and writes {client_id, client_secret} to <out-json> (mode 600).
create_client() {
    local base=$1 token=$2 tenant=$3 body=$4 out=$5 resp
    resp="$LOAD_TMP/client-resp.json"
    curl -fsS -o "$resp" -H "authorization: Bearer $token" \
        -H 'content-type: application/json' --data-binary @- \
        "$base/api/admin/v1/tenants/$tenant/clients" <<<"$body" || die "creating a client in $tenant failed"
    python3 -I - "$resp" "$out" <<'PY' || die "the client response has no secret"
import json, os, sys
c = json.load(open(sys.argv[1]))
if not c.get("client_id") or not c.get("client_secret"):
    sys.exit(1)
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump({"client_id": c["client_id"], "client_secret": c["client_secret"]}, f)
PY
    rm -f "$resp"
}

# provision <setup-url> <base-url>: completes setup, then creates
#   $LOAD_TMP/admin.json  a confidential system-tenant admin client (admin:read admin:write) for
#                         automation that later plans add (shared-limit and webhook checks);
#   $LOAD_TMP/bench.json  a confidential client_credentials client (client_secret_basic) in the
#                         `default` tenant, served at the public host (no tenant host lookup).
provision() {
    local setup_url=$1 base=$2 token
    complete_setup "$setup_url" "$base" "$LOAD_TMP/mgmt.json"
    token=$(client_token "$base/t/system/token" "$LOAD_TMP/mgmt.json" "admin:read admin:write")
    create_client "$base" "$token" system '{
        "name": "load admin automation",
        "client_type": "confidential",
        "grant_types": ["client_credentials"],
        "scopes": ["admin:read", "admin:write"]
    }' "$LOAD_TMP/admin.json"
    create_client "$base" "$token" default '{
        "name": "load benchmark",
        "client_type": "confidential",
        "auth_method": "client_secret_basic",
        "grant_types": ["client_credentials"]
    }' "$LOAD_TMP/bench.json"
    # Smoke: one token for the benchmark client before the load starts.
    client_token "$base/token" "$LOAD_TMP/bench.json" >/dev/null
    log "setup complete; admin and benchmark clients created"
}

# admin_token <base-url>: an access token of the system-tenant admin automation client
# ($LOAD_TMP/admin.json, created by provision) with admin:read admin:write.
admin_token() {
    client_token "$1/t/system/token" "$LOAD_TMP/admin.json" "admin:read admin:write"
}

# api_call <method> <url> <token> <json-body> <out-file>: an admin API request; prints the HTTP
# status (000 when no response arrived) and writes the response body to <out-file>.
api_call() {
    local method=$1 url=$2 token=$3 body=$4 out=$5
    curl -sS -o "$out" -w '%{http_code}' --max-time 15 -X "$method" \
        -H "authorization: Bearer $token" -H 'content-type: application/json' \
        --data-binary @- "$url" <<<"$body" 2>/dev/null || true
}

# run_k6 <script> <summary-json> [k6 args...]: runs k6 with the benchmark client in the
# environment (CLIENT_ID, CLIENT_SECRET; never on the command line) and BASE. The script writes
# its end-of-test summary to <summary-json> (handleSummary). Returns k6's exit status (non-zero
# when a threshold fails).
run_k6() {
    local script=$1 summary=$2 dir
    shift 2
    dir=$(cd "$(dirname "$script")" && pwd)
    CLIENT_ID=$(json_get "$LOAD_TMP/bench.json" client_id)
    CLIENT_SECRET=$(json_get "$LOAD_TMP/bench.json" client_secret)
    export CLIENT_ID CLIENT_SECRET
    local status=0
    if command -v k6 >/dev/null 2>&1; then
        SUMMARY="$summary" k6 run --quiet "$@" "$script" || status=$?
    else
        local sdir
        sdir=$(cd "$(dirname "$summary")" && pwd)
        docker run --rm --network host -u "$(id -u):$(id -g)" \
            -e BASE -e RATE -e CLIENT_ID -e CLIENT_SECRET -e "SUMMARY=/out/$(basename "$summary")" \
            -v "$dir:/scripts:ro" -v "$sdir:/out" \
            "$K6_IMAGE" run --quiet "$@" "/scripts/$(basename "$script")" || status=$?
    fi
    unset CLIENT_ID CLIENT_SECRET
    return "$status"
}

# summary_line <text>: prints and, on GitHub Actions, appends to the job summary.
summary_line() {
    echo "$*"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        echo "$*" >>"$GITHUB_STEP_SUMMARY"
    fi
}
