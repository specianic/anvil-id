#!/usr/bin/env bash
# tests/saml-interop/run.sh: AnvilID signs in through real SAML IdP software (Keycloak, SimpleSAMLphp,
# Shibboleth IdP), each from the pinned image in tests/saml-interop/compose.yml.
#
#   run.sh [--provision-only] [sqlite|postgres] [keycloak simplesamlphp shibboleth ...]
#   run.sh --clean [images]
#
#   1. a mode-700 run dir (mktemp -d) with everything generated for this run only: a TLS CA and a
#      leaf for 127.0.0.1/localhost, IdP signing (and Shibboleth encryption/back-channel) key pairs,
#      a throwaway "SP encryption" certificate (only to make Keycloak and SimpleSAMLphp encrypt, for
#      the refusal case), the Shibboleth sealer, persistent-ID salt and test-account file, the
#      SimpleSAMLphp secret salt and admin password, the Keycloak bootstrap admin password and the
#      test users' passwords. Nothing is echoed; templates hold placeholders only.
#   2. every tests/saml-interop/**/*.tmpl rendered into the run dir (@@NAME@@ placeholders; the run
#      fails if one is left), other config files copied as they are
#   3. `docker compose up` of the selected IdPs, then each IdP's metadata polled over https with the
#      run CA until it parses and offers an https HTTP-Redirect SingleSignOnService
#   4. --provision-only stops here. Otherwise the IdP facts are exported (SAML_INTEROP_*,
#      ANVILID_OUTBOUND_CA_FILE and NODE_EXTRA_CA_CERTS = the run CA) and tests/e2e/run.sh builds and
#      starts AnvilID (ANVILID_SAML_EXPERIMENTAL=true, the suite's mock DNS) and runs
#      specs/saml-interop.spec.ts
#   5. on exit, always: on failure the IdP logs go to saml-interop-results/logs/ with every per-run
#      password replaced by <redacted>; then `docker compose down -v` and the run dir is removed.
#
# --clean removes leftovers of an interrupted run (the compose project and any container labelled
# dev.anvilid.test=saml-interop); `--clean images` also removes the pinned IdP images.
#
# Requires Docker (compose v2), openssl, node, curl; for the full run also what tests/e2e/run.sh
# needs. Ports (127.0.0.1 only): SAML_INTEROP_KEYCLOAK_PORT (18443), SAML_INTEROP_SSP_PORT (18444),
# SAML_INTEROP_SHIB_PORT (18445); AnvilID on E2E_PORT (18090). The IdP templates register the SP
# values of tenant `interop`, so the IdPs are provisioned before AnvilID starts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/tests/saml-interop"
cd "$ROOT"

PROJECT=anvil-saml-interop
COMPOSE_FILE="$HERE/compose.yml"
ALL_IDPS=(keycloak simplesamlphp shibboleth)
RESULTS_DIR="$ROOT/saml-interop-results"

die() {
    echo "error: $*" >&2
    exit 1
}

# docker compose with harmless defaults for the required variables, so `config`, `down` and `logs`
# also work outside a run (the values are never used to start anything).
compose() {
    SAML_INTEROP_RUN_DIR="${SAML_INTEROP_RUN_DIR:-/nonexistent}" \
        SAML_INTEROP_KC_ADMIN_PASSWORD="${SAML_INTEROP_KC_ADMIN_PASSWORD:-unused}" \
        SAML_INTEROP_SSP_ADMIN_PASSWORD="${SAML_INTEROP_SSP_ADMIN_PASSWORD:-unused}" \
        SAML_INTEROP_SSP_SECRET_SALT="${SAML_INTEROP_SSP_SECRET_SALT:-unused}" \
        docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

# The pinned image of compose service $1 (compose.yml is the single source).
image_of() {
    compose config --format json | node -e '
        let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
            const img = JSON.parse(s).services?.[process.argv[1]]?.image;
            if (!img) process.exit(1);
            process.stdout.write(img);
        });' "$1"
}

clean() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    docker ps -aq --filter label=dev.anvilid.test=saml-interop | xargs -r docker rm -f -v >/dev/null
    if [[ "${1:-}" == images ]]; then
        local svc ref
        for svc in "${ALL_IDPS[@]}"; do
            ref=$(image_of "$svc")
            docker image rm "$ref" >/dev/null 2>&1 && echo "removed $ref" || true
        done
    fi
}

# --- arguments -------------------------------------------------------------------------------
PROVISION_ONLY=0
case "${1:-}" in
    --clean)
        clean "${2:-}"
        exit 0
        ;;
    --provision-only)
        PROVISION_ONLY=1
        shift
        ;;
esac
BACKEND=sqlite
if [[ "${1:-}" == sqlite || "${1:-}" == postgres ]]; then
    BACKEND=$1
    shift
fi
IDPS=("$@")
((${#IDPS[@]} > 0)) || IDPS=("${ALL_IDPS[@]}")
for idp in "${IDPS[@]}"; do
    case "$idp" in
        keycloak | simplesamlphp | shibboleth) ;;
        *) die "unknown IdP '$idp' (expected: ${ALL_IDPS[*]})" ;;
    esac
done
selected() { [[ " ${IDPS[*]} " == *" $1 "* ]]; }

for tool in docker openssl node curl; do
    command -v "$tool" >/dev/null || die "$tool is required"
done

export SAML_INTEROP_KEYCLOAK_PORT=${SAML_INTEROP_KEYCLOAK_PORT:-18443}
export SAML_INTEROP_SSP_PORT=${SAML_INTEROP_SSP_PORT:-18444}
export SAML_INTEROP_SHIB_PORT=${SAML_INTEROP_SHIB_PORT:-18445}
E2E_PORT=${E2E_PORT:-18090}
ISSUER="http://localhost:$E2E_PORT/t/interop"

# --- run dir and cleanup ---------------------------------------------------------------------
RUN_DIR=$(mktemp -d)
chmod 700 "$RUN_DIR"
export SAML_INTEROP_RUN_DIR="$RUN_DIR"
STARTED=0
SECRETS=() # every per-run password/salt, for log redaction

cleanup() {
    local status=$?
    trap - EXIT
    if ((STARTED)); then
        if ((status != 0)); then
            mkdir -p "$RESULTS_DIR/logs"
            local svc sed_args=()
            for s in "${SECRETS[@]}"; do sed_args+=(-e "s/$s/<redacted>/g"); done
            for svc in "${IDPS[@]}"; do
                compose logs --no-color "$svc" 2>&1 | sed "${sed_args[@]}" >"$RESULTS_DIR/logs/$svc.log" || true
            done
            echo "IdP logs (passwords redacted): $RESULTS_DIR/logs/" >&2
        fi
        compose down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    rm -rf "$RUN_DIR"
    exit "$status"
}
trap cleanup EXIT

# Random hex secret (no characters that need escaping in sed, PHP, XML, JSON or properties files).
secret() { openssl rand -hex "${1:-24}"; }
# Base64 of a PEM certificate's DER (one line), as metadata and IdP configs embed it.
cert_b64() { openssl x509 -in "$1" -outform der | base64 | tr -d '\n'; }
# A self-signed RSA-2048 key pair: $1 = path prefix, $2 = CN.
key_pair() {
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 -subj "/CN=$2" \
        -keyout "$1.key" -out "$1.crt" 2>/dev/null
}

# --- 1. per-run material ---------------------------------------------------------------------
# The containers run as various users (Keycloak uid 1000, Apache's www-data, root for Shibboleth),
# so files below the mode-700 run dir are world-readable; the run dir itself is private.
umask 022
mkdir -p "$RUN_DIR"/{tls,keycloak/import,simplesamlphp/cert,shibboleth/credentials,shibboleth/conf/authn,shibboleth/metadata}

# TLS: a CA plus a leaf for 127.0.0.1/localhost (webpki refuses a self-signed leaf used as a root).
cat >"$RUN_DIR/tls/cert.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = anvilid saml-interop CA
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[leaf_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1,DNS:localhost
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
openssl req -x509 -config "$RUN_DIR/tls/cert.cnf" -extensions ca_ext \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -keyout "$RUN_DIR/ca.key" -out "$RUN_DIR/ca.pem" 2>/dev/null
openssl req -new -config "$RUN_DIR/tls/cert.cnf" -subj "/CN=localhost" -newkey rsa:2048 -nodes \
    -keyout "$RUN_DIR/tls/tls.key" -out "$RUN_DIR/tls/tls.csr" 2>/dev/null
openssl x509 -req -in "$RUN_DIR/tls/tls.csr" -CA "$RUN_DIR/ca.pem" -CAkey "$RUN_DIR/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days 2 -sha256 \
    -extfile "$RUN_DIR/tls/cert.cnf" -extensions leaf_ext -out "$RUN_DIR/tls/tls.crt" 2>/dev/null
rm -f "$RUN_DIR/tls/tls.csr" "$RUN_DIR/tls/cert.cnf" "$RUN_DIR/ca.key"
chmod 600 "$RUN_DIR/ca.pem"
openssl verify -CAfile "$RUN_DIR/ca.pem" -purpose sslserver -verify_ip 127.0.0.1 "$RUN_DIR/tls/tls.crt" >/dev/null ||
    die "the generated TLS leaf does not verify"

# The throwaway SP encryption certificate (AnvilID has no SP keys; its private key is discarded).
key_pair "$RUN_DIR/sp-enc" "anvilid saml-interop throwaway SP encryption"
SP_ENC_CERT_B64=$(cert_b64 "$RUN_DIR/sp-enc.crt")
rm -f "$RUN_DIR/sp-enc.key"

KC_ADMIN_PASSWORD=$(secret)
KC_USER_PASSWORD=$(secret 12)
SSP_ADMIN_PASSWORD=$(secret)
SSP_SECRET_SALT=$(secret 32)
SSP_USER_PASSWORD=$(secret 12)
SHIB_USER_PASSWORD=$(secret 12)
SHIB_SEALER_PASSWORD=$(secret)
SHIB_BACKCHANNEL_PASSWORD=$(secret)
SHIB_LDAP_PLACEHOLDER=$(secret 8)
SHIB_PERSISTENT_ID_SALT=$(secret 32)
SECRETS=("$KC_ADMIN_PASSWORD" "$KC_USER_PASSWORD" "$SSP_ADMIN_PASSWORD" "$SSP_SECRET_SALT"
    "$SSP_USER_PASSWORD" "$SHIB_USER_PASSWORD" "$SHIB_SEALER_PASSWORD" "$SHIB_BACKCHANNEL_PASSWORD"
    "$SHIB_PERSISTENT_ID_SALT")
export SAML_INTEROP_KC_ADMIN_PASSWORD="$KC_ADMIN_PASSWORD"
export SAML_INTEROP_SSP_ADMIN_PASSWORD="$SSP_ADMIN_PASSWORD"
export SAML_INTEROP_SSP_SECRET_SALT="$SSP_SECRET_SALT"

# SimpleSAMLphp signing pair.
key_pair "$RUN_DIR/simplesamlphp/cert/idp" "anvilid saml-interop simplesamlphp signing"
# Shibboleth signing, encryption and back-channel pairs, test accounts and sealer.
SHIB_CRED="$RUN_DIR/shibboleth/credentials"
key_pair "$SHIB_CRED/idp-signing" "anvilid saml-interop shibboleth signing"
key_pair "$SHIB_CRED/idp-encryption" "anvilid saml-interop shibboleth encryption"
key_pair "$SHIB_CRED/idp-backchannel" "anvilid saml-interop shibboleth back-channel"
openssl pkcs12 -export -in "$SHIB_CRED/idp-backchannel.crt" -inkey "$SHIB_CRED/idp-backchannel.key" \
    -name idp-backchannel -passout "pass:$SHIB_BACKCHANNEL_PASSWORD" -out "$SHIB_CRED/idp-backchannel.p12"
rm -f "$SHIB_CRED/idp-backchannel.key"
{
    printf 'alice:%s\n' "$(openssl passwd -apr1 "$SHIB_USER_PASSWORD")"
    printf 'bob:%s\n' "$(openssl passwd -apr1 "$SHIB_USER_PASSWORD")"
} >"$SHIB_CRED/interop.htpasswd"
if selected shibboleth; then
    # The sealer (AES key store) with the image's own tool, as the calling user.
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e SEALER_PASSWORD="$SHIB_SEALER_PASSWORD" \
        -v "$SHIB_CRED:/out" --entrypoint /bin/sh "$(image_of shibboleth)" -c \
        '/opt/shibboleth-idp/bin/seckeygen.sh --storefile /out/sealer.jks --storepass "$SEALER_PASSWORD" --versionfile /out/sealer.kver --alias secret' \
        >/dev/null 2>&1 || die "generating the Shibboleth sealer failed"
    [[ -s "$SHIB_CRED/sealer.jks" ]] || die "the Shibboleth sealer was not written"
fi

# --- 2. templates ----------------------------------------------------------------------------
# Placeholder values reach node through the environment (never argv).
export R_ISSUER="$ISSUER" R_E2E_PORT="$E2E_PORT" R_KC_PORT="$SAML_INTEROP_KEYCLOAK_PORT" \
    R_SSP_PORT="$SAML_INTEROP_SSP_PORT" R_SHIB_PORT="$SAML_INTEROP_SHIB_PORT" \
    R_SP_ENC_CERT_B64="$SP_ENC_CERT_B64" R_SHIB_SEALER_PASSWORD="$SHIB_SEALER_PASSWORD" \
    R_SHIB_BACKCHANNEL_PASSWORD="$SHIB_BACKCHANNEL_PASSWORD" R_SHIB_LDAP_PLACEHOLDER="$SHIB_LDAP_PLACEHOLDER" \
    R_SHIB_PERSISTENT_ID_SALT="$SHIB_PERSISTENT_ID_SALT" \
    R_SHIB_SIGNING_CERT_B64="$(cert_b64 "$SHIB_CRED/idp-signing.crt")" \
    R_SHIB_ENCRYPTION_CERT_B64="$(cert_b64 "$SHIB_CRED/idp-encryption.crt")"
# One template, one output: @@NAME@@ -> $R_NAME (USER_PASSWORD per IdP, set by the caller).
render() {
    node -e '
        const fs = require("fs");
        const [src, dst] = process.argv.slice(1);
        const missing = new Set();
        const out = fs.readFileSync(src, "utf8").replace(/@@([A-Z0-9_]+)@@/g, (m, name) => {
            const v = process.env["R_" + name];
            if (v === undefined || v === "") { missing.add(name); return m; }
            return v;
        });
        if (missing.size) { console.error(`${src}: no value for ${[...missing].join(", ")}`); process.exit(1); }
        if (/@@[A-Z0-9_]+@@/.test(out)) { console.error(`${src}: placeholder left`); process.exit(1); }
        fs.writeFileSync(dst, out);' "$1" "$2"
}
render_tree() { # $1 = source dir, $2 = target dir
    local src rel
    while IFS= read -r -d '' src; do
        rel=${src#"$1"/}
        mkdir -p "$2/$(dirname "$rel")"
        case "$src" in
            *.tmpl) render "$src" "$2/${rel%.tmpl}" ;;
            *) cp "$src" "$2/$rel" ;;
        esac
    done < <(find "$1" -type f -print0)
}
R_USER_PASSWORD="$KC_USER_PASSWORD" render \
    "$HERE/keycloak/interop-realm.json.tmpl" "$RUN_DIR/keycloak/import/interop-realm.json"
R_USER_PASSWORD="$SSP_USER_PASSWORD" render_tree "$HERE/simplesamlphp" "$RUN_DIR/simplesamlphp"
R_USER_PASSWORD="$SHIB_USER_PASSWORD" render_tree "$HERE/shibboleth" "$RUN_DIR/shibboleth"
# The IdP reads it from credentials/ (idp.additionalProperties).
mv "$RUN_DIR/shibboleth/conf/secrets.properties" "$SHIB_CRED/secrets.properties"

# openssl writes private keys mode 600; the container users must read the mounted copies.
chmod -R a+rX "$RUN_DIR"/{tls,keycloak,simplesamlphp,shibboleth}

# --- 3. IdPs ---------------------------------------------------------------------------------
STARTED=1
compose up -d --quiet-pull "${IDPS[@]}" >/dev/null

metadata_url() {
    case "$1" in
        keycloak) echo "https://127.0.0.1:$SAML_INTEROP_KEYCLOAK_PORT/realms/interop/protocol/saml/descriptor" ;;
        simplesamlphp) echo "https://127.0.0.1:$SAML_INTEROP_SSP_PORT/simplesaml/module.php/saml/idp/metadata" ;;
        shibboleth) echo "https://127.0.0.1:$SAML_INTEROP_SHIB_PORT/idp/shibboleth" ;;
    esac
}
base_url() {
    case "$1" in
        keycloak) echo "https://127.0.0.1:$SAML_INTEROP_KEYCLOAK_PORT" ;;
        simplesamlphp) echo "https://127.0.0.1:$SAML_INTEROP_SSP_PORT/simplesaml" ;;
        shibboleth) echo "https://127.0.0.1:$SAML_INTEROP_SHIB_PORT/idp" ;;
    esac
}
check_metadata() { # $1 = file
    if command -v xmllint >/dev/null; then
        xmllint --noout "$1" 2>/dev/null || return 1
    fi
    node -e '
        const xml = require("fs").readFileSync(process.argv[1], "utf8");
        if (!/<(\w+:)?EntityDescriptor[\s>]/.test(xml) || !/<(\w+:)?IDPSSODescriptor[\s>]/.test(xml)) process.exit(1);
        const sso = [...xml.matchAll(/<(?:\w+:)?SingleSignOnService\b[^>]*>/g)].map((m) => m[0]);
        const ok = sso.some((t) => t.includes("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect") &&
            /Location="https:\/\/127\.0\.0\.1:/.test(t));
        process.exit(ok ? 0 : 1);' "$1"
}
wait_ready() { # $1 = IdP, $2 = seconds
    local url deadline file="$RUN_DIR/metadata-$1.xml"
    url=$(metadata_url "$1")
    deadline=$((SECONDS + $2))
    while ((SECONDS < deadline)); do
        if curl -fsS --max-time 10 --cacert "$RUN_DIR/ca.pem" -o "$file" "$url" 2>/dev/null &&
            check_metadata "$file"; then
            echo "$1: ready ($url)"
            return 0
        fi
        if [[ -z "$(compose ps -q --status running "$1" 2>/dev/null)" ]]; then
            echo "error: the $1 container is not running" >&2
            return 1
        fi
        sleep 3
    done
    echo "error: $1 did not serve valid metadata at $url within $2 s" >&2
    return 1
}
for idp in "${IDPS[@]}"; do
    case "$idp" in
        keycloak) wait_ready keycloak 240 ;;
        simplesamlphp) wait_ready simplesamlphp 180 ;;
        shibboleth) wait_ready shibboleth 420 ;;
    esac
done

if ((PROVISION_ONLY)); then
    echo "saml-interop: ${IDPS[*]} provisioned (--provision-only)"
    exit 0
fi

# --- 4. AnvilID and the spec -----------------------------------------------------------------
mkdir -p "$RESULTS_DIR"
export ANVILID_OUTBOUND_CA_FILE="$RUN_DIR/ca.pem"
export NODE_EXTRA_CA_CERTS="$RUN_DIR/ca.pem"
export SAML_INTEROP_IDPS="${IDPS[*]}"
export SAML_INTEROP_RESULTS="$RESULTS_DIR/results.json"
export SAML_INTEROP_SP_ENC_CERT_B64="$SP_ENC_CERT_B64"
rm -f "$SAML_INTEROP_RESULTS"
# The set-up creates ~12 connections with their domains in a burst of admin calls, above the
# default admin budget (20/s). Rate limiting stays on; only this run's admin budget is raised
# (tests/e2e/run.sh starts anvilid with the caller's environment).
export ANVILID_RATE_LIMIT_ADMIN_PER_SECOND=200
for idp in "${IDPS[@]}"; do
    var=$(tr '[:lower:]' '[:upper:]' <<<"$idp")
    export "SAML_INTEROP_${var}_METADATA_URL=$(metadata_url "$idp")"
    export "SAML_INTEROP_${var}_BASE_URL=$(base_url "$idp")"
    export "SAML_INTEROP_${var}_IMAGE=$(image_of "$idp")"
    case "$idp" in
        keycloak) export "SAML_INTEROP_${var}_USER_PASSWORD=$KC_USER_PASSWORD" ;;
        simplesamlphp) export "SAML_INTEROP_${var}_USER_PASSWORD=$SSP_USER_PASSWORD" ;;
        shibboleth) export "SAML_INTEROP_${var}_USER_PASSWORD=$SHIB_USER_PASSWORD" ;;
    esac
done
E2E_PORT="$E2E_PORT" "$ROOT/tests/e2e/run.sh" "$BACKEND" specs/saml-interop.spec.ts
echo "saml-interop ($BACKEND; ${IDPS[*]}): passed"
