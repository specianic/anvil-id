#!/usr/bin/env bash
# scripts/check-migrations.sh: migration safety lint (OPS-04).
#
#   scripts/check-migrations.sh              check the tree, exit non-zero on any violation
#   scripts/check-migrations.sh --self-test  prove both checks reject bad input
#
# 1. Immutability: every released migration is pinned by sha256 in
#    scripts/released-migrations.sha256 (sha256sum format: `<sha256>  <repo-relative path>`).
#    A released file that is missing or whose content changed fails the check. sqlx refuses to
#    start on an edited applied migration anyway (checksum mismatch); this catches it in CI.
# 2. Destructive SQL: an unreleased migration (any crates/anvil-storage-*/migrations/*.sql not in
#    the manifest) containing DROP TABLE, DROP COLUMN (or a bare ALTER TABLE … DROP <column>),
#    RENAME, ALTER COLUMN … TYPE, DELETE FROM or TRUNCATE must either be named
#    NNNN_destructive_*.sql (the binary then refuses to apply it without
#    --allow-destructive-migrations) or carry the file-level annotation
#    `-- anvil:non-destructive-rebuild` (a reviewed table rebuild that copies every row).
#    SQL comments are ignored when scanning.
#
# Releasing: add the new release's migration files to the manifest, e.g.
#   sha256sum crates/anvil-storage-*/migrations/0003_*.sql >> scripts/released-migrations.sha256
# From then on those files are immutable; schema changes go into new migrations.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=${CHECK_MIGRATIONS_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}
MANIFEST="$ROOT/scripts/released-migrations.sha256"
ANNOTATION='-- anvil:non-destructive-rebuild'

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Prints the destructive-statement rules a file matches (one per line), comments stripped.
destructive_rules() {
  perl -0777 -ne '
    s{/\*.*?\*/}{ }gs;          # block comments
    s{--[^\n]*}{}g;             # line comments
    s{\s+}{ }g;                 # statements may span lines
    my @rules = (
      ["DROP TABLE",            qr/\bDROP\s+TABLE\b/i],
      ["DROP COLUMN",           qr/\bDROP\s+COLUMN\b/i],
      ["ALTER TABLE ... DROP <column>",
       qr/(?:\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?[\w."]+\s+|,\s*)DROP\s+(?!COLUMN\b|CONSTRAINT\b|DEFAULT\b|NOT\s+NULL\b|IDENTITY\b|EXPRESSION\b)/i],
      ["RENAME",                qr/\bRENAME\b/i],
      ["ALTER COLUMN ... TYPE", qr/\bALTER\s+(?:COLUMN\s+)?(?!TABLE\b)[\w"]+\s+(?:SET\s+DATA\s+)?TYPE\b/i],
      ["DELETE FROM",           qr/\bDELETE\s+FROM\b/i],
      ["TRUNCATE",              qr/\bTRUNCATE\b/i],
    );
    for my $r (@rules) { print "$r->[0]\n" if $_ =~ $r->[1]; }
  ' "$1"
}

check() {
  local fail=0 line sum path abs file rel name rules released=""

  if [[ ! -f "$MANIFEST" ]]; then
    echo "MIGRATION VIOLATION: manifest ${MANIFEST#"$ROOT"/} is missing"
    return 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    sum=${line%%  *}
    path=${line#*  }
    if [[ ! "$sum" =~ ^[0-9a-f]{64}$ || -z "$path" || "$path" == "$line" ]]; then
      echo "MIGRATION VIOLATION: malformed manifest line: $line"
      fail=1
      continue
    fi
    released+="$path"$'\n'
    abs="$ROOT/$path"
    if [[ ! -f "$abs" ]]; then
      echo "MIGRATION VIOLATION: released migration $path is missing"
      fail=1
    elif [[ "$(sha256 "$abs")" != "$sum" ]]; then
      echo "MIGRATION VIOLATION: released migration $path was modified (sha256 differs from the manifest)"
      fail=1
    fi
  done <"$MANIFEST"

  shopt -s nullglob
  for file in "$ROOT"/crates/anvil-storage-*/migrations/*.sql; do
    rel=${file#"$ROOT"/}
    grep -qxF -- "$rel" <<<"$released" && continue
    rules=$(destructive_rules "$file")
    [[ -z "$rules" ]] && continue
    name=$(basename "$file")
    if [[ "$name" =~ ^[0-9]+_destructive_.*\.sql$ ]]; then
      echo "warning: $rel is a destructive migration ($(paste -sd, <<<"$rules")); anvilid applies it only with --allow-destructive-migrations"
    elif grep -qF -- "$ANNOTATION" "$file"; then
      :
    else
      echo "MIGRATION VIOLATION: $rel contains destructive SQL ($(paste -sd, <<<"$rules")) but is neither named NNNN_destructive_*.sql nor annotated '$ANNOTATION'"
      fail=1
    fi
  done
  shopt -u nullglob

  if [[ $fail -ne 0 ]]; then
    return 1
  fi
  echo "migrations OK"
}

# --- self-test -------------------------------------------------------------------------------
self_test() {
  local tmp failures=0
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  # A fresh tree with two released files and one clean unreleased file.
  setup() {
    rm -rf "$tmp/ws"
    mkdir -p "$tmp/ws/scripts" "$tmp/ws/crates/anvil-storage-sqlite/migrations"
    local m="$tmp/ws/crates/anvil-storage-sqlite/migrations"
    printf 'CREATE TABLE a (id INTEGER);\n' >"$m/0001_init.sql"
    # Released files are grandfathered even when destructive.
    printf 'CREATE TABLE b_new (id INTEGER);\nDROP TABLE b;\nALTER TABLE b_new RENAME TO b;\n' >"$m/0002_release.sql"
    printf -- '-- mentions DROP TABLE and DELETE FROM in a comment only\nCREATE TABLE c (id INTEGER);\n' >"$m/0003_next.sql"
    (cd "$tmp/ws" && for f in crates/anvil-storage-sqlite/migrations/0001_init.sql \
      crates/anvil-storage-sqlite/migrations/0002_release.sql; do
      printf '%s  %s\n' "$(sha256 "$f")" "$f"
    done) >"$tmp/ws/scripts/released-migrations.sha256"
  }

  # expect <name> <pass|fail> [output substring]: runs the checker on $tmp/ws.
  expect() {
    local name=$1 want=$2 needle=${3:-} actual=pass
    CHECK_MIGRATIONS_ROOT="$tmp/ws" "$SCRIPT_DIR/check-migrations.sh" >"$tmp/out.log" 2>&1 || actual=fail
    if [[ "$actual" != "$want" ]]; then
      echo "self-test case '$name': expected $want, got $actual"
      sed 's/^/    /' "$tmp/out.log"
      failures=$((failures + 1))
    elif [[ -n "$needle" ]] && ! grep -qF -- "$needle" "$tmp/out.log"; then
      echo "self-test case '$name': output lacks '$needle'"
      sed 's/^/    /' "$tmp/out.log"
      failures=$((failures + 1))
    else
      echo "self-test case '$name': $actual (as expected)"
    fi
  }

  local m="crates/anvil-storage-sqlite/migrations"
  unreleased() { printf '%b' "$2" >"$tmp/ws/$m/$1"; }

  setup
  expect "clean tree" pass "migrations OK"

  setup
  printf '\n-- edited\n' >>"$tmp/ws/$m/0001_init.sql"
  expect "released file modified" fail "$m/0001_init.sql was modified"

  setup
  rm "$tmp/ws/$m/0002_release.sql"
  expect "released file missing" fail "$m/0002_release.sql is missing"

  setup
  printf 'not-a-hash  x.sql\n' >>"$tmp/ws/scripts/released-migrations.sha256"
  expect "malformed manifest line" fail "malformed manifest line"

  setup
  unreleased 0004_x.sql 'ALTER TABLE a DROP COLUMN id;\n'
  expect "unmarked DROP COLUMN" fail "$m/0004_x.sql contains destructive SQL (DROP COLUMN)"

  setup
  unreleased 0004_x.sql '-- anvil:non-destructive-rebuild\nALTER TABLE a DROP COLUMN id;\n'
  expect "annotated DROP COLUMN" pass

  setup
  unreleased 0004_destructive_drop_id.sql 'ALTER TABLE a DROP COLUMN id;\n'
  expect "destructive_ name" pass "warning: $m/0004_destructive_drop_id.sql is a destructive migration"

  setup
  unreleased 0004_x.sql 'DROP TABLE a;\n'
  expect "unmarked DROP TABLE" fail "DROP TABLE"

  setup
  unreleased 0004_x.sql 'ALTER TABLE a ADD COLUMN x INTEGER, DROP y;\n'
  expect "unmarked bare DROP <column>" fail "ALTER TABLE ... DROP <column>"

  setup
  unreleased 0004_x.sql 'ALTER TABLE a RENAME TO z;\n'
  expect "unmarked RENAME" fail "RENAME"

  setup
  unreleased 0004_x.sql 'ALTER TABLE a\n  ALTER COLUMN id\n  TYPE bigint;\n'
  expect "unmarked multi-line ALTER COLUMN TYPE" fail "ALTER COLUMN ... TYPE"

  setup
  unreleased 0004_x.sql 'DELETE FROM a;\n'
  expect "unmarked DELETE FROM" fail "DELETE FROM"

  setup
  unreleased 0004_x.sql 'TRUNCATE a;\n'
  expect "unmarked TRUNCATE" fail "TRUNCATE"

  setup
  unreleased 0004_x.sql 'ALTER TABLE a DROP CONSTRAINT a_check, ADD CONSTRAINT a_check CHECK (id > 0);\nALTER TABLE a ALTER COLUMN id DROP NOT NULL;\nCREATE TABLE d (t uuid REFERENCES a (id) ON DELETE CASCADE);\n'
  expect "constraint swaps and ON DELETE are not destructive" pass

  if [[ $failures -ne 0 ]]; then
    echo "migration checker self-test FAILED ($failures case(s))"
    return 1
  fi
  echo "migration checker self-test OK"
}

case "${1:-}" in
  --self-test) self_test ;;
  "") check ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac
