#!/usr/bin/env bash
# scripts/check-fonts.sh: the self-hosted theme fonts are the pinned upstream files.
#
#   scripts/check-fonts.sh              verify themes/default/static/fonts
#   scripts/check-fonts.sh <dir>        verify another directory laid out the same way
#   scripts/check-fonts.sh --self-test  prove the check rejects a font with one flipped byte
#
# Checks: every entry of SHA256SUMS matches (sha256sum -c), every .ttf/.woff2 in the directory is
# listed in SHA256SUMS, and both OFL licence texts are present. Provenance is in SOURCES.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FONTS_DIR="$ROOT/themes/default/static/fonts"
LICENCES=(OFL-HankenGrotesk.txt OFL-IBMPlex.txt)

check_dir() {
    local dir="$1"
    local failed=0

    if [[ ! -f "$dir/SHA256SUMS" ]]; then
        echo "error: $dir/SHA256SUMS is missing" >&2
        return 1
    fi

    for licence in "${LICENCES[@]}"; do
        if [[ ! -s "$dir/$licence" ]]; then
            echo "error: licence text $licence is missing" >&2
            failed=1
        fi
    done

    local font name
    while IFS= read -r -d '' font; do
        name="$(basename "$font")"
        if ! awk -v n="$name" '{ f = $2; sub(/^\*/, "", f); if (f == n) found = 1 } END { exit !found }' \
            "$dir/SHA256SUMS"; then
            echo "error: font $name is not listed in SHA256SUMS" >&2
            failed=1
        fi
    done < <(find "$dir" -maxdepth 1 -type f \( -name '*.ttf' -o -name '*.woff2' \) -print0)

    if ! (cd "$dir" && sha256sum --quiet -c SHA256SUMS); then
        echo "error: font files differ from the pinned upstream hashes (see SOURCES.md)" >&2
        failed=1
    fi

    return "$failed"
}

self_test() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    cp -p "$FONTS_DIR"/* "$tmp"/
    if ! check_dir "$tmp" >/dev/null 2>&1; then
        echo "self-test: FAIL (pristine copy rejected)" >&2
        return 1
    fi

    # Flip one byte in the middle of the first font file.
    local victim size offset byte
    victim="$(find "$tmp" -maxdepth 1 -type f \( -name '*.ttf' -o -name '*.woff2' \) | sort | head -n 1)"
    size="$(stat -c %s "$victim")"
    offset=$((size / 2))
    byte="$(od -An -tu1 -j "$offset" -N1 "$victim" | tr -d ' ')"
    printf "$(printf '\\%03o' $(((byte ^ 1) & 255)))" |
        dd of="$victim" bs=1 seek="$offset" count=1 conv=notrunc status=none
    if check_dir "$tmp" >/dev/null 2>&1; then
        echo "self-test: FAIL (flipped byte in $(basename "$victim") accepted)" >&2
        return 1
    fi

    # An unlisted font must be rejected too.
    cp -p "$FONTS_DIR"/* "$tmp"/
    cp "$tmp/$(basename "$victim")" "$tmp/Unlisted.woff2"
    if check_dir "$tmp" >/dev/null 2>&1; then
        echo "self-test: FAIL (unlisted font accepted)" >&2
        return 1
    fi
    rm "$tmp/Unlisted.woff2"

    # A missing licence must be rejected.
    rm "$tmp/${LICENCES[1]}"
    if check_dir "$tmp" >/dev/null 2>&1; then
        echo "self-test: FAIL (missing licence accepted)" >&2
        return 1
    fi

    echo "self-test: ok (flipped byte, unlisted font and missing licence rejected)"
}

case "${1:-}" in
    --self-test)
        self_test
        ;;
    "")
        check_dir "$FONTS_DIR"
        echo "fonts: ok"
        ;;
    *)
        check_dir "$1"
        echo "fonts: ok"
        ;;
esac
