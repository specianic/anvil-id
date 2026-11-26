#!/usr/bin/env bash
# Checks a built documentation site (mdBook output) before it is uploaded or published.
#
#   scripts/check-docs-site.sh <book-dir>   check a built site
#   scripts/check-docs-site.sh --self-test  prove that every rule rejects a planted violation
#
# Rules (each one fails the check):
#   1. external assets: a <script src> or <link href> pointing at another origin (http:, https: or
#      protocol-relative //), or a stylesheet that loads a remote url() / @import (external fonts, CDNs)
#   2. tracking: analytics or tag-manager code (Google Analytics / Tag Manager, gtag, Plausible,
#      Matomo, ...)
#   3. research leak: any file or directory under a `research` path, or any reference to `research/`
#      (docs/research/ holds local-only notes and must never reach the site)
#   4. broken internal links: a relative href/src in an HTML page that does not resolve to a file in
#      the output (anchors, query strings, http(s):, mailto:, data: and javascript: are ignored)
#   5. security policy: the repository's SECURITY.md (which the site's security page points to) is
#      missing, has no supported-versions table, or still contains an `OWNER:` placeholder that the
#      owner has to resolve before the policy is published
set -euo pipefail

# The security policy checked by rule 5: SECURITY.md at the repository root.
SECURITY_POLICY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/SECURITY.md"

usage() {
	echo "usage: $0 <book-dir> | --self-test" >&2
	exit 2
}

# check_policy <file>: rule 5. Prints one line per violation, returns 1 if any were found.
check_policy() {
	local policy="$1"
	if [[ ! -f "$policy" ]]; then
		echo "FAIL [security-policy] $policy is missing"
		return 1
	fi
	local fail=0
	# A "## Supported versions" section with a Markdown table (header row plus separator row)
	# before the next level-2 heading.
	if ! awk '
		/^## / { in_section = ($0 ~ /^## Supported versions[[:space:]]*$/); next }
		in_section && /^\|.*\|[[:space:]]*$/ { rows++ }
		in_section && /^\|[[:space:]:]*-{3,}/ { sep++ }
		END { exit !(rows >= 2 && sep >= 1) }
	' "$policy"; then
		echo "FAIL [security-policy] $policy has no supported-versions table (## Supported versions)"
		fail=1
	fi
	local hits
	hits="$(grep -n 'OWNER:' "$policy" || true)"
	if [[ -n "$hits" ]]; then
		echo "FAIL [security-policy] $policy still contains an OWNER: placeholder:"
		echo "$hits" | sed 's/^/  /'
		fail=1
	fi
	return $fail
}

# check_site <dir> [<security-policy>]: prints one line per violation, returns 1 if any were found.
check_site() {
	local root="$1"
	local policy="${2:-$SECURITY_POLICY}"
	local fail=0
	if [[ ! -d "$root" ]]; then
		echo "error: $root is not a directory" >&2
		return 2
	fi
	root="$(cd "$root" && pwd)"

	# Rule 1: external scripts, stylesheets and remote CSS resources.
	local hits
	hits="$(grep -rnoiE '<script[^>]*[[:space:]]src="(https?:)?//[^"]*"' --include='*.html' "$root" || true)"
	hits+="$(grep -rnoiE '<link[^>]*[[:space:]]href="(https?:)?//[^"]*"' --include='*.html' "$root" || true)"
	hits+="$(grep -rnoiE "(@import[[:space:]]+(url\()?|url\()[\"']?(https?:)?//[^)\"';]*" --include='*.css' --include='*.html' "$root" || true)"
	if [[ -n "$hits" ]]; then
		echo "FAIL [external-asset] remote script, stylesheet or font:"
		echo "$hits" | sed 's/^/  /'
		fail=1
	fi

	# Rule 2: analytics / tag managers.
	hits="$(grep -rnoiE 'googletagmanager|google-analytics|googleanalytics|gtag\(|analytics\.js|plausible\.io|matomo|piwik|_paq\.push|segment\.(com|io)|hotjar|clarity\.ms|[^a-z]analytics[^a-z]' "$root" || true)"
	if [[ -n "$hits" ]]; then
		echo "FAIL [tracking] analytics or tag-manager code:"
		echo "$hits" | sed 's/^/  /'
		fail=1
	fi

	# Rule 3: research notes must not be in the output, nor be referenced from it.
	hits="$(find "$root" -ipath '*research*' -printf '%P\n' || true)"
	hits+="$(grep -rnoi 'research/' "$root" || true)"
	if [[ -n "$hits" ]]; then
		echo "FAIL [research] research path in the site output:"
		echo "$hits" | sed 's/^/  /'
		fail=1
	fi

	# Rule 4: broken internal links in HTML pages.
	local page dir base link target path broken=""
	while IFS= read -r -d '' page; do
		dir="$(dirname "$page")"
		# A page with <base href> (mdBook's 404 page) resolves relative links against the site root.
		base="$(grep -oiE '<base[[:space:]]+href="[^"]*"' "$page" | head -n1 | sed -E 's/.*href="([^"]*)"/\1/I' || true)"
		[[ -n "$base" ]] && dir="$root"
		while IFS= read -r link; do
			link="${link#*\"}"
			link="${link%\"}"
			case "$link" in
			'' | '#'* | http:* | https:* | //* | mailto:* | data:* | javascript:* | tel:*) continue ;;
			esac
			path="${link%%#*}"
			path="${path%%\?*}"
			[[ -z "$path" ]] && continue
			if [[ "$path" == /* ]]; then
				# Site-absolute: strip the site prefix (from <base href>, else none).
				if [[ -n "$base" && "$path" == "$base"* ]]; then
					path="${path#"$base"}"
				else
					path="${path#/}"
				fi
				target="$root/$path"
			else
				target="$dir/$path"
			fi
			[[ "$target" == */ ]] && target="${target}index.html"
			if [[ ! -e "$target" ]]; then
				broken+="  ${page#"$root"/}: $link"$'\n'
			elif [[ -d "$target" && ! -e "$target/index.html" ]]; then
				broken+="  ${page#"$root"/}: $link (directory without index.html)"$'\n'
			fi
		done < <(grep -oiE '[[:space:]](href|src)="[^"]*"' "$page" | sed -E 's/^[[:space:]]+//' || true)
	done < <(find "$root" -type f -name '*.html' -print0)
	if [[ -n "$broken" ]]; then
		echo "FAIL [broken-link] relative links to files that are not in the output:"
		printf '%s' "$broken"
		fail=1
	fi

	# Rule 5: the published security policy.
	check_policy "$policy" || fail=1

	if [[ $fail -eq 0 ]]; then
		echo "ok: $root (no external assets, no tracking, no research paths, no broken internal links; security policy complete)"
	fi
	return $fail
}

# A minimal clean site shaped like mdBook output.
make_clean_site() {
	local d="$1"
	mkdir -p "$d/css" "$d/fonts" "$d/schemas"
	cat >"$d/index.html" <<-'HTML'
		<!DOCTYPE html>
		<html><head>
		<link rel="stylesheet" href="css/general.css">
		<link rel="stylesheet" href="fonts/fonts.css">
		<script src="book.js"></script>
		</head><body>
		<a href="guide.html#install">Install</a>
		<a href="schemas/config.json">Schema</a>
		<a href="#top">Top</a>
		<a href="https://github.com/example/project">Source</a>
		<a href="mailto:security@example.invalid">Report</a>
		</body></html>
	HTML
	cat >"$d/guide.html" <<-'HTML'
		<!DOCTYPE html>
		<html><head><link rel="stylesheet" href="css/general.css"></head>
		<body><h2 id="install">Install</h2><a href="index.html">Home</a><a href="./">Up</a></body></html>
	HTML
	cat >"$d/404.html" <<-'HTML'
		<!DOCTYPE html>
		<html><head><base href="/site/"><link rel="stylesheet" href="css/general.css"></head>
		<body><a href="index.html">Home</a><a href="/site/guide.html">Guide</a></body></html>
	HTML
	echo 'body { color: black; }' >"$d/css/general.css"
	echo "@font-face { font-family: 'Open Sans'; src: url('open-sans.woff2') format('woff2'); }" >"$d/fonts/fonts.css"
	echo 'console.log("book");' >"$d/book.js"
	echo '{}' >"$d/schemas/config.json"
}

# A minimal complete security policy.
make_policy() {
	cat >"$1" <<-'MD'
		# Security policy

		## Supported versions

		| Version | Supported |
		| --- | --- |
		| 1.0.x | Yes |

		## Reporting a vulnerability

		Report it privately.
	MD
}

self_test() {
	local tmp # removed by the EXIT trap through _selftest_tmp
	tmp="$(mktemp -d)"
	_selftest_tmp="$tmp"
	trap 'rm -rf "${_selftest_tmp:-}"' EXIT
	local failures=0

	# A complete security policy for every case except the rule-5 ones.
	local good_policy="$tmp/SECURITY.md"
	make_policy "$good_policy"

	expect() { # expect <name> <expected-rc> <expected-rule-tag or ""> <dir> [<security-policy>]
		local name="$1" want="$2" tag="$3" dir="$4" policy="${5:-$good_policy}" out rc=0
		out="$(check_site "$dir" "$policy" 2>&1)" || rc=$?
		if [[ $rc -ne $want ]]; then
			echo "self-test FAIL: $name: exit $rc, want $want"
			echo "$out" | sed 's/^/    /'
			failures=$((failures + 1))
		elif [[ -n "$tag" ]] && ! grep -q "\[$tag\]" <<<"$out"; then
			echo "self-test FAIL: $name: rejected, but not by rule [$tag]"
			echo "$out" | sed 's/^/    /'
			failures=$((failures + 1))
		else
			echo "self-test ok: $name"
		fi
	}

	local c="$tmp/clean"
	make_clean_site "$c"
	expect "clean site passes" 0 "" "$c"

	local d
	d="$tmp/ext-script"
	make_clean_site "$d"
	sed -i 's#<script src="book.js"></script>#<script src="https://cdn.example.com/lib.js"></script>#' "$d/index.html"
	expect "external <script src> rejected" 1 external-asset "$d"

	d="$tmp/ext-link"
	make_clean_site "$d"
	sed -i 's#href="fonts/fonts.css"#href="https://fonts.googleapis.com/css?family=Open+Sans"#' "$d/index.html"
	expect "external <link href> rejected" 1 external-asset "$d"

	d="$tmp/ext-proto-relative"
	make_clean_site "$d"
	sed -i 's#<script src="book.js"></script>#<script src="//cdn.example.com/lib.js"></script>#' "$d/index.html"
	expect "protocol-relative <script src> rejected" 1 external-asset "$d"

	d="$tmp/ext-font"
	make_clean_site "$d"
	echo "@import url('https://fonts.example.com/css');" >>"$d/fonts/fonts.css"
	expect "remote @import in CSS rejected" 1 external-asset "$d"

	d="$tmp/tracking"
	make_clean_site "$d"
	sed -i 's#</head>#<script>(function(w,d,s,l,i){w[l]=w[l]||[];})(window,document,"script","dataLayer","GTM-XXXX");</script><script src="gtm.js"></script><!-- googletagmanager --></head>#' "$d/index.html"
	echo '// tag manager' >"$d/gtm.js"
	expect "tag-manager code rejected" 1 tracking "$d"

	d="$tmp/tracking-gtag"
	make_clean_site "$d"
	echo 'window.dataLayer = []; function gtag(){dataLayer.push(arguments);}' >>"$d/book.js"
	expect "gtag() in a script rejected" 1 tracking "$d"

	d="$tmp/research-file"
	make_clean_site "$d"
	mkdir -p "$d/research"
	echo 'notes' >"$d/research/notes.txt"
	expect "research/ directory in output rejected" 1 research "$d"

	d="$tmp/research-ref"
	make_clean_site "$d"
	sed -i 's#</body>#<p>see docs/research/vendor.md</p></body>#' "$d/guide.html"
	expect "reference to research/ rejected" 1 research "$d"

	d="$tmp/broken-link"
	make_clean_site "$d"
	sed -i 's#href="guide.html\#install"#href="missing.html\#install"#' "$d/index.html"
	expect "broken relative link rejected" 1 broken-link "$d"

	d="$tmp/broken-src"
	make_clean_site "$d"
	rm "$d/book.js"
	expect "missing script file rejected" 1 broken-link "$d"

	d="$tmp/broken-outside"
	make_clean_site "$d"
	sed -i 's#href="index.html">Home#href="../deploy/README.md">Deploy#' "$d/guide.html"
	expect "link outside the site rejected" 1 broken-link "$d"

	d="$tmp/broken-base"
	make_clean_site "$d"
	sed -i 's#href="/site/guide.html"#href="/site/nope.html"#' "$d/404.html"
	expect "broken link under <base href> rejected" 1 broken-link "$d"

	expect "missing directory rejected" 2 "" "$tmp/does-not-exist"

	local p
	p="$tmp/policy-missing.md"
	expect "missing SECURITY.md rejected" 1 security-policy "$c" "$p"

	p="$tmp/policy-no-table.md"
	make_policy "$p"
	sed -i '/^|/d' "$p"
	expect "SECURITY.md without a supported-versions table rejected" 1 security-policy "$c" "$p"

	p="$tmp/policy-table-elsewhere.md"
	make_policy "$p"
	sed -i 's/^## Supported versions$/## Versions we like/' "$p"
	expect "table outside the supported-versions section rejected" 1 security-policy "$c" "$p"

	p="$tmp/policy-owner.md"
	make_policy "$p"
	echo '<!-- OWNER: optional alternative contact -->' >>"$p"
	expect "SECURITY.md with an OWNER: placeholder rejected" 1 security-policy "$c" "$p"

	if [[ $failures -ne 0 ]]; then
		echo "self-test: $failures case(s) failed"
		return 1
	fi
	echo "self-test: all cases passed"
}

[[ $# -eq 1 ]] || usage
case "$1" in
--self-test) self_test ;;
-h | --help) usage ;;
*) check_site "$1" ;;
esac
