---
phase: 02-release-0-1-first-login
plan: 23
subsystem: release
tags: [release, ci, github-actions, ghcr, musl, macos, attestations, OPS-01]
requires:
  - phase: 02-release-0-1-first-login
    provides: "02-20 size-gated container image + build-musl.sh; 02-21 phase gate (67dd7f8, CI green)"
provides:
  - "Tag-triggered release workflow (.github/workflows/release.yml): musl x86_64/aarch64, macOS aarch64/x86_64, .tar.gz + .sha256, GitHub Release, multi-arch image to ghcr, build provenance attestations"
  - "Published AnvilID v0.1.0 (GitHub Release + ghcr.io/specianic/anvil-id:0.1.0 / latest)"
  - "release/0.1 maintenance branch"
affects: [all future releases, Phase 3 gate (0.2.0)]
tech-stack:
  added: [GitHub artifact attestations, docker buildx multi-arch]
  patterns: ["Release from a maintenance branch cut at the phase gate commit, so in-progress next-phase work on main never ships", "Tag must equal anvilid crate version (meta job enforces)"]
key-files:
  created:
    - .github/workflows/release.yml
    - scripts/release-artifacts.sh
    - docs/RELEASING.md
  modified:
    - Dockerfile
    - scripts/docker-image.sh
    - README.md
    - docs/ARCHITECTURE.md
key-decisions:
  - "v0.1.0 cut from branch release/0.1 = Phase 2 gate 67dd7f8 + the four release-pipeline commits + version bump; main keeps 0.0.0 until Phase 3's gate sets 0.2.0; release/0.1 is not merged back"
  - "ghcr package is private by default: anonymous pull fails until the owner sets the package visibility to public (not worked around)"
requirements-completed: [OPS-01]
duration: ~25min (continuation; excludes the earlier pipeline/dry-run work)
completed: 2026-11-25
---

# Phase 2 Plan 23: Release pipeline and v0.1.0 Summary

**Tag-triggered GitHub Actions release (static musl Linux amd64/arm64, macOS arm64/x86_64, SHA-256 files, provenance attestations, multi-arch nonroot 19 MB image on ghcr). v0.1.0 is published from a `release/0.1` branch cut at the Phase 2 gate. Anonymous image pull is blocked until the ghcr package is made public.**

## Release

- GitHub Release: https://github.com/specianic/anvil-id/releases/tag/v0.1.0 (normal release, not draft or prerelease)
- Tag-triggered run (green, all 8 jobs): https://github.com/specianic/anvil-id/actions/runs/45559945860
- Earlier dry run (workflow_dispatch on main, green): https://github.com/specianic/anvil-id/actions/runs/45557179001

### Assets (4 archives + 4 checksums)

| Asset | Size |
|-------|------|
| anvilid-0.1.0-x86_64-unknown-linux-musl.tar.gz (+ .sha256) | 7.3 MB |
| anvilid-0.1.0-aarch64-unknown-linux-musl.tar.gz (+ .sha256) | 6.8 MB |
| anvilid-0.1.0-aarch64-apple-darwin.tar.gz (+ .sha256) | 6.2 MB |
| anvilid-0.1.0-x86_64-apple-darwin.tar.gz (+ .sha256) | 6.9 MB |

The attestations live in GitHub's attestation store, not as release assets. Check them with `gh attestation verify`.

### Verification (run locally after publish)

- `gh release download` of the x86_64 musl archive, then `sha256sum -c anvilid-0.1.0-x86_64-unknown-linux-musl.tar.gz.sha256`: **OK**
- `gh attestation verify anvilid-0.1.0-x86_64-unknown-linux-musl.tar.gz --repo specianic/anvil-id`: exit 0
- The archive contains `anvilid`, `LICENSE` and `README.md`. The binary is a static-pie x86-64 ELF, stripped. `anvilid --version` prints `anvilid 0.1.0`
- Image `ghcr.io/specianic/anvil-id:0.1.0` is an OCI index with linux/amd64 and linux/arm64 entries. Index digest is `sha256:6424f2c4f6c185566d2bae332583adea6a79c4095767c4cd154566abd77e6ac6`, and `latest` points to the same digest.
  - amd64 image is 19.3 MB, user `nonroot`, with labels `org.opencontainers.image.source=https://github.com/specianic/anvil-id` and `version=0.1.0`
- **Anonymous pull: FAILS.** With an empty DOCKER_CONFIG, `docker pull` returns `unauthorized`, and the anonymous ghcr token endpoint returns `authentication required`. `gh api /users/specianic/packages/container/anvil-id` reports `visibility: private`. ghcr creates new packages as private. **Owner action required:** open GitHub > Packages > anvil-id > Package settings > Change visibility > Public. I did not work around this.
- Authenticated pull plus `docker run --rm ghcr.io/specianic/anvil-id:0.1.0` prints `Setup URL: http://localhost:8080/setup?token=...`, listens on 0.0.0.0:8080 and shuts down cleanly on SIGTERM. So the image works once it is public.

## Branch / tag strategy

- On main, Phase 3 commits had already landed on top of the Phase 2 gate. To keep v0.1.0 to exactly the verified Phase 2 code, branch `release/0.1` was cut from `67dd7f8`, the Phase 2 gate with CI verified green.
- These were cherry-picked without conflicts: 9862415 became 41381c7 (workflow + packaging), fd961f4 became fed08fb (docs), a58728f became dea3a47 (arm64 image fix), and 9d352db became 5d236f9 (smoke-test wait).
- `9fb067b chore(release): 0.1.0` changes the `anvilid` version from 0.0.0 to 0.1.0 in `crates/anvilid/Cargo.toml` and `Cargo.lock`, on the release branch only.
- Checks on the branch before tagging: `cargo build --release --locked -p anvilid` passed and `--version` printed 0.1.0; `cargo test --workspace --locked` passed 793 tests with 0 failures across 52 test binaries (SQLite); `cargo clippy --workspace --all-targets --locked -- -D warnings` was clean.
- The annotated tag `v0.1.0` points at 9fb067b. `release/0.1` is pushed and is not merged into main. Main's crate version stays 0.0.0, and Phase 3's gate sets 0.2.0.
- Patch releases (0.1.x) are cut from `release/0.1`.

## Task Commits

On main (before the checkpoint):
1. Task 1: `9862415` feat(02-23): tag-triggered release workflow and packaging script
2. Task 2: `fd961f4` docs(02-23): release process and install instructions; `a58728f` fix(02-23): arm64 image arch + gate; `9d352db` fix(02-23): smoke test waits for setup URL

On release/0.1: `41381c7`, `fed08fb`, `dea3a47`, `5d236f9` (cherry-picks), `9fb067b` chore(release): 0.1.0

## Deviations from Plan

- **The release does not come from main.** The plan said to tag main. At the checkpoint the orchestrator decided to tag a `release/0.1` branch instead, so that Phase 3 work in progress would not ship in 0.1.0.
- **The ghcr visibility truth is not met yet.** "docker pull works anonymously" needs the owner to change the package's visibility. As the plan instructs, this is reported and not worked around.
- **Non-fatal annotation.** The image attestation step warned: "Failed to create storage record ... check that the artifact-metadata:write permission has been included". The image provenance attestation was still created and the job passed. Only the optional org artifact-metadata storage record was skipped. A later release could add `artifact-metadata: write` to the image job, or ignore the warning.

## Issues Encountered

None in the release run. The first tag push was green.

## Next Phase Readiness

OPS-01 is delivered once the package is public: an operator can download a static Linux binary or a macOS binary, or pull an image under 50 MB.

## Self-Check: PASSED

- Release v0.1.0 exists with 8 assets (4 .tar.gz + 4 .sha256)
- origin `release/0.1` = 9fb067b; tag `v0.1.0^{}` = 9fb067b
- Run 45559945860 conclusion: success
