# Releasing AnvilID

Releases are built and published by [`.github/workflows/release.yml`](https://github.com/specianic/anvil-id/blob/main/.github/workflows/release.yml)
when a version tag is pushed. Nothing is built or uploaded from a developer machine.

## What a release publishes

For a tag `vX.Y.Z` the workflow publishes:

| Artifact | Where |
|---|---|
| `anvilid-X.Y.Z-x86_64-unknown-linux-musl.tar.gz` | GitHub Release (static, runs on any x86_64 Linux) |
| `anvilid-X.Y.Z-aarch64-unknown-linux-musl.tar.gz` | GitHub Release (static, runs on any arm64 Linux) |
| `anvilid-X.Y.Z-aarch64-apple-darwin.tar.gz` | GitHub Release (macOS, Apple silicon) |
| `anvilid-X.Y.Z-x86_64-apple-darwin.tar.gz` | GitHub Release (macOS, Intel) |
| `<archive>.sha256` for each archive | GitHub Release |
| `ghcr.io/specianic/anvil-id:X.Y.Z` (linux/amd64, linux/arm64) | GitHub Container Registry |
| `ghcr.io/specianic/anvil-id:latest` | only for tags without a prerelease suffix |
| Build provenance attestations for every archive and the image | GitHub attestations |

Each archive contains the `anvilid` binary, `LICENSE` and `README.md` in a directory named after
the archive. Every binary embeds the admin console: the workflow builds `admin-ui` once, and a build
whose binary does not contain it fails (`scripts/check-console-embedded.sh`). Linux binaries are built natively per architecture in the official Rust Alpine image
(`scripts/build-musl.sh`) and asserted to be statically linked. The container image is the Linux
binary on distroless `static-debian13:nonroot`. Before anything is pushed, each architecture's
image must be under 50 MB, run as `nonroot`, and pass a zero-configuration smoke test
(`scripts/docker-image.sh`, the arm64 image runs under QEMU).

Tags with a suffix (`v0.2.0-rc.1`) produce a GitHub prerelease and do not move `latest`.

## Cutting a release

1. Make sure `main` is green in CI.
2. Set `version` in `crates/anvilid/Cargo.toml` to the release version, run `cargo check` so
   `Cargo.lock` records it, and commit both. The workflow refuses a tag that does not match this
   version, so `anvilid --version` always reports the release it came from.
   In the same commit, pin the release's new migrations of both backends so they become immutable
   (`scripts/check-migrations.sh` fails on any later edit):

   ```bash
   sha256sum crates/anvil-storage-sqlite/migrations/NNNN_*.sql \
             crates/anvil-storage-postgres/migrations/NNNN_*.sql >> scripts/released-migrations.sha256
   scripts/check-migrations.sh
   ```

   Add upgrade notes for the release to [`docs/UPGRADING.md`](UPGRADING.md).
3. Optional dry run: run the `release` workflow manually (`gh workflow run release.yml --ref main`).
   It builds and packages every target and runs the image gate, but pushes, attests and releases
   nothing.
4. Tag and push:

   ```bash
   git tag -a vX.Y.Z -m "AnvilID X.Y.Z"
   git push origin vX.Y.Z
   gh run watch --exit-status "$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
   ```

5. Check the result: `gh release view vX.Y.Z` lists four archives and four `.sha256` files, and
   `docker pull ghcr.io/specianic/anvil-id:X.Y.Z` works without logging in. (Anonymous pulls need
   the ghcr.io package to be public; that is a one-time package setting, not part of the workflow.)

If the run fails before the GitHub Release is created (the release job runs last), fix the cause,
delete the tag locally and remotely (`git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`) and
tag again. An image that was already pushed is overwritten by the retry. Once a GitHub Release
exists, do not delete or replace it; publish a new patch version instead.

The workflow uses only the repository's `GITHUB_TOKEN`. Jobs get the least permissions they need:
`packages: write` only for the image job, `contents: write` only for the release job, and
`id-token: write` + `attestations: write` for the two jobs that create attestations. Third-party
actions are pinned to commit SHAs.

## Verifying a download

```bash
V=X.Y.Z
T=x86_64-unknown-linux-musl
gh release download "v$V" --repo specianic/anvil-id --pattern "anvilid-$V-$T.tar.gz*"

# Checksum (on macOS: shasum -a 256 -c ...)
sha256sum -c "anvilid-$V-$T.tar.gz.sha256"

# Provenance: proves the archive was built by this repository's release workflow
gh attestation verify "anvilid-$V-$T.tar.gz" --repo specianic/anvil-id

# Container image provenance
gh attestation verify "oci://ghcr.io/specianic/anvil-id:$V" --repo specianic/anvil-id
```
