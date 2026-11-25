# AnvilID container image: the static musl binary on distroless (no shell, no package manager).
#
# Build with `scripts/docker-image.sh` (or `just docker-image`), which first produces
# target/x86_64-unknown-linux-musl/release/anvilid via scripts/build-musl.sh and an empty
# target/docker/data directory. No Rust toolchain is involved in this Dockerfile.
#
# Zero-config run:
#   docker run -p 8080:8080 anvilid:ci
# The setup URL is printed to the logs on first start. Data (SQLite, KEK) lives in /data;
# mount a volume there to keep it across container restarts.

# gcr.io/distroless/static-debian13:nonroot, pinned by digest.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5

LABEL org.opencontainers.image.title="AnvilID" \
      org.opencontainers.image.description="Self-hostable OpenID Connect provider" \
      org.opencontainers.image.source="https://github.com/specianic/anvil-id" \
      org.opencontainers.image.licenses="MIT"

COPY --chown=nonroot:nonroot target/x86_64-unknown-linux-musl/release/anvilid /usr/local/bin/anvilid
# Distroless has no shell to mkdir with: copy an empty directory to get a writable /data.
COPY --chown=nonroot:nonroot target/docker/data /data

WORKDIR /data
# The binary defaults to 127.0.0.1:8080, which is unreachable through `-p`. Inside the container
# listen on every interface; public_url stays the default http://localhost:8080 (dev mode).
ENV ANVILID_LISTEN=0.0.0.0:8080
EXPOSE 8080
USER nonroot

ENTRYPOINT ["/usr/local/bin/anvilid"]
CMD ["serve"]
