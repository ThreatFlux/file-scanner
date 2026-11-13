# ThreatFlux Rust Dockerfile
# Multi-stage build for file-scanner using the standard ThreatFlux Rust template.
#
# Keep the standard Debian 13 Rust builder, with a minimal nonroot Wolfi GNU
# runtime. The pinned Wolfi glibc 2.44 runtime fixes the affected glibc 2.41
# components in Debian 13; it preserves the GNU ABI used by the scanner and tini.
# Both amd64 and arm64 runtime indexes are scanned at all severities.
#
# Base images are pinned by multi-arch index digest for reproducibility.
# Refresh with: docker buildx imagetools inspect <image>
# Dependabot tracks both image references. See docs/security for fix evidence.

# rust 1.100.0 on Debian 13 (trixie); multi-arch index digest
FROM rust:1.100.0-trixie@sha256:e19840879045c951c905d0eaa9887f3439c62000e429963371b376bac8d38c31 AS rust-base

# Install every requested component before the nonroot builder enters the repo.
ENV RUST_VERSION=1.100.0
RUN rustup component add --toolchain 1.100.0 clippy rustfmt llvm-tools-preview && \
    rustc --version | grep -q '^rustc 1[.]100[.]0 '

ARG VERSION=0.3.12
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG BINARY_NAME=file-scanner
ARG BINARY_PACKAGE=threatflux-file-scanner
ARG SBOM_MANIFEST_PATH=Cargo.toml
ARG OCI_IMAGE_TITLE="File Scanner"
ARG OCI_IMAGE_DESCRIPTION="Static file analysis CLI and MCP server"
ARG OCI_IMAGE_VENDOR=ThreatFlux
ARG OCI_IMAGE_SOURCE=https://github.com/ThreatFlux/file-scanner

# tini is installed here so the minimal runtime stage can copy it out:
# PID 1 must reap zombies and forward signals. Package revisions
# follow the pinned base image's Debian 13 repositories.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    lld \
    pkg-config \
    tini \
    && rm -rf /var/lib/apt/lists/*

FROM rust-base AS builder

RUN useradd -m -u 1000 builder
USER builder
ENV CARGO_HOME=/home/builder/.cargo
ENV PATH="/home/builder/.cargo/bin:/usr/local/cargo/bin:${PATH}"
WORKDIR /build
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
# Compile the fixed zlib 1.4 bundled by locked libz-sys 1.1.33, rather than
# accidentally linking the builder distribution's older system libz.
ENV LIBZ_SYS_STATIC=1

COPY --chown=builder:builder . .

RUN rustc --version --verbose && cargo --version && \
    if [ -n "${BINARY_PACKAGE}" ]; then \
      cargo build --release -p "${BINARY_PACKAGE}" --bin "${BINARY_NAME}" --all-features --locked; \
    else \
      cargo build --release --bin "${BINARY_NAME}" --all-features --locked; \
    fi

RUN cargo install cargo-cyclonedx --locked --version 0.5.10 && \
    cargo cyclonedx \
      --manifest-path "${SBOM_MANIFEST_PATH}" \
      --all-features \
      --format json \
      --spec-version 1.5 \
      --override-filename "${BINARY_NAME}-sbom" && \
    test -s "/build/${BINARY_NAME}-sbom.json"

# Stage the runtime filesystem under a fixed layout. Exec-form ENTRYPOINT and
# HEALTHCHECK do not expand build ARGs, so the binary always lands at
# /usr/local/bin/file-scanner. The writable /data directory is created here
# because the runtime has no shell to mkdir with.
RUN mkdir -p /home/builder/out/bin /home/builder/out/doc /home/builder/runtime-skel/data && \
    cp "target/release/${BINARY_NAME}" /home/builder/out/bin/file-scanner && \
    cp "/build/${BINARY_NAME}-sbom.json" /home/builder/out/doc/sbom.cdx.json

# Wolfi glibc 2.44, nonroot uid/gid 65532; amd64/arm64 multi-arch index digest
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:cb7aa4681bef604e99ad3fb6fb365330a3ca24fcee56df0b60b27ac4983409eb AS runtime

ARG VERSION=0.3.12
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG OCI_IMAGE_TITLE="File Scanner"
ARG OCI_IMAGE_DESCRIPTION="Static file analysis CLI and MCP server"
ARG OCI_IMAGE_VENDOR=ThreatFlux
ARG OCI_IMAGE_SOURCE=https://github.com/ThreatFlux/file-scanner

LABEL org.opencontainers.image.title="${OCI_IMAGE_TITLE}" \
      org.opencontainers.image.description="${OCI_IMAGE_DESCRIPTION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="${OCI_IMAGE_VENDOR}" \
      org.opencontainers.image.source="${OCI_IMAGE_SOURCE}" \
      org.opencontainers.image.authors="Wyatt Roersma <wyattroersma@gmail.com>" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.documentation="https://github.com/ThreatFlux/file-scanner/blob/main/README.md" \
      io.modelcontextprotocol.server.name="io.github.threatflux/file-scanner"

COPY --from=builder /usr/bin/tini /usr/bin/tini

# The binary and SBOM stay root-owned so the runtime user cannot modify them;
# only the /data working directory belongs to the nonroot user.
COPY --from=builder --chown=0:0 /home/builder/out/bin/ /usr/local/bin/
COPY --from=builder --chown=0:0 /home/builder/out/doc/ /usr/share/doc/file-scanner/
COPY --from=builder --chown=65532:65532 /home/builder/runtime-skel/data /data

USER 65532:65532
WORKDIR /data

# Exec form (the runtime has no shell); a nonzero exit means unhealthy. This only proves that the
# binary starts. For the HTTP server, probe GET /health on the published port instead.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/file-scanner", "--help"]

# Arguments go straight to the scanner, and there is no default command, so always pass some:
#   scan a file:  docker run --rm -v "$PWD:/data:ro" <image> /data/file --format json
#   MCP, stdio:   docker run -i --rm -v "$PWD:$PWD:ro" -w "$PWD" <image> mcp-stdio --allow-root "$PWD"
#   MCP, HTTP:    docker run --rm -p 127.0.0.1:3000:3000 -v DIR:/data:ro <image> \
#                   mcp-http --host 0.0.0.0 --allow-root /data \
#                   (set FILE_SCANNER_AUTH_TOKEN with -e)
# (These need an image newer than 0.3.12.) Tool calls name paths inside the container, so only mounted files can be analyzed.
# The HTTP server must bind 0.0.0.0 here for Docker to reach it; publish the port on 127.0.0.1.
# See DEPLOYMENT_GUIDE.md.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/file-scanner"]

EXPOSE 3000
