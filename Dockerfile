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

# rust 1.99.1 on Debian 13 (trixie); multi-arch index digest
FROM rust:1.99.1-trixie@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS rust-base

ARG VERSION=0.3.5
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG BINARY_NAME=file-scanner
ARG BINARY_PACKAGE=threatflux-file-scanner
ARG SBOM_MANIFEST_PATH=Cargo.toml
ARG OCI_IMAGE_TITLE="File Scanner"
ARG OCI_IMAGE_DESCRIPTION="Comprehensive native file scanner with MCP server support"
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
# Compile the patched zlib 1.3.2 bundled by locked libz-sys 1.1.31, rather than
# accidentally linking the builder distribution's older system libz.
ENV LIBZ_SYS_STATIC=1

COPY --chown=builder:builder . .

RUN rustc --version --verbose && cargo --version && \
    if [ -n "${BINARY_PACKAGE}" ]; then \
      cargo build --release -p "${BINARY_PACKAGE}" --bin "${BINARY_NAME}" --all-features --locked; \
    else \
      cargo build --release --bin "${BINARY_NAME}" --all-features --locked; \
    fi

RUN cargo install cargo-cyclonedx --locked --version 0.5.9 && \
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
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:3f1283dc2a6a48c25cd2e1c7730a871b19b721975240e108e0d6a73b555a3a20 AS runtime

ARG VERSION=0.3.5
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG OCI_IMAGE_TITLE="File Scanner"
ARG OCI_IMAGE_DESCRIPTION="Comprehensive native file scanner with MCP server support"
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
      org.opencontainers.image.documentation="https://github.com/ThreatFlux/file-scanner/blob/main/README.md"

COPY --from=builder /usr/bin/tini /usr/bin/tini

# The binary and SBOM stay root-owned so the runtime user cannot modify them;
# only the /data working directory belongs to the nonroot user.
COPY --from=builder --chown=0:0 /home/builder/out/bin/ /usr/local/bin/
COPY --from=builder --chown=0:0 /home/builder/out/doc/ /usr/share/doc/file-scanner/
COPY --from=builder --chown=65532:65532 /home/builder/runtime-skel/data /data

USER 65532:65532
WORKDIR /data

# Exec form (the runtime has no shell); a nonzero exit means unhealthy.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/file-scanner", "--help"]

# Arguments go straight to the scanner: `docker run <image> /data/file --format json`.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/file-scanner"]

EXPOSE 3000
