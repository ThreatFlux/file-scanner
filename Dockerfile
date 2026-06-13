# ThreatFlux Rust Dockerfile
# Multi-stage build for file-scanner using the standard ThreatFlux Rust template.

FROM rust:1.96.0-bookworm AS rust-base

ARG VERSION=0.2.9
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG BINARY_NAME=file-scanner
ARG BINARY_PACKAGE=file-scanner
ARG SBOM_MANIFEST_PATH=Cargo.toml
ARG OCI_IMAGE_TITLE="File Scanner"
ARG OCI_IMAGE_DESCRIPTION="Comprehensive native file scanner with MCP server support"
ARG OCI_IMAGE_VENDOR=ThreatFlux
ARG OCI_IMAGE_SOURCE=https://github.com/ThreatFlux/file-scanner

RUN apt-get update && apt-get install -y \
    build-essential \
    ca-certificates \
    clang \
    curl \
    libssl-dev \
    lld \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

FROM rust-base AS builder

RUN useradd -m -u 1000 builder
USER builder
ENV CARGO_HOME=/home/builder/.cargo
ENV PATH="/home/builder/.cargo/bin:/usr/local/cargo/bin:${PATH}"
WORKDIR /build

COPY --chown=builder:builder . .

RUN if [ -n "${BINARY_PACKAGE}" ]; then \
      cargo build --release -p "${BINARY_PACKAGE}" --bin "${BINARY_NAME}" --all-features; \
    else \
      cargo build --release --bin "${BINARY_NAME}" --all-features || cargo build --release --all-features; \
    fi

RUN cargo install cargo-cyclonedx --locked --version 0.5.8 && \
    cargo cyclonedx \
      --manifest-path "${SBOM_MANIFEST_PATH}" \
      --all-features \
      --format json \
      --spec-version 1.5 \
      --override-filename "${BINARY_NAME}-sbom"

FROM debian:bookworm-slim AS runtime

ARG VERSION=0.2.9
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG BINARY_NAME=file-scanner
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

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/share/doc/file-scanner /data \
    && useradd -m -u 1000 -s /bin/bash scanner

COPY --from=builder /build/target/release/${BINARY_NAME} /usr/local/bin/file-scanner
COPY --from=builder /build/${BINARY_NAME}-sbom.json /usr/share/doc/file-scanner/sbom.cdx.json

RUN chown -R scanner:scanner /usr/local/bin/file-scanner /usr/share/doc/file-scanner /data

USER scanner
WORKDIR /data

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/file-scanner"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/file-scanner", "--help"]

EXPOSE 3000
