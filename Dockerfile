# Build stage
FROM rust:1.88.0-slim AS builder

# Build arguments
ARG VERSION=unknown
ARG BUILD_DATE
ARG VCS_REF

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/file-scanner

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Create dummy directories and files for dependencies
RUN mkdir -p src benches && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > benches/hash_benchmark.rs && \
    echo "fn main() {}" > benches/parser_benchmark.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf src benches target/release/deps/*file*scanner* target/release/.fingerprint/*file*scanner*

# Copy source code
COPY src ./src
COPY benches ./benches

# Build for release with version info
ENV CARGO_PKG_VERSION=${VERSION}
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash scanner

# Copy the binary from builder
COPY --from=builder /usr/src/file-scanner/target/release/file-scanner /usr/local/bin/file-scanner

# Set ownership
RUN chown scanner:scanner /usr/local/bin/file-scanner

# Switch to non-root user
USER scanner

# Set working directory
WORKDIR /data

# Default command (can be overridden)
ENTRYPOINT ["file-scanner"]

# Health check for MCP server mode
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/file-scanner", "--version"] || exit 1

# Expose common MCP server ports
EXPOSE 3000

# Labels with build info
LABEL org.opencontainers.image.title="File Scanner"
LABEL org.opencontainers.image.description="Comprehensive native file scanner with MCP server support"
LABEL org.opencontainers.image.authors="Wyatt Roersma <wyattroersma@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/ThreatFlux/file-scanner"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.vendor="ThreatFlux"
LABEL org.opencontainers.image.documentation="https://github.com/ThreatFlux/file-scanner/blob/main/README.md"
