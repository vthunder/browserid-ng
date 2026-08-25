# Stage 1: Build
FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Copy manifests first for better caching (all workspace members must be
# present for cargo to resolve the workspace, even when only building the broker)
COPY Cargo.toml Cargo.lock ./
COPY browserid-core/Cargo.toml browserid-core/
COPY browserid-dnssec/Cargo.toml browserid-dnssec/
COPY browserid-registrar/Cargo.toml browserid-registrar/
COPY browserid-broker/Cargo.toml browserid-broker/
COPY browserid-agent/Cargo.toml browserid-agent/
COPY browserid-rp/Cargo.toml browserid-rp/

# Create dummy source files to cache dependencies
RUN mkdir -p browserid-core/src browserid-dnssec/src browserid-registrar/src browserid-broker/src browserid-agent/src browserid-rp/src && \
    echo "pub fn dummy() {}" > browserid-core/src/lib.rs && \
    echo "pub fn dummy() {}" > browserid-dnssec/src/lib.rs && \
    echo "pub fn dummy() {}" > browserid-registrar/src/lib.rs && \
    echo "pub fn dummy() {}" > browserid-agent/src/lib.rs && \
    echo "pub fn dummy() {}" > browserid-rp/src/lib.rs && \
    echo "fn main() {}" > browserid-broker/src/main.rs && \
    cargo build --release --package browserid-broker && \
    rm -rf browserid-core/src browserid-dnssec/src browserid-registrar/src browserid-broker/src browserid-agent/src browserid-rp/src

# Copy actual source code
COPY browserid-core/src browserid-core/src
COPY browserid-dnssec/src browserid-dnssec/src
COPY browserid-registrar/src browserid-registrar/src
COPY browserid-agent/src browserid-agent/src
COPY browserid-rp/src browserid-rp/src
COPY browserid-broker/src browserid-broker/src
# The broker include_str!'s its OpenAPI spec from the crate root.
COPY browserid-broker/openapi.json browserid-broker/

# Touch files to invalidate cache and rebuild
RUN touch browserid-core/src/lib.rs browserid-dnssec/src/lib.rs browserid-registrar/src/lib.rs browserid-agent/src/lib.rs browserid-rp/src/lib.rs browserid-broker/src/main.rs && \
    cargo build --release --package browserid-broker

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary
COPY --from=builder /build/target/release/browserid-broker /app/

# Copy static files
COPY browserid-broker/static /app/static

# Create data directory
RUN mkdir -p /data

ENV BROKER_PORT=5000
ENV DATABASE_PATH=/data/browserid.db
ENV BROKER_KEY_FILE=/data/broker-key.json

EXPOSE 5000

CMD ["/app/browserid-broker"]
