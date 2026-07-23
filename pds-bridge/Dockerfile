# pds-bridge — the Bluesky bridge (bean ezk6). Its own dokku app beside the
# broker; build from the repo root: docker build -f pds-bridge/Dockerfile .

# Stage 1: Build
FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Copy manifests first for better caching (all workspace members must be
# present for cargo to resolve the workspace)
COPY Cargo.toml Cargo.lock ./
COPY browserid-core/Cargo.toml browserid-core/
COPY browserid-registrar/Cargo.toml browserid-registrar/
COPY browserid-broker/Cargo.toml browserid-broker/
COPY browserid-agent/Cargo.toml browserid-agent/
COPY browserid-rp/Cargo.toml browserid-rp/
COPY pds-bridge/Cargo.toml pds-bridge/

# Create dummy source files to cache dependencies
RUN mkdir -p browserid-core/src browserid-registrar/src browserid-broker/src browserid-agent/src browserid-rp/src pds-bridge/src && \
    echo "pub fn dummy() {}" > browserid-core/src/lib.rs && \
    echo "pub fn dummy() {}" > browserid-registrar/src/lib.rs && \
    echo "pub fn dummy() {}" > browserid-agent/src/lib.rs && \
    echo "pub fn dummy() {}" > browserid-rp/src/lib.rs && \
    echo "pub fn dummy() {}" > pds-bridge/src/lib.rs && \
    echo "fn main() {}" > pds-bridge/src/main.rs && \
    echo "fn main() {}" > browserid-broker/src/main.rs && \
    cargo build --release --package pds-bridge && \
    rm -rf browserid-core/src browserid-registrar/src browserid-broker/src browserid-agent/src browserid-rp/src pds-bridge/src

# Copy actual source code
COPY browserid-core/src browserid-core/src
COPY browserid-registrar/src browserid-registrar/src
COPY browserid-agent/src browserid-agent/src
COPY browserid-rp/src browserid-rp/src
COPY browserid-broker/src browserid-broker/src
COPY pds-bridge/src pds-bridge/src

# Touch files to invalidate cache and rebuild
RUN touch browserid-core/src/lib.rs browserid-registrar/src/lib.rs browserid-agent/src/lib.rs browserid-rp/src/lib.rs pds-bridge/src/main.rs && \
    cargo build --release --package pds-bridge

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/pds-bridge /app/

RUN mkdir -p /data

ENV BRIDGE_PORT=5000
ENV BRIDGE_DB=/data/pds-bridge.db

EXPOSE 5000

CMD ["/app/pds-bridge"]
