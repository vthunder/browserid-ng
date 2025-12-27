# Stage 1: Build
FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./
COPY browserid-core/Cargo.toml browserid-core/
COPY browserid-broker/Cargo.toml browserid-broker/

# Create dummy source files to cache dependencies
RUN mkdir -p browserid-core/src browserid-broker/src && \
    echo "pub fn dummy() {}" > browserid-core/src/lib.rs && \
    echo "fn main() {}" > browserid-broker/src/main.rs && \
    cargo build --release --package browserid-broker && \
    rm -rf browserid-core/src browserid-broker/src

# Copy actual source code
COPY browserid-core/src browserid-core/src
COPY browserid-broker/src browserid-broker/src

# Touch files to invalidate cache and rebuild
RUN touch browserid-core/src/lib.rs browserid-broker/src/main.rs && \
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
