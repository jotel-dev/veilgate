# Stage 1: Build binary using official Rust image matching local rustc (1.96.1)
FROM rust:1.96.1-slim-bookworm AS builder

# Install build essentials for C/C++ dependencies (bundled SQLite, ring, TLS)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies: copy Cargo manifests first
COPY backend/Cargo.toml backend/Cargo.lock ./

# Create dummy sources for lib and all binary targets to pre-build dependencies
RUN mkdir -p src/bin && \
    echo "pub fn dummy() {}" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/server.rs && \
    echo "fn main() {}" > src/bin/scanner.rs && \
    echo "fn main() {}" > src/bin/keygen.rs && \
    echo "fn main() {}" > src/bin/invoice_demo.rs && \
    echo "fn main() {}" > src/bin/process_assets.rs && \
    echo "fn main() {}" > src/bin/scan_spike.rs && \
    cargo build --release --bin server && \
    rm -rf src

# Copy actual source code
COPY backend/src ./src

# Touch source files to ensure cargo compiles actual code and build release server binary
RUN touch src/lib.rs src/bin/server.rs && \
    cargo build --release --bin server

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim AS runner

# Install only ca-certificates (required for TLS gRPC connection to lightwalletd)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user
RUN groupadd -r veilgate && useradd -r -g veilgate -m -d /home/veilgate veilgate

WORKDIR /app

# Create data directory for SQLite database with proper ownership
RUN mkdir -p /app/data && chown -R veilgate:veilgate /app

# Copy compiled binary from builder
COPY --from=builder /app/target/release/server /app/server
RUN chown veilgate:veilgate /app/server && chmod +x /app/server

USER veilgate

ENV PORT=8080
ENV VEILGATE_DB_PATH=/app/data/veilgate.db

EXPOSE 8080

ENTRYPOINT ["/app/server"]
