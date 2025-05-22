FROM rust:slim AS builder

WORKDIR /usr/src/audit-service
COPY . .

# Install dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Build with release profile
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/audit-service/target/release/audit-service /app/audit-service

# Expose the server port
EXPOSE 3001

# Run the binary
CMD ["/app/audit-service"] 