FROM rust:slim as builder

WORKDIR /usr/src/sofa
COPY . .

# Install dependencies including OpenSSL development libraries
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Build with release profile
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/sofa/target/release/sofa /app/sofa

# Create config directory
RUN mkdir -p /app/config

# Set environment variables
ENV SOFA_SERVER_PORT=3000
ENV SOFA_COUCHDB_URL=http://localhost:5984
ENV SOFA_COUCHDB_USERNAME=admin
ENV SOFA_COUCHDB_PASSWORD=password
ENV CONFIG_DIR=/app/config

# OAuth2 configuration (disabled by default)
ENV SOFA_AUTH_ENABLED=false
# ENV SOFA_AUTH_ISSUER=https://your-auth-server.com
# ENV SOFA_AUTH_AUDIENCE=your-api-audience
# ENV SOFA_AUTH_JWKS_URL=https://your-auth-server.com/.well-known/jwks.json

# Expose the server port
EXPOSE 3000

# Run the binary
CMD ["/app/sofa"] 