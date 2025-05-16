# Sofa - CouchDB Proxy

A lightweight CouchDB proxy server written in Rust. This service proxies all REST API calls to a CouchDB instance.

## Features

- Proxies all CouchDB REST API calls
- Configurable CouchDB URL and credentials
- OAuth2 authentication support
- Docker support for easy deployment
- CORS enabled for browser applications
- Lightweight and fast Rust implementation

## Configuration

The application can be configured through:
- Environment variables (prefixed with `SOFA_`)
- Configuration file in the `./config` directory

Default configuration:
- CouchDB URL: `http://localhost:5984`
- CouchDB credentials: `admin:password`
- Server port: `3000`
- OAuth2 authentication: disabled

### Environment Variables

#### CouchDB Configuration
- `SOFA_COUCHDB_URL`: URL of the CouchDB server (default: http://localhost:5984)
- `SOFA_COUCHDB_USERNAME`: Username for CouchDB authentication (default: admin)
- `SOFA_COUCHDB_PASSWORD`: Password for CouchDB authentication (default: password)
- `SOFA_SERVER_PORT`: Port on which the proxy will listen (default: 3000)
- `CONFIG_DIR`: Directory containing config files (default: ./config)

#### OAuth2 Configuration
- `SOFA_AUTH_ENABLED`: Enable OAuth2 authentication (default: false)
- `SOFA_AUTH_ISSUER`: The expected issuer of the JWT token
- `SOFA_AUTH_AUDIENCE`: The expected audience of the JWT token
- `SOFA_AUTH_JWKS_URL`: URL to the JWKS endpoint for fetching public keys

## OAuth2 Authentication

When OAuth2 authentication is enabled, the proxy will validate JWT tokens provided in the `Authorization` header of incoming requests. The token must be provided as a Bearer token:

```
Authorization: Bearer <your_jwt_token>
```

The token will be validated against the configured issuer, audience, and will be verified using the public keys from the JWKS endpoint.

## Running with Docker

Build the Docker image:

```bash
docker build -t sofa .
```

Run the container:

```bash
docker run -p 3000:3000 -e SOFA_COUCHDB_URL=http://couchdb:5984 sofa
```

Run with OAuth2 authentication enabled:

```bash
docker run -p 3000:3000 \
  -e SOFA_COUCHDB_URL=http://couchdb:5984 \
  -e SOFA_AUTH_ENABLED=true \
  -e SOFA_AUTH_ISSUER=https://your-auth-server.com \
  -e SOFA_AUTH_AUDIENCE=your-api-audience \
  -e SOFA_AUTH_JWKS_URL=https://your-auth-server.com/.well-known/jwks.json \
  sofa
```

## Running Locally

Clone the repository and build the project:

```bash
cargo build --release
```

Run the application:

```bash
./target/release/sofa
```

Run with OAuth2 authentication enabled:

```bash
SOFA_AUTH_ENABLED=true \
SOFA_AUTH_ISSUER=https://your-auth-server.com \
SOFA_AUTH_AUDIENCE=your-api-audience \
SOFA_AUTH_JWKS_URL=https://your-auth-server.com/.well-known/jwks.json \
./target/release/sofa
```

## Kubernetes Deployment

We use Kustomize for managing Kubernetes configurations across different environments (dev, test, prod).

### Directory Structure

Our Kubernetes configurations are organized in a standard Kustomize structure:

```
k8s/
├── base/                  # Base configurations shared across environments
│   ├── couchdb/           # CouchDB database service
│   ├── dex/               # Dex OAuth2 provider
│   ├── sofa/              # Sofa CouchDB proxy service with OAuth2
│   └── kustomization.yaml # Main base kustomization file
│
└── overlays/              # Environment-specific configurations
    ├── dev/               # Development environment
    ├── prod/              # Production environment
    └── test/              # Testing environment with automated test client
```

### Deploying with Kustomize

You can directly deploy using kubectl with the `-k` flag:

```bash
# Deploy the development environment
kubectl apply -k k8s/overlays/dev

# Deploy the production environment
kubectl apply -k k8s/overlays/prod

# Deploy the test environment
kubectl apply -k k8s/overlays/test
```

See the `k8s/README.md` file for more details about the Kustomize configuration.

## Automated Deployment with Taskfile

We provide a Taskfile for easy deployment and testing. You'll need to install [Task](https://taskfile.dev/) first:

```bash
# On macOS
brew install go-task

# On Linux
sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b ~/.local/bin
```

Available tasks:

```bash
# Show available tasks
task

# Build the Sofa Docker image
task build

# Create a Kind cluster
task create-cluster

# Load the image into the cluster
task load-image

# Apply Kubernetes manifests for the current environment (default: dev)
task apply-manifests

# Switch between environments (dev, test, prod)
task switch-env -- dev
task switch-env -- prod

# Show the current active environment
task show-env

# Set up port-forwarding to access services locally (interactive)
task port-forward

# Run the full setup (build, create cluster, load image, apply manifests)
task setup

# Run the OAuth2 test client inside the cluster (no port-forwarding needed)
task run-test

# Run the OAuth2 test client locally (requires port-forwarding)
task run-test-local
```

For a complete setup and test workflow:

```bash
# Setup everything (default environment: dev)
task setup

# Switch to the test environment and run the test
task switch-env -- test
task run-test

# If you want to access the services locally:
task port-forward
```

## Testing OAuth2 Authentication

We provide two ways to test the OAuth2 authentication setup:

### 1. In-Cluster Testing

This approach runs a test pod inside the Kubernetes cluster that communicates directly with the Dex and Sofa services:

```bash
# Fully automated setup and test
./scripts/setup-test-env.sh

# Or manually
task setup
task run-test
```

The in-cluster test will:
1. Create a test pod with curl
2. Try to access Sofa without a token (should fail)
3. Get a token from Dex
4. Access Sofa with the token (should succeed)

### 2. Local Testing (with Port Forwarding)

If you want to run the tests from your local machine:

```bash
# In one terminal, start port-forwarding
task port-forward

# In another terminal, run the local test client
task run-test-local
```

## License

MIT 