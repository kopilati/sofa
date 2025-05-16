# Kubernetes Deployment with Kustomize

This directory contains Kubernetes manifests organized with Kustomize for deploying the Sofa CouchDB proxy service with OAuth2 authentication.

## Directory Structure

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

## Environments

### Development Environment (dev)
- Uses the `latest` image tag
- Configured for local development and testing
- Includes development-specific service names and configurations

### Production Environment (prod)
- Uses versioned image tags (e.g., `v1.0.0`)
- Increased resource limits and replicas for reliability
- Production-specific service configurations

### Test Environment (test)
- Includes a test client job to verify OAuth2 functionality
- Used for automated testing in CI/CD pipelines

## Usage

The project uses a Taskfile to simplify deployment and management. Here are common commands:

```bash
# Apply the dev environment configuration
task apply-manifests

# Switch to a different environment
task switch-env -- prod
task apply-manifests

# Run the automated tests
task run-test
```

You can also apply configurations directly with kubectl:

```bash
# Apply development configuration
kubectl apply -k k8s/overlays/dev

# Apply production configuration
kubectl apply -k k8s/overlays/prod

# Apply test configuration
kubectl apply -k k8s/overlays/test
```

## Components

### CouchDB
- Standard CouchDB installation
- Used as the backend database

### Dex
- OpenID Connect identity provider
- Provides OAuth2 authentication for Sofa
- Configured with static test users in development and test environments

### Sofa
- CouchDB proxy with OAuth2 authentication
- Validates JWT tokens from Dex
- Provides secure access to CouchDB 