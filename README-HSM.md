# HSM Provider Architecture

This document explains the Hardware Security Module (HSM) integration in Sofa.

## Architecture Overview

The HSM integration in Sofa is built around a trait-based architecture that allows for multiple implementations:

1. **HsmProvider Trait**: Defines the contract that any HSM implementation must fulfill.
2. **Feature-gated Implementations**: Different HSM backends are conditionally compiled based on feature flags.
3. **Feature-gated Configuration**: Each provider has its own specialized configuration structure, all named `HsmConfig`.
4. **Delegating Service**: The `HsmService` delegates to the appropriate provider.

## Provider Implementations

### HSM Simulator

The `HsmSimulator` implementation is designed for development and testing. It uses a RESTful API to communicate with a simulated HSM service that implements basic cryptographic operations.

This is enabled with the `hsm-simulator` feature flag, which is the default.

Configuration structure:
```rust
#[cfg(feature = "hsm-simulator")]
pub struct HsmConfig {
    pub enabled: bool,
    pub key_name: String,
    pub simulator_url: String,
}
```

### Azure HSM

The `AzureHsm` implementation integrates with Azure Key Vault for production environments. It uses Azure's managed HSM service for secure key operations.

This is enabled with the `azure-hsm` feature flag.

Configuration structure:
```rust
#[cfg(feature = "azure-hsm")]
pub struct HsmConfig {
    pub enabled: bool,
    pub keyvault_url: String,
    pub key_name: String,
    pub key_version: Option<String>,
}
```

### Null Provider

If no HSM provider is enabled through feature flags, a `NullHsmProvider` is used as a fallback. This implementation returns appropriate errors and logs warnings when operations are attempted.

Configuration structure:
```rust
#[cfg(not(any(feature = "hsm-simulator", feature = "azure-hsm")))]
pub struct HsmConfig {
    pub enabled: bool,
}
```

## Client Code

Client code interacts with a unified `HsmService` interface without needing to know which provider is active. The implementation details are completely hidden behind the feature flags.

```rust
// Initialize HSM service with appropriate config (same API regardless of provider)
let hsm_service = create_hsm_service(hsm_config).await?;

// Use HSM service without knowing which provider is active
let encrypted = hsm_service.encrypt(&plaintext).await?;
let decrypted = hsm_service.decrypt(&encrypted).await?;
```

## Feature Flags

The HSM provider to use is selected at compile-time through feature flags:

- `hsm-simulator`: Build with the HSM simulator support (default)
- `azure-hsm`: Build with Azure Key Vault HSM support

## Environment Variables

Each provider looks for specific environment variables:

### HSM Simulator
- `SOFA_HSM_KEY_NAME`: The key name to use in the HSM simulator (default: "sofa-master-key")
- `SOFA_HSM_SIMULATOR_URL`: The URL of the HSM simulator (default: "http://hsm-simulator:8080")

### Azure HSM
- `SOFA_HSM_AZURE_KEYVAULT_URL`: The Azure Key Vault URL (default: "https://your-keyvault.vault.azure.net")
- `SOFA_HSM_AZURE_KEY_NAME`: The key name in Azure Key Vault (default: "sofa-master-key")
- `SOFA_HSM_AZURE_KEY_VERSION`: Optional specific key version to use

## Building with Different Providers

### HSM Simulator (Default)

```
cargo build --features hsm-simulator
# or just
cargo build
```

### Azure HSM

```
cargo build --no-default-features --features azure-hsm
```

## Docker Builds

Two Dockerfiles are provided:

1. `Dockerfile`: Builds with the HSM simulator support
2. `Dockerfile.azure`: Builds with Azure HSM support

## Task Commands

The following tasks are available:

- `task build`: Build Sofa with the default HSM simulator
- `task build-azure`: Build Sofa with Azure HSM support
- `task rollout`: Deploy Sofa with HSM simulator to Kubernetes
- `task rollout-azure`: Deploy Sofa with Azure HSM to Kubernetes

## How to Choose an Implementation

Select the appropriate implementation based on your environment:

- **Development/Testing**: Use the HSM simulator provider
- **Production**: Use the Azure HSM provider

## HSM Simulator Setup

The HSM simulator is a Python FastAPI service that simulates an HSM. It provides endpoints for:

- Key creation and management
- Encryption and decryption
- Key wrapping and unwrapping

The simulator is deployed in the same Kubernetes cluster as Sofa during development.

## Azure HSM Setup

To use Azure HSM in production:

1. Provision an Azure Key Vault with HSM capabilities
2. Configure appropriate access policies
3. Create encryption keys in the vault
4. Set the required environment variables:
   - `SOFA_ENCRYPTION_HSM=true`
   - `AZURE_TENANT_ID`
   - `AZURE_CLIENT_ID`
   - `AZURE_CLIENT_SECRET`
   - `SOFA_HSM_AZURE_KEYVAULT_URL`
   - `SOFA_HSM_AZURE_KEY_NAME`
   - `SOFA_HSM_AZURE_KEY_VERSION` (optional) 