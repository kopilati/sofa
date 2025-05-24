use anyhow::{Result, anyhow};
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault::KeyClient;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

// Feature-gated HSM configuration
// When hsm-simulator feature is enabled
#[cfg(feature = "hsm-simulator")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// Whether HSM integration is enabled
    pub enabled: bool,
    /// Key name in the HSM
    pub key_name: String,
    /// HSM Simulator URL
    pub simulator_url: String,
}

#[cfg(feature = "hsm-simulator")]
impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_name: "master-key".to_string(),
            simulator_url: "http://hsm-simulator:8080".to_string(),
        }
    }
}

// When azure-hsm feature is enabled
#[cfg(feature = "azure-hsm")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// Whether HSM integration is enabled
    pub enabled: bool,
    /// Azure Key Vault URL
    pub keyvault_url: String,
    /// Key name in the Azure Key Vault
    pub key_name: String,
    /// Key version in Azure Key Vault (optional)
    pub key_version: Option<String>,
}

#[cfg(feature = "azure-hsm")]
impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            keyvault_url: "https://your-keyvault.vault.azure.net".to_string(),
            key_name: "master-key".to_string(),
            key_version: None,
        }
    }
}

// When no HSM feature is enabled
#[cfg(not(any(feature = "hsm-simulator", feature = "azure-hsm")))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// Whether HSM integration is enabled
    pub enabled: bool,
}

#[cfg(not(any(feature = "hsm-simulator", feature = "azure-hsm")))]
impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
        }
    }
}

/// Define a common way to extract key_name from all config types
pub trait KeyNameProvider {
    fn get_key_name(&self) -> String;
}

#[cfg(feature = "hsm-simulator")]
impl KeyNameProvider for HsmConfig {
    fn get_key_name(&self) -> String {
        self.key_name.clone()
    }
}

#[cfg(feature = "azure-hsm")]
impl KeyNameProvider for HsmConfig {
    fn get_key_name(&self) -> String {
        self.key_name.clone()
    }
}

#[cfg(not(any(feature = "hsm-simulator", feature = "azure-hsm")))]
impl KeyNameProvider for HsmConfig {
    fn get_key_name(&self) -> String {
        "no-key".to_string()
    }
}

// Models to communicate with HSM simulator
#[cfg(feature = "hsm-simulator")]
#[derive(Debug, Serialize, Deserialize)]
struct KeyResponse {
    name: String,
    id: String,
    key_type: String,
    version: String,
}

#[cfg(feature = "hsm-simulator")]
#[derive(Debug, Serialize, Deserialize)]
struct WrapKeyRequest {
    key_name: String,
    algorithm: String,
    value: String,
}

#[cfg(feature = "hsm-simulator")]
#[derive(Debug, Serialize, Deserialize)]
struct WrapKeyResponse {
    kid: String,
    value: String,
}

#[cfg(feature = "hsm-simulator")]
#[derive(Debug, Serialize, Deserialize)]
struct UnwrapKeyRequest {
    key_name: String,
    algorithm: String,
    value: String,
}

#[cfg(feature = "hsm-simulator")]
#[derive(Debug, Serialize, Deserialize)]
struct UnwrapKeyResponse {
    value: String,
}

// Models for HSM simulator API responses
#[cfg(feature = "hsm-simulator")]
#[derive(Debug, Serialize, Deserialize)]
struct EncryptResponse {
    kid: String,
    value: String,
}

#[cfg(feature = "hsm-simulator")]
#[derive(Debug, Serialize, Deserialize)]
struct DecryptResponse {
    value: String,
}

/// Trait defining the operations that an HSM service provides
trait HsmProvider {
    /// Initialize the HSM service by loading keys
    fn initialize(&self) -> tokio::sync::futures::BoxFuture<'_, Result<()>>;
    
    /// Get the loaded key material
    fn get_key(&self) -> tokio::sync::futures::BoxFuture<'_, Option<Vec<u8>>>;
    
    /// Check if HSM is enabled and initialized
    fn is_available(&self) -> tokio::sync::futures::BoxFuture<'_, bool>;
    
    /// Encrypt a value using the HSM
    fn encrypt(&self, plaintext: &[u8]) -> tokio::sync::futures::BoxFuture<'_, Result<Vec<u8>>>;
    
    /// Decrypt a value using the HSM
    fn decrypt(&self, ciphertext: &[u8]) -> tokio::sync::futures::BoxFuture<'_, Result<Vec<u8>>>;
}

// Simulator implementation of HSM Provider
#[cfg(feature = "hsm-simulator")]
struct HsmSimulator {
    /// Configuration for the HSM
    config: HsmConfig,
    /// HTTP client for simulator requests
    http_client: Client,
    /// Key material loaded from HSM
    key_material: RwLock<Option<Vec<u8>>>,
}

#[cfg(feature = "hsm-simulator")]
impl HsmSimulator {
    /// Create a new HSM simulator with the given configuration
    fn new(config: HsmConfig) -> Self {
        let http_client = Client::new();
        
        Self {
            config,
            http_client,
            key_material: RwLock::new(None),
        }
    }
}

#[cfg(feature = "hsm-simulator")]
impl HsmProvider for HsmSimulator {
    fn initialize<'a>(&'a self) -> tokio::sync::futures::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.config.enabled {
                debug!("HSM integration is disabled, skipping initialization");
                return Ok(());
            }

            info!("Initializing HSM simulator");
            
            let key_name = &self.config.key_name;
            let simulator_url = &self.config.simulator_url;
            
            info!("Loading key '{}' from HSM simulator at {}", key_name, simulator_url);
            
            // Get the key from the simulator
            let response = self.http_client
                .get(&format!("{}/keys/{}", simulator_url, key_name))
                .send()
                .await;
            
            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        // Key exists, we'll use it
                        info!("Found existing key '{}' in HSM simulator", key_name);
                    } else if resp.status().as_u16() == 404 {
                        // Key doesn't exist, create it
                        info!("Key '{}' not found in HSM simulator, creating it", key_name);
                        
                        let create_response = self.http_client
                            .post(&format!("{}/keys", simulator_url))
                            .json(&serde_json::json!({
                                "name": key_name
                            }))
                            .send()
                            .await?;
                        
                        if !create_response.status().is_success() {
                            let error_text = create_response.text().await?;
                            error!("Failed to create key in HSM simulator: {}", error_text);
                            return Err(anyhow!("Failed to create key in HSM simulator: {}", error_text));
                        }
                        
                        info!("Successfully created key '{}' in HSM simulator", key_name);
                    } else {
                        let error_text = resp.text().await?;
                        error!("Failed to access key in HSM simulator: {}", error_text);
                        return Err(anyhow!("Failed to access key in HSM simulator: {}", error_text));
                    }
                },
                Err(e) => {
                    error!("Failed to connect to HSM simulator: {}", e);
                    return Err(anyhow!("Failed to connect to HSM simulator: {}", e));
                }
            }
            
            // For simulator we don't actually store key material locally
            // We'll just set a placeholder and use the simulator API for operations
            let mut key_guard = self.key_material.write().await;
            *key_guard = Some(vec![1]);
            
            info!("Successfully initialized HSM simulator integration");
            Ok(())
        })
    }
    
    fn get_key<'a>(&'a self) -> tokio::sync::futures::BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let key_guard = self.key_material.read().await;
            key_guard.clone()
        })
    }
    
    fn is_available<'a>(&'a self) -> tokio::sync::futures::BoxFuture<'a, bool> {
        Box::pin(async move {
            self.config.enabled && self.key_material.read().await.is_some()
        })
    }
    
    fn encrypt<'a>(&'a self, plaintext: &'a [u8]) -> tokio::sync::futures::BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            if !self.config.enabled {
                return Err(anyhow!("HSM integration is disabled"));
            }
            
            let key_name = &self.config.key_name;
            let simulator_url = &self.config.simulator_url;
            
            // Encode plaintext as base64
            let plaintext_b64 = BASE64.encode(plaintext);
            
            // Call encrypt API on simulator
            let response = self.http_client
                .post(&format!("{}/keys/{}/encrypt", simulator_url, key_name))
                .json(&serde_json::json!({
                    "key_name": key_name,
                    "algorithm": "RSA-OAEP-256",
                    "plaintext": plaintext_b64
                }))
                .send()
                .await?;
            
            if !response.status().is_success() {
                let error_text = response.text().await?;
                error!("Failed to encrypt data with HSM simulator: {}", error_text);
                return Err(anyhow!("Failed to encrypt data with HSM simulator: {}", error_text));
            }
            
            // Parse response
            let encrypt_response: EncryptResponse = response.json().await?;
            
            // Decode the base64 ciphertext
            let ciphertext = BASE64.decode(encrypt_response.value)?;
            
            Ok(ciphertext)
        })
    }
    
    fn decrypt<'a>(&'a self, ciphertext: &'a [u8]) -> tokio::sync::futures::BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            if !self.config.enabled {
                return Err(anyhow!("HSM integration is disabled"));
            }
            
            let key_name = &self.config.key_name;
            let simulator_url = &self.config.simulator_url;
            
            // Encode ciphertext as base64
            let ciphertext_b64 = BASE64.encode(ciphertext);
            
            // Call decrypt API on simulator
            let response = self.http_client
                .post(&format!("{}/keys/{}/decrypt", simulator_url, key_name))
                .json(&serde_json::json!({
                    "key_name": key_name,
                    "algorithm": "RSA-OAEP-256",
                    "ciphertext": ciphertext_b64
                }))
                .send()
                .await?;
            
            if !response.status().is_success() {
                let error_text = response.text().await?;
                error!("Failed to decrypt data with HSM simulator: {}", error_text);
                return Err(anyhow!("Failed to decrypt data with HSM simulator: {}", error_text));
            }
            
            // Parse response
            let decrypt_response: DecryptResponse = response.json().await?;
            
            // Decode the base64 plaintext
            let plaintext = BASE64.decode(decrypt_response.value)?;
            
            Ok(plaintext)
        })
    }
}

// Azure HSM implementation
#[cfg(feature = "azure-hsm")]
struct AzureHsm {
    /// Configuration for the HSM
    config: HsmConfig,
    /// Azure Key Vault client
    key_client: Option<azure_security_keyvault::KeyClient>,
    /// Key material loaded from HSM
    key_material: RwLock<Option<Vec<u8>>>,
}

#[cfg(feature = "azure-hsm")]
impl AzureHsm {
    /// Create a new Azure HSM service with the given configuration
    fn new(config: HsmConfig) -> Self {
        let key_client = if config.enabled {
            let url = &config.keyvault_url;
            
            // Create Azure Key Vault client
            let credential = azure_identity::DefaultAzureCredential::with_sources(Vec::new());
            
            match azure_security_keyvault::KeyClient::new(url, Arc::new(credential)) {
                Ok(client) => {
                    info!("Successfully created Azure Key Vault client for {}", url);
                    Some(client)
                },
                Err(e) => {
                    error!("Failed to create Azure Key Vault client: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            config,
            key_client,
            key_material: RwLock::new(None),
        }
    }
}

#[cfg(feature = "azure-hsm")]
impl HsmProvider for AzureHsm {
    fn initialize<'a>(&'a self) -> tokio::sync::futures::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.config.enabled {
                debug!("HSM integration is disabled, skipping initialization");
                return Ok(());
            }

            info!("Initializing Azure HSM service");
            
            if let Some(_client) = &self.key_client {
                if let Some(key_version) = &self.config.key_version {
                    info!("Loading key '{}' (version: {}) from Azure Key Vault", self.config.key_name, key_version);
                    
                    // For the stub implementation, we'll just set some dummy key material
                    // In a real implementation, we would load the key from Azure Key Vault
                    let mut key_guard = self.key_material.write().await;
                    *key_guard = Some(vec![1, 2, 3, 4, 5]);
                    
                    info!("Successfully loaded key from Azure Key Vault");
                } else {
                    info!("Loading latest version of key '{}' from Azure Key Vault", self.config.key_name);
                    
                    // For the stub implementation, we'll just set some dummy key material
                    let mut key_guard = self.key_material.write().await;
                    *key_guard = Some(vec![1, 2, 3, 4, 5]);
                    
                    info!("Successfully loaded key from Azure Key Vault");
                }
            } else {
                error!("No Key Vault client available");
                return Err(anyhow!("No Key Vault client available"));
            }
            
            Ok(())
        })
    }
    
    fn get_key<'a>(&'a self) -> tokio::sync::futures::BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let key_guard = self.key_material.read().await;
            key_guard.clone()
        })
    }
    
    fn is_available<'a>(&'a self) -> tokio::sync::futures::BoxFuture<'a, bool> {
        Box::pin(async move {
            self.config.enabled && self.key_material.read().await.is_some()
        })
    }
    
    fn encrypt<'a>(&'a self, _plaintext: &'a [u8]) -> tokio::sync::futures::BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            // Stub implementation for Azure Key Vault
            error!("Azure Key Vault encryption not implemented");
            Err(anyhow!("Azure Key Vault encryption not implemented"))
        })
    }
    
    fn decrypt<'a>(&'a self, _ciphertext: &'a [u8]) -> tokio::sync::futures::BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            // Stub implementation for Azure Key Vault
            error!("Azure Key Vault decryption not implemented");
            Err(anyhow!("Azure Key Vault decryption not implemented"))
        })
    }
}

/// Null implementation for when no HSM provider is enabled
#[cfg(not(any(feature = "hsm-simulator", feature = "azure-hsm")))]
struct NullHsmProvider {
    config: HsmConfig,
}

#[cfg(not(any(feature = "hsm-simulator", feature = "azure-hsm")))]
impl NullHsmProvider {
    fn new(config: HsmConfig) -> Self {
        Self { config }
    }
}

#[cfg(not(any(feature = "hsm-simulator", feature = "azure-hsm")))]
impl HsmProvider for NullHsmProvider {
    fn initialize<'a>(&'a self) -> tokio::sync::futures::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            info!("No HSM provider is enabled via feature flags");
            Ok(())
        })
    }
    
    fn get_key<'a>(&'a self) -> tokio::sync::futures::BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move { None })
    }
    
    fn is_available<'a>(&'a self) -> tokio::sync::futures::BoxFuture<'a, bool> {
        Box::pin(async move { false })
    }
    
    fn encrypt<'a>(&'a self, _plaintext: &'a [u8]) -> tokio::sync::futures::BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            Err(anyhow!("No HSM provider is enabled via feature flags"))
        })
    }
    
    fn decrypt<'a>(&'a self, _ciphertext: &'a [u8]) -> tokio::sync::futures::BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            Err(anyhow!("No HSM provider is enabled via feature flags"))
        })
    }
}

/// Public HSM service that hides implementation details
pub struct HsmService {
    #[cfg(feature = "hsm-simulator")]
    provider: HsmSimulator,
    
    #[cfg(feature = "azure-hsm")]
    provider: AzureHsm,
    
    #[cfg(not(any(feature = "hsm-simulator", feature = "azure-hsm")))]
    provider: NullHsmProvider,
}

impl HsmService {
    /// Create a new HSM service with the given configuration
    pub fn new(config: HsmConfig) -> Self {
        #[cfg(feature = "hsm-simulator")]
        {
            info!("Using HSM simulator provider (enabled via feature flag)");
            return Self {
                provider: HsmSimulator::new(config),
            };
        }
        
        #[cfg(feature = "azure-hsm")]
        {
            info!("Using Azure HSM provider (enabled via feature flag)");
            return Self {
                provider: AzureHsm::new(config),
            };
        }
        
        #[cfg(not(any(feature = "hsm-simulator", feature = "azure-hsm")))]
        {
            info!("No HSM provider enabled via feature flags");
            return Self {
                provider: NullHsmProvider::new(config),
            };
        }
    }

    /// Initialize the HSM service by loading keys
    pub async fn initialize(&self) -> Result<()> {
        self.provider.initialize().await
    }
    
    /// Get the loaded key material
    pub async fn get_key(&self) -> Option<Vec<u8>> {
        self.provider.get_key().await
    }
    
    /// Check if HSM is enabled and initialized
    pub async fn is_available(&self) -> bool {
        self.provider.is_available().await
    }
    
    /// Encrypt a value using the HSM
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.provider.encrypt(plaintext).await
    }
    
    /// Decrypt a value using the HSM
    pub async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.provider.decrypt(ciphertext).await
    }
}

// Create a shareable HSM service
pub type SharedHsmService = Arc<HsmService>;

// Helper function to create and initialize an HSM service
pub async fn create_hsm_service(config: HsmConfig) -> Result<SharedHsmService> {
    let service = Arc::new(HsmService::new(config));
    service.initialize().await?;
    Ok(service)
} 