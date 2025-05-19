use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::sync::Arc;
use tokio::sync::OnceCell;
use tracing::{debug, error, info};

/// Request payload for encryption
#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    /// Plain text to encrypt
    pub plaintext: String,
}

/// Response from encryption
#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    /// Base64-encoded encrypted data (includes nonce)
    pub ciphertext: String,
}

/// Request payload for decryption
#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    /// Base64-encoded encrypted data (includes nonce)
    pub ciphertext: String,
}

/// Response from decryption
#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    /// Decrypted plain text
    pub plaintext: String,
}

/// Encryption service for secure operations
pub struct EncryptionService {
    /// AES-256-GCM cipher for encryption/decryption
    cipher: OnceCell<Aes256Gcm>,
}

impl EncryptionService {
    /// Create a new encryption service
    pub fn new() -> Self {
        Self {
            cipher: OnceCell::new(),
        }
    }

    /// Initialize the encryption service with the master key
    pub async fn initialize(&self, master_key: &str) -> Result<()> {
        info!("Initializing encryption service");
        
        // Derive a 32-byte key using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(master_key.as_bytes());
        let derived_key = hasher.finalize();
        
        debug!("Derived encryption key from master key");
        
        // Create the AES-GCM cipher
        let key = Key::<Aes256Gcm>::from_slice(derived_key.as_slice());
        let cipher = Aes256Gcm::new(key);
        
        // Store the cipher
        if let Err(_) = self.cipher.set(cipher) {
            return Err(anyhow!("Encryption service already initialized"));
        }
        
        info!("Encryption service initialized successfully");
        Ok(())
    }
    
    /// Encrypt a plaintext string
    pub async fn encrypt(&self, plaintext: &str) -> Result<String> {
        // Get the cipher
        let cipher = self.cipher
            .get()
            .ok_or_else(|| anyhow!("Encryption service not initialized"))?;
        
        // Generate a random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        // Encrypt the plaintext
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;
        
        // Combine nonce and ciphertext and encode as base64
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ciphertext);
        let encoded = BASE64.encode(combined);
        
        Ok(encoded)
    }
    
    /// Decrypt a ciphertext string
    pub async fn decrypt(&self, encoded: &str) -> Result<String> {
        // Get the cipher
        let cipher = self.cipher
            .get()
            .ok_or_else(|| anyhow!("Encryption service not initialized"))?;
        
        // Decode the base64 ciphertext
        let combined = BASE64.decode(encoded)
            .map_err(|e| anyhow!("Invalid base64 encoding: {}", e))?;
        
        // Extract the nonce (first 12 bytes) and ciphertext
        if combined.len() < 12 {
            return Err(anyhow!("Ciphertext too short"));
        }
        
        let nonce = Nonce::from_slice(&combined[..12]);
        let ciphertext = &combined[12..];
        
        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {:?}", e))?;
        
        // Convert to string
        let plaintext_str = String::from_utf8(plaintext)
            .map_err(|e| anyhow!("Invalid UTF-8 in decrypted data: {}", e))?;
        
        Ok(plaintext_str)
    }
    
    /// Check if the encryption service is initialized
    pub fn is_initialized(&self) -> bool {
        self.cipher.initialized()
    }
}

// Create a shareable encryption service
pub type SharedEncryptionService = Arc<EncryptionService>;

// Helper function to create and initialize an encryption service
pub async fn create_encryption_service(key_material: &[u8]) -> Result<SharedEncryptionService> {
    let service = Arc::new(EncryptionService::new());
    service.initialize(key_material).await?;
    Ok(service)
} 