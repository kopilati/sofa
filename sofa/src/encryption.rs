use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Result, anyhow};
use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{StatusCode, HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
    BoxError,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use http_body_util::BodyExt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Sha256, Digest};
use std::{
    sync::Arc, 
    str::FromStr
};
use tokio::sync::OnceCell;
use tracing::{debug, error, info, warn};

use crate::proxy::AppState;

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
pub async fn create_encryption_service(key_material: &str) -> Result<SharedEncryptionService> {
    let service = Arc::new(EncryptionService::new());
    service.initialize(key_material).await?;
    Ok(service)
}

/// Middleware to encrypt JSON properties in request bodies
pub async fn encrypt_json_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    // First check if the encryption service is available
    let encryption_service = match &state.encryption_service {
        Some(service) => service,
        None => {
            // If encryption is not enabled, just pass through
            debug!("Encryption service not available, skipping encryption middleware");
            return next.run(req).await;
        }
    };

    // Get request path to check if it matches any encrypted_endpoints
    let path = req.uri().path();
    
    // Check if this path matches any of the encrypted_endpoints patterns
    let should_encrypt = state.config.encryption.endpoints.iter().any(|pattern| {
        match Regex::new(pattern) {
            Ok(regex) => regex.is_match(path),
            Err(e) => {
                warn!("Invalid regex pattern '{}': {}", pattern, e);
                false
            }
        }
    });

    if !should_encrypt {
        // Path doesn't match any encryption patterns, pass through
        debug!("Path {} doesn't require encryption, skipping", path);
        return next.run(req).await;
    }

    // Check content type
    let content_type = req.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.contains("application/json") && 
       !content_type.contains("text/json") && 
       !content_type.contains("+json") {
        // Not JSON, pass through
        debug!("Content type '{}' is not JSON, skipping encryption", content_type);
        return next.run(req).await;
    }

    // Extract and parse JSON body
    let body_bytes = match body_to_bytes(req.body_mut()).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("Failed to read request body: {}", e)))
                .unwrap();
        }
    };

    if body_bytes.is_empty() {
        // Empty body, just pass through
        debug!("Empty request body, skipping encryption");
        // Restore the empty body
        *req.body_mut() = Body::empty();
        return next.run(req).await;
    }

    // Parse JSON
    match serde_json::from_slice::<Value>(&body_bytes) {
        Ok(json) => {
            debug!("Successfully parsed JSON body");
            // Encrypt JSON properties
            match encrypt_json_properties(&json, encryption_service).await {
                Ok(encrypted_json) => {
                    debug!("Successfully encrypted JSON properties");
                    
                    // Replace the request body with the encrypted JSON
                    let json_string = serde_json::to_string(&encrypted_json)
                        .unwrap_or_else(|_| "{}".to_string());
                    
                    // Update content-length if present
                    if let Some(header) = req.headers_mut().get_mut("content-length") {
                        if let Ok(len) = json_string.len().to_string().parse() {
                            *header = len;
                        }
                    }
                    
                    // Set the new body
                    *req.body_mut() = Body::from(json_string);
                    
                    // Continue with the modified request
                    next.run(req).await
                },
                Err(e) => {
                    error!("Failed to encrypt JSON properties: {}", e);
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(format!("Failed to encrypt JSON: {}", e)))
                        .unwrap()
                }
            }
        },
        Err(e) => {
            // Not valid JSON or empty, pass through unchanged
            warn!("Request body is not valid JSON: {}", e);
            // Restore the original body
            *req.body_mut() = Body::from(body_bytes);
            next.run(req).await
        }
    }
}

/// Helper function to convert a body to bytes
async fn body_to_bytes(body: &mut Body) -> Result<Bytes, BoxError> {
    let collected = body.collect().await?;
    Ok(collected.to_bytes())
}

/// Encrypt JSON properties recursively
async fn encrypt_json_properties(
    json_value: &Value, 
    encryption_service: &EncryptionService
) -> Result<Value> {
    match json_value {
        Value::Object(map) => {
            let mut encrypted_map = serde_json::Map::new();
            
            for (key, value) in map {
                // Skip properties starting with _ or $
                if key.starts_with('_') || key.starts_with('$') {
                    encrypted_map.insert(key.clone(), value.clone());
                    continue;
                }
                
                match value {
                    Value::Object(_) | Value::Array(_) => {
                        // Recursively process nested objects and arrays
                        let future = Box::pin(encrypt_json_properties(value, encryption_service));
                        let encrypted_value = future.await?;
                        
                        // Create new property name: $$<original_name>
                        let new_key = format!("$${}", key);
                        encrypted_map.insert(new_key, encrypted_value);
                    },
                    _ => {
                        // For other properties, encrypt the value as string
                        let value_str = value.to_string();
                        match encryption_service.encrypt(&value_str).await {
                            Ok(encrypted) => {
                                // Create new property name: $$<original_name>
                                let new_key = format!("$${}", key);
                                encrypted_map.insert(new_key, Value::String(encrypted));
                            },
                            Err(e) => {
                                error!("Failed to encrypt property '{}': {}", key, e);
                                // Keep original on error
                                encrypted_map.insert(key.clone(), value.clone());
                            }
                        }
                    }
                }
            }
            
            Ok(Value::Object(encrypted_map))
        },
        Value::Array(items) => {
            // For arrays, encrypt each item recursively
            let mut encrypted_items = Vec::new();
            
            for item in items {
                match item {
                    Value::Object(_) | Value::Array(_) => {
                        // Recursively process nested objects and arrays
                        let future = Box::pin(encrypt_json_properties(item, encryption_service));
                        encrypted_items.push(future.await?);
                    },
                    _ => {
                        // Add non-objects/arrays as is
                        encrypted_items.push(item.clone());
                    }
                }
            }
            
            Ok(Value::Array(encrypted_items))
        },
        // Return other values as is
        _ => Ok(json_value.clone()),
    }
}

/// Middleware to decrypt JSON properties in response bodies
pub async fn decrypt_json_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    // First check if the encryption service is available
    let encryption_service = match &state.encryption_service {
        Some(service) => service,
        None => {
            // If encryption is not enabled, just pass through
            debug!("Encryption service not available, skipping decryption middleware");
            return next.run(req).await;
        }
    };

    // Get request path to check if it matches any encrypted_endpoints
    let path = req.uri().path();
    
    // Check if this path matches any of the encrypted_endpoints patterns
    let should_decrypt = state.config.encryption.endpoints.iter().any(|pattern| {
        match Regex::new(pattern) {
            Ok(regex) => regex.is_match(path),
            Err(e) => {
                warn!("Invalid regex pattern '{}': {}", pattern, e);
                false
            }
        }
    });

    if !should_decrypt {
        // Path doesn't match any encryption patterns, pass through
        debug!("Path {} doesn't require decryption, skipping", path);
        return next.run(req).await;
    }

    debug!("Will decrypt response for path: {}", path);

    // Process the request and get the response
    let mut response = next.run(req).await;
    
    // Check content type of response
    let is_json_response = response.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.contains("application/json") || 
            s.contains("text/json") || 
            s.contains("+json")
        })
        .unwrap_or(false);

    if !is_json_response {
        // Not JSON, pass through unchanged
        debug!("Response is not JSON, skipping decryption");
        return response;
    }

    // Extract the response body
    let body = response.body_mut();
    let bytes = match body_to_bytes(body).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read response body: {}", e);
            return response;
        }
    };

    if bytes.is_empty() {
        debug!("Empty response body, skipping decryption");
        return response;
    }

    // Try to parse as JSON
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(json) => {
            debug!("Successfully parsed JSON response body");
            
            // Decrypt JSON properties
            match decrypt_json_properties(&json, encryption_service).await {
                Ok(decrypted_json) => {
                    debug!("Successfully decrypted JSON properties");
                    
                    // Convert back to string
                    let json_string = serde_json::to_string(&decrypted_json)
                        .unwrap_or_else(|_| String::from("{}"));
                    
                    // Create a new response with the decrypted body
                    let status = response.status();
                    let mut builder = Response::builder().status(status);
                    
                    // Copy all headers from the original response
                    if let Some(headers) = builder.headers_mut() {
                        headers.extend(
                            response.headers()
                                .iter()
                                .filter(|(k, _)| k.as_str() != "content-length")
                                .map(|(k, v)| (k.clone(), v.clone()))
                        );
                    }
                    
                    // Set the content-length for the new response
                    if let Some(headers) = builder.headers_mut() {
                        if let Ok(len_value) = HeaderValue::from_str(&json_string.len().to_string()) {
                            headers.insert(
                                HeaderName::from_static("content-length"), 
                                len_value
                            );
                        }
                    }
                    
                    // Return the new response with decrypted body
                    builder
                        .body(Body::from(json_string))
                        .unwrap_or(response)
                },
                Err(e) => {
                    error!("Failed to decrypt JSON properties: {}", e);
                    response
                }
            }
        },
        Err(e) => {
            warn!("Response body is not valid JSON: {}", e);
            response
        }
    }
}

/// Decrypt JSON properties recursively
async fn decrypt_json_properties(
    json_value: &Value, 
    encryption_service: &EncryptionService
) -> Result<Value> {
    match json_value {
        Value::Object(map) => {
            let mut decrypted_map = serde_json::Map::new();
            
            for (key, value) in map {
                // Check if this is an encrypted property (starts with $$)
                if key.starts_with("$$") {
                    // Extract the original property name
                    let original_key = key.trim_start_matches("$$");
                    
                    // Handle string values which are encrypted
                    if let Value::String(encrypted) = value {
                        match encryption_service.decrypt(encrypted).await {
                            Ok(decrypted_str) => {
                                // Parse the decrypted string back to JSON if possible
                                match serde_json::from_str::<Value>(&decrypted_str) {
                                    Ok(json_value) => {
                                        // Successfully parsed as JSON, use the parsed value
                                        decrypted_map.insert(original_key.to_string(), json_value);
                                    },
                                    Err(_) => {
                                        // Not valid JSON, use as string
                                        decrypted_map.insert(original_key.to_string(), Value::String(decrypted_str));
                                    }
                                }
                            },
                            Err(e) => {
                                error!("Failed to decrypt property '{}': {}", key, e);
                                // Keep original on error
                                decrypted_map.insert(key.clone(), value.clone());
                            }
                        }
                    } else if let Value::Object(_) | Value::Array(_) = value {
                        // Recursively process nested objects and arrays
                        let future = Box::pin(decrypt_json_properties(value, encryption_service));
                        let decrypted_value = future.await?;
                        decrypted_map.insert(original_key.to_string(), decrypted_value);
                    } else {
                        // For non-string, non-nested values, just copy as is
                        decrypted_map.insert(original_key.to_string(), value.clone());
                    }
                } else {
                    // Not an encrypted property, process normally
                    if let Value::Object(_) | Value::Array(_) = value {
                        // Recursively process nested objects and arrays
                        let future = Box::pin(decrypt_json_properties(value, encryption_service));
                        let decrypted_value = future.await?;
                        decrypted_map.insert(key.clone(), decrypted_value);
                    } else {
                        // Copy non-objects/arrays as is
                        decrypted_map.insert(key.clone(), value.clone());
                    }
                }
            }
            
            Ok(Value::Object(decrypted_map))
        },
        Value::Array(items) => {
            // For arrays, decrypt each item recursively
            let mut decrypted_items = Vec::new();
            
            for item in items {
                match item {
                    Value::Object(_) | Value::Array(_) => {
                        // Recursively process nested objects and arrays
                        let future = Box::pin(decrypt_json_properties(item, encryption_service));
                        decrypted_items.push(future.await?);
                    },
                    _ => {
                        // Add non-objects/arrays as is
                        decrypted_items.push(item.clone());
                    }
                }
            }
            
            Ok(Value::Array(decrypted_items))
        },
        // Return other values as is
        _ => Ok(json_value.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_encrypt_json_properties() {
        // Create an encryption service
        let service = EncryptionService::new();
        service.initialize("test-master-key-for-unit-testing").await.unwrap();
        
        // Test with a complex JSON object
        let json = json!({
            "_id": "doc1",
            "$meta": "metadata",
            "name": "John Doe",
            "age": 30,
            "details": {
                "address": "123 Main St",
                "_private": "secret",
                "contacts": [
                    { "type": "email", "value": "john@example.com" },
                    { "type": "phone", "value": "555-1234" }
                ]
            },
            "tags": ["user", "active"]
        });
        
        // Encrypt the JSON
        let encrypted = encrypt_json_properties(&json, &service).await.unwrap();
        
        // Check that properties starting with _ or $ are unchanged
        assert_eq!(encrypted["_id"], "doc1");
        assert_eq!(encrypted["$meta"], "metadata");
        
        // Check that other top-level properties are renamed and encrypted
        assert!(encrypted.as_object().unwrap().contains_key("$$name"));
        assert!(encrypted.as_object().unwrap().contains_key("$$age"));
        
        // Verify the encrypted values are strings (base64)
        assert!(encrypted["$$name"].is_string());
        assert!(encrypted["$$age"].is_string());
        
        // Verify we can decrypt the values
        let name_encrypted = encrypted["$$name"].as_str().unwrap();
        let name_decrypted = service.decrypt(name_encrypted).await.unwrap();
        assert_eq!(name_decrypted, "\"John Doe\""); // JSON string representation
        
        let age_encrypted = encrypted["$$age"].as_str().unwrap();
        let age_decrypted = service.decrypt(age_encrypted).await.unwrap();
        assert_eq!(age_decrypted, "30"); // JSON number representation
        
        // Check nested objects
        assert!(encrypted["$$details"].is_object());
        let details = encrypted["$$details"].as_object().unwrap();
        
        // Private property should be unchanged
        assert_eq!(details["_private"], "secret");
        
        // Address should be encrypted
        assert!(details.contains_key("$$address"));
        assert!(details["$$address"].is_string());
        
        // Check array in nested object
        assert!(details["$$contacts"].is_array());
        let contacts = details["$$contacts"].as_array().unwrap();
        assert_eq!(contacts.len(), 2);
        
        // Check array values
        assert!(contacts[0].is_object());
        let contact1 = contacts[0].as_object().unwrap();
        assert!(contact1.contains_key("$$type"));
        assert!(contact1.contains_key("$$value"));
        
        // Check top-level array
        assert!(encrypted["$$tags"].is_array());
        let tags = encrypted["$$tags"].as_array().unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0], "user"); // Arrays of primitives are not encrypted
        assert_eq!(tags[1], "active");
    }
    
    #[tokio::test]
    async fn test_decrypt_json_properties() {
        // Create an encryption service
        let service = EncryptionService::new();
        service.initialize("test-master-key-for-unit-testing").await.unwrap();
        
        // Start with a normal JSON object
        let original = json!({
            "_id": "doc1",
            "$meta": "metadata",
            "name": "John Doe",
            "age": 30,
            "details": {
                "address": "123 Main St",
                "_private": "secret",
                "contacts": [
                    { "type": "email", "value": "john@example.com" },
                    { "type": "phone", "value": "555-1234" }
                ]
            },
            "tags": ["user", "active"]
        });
        
        // Encrypt the JSON
        let encrypted = encrypt_json_properties(&original, &service).await.unwrap();
        
        // Now decrypt the JSON
        let decrypted = decrypt_json_properties(&encrypted, &service).await.unwrap();
        
        // Verify that original properties and values are restored
        assert_eq!(decrypted["_id"], original["_id"]);
        assert_eq!(decrypted["$meta"], original["$meta"]);
        assert_eq!(decrypted["name"], original["name"]);
        assert_eq!(decrypted["age"], original["age"]);
        
        // Check nested objects
        assert!(decrypted["details"].is_object());
        assert_eq!(decrypted["details"]["_private"], original["details"]["_private"]);
        assert_eq!(decrypted["details"]["address"], original["details"]["address"]);
        
        // Check nested arrays
        assert!(decrypted["details"]["contacts"].is_array());
        assert_eq!(decrypted["details"]["contacts"].as_array().unwrap().len(), 2);
        assert_eq!(decrypted["details"]["contacts"][0]["type"], original["details"]["contacts"][0]["type"]);
        assert_eq!(decrypted["details"]["contacts"][0]["value"], original["details"]["contacts"][0]["value"]);
        assert_eq!(decrypted["details"]["contacts"][1]["type"], original["details"]["contacts"][1]["type"]);
        assert_eq!(decrypted["details"]["contacts"][1]["value"], original["details"]["contacts"][1]["value"]);
        
        // Check top-level arrays
        assert!(decrypted["tags"].is_array());
        assert_eq!(decrypted["tags"], original["tags"]);
    }
    
    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        // Create an encryption service
        let service = EncryptionService::new();
        service.initialize("test-master-key-for-unit-testing").await.unwrap();
        
        // Test various data types
        let original = json!({
            "string": "Hello, World!",
            "number": 42,
            "boolean": true,
            "null": null,
            "object": { "nested": "value" },
            "array": [1, 2, 3],
            "mixed_array": [1, "two", true, { "key": "value" }]
        });
        
        // Encrypt then decrypt
        let encrypted = encrypt_json_properties(&original, &service).await.unwrap();
        let decrypted = decrypt_json_properties(&encrypted, &service).await.unwrap();
        
        // Verify roundtrip works for all data types
        assert_eq!(decrypted["string"], original["string"]);
        assert_eq!(decrypted["number"], original["number"]);
        assert_eq!(decrypted["boolean"], original["boolean"]);
        assert_eq!(decrypted["null"], original["null"]);
        
        assert_eq!(decrypted["object"]["nested"], original["object"]["nested"]);
        
        assert_eq!(decrypted["array"].as_array().unwrap().len(), 3);
        assert_eq!(decrypted["array"][0], original["array"][0]);
        assert_eq!(decrypted["array"][1], original["array"][1]);
        assert_eq!(decrypted["array"][2], original["array"][2]);
        
        assert_eq!(decrypted["mixed_array"].as_array().unwrap().len(), 4);
        assert_eq!(decrypted["mixed_array"][0], original["mixed_array"][0]);
        assert_eq!(decrypted["mixed_array"][1], original["mixed_array"][1]);
        assert_eq!(decrypted["mixed_array"][2], original["mixed_array"][2]);
        assert_eq!(decrypted["mixed_array"][3]["key"], original["mixed_array"][3]["key"]);
    }
} 