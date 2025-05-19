use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use config::{Config, ConfigError, File};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    pub couchdb_url: String,
    pub couchdb_username: String,
    pub couchdb_password: String,
    pub server_port: u16,
    pub auth: AuthConfig,
    pub audit_log_service_url: Option<String>,
    pub audit_enabled: bool,
    pub master_enc_key: Option<String>,
    pub encrypted_endpoints: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthConfig {
    pub enabled: bool,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub jwks_url: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: None,
            audience: None,
            jwks_url: None,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            couchdb_url: "http://localhost:5984".to_string(),
            couchdb_username: "admin".to_string(),
            couchdb_password: "password".to_string(),
            server_port: 3000,
            auth: AuthConfig::default(),
            audit_log_service_url: None,
            audit_enabled: false,
            master_enc_key: None,
            encrypted_endpoints: Vec::new(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        // Load .env file if it exists
        let _ = dotenv::dotenv();
        
        let config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "./config".to_string());
        
        let builder = Config::builder()
            // Start with default values
            .add_source(config::Config::try_from(&AppConfig::default())?)
            // Add in settings from the environment (with a prefix of SOFA)
            // E.g. `SOFA_COUCHDB_URL=foo ./target/app` would set the `couchdb_url` key
            .add_source(config::Environment::with_prefix("SOFA").separator("_"))
            // Attempt to load config file if present
            .add_source(File::from(PathBuf::from(format!("{}/config", config_dir))).required(false));

        // Build and attempt to deserialize to our Config type
        let mut config: AppConfig = builder.build()?.try_deserialize()?;
        
        // Explicitly check and set environment variables for couchdb url
        if let Ok(couchdb_url) = env::var("SOFA_COUCHDB_URL") {
            config.couchdb_url = couchdb_url;
        }
        
        // Also explicitly handle username and password
        if let Ok(couchdb_username) = env::var("SOFA_COUCHDB_USERNAME") {
            config.couchdb_username = couchdb_username;
        }
        
        if let Ok(couchdb_password) = env::var("SOFA_COUCHDB_PASSWORD") {
            config.couchdb_password = couchdb_password;
        }
        
        // Explicitly check and set environment variables for auth config
        // This is to workaround potential issues with nested config structures
        if let Ok(enabled) = env::var("SOFA_AUTH_ENABLED") {
            config.auth.enabled = enabled.to_lowercase() == "true";
        }
        
        if let Ok(issuer) = env::var("SOFA_AUTH_ISSUER") {
            config.auth.issuer = Some(issuer);
        }
        
        if let Ok(audience) = env::var("SOFA_AUTH_AUDIENCE") {
            config.auth.audience = Some(audience);
        }
        
        if let Ok(jwks_url) = env::var("SOFA_AUTH_JWKS_URL") {
            config.auth.jwks_url = Some(jwks_url);
        }
        
        // Handle audit configuration
        if let Ok(audit_enabled) = env::var("SOFA_AUDIT_ENABLED") {
            config.audit_enabled = audit_enabled.to_lowercase() == "true";
        }
        
        if let Ok(audit_url) = env::var("SOFA_AUDIT_LOG_SERVICE_URL") {
            config.audit_log_service_url = Some(audit_url);
        }
        
        // Handle master encryption key
        if let Ok(master_key) = env::var("SOFA_MASTER_ENC_KEY") {
            config.master_enc_key = Some(master_key);
        }
        
        // Handle encrypted endpoints
        if let Ok(endpoints) = env::var("SOFA_ENCRYPTED_ENDPOINTS") {
            // Split by comma and trim each entry
            config.encrypted_endpoints = endpoints
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        
        Ok(config)
    }
} 