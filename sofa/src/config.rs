use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use config::{Config, ConfigError, File, Environment};
use tracing::{debug, info, error};

// Import the feature-gated HsmConfig
use crate::hsm::HsmConfig;

// Server configuration settings
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerSettings {
    pub port: u16,
}

// CouchDB connection settings
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CouchDBSettings {
    pub url: String,
    pub username: String,
    pub password: String,
}

// Authentication settings
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthSettings {
    pub enabled: bool,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub jwks_url: Option<String>,
}

// Audit logging settings
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuditSettings {
    pub enabled: bool,
    pub service_url: Option<String>,
}

// Encryption settings
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EncryptionSettings {
    pub master_key: Option<String>,
    pub endpoints: Vec<String>,
    pub hsm: bool,
}

impl EncryptionSettings {
    pub fn hsm_enabled(&self) -> bool {
        self.hsm && self.is_enabled()
    }

    pub fn is_enabled(&self) -> bool {
        self.master_key.is_some()
    }
}

// Proxy settings
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxySettings {
    pub headers_remove: Vec<String>,
    pub preserve_host: bool,
    pub chunked_encoding: bool,
    pub buffer_size: String,
    pub timeout: u64,
}

// Main application configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    pub server: ServerSettings,
    pub couchdb: CouchDBSettings,
    pub auth: AuthSettings,
    pub audit: AuditSettings,
    pub encryption: EncryptionSettings,
    pub proxy: ProxySettings,
}

// For compatibility with the rest of the code
impl AppConfig {
    // Helper method to get CouchDB URL directly (for backward compatibility)
    pub fn couchdb_url(&self) -> &str {
        &self.couchdb.url
    }
    
    // Helper method to get CouchDB username directly (for backward compatibility)
    pub fn couchdb_username(&self) -> &str {
        &self.couchdb.username
    }
    
    // Helper method to get CouchDB password directly (for backward compatibility)
    pub fn couchdb_password(&self) -> &str {
        &self.couchdb.password
    }
    
    // Helper method to get server port directly (for backward compatibility)
    pub fn server_port(&self) -> u16 {
        self.server.port
    }
    
    // Helper method to check if audit is enabled (for backward compatibility)
    pub fn audit_enabled(&self) -> bool {
        self.audit.enabled
    }
    
    // Helper method to get audit service URL (for backward compatibility)
    pub fn audit_log_service_url(&self) -> Option<&String> {
        self.audit.service_url.as_ref()
    }
    
    // Helper method to get master encryption key (for backward compatibility)
    pub fn master_enc_key(&self) -> Option<&String> {
        self.encryption.master_key.as_ref()
    }
    
    // Helper method to get encrypted endpoints (for backward compatibility)
    pub fn encrypted_endpoints(&self) -> &Vec<String> {
        &self.encryption.endpoints
    }
    
    // Load configuration from files and environment variables
    pub fn load() -> Result<Self, ConfigError> {
        // Load .env file if it exists
        let _ = dotenv::dotenv();
        
        let env_name = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        let config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "./config".to_string());
        
        info!("Loading configuration for environment: {}", env_name);
        debug!("Configuration directory: {}", config_dir);
        
        // Build configuration, starting with defaults and merging in other sources
        let builder = Config::builder()
            // Start with default config file (must exist)
            .add_source(File::from(PathBuf::from(format!("{}/defaults.yaml", config_dir))).required(false))
            // Add environment-specific config if exists
            .add_source(File::from(PathBuf::from(format!("{}/{}.yaml", config_dir, env_name))).required(false))
            // Add local overrides if exists (not committed to version control)
            .add_source(File::from(PathBuf::from(format!("{}/local.yaml", config_dir))).required(false))
            // Add environment variables with prefix SOFA_
            .add_source(
                Environment::with_prefix("SOFA")
                    .separator("_")
                    .try_parsing(true)
                    .list_separator(",")
                    // We need to correctly map nested keys
                    .with_list_parse_key("encryption_endpoints")
                    .with_list_parse_key("proxy_headers_remove")
            );
        
        // Build and deserialize
        let config = match builder.build() {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to build configuration: {}", e);
                return Err(e);
            }
        };
        
        // Try to deserialize the configuration to our AppConfig struct
        let app_config: AppConfig = match config.try_deserialize() {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to deserialize configuration: {}", e);
                return Err(e);
            }
        };
        let ac = app_config.clone();
        // Print key configuration values for debugging
        debug!("Loaded configuration:");
        debug!("CouchDB URL: {}", app_config.couchdb.url);
        debug!("Server Port: {}", app_config.server.port);
        debug!("Auth Enabled: {}", app_config.auth.enabled);
        if app_config.auth.enabled {
            debug!("Auth Issuer: {}", app_config.auth.issuer.unwrap_or_default());
            debug!("Auth Audience: {}", app_config.auth.audience.unwrap_or_default());
            debug!("Auth JWKS URL: {}", app_config.auth.jwks_url.unwrap_or_default());
        }
        debug!("Audit Enabled: {}", app_config.audit.enabled);
        if let Some(url) = &app_config.audit.service_url {
            debug!("Audit Service URL: {}", url);
        }
        debug!("Encryption Enabled: {}", app_config.encryption.is_enabled());
        debug!("HSM Enabled: {}", app_config.encryption.hsm_enabled());
        debug!("Encrypted Endpoints: {:?}", app_config.encryption.endpoints);
        debug!("Proxy Headers to Remove: {:?}", app_config.proxy.headers_remove);
        debug!("Proxy Preserve Host: {}", app_config.proxy.preserve_host);
        debug!("Proxy Chunked Encoding: {}", app_config.proxy.chunked_encoding);
        debug!("Proxy Buffer Size: {}", app_config.proxy.buffer_size);
        debug!("Proxy Timeout: {}", app_config.proxy.timeout);
        
        Ok(ac)
    }
}

// For backward compatibility with existing code
impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            port: 3000,
        }
    }
}

impl Default for CouchDBSettings {
    fn default() -> Self {
        Self {
            url: "http://localhost:5984".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
        }
    }
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: None,
            audience: None,
            jwks_url: None,
        }
    }
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            service_url: None,
        }
    }
}

impl Default for EncryptionSettings {
    fn default() -> Self {
        Self {
            master_key: None,
            endpoints: Vec::new(),
            hsm: false,
        }
    }
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            headers_remove: vec!["transfer-encoding".to_string()],
            preserve_host: true,
            chunked_encoding: false,
            buffer_size: "10mb".to_string(),
            timeout: 60000,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings::default(),
            couchdb: CouchDBSettings::default(),
            auth: AuthSettings::default(),
            audit: AuditSettings::default(),
            encryption: EncryptionSettings::default(),
            proxy: ProxySettings::default(),
        }
    }
} 