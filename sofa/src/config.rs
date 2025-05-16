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

        // Build and convert to our Config type
        builder.build()?.try_deserialize()
    }
} 