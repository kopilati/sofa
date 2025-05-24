mod config;
mod proxy;
mod auth;
mod audit;
mod encryption;
mod hsm;

use anyhow::Result;
use axum::{
    http::Method,
    middleware,
    routing::any,
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, Level};
use tracing_subscriber::FmtSubscriber;
use reqwest::Client;

use auth::auth_middleware;
use config::AppConfig;
use proxy::{proxy_handler, AppState};
use audit::{AuditLogger, audit_middleware};
use encryption::{EncryptionService, SharedEncryptionService, encrypt_json_middleware, decrypt_json_middleware};
use hsm::{HsmConfig, create_hsm_service};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with debug level
    let _subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing_subscriber::fmt::init();

    debug!("Starting config loading...");
    
    // Load configuration
    let config = AppConfig::load().unwrap_or_else(|err| {
        eprintln!("Failed to load configuration: {}", err);
        AppConfig::default()
    });

    info!("Starting CouchDB proxy server");
    info!("CouchDB URL: {}", config.couchdb.url);
    info!("Server port: {}", config.server.port);
    info!("OAuth2 authentication enabled: {}", config.auth.enabled);
    
    debug!("Full configuration: {:?}", config);
    
    // Log authentication settings
    if config.auth.enabled {
        if let Some(issuer) = &config.auth.issuer {
            info!("OAuth2 issuer: {}", issuer);
        } else {
            info!("OAuth2 issuer is not set");
        }
        if let Some(audience) = &config.auth.audience {
            info!("OAuth2 audience: {}", audience);
        } else {
            info!("OAuth2 audience is not set");
        }
        if let Some(jwks_url) = &config.auth.jwks_url {
            info!("OAuth2 JWKS URL: {}", jwks_url);
        } else {
            info!("OAuth2 JWKS URL is not set");
        }
    }

    info!("headers to be removed: {:?}", config.proxy.headers_remove);
    
    // Log audit configuration
    info!("Audit logging enabled: {}", config.audit.enabled);
    if config.audit.enabled {
        if let Some(url) = &config.audit.service_url {
            info!("Audit log service URL: {}", url);
        } else {
            info!("Audit log service URL is not set");
        }
    }
    
    // Log encryption configuration
    if let Some(_) = &config.encryption.master_key {
        info!("Encryption enabled with master key");
        if !config.encryption.endpoints.is_empty() {
            info!("Encrypted endpoints: {}", config.encryption.endpoints.join(", "));
        } else {
            info!("No encrypted endpoints configured");
        }
    } else {
        info!("Encryption disabled (no master key provided)");
    }
    
    // Log HSM configuration
    if config.encryption.hsm {
        info!("HSM integration enabled");
    } else {
        info!("HSM integration disabled");
    }

    // Initialize HSM service if configured
    let hsm_service = if config.encryption.hsm_enabled() {
        // Create HSM configuration based on feature flag
        #[cfg(feature = "hsm-simulator")]
        let hsm_config = HsmConfig {
            enabled: true,
            key_name: std::env::var("SOFA_HSM_KEY_NAME")
                .unwrap_or_else(|_| "sofa-master-key".to_string()),
            simulator_url: std::env::var("SOFA_HSM_SIMULATOR_URL")
                .unwrap_or_else(|_| "http://hsm-simulator:8080".to_string()),
        };

        #[cfg(feature = "azure-hsm")]
        let hsm_config = HsmConfig {
            enabled: true,
            keyvault_url: std::env::var("SOFA_HSM_AZURE_KEYVAULT_URL")
                .unwrap_or_else(|_| "https://your-keyvault.vault.azure.net".to_string()),
            key_name: std::env::var("SOFA_HSM_AZURE_KEY_NAME")
                .unwrap_or_else(|_| "sofa-master-key".to_string()),
            key_version: std::env::var("SOFA_HSM_AZURE_KEY_VERSION").ok(),
        };

        #[cfg(not(any(feature = "hsm-simulator", feature = "azure-hsm")))]
        let hsm_config = HsmConfig {
            enabled: true,
        };
        
        info!("HSM Config: {:?}", hsm_config);
        
        match create_hsm_service(hsm_config).await {
            Ok(service) => {
                info!("HSM service initialized successfully");
                Some(service)
            },
            Err(e) => {
                error!("Failed to initialize HSM service: {}", e);
                None
            }
        }
    } else {
        info!("HSM integration not enabled");
        None
    };

    // Initialize encryption service if master key is provided
    let encryption_service = if let Some(master_key) = &config.encryption.master_key {
        info!("Initializing encryption service with master key");
        let service = Arc::new(EncryptionService::new());
        if let Err(e) = service.initialize(master_key).await {
            error!("Failed to initialize encryption service: {}", e);
            None
        } else {
            info!("Encryption service initialized successfully");
            Some(service as SharedEncryptionService)
        }
    } else {
        info!("No master encryption key provided, encryption disabled");
        None
    };

    // Create HTTP client
    let client = Arc::new(Client::new());

    // Create the audit logger if enabled
    let audit_logger = if config.audit.enabled {
        if let Some(url) = &config.audit.service_url {
            AuditLogger::new(Arc::new(config.clone()), client.clone(), url)
        } else {
            info!("Audit logging enabled but no service URL provided");
            None
        }
    } else {
        None
    };

    // Create application state with HSM service
    let app_state = Arc::new(AppState::new(
        config.clone(),
        client,
        audit_logger,
        encryption_service,
        hsm_service,
    ));

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::HEAD, Method::OPTIONS])
        .allow_headers(Any)
        .allow_origin(Any);

    // Build the application with routes
    // Middleware executes in reverse order of addition (first added = last executed)
    let app = Router::new()
        .route("/*path", any(proxy_handler))
        // Middleware order (from outermost to innermost):
        // 1. Decrypt Response - transforms CouchDB responses by decrypting encrypted JSON properties
        // 2. Encrypt Request - transforms request bodies by encrypting JSON properties
        // 3. Auth - authenticates requests before they reach the encryption stage
        // 4. Audit - logs all requests after auth but before encryption
        .layer(middleware::from_fn_with_state(app_state.clone(), decrypt_json_middleware))
        .layer(middleware::from_fn_with_state(app_state.clone(), encrypt_json_middleware))
        .layer(middleware::from_fn_with_state(app_state.clone(), auth_middleware))
        .layer(middleware::from_fn_with_state(app_state.clone(), audit_middleware))
        .with_state(app_state)
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "CouchDB Proxy is running"
}
