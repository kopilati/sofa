mod config;
mod proxy;
mod auth;
mod audit;

use anyhow::Result;
use axum::{
    http::Method,
    middleware,
    routing::{any, get},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{debug, info, Level};
use tracing_subscriber::FmtSubscriber;
use reqwest::Client;

use auth::auth_middleware;
use config::AppConfig;
use proxy::{proxy_handler, AppState};
use audit::{AuditLogger, audit_middleware};

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
    info!("CouchDB URL: {}", config.couchdb_url);
    info!("Server port: {}", config.server_port);
    info!("OAuth2 authentication enabled: {}", config.auth.enabled);
    
    debug!("Full configuration: {:?}", config);
    
    // Print all environment variables for debugging
    for (key, value) in std::env::vars() {
        if key.starts_with("SOFA_AUTH") {
            debug!("ENV: {}={}", key, value);
        }
    }
    
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
    
    // Log audit configuration
    info!("Audit logging enabled: {}", config.audit_enabled);
    if config.audit_enabled {
        if let Some(url) = &config.audit_log_service_url {
            info!("Audit log service URL: {}", url);
        } else {
            info!("Audit log service URL is not set");
        }
    }

    // Create HTTP client
    let client = Arc::new(Client::new());

    // Create the audit logger if enabled
    let audit_logger = if config.audit_enabled {
        AuditLogger::new(Arc::new(config.clone()), client.clone())
    } else {
        None
    };

    // Create application state
    let app_state = Arc::new(AppState::new(config.clone(), client, audit_logger));

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::HEAD, Method::OPTIONS])
        .allow_headers(Any)
        .allow_origin(Any);

    // Build the application with routes
    let app = Router::new()
        .route("/*path", any(proxy_handler))
        .layer(middleware::from_fn_with_state(app_state.clone(), auth_middleware))
        .layer(middleware::from_fn_with_state(app_state.clone(), audit_middleware))
        .with_state(app_state)
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server_port));
    info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "CouchDB Proxy is running"
}
