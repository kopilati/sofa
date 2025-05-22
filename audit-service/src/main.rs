use axum::{
    routing::{get, post},
    http::StatusCode,
    Json, Router,
    extract::State,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{debug, info, Level};
use tracing_subscriber::FmtSubscriber;
use tokio::signal;

// This matches the structure used in SOFA
#[derive(Debug, Deserialize, Serialize, Clone)]
struct AuditLogEntry {
    method: String,
    path: String,
    user_id: Option<String>,
    timestamp: u64,
    success: bool,
    status_code: u16,
}

// Additional field for formatting
#[derive(Debug, Serialize)]
struct FormattedAuditLogEntry {
    method: String,
    path: String,
    user_id: Option<String>,
    timestamp: String,
    success: bool,
    status_code: u16,
}

// Used to count total number of logs
#[derive(Debug, Default)]
struct AppState {
    log_count: Mutex<usize>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing with debug level
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing_subscriber::fmt::init();

    // Create application state
    let state = Arc::new(AppState::default());

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    // Build the application with routes
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/audit", post(receive_audit_log))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    info!("Audit Log Service starting on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

// Health check endpoint
async fn health_check() -> &'static str {
    info!("Health check endpoint called");
    "Audit Log Service is running"
}

// Receive audit log entries
async fn receive_audit_log(
    State(state): State<Arc<AppState>>,
    Json(entry): Json<AuditLogEntry>
) -> StatusCode {
    // Convert Unix timestamp to human-readable date
    let timestamp = DateTime::<Utc>::from_timestamp(entry.timestamp as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "Invalid timestamp".to_string());

    // Format the entry for logging
    let formatted_entry = FormattedAuditLogEntry {
        method: entry.method.clone(),
        path: entry.path.clone(),
        user_id: entry.user_id.clone(),
        timestamp,
        success: entry.success,
        status_code: entry.status_code,
    };

    // Log the audit entry
    info!(
        "AUDIT LOG: {} {} by user {:?} at {} - Status: {} Success: {}", 
        formatted_entry.method, 
        formatted_entry.path,
        formatted_entry.user_id.as_deref().unwrap_or("anonymous"),
        formatted_entry.timestamp,
        formatted_entry.status_code,
        formatted_entry.success
    );

    // Also log the raw entry
    debug!("Raw audit entry: {:?}", entry);

    // Increment the log count
    let mut count = state.log_count.lock().unwrap();
    *count += 1;
    info!("Total audit logs received: {}", *count);

    StatusCode::OK
}

// Handle graceful shutdown
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, stopping server");
} 