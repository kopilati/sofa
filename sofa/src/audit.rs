use axum::{
    extract::{Request, State},
    http::{Method, StatusCode, Uri},
    middleware::Next,
    response::Response,
};
use reqwest::Client;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::config::AppConfig;
use crate::proxy::AppState;
use crate::auth::{AuthToken, UserId};

#[derive(Debug, Serialize, Clone)]
pub struct AuditLogEntry {
    pub method: String,
    pub path: String,
    pub user_id: Option<String>,
    pub timestamp: u64,
    pub success: bool,
    pub status_code: u16,
}

#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::Sender<(AuditLogEntry, String)>,
}

impl AuditLogger {
    pub fn new(config: Arc<AppConfig>, client: Arc<Client>, service_url: &str) -> Option<Self> {
        let (tx, mut rx) = mpsc::channel::<(AuditLogEntry, String)>(100); // Buffer size of 100
        
        // Create a clone of the service URL for the background task
        let url = service_url.to_string();
        
        // Spawn a background worker
        tokio::spawn(async move {
            info!("Audit log worker started, sending logs to: {}", url);
            
            while let Some((entry, token)) = rx.recv().await {
                debug!("Processing audit log entry: {:?}", entry);
                
                match send_audit_log(&entry, &token, &url, &client).await {
                    Ok(_) => debug!("Audit log sent successfully"),
                    Err(e) => error!("Failed to send audit log: {}", e),
                }
            }
            
            info!("Audit log worker shutting down");
        });
        
        Some(Self { tx })
    }
    
    pub async fn log(&self, entry: AuditLogEntry, token: String) {
        if let Err(e) = self.tx.send((entry, token)).await {
            error!("Failed to queue audit log entry: {}", e);
        }
    }
}

async fn send_audit_log(
    entry: &AuditLogEntry,
    token: &str,
    url: &str,
    client: &Client,
) -> Result<(), String> {
    client
        .post(url)
        .header("Authorization", format!("Bearer {}", token))
        .json(entry)
        .send()
        .await
        .map_err(|e| format!("Failed to send audit log: {}", e))?;
    
    Ok(())
}

// Helper function to create an audit entry from a request
pub fn create_audit_entry(
    method: &Method,
    path: &str,
    user_id: Option<String>,
    status_code: u16,
    success: bool,
) -> AuditLogEntry {
    AuditLogEntry {
        method: method.to_string(),
        path: path.to_string(),
        user_id,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        success,
        status_code,
    }
}

// Middleware for audit logging
pub async fn audit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    // Get method and path for audit entry
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    
    // Extract user ID if present
    let user_id = req.extensions().get::<UserId>().map(|id| id.0.clone());
    
    // Extract token from Authorization header
    let token = req.headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| {
            if header.starts_with("Bearer ") {
                Some(header.trim_start_matches("Bearer ").trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    
    // Process the request
    let response = next.run(req).await;
    
    // Extract status code
    let status_code = response.status().as_u16();
    let success = response.status().is_success();
    
    // Create audit entry
    let entry = create_audit_entry(
        &method,
        &path,
        user_id,
        status_code,
        success,
    );
    
    // Log the entry if audit logging is enabled
    if let Some(logger) = &state.audit_logger {
        // Log the audit entry
        debug!("Logging audit entry: {:?}", entry);
        logger.log(entry, token).await;
    }
    
    response
}