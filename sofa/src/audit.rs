use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::Response,
};
use reqwest::Client;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::config::AppConfig;
use crate::proxy::AppState;
use crate::auth::UserId;

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::{sleep, Duration};

    #[test]
    fn test_create_audit_entry() {
        let method = Method::GET;
        let path = "/test/path";
        let user_id = Some("user123".to_string());
        let status_code = 200;
        let success = true;

        let entry = create_audit_entry(&method, path, user_id.clone(), status_code, success);

        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/test/path");
        assert_eq!(entry.user_id, user_id);
        assert_eq!(entry.status_code, 200);
        assert_eq!(entry.success, true);
        
        // Check timestamp is reasonable (within last minute)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(entry.timestamp <= now);
        assert!(entry.timestamp > now - 60);
    }

    #[test]
    fn test_create_audit_entry_anonymous() {
        let entry = create_audit_entry(&Method::POST, "/api/endpoint", None, 401, false);
        
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.path, "/api/endpoint");
        assert_eq!(entry.user_id, None);
        assert_eq!(entry.status_code, 401);
        assert_eq!(entry.success, false);
    }

    #[tokio::test]
    async fn test_audit_logger_creation() {
        let config = Arc::new(AppConfig::default());
        let client = Arc::new(reqwest::Client::new());
        let service_url = "http://test-audit-service/audit";

        let logger = AuditLogger::new(config, client, service_url);
        assert!(logger.is_some());
    }

    #[tokio::test]
    async fn test_audit_logger_queue_processing() {
        let config = Arc::new(AppConfig::default());
        let client = Arc::new(reqwest::Client::new());
        let service_url = "http://test-audit-service/audit";

        let logger = AuditLogger::new(config, client, service_url).unwrap();
        
        let entry = create_audit_entry(&Method::GET, "/test", Some("user123".to_string()), 200, true);
        let token = "test-token".to_string();

        // This should not block
        logger.log(entry, token).await;
        
        // Give some time for background processing
        sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test]
    async fn test_audit_entry_serialization() {
        let entry = AuditLogEntry {
            method: "GET".to_string(),
            path: "/test/path".to_string(),
            user_id: Some("user123".to_string()),
            timestamp: 1640995200, // 2022-01-01 00:00:00 UTC
            success: true,
            status_code: 200,
        };

        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditLogEntry = serde_json::from_str(&serialized).unwrap();

        assert_eq!(entry.method, deserialized.method);
        assert_eq!(entry.path, deserialized.path);
        assert_eq!(entry.user_id, deserialized.user_id);
        assert_eq!(entry.timestamp, deserialized.timestamp);
        assert_eq!(entry.success, deserialized.success);
        assert_eq!(entry.status_code, deserialized.status_code);
    }

    #[test]
    fn test_audit_entry_with_special_characters() {
        let entry = create_audit_entry(
            &Method::POST,
            "/database/document%20with%20spaces?query=test&value=hello%20world",
            Some("user@example.com".to_string()),
            201,
            true,
        );

        assert_eq!(entry.path, "/database/document%20with%20spaces?query=test&value=hello%20world");
        assert_eq!(entry.user_id, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_audit_entry_with_different_methods() {
        let methods = [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::HEAD,
            Method::OPTIONS,
        ];

        for method in methods {
            let entry = create_audit_entry(&method, "/test", None, 200, true);
            assert_eq!(entry.method, method.to_string());
        }
    }

    #[test]
    fn test_audit_entry_with_different_status_codes() {
        let test_cases = [
            (200, true),   // OK
            (201, true),   // Created
            (204, true),   // No Content
            (400, false),  // Bad Request
            (401, false),  // Unauthorized
            (403, false),  // Forbidden
            (404, false),  // Not Found
            (500, false),  // Internal Server Error
        ];

        for (status_code, expected_success) in test_cases {
            let entry = create_audit_entry(&Method::GET, "/test", None, status_code, expected_success);
            assert_eq!(entry.status_code, status_code);
            assert_eq!(entry.success, expected_success);
        }
    }

    // Mock HTTP server for testing actual HTTP requests
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use tokio::net::TcpListener;
    use axum::{routing::post, Json, Router};

    static REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

    async fn mock_audit_handler(Json(entry): Json<AuditLogEntry>) -> axum::http::StatusCode {
        REQUEST_COUNT.fetch_add(1, Ordering::SeqCst);
        println!("Mock audit service received: {:?}", entry);
        axum::http::StatusCode::OK
    }

    #[tokio::test]
    async fn test_send_audit_log_integration() {
        // Start mock audit service
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let app = Router::new().route("/audit", post(mock_audit_handler));
        
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give server time to start
        sleep(Duration::from_millis(100)).await;

        // Test the actual HTTP request
        let client = reqwest::Client::new();
        let entry = AuditLogEntry {
            method: "GET".to_string(),
            path: "/test".to_string(),
            user_id: Some("test-user".to_string()),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            success: true,
            status_code: 200,
        };

        let url = format!("http://{}/audit", addr);
        let result = send_audit_log(&entry, "test-token", &url, &client).await;

        assert!(result.is_ok());
        
        // Give some time for the request to be processed
        sleep(Duration::from_millis(50)).await;
        
        // Verify the mock service received the request
        assert_eq!(REQUEST_COUNT.load(Ordering::SeqCst), 1);
    }
}