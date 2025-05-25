use axum::{
    body::Body,
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
};
use serde_json::json;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use sofa::{
    audit::{AuditLogger, audit_middleware, create_audit_entry},
    auth::UserId,
    config::{AppConfig, AuditSettings},
    proxy::AppState,
};
use tower::ServiceExt;

fn create_test_app_state_with_audit(audit_url: Option<String>) -> Arc<AppState> {
    let mut config = AppConfig::default();
    config.audit.enabled = audit_url.is_some();
    config.audit.service_url = audit_url.clone();
    
    let client = Arc::new(reqwest::Client::new());
    
    let audit_logger = if let Some(url) = audit_url {
        AuditLogger::new(Arc::new(config.clone()), client.clone(), &url)
    } else {
        None
    };
    
    Arc::new(AppState::new(
        config,
        client,
        audit_logger,
        None, // encryption_service
        None, // hsm_service
    ))
}

#[tokio::test]
async fn test_audit_middleware_disabled() {
    let state = create_test_app_state_with_audit(None);
    
    let request = Request::builder()
        .method(Method::GET)
        .uri("/_all_dbs")
        .body(Body::empty())
        .unwrap();
    
    let next = Next::new(|_req: Request| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("success"))
            .unwrap()
    });
    
    let response = audit_middleware(
        State(state),
        request,
        next,
    ).await;
    
    // Should pass through when audit is disabled
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_audit_middleware_with_user_id() {
    let state = create_test_app_state_with_audit(Some("http://test-audit/audit".to_string()));
    
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/database/document")
        .header("Authorization", "Bearer test-token")
        .body(Body::empty())
        .unwrap();
    
    // Add user ID to request extensions
    request.extensions_mut().insert(UserId("user123".to_string()));
    
    let next = Next::new(|_req: Request| async move {
        Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::from("created"))
            .unwrap()
    });
    
    let response = audit_middleware(
        State(state),
        request,
        next,
    ).await;
    
    assert_eq!(response.status(), StatusCode::CREATED);
    // Note: Actual audit log sending is tested separately due to async nature
}

#[tokio::test]
async fn test_audit_middleware_without_user_id() {
    let state = create_test_app_state_with_audit(Some("http://test-audit/audit".to_string()));
    
    let request = Request::builder()
        .method(Method::GET)
        .uri("/_session")
        .body(Body::empty())
        .unwrap();
    
    let next = Next::new(|_req: Request| async move {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("unauthorized"))
            .unwrap()
    });
    
    let response = audit_middleware(
        State(state),
        request,
        next,
    ).await;
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_audit_middleware_extracts_token() {
    let state = create_test_app_state_with_audit(Some("http://test-audit/audit".to_string()));
    
    let request = Request::builder()
        .method(Method::DELETE)
        .uri("/database/document")
        .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        .body(Body::empty())
        .unwrap();
    
    let next = Next::new(|_req: Request| async move {
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap()
    });
    
    let response = audit_middleware(
        State(state),
        request,
        next,
    ).await;
    
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_audit_middleware_handles_malformed_auth_header() {
    let state = create_test_app_state_with_audit(Some("http://test-audit/audit".to_string()));
    
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .header("Authorization", "InvalidFormat token123")
        .body(Body::empty())
        .unwrap();
    
    let next = Next::new(|_req: Request| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("success"))
            .unwrap()
    });
    
    let response = audit_middleware(
        State(state),
        request,
        next,
    ).await;
    
    assert_eq!(response.status(), StatusCode::OK);
    // Should still audit with empty token
}

// Mock audit service for end-to-end integration testing
use std::sync::Mutex;
use axum::{routing::post, Json, Router};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
struct ReceivedAuditLog {
    method: String,
    path: String,
    user_id: Option<String>,
    status_code: u16,
    success: bool,
}

lazy_static::lazy_static! {
    static ref RECEIVED_LOGS: Mutex<Vec<ReceivedAuditLog>> = Mutex::new(Vec::new());
}

async fn mock_audit_receiver(Json(entry): Json<serde_json::Value>) -> StatusCode {
    let log = ReceivedAuditLog {
        method: entry["method"].as_str().unwrap_or("").to_string(),
        path: entry["path"].as_str().unwrap_or("").to_string(),
        user_id: entry["user_id"].as_str().map(|s| s.to_string()),
        status_code: entry["status_code"].as_u64().unwrap_or(0) as u16,
        success: entry["success"].as_bool().unwrap_or(false),
    };
    
    RECEIVED_LOGS.lock().unwrap().push(log);
    StatusCode::OK
}

#[tokio::test]
async fn test_end_to_end_audit_logging() {
    // Clear previous logs
    RECEIVED_LOGS.lock().unwrap().clear();
    
    // Start mock audit service
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let app = Router::new().route("/audit", post(mock_audit_receiver));
    
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    
    sleep(Duration::from_millis(100)).await;
    
    // Create audit logger with real HTTP endpoint
    let audit_url = format!("http://{}/audit", addr);
    let config = Arc::new(AppConfig::default());
    let client = Arc::new(reqwest::Client::new());
    let logger = AuditLogger::new(config, client, &audit_url).unwrap();
    
    // Send an audit log
    let entry = create_audit_entry(
        &Method::PUT,
        "/testdb/testdoc",
        Some("testuser".to_string()),
        200,
        true,
    );
    
    logger.log(entry, "test-token".to_string()).await;
    
    // Wait for background processing
    sleep(Duration::from_millis(500)).await;
    
    // Verify the log was received
    let logs = RECEIVED_LOGS.lock().unwrap();
    assert_eq!(logs.len(), 1);
    
    let received = &logs[0];
    assert_eq!(received.method, "PUT");
    assert_eq!(received.path, "/testdb/testdoc");
    assert_eq!(received.user_id, Some("testuser".to_string()));
    assert_eq!(received.status_code, 200);
    assert_eq!(received.success, true);
}
