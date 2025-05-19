use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use reqwest::Client;
use std::convert::TryFrom;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::config::AppConfig;
use crate::audit::AuditLogger;
use crate::encryption::SharedEncryptionService;

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub client: Arc<Client>,
    pub audit_logger: Option<AuditLogger>,
    pub encryption_service: Option<SharedEncryptionService>,
}

impl AppState {
    pub fn new(
        config: AppConfig, 
        client: Arc<Client>, 
        audit_logger: Option<AuditLogger>,
        encryption_service: Option<SharedEncryptionService>,
    ) -> Self {
        // Log the CouchDB URL for debugging
        info!("Creating AppState with CouchDB URL: {}", config.couchdb_url);
        
        Self { 
            config, 
            client, 
            audit_logger,
            encryption_service,
        }
    }
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    path: axum::extract::Path<String>,
    req: Request,
) -> impl IntoResponse {
    // Clean and normalize the path
    let path_str = path.0;
    let cleaned_path = path_str.trim_start_matches('/');
    
    // Ensure CouchDB URL doesn't end with a slash
    let base_url = state.config.couchdb_url.trim_end_matches('/');
    
    // Construct the target URL with proper path handling
    let target_url = if cleaned_path.is_empty() {
        base_url.to_string()
    } else {
        format!("{}/{}", base_url, cleaned_path)
    };
    
    // More detailed logging
    info!("====== CouchDB Proxy Request ======");
    info!("Original request: {} {}", method, req.uri());
    info!("Proxying to CouchDB: {} {}", method, target_url);
    debug!("Original path parameter: {:?}", path_str);
    debug!("Cleaned path: {:?}", cleaned_path);
    debug!("Base CouchDB URL: {}", base_url);
    debug!("Final target URL: {}", target_url);
    debug!("CouchDB credentials - Username: {}, Password: {}", 
           state.config.couchdb_username, 
           "*".repeat(state.config.couchdb_password.len()));
    
    // Debug all headers
    debug!("Request headers:");
    for (key, value) in headers.iter() {
        debug!("  {}: {:?}", key, value);
    }
    
    // Extract request body
    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(bytes) => {
            debug!("Request body size: {} bytes", bytes.len());
            if bytes.len() < 1000 {
                debug!("Request body: {:?}", String::from_utf8_lossy(&bytes));
            }
            bytes
        },
        Err(err) => {
            error!("Failed to read request body: {}", err);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to read request body"))
                .unwrap();
        }
    };

    // Convert axum method to reqwest method
    let reqwest_method = match method.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        "PATCH" => reqwest::Method::PATCH,
        _ => {
            error!("Unsupported method: {}", method);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("Unsupported method: {}", method)))
                .unwrap();
        }
    };

    // Create a reqwest request
    let mut client_req = state.client.request(reqwest_method.clone(), &target_url);
    
    // Add basic auth
    debug!("Adding basic auth with username: {}", state.config.couchdb_username);
    client_req = client_req.basic_auth(
        &state.config.couchdb_username,
        Some(&state.config.couchdb_password),
    );
    
    // Copy headers from original request to proxy request, excluding authorization
    for (key, value) in headers.iter() {
        // Skip headers that reqwest will set or that we want to replace
        if key == "host" || key == "content-length" || key == "authorization" {
            debug!("Skipping header: {}", key);
            continue;
        }
        
        if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_str().as_bytes()) {
            let header_value = match reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                Ok(v) => v,
                Err(_) => {
                    debug!("Failed to convert header value: {}", key);
                    continue;
                }
            };
            debug!("Adding header to proxied request: {}: {:?}", key, value);
            client_req = client_req.header(header_name, header_value);
        }
    }
    
    // Set the body, if any
    if !body_bytes.is_empty() {
        debug!("Adding request body");
        client_req = client_req.body(body_bytes);
    }

    debug!("Sending request to CouchDB: {} {}", reqwest_method, target_url);
    
    // Send the request to CouchDB
    match client_req.send().await {
        Ok(resp) => {
            // Log the response
            let status = resp.status();
            info!("====== CouchDB Response ======");
            info!("URL: {}, Status: {}", target_url, status);
            
            // Store the headers before moving the response
            let resp_headers = resp.headers().clone();
            
            debug!("Response headers:");
            for (key, value) in &resp_headers {
                debug!("  {}: {:?}", key, value);
            }
            
            // Get response body
            match resp.bytes().await {
                Ok(bytes) => {
                    let body_str = String::from_utf8_lossy(&bytes);
                    info!("Response body size: {} bytes", bytes.len());
                    
                    if status.is_success() {
                        if bytes.len() < 1000 {
                            info!("Response body: {}", body_str);
                        } else {
                            info!("Response body too large to log completely (size: {} bytes)", bytes.len());
                            info!("Response body starts with: {}", &body_str.chars().take(500).collect::<String>());
                        }
                    } else {
                        error!("CouchDB request failed!");
                        error!("URL: {}, Status: {}", target_url, status);
                        error!("Response body: {}", body_str);
                    }
                    
                    // Create a simple response with the exact body and status
                    info!("====== Response to Client ======");
                    info!("Status: {}", status);
                    info!("Body length: {} bytes", bytes.len());
                    
                    // Copy all the important headers
                    let mut builder = Response::builder()
                        .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
                    
                    // Add essential headers
                    let headers = builder.headers_mut().unwrap();
                    for (key, value) in resp_headers.iter() {
                        if key.as_str().eq_ignore_ascii_case("transfer-encoding") {
                            continue; // Let Hyper handle it
                        }
                        if let Ok(name) = HeaderName::try_from(key.as_str()) {
                            if let Ok(val) = HeaderValue::try_from(value.as_bytes()) {
                                headers.insert(name, val);
                            }
                        }
                    }
                    
                    // Ensure content-type is set
                    if !headers.contains_key("content-type") && status.is_success() {
                        headers.insert(
                            HeaderName::from_static("content-type"),
                            HeaderValue::from_static("application/json")
                        );
                    }
                    
                    // Return the body directly
                    builder.body(Body::from(bytes)).unwrap()
                },
                Err(e) => {
                    error!("Failed to get response body from CouchDB at {}: {}", target_url, e);
                    
                    // Create an error response
                    let error_msg = format!("Failed to get response body: {}", e);
                    info!("Returning error response: {}", error_msg);
                    
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("content-type", "text/plain")
                        .body(Body::from(error_msg))
                        .unwrap()
                }
            }
        }
        Err(e) => {
            error!("Request to CouchDB failed for URL {}: {}", target_url, e);
            
            // Create an error response
            let error_msg = format!("Request to CouchDB failed: {}", e);
            info!("Returning error response: {}", error_msg);
            
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("content-type", "text/plain")
                .body(Body::from(error_msg))
                .unwrap()
        }
    }
} 