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

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub client: Client,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        let client = Client::builder()
            .build()
            .expect("Failed to create HTTP client");
        
        Self { config, client }
    }
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    path: axum::extract::Path<String>,
    req: Request,
) -> impl IntoResponse {
    let path = path.0;
    let target_url = format!("{}/{}", state.config.couchdb_url, path);
    
    info!("Proxying request to {}", target_url);
    debug!("Method: {:?}", method);
    
    // Extract request body
    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
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
    let mut client_req = state.client.request(reqwest_method, &target_url);
    
    // Add basic auth
    client_req = client_req.basic_auth(
        &state.config.couchdb_username,
        Some(&state.config.couchdb_password),
    );
    
    // Copy headers from original request to proxy request
    for (key, value) in headers.iter() {
        // Skip headers that reqwest will set
        if key == "host" || key == "content-length" {
            continue;
        }
        
        if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_str().as_bytes()) {
            let header_value = match reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            client_req = client_req.header(header_name, header_value);
        }
    }
    
    // Set the body, if any
    if !body_bytes.is_empty() {
        client_req = client_req.body(body_bytes);
    }

    // Send the request to CouchDB
    match client_req.send().await {
        Ok(resp) => {
            // Convert reqwest status to axum status
            let status_code = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut builder = Response::builder().status(status_code);
            
            // Copy response headers
            let headers = builder.headers_mut().unwrap();
            for (key, value) in resp.headers() {
                if let Ok(name) = HeaderName::try_from(key.as_str()) {
                    if let Ok(val) = HeaderValue::try_from(value.as_bytes()) {
                        headers.insert(name, val);
                    }
                }
            }
            
            // Get response body
            match resp.bytes().await {
                Ok(bytes) => builder.body(Body::from(bytes)).unwrap(),
                Err(e) => {
                    error!("Failed to get response body: {}", e);
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(format!("Failed to get response body: {}", e)))
                        .unwrap()
                }
            }
        }
        Err(e) => {
            error!("Request to CouchDB failed: {}", e);
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Request to CouchDB failed: {}", e)))
                .unwrap()
        }
    }
} 