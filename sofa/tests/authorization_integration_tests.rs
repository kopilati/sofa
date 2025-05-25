use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
};
use serde_json::json;
use std::sync::Arc;
use sofa::{
    auth::{AuthorizationConfig, AuthorizationRule, ClaimRequirement, ClaimValues, DefaultAction},
    config::{AuthSettings, AppConfig},
    proxy::AppState,
};
use tower::ServiceExt;

fn create_test_app_state(auth_config: Option<AuthorizationConfig>) -> Arc<AppState> {
    let config = AppConfig {
        auth: AuthSettings {
            enabled: true,
            issuer: Some("http://test-issuer".to_string()),
            audience: Some("test-audience".to_string()),
            jwks_url: Some("http://test-jwks".to_string()),
            authorization: auth_config,
        },
        // ... other config fields with defaults
    };
    
    Arc::new(AppState {
        config,
        client: reqwest::Client::new(),
    })
}

#[tokio::test]
async fn test_auth_middleware_no_token() {
    let state = create_test_app_state(None);
    
    let request = Request::builder()
        .method(Method::GET)
        .uri("/_all_dbs")
        .body(Body::empty())
        .unwrap();
    
    // Mock the next middleware
    let next = Next::new(|_req: Request| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("success"))
            .unwrap()
    });
    
    let response = sofa::auth::auth_middleware(
        axum::extract::State(state),
        request,
        next,
    ).await;
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_middleware_disabled() {
    let mut config = AppConfig::default();
    config.auth.enabled = false;
    
    let state = Arc::new(AppState {
        config,
        client: reqwest::Client::new(),
    });
    
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
    
    let response = sofa::auth::auth_middleware(
        axum::extract::State(state),
        request,
        next,
    ).await;
    
    // Should pass through when auth is disabled
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_authorization_config_parsing() {
    let yaml_config = r#"
default_action: deny
rules:
  - name: "test-rule"
    paths: ["^/test.*"]
    when:
      - claim: "role"
        values: "admin"
"#;
    
    let config: AuthorizationConfig = serde_yaml::from_str(yaml_config).unwrap();
    
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].name, Some("test-rule".to_string()));
    assert_eq!(config.rules[0].paths, Some(vec!["^/test.*".to_string()]));
    assert_eq!(config.rules[0].when.len(), 1);
    assert_eq!(config.rules[0].when[0].claim, "role");
    
    match &config.rules[0].when[0].values {
        ClaimValues::String(s) => assert_eq!(s, "admin"),
        _ => panic!("Expected string value"),
    }
}