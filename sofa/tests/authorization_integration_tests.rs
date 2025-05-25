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
    let mut config = AppConfig::default();
    config.auth.enabled = true;
    config.auth.issuer = Some("http://test-issuer".to_string());
    config.auth.audience = Some("test-audience".to_string());
    config.auth.jwks_url = Some("http://test-jwks".to_string());
    config.auth.authorization = auth_config;
    
    Arc::new(AppState::new(
        config,
        Arc::new(reqwest::Client::new()),
        None, // audit_logger
        None, // encryption_service
        None, // hsm_service
    ))
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

#[test]
fn test_authorization_rule_creation() {
    let rule = AuthorizationRule {
        name: Some("test-rule".to_string()),
        hosts: None,
        paths: Some(vec!["^/api/.*".to_string()]),
        methods: Some(vec!["GET".to_string(), "POST".to_string()]),
        when: vec![ClaimRequirement {
            claim: "role".to_string(),
            values: ClaimValues::String("admin".to_string()),
        }],
    };
    
    assert_eq!(rule.name, Some("test-rule".to_string()));
    assert_eq!(rule.paths, Some(vec!["^/api/.*".to_string()]));
    assert_eq!(rule.methods, Some(vec!["GET".to_string(), "POST".to_string()]));
    assert_eq!(rule.when.len(), 1);
}

#[test]
fn test_claim_values_variants() {
    // Test string value
    let string_value = ClaimValues::String("admin".to_string());
    match string_value {
        ClaimValues::String(s) => assert_eq!(s, "admin"),
        _ => panic!("Expected string value"),
    }
    
    // Test string array value
    let array_value = ClaimValues::StringArray(vec!["admin".to_string(), "user".to_string()]);
    match array_value {
        ClaimValues::StringArray(arr) => {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0], "admin");
            assert_eq!(arr[1], "user");
        },
        _ => panic!("Expected string array value"),
    }
    
    // Test boolean value
    let bool_value = ClaimValues::Boolean(true);
    match bool_value {
        ClaimValues::Boolean(b) => assert_eq!(b, true),
        _ => panic!("Expected boolean value"),
    }
}

#[test]
fn test_default_action() {
    let default = DefaultAction::default();
    match default {
        DefaultAction::Deny => assert!(true),
        DefaultAction::Allow => panic!("Expected default to be Deny"),
    }
}

#[test]
fn test_complex_authorization_config() {
    let yaml_config = r#"
default_action: deny
rules:
  - name: "admin-access"
    paths: ["^/admin/.*"]
    methods: ["GET", "POST", "PUT", "DELETE"]
    when:
      - claim: "role"
        values: "admin"
  - name: "user-read-access"
    paths: ["^/api/.*"]
    methods: ["GET"]
    when:
      - claim: "role"
        values: ["user", "admin"]
      - claim: "organization"
        values: "test-org"
"#;
    
    let config: AuthorizationConfig = serde_yaml::from_str(yaml_config).unwrap();
    
    assert_eq!(config.rules.len(), 2);
    
    // Check first rule
    let admin_rule = &config.rules[0];
    assert_eq!(admin_rule.name, Some("admin-access".to_string()));
    assert_eq!(admin_rule.paths, Some(vec!["^/admin/.*".to_string()]));
    assert_eq!(admin_rule.methods, Some(vec!["GET".to_string(), "POST".to_string(), "PUT".to_string(), "DELETE".to_string()]));
    assert_eq!(admin_rule.when.len(), 1);
    
    // Check second rule
    let user_rule = &config.rules[1];
    assert_eq!(user_rule.name, Some("user-read-access".to_string()));
    assert_eq!(user_rule.when.len(), 2);
    
    // Check the string array claim
    match &user_rule.when[0].values {
        ClaimValues::StringArray(arr) => {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0], "user");
            assert_eq!(arr[1], "admin");
        },
        _ => panic!("Expected string array value"),
    }
}