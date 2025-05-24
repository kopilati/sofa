use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use reqwest::Client;
use tracing::{error, info, debug, warn};
use regex::Regex;
use anyhow::{Result, anyhow};

use crate::config::AuthSettings;
use crate::proxy::AppState;

/// Istio-like authorization rule structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthorizationRule {
    /// Optional host patterns to match (if omitted, matches all hosts)
    pub hosts: Option<Vec<String>>,
    /// Optional path patterns to match (if omitted, matches all paths)  
    pub paths: Option<Vec<String>>,
    /// HTTP methods this rule applies to (if omitted, applies to all methods)
    pub methods: Option<Vec<String>>,
    /// Required claims and their expected values
    pub when: Vec<ClaimRequirement>,
    /// Optional rule name for debugging
    pub name: Option<String>,
}

/// Represents a claim requirement with type/name and expected value
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClaimRequirement {
    /// The claim name (e.g., "role", "organization", "sub")
    pub claim: String,
    /// The expected value(s) for the claim
    pub values: ClaimValues,
}

/// Supported claim value types
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ClaimValues {
    /// Single string value
    String(String),
    /// Multiple string values (OR logic)
    StringArray(Vec<String>),
    /// Boolean value
    Boolean(bool),
    /// Regex pattern to match against
    Regex(RegexPattern),
}

/// Wrapper for regex patterns with validation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegexPattern {
    pub pattern: String,
}

/// Authorization configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthorizationConfig {
    /// List of authorization rules
    pub rules: Vec<AuthorizationRule>,
    /// Default action when no rules match (default: deny)
    pub default_action: Option<DefaultAction>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    Allow,
    Deny,
}

impl Default for DefaultAction {
    fn default() -> Self {
        DefaultAction::Deny
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub iss: Option<String>,      // issuer
    pub sub: Option<String>,      // subject (usually user id)
    pub aud: Option<String>,      // audience
    pub exp: Option<u64>,         // expiration time
    pub nbf: Option<u64>,         // not before
    pub iat: Option<u64>,         // issued at
    pub jti: Option<String>,      // JWT ID
    #[serde(flatten)]
    pub additional_claims: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct JwkKey {
    kid: String,
    kty: String,
    #[serde(rename = "use")]
    usage: Option<String>,
    n: Option<String>,   // Modulus for RSA keys
    e: Option<String>,   // Exponent for RSA keys
    x: Option<String>,   // X coordinate for EC keys
    y: Option<String>,   // Y coordinate for EC keys
    crv: Option<String>, // Curve for EC keys
}

// Token type to store in extensions
#[derive(Clone)]
pub struct AuthToken(pub String);

// UserId type to store in extensions
#[derive(Clone)]
pub struct UserId(pub String);

// Check if a path is authorized based on the claims
fn is_authorized(method: &Method, path: &str, claims: &serde_json::Value) -> bool {
    let claim_name = method.as_str().to_lowercase();
    debug!("Checking authorization for method: '{}' (claim name: '{}'), path: '{}'", method, claim_name, path);
    debug!("Available claims: {:?}", claims);

    if let Some(claim_value) = claims.get(&claim_name) {
        debug!("Found claim for method {}: {:?}", claim_name, claim_value);
        if let Some(paths) = claim_value.as_array() {
            debug!("Claim is an array with {} elements", paths.len());
            for path_pattern in paths {
                if let Some(pattern) = path_pattern.as_str() {
                    debug!("Checking regex pattern '{}' against path '{}'", pattern, path);
                    match Regex::new(pattern) {
                        Ok(re) => {
                            if re.is_match(path) {
                                debug!("Authorized via regex match: '{}' matches '{}'", pattern, path);
                                return true;
                            } else {
                                debug!("Regex match failed: '{}' does not match '{}'", pattern, path);
                            }
                        }
                        Err(e) => {
                            error!("Invalid regex pattern '{}': {}", pattern, e);
                            continue;
                        }
                    }
                }
            }
            debug!("No matching regex pattern found for path: {}", path);
            return false;
        } else if let Some(pattern) = claim_value.as_str() {
            debug!("Claim is a string: {} (interpreted as regex)", pattern);
            match Regex::new(pattern) {
                Ok(re) => {
                    if re.is_match(path) {
                        debug!("Authorized via regex match (string): '{}' matches '{}'", pattern, path);
                        return true;
                    }
                }
                Err(e) => {
                    error!("Invalid regex pattern '{}': {}", pattern, e);
                }
            }
        }
    } else {
        debug!("No claim found for method: {}", claim_name);
    }
    debug!("Authorization failed for {}: {}", method, path);
    false
}

/// New Istio-like authorization function
fn is_authorized_with_rules(
    method: &Method, 
    path: &str, 
    host: Option<&str>,
    claims: &serde_json::Value,
    auth_config: &Option<AuthorizationConfig>
) -> bool {
    debug!("Checking authorization with rules for method: '{}', path: '{}', host: '{:?}'", method, path, host);
    debug!("Available claims: {:?}", claims);

    // If no authorization rules are configured, fall back to legacy authorization
    let auth_config = match auth_config {
        Some(config) => config,
        None => {
            debug!("No authorization rules configured, falling back to legacy authorization");
            return is_authorized_legacy(method, path, claims);
        }
    };

    // Check each rule
    for (index, rule) in auth_config.rules.iter().enumerate() {
        debug!("Evaluating rule {}: {:?}", index, rule.name.as_deref().unwrap_or("unnamed"));
        
        if rule_matches_request(rule, method, path, host) {
            debug!("Rule {} matches request context", index);
            
            if evaluate_claim_requirements(&rule.when, claims) {
                debug!("Rule {} claim requirements satisfied - AUTHORIZED", index);
                return true;
            } else {
                debug!("Rule {} claim requirements not satisfied", index);
            }
        } else {
            debug!("Rule {} doesn't match request context", index);
        }
    }

    // No rules matched, use default action
    let default_action = auth_config.default_action.as_ref().unwrap_or(&DefaultAction::Deny);
    match default_action {
        DefaultAction::Allow => {
            debug!("No rules matched, default action is ALLOW");
            true
        }
        DefaultAction::Deny => {
            debug!("No rules matched, default action is DENY");
            false
        }
    }
}

/// Check if a rule matches the request context (method, path, host)
fn rule_matches_request(rule: &AuthorizationRule, method: &Method, path: &str, host: Option<&str>) -> bool {
    // Check methods
    if let Some(methods) = &rule.methods {
        let method_str = method.as_str().to_uppercase();
        if !methods.iter().any(|m| m.to_uppercase() == method_str) {
            debug!("Method '{}' doesn't match rule methods: {:?}", method_str, methods);
            return false;
        }
    }

    // Check paths
    if let Some(paths) = &rule.paths {
        let mut path_matches = false;
        for path_pattern in paths {
            match Regex::new(path_pattern) {
                Ok(regex) => {
                    if regex.is_match(path) {
                        debug!("Path '{}' matches pattern '{}'", path, path_pattern);
                        path_matches = true;
                        break;
                    }
                }
                Err(e) => {
                    error!("Invalid regex pattern '{}': {}", path_pattern, e);
                }
            }
        }
        if !path_matches {
            debug!("Path '{}' doesn't match any rule patterns: {:?}", path, paths);
            return false;
        }
    }

    // Check hosts
    if let Some(hosts) = &rule.hosts {
        if let Some(host_value) = host {
            let mut host_matches = false;
            for host_pattern in hosts {
                match Regex::new(host_pattern) {
                    Ok(regex) => {
                        if regex.is_match(host_value) {
                            debug!("Host '{}' matches pattern '{}'", host_value, host_pattern);
                            host_matches = true;
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Invalid regex pattern '{}': {}", host_pattern, e);
                    }
                }
            }
            if !host_matches {
                debug!("Host '{}' doesn't match any rule patterns: {:?}", host_value, hosts);
                return false;
            }
        } else {
            debug!("Rule requires host matching but no host provided");
            return false;
        }
    }

    true
}

/// Evaluate claim requirements against JWT claims
fn evaluate_claim_requirements(requirements: &[ClaimRequirement], claims: &serde_json::Value) -> bool {
    for requirement in requirements {
        if !evaluate_single_claim_requirement(requirement, claims) {
            debug!("Claim requirement failed for claim '{}': {:?}", requirement.claim, requirement.values);
            return false;
        }
    }
    true
}

/// Evaluate a single claim requirement
fn evaluate_single_claim_requirement(requirement: &ClaimRequirement, claims: &serde_json::Value) -> bool {
    let claim_value = match claims.get(&requirement.claim) {
        Some(value) => value,
        None => {
            debug!("Required claim '{}' not found in token", requirement.claim);
            return false;
        }
    };

    match &requirement.values {
        ClaimValues::String(expected) => {
            let actual = claim_value.as_str().unwrap_or("");
            let matches = actual == expected;
            debug!("String claim check: '{}' == '{}' -> {}", actual, expected, matches);
            matches
        }
        ClaimValues::StringArray(expected_values) => {
            let actual = claim_value.as_str().unwrap_or("");
            let matches = expected_values.contains(&actual.to_string());
            debug!("String array claim check: '{}' in {:?} -> {}", actual, expected_values, matches);
            matches
        }
        ClaimValues::Boolean(expected) => {
            let actual = claim_value.as_bool().unwrap_or(false);
            let matches = actual == *expected;
            debug!("Boolean claim check: {} == {} -> {}", actual, expected, matches);
            matches
        }
        ClaimValues::Regex(regex_pattern) => {
            let actual = claim_value.as_str().unwrap_or("");
            match Regex::new(&regex_pattern.pattern) {
                Ok(regex) => {
                    let matches = regex.is_match(actual);
                    debug!("Regex claim check: '{}' matches '{}' -> {}", actual, regex_pattern.pattern, matches);
                    matches
                }
                Err(e) => {
                    error!("Invalid regex pattern '{}': {}", regex_pattern.pattern, e);
                    false
                }
            }
        }
    }
}

/// Legacy authorization function for backward compatibility
fn is_authorized_legacy(method: &Method, path: &str, claims: &serde_json::Value) -> bool {
    let claim_name = method.as_str().to_lowercase();
    debug!("Using legacy authorization for method: '{}' (claim name: '{}'), path: '{}'", method, claim_name, path);

    if let Some(claim_value) = claims.get(&claim_name) {
        debug!("Found claim for method {}: {:?}", claim_name, claim_value);
        if let Some(paths) = claim_value.as_array() {
            debug!("Claim is an array with {} elements", paths.len());
            for path_pattern in paths {
                if let Some(pattern) = path_pattern.as_str() {
                    debug!("Checking regex pattern '{}' against path '{}'", pattern, path);
                    match Regex::new(pattern) {
                        Ok(re) => {
                            if re.is_match(path) {
                                debug!("Authorized via regex match: '{}' matches '{}'", pattern, path);
                                return true;
                            } else {
                                debug!("Regex match failed: '{}' does not match '{}'", pattern, path);
                            }
                        }
                        Err(e) => {
                            error!("Invalid regex pattern '{}': {}", pattern, e);
                            continue;
                        }
                    }
                }
            }
            debug!("No matching regex pattern found for path: {}", path);
            return false;
        } else if let Some(pattern) = claim_value.as_str() {
            debug!("Claim is a string: {} (interpreted as regex)", pattern);
            match Regex::new(pattern) {
                Ok(re) => {
                    if re.is_match(path) {
                        debug!("Authorized via regex match (string): '{}' matches '{}'", pattern, path);
                        return true;
                    }
                }
                Err(e) => {
                    error!("Invalid regex pattern '{}': {}", pattern, e);
                }
            }
        }
    } else {
        debug!("No claim found for method: {}", claim_name);
    }
    debug!("Legacy authorization failed for {}: {}", method, path);
    false
}

// Middleware for validating JWT tokens and authorizing requests
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Skip auth if disabled
    if !state.config.auth.enabled {
        debug!("Authentication is disabled, skipping auth middleware");
        return next.run(request).await;
    }

    // Get method and path for authorization check
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    
    // Extract host header for authorization rules
    let host = request
        .headers()
        .get("host")
        .and_then(|header| header.to_str().ok())
        .map(|s| s.to_string());
    
    debug!("Authenticating request: {} {} (host: {:?})", method, path, host);

    // Check for Authorization header
    let auth_header = match request
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
    {
        Some(header) => header,
        None => {
            warn!("No Authorization Bearer token found");
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(axum::body::Body::from("Missing or invalid Authorization header"))
                .unwrap();
        }
    };

    // Extract the token from the Authorization header (Bearer token)
    let token = if auth_header.trim().to_lowercase().starts_with("bearer ") {
        // Preserve original case of the token
        auth_header.trim().split_whitespace().nth(1).unwrap_or("").trim().to_string()
    } else {
        warn!("Invalid authorization header format {}", auth_header);
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(axum::body::Body::from("Invalid authorization header format"))
            .unwrap();
    };

    debug!("Found token: {}...", token.chars().take(10).collect::<String>());

    // Verify the token
    match verify_token(&token, &state.config.auth, &state.client).await {
        Ok(claims) => {
            debug!("Token verified successfully");
            // Check authorization using new Istio-like rules
            if !is_authorized_with_rules(&method, &path, host.as_deref(), &claims, &state.config.auth.authorization) {
                error!("Authorization failed for {} {} {} (host: {:?})", method, path, claims, host);
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(axum::body::Body::from("Not authorized to access this resource"))
                    .unwrap();
            }
            
            // Store user ID in extensions if available
            if let Some(sub) = claims.get("sub").and_then(|v| v.as_str()) {
                debug!("User ID (sub) extracted: {}", sub);
                request.extensions_mut().insert(UserId(sub.to_string()));
            }
            
            // Store the raw token for downstream middleware/handlers
            request.extensions_mut().insert(AuthToken(token));
            
            // Authentication and authorization succeeded
            info!("Request authorized: {} {} (host: {:?})", method, path, host);
            next.run(request).await
        },
        Err(e) => {
            warn!("Token verification failed: {}", e);
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(axum::body::Body::from(format!("Invalid token: {}", e)))
                .unwrap()
        }
    }
}

// Verify JWT token with JWKS key rotation
async fn verify_token(token: &str, auth_config: &AuthSettings, client: &Client) -> Result<Value> {
    // Get the JWKS URL
    let jwks_url = auth_config.jwks_url
        .as_ref()
        .ok_or_else(|| anyhow!("JWKS URL not configured"))?;
    
    // Get the issuer
    let issuer = auth_config.issuer
        .as_ref()
        .ok_or_else(|| anyhow!("Issuer not configured"))?;
    
    // Get the audience
    let audience = auth_config.audience
        .as_ref()
        .ok_or_else(|| anyhow!("Audience not configured"))?;
    
    // Decode header without verification to get kid (key ID)
    let header = decode_header(token)
        .map_err(|e| anyhow!("Failed to decode token header: {} - {}", e, token))?;
    
    let kid = header.kid
        .ok_or_else(|| anyhow!("Token doesn't have a 'kid' header parameter"))?;
    
    debug!("Token uses key ID (kid): {}", kid);
    
    // Fetch JWKS (JSON Web Key Set) from the URL
    debug!("Fetching JWKS from URL: {}", jwks_url);
    let jwks: JwksResponse = client.get(jwks_url)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to fetch JWKS: {}", e))?
        .json()
        .await
        .map_err(|e| anyhow!("Failed to parse JWKS response: {}", e))?;
    
    debug!("JWKS fetched successfully, found {} keys", jwks.keys.len());
    
    // Find the key with matching kid
    let key = jwks.keys.iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| anyhow!("No matching key found in JWKS with kid: {}", kid))?;
    
    debug!("Matching key found with kid: {}, type: {}", key.kid, key.kty);
    
    // Create the appropriate decoding key based on key type
    let decoding_key = match key.kty.as_str() {
        "RSA" => {
            let n = key.n.as_ref()
                .ok_or_else(|| anyhow!("RSA key missing 'n' parameter"))?;
            let e = key.e.as_ref()
                .ok_or_else(|| anyhow!("RSA key missing 'e' parameter"))?;
            
            DecodingKey::from_rsa_components(n, e)
                .map_err(|e| anyhow!("Failed to create RSA decoding key: {}", e))?
        },
        "EC" => {
            let x = key.x.as_ref()
                .ok_or_else(|| anyhow!("EC key missing 'x' parameter"))?;
            let y = key.y.as_ref()
                .ok_or_else(|| anyhow!("EC key missing 'y' parameter"))?;
            let curve = key.crv.as_ref()
                .ok_or_else(|| anyhow!("EC key missing 'crv' parameter"))?;
            
            // Map curve name to algorithm
            let _algorithm = match curve.as_str() {
                "P-256" => Algorithm::ES256,
                "P-384" => Algorithm::ES384,
                // ES512 isn't available in jsonwebtoken, use HS512 as a fallback
                "P-521" => Algorithm::HS512,
                _ => return Err(anyhow!("Unsupported EC curve: {}", curve)),
            };
            
            DecodingKey::from_ec_components(x, y)
                .map_err(|e| anyhow!("Failed to create EC decoding key: {}", e))?
        },
        _ => return Err(anyhow!("Unsupported key type: {}", key.kty)),
    };
    
    // Create validation with appropriate configurations
    let mut validation = Validation::new(Algorithm::RS256); // Will be adjusted based on alg
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    
    // Decode and verify the token
    let token_data = decode::<Value>(token, &decoding_key, &validation)
        .map_err(|e| anyhow!("Token validation failed: {}", e))?;
    
    debug!("Token validated successfully");
    
    Ok(token_data.claims)
} 