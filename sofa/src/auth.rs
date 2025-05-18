use axum::{
    extract::{Request, State},
    http::{Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use reqwest::Client;
use tracing::{error, info, debug};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use regex::Regex;

use crate::config::AuthConfig;
use crate::proxy::AppState;

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
    keys: Vec<Jwk>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    #[serde(rename = "use")]
    usage: Option<String>,
    alg: Option<String>,
    n: Option<String>,   // modulus for RSA
    e: Option<String>,   // exponent for RSA
    x: Option<String>,   // x coordinate for EC
    y: Option<String>,   // y coordinate for EC
    crv: Option<String>, // curve for EC
}

// Token type to store in extensions
#[derive(Clone)]
pub struct AuthToken(pub String);

// UserId type to store in extensions
#[derive(Clone)]
pub struct UserId(pub String);

// Check if a path is authorized based on the claims
fn is_authorized(method: &Method, path: &str, claims: &JwtClaims) -> bool {
    let claim_name = method.as_str().to_lowercase();
    debug!("Checking authorization for method: '{}' (claim name: '{}'), path: '{}'", method, claim_name, path);
    debug!("Available claims: {:?}", claims.additional_claims);

    if let Some(claim_value) = claims.additional_claims.get(&claim_name) {
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

// Middleware for validating JWT tokens and authorizing requests
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Skip auth if disabled
    if !state.config.auth.enabled {
        return next.run(request).await;
    }

    // Get method and path for authorization check
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    
    debug!("Authenticating request: {} {}", method, path);

    // Check for Authorization header
    let auth_header = match request
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
    {
        Some(header) => header,
        None => {
            return (StatusCode::UNAUTHORIZED, "Missing authorization header").into_response();
        }
    };

    // Extract the token from the Authorization header (Bearer token)
    let token = if auth_header.starts_with("Bearer ") {
        auth_header.trim_start_matches("Bearer ").trim()
    } else {
        return (StatusCode::UNAUTHORIZED, "Invalid authorization header format").into_response();
    };

    // Validate the token
    let validation_result = validate_token(token, &state.config.auth, &state.client).await;
    
    match validation_result {
        Ok(token_data) => {
            // Check authorization
            if !is_authorized(&method, &path, &token_data.claims) {
                error!("Authorization failed for {} {}", method, path);
                return (StatusCode::FORBIDDEN, "Not authorized to access this resource").into_response();
            }
            
            // Store user ID in extensions if available
            if let Some(sub) = token_data.claims.sub {
                request.extensions_mut().insert(UserId(sub));
            }
            
            // Authentication and authorization succeeded
            info!("Request authorized: {} {}", method, path);
            next.run(request).await
        }
        Err(err) => {
            // Invalid token
            error!("Token validation failed: {}", err);
            (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", err)).into_response()
        }
    }
}

// Validate the JWT token
async fn validate_token(
    token: &str,
    auth_config: &AuthConfig,
    client: &Client,
) -> Result<TokenData<JwtClaims>, String> {
    // Decode the token header to get the key ID (kid)
    let header = decode_header(token).map_err(|e| format!("Invalid token header: {}", e))?;
    
    let kid = header.kid.as_deref();
    
    // Log the config for debugging
    debug!("Auth config - enabled: {}", auth_config.enabled);
    if let Some(issuer) = &auth_config.issuer {
        debug!("Auth config - issuer: {}", issuer);
    } else {
        debug!("Auth config - issuer is not set");
    }
    if let Some(jwks_url) = &auth_config.jwks_url {
        debug!("Auth config - jwks_url: {}", jwks_url);
    } else {
        error!("Auth config - jwks_url is not set");
    }
    
    // If jwks_url is configured, fetch the JWKS
    let decoding_key = if let Some(jwks_url) = &auth_config.jwks_url {
        // Fetch JWKS
        let jwks = fetch_jwks(jwks_url, client).await
            .map_err(|e| format!("Failed to fetch JWKS: {}", e))?;
        
        // Find the key with matching kid
        let jwk = match kid {
            Some(kid) => jwks.keys.iter().find(|k| k.kid.as_deref() == Some(kid)),
            None => jwks.keys.first(),
        };
        
        let jwk = jwk.ok_or_else(|| "No matching key found in JWKS".to_string())?;
        
        // Convert JWK to DecodingKey
        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk.n.as_deref().ok_or_else(|| "Missing modulus (n) in RSA key".to_string())?;
                let e = jwk.e.as_deref().ok_or_else(|| "Missing exponent (e) in RSA key".to_string())?;
                
                // Use from_rsa_components which takes &str parameters for modulus and exponent
                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| format!("Failed to create RSA key: {}", e))
            },
            // Add support for EC keys if needed
            _ => Err(format!("Unsupported key type: {}", jwk.kty)),
        }
    } else {
        // No JWKS URL configured, can't validate signature
        return Err("JWKS URL not configured".to_string());
    }?;
    
    // Set up validation parameters
    let mut validation = Validation::new(Algorithm::RS256); // Adjust algorithm as needed
    
    // Check issuer if configured
    if let Some(issuer) = &auth_config.issuer {
        validation.set_issuer(&[issuer.as_str()]);
    }
    
    // Check audience if configured
    if let Some(audience) = &auth_config.audience {
        validation.set_audience(&[audience.as_str()]);
    }
    
    // Validate the token
    let token_data = decode::<JwtClaims>(token, &decoding_key, &validation)
        .map_err(|e| format!("Token validation failed: {}", e))?;
    
    Ok(token_data)
}

// Fetch JWKS from the provided URL
async fn fetch_jwks(jwks_url: &str, client: &Client) -> Result<JwksResponse, String> {
    info!("Fetching JWKS from URL: {}", jwks_url);
    
    let response = client
        .get(jwks_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch JWKS: {}", e))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|_| "Could not read response body".to_string());
        error!("JWKS request failed with status: {}, body: {}", status, body);
        return Err(format!("JWKS request failed with status: {}", status));
    }
    
    let response_text = response.text().await
        .map_err(|e| format!("Failed to read JWKS response: {}", e))?;
    
    info!("Received JWKS response: {}", response_text);
    
    // Parse the response
    serde_json::from_str::<JwksResponse>(&response_text)
        .map_err(|e| format!("Failed to parse JWKS response: {}", e))
} 