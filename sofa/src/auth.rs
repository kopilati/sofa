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
use base64::Engine;
use regex::Regex;
use anyhow::{Result, anyhow};

use crate::config::AuthSettings;
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
    
    debug!("Authenticating request: {} {}", method, path);

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
            // Check authorization
            if !is_authorized(&method, &path, &claims) {
                error!("Authorization failed for {} {} {}", method, path, claims);
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
            info!("Request authorized: {} {}", method, path);
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
            let algorithm = match curve.as_str() {
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