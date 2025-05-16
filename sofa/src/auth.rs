use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use reqwest::Client;
use tracing::error;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

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

// Middleware for validating JWT tokens
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    // Skip auth if disabled
    if !state.config.auth.enabled {
        return next.run(request).await;
    }

    // Check for Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok());

    let auth_header = match auth_header {
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
    match validate_token(token, &state.config.auth, &state.client).await {
        Ok(_) => {
            // Token is valid, proceed with the request
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
    let response = client
        .get(jwks_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch JWKS: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("JWKS request failed with status: {}", response.status()));
    }
    
    response.json::<JwksResponse>()
        .await
        .map_err(|e| format!("Failed to parse JWKS response: {}", e))
} 