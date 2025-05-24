use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::error::Error;

// Token endpoint response
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

// Client credentials request
#[derive(Debug, Serialize)]
struct ClientCredentialsRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    audience: String,
    scope: String,
}

async fn get_token(dex_url: &str, client_id: &str, client_secret: &str) -> Result<String, Box<dyn Error>> {
    // For Dex with client credentials, we'll use the password grant type
    // In a real-world scenario, you'd use the OAuth2 authorization code flow
    let token_endpoint = format!("{}/token", dex_url);
    
    // Create a form with client credentials
    let form = [
        ("grant_type", "password"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("username", "sofa-user"),
        ("password", "password"),
        ("scope", "openid"),
    ];
    
    // Get token
    let client = Client::new();
    let response = client
        .post(&token_endpoint)
        .form(&form)
        .send()
        .await?;
    
    if !response.status().is_success() {
        return Err(format!("Failed to get token: {:?}", response.text().await?).into());
    }
    
    let token_response: TokenResponse = response.json().await?;
    Ok(token_response.access_token)
}

async fn test_sofa_with_token(sofa_url: &str, token: &str, path: &str) -> Result<String, Box<dyn Error>> {
    let client = Client::new();
    let response = client
        .get(&format!("{}/{}", sofa_url, path))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    
    if !response.status().is_success() {
        return Err(format!("Request failed: {:?}", response.text().await?).into());
    }
    
    Ok(response.text().await?)
}

async fn test_sofa_without_token(sofa_url: &str, path: &str) -> Result<(StatusCode, String), Box<dyn Error>> {
    let client = Client::new();
    let response = client
        .get(&format!("{}/{}", sofa_url, path))
        .send()
        .await?;
    
    let status = response.status();
    let body = response.text().await?;
    
    Ok((status, body))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Configure these values based on your environment
    let dex_url = std::env::var("DEX_URL").unwrap_or_else(|_| "http://localhost:30082/realms/sofa/protocol/openid-connect".to_string());
    let sofa_url = std::env::var("SOFA_URL").unwrap_or_else(|_| "http://localhost:30081".to_string());
    let client_id = std::env::var("CLIENT_ID").unwrap_or_else(|_| "sofa-client".to_string());
    let client_secret = std::env::var("CLIENT_SECRET").unwrap_or_else(|_| "sofa-client-secret".to_string());
    
    println!("Testing Sofa proxy with OAuth2 authentication");
    
    // First, try accessing Sofa without a token - should fail with 401
    let (status, body) = test_sofa_without_token(&sofa_url, "_all_dbs").await?;
    println!("Access without token: Status={}, Body={}", status, body);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    
    // Get a token from Dex
    println!("Getting token from Dex...");
    let token = get_token(&dex_url, &client_id, &client_secret).await?;
    println!("Token received: {:.20}...", token);
    
    // Test accessing Sofa with the token
    println!("Testing access to Sofa with token...");
    let response = test_sofa_with_token(&sofa_url, &token, "_all_dbs").await?;
    println!("Response from Sofa: {}", response);
    
    println!("All tests passed!");
    Ok(())
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_oauth_flow() {
        // Skip this test if we're not in a test environment with Dex and Sofa running
        let dex_url = match std::env::var("DEX_URL") {
            Ok(url) => url,
            Err(_) => return, // Skip test if DEX_URL isn't set
        };
        
        let sofa_url = std::env::var("SOFA_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        let client_id = std::env::var("CLIENT_ID").unwrap_or_else(|_| "sofa-client".to_string());
        let client_secret = std::env::var("CLIENT_SECRET").unwrap_or_else(|_| "sofa-client-secret".to_string());
        
        // Verify that access is denied without a token
        let result = test_sofa_without_token(&sofa_url, "_all_dbs").await;
        assert!(result.is_ok());
        let (status, _) = result.unwrap();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        
        // Get a token and verify access is granted
        let token = get_token(&dex_url, &client_id, &client_secret).await;
        assert!(token.is_ok());
        
        let response = test_sofa_with_token(&sofa_url, &token.unwrap(), "_all_dbs").await;
        assert!(response.is_ok());
    }
} 