#!/bin/bash

# This script is meant to be run inside the Sofa pod to test internal connectivity

KC_URL="http://dev-keycloak-service:8080"
REALM="sofa"
SOFA_URL="http://dev-sofa-service:80"

# Function to get a token for testing
function get_token() {
    echo "Getting token from internal Keycloak service..."
    
    # Make the request with hardcoded values
    local resp
    resp=$(curl -s -X POST \
        "$KC_URL/realms/$REALM/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=topology" \
        -d "client_secret=topology" \
        -d "username=sofa-user" \
        -d "password=password")
    
    # Extract and store the token
    ACCESS_TOKEN=$(echo "$resp" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
    
    if [ -z "$ACCESS_TOKEN" ]; then
        echo "Failed to get token:"
        echo "$resp"
        return
    fi
    
    echo "Got token successfully"
    echo "First 20 characters: ${ACCESS_TOKEN:0:20}..."
}

# Function to test API access
function test_api() {
    if [ -z "$ACCESS_TOKEN" ]; then
        echo "No token available. Get a token first."
        return
    fi
    
    echo "Testing API access..."
    curl -v -s -X GET \
        "$SOFA_URL/d_all_dbs" \
        -H "Authorization: Bearer $ACCESS_TOKEN"
}

echo "Starting internal connectivity test..."
get_token
test_api 