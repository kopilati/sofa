#!/bin/bash

# This is a very simple script for testing Keycloak auth with the Sofa API
# It doesn't use any fancy substitution or parameter handling that might cause issues

# Fixed variables
KC_URL="http://localhost:30082"
REALM="sofa"
SOFA_URL="http://localhost:30081"
KC_INTERNAL_URL="http://dev-keycloak-service:8080" # Internal URL for issuer claim

# Global variable to store the access token
ACCESS_TOKEN=""

# Get a token for the sofa client
function get_sofa_token() {
    echo "Getting token for sofa-client..."
    
    # Make the request with hardcoded values
    local resp
    resp=$(curl -s -X POST \
        "$KC_URL/realms/$REALM/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=sofa-client" \
        -d "client_secret=sofa-client-secret" \
        -d "username=sofa-user" \
        -d "password=password")
    
    # Extract and store the token
    ACCESS_TOKEN=$(echo "$resp" | jq -r '.access_token')
    
    if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
        echo "Failed to get token:"
        echo "$resp" | jq
        return
    fi
    
    echo "Got token successfully"
    # Show token by default for debugging
    show_token
}

# Get a token for the topology client
function get_topology_token() {
    echo "Getting token for topology client..."
    
    # Make the request with hardcoded values
    local resp
    resp=$(curl -v -s -X POST \
        "$KC_URL/realms/$REALM/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=topology" \
        -d "client_secret=topology" \
        -d "username=sofa-user" \
        -d "password=password")
    
    # Extract and store the token
    ACCESS_TOKEN=$(echo "$resp" | jq -r '.access_token')
    
    if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
        echo "Failed to get token:"
        echo "$resp" | jq
        return
    fi
    
    echo "Got token successfully"
    # Show token by default for debugging
    show_token
}

# Show the current token details
function show_token() {
    if [ -z "$ACCESS_TOKEN" ]; then
        echo "No token available. Get a token first."
        return
    fi
    
    echo "Token contents:"
    echo "$ACCESS_TOKEN" | jq -R 'split(".") | .[1] | @base64d | fromjson'
    echo
    echo "Token length: ${#ACCESS_TOKEN} characters"
    echo "First 20 characters: ${ACCESS_TOKEN:0:20}..."
}

# List databases or a specific database
function list_db() {
    if [ -z "$ACCESS_TOKEN" ]; then
        echo "No token available. Get a token first."
        return
    fi
    
    local db="_all_dbs"
    if [ ! -z "$1" ]; then
        db="$1"
    fi
    
    echo "Listing database: $db"
    echo "Using Authorization: Bearer ${ACCESS_TOKEN:0:20}..."
    
    # Use -v for verbose output to see the headers
    curl -X GET \
        "$SOFA_URL/$db" \
        -H "Authorization: Bearer $ACCESS_TOKEN" --fail
}

# Create a database
function create_db() {
    if [ -z "$ACCESS_TOKEN" ]; then
        echo "No token available. Get a token first."
        return
    fi
    
    if [ -z "$1" ]; then
        echo "Please provide a database name"
        return
    fi
    
    echo "Creating database: $1"
    # Use -v for verbose output to see the headers
    curl -X POST \
        "$SOFA_URL/$1" \
        -H "Authorization: Bearer $ACCESS_TOKEN" --fail
}

# Usage examples:
#
# Source this script:
# source scripts/requests.sh
#
# Get a token with the sofa client:
# get_sofa_token
#
# Get a token with the topology client:
# get_topology_token
#
# Get a token with custom credentials:
# get_sofa_token "custom_username" "custom_password" "show"
#
# List databases:
# list_db "_all_dbs"
#
# Create a database:
# create_db "mydb"

