#!/bin/bash
set -e

echo "Setting up Keycloak for Sofa..."

# Wait for Keycloak to be ready
echo "Waiting for Keycloak to start..."
kubectl wait --for=condition=available deployment/keycloak --timeout=180s

# Forward port to Keycloak (or use NodePort)
KC_URL="http://localhost:8080"
KC_ADMIN="admin"
KC_PASSWORD="admin"

echo "Port-forwarding Keycloak service..."
kubectl port-forward svc/keycloak-service 8080:8080 &
PF_PID=$!

# Make sure to kill the port-forward when the script exits
trap "kill $PF_PID" EXIT

# Wait for port-forward to establish
sleep 5

# Get admin token
echo "Getting admin token..."
ADMIN_TOKEN=$(curl -s -X POST "${KC_URL}/auth/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${KC_ADMIN}" \
  -d "password=${KC_PASSWORD}" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  echo "Failed to get admin token. Make sure Keycloak is running and accessible."
  exit 1
fi

# Create Sofa realm
echo "Creating Sofa realm..."
curl -s -X POST "${KC_URL}/auth/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "sofa",
    "enabled": true,
    "displayName": "Sofa Realm",
    "accessTokenLifespan": 1800
  }'

# Create Sofa client
echo "Creating Sofa client..."
CLIENT_ID=$(curl -s -X POST "${KC_URL}/auth/admin/realms/sofa/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "sofa-client",
    "name": "Sofa Client",
    "enabled": true,
    "secret": "sofa-client-secret",
    "clientAuthenticatorType": "client-secret",
    "directAccessGrantsEnabled": true,
    "standardFlowEnabled": true,
    "implicitFlowEnabled": false,
    "serviceAccountsEnabled": false,
    "publicClient": false,
    "redirectUris": ["http://localhost:8000/callback"],
    "webOrigins": ["+"]
  }' | jq -r '.id')

# Create a test user
echo "Creating test user..."
curl -s -X POST "${KC_URL}/auth/admin/realms/sofa/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "firstName": "Admin",
    "lastName": "User",
    "enabled": true,
    "emailVerified": true,
    "credentials": [
      {
        "type": "password",
        "value": "admin",
        "temporary": false
      }
    ]
  }'

echo "Keycloak setup complete!"
echo ""
echo "Access Keycloak admin console at: ${KC_URL}/auth/admin"
echo "Username: ${KC_ADMIN}"
echo "Password: ${KC_PASSWORD}"
echo ""
echo "Realm: sofa"
echo "Client ID: sofa-client"
echo "Client Secret: sofa-client-secret"
echo "Test User: admin/admin" 