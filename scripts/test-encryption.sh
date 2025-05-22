#!/bin/bash
set -e

# Colors for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}==== Testing SOFA Encryption in Kubernetes ====${NC}"

# Step 1: Build and push the Docker image
echo -e "${GREEN}Building Docker image...${NC}"
docker build -t sofa:latest .

# Step 2: Apply the Kubernetes configuration
echo -e "${GREEN}Deploying SOFA to Kubernetes...${NC}"
kubectl apply -k k8s/overlays/test

# Wait for pods to be ready
echo -e "${GREEN}Waiting for SOFA pod to be ready...${NC}"
kubectl wait --for=condition=ready pod -l app=sofa --timeout=120s

# Step 3: Set up port forwarding
POD_NAME=$(kubectl get pod -l app=sofa -o jsonpath="{.items[0].metadata.name}")
echo -e "${GREEN}Setting up port forwarding for pod ${POD_NAME}...${NC}"
kubectl port-forward $POD_NAME 3000:3000 &
PORT_FORWARD_PID=$!

# Give port forwarding time to establish
sleep 3

# Step 4: Get an auth token if authentication is enabled
AUTH_ENABLED=$(kubectl get configmap test-sofa-config -o jsonpath="{.data.auth_enabled}")
if [ "$AUTH_ENABLED" == "true" ]; then
  echo -e "${GREEN}Auth is enabled, obtaining token...${NC}"
  # This is a placeholder - in a real environment, you would obtain a token from your auth provider
  # For testing, you might use curl to get a token from Keycloak
  TOKEN="your-auth-token"
  AUTH_HEADER="Authorization: Bearer $TOKEN"
else
  echo -e "${YELLOW}Auth is disabled, no token needed${NC}"
  AUTH_HEADER=""
fi

# Step 5: Test a regular endpoint
echo -e "${GREEN}Testing non-encrypted endpoint...${NC}"
curl -s -X GET http://localhost:3000/_all_dbs | jq .

# Step 6: Create a test database
echo -e "${GREEN}Creating test database...${NC}"
curl -s -X PUT http://localhost:3000/secure_test

# Step 7: Test encryption with a document that should be encrypted
echo -e "${GREEN}Creating a document with data to be encrypted...${NC}"
curl -s -X PUT \
  -H "Content-Type: application/json" \
  $AUTH_HEADER \
  -d '{
    "name": "Test User",
    "email": "test@example.com",
    "sensitive": "This should be encrypted",
    "_id": "test_doc_1"
  }' \
  http://localhost:3000/secure_test/test_doc_1 | jq .

# Step 8: Retrieve the document and verify encryption worked
echo -e "${GREEN}Retrieving document to verify encryption/decryption...${NC}"
curl -s -X GET \
  $AUTH_HEADER \
  http://localhost:3000/secure_test/test_doc_1 | jq .

# Step 9: Compare raw document in CouchDB to see if it's encrypted
echo -e "${GREEN}Checking if document is stored encrypted in CouchDB...${NC}"
COUCHDB_POD=$(kubectl get pod -l app=couchdb -o jsonpath="{.items[0].metadata.name}")
COUCHDB_RESULT=$(kubectl exec $COUCHDB_POD -- curl -s -X GET \
  -u admin:password \
  http://localhost:5984/secure_test/test_doc_1)
echo $COUCHDB_RESULT | jq .

echo -e "${GREEN}Look for '$$name', '$$email', '$$sensitive' keys in the raw CouchDB document${NC}"
echo -e "${GREEN}These indicate the properties were encrypted before storage${NC}"

# Clean up
echo -e "${GREEN}Cleaning up...${NC}"
kill $PORT_FORWARD_PID
wait $PORT_FORWARD_PID 2>/dev/null || true

echo -e "${GREEN}Test completed!${NC}" 