#!/bin/bash
set -e

# Colors for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}==== Testing SOFA Encryption Locally ====${NC}"

# Check if SOFA is running locally
if ! nc -z localhost 3000 >/dev/null 2>&1; then
  echo -e "${RED}SOFA is not running locally on port 3000. Please start it first.${NC}"
  echo -e "${YELLOW}Start SOFA with environment variables:${NC}"
  echo -e "SOFA_MASTER_ENC_KEY=test-key-for-local-dev"
  echo -e "SOFA_ENCRYPTED_ENDPOINTS=^/secure/.*,^/test/.*"
  exit 1
fi

# Step 1: Test a regular endpoint (should not be encrypted)
echo -e "${GREEN}Testing non-encrypted endpoint...${NC}"
curl -s -X GET http://localhost:3000/_all_dbs | jq .

# Step 2: Create a test database
echo -e "${GREEN}Creating test database 'secure'...${NC}"
curl -s -X PUT http://localhost:3000/secure

# Step 3: Create a non-secure database for comparison
echo -e "${GREEN}Creating non-secure database 'regular'...${NC}"
curl -s -X PUT http://localhost:3000/regular

# Step 4: Create a document in secure database (should be encrypted)
echo -e "${GREEN}Creating document in /secure (should be encrypted)...${NC}"
curl -s -X PUT \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Secure User",
    "email": "secure@example.com",
    "sensitive": "This should be encrypted",
    "nestedObject": {
      "nested1": "This nested value should be encrypted too",
      "nested2": 12345
    },
    "array": ["item1", "item2", 3],
    "_id": "secure_doc_1"
  }' \
  http://localhost:3000/secure/secure_doc_1 | jq .

# Step 5: Create a similar document in regular database (should not be encrypted)
echo -e "${GREEN}Creating document in /regular (should NOT be encrypted)...${NC}"
curl -s -X PUT \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Regular User",
    "email": "regular@example.com",
    "sensitive": "This should NOT be encrypted",
    "nestedObject": {
      "nested1": "This nested value should NOT be encrypted",
      "nested2": 12345
    },
    "array": ["item1", "item2", 3],
    "_id": "regular_doc_1"
  }' \
  http://localhost:3000/regular/regular_doc_1 | jq .

# Step 6: Retrieve the secure document (should be automatically decrypted)
echo -e "${GREEN}Retrieving document from /secure (should be decrypted)...${NC}"
curl -s -X GET http://localhost:3000/secure/secure_doc_1 | jq .

# Step 7: Retrieve the regular document
echo -e "${GREEN}Retrieving document from /regular...${NC}"
curl -s -X GET http://localhost:3000/regular/regular_doc_1 | jq .

# Step 8: Verify encryption by directly accessing CouchDB
echo -e "${GREEN}Directly checking CouchDB to verify encryption (if CouchDB is on localhost:5984):${NC}"
echo -e "${YELLOW}This will fail if CouchDB is not available at localhost:5984${NC}"
if nc -z localhost 5984 >/dev/null 2>&1; then
  echo -e "${GREEN}Checking secure document in CouchDB:${NC}"
  curl -s -u admin:password http://localhost:5984/secure/secure_doc_1 | jq .
  
  echo -e "${GREEN}Checking regular document in CouchDB:${NC}"
  curl -s -u admin:password http://localhost:5984/regular/regular_doc_1 | jq .
  
  echo -e "${GREEN}Look for '$$name', '$$email', '$$sensitive' keys in the secure document${NC}"
  echo -e "${GREEN}These indicate the properties were encrypted before storage${NC}"
else
  echo -e "${YELLOW}CouchDB not available at localhost:5984, skipping direct verification${NC}"
fi

echo -e "${GREEN}Test completed!${NC}" 