#!/bin/bash
set -e

# Colors for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}==== Starting SOFA with Encryption Enabled ====${NC}"

# Check if CouchDB is running
if ! nc -z localhost 5984 >/dev/null 2>&1; then
  echo -e "${RED}CouchDB is not running on localhost:5984${NC}"
  echo -e "${YELLOW}Please start CouchDB first:${NC}"
  echo -e "docker run -d -p 5984:5984 -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=password couchdb:latest"
  exit 1
fi

# Build the application if needed
if [ ! -f "target/debug/sofa" ]; then
  echo -e "${GREEN}Building the application...${NC}"
  cargo build
fi

# Set environment variables for encryption
export SOFA_MASTER_ENC_KEY="test-key-for-local-dev"
export SOFA_ENCRYPTED_ENDPOINTS="^/secure/.*,^/test/.*"
export SOFA_COUCHDB_URL="http://localhost:5984"
export SOFA_COUCHDB_USERNAME="admin"
export SOFA_COUCHDB_PASSWORD="password"

echo -e "${GREEN}Starting SOFA with encryption enabled...${NC}"
echo -e "${GREEN}Master Key: ${SOFA_MASTER_ENC_KEY}${NC}"
echo -e "${GREEN}Encrypted Endpoints: ${SOFA_ENCRYPTED_ENDPOINTS}${NC}"

# Run the application
cargo run

# This will be executed when the process is terminated
echo -e "${GREEN}SOFA has been stopped${NC}" 