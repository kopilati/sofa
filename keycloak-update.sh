#!/bin/bash

# Script to update Keycloak configuration with regex permission patterns for the topology token

# Export the current ConfigMap
kubectl get configmap dev-keycloak-config -o json > original-config.json

# Extract the realm JSON
jq -r '.data["realm.json"]' original-config.json > realm.json

# Function to update permission mapper claim values
update_permission() {
  local file=$1
  local mapper_name=$2
  local new_value=$3
  
  # Create a temporary file
  jq --arg mapper "$mapper_name" --arg value "$new_value" '
    .clientScopes[] |= 
    if .name == "topology-http-methods" then 
      .protocolMappers[] |= 
      if .name == $mapper then 
        .config["claim.value"] = $value 
      else . 
      end 
    else . 
    end
  ' $file > tmp.json && mv tmp.json $file
}

# Regex patterns for topology token:
# ^/.*$ - Matches any path that starts with / (allows access to all paths)
# ^/_all_dbs$ - Matches exactly /_all_dbs

# Update each permission mapper with regex patterns for the topology token
for method in "get" "post" "put" "delete" "patch" "head"; do
  echo "Updating topology token $method-permission with regex patterns..."
  # Main pattern ^/.*$ gives access to all paths starting with /
  update_permission realm.json "${method}-permission" "[\"^/.*$\", \"^/_all_dbs$\"]"
done

echo "Verifying the changes..."
grep -A 3 "claim.value" realm.json

# Update the ConfigMap
kubectl create configmap dev-keycloak-config --from-file=realm.json=realm.json -o yaml --dry-run=client | kubectl apply -f -

# Restart Keycloak to apply changes
kubectl rollout restart deployment/dev-keycloak

echo "Configuration updated with regex patterns for topology token. Keycloak restarting..."
echo "Note: It may take a minute or two for Keycloak to restart completely." 