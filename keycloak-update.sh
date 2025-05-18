#!/bin/bash

# Script to update Keycloak configuration with additional permissions

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

# Update each permission mapper
for method in "get" "post" "put" "delete" "patch" "head"; do
  echo "Updating $method-permission..."
  update_permission realm.json "${method}-permission" "[\"\\//*\", \"\\/_all_dbs\"]"
done

# Update the ConfigMap
kubectl create configmap dev-keycloak-config --from-file=realm.json=realm.json -o yaml --dry-run=client | kubectl apply -f -

# Restart Keycloak to apply changes
kubectl rollout restart deployment/dev-keycloak

echo "Configuration updated. Keycloak restarting..." 