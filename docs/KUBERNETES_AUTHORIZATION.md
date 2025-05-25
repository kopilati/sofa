# Kubernetes Authorization Configuration

This document explains how to configure the new Istio-like authorization system in Kubernetes deployments.

## Overview

The new authorization system uses YAML-based configuration that's stored in Kubernetes ConfigMaps and loaded via the `SOFA_AUTH_AUTHORIZATION` environment variable.

## Configuration Structure

### Environment Variable Mapping

The deployment automatically maps the authorization configuration from the ConfigMap:

```yaml
- name: SOFA_AUTH_AUTHORIZATION
  valueFrom:
    configMapKeyRef:
      name: sofa-config  # or dev-sofa-config, prod-sofa-config
      key: auth_authorization
      optional: true
```

### ConfigMap Format

The authorization rules are stored in the `auth_authorization` key as YAML content:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sofa-config
data:
  auth_authorization: |
    default_action: deny
    rules:
      - name: "admin-full-access"
        when:
          - claim: "role"
            values: "admin"
      # ... more rules
```

## Environment-Specific Configurations

### Development Environment

The development configuration (`k8s/overlays/dev/sofa-config-patch.yaml`) includes:

- **Admin Access**: Full access for admin users
- **User Database Access**: Document operations for users with organization claims
- **Database Creation**: PUT operations for database creation
- **System Access**: GET/HEAD for system endpoints
- **Auth Endpoints**: Access to session and user endpoints

**Key Claims Required:**
- `role`: "admin" or "user"
- `organization`: "Sofa Organization"
- `db_create`: true (for database creation)

### Production Environment

The production configuration (`k8s/overlays/prod/sofa-config-patch.yaml`) is more restrictive:

- **Admin Access**: Full access for admin users only
- **Service Account Access**: Automated processes with environment validation
- **Limited User Access**: Only GET/POST/PUT operations (no DELETE)
- **Monitoring Access**: Limited system access for monitoring roles

**Key Claims Required:**
- `role`: "admin", "user", or "monitor"
- `organization`: "Production Organization"
- `environment`: "production"
- `service_account`: true (for automated processes)

## Deployment Process

### 1. Build and Push Images

```bash
# Build the Sofa image with new authorization
task build-sofa

# Tag and push to your registry (if needed)
docker tag sofa:latest your-registry/sofa:latest
docker push your-registry/sofa:latest
```

### 2. Apply Configuration

```bash
# Apply to development environment
kubectl apply -k k8s/overlays/dev

# Apply to production environment
kubectl apply -k k8s/overlays/prod
```

### 3. Verify Configuration

```bash
# Check if the pods are running
kubectl get pods -l app=sofa

# Check the ConfigMap
kubectl get configmap sofa-config -o yaml

# Check the environment variables in the pod
kubectl exec -it deployment/sofa -- env | grep SOFA_AUTH_AUTHORIZATION
```

## Testing Authorization

### 1. Without Token (Should Deny)

```bash
curl -v http://your-sofa-service/_all_dbs
# Expected: 401 Unauthorized
```

### 2. With Valid Token

```bash
# Get token from Keycloak
TOKEN=$(curl -s -X POST \
  http://your-keycloak-service:8080/realms/sofa/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=sofa-client" \
  -d "client_secret=sofa-client-secret" \
  -d "username=sofa-user" \
  -d "password=password" \
  -d "grant_type=password" | jq -r '.access_token')

# Test with token
curl -v -H "Authorization: Bearer $TOKEN" http://your-sofa-service/_all_dbs
# Expected: 200 OK (if user has proper claims)
```

## Troubleshooting

### 1. Check Configuration Loading

```bash
# Check Sofa logs for configuration errors
kubectl logs deployment/sofa | grep -i "authorization\|config"
```

### 2. Verify Claims in Token

Decode the JWT token to verify claims:

```bash
# Using jwt-cli (install with: cargo install jwt-cli)
jwt decode $TOKEN

# Or use online JWT debugger at jwt.io
```

### 3. Check Rule Matching

Look for authorization decision logs:

```bash
kubectl logs deployment/sofa | grep -i "rule\|authorized\|denied"
```

## Migration from Legacy System

The new system maintains backward compatibility:

1. **Gradual Migration**: Deploy with authorization rules but keep legacy claims
2. **Token Updates**: Update Keycloak mappers to include new claims
3. **Rule Testing**: Test rules in development before production
4. **Legacy Removal**: Remove old method-based claims after validation

## Security Best Practices

### Development
- Use organization-based access control
- Allow broader access for development and testing
- Include database creation permissions for developers

### Production
- Enforce strict organization and environment claims
- Limit DELETE operations
- Use service accounts for automated processes
- Monitor authorization decisions via audit logs

## Example Keycloak Configuration

Update your Keycloak client scopes to include the required claims:

```json
{
  "name": "organization-mapper",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "config": {
    "user.attribute": "organization",
    "claim.name": "organization",
    "access.token.claim": "true"
  }
}
```

## See Also

- [Authorization Rules Documentation](./AUTHORIZATION.md)
- [Development Setup](./DEVELOPMENT.md)
- [Production Deployment](./PRODUCTION.md) 