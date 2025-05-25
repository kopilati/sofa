# Authorization System

Sofa's authorization system has been redesigned to use Istio-like authorization policies. This provides more flexible and powerful access control compared to the legacy method-based claims system.

## Overview

The new authorization system uses **rules** that match against request attributes (host, path, method) and evaluate **claims** from JWT tokens. This approach is similar to Istio's AuthorizationPolicy but tailored for CouchDB proxy scenarios.

## Configuration Structure

```yaml
auth:
  enabled: true
  issuer: "http://localhost:30082/realms/sofa"
  audience: "sofa-client"
  jwks_url: "http://keycloak-service:8080/realms/sofa/protocol/openid-connect/certs"
  
  authorization:
    default_action: deny  # or "allow"
    rules:
      - name: "rule-name"
        hosts: ["pattern1", "pattern2"]      # Optional
        paths: ["pattern1", "pattern2"]      # Optional
        methods: ["GET", "POST", "PUT"]      # Optional
        when:
          - claim: "claim_name"
            values: "expected_value"         # or array or boolean
```

## Rule Matching

### Request Context Matching

Rules first check if the incoming request matches the specified context:

1. **Host Matching** (optional): If `hosts` is specified, the request's `Host` header must match at least one pattern
2. **Path Matching** (optional): If `paths` is specified, the request path must match at least one pattern  
3. **Method Matching** (optional): If `methods` is specified, the HTTP method must be in the list

**Pattern Matching**: All patterns use regular expressions for maximum flexibility.

**Omitted Fields**: If any of these fields are omitted, they match all values (e.g., no `hosts` means all hosts are allowed).

### Claim Requirements

Once request context matching passes, the rule evaluates claim requirements in the `when` section:

- **ALL** claim requirements must be satisfied for the rule to allow access
- If any claim requirement fails, the rule is skipped

## Claim Value Types

### String Values
```yaml
when:
  - claim: "role"
    values: "admin"
```

### String Arrays (OR logic)
```yaml
when:
  - claim: "organization"
    values: ["Acme Corp", "Beta Inc", "Gamma LLC"]
```

### Boolean Values
```yaml
when:
  - claim: "service_account"
    values: true
```

### Regex Patterns
```yaml
when:
  - claim: "sub"
    values:
      pattern: "^service-.*"
```

## Default Action

When no rules match the request, the `default_action` determines the outcome:

- `deny` (default): Reject the request with 403 Forbidden
- `allow`: Allow the request to proceed

## Examples

### Example 1: Admin Full Access
```yaml
- name: "admin-full-access"
  when:
    - claim: "role"
      values: "admin"
```
Admins can access any resource.

### Example 2: Organization-Scoped Database Access
```yaml
- name: "org-database-access"
  paths:
    - "^/[^_][^/]+/.*"           # Database documents
    - "^/[^_][^/]+/_design/.*"   # Design documents
  when:
    - claim: "organization"
      values: ["Acme Corp", "Beta Inc"]
    - claim: "role"
      values: ["user", "admin"]
```
Users from specific organizations can access database documents.

### Example 3: Read-Only Public Access
```yaml
- name: "readonly-public-access"
  methods: ["GET", "HEAD"]
  paths:
    - "^/public-.*"
  when:
    - claim: "access_level"
      values: "read"
```
Read-only access to public databases.

### Example 4: Service Account with Regex
```yaml
- name: "service-account-access"
  when:
    - claim: "service_account"
      values: true
    - claim: "sub"
      values:
        pattern: "^service-.*"
```
Service accounts with subject starting with "service-".

### Example 5: Host-Specific Access
```yaml
- name: "staging-environment"
  hosts:
    - ".*\\.staging\\..*"
  when:
    - claim: "environment"
      values: ["staging", "development"]
```
Staging environment access based on hostname.

## Migration from Legacy System

The legacy authorization system used method-based claims (e.g., `get`, `post`, `put` claims with path patterns). The new system maintains backward compatibility:

1. If no `authorization` section is configured, the legacy system is used
2. Legacy claims like `get: ["^/.*$"]` still work
3. Gradually migrate to the new rule-based system

### Legacy vs New Comparison

**Legacy:**
```json
{
  "get": ["^/.*$"],
  "post": ["^/database.*"],
  "organization": "Acme Corp"
}
```

**New Equivalent:**
```yaml
rules:
  - name: "legacy-get-access"
    methods: ["GET"]
    when:
      - claim: "organization"
        values: "Acme Corp"
  
  - name: "legacy-post-access"
    methods: ["POST"]
    paths: ["^/database.*"]
    when:
      - claim: "organization"
        values: "Acme Corp"
```

## Debugging

Enable debug logging to see authorization decisions:

```
RUST_LOG=sofa::auth=debug
```

Log output includes:
- Rule evaluation order
- Pattern matching results
- Claim requirement evaluation
- Final authorization decision

## Best Practices

1. **Principle of Least Privilege**: Start with `default_action: deny`
2. **Named Rules**: Always use descriptive `name` fields for debugging
3. **Specific Patterns**: Use specific regex patterns to avoid accidental matches
4. **Testing**: Test authorization rules thoroughly with representative tokens
5. **Documentation**: Document the business logic behind each rule

## Security Considerations

1. **Regex Safety**: Ensure regex patterns don't cause ReDoS (Regular Expression Denial of Service)
2. **Claim Validation**: Verify claims are properly set in your identity provider
3. **Token Expiry**: Configure appropriate token lifetimes
4. **Audit Logging**: Enable audit logging to track access patterns
5. **HTTPS**: Always use HTTPS in production to protect tokens in transit 