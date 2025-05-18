#!/bin/bash
set -e

echo "Fixing Dex configuration..."

# Clean up existing resources
kubectl delete deployment dex --ignore-not-found
kubectl delete deployment dev-dex --ignore-not-found
kubectl delete configmap dex-config --ignore-not-found
kubectl delete service dex-nodeport --ignore-not-found
kubectl delete service dev-dex-nodeport --ignore-not-found

# Create the config file
cat > /tmp/dex-config.yaml << 'EOF'
issuer: http://dex-service:5556/dex
storage:
  type: memory
web:
  http: 0.0.0.0:5556
oauth2:
  skipApprovalScreen: true
staticClients:
- id: sofa-client
  redirectURIs:
  - 'http://localhost:8000/callback'
  name: 'Sofa Client'
  secret: sofa-client-secret
enablePasswordDB: true
staticPasswords:
- email: admin@example.com
  hash: $2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W
  username: admin
  userID: 08a8684b-db88-4b73-90a9-3cd1661f5466
EOF

echo "Creating ConfigMap..."
kubectl create configmap dex-config --from-file=config.yaml=/tmp/dex-config.yaml

# Create the deployment
cat > /tmp/dex-deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dex
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dex
  template:
    metadata:
      labels:
        app: dex
    spec:
      containers:
      - name: dex
        image: dexidp/dex:v2.30.2
        command: [ "/usr/local/bin/dex", "serve", "/etc/dex/config.yaml" ]
        ports:
        - containerPort: 5556
        volumeMounts:
        - name: config
          mountPath: /etc/dex
      volumes:
      - name: config
        configMap:
          name: dex-config
---
apiVersion: v1
kind: Service
metadata:
  name: dex-service
spec:
  selector:
    app: dex
  ports:
  - port: 5556
    targetPort: 5556
---
apiVersion: v1
kind: Service
metadata:
  name: dex-nodeport
spec:
  type: NodePort
  selector:
    app: dex
  ports:
  - port: 5556
    targetPort: 5556
    nodePort: 30557
EOF

echo "Applying deployment..."
kubectl apply -f /tmp/dex-deployment.yaml

echo "Waiting for Dex to start..."
kubectl rollout status deployment/dex --timeout=60s || true

echo "Done! Check the status with: kubectl get pods" 