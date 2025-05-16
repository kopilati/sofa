#!/bin/bash
set -e

# Build the Docker image
echo "Building Docker image..."
docker build -t sofa:latest .

# Load the image into Kind
echo "Loading image into Kind cluster..."
kind load docker-image sofa:latest

echo "Image loaded successfully!"
echo "You can now apply the Kubernetes manifests:"
echo "kubectl apply -f k8s/deployment.yaml" 