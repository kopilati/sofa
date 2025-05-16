#!/bin/bash
set -e

# Check if Task is installed
if ! command -v task &> /dev/null; then
    echo "Task is not installed. Please install it from https://taskfile.dev/"
    echo "On macOS: brew install go-task"
    echo "On Linux: sh -c \"\$(curl --location https://taskfile.dev/install.sh)\" -- -d -b ~/.local/bin"
    exit 1
fi

echo "Using Taskfile to set up the test environment"

# Run the setup task
task setup

# Run the test directly in the cluster
echo "Running the OAuth2 test client in-cluster..."
task run-test

echo "Test environment setup and test completed!"

# Optional: ask if user wants to start port forwarding for manual testing
read -p "Do you want to start port-forwarding to access the services in a browser? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting port-forwarding. Press Ctrl+C to stop."
    task port-forward
fi 