#!/bin/bash

# Update Go dependencies
echo "Updating Go dependencies..."

cd backend/auth-service
go get -u github.com/gin-gonic/gin

cd ../api-gateway
go get -u github.com/gin-gonic/gin

cd ../..

# Generate go.sum
go mod tidy

echo "Dependencies updated successfully!"
