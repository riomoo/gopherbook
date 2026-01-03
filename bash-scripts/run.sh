#!/bin/bash

IMAGE_NAME="localhost/gopherbook:latest"
CONTAINER_NAME="gopherbook"

echo "Building new image: $IMAGE_NAME..."
podman build --force-rm -t "$IMAGE_NAME" .

if [ $? -ne 0 ]; then
    echo "Image build failed. Exiting script."
    exit 1
fi

# Ensure directories exist with correct permissions
mkdir -p ./library ./cache ./etc

if podman container exists "$CONTAINER_NAME"; then
    echo "Container '$CONTAINER_NAME' already exists. Stopping and removing it..."
    podman stop "$CONTAINER_NAME"
    podman rm "$CONTAINER_NAME"
fi

echo "Starting new container from image: $IMAGE_NAME..."
# IMPROVED: Better memory settings and limits
podman run -d --name "$CONTAINER_NAME" \
  --memory=512m \
  --restart unless-stopped \
  -p 12010:8080 \
  -v ./library:/app/library \
  -v ./cache:/app/cache \
  -v ./etc:/app/etc \
  "$IMAGE_NAME"

if [ $? -ne 0 ]; then
    echo "Failed to start new container. Exiting script."
    exit 1
fi

echo "Cleaning up old images..."
podman image prune --force

echo "Update and cleanup complete!"
echo "Container is running with memory limit: 512MB, swap: 512MB"
echo "Go memory limit (GOMEMLIMIT): 512MiB"
echo "Aggressive GC enabled (GOGC=50)"
