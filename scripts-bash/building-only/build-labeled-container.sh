#!/bin/bash

IMAGE_NAME="localhost/gopherbook:2.2.0"
CONTAINER_NAME="gopherbook"
VERSION="2.2.0"
# Use the latest git commit timestamp instead of the current wall-clock time.
# This makes BUILD_DATE stable and reproducible: two builds from the same
# commit will always produce the same value. Only changes when you commit.
BUILD_DATE=$(git log -1 --format=%cI 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
VCS_REF=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "Building new image: $IMAGE_NAME..."
podman build --force-rm -t "${IMAGE_NAME}-temp" \
  --format oci \
  -f Containerfile .

if [ $? -ne 0 ]; then
    echo "Image build failed. Exiting script."
    exit 1
fi

# Ensure directories exist with correct permissions
mkdir -p ./library ./cache ./etc ./watch

if podman container exists "$CONTAINER_NAME"; then
    echo "Container '$CONTAINER_NAME' already exists. Stopping and removing it..."
    podman stop "$CONTAINER_NAME"
    podman rm "$CONTAINER_NAME"
fi

echo "Creating final image with labels in config (no layer)..."

# Use buildah to modify the image config directly
buildah from --name working-container "${IMAGE_NAME}-temp"

# Add labels directly to the config (doesn't create a layer!)
buildah config \
  --label "org.opencontainers.image.title=Gopherbook" \
  --label "org.opencontainers.image.description=Gopherbook Minimal Image" \
  --label "org.opencontainers.image.version=${VERSION}" \
  --label "org.opencontainers.image.created=${BUILD_DATE}" \
  --label "org.opencontainers.image.revision=${VCS_REF}" \
  --label "org.opencontainers.image.authors=Alister <alister@kamikishi.net>" \
  --label "org.opencontainers.image.vendor=Jester Designs" \
  --label "org.opencontainers.image.licenses=PIL" \
  --label "com.jesterdesigns.image.type=base-image" \
  --label "com.jesterdesigns.image.purpose=static-binary-runtime" \
  working-container

# Commit the container to the final image name
buildah commit --format oci working-container "$IMAGE_NAME"

# Cleanup
buildah rm working-container
podman rmi "${IMAGE_NAME}-temp"

echo "Starting new container from image: $IMAGE_NAME..."
# IMPROVED: Better memory settings and limits
podman run -d --name "$CONTAINER_NAME" \
  --memory=512m \
  --memory-swap=512m \
  --restart unless-stopped \
  -e GOMEMLIMIT=480MiB \
  -e GOMAXPROCS=2 \
  -p 12010:8080 \
  -v ./library:/app/library \
  -v ./cache:/app/cache \
  -v ./etc:/app/etc \
  -v ./watch:/app/watch \
  "$IMAGE_NAME"

if [ $? -ne 0 ]; then
    echo "Failed to start new container. Exiting script."
    exit 1
fi

echo "Cleaning up old images..."
podman image prune --force

echo "Update and cleanup complete!"
echo "Container is running with memory limit: 512MB"
echo "Container is running with memory swap: 512MB"
echo "Go memory limit (GOMEMLIMIT): 480MiB"
