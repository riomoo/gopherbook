#!/bin/bash

set -e

IMAGE_NAME="localhost/gopherbook-builder:latest"
CONTAINER_NAME="gopherbook-builder-tmp"
OUTPUT_DIR="./binaries"

echo "=== Building cross-compilation container ==="
podman build --force-rm -t "$IMAGE_NAME" -f Containerfile.build .

if [ $? -ne 0 ]; then
    echo "Image build failed. Exiting."
    exit 1
fi

echo ""
echo "=== Creating temporary container ==="
podman create --name "$CONTAINER_NAME" "$IMAGE_NAME"

echo ""
echo "=== Creating output directory ==="
mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/*

echo ""
echo "=== Extracting Linux binary ==="
podman cp "$CONTAINER_NAME:/app/bin/gopherbook-linux" "$OUTPUT_DIR/gopherbook-linux"
chmod +x "$OUTPUT_DIR/gopherbook-linux"

echo ""
echo "=== Extracting Windows binary ==="
podman cp "$CONTAINER_NAME:/app/bin/gopherbook-windows.exe" "$OUTPUT_DIR/gopherbook-windows.exe"
chmod +x "$OUTPUT_DIR/gopherbook-windows.exe"

echo ""
echo "=== Cleaning up temporary container ==="
podman rm "$CONTAINER_NAME"

echo ""
echo "=== Build complete! ==="
echo "Binaries are in: $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR/"

echo ""
echo "=== Binary sizes ==="
du -h "$OUTPUT_DIR"/*

echo ""
echo "=== Cleaning up builder image ==="
podman rmi "$IMAGE_NAME"

echo ""
echo "✓ Done! Your binaries are ready:"
echo "  • Linux:   $OUTPUT_DIR/gopherbook-linux"
echo "  • Windows: $OUTPUT_DIR/gopherbook-windows.exe"
echo ""
echo "To run the Linux binary:"
echo "  $OUTPUT_DIR/gopherbook-linux"
echo ""
echo "To test the Windows binary (requires wine):"
echo "  wine $OUTPUT_DIR/gopherbook-windows.exe"
