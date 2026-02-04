#!/bin/bash

set -e

VERSION="${1:-v1.3.000}"
RELEASE_DIR="./releases"
BINARIES_DIR="./binaries"

echo "=== Packaging Gopherbook $VERSION ==="
echo ""

# Create release directory
mkdir -p "$RELEASE_DIR"

# Clean old releases for this version
rm -f "$RELEASE_DIR"/gopherbook-$VERSION-*

# Check if binaries exist
if [ ! -f "$BINARIES_DIR/gopherbook-linux" ] || [ ! -f "$BINARIES_DIR/gopherbook-windows.exe" ]; then
    echo "Error: Binaries not found. Run ./build-and-extract.sh first."
    exit 1
fi

echo "=== Creating README.txt ==="
cat > /tmp/README.txt << 'EOF'
Gopherbook - Comic Book Reader (CBZ/CBT)
=========================================

Quick Start:
------------
1. Run the gopherbook executable
2. Open your browser to http://localhost:8080
3. Register a new user account
4. Upload your CBZ/CBT comic files

Features:
---------
• Supports CBZ (ZIP) and CBT (TAR) formats
• Password-protected archives
• Tag management and filtering
• Bookmark pages
• Auto-organize by artist and story arc
• Watch folder for automatic imports
• Multi-user support with admin controls

Watch Folder:
-------------
Place CBZ/CBT files in the ./watch/<username>/ directory
and they will be automatically imported to your library.

Directory Structure:
--------------------
./library/     - Your comic library (per user)
./cache/       - Cover image cache
./etc/         - User data and settings
./watch/       - Watch folders for auto-import

Default Port: 8080

For more information, visit:
https://github.com/riomoo/gopherbook
https://codeberg.org/riomoo/gofudge
https://gitgud.io/riomoo/gopherbook

EOF

echo "=== Creating Linux package ==="
LINUX_DIR="/tmp/gopherbook-linux"
rm -rf "$LINUX_DIR"
mkdir -p "$LINUX_DIR"

# Copy Linux binary
cp "$BINARIES_DIR/gopherbook-linux" "$LINUX_DIR/gopherbook"
chmod +x "$LINUX_DIR/gopherbook"

# Copy documentation
cp /tmp/README.txt "$LINUX_DIR/"

# Create run script
cat > "$LINUX_DIR/run.sh" << 'EOF'
#!/bin/bash
echo "Starting Gopherbook..."
echo "Open your browser to: http://localhost:8080"
echo "Press Ctrl+C to stop"
echo ""
./gopherbook
EOF
chmod +x "$LINUX_DIR/run.sh"

# Package Linux
cd /tmp
tar -czf "$LINUX_DIR.tar.gz" gopherbook-linux/
cd - > /dev/null
mv "/tmp/gopherbook-linux.tar.gz" "$RELEASE_DIR/gopherbook-$VERSION-linux-amd64.tar.gz"
rm -rf "$LINUX_DIR"

echo "✓ Linux package created"

echo ""
echo "=== Creating Windows package ==="
WINDOWS_DIR="/tmp/gopherbook-windows"
rm -rf "$WINDOWS_DIR"
mkdir -p "$WINDOWS_DIR"

# Copy Windows binary
cp "$BINARIES_DIR/gopherbook-windows.exe" "$WINDOWS_DIR/gopherbook.exe"

# Copy documentation (Windows line endings)
unix2dos < /tmp/README.txt > "$WINDOWS_DIR/README.txt" 2>/dev/null || cp /tmp/README.txt "$WINDOWS_DIR/README.txt"

# Create batch file
cat > "$WINDOWS_DIR/run.bat" << 'EOF'
@echo off
echo Starting Gopherbook...
echo Open your browser to: http://localhost:8080
echo Press Ctrl+C to stop
echo.
gopherbook.exe
pause
EOF

# Create PowerShell script
cat > "$WINDOWS_DIR/run.ps1" << 'EOF'
Write-Host "Starting Gopherbook..." -ForegroundColor Green
Write-Host "Open your browser to: http://localhost:8080" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""
.\gopherbook.exe
EOF

# Package Windows
cd /tmp
zip -q -r "$WINDOWS_DIR.zip" gopherbook-windows/
cd - > /dev/null
mv "/tmp/gopherbook-windows.zip" "$RELEASE_DIR/gopherbook-$VERSION-windows-amd64.zip"
rm -rf "$WINDOWS_DIR"

echo "✓ Windows package created"

echo ""
echo "=== Creating checksums ==="
cd "$RELEASE_DIR"
sha256sum gopherbook-$VERSION-*.tar.gz gopherbook-$VERSION-*.zip > gopherbook-$VERSION-checksums.txt
cd - > /dev/null

echo "✓ Checksums created"

echo ""
echo "=== Release packages ready! ==="
echo ""
ls -lh "$RELEASE_DIR"/gopherbook-$VERSION-*
echo ""
echo "Release files:"
echo "  • $RELEASE_DIR/gopherbook-$VERSION-linux-amd64.tar.gz"
echo "  • $RELEASE_DIR/gopherbook-$VERSION-windows-amd64.zip"
echo "  • $RELEASE_DIR/gopherbook-$VERSION-checksums.txt"
echo ""
echo "Upload these files to GitHub Releases!"

# Cleanup
rm -f /tmp/README.txt
