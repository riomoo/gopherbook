#!/bin/bash

set -e

VERSION="${1:-v3.0.0}"
RELEASE_DIR="./releases"
BINARIES_DIR="./binaries"
ICON_SRC="./app/gopherbook/static/images/pngs/LogoPose2.png"
APPIMAGETOOL="${APPIMAGETOOL:-/home/$USER/.local/bin/appimagetool-x86_64.AppImage}"
SIGN_KEY="${SIGN_KEY:-554AF2CEAE26AC80}"

echo "=== Packaging Gopherbook $VERSION ==="
echo ""

# Create release directory
mkdir -p "$RELEASE_DIR"

# Clean old releases for this version
rm -f "$RELEASE_DIR"/gopherbook-$VERSION-*

# Check all binaries exist
MISSING=0
for bin in \
    gopherbook-linux \
    gopherbook-windows.exe \
    gopherbook-desktop-linux-musl \
    gopherbook-desktop-linux-glibc \
    gopherbook-desktop-windows.exe; do
    if [ ! -f "$BINARIES_DIR/$bin" ]; then
        echo "Error: $BINARIES_DIR/$bin not found."
        MISSING=1
    fi
done
if [ "$MISSING" -eq 1 ]; then
    echo "Run ./build-and-extract.sh first."
    exit 1
fi

# Check appimagetool
if [ ! -f "$APPIMAGETOOL" ]; then
    echo "Warning: appimagetool not found at $APPIMAGETOOL — skipping AppImage builds."
    echo "         Set APPIMAGETOOL=/path/to/appimagetool-x86_64.AppImage to enable."
    BUILD_APPIMAGE=0
else
    chmod +x "$APPIMAGETOOL"
    BUILD_APPIMAGE=1
fi

# ── READMEs ───────────────────────────────────────────────────────────────────
echo "=== Creating READMEs ==="

cat > /tmp/README-server.txt << 'EOF'
Gopherbook - Comic Book Reader (CBZ/CBT/CB7)
============================================

This is the SERVER version of Gopherbook.
Run it and open your browser to access your comic library.

Quick Start:
------------
1. Run the gopherbook executable (or run.sh / run.bat)
2. Open your browser to http://localhost:8112
3. Register a new user account
4. Upload your CBZ/CBT/CB7 comic files

Features:
---------
• Supports CBZ (ZIP), CBT (TAR), and CB7 (7zip) formats
• Password-protected archives
• Tag management and filtering
• Bookmark pages
• Auto-organize by artist and story arc
• Watch folder for automatic imports
• Multi-user support with admin controls
• Delete comics by right-clicking or clicking the trash can icon
• Share comics by right-clicking a comic
     - Encrypted comics? You can set a separate share password
       for the person you are sharing with.
• Categories with generated or uploaded covers
• No JSON files — single bbolt database

Watch Folder:
-------------
Place CBZ/CBT/CB7 files in the ./watch/<username>/ directory
and they will be automatically imported to your library.

Directory Structure:
--------------------
./library/     - Your comic library (per user)
./cache/       - Cover image cache
./etc/         - User data and settings
./watch/       - Watch folders for auto-import

Port:
-----
Default port is 8080, set to 8112 in the provided run scripts.
Override with environment variable: GBKPORT=8112

For more information, visit:
https://github.com/riomoo/gopherbook
https://codeberg.org/riomoo/gopherbook
https://gitgud.io/riomoo/gopherbook

EOF

cat > /tmp/README-desktop-musl.txt << 'EOF'
Gopherbook Desktop - Comic Book Reader (CBZ/CBT/CB7)
====================================================

This is the DESKTOP version of Gopherbook, built for
musl-based Linux distributions.

Compatible with:
----------------
• Alpine Linux
• Void Linux (musl variant)
• Gentoo (musl profile)
• Any other musl-based Linux distro

NOT compatible with glibc-based distros (Ubuntu, Debian, Fedora,
Arch, etc.) — use the glibc build instead.

Quick Start:
------------
1. Run gopherbook-desktop (or run.sh), or launch the AppImage
2. The app opens directly as a native desktop window
3. Register a new user account on first launch
4. Upload or import your CBZ/CBT/CB7 comic files

Features:
---------
• Native desktop window — no browser required
• Supports CBZ (ZIP), CBT (TAR), and CB7 (7zip) formats
• Password-protected archives — known passwords tried automatically
• Tag management and filtering
• Alphabetical and search filtering
• Bookmark pages
• Auto-organize by artist and story arc
• Watch folder for automatic imports
• Categories with generated or uploaded covers
• No JSON files — single bbolt database

Watch Folder:
-------------
Place CBZ/CBT/CB7 files in the ./watch/<username>/ directory
and they will be automatically imported to your library.

Directory Structure:
--------------------
./library/     - Your comic library (per user)
./cache/       - Cover image cache
./etc/         - User data and settings
./watch/       - Watch folders for auto-import

For more information, visit:
https://github.com/riomoo/gopherbook
https://codeberg.org/riomoo/gopherbook
https://gitgud.io/riomoo/gopherbook

EOF

cat > /tmp/README-desktop-glibc.txt << 'EOF'
Gopherbook Desktop - Comic Book Reader (CBZ/CBT/CB7)
====================================================

This is the DESKTOP version of Gopherbook, built for
glibc-based Linux distributions.

Compatible with:
----------------
• Ubuntu 18.10 and newer
• Debian 10 (Buster) and newer
• Fedora 29 and newer
• Arch Linux
• Void Linux (glibc variant)
• Linux Mint, Pop!_OS, and most mainstream distros
• Any distro with glibc 2.28 or newer

NOT compatible with musl-based distros (Alpine, Void musl, etc.)
— use the musl build instead.

Quick Start:
------------
1. Run gopherbook-desktop (or run.sh), or launch the AppImage
2. The app opens directly as a native desktop window
3. Register a new user account on first launch
4. Upload or import your CBZ/CBT/CB7 comic files

Features:
---------
• Native desktop window — no browser required
• Supports CBZ (ZIP), CBT (TAR), and CB7 (7zip) formats
• Password-protected archives — known passwords tried automatically
• Tag management and filtering
• Alphabetical and search filtering
• Bookmark pages
• Auto-organize by artist and story arc
• Watch folder for automatic imports
• Categories with generated or uploaded covers
• No JSON files — single bbolt database

Watch Folder:
-------------
Place CBZ/CBT/CB7 files in the ./watch/<username>/ directory
and they will be automatically imported to your library.

Directory Structure:
--------------------
./library/     - Your comic library (per user)
./cache/       - Cover image cache
./etc/         - User data and settings
./watch/       - Watch folders for auto-import

For more information, visit:
https://github.com/riomoo/gopherbook
https://codeberg.org/riomoo/gopherbook
https://gitgud.io/riomoo/gopherbook

EOF

cat > /tmp/README-desktop-windows.txt << 'EOF'
Gopherbook Desktop - Comic Book Reader (CBZ/CBT/CB7)
====================================================

This is the DESKTOP version of Gopherbook for Windows.

Compatible with:
----------------
• Windows 10 and newer (64-bit)

Quick Start:
------------
1. Run gopherbook-desktop.exe (or run.bat / run.ps1)
2. The app opens directly as a native desktop window
3. Register a new user account on first launch
4. Upload or import your CBZ/CBT/CB7 comic files

Features:
---------
• Native desktop window — no browser required
• Supports CBZ (ZIP), CBT (TAR), and CB7 (7zip) formats
• Password-protected archives — known passwords tried automatically
• Tag management and filtering
• Alphabetical and search filtering
• Bookmark pages
• Auto-organize by artist and story arc
• Watch folder for automatic imports
• Categories with generated or uploaded covers
• No JSON files — single bbolt database

Watch Folder:
-------------
Place CBZ/CBT/CB7 files in the watch\<username>\ directory
and they will be automatically imported to your library.

Directory Structure:
--------------------
library\       - Your comic library (per user)
cache\         - Cover image cache
etc\           - User data and settings
watch\         - Watch folders for auto-import

Note:
-----
Windows may show a SmartScreen warning on first launch since the
binary is not code-signed. Click "More info" then "Run anyway".

For more information, visit:
https://github.com/riomoo/gopherbook
https://codeberg.org/riomoo/gopherbook
https://gitgud.io/riomoo/gopherbook

EOF

echo "✓ READMEs created"

# ── AppRun scripts ────────────────────────────────────────────────────────────
# Server AppRun — stores data in ~/.config/gopherbook, loads config file
cat > /tmp/AppRun-server << 'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"

CONFIG="$HOME/.config/gopherbook/gopherbook.conf"

# Create default config if it doesn't exist
if [ ! -f "$CONFIG" ]; then
    mkdir -p "$(dirname "$CONFIG")"
    cat > "$CONFIG" << 'CONF'
GOPHERBOOK_LIBRARY=$HOME/.config/gopherbook/library
GOPHERBOOK_CACHE=$HOME/.config/gopherbook/covers
GOPHERBOOK_ETC=$HOME/.config/gopherbook/etc
GOPHERBOOK_WATCH=$HOME/.config/gopherbook/watch
GBKPORT=8112
CONF
fi

# Load config
set -a
source "$CONFIG"
set +a

exec "$HERE/usr/bin/gopherbook" "$@"
EOF
chmod +x /tmp/AppRun-server

# Desktop AppRun — same config approach, launches desktop binary
cat > /tmp/AppRun-desktop << 'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"

CONFIG="$HOME/.config/gopherbook/gopherbook.conf"

# Create default config if it doesn't exist
if [ ! -f "$CONFIG" ]; then
    mkdir -p "$(dirname "$CONFIG")"
    cat > "$CONFIG" << 'CONF'
GOPHERBOOK_LIBRARY=$HOME/.config/gopherbook/library
GOPHERBOOK_CACHE=$HOME/.config/gopherbook/covers
GOPHERBOOK_ETC=$HOME/.config/gopherbook/etc
GOPHERBOOK_WATCH=$HOME/.config/gopherbook/watch
CONF
fi

# Load config
set -a
source "$CONFIG"
set +a

exec "$HERE/usr/bin/gopherbook-desktop" "$@"
EOF
chmod +x /tmp/AppRun-desktop

# ── Helper: build an AppDir and invoke appimagetool ──────────────────────────
# Usage: build_appimage <binary> <variant> <output_name> <exec_name> <apprun_file>
#   binary       — path to the binary
#   variant      — "server", "musl", or "glibc" (used in desktop Comment field)
#   output_name  — final AppImage filename (no path)
#   exec_name    — name of binary inside usr/bin/
#   apprun_file  — path to a pre-written AppRun script
build_appimage() {
    local BINARY="$1"
    local VARIANT="$2"
    local OUTPUT="$3"
    local EXEC_NAME="$4"
    local APPRUN_FILE="$5"

    local APPDIR="/tmp/gopherbook-${VARIANT}.AppDir"
    rm -rf "$APPDIR"

    # ── Directory structure ───────────────────────────────────────────────────
    mkdir -p "$APPDIR/usr/bin"
    mkdir -p "$APPDIR/usr/share/applications"
    mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

    # ── Binary ───────────────────────────────────────────────────────────────
    cp "$BINARY" "$APPDIR/usr/bin/$EXEC_NAME"
    chmod +x "$APPDIR/usr/bin/$EXEC_NAME"

    # ── Icon — resize to 256x256 if convert is available, else copy as-is ────
    local ICON_DEST="$APPDIR/usr/share/icons/hicolor/256x256/apps/gopherbook.png"
    if command -v convert > /dev/null 2>&1; then
        convert "$ICON_SRC" -resize 256x256 "$ICON_DEST"
    else
        cp "$ICON_SRC" "$ICON_DEST"
    fi
    # Root-level icon files required by AppImage spec.
    # PCManFM and most thumbnailers won't follow symlinks inside squashfs,
    # so these must be real copies, not symlinks.
    cp "$ICON_DEST" "$APPDIR/gopherbook.png"
    cp "$ICON_DEST" "$APPDIR/.DirIcon"

    # ── Desktop file ─────────────────────────────────────────────────────────
    cat > "$APPDIR/usr/share/applications/gopherbook.desktop" << EOF2
[Desktop Entry]
Name=Gopherbook
Comment=Comic Book Reader (${VARIANT})
Exec=${EXEC_NAME}
Icon=gopherbook
Type=Application
Categories=Graphics;Viewer;
Terminal=false
StartupNotify=true
EOF2
    # Root-level symlink required by AppImage spec
    ln -sf "usr/share/applications/gopherbook.desktop" "$APPDIR/gopherbook.desktop"

    # ── AppRun ────────────────────────────────────────────────────────────────
    cp "$APPRUN_FILE" "$APPDIR/AppRun"
    chmod +x "$APPDIR/AppRun"

    # ── Build AppImage ────────────────────────────────────────────────────────
    "$APPIMAGETOOL" -v -s \
        --sign-key "$SIGN_KEY" \
        --comp zstd \
        --mksquashfs-opt -Xcompression-level --mksquashfs-opt 22 \
        "$APPDIR" "$RELEASE_DIR/$OUTPUT"

    rm -rf "$APPDIR"
    echo "✓ $OUTPUT created"
}

# ── Server — Linux ────────────────────────────────────────────────────────────
echo ""
echo "=== Creating Server Linux package ==="
LINUX_DIR="/tmp/gopherbook-linux"
rm -rf "$LINUX_DIR"
mkdir -p "$LINUX_DIR"

cp "$BINARIES_DIR/gopherbook-linux" "$LINUX_DIR/gopherbook"
chmod +x "$LINUX_DIR/gopherbook"
cp /tmp/README-server.txt "$LINUX_DIR/README.txt"

cat > "$LINUX_DIR/run.sh" << 'EOF'
#!/bin/bash
echo "Starting Gopherbook..."
echo "Open your browser to: http://localhost:8112"
echo "Press Ctrl+C to stop"
echo ""
GBKPORT=8112 ./gopherbook
EOF
chmod +x "$LINUX_DIR/run.sh"

cd /tmp && tar -czf "$LINUX_DIR.tar.gz" gopherbook-linux/ && cd - > /dev/null
mv "/tmp/gopherbook-linux.tar.gz" "$RELEASE_DIR/gopherbook-$VERSION-linux-x86_64.tar.gz"
rm -rf "$LINUX_DIR"
echo "✓ Server Linux package created"

# ── Server — Linux AppImage ───────────────────────────────────────────────────
if [ "$BUILD_APPIMAGE" -eq 1 ]; then
    echo ""
    echo "=== Creating Server Linux AppImage ==="
    build_appimage \
        "$BINARIES_DIR/gopherbook-linux" \
        "server" \
        "gopherbook-$VERSION-linux-x86_64.AppImage" \
        "gopherbook" \
        /tmp/AppRun-server
fi

# ── Server — Windows ──────────────────────────────────────────────────────────
echo ""
echo "=== Creating Server Windows package ==="
WINDOWS_DIR="/tmp/gopherbook-windows"
rm -rf "$WINDOWS_DIR"
mkdir -p "$WINDOWS_DIR"

cp "$BINARIES_DIR/gopherbook-windows.exe" "$WINDOWS_DIR/gopherbook.exe"
unix2dos < /tmp/README-server.txt > "$WINDOWS_DIR/README.txt" 2>/dev/null || cp /tmp/README-server.txt "$WINDOWS_DIR/README.txt"

cat > "$WINDOWS_DIR/run.bat" << 'EOF'
@echo off
echo Starting Gopherbook...
echo Open your browser to: http://localhost:8112
echo Press Ctrl+C to stop
echo.
set GBKPORT=8112
gopherbook.exe
pause
EOF

cat > "$WINDOWS_DIR/run.ps1" << 'EOF'
Write-Host "Starting Gopherbook..." -ForegroundColor Green
Write-Host "Open your browser to: http://localhost:8112" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""
$env:GBKPORT = 8112
.\gopherbook.exe
EOF

cd /tmp && zip -q -r "$WINDOWS_DIR.zip" gopherbook-windows/ && cd - > /dev/null
mv "/tmp/gopherbook-windows.zip" "$RELEASE_DIR/gopherbook-$VERSION-windows-amd64.zip"
rm -rf "$WINDOWS_DIR"
echo "✓ Server Windows package created"

# ── Desktop — Linux musl ──────────────────────────────────────────────────────
echo ""
echo "=== Creating Desktop Linux musl package ==="
DESKMUSL_DIR="/tmp/gopherbook-desktop-linux-musl"
rm -rf "$DESKMUSL_DIR"
mkdir -p "$DESKMUSL_DIR"

cp "$BINARIES_DIR/gopherbook-desktop-linux-musl" "$DESKMUSL_DIR/gopherbook-desktop"
chmod +x "$DESKMUSL_DIR/gopherbook-desktop"
cp /tmp/README-desktop-musl.txt "$DESKMUSL_DIR/README.txt"

cat > "$DESKMUSL_DIR/run.sh" << 'EOF'
#!/bin/bash
echo "Starting Gopherbook Desktop..."
./gopherbook-desktop
EOF
chmod +x "$DESKMUSL_DIR/run.sh"

cd /tmp && tar -czf "$DESKMUSL_DIR.tar.gz" gopherbook-desktop-linux-musl/ && cd - > /dev/null
mv "/tmp/gopherbook-desktop-linux-musl.tar.gz" "$RELEASE_DIR/gopherbook-$VERSION-desktop-linux-musl-x86_64.tar.gz"
rm -rf "$DESKMUSL_DIR"
echo "✓ Desktop Linux musl package created"

# ── Desktop — Linux musl AppImage ────────────────────────────────────────────
if [ "$BUILD_APPIMAGE" -eq 1 ]; then
    echo ""
    echo "=== Creating Desktop Linux musl AppImage ==="
    build_appimage \
        "$BINARIES_DIR/gopherbook-desktop-linux-musl" \
        "musl" \
        "gopherbook-$VERSION-desktop-linux-musl-x86_64.AppImage" \
        "gopherbook-desktop" \
        /tmp/AppRun-desktop
fi

# ── Desktop — Linux glibc ─────────────────────────────────────────────────────
echo ""
echo "=== Creating Desktop Linux glibc package ==="
DESKGLIBC_DIR="/tmp/gopherbook-desktop-linux-glibc"
rm -rf "$DESKGLIBC_DIR"
mkdir -p "$DESKGLIBC_DIR"

cp "$BINARIES_DIR/gopherbook-desktop-linux-glibc" "$DESKGLIBC_DIR/gopherbook-desktop"
chmod +x "$DESKGLIBC_DIR/gopherbook-desktop"
cp /tmp/README-desktop-glibc.txt "$DESKGLIBC_DIR/README.txt"

cat > "$DESKGLIBC_DIR/run.sh" << 'EOF'
#!/bin/bash
echo "Starting Gopherbook Desktop..."
./gopherbook-desktop
EOF
chmod +x "$DESKGLIBC_DIR/run.sh"

cd /tmp && tar -czf "$DESKGLIBC_DIR.tar.gz" gopherbook-desktop-linux-glibc/ && cd - > /dev/null
mv "/tmp/gopherbook-desktop-linux-glibc.tar.gz" "$RELEASE_DIR/gopherbook-$VERSION-desktop-linux-glibc-x86_64.tar.gz"
rm -rf "$DESKGLIBC_DIR"
echo "✓ Desktop Linux glibc package created"

# ── Desktop — Linux glibc AppImage ───────────────────────────────────────────
if [ "$BUILD_APPIMAGE" -eq 1 ]; then
    echo ""
    echo "=== Creating Desktop Linux glibc AppImage ==="
    build_appimage \
        "$BINARIES_DIR/gopherbook-desktop-linux-glibc" \
        "glibc" \
        "gopherbook-$VERSION-desktop-linux-glibc-x86_64.AppImage" \
        "gopherbook-desktop" \
        /tmp/AppRun-desktop
fi

# ── Desktop — Windows ─────────────────────────────────────────────────────────
echo ""
echo "=== Creating Desktop Windows package ==="
DESKWIN_DIR="/tmp/gopherbook-desktop-windows"
rm -rf "$DESKWIN_DIR"
mkdir -p "$DESKWIN_DIR"

cp "$BINARIES_DIR/gopherbook-desktop-windows.exe" "$DESKWIN_DIR/gopherbook-desktop.exe"
unix2dos < /tmp/README-desktop-windows.txt > "$DESKWIN_DIR/README.txt" 2>/dev/null || cp /tmp/README-desktop-windows.txt "$DESKWIN_DIR/README.txt"

cat > "$DESKWIN_DIR/run.bat" << 'EOF'
@echo off
echo Starting Gopherbook Desktop...
gopherbook-desktop.exe
pause
EOF

cat > "$DESKWIN_DIR/run.ps1" << 'EOF'
Write-Host "Starting Gopherbook Desktop..." -ForegroundColor Green
.\gopherbook-desktop.exe
EOF

cd /tmp && zip -q -r "$DESKWIN_DIR.zip" gopherbook-desktop-windows/ && cd - > /dev/null
mv "/tmp/gopherbook-desktop-windows.zip" "$RELEASE_DIR/gopherbook-$VERSION-desktop-windows-amd64.zip"
rm -rf "$DESKWIN_DIR"
echo "✓ Desktop Windows package created"

# ── Checksums ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Creating checksums ==="
cd "$RELEASE_DIR"
sha256sum gopherbook-$VERSION-* > gopherbook-$VERSION-checksums.txt
cd - > /dev/null
echo "✓ Checksums created"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Release packages ready! ==="
echo ""
ls -lh "$RELEASE_DIR"/gopherbook-$VERSION-*
echo ""
echo "Release files:"
echo "  • $RELEASE_DIR/gopherbook-$VERSION-linux-x86_64.tar.gz"
echo "  • $RELEASE_DIR/gopherbook-$VERSION-windows-amd64.zip"
echo "  • $RELEASE_DIR/gopherbook-$VERSION-desktop-linux-musl-x86_64.tar.gz"
echo "  • $RELEASE_DIR/gopherbook-$VERSION-desktop-linux-glibc-x86_64.tar.gz"
echo "  • $RELEASE_DIR/gopherbook-$VERSION-desktop-windows-amd64.zip"
if [ "$BUILD_APPIMAGE" -eq 1 ]; then
echo "  • $RELEASE_DIR/gopherbook-$VERSION-linux-x86_64.AppImage"
echo "  • $RELEASE_DIR/gopherbook-$VERSION-desktop-linux-musl-x86_64.AppImage"
echo "  • $RELEASE_DIR/gopherbook-$VERSION-desktop-linux-glibc-x86_64.AppImage"
fi
echo "  • $RELEASE_DIR/gopherbook-$VERSION-checksums.txt"
echo ""
echo "Upload these files to GitHub Releases!"

# Cleanup
rm -f /tmp/README-server.txt \
      /tmp/README-desktop-musl.txt \
      /tmp/README-desktop-glibc.txt \
      /tmp/README-desktop-windows.txt \
      /tmp/AppRun-server \
      /tmp/AppRun-desktop
