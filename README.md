<div align="center">

<img src="https://git.jester-designs.com/riomoo/gopherbook/media/branch/main/docs/images/gopherbook-title.png" alt="Description" width="50%">

</div>

<div align="center">

## Self-Hosted Comic Library & CBZ/CBT/CB7/EPUB Reader

Gopherbook is a lightweight, single-binary, self-hosted comic reader and library manager written in Go.  
It is designed for people who want full control over their digital comic collection (CBZ/CBT/CB7/EPUB files), including support for password-protected/encrypted archives, per-user libraries, tagging, automatic organization, and a clean modern reader.

Available as a **server** (browser-based) and a **desktop** (native window, no browser required) version.

Pages can be JPEG, PNG, WebP, BMP, **JPEG XL** or **JPEG 2000**, and animated **GIF**, **APNG** and **JPEG XL** pages play in both the web reader and the desktop app.

</div>

## License

[![Custom badge](https://git.jester-designs.com/riomoo/gopherbook/media/branch/main/docs/images/svgs/PIL.svg)](LICENSE)

## Versions

| Version | Description | Runs on |
|---------|-------------|---------|
| **Server** | Browser-based, self-hosted, multi-user; pure Go, single static binary | Any Linux, Windows |
| **Desktop (glibc)** | Native desktop window, no browser needed | Ubuntu, Debian, Fedora, Arch, Void glibc, any glibc 2.28+ distro |
| **Desktop (musl)** | Native desktop window, no browser needed | Alpine, Void musl, any musl-based distro |
| **Desktop (Windows)** | Native desktop window, no browser needed | Windows 10+ 64-bit |

### Desktop Example:
<details>
<summary>See it in action</summary>
<br>

#### MP4 Video Link:
<a href="https://share.jester-designs.com/view/gopherbook-desktop.mp4">
  <img src="https://share.jester-designs.com/view/gopherbook-desktop.png" alt="Gopherbook Desktop Demo — click to watch" width="100%">
</a>

</details>


## Features

### Server & Desktop
- Upload & read `.cbz` (ZIP-based), `.cbt` (TAR-based), `.cb7` (7-Zip-based), or `.epub` (EPUB 3-based) comics
- **Modern page formats**: pages can be JPEG, PNG, WebP, BMP, **JPEG XL** (`.jxl`) or **JPEG 2000** (`.jp2`, `.j2k`, `.jpf`, `.jpx`); see [Page image formats](#page-image-formats)
  - **JPEG XL**: lossy, lossless, losslessly recompressed JPEGs, high bit depth, alpha and animation (pure Go, via [gen2brain/jxl](https://github.com/gen2brain/jxl))
  - **JPEG 2000**: lossless and lossy, tiled, layered, every progression order, greyscale, 16-bit and alpha (pure Go, via [seehuhn.de/go/jpx](https://github.com/seehuhn/go-jpx); matches the OpenJPEG reference decoder)
  - Browsers that can't display JPEG XL or JPEG 2000 are sent a pixel-exact PNG made on the fly; browsers that can are sent the original file
- **Animated pages**: animated GIF, APNG (animated PNG) and animated JPEG XL pages play with their original frame timing and loop count, in the web reader and the desktop app
- **CB7 / 7-Zip support**: full read support for 7-Zip archives, both unencrypted and AES-256 encrypted (including header-encrypted `-mhe=on` archives)
  - LZMA (v1) and LZMA2 decompression supported
  - CRC32 verification used for reliable password validation (works even with store-only/uncompressed archives where wrong passwords produce silent garbage)
- **EPUB 3 support**: full read support for EPUB 3 comic archives, both unencrypted and AES-256-GCM encrypted
  - Reads spine order from `content.opf` so pages always appear in the correct sequence
  - Extracts rich OPF metadata: title, creator, series, story arc, publication year, and subject tags
  - Encryption detection via `META-INF/encryption.xml`; fast password validation via SHA-256 verify hash in `META-INF/key-hint.txt`
  - Structural files (`content.opf`, navigation, XHTML) are always plaintext so metadata is readable even on encrypted files without a password
- **Watch folder support for bulk imports**: drop CBZ/CBT/CB7/EPUB files into your watch folder and they're automatically imported
- Supports 8 Megapixel images at 512MB memory limits
    - (increase in bash script for higher Megapixels or remove the limitation if you don't care)
- Full support for password-protected/encrypted CBZ files (AES-256 via yeka/zip), CBT files (AES-256-CFB OpenSSL), and CB7 files (AES-256 via bodgit/sevenzip)
- **Automatically tries all previously successful passwords** when opening a new encrypted comic, no prompt if a known password works
- Persists discovered passwords securely (AES-encrypted on disk, key derived from your login password)
- Extracts ComicInfo.xml metadata (title, series, number, writer, inker, tags, story arc, etc.) from CBZ, CBT, and CB7 archives; extracts OPF metadata (title, creator, series, story arc, year, subjects) from EPUB archives
- Automatic folder organization: `Library/Artist/StoryArc/Comic.cbz`
- **Automatic artist tag**: when metadata is extracted, the artist is automatically added as a tag so your tag list always reflects your library's artists without any manual effort
- Manual reorganization via UI if needed
- Powerful tagging system with custom colors and counts
- Filter comics by any combination of tags, alphabetically, or by search
- Responsive grid view with cached JPEG covers
- Paginated library browsing for large collections
- **Single unified bbolt database**: replaces scattered JSON files for better performance and reliability
- **Easy comic deletion**: remove comics from your library with a right-click or trash icon
- **Changes are never lost**: deletions are saved immediately, and logging out, closing the desktop app or stopping the server (Ctrl-C, `podman stop`) saves any pending edits first. Library entries whose file has gone missing are cleaned up automatically at login
- **Uploads never overwrite**: uploading a comic whose filename already exists stores it as `name_1.cbz`, `name_2.cbz`, … (just like the watch folder)
- **Shareable links**: generate and share direct links to individual comics, with optional share-level password protection
- **Collections**: organize comics into custom collections with generated or uploaded covers
- No external dependencies: everything self-contained in a single binary. The server (and both Windows builds) is pure Go, built with `CGO_ENABLED=0`, so it needs no C toolchain or system libraries

### Server only
- Full-screen web reader with:
  - Page pre-loading
  - Zoom / pan
  - Fit-to-width/height/page
  - Keyboard navigation (←→, A/D, +/-, Esc)
- Multi-user support:
  - Each user has their own completely isolated library and password vault
  - First registered user becomes admin
  - Admin can disable new registrations
  - Admin can delete any comic

### Desktop only
- Native window — no browser required, launches directly as a desktop app (built with [Gio](https://gioui.org); Wayland or X11 on Linux, and Windows)
- Plays animated GIF, APNG and JPEG XL pages natively
- Keyboard controls, Vim-style or arrows:

  | Keys | Action |
  |------|--------|
  | `H` `J` `K` `L` / `←` `↓` `↑` `→` | Pan around the page |
  | `Shift`+`H` / `Shift`+`←` | Previous page |
  | `Shift`+`L` / `Shift`+`→` | Next page |
  | `+` / `-` (or `Shift`+`K` / `Shift`+`J`) | Zoom in / out |
  | `=` | Reset zoom to 100% |

- Available as an AppImage for easy distribution on Linux

## Installation / Running

### Prerequisites
[![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)](https://golang.org/dl/)
- Go 1.27.2+ (only needed to build from source)
- Desktop on Linux only: a C compiler and the development packages for libx11, libxcursor, libxfixes, libxkbcommon, Mesa (EGL), Wayland and the Vulkan headers
- Or download a pre-built binary or AppImage from Releases

### Quick start: Server (from source)
```bash
git clone https://codeberg.org/riomoo/gopherbook.git
cd gopherbook
CGO_ENABLED=0 go build -o gopherbook ./app/gopherbook
./gopherbook
```

`CGO_ENABLED=0` gives a fully static binary; the server has no C code.

Then open http://localhost:8080 in your browser and upload CBZ, CBT, CB7, or EPUB files.

### Quick start: Desktop (from source)
```bash
git clone https://codeberg.org/riomoo/gopherbook.git
cd gopherbook
go build -tags desktop -o gopherbook-desktop ./app/gopherbook
./gopherbook-desktop
```

### Quick start: GNU Guix

Gopherbook is packaged in the [PIL Guix channel](https://git.jester-designs.com/riomoo/guix-channel). Add it to `~/.config/guix/channels.scm`:

```scheme
(cons* (channel
         (name 'pil-channel)
         (url "https://git.jester-designs.com/riomoo/guix-channel")
         (branch "main")
         (introduction
          (make-channel-introduction
           "13b62f3f4b945786454d1b8f4091100c3140c8cc"
           (openpgp-fingerprint
            "5A13 43DB 4CBA 9A07 FC1F  FC02 554A F2CE AE26 AC80"))))
       %default-channels)
```

Then:

```bash
guix pull
guix install gopherbook           # server
guix install gopherbook-desktop   # desktop app
```

The channel also provides a Guix Home service (`home-gopherbook-service-type`) that runs the server for your user.

### Quick start: Pre-built binaries

Download the appropriate release from the Releases page:

| File | Description |
|------|-------------|
| `gopherbook-*-linux-x86_64.tar.gz` | Server, Linux |
| `gopherbook-*-windows-amd64.zip` | Server, Windows |
| `gopherbook-*-desktop-linux-glibc-x86_64.tar.gz` | Desktop, Linux glibc (Ubuntu/Fedora/Arch/etc) |
| `gopherbook-*-desktop-linux-musl-x86_64.tar.gz` | Desktop, Linux musl (Alpine/Void musl/etc) |
| `gopherbook-*-desktop-windows-amd64.zip` | Desktop, Windows |
| `gopherbook-*-linux-x86_64.AppImage` | Server, Linux AppImage |
| `gopherbook-*-desktop-linux-glibc-x86_64.AppImage` | Desktop, Linux glibc AppImage |

### Building all binaries with Podman

```bash
# Build the container image
podman build -f Containerfile.build -t gopherbook-builder .

# Extract all 5 binaries
# (server Linux/Windows and desktop Windows are pure Go; only the two Linux
#  desktop builds use cgo, for Gio's X11/Wayland/EGL bindings)
mkdir -p binaries
podman run --rm -v ./binaries:/out gopherbook-builder \
  sh -c "cp bin/* /out/"
```

Then package for release:
```bash
./scripts-bash/building-only/package-release.sh vX.Y.Z
```

The Containerfiles pin exact Alpine package versions. Alpine only keeps the newest build of each package, so when a build fails with `unable to select packages`, refresh the pins:
```bash
./scripts-bash/building-only/check-apk-pins.sh                 # Containerfile.build
./scripts-bash/building-only/check-apk-pins.sh Containerfile   # server image
```
It reads the `apk add` list from the Containerfile, checks it against the pinned base image, flags base-image packages that also need upgrading (e.g. `musl`), and prints a ready-to-paste block.

## If you want to use this with podman:
```bash
git clone https://codeberg.org/riomoo/gopherbook.git
cd gopherbook
./scripts-bash/run-gb-container/run-podman.sh
```

or

## If you want to use this with docker:
```bash
git clone https://codeberg.org/riomoo/gopherbook.git
cd gopherbook
./scripts-bash/run-gb-container/run-docker.sh
```

Then open http://localhost:12010 in your browser.

### First launch
1. On first run there are no users → registration is open
2. Create the first account → this user automatically becomes admin
3. Log in → start uploading CBZ/CBT/CB7/EPUB files

## Directory layout after first login
```
./library/username/                <- your comics (organized or Unorganized/)
./cache/covers/username/           <- generated cover thumbnails
./watch/username/                  <- watch folder for bulk imports (auto-scanned)
./etc/gopherbook.db                <- unified bbolt database (users, comics, tags, passwords, collections)
```

For AppImage installs, data is stored in:
```
~/.config/gopherbook/library/        <- your comics
~/.config/gopherbook/covers/         <- generated cover thumbnails
~/.config/gopherbook/watch/          <- watch folder
~/.config/gopherbook/etc/            <- database
~/.config/gopherbook/gopherbook.conf <- config file (edit to change port or paths)
```

## Environment Variables
Can be used to configure storage locations and server settings:
```
GOPHERBOOK_LIBRARY=$HOME/.config/gopherbook/library
GOPHERBOOK_CACHE=$HOME/.config/gopherbook/covers
GOPHERBOOK_ETC=$HOME/.config/gopherbook/etc
GOPHERBOOK_WATCH=$HOME/.config/gopherbook/watch
GBKPORT=8112                                           # Set the port the server listens on (default: 8080)
```

## Supported Formats

| Format | Extension | Encryption | Metadata (ComicInfo.xml) | Notes |
|--------|-----------|------------|--------------------------|-------|
| CBZ    | `.cbz`    | AES-256 (yeka/zip) | ✅ | Standard ZIP-based format |
| CBT    | `.cbt`    | AES-256-CFB (OpenSSL-compatible) | ✅ | TAR-based format |
| CB7    | `.cb7`    | AES-256 (7-Zip) | ✅ | 7-Zip-based; supports LZMA, LZMA2, header encryption |
| EPUB   | `.epub`   | AES-256-GCM | ✅ OPF metadata | EPUB 3-based; spine-ordered pages; structural files always plaintext |

### Page image formats

| Format | Extensions | Covers | Web reader | Desktop | Animation |
|--------|------------|--------|------------|---------|-----------|
| JPEG | `.jpg` `.jpeg` | ✅ | ✅ | ✅ | — |
| PNG / APNG | `.png` `.apng` | ✅ | ✅ | ✅ | ✅ APNG |
| GIF | `.gif` | ✅ | ✅ | ✅ | ✅ |
| WebP | `.webp` | ✅ | ✅ | ✅ | still images |
| BMP | `.bmp` | ✅ | ✅ | ✅ | — |
| JPEG XL | `.jxl` | ✅ | ✅ converted to PNG/APNG unless the browser supports JPEG XL | ✅ | ✅ |
| JPEG 2000 | `.jp2` `.j2k` `.j2c` `.jpf` `.jpx` | ✅ | ✅ converted to PNG | ✅ | — |
| AVIF | `.avif` | ❌ | ✅ (the browser decodes it) | ❌ | — |

Format conversions for the web reader happen in memory only; pages from password-protected comics are never written to disk.

**AVIF was replaced by JPEG XL.** Gopherbook no longer bundles an AVIF decoder: it was the only C dependency, and dropping it made the server a pure-Go static binary. AVIF pages are still listed and display in browsers, which decode AVIF themselves, but they get no cover and the desktop app can't show them.

**Not supported:** colour management from embedded ICC profiles (JPEG XL and JPEG 2000 pages are treated as sRGB, so CMYK pages show inaccurate colours), animated WebP (shows its first frame).

## Watch folder for bulk imports

Gopherbook includes an automatic watch folder system that makes bulk importing comics effortless:

- **Per-user watch folders**: Each user gets their own watch folder at `./watch/[username]/`
- **Automatic scanning**: The system checks for new CBZ/CBT/CB7/EPUB files every 10 seconds
- **Smart debouncing**: Waits 5 seconds after detecting files to ensure they're fully copied
- **File validation**: Checks that files aren't still being written before importing
- **Duplicate handling**: Automatically renames files if they already exist (adds _1, _2, etc.)
- **Zero configuration**: Just drop CBZ/CBT/CB7/EPUB files into your watch folder under your user name and they appear in your library

### How to use

1. After logging in, your personal watch folder is at `./watch/[yourusername]/`
2. Copy or move CBZ/CBT/CB7/EPUB files into this folder using any method:
   - Direct file copy/paste
   - SCP/SFTP upload
   - Network share mount
   - Automated scripts
3. Within ~15 seconds, files are automatically imported to your library
4. Files are **moved** (not copied) to preserve disk space
5. Check the API endpoint `/api/watch-folder` to see pending files

**Example workflow:**
```bash
# Bulk copy comics to your watch folder
cp ~/Downloads/*.cbz ./watch/myusername/
cp ~/Downloads/*.cbt ./watch/myusername/
cp ~/Downloads/*.cb7 ./watch/myusername/
cp ~/Downloads/*.epub ./watch/myusername/

# Wait ~15 seconds, then check your library in the web UI
# All comics will be imported and organized automatically
```

## How encrypted/password-protected comics work

- When you upload or scan an encrypted CBZ/CBT/CB7/EPUB that has no known password yet, the server marks it as Encrypted = true.
- When you open it, Gopherbook first tries all previously successful passwords automatically.
- If none work, a password prompt appears.
- If the password is correct, Gopherbook:
  - Stores the password (encrypted with a key derived from your login password)
  - Extracts metadata (ComicInfo.xml for CBZ/CBT/CB7; OPF for EPUB)
  - Auto-organizes the file into Artist/StoryArc folders
  - Updates tags and cover cache
- From then on the comic opens instantly, and that password is automatically tried on every future encrypted comic you upload (so whole collections that share one password "just work").

### CB7 encryption notes

CB7 archives support two modes of encryption:

- **Content encryption** (default `-p` flag): file headers are readable but content is encrypted. Wrong passwords produce a decompression error.
- **Header encryption** (`-mhe=on`): the entire archive including the file list is encrypted. Gopherbook detects this automatically and prompts for a password before listing pages.

In both cases, Gopherbook validates passwords by extracting a file and verifying its CRC32 checksum against the value stored in the archive header, which correctly handles store-only (uncompressed) encrypted archives where wrong passwords otherwise produce silent garbage output.

### EPUB encryption notes

EPUB archives use AES-256-GCM encryption applied only to image files inside `OEBPS/images/`. Structural files (`content.opf`, navigation documents, XHTML pages) are always stored unencrypted, which means:

- Metadata (title, creator, series, etc.) is always readable without a password
- Gopherbook can show cover placeholders and library entries for encrypted EPUBs before any password is entered
- Password validation uses a SHA-256 verify hash stored in `META-INF/key-hint.txt`, giving an instant correct/wrong response without needing to decrypt a full image

## Security notes

- Passwords are stored encrypted on disk using AES-256-CFB with a key derived from your login password via SHA-256.
- Session cookie is HttpOnly, expires after 24 h.
- No external dependencies that phone home.
- Still: treat this as a personal/private server – do not expose it publicly without HTTPS/reverse-proxy auth.

## Config for NGINX to use as a website:
```
upstream gopherbook {
        server 127.0.0.1:8080;
        #server 127.0.0.1:12010; #For Podman instead
        server [::1]:8080;
        #server [::1]:12010; #For Podman instead
}
server {
        listen 80;
        listen [::1]:80;
        server_name gopherbook.example.com;
        location / {
                proxy_pass http://gopherbook;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
                # 1. Allow very large uploads (e.g. 500 MB – adjust as needed)
                client_max_body_size 500M;          # 0 = unlimited, but never do that on a public server

                # 2. Give the upload enough time (important for slow connections)
                client_body_timeout 5m;             # time to read the entire request body (default 60s)
                proxy_read_timeout 5m;              # if you're proxying to your Go app
                proxy_send_timeout 5m;

                # 3. Increase buffer sizes so Nginx doesn't spill everything to disk
                client_body_buffer_size 512k;       # default 8k/16k – too small for big uploads
                proxy_buffers 8 512k;
                proxy_buffer_size 256k;

                # 4. Recommended: put uploads in a temporary directory with plenty of space
                client_body_temp_path /var/lib/nginx/body 1 2;   # make sure this directory exists and is writable by nginx
        }
}
```

## Contributing

Pull requests are welcome! Especially:
- Better mobile reader experience
- Bulk tag editing
- Search box

Please open an issue first for bigger changes.

## If you'd like to know about the new mascot Vinny

- Check the Wiki!
- **GitHub**: https://github.com/riomoo/gopherbook/wiki/Meet-Vinny
- **GitGud**: https://gitgud.io/riomoo/gopherbook/-/wikis/Meet-Vinny
- **JesterDesigns**: https://git.jester-designs.com/riomoo/gopherbook/wiki/Meet-Vinny


## Thanks / Credits

- yeka/zip – password-protected ZIP support in pure Go
- bodgit/sevenzip – 7-Zip archive support in pure Go
- kulaginds/lzma – LZMA (v1) decompressor for 7-Zip archives (LGPL-3.0)
- gioui.org (Gio) – GUI toolkit for the native desktop version
- gen2brain/jxl – pure-Go JPEG XL decoder
- seehuhn.de/go/jpx – pure-Go JPEG 2000 decoder
- go.etcd.io/bbolt – the embedded database
- The ComicRack ComicInfo.xml standard
- The EPUB 3 specification (IDPF / W3C)
- Everyone who hoards comics ❤️

Enjoy your library!  
– Happy reading with Gopherbook

<div align="center">

## Software Used but not included

![Arch](https://img.shields.io/badge/Arch%20Linux-1793D1?logo=arch-linux&logoColor=fff&style=for-the-badge)
![Gimp Gnu Image Manipulation Program](https://img.shields.io/badge/Gimp-657D8B?style=for-the-badge&logo=gimp&logoColor=FFFFFF)
![Podman](https://img.shields.io/badge/-Podman-892CA0?style=flat-square&logo=podman&logoColor=white)
![Vim](https://img.shields.io/badge/VIM-%2311AB00.svg?style=for-the-badge&logo=vim&logoColor=white)
![Git](https://img.shields.io/badge/git-%23F05033.svg?style=for-the-badge&logo=git&logoColor=white)
![Forgejo](https://img.shields.io/badge/forgejo-%23FB923C.svg?style=for-the-badge&logo=forgejo&logoColor=white)

</div>

## Creator:
- [Codeberg Riomoo](https://codeberg.org/riomoo)
- [GitGud Riomoo](https://gitgud.io/riomoo)
- [Github Riomoo](https://github.com/riomoo)
