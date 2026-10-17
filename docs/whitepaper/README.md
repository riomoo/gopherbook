# Gopherbook: Technical Whitepaper

**Version 3.x | Self-Hosted Comic Library and Reader**

---

## Table of Contents

1. [Overview](#overview)
2. [Design Goals](#design-goals)
3. [Architecture](#architecture)
4. [Build Targets](#build-targets)
5. [Supported File Formats](#supported-file-formats)
6. [Encryption and Password Management](#encryption-and-password-management)
7. [Metadata Extraction](#metadata-extraction)
8. [Library Organization](#library-organization)
9. [Cover Generation](#cover-generation)
10. [Database Layer](#database-layer)
11. [API Reference](#api-reference)
12. [Authentication and Sessions](#authentication-and-sessions)
13. [Sharing System](#sharing-system)
14. [Collections and Tagging](#collections-and-tagging)
15. [Watch Folder System](#watch-folder-system)
16. [Reader Features](#reader-features)
17. [Desktop Build](#desktop-build)
18. [Memory Management](#memory-management)
19. [Deployment](#deployment)
20. [Security Considerations](#security-considerations)
21. [Configuration Reference](#configuration-reference)

---

## Overview

Gopherbook is a self-hosted comic library manager and reader written entirely in Go. It ships as a single compiled binary with no runtime dependencies. All HTML, CSS, JavaScript, images, and templates are embedded directly into the binary at compile time using Go's `embed` package, so there is nothing to install beyond the binary itself.

It comes in two flavors: a server build that serves a web interface over HTTP, and a desktop build that spins up the same HTTP server internally and wraps it in a native Fyne window. Both builds compile from the same codebase, with build tags controlling which `main` function is used and which GUI code is included.

The project targets people who want to self-host their comic collection without depending on cloud services, Electron apps, or fragile Python environments. The whole thing stays on your machine. Passwords never leave it unencrypted.

---

## Design Goals

A few things were non-negotiable from the start:

**Single binary.** No "install Go, install Node, install Postgres" setup. You run one file. The database, the web server, the static assets, all of it is in that one file.

**No external runtime dependencies.** All third-party libraries are compiled in. The binary runs on a clean system with nothing else installed.

**Real encryption support.** CBZ/CBT/CB7/EPUB files can be password-protected and Gopherbook handles them properly, including trying known passwords automatically, storing discovered passwords securely, and extracting metadata without requiring a password re-entry every time.

**Per-user isolation.** Each user gets their own library, their own password vault, their own tags. One user cannot see or touch another user's comics.

**Practical performance.** Cover generation runs concurrently but is capped so it cannot exhaust memory on large libraries. Page indexes are cached after the first read so navigating a 500-page comic does not re-scan the archive on every page turn.

---

## Architecture

The server is a standard Go `net/http` server. There is no framework. Routes are registered directly against the default `http.ServeMux` using `http.HandleFunc`. All handlers are plain functions that read from request bodies, write JSON or binary responses, and share state through a small set of global maps protected by `sync.RWMutex`.

The state model is straightforward: users, comics, sessions, tags, passwords, share links, categories, and watch folder timers are all in-memory maps. On startup they are loaded from the bbolt database. On write they are saved back to bbolt, usually via a debounced five-second timer to avoid hammering the disk on rapid sequential changes.

```
Request
  -> authMiddleware (session cookie check)
  -> handler function
  -> reads/writes in-memory maps (mutex-protected)
  -> debounceSave() schedules a db write in 5 seconds
```

The static frontend is a single `index.html` file with inline CSS and JavaScript. It is embedded via `//go:embed templates/index.html` and served from `serveUI`. Static assets (images, favicons) are embedded under `//go:embed all:static` and served at `/static/`.

The entire frontend talks to the backend through a JSON REST API. The reader itself is just JavaScript fetching images from `/api/comic/<id>/page/<n>` and swapping the `src` on an `<img>` element. No WebSockets, no server-sent events, no build pipeline.

---

## Build Targets

There are four shipped binaries and two build modes.

### Server build

```bash
go build -o gopherbook ./app/gopherbook
```

No build tags. Uses `main_server.go` as the entry point. Listens on `:8080` by default (overridable with `GBKPORT`). Suitable for running on a Linux server, in a container, or on Windows.

### Desktop build

```bash
go build -tags desktop -o gopherbook-desktop ./app/gopherbook
```

Uses `desktop_main.go` as the entry point. Starts the HTTP server on a random loopback port chosen by the OS (`127.0.0.1:0`), then opens a Fyne window that serves as the UI. The window talks to the embedded server over localhost HTTP just like a browser would, but without requiring a browser.

The `//go:build desktop` tag gates several files: `desktop_main.go`, `desktop_webview.go`, `desktop_theme.go`, and `desktop_helpers.go`. Files with `//go:build !desktop` (like `main_server.go`) are excluded from desktop builds.

### Binary matrix

| File | OS | Libc |
|------|----|------|
| `gopherbook-*-linux-x86_64.tar.gz` | Linux | glibc |
| `gopherbook-*-windows-amd64.zip` | Windows | n/a |
| `gopherbook-*-desktop-linux-glibc-x86_64.tar.gz` | Linux | glibc 2.28+ |
| `gopherbook-*-desktop-linux-musl-x86_64.tar.gz` | Linux | musl |
| `gopherbook-*-desktop-windows-amd64.zip` | Windows | n/a |

The musl desktop build requires `musl_compat.go`, which provides stub implementations of glibc security-checked memory functions (`__memcpy_chk`, `__memset_chk`, etc.) that some C libraries call but musl does not export. This file is compiled unconditionally on Linux via a `//go:build linux` tag and uses CGo to define those stubs.

---

## Supported File Formats

### CBZ (Comic Book ZIP)

CBZ files are standard ZIP archives containing image files. Gopherbook uses the `github.com/yeka/zip` library (a fork of `archive/zip`) which adds AES-256 password support compatible with the WinZip encryption scheme.

On upload, the archive is opened and checked for any encrypted entries. If any file inside the ZIP has `IsEncrypted() == true`, the comic is marked `Encrypted: true`. Metadata is extracted immediately for unencrypted files. For encrypted files, metadata extraction is deferred until a password is supplied.

Page ordering is done by sorting filenames alphabetically within the archive. The sorted list is cached in `pageIndexCache` after the first read. Subsequent page requests look up the target filename by index and seek directly to it in the ZIP.

### CBT (Comic Book TAR)

CBT files are TAR archives. Gopherbook supports both unencrypted TAR files and a custom AES-256-CFB encryption scheme compatible with OpenSSL's `enc` command.

Encryption detection reads the first 512 bytes of the file (one TAR header block) and tries to parse a valid TAR header from them. If parsing fails, the file is assumed to be encrypted. Encrypted CBT files must be fully read into memory and decrypted before any content can be accessed, because TAR is a streaming format without a central directory.

Password validation for CBT files decrypts the file and checks that the resulting bytes can be parsed as a valid TAR header.

The encryption key is derived using `SHA-256(password)`, producing a 32-byte key. The IV is extracted from the first 16 bytes of the ciphertext (OpenSSL `enc -aes-256-cfb` format).

### CB7 (Comic Book 7-Zip)

CB7 files are 7-Zip archives. Gopherbook uses `github.com/bodgit/sevenzip` for 7-Zip support, with `github.com/kulaginds/lzma` registered as a decompressor for LZMA v1 archives (bodgit/sevenzip ships LZMA2 natively but needs an external LZMA v1 provider).

7-Zip supports two encryption modes. Content encryption (the `-p` flag) leaves file headers readable but encrypts the data. Header encryption (`-mhe=on`) encrypts everything including the file list. Gopherbook detects header encryption by attempting to open the archive without a password: if that fails, it tries again with a dummy password; if that succeeds, it confirms header encryption is present.

Password validation for CB7 files is done by decrypting a file and verifying its CRC32 checksum against the value stored in the archive's central directory. This is necessary because 7-Zip with store mode (no compression, just encryption) produces valid-looking output even with a wrong password; only the CRC check reveals that the decrypted bytes are garbage.

Per-file mutexes (`cb7Mutexes sync.Map`) serialize concurrent access to the same CB7 file because the LZMA range decoder in bodgit/sevenzip is not goroutine-safe.

### EPUB

EPUB files are ZIP archives following the EPUB 3 specification. The internal structure is:

```
META-INF/
  container.xml         <- points to the OPF file
  encryption.xml        <- present only in encrypted EPUBs; lists encrypted entries
  key-hint.txt          <- present in encrypted EPUBs; contains the verify hash
OEBPS/
  content.opf           <- package metadata and spine (always plaintext)
  nav.xhtml             <- navigation document (always plaintext)
  images/               <- image files (encrypted per-file in encrypted EPUBs)
  pages/                <- XHTML page wrappers (always plaintext)
```

Gopherbook uses a custom AES-256-GCM encryption scheme for EPUBs. Only the image files under `OEBPS/images/` are encrypted. All structural files remain plaintext. This means metadata is always readable even without a password, which is the same behavior you get with unencrypted EPUBs.

The key derivation function is a double SHA-256 with a fixed prefix:

```
key = SHA-256(SHA-256("epub-comic-key-v1:" + password) + password)
```

Each encrypted image has a 12-byte random nonce prepended to the ciphertext. The GCM authentication tag (16 bytes) is appended by the cipher itself as part of `gcm.Seal`.

Password validation uses `META-INF/key-hint.txt`, which contains a base64-encoded SHA-256 hash of `"verify:" + password`. This gives an immediate correct/wrong answer without decrypting any image data. For older files that predate the key-hint format, validation falls back to decrypting the first image and checking that GCM authentication succeeds.

Page ordering reads the spine from `OEBPS/content.opf`. The OPF manifest lists image items with their `media-type` attributes; Gopherbook extracts these in document order, which matches the order images were written by the builder tool. If OPF parsing fails, it falls back to sorting `OEBPS/images/*` alphabetically.

---

## Encryption and Password Management

### Password storage

Discovered passwords are stored in bbolt in a per-user `passwords:<username>` bucket. They are never written to disk in plaintext. Before writing, the entire `comicPasswords` map is serialized to JSON, encrypted with AES-256-CFB using a key derived from the user's login password, base64-encoded, and stored as a single value under the key `"encrypted"`.

The encryption key is derived at login time:

```
encryptionKey = SHA-256(loginPassword)
```

This means passwords are only decryptable by someone who knows the user's login password. They are not recoverable from the database file alone.

### Automatic password trying

When a user opens an encrypted comic that does not yet have a password, Gopherbook collects all currently known passwords from `comicPasswords` (deduplicated) and tries each one against the new comic using the format-appropriate validation function. This happens before any password prompt is shown.

If any known password works, it is silently applied, metadata is extracted, the comic is auto-organized, and the reader opens. If none work, the password prompt appears.

This behavior means that a collection of comics all protected by the same password only requires entering that password once.

### Password application

When a correct password is confirmed (either found automatically or entered manually), `applyPasswordToComic` runs:

1. Stores the password in the in-memory `comicPasswords` map.
2. Extracts metadata from the archive using the password.
3. Injects the artist name as a lowercase tag.
4. Auto-organizes the file into `Library/Artist/StoryArc/`.
5. Persists everything to bbolt.
6. Rebuilds tag counts.

---

## Metadata Extraction

### ComicInfo.xml (CBZ, CBT, CB7)

The standard ComicInfo.xml schema originated with ComicRack and is widely supported by comic creation tools. Gopherbook maps the following fields:

| XML field | Comic struct field |
|-----------|--------------------|
| `Title` | `Title` |
| `Series` | `Series` |
| `StoryArc` | `StoryArc` |
| `Number` | `Number` |
| `Writer` or `Artist` | `Artist` |
| `Publisher` | `Publisher` |
| `Year` | `Year` |
| `PageCount` | `PageCount` |
| `Tags` or `Genre` | `Tags` |

Tags are split on commas, semicolons, and pipes. Whitespace is trimmed from each value.

### OPF metadata (EPUB)

EPUB 3 packages store metadata in `OEBPS/content.opf` using Dublin Core elements and OPF-specific meta elements. Gopherbook extracts:

| OPF element | Comic struct field |
|-------------|--------------------|
| `dc:title` | `Title` |
| `dc:creator` | `Artist` |
| `meta name="calibre:series"` | `Series` |
| `meta name="calibre:series_index"` | `Number` |
| `meta property="belongs-to-collection"` | `StoryArc` |
| `dc:date` (first 4 chars) | `Year` |
| `dc:subject` (one per element) | `Tags` |

OPF parsing is done with a lightweight string scan rather than a full XML parser, which keeps the code dependency-free and avoids the overhead of `encoding/xml` for a file that is typically a few kilobytes.

### Artist tag injection

After metadata is resolved, `injectArtistTag` runs unconditionally. It takes the `Artist` field, lowercases it, and adds it to the comic's tag list if not already present. This ensures the tag system always reflects the full artist roster without manual effort.

### Lazy loading

For large libraries, scanning every archive on startup would be slow. Gopherbook only does encryption detection at import time. Metadata is extracted eagerly for unencrypted files because that is cheap (reading a small XML file from a local disk archive). For encrypted files, metadata extraction is deferred to `loadComicMetadataLazy`, which runs on the first page load of each comic. Once extracted, the metadata is persisted so it is not re-extracted on subsequent loads.

---

## Library Organization

When metadata is available, Gopherbook automatically moves the comic file into a structured directory tree:

```
library/<username>/<Artist>/<StoryArc>/<filename>
```

Artist and StoryArc values are sanitized before use as directory names: spaces become underscores, any character outside `[a-zA-Z0-9-_]` is replaced with an underscore, and leading/trailing underscores are trimmed. An empty result falls back to `"Unknown"` or `"No_StoryArc"`.

Comics without metadata land in `library/<username>/Unorganized/` and stay there until a password is supplied (for encrypted files) or the file is rescanned with different metadata.

The directory structure also serves as a fallback for the artist name. If a comic has no `Artist` field in its metadata but lives in a structured path, the grandparent directory name is used as the artist:

```
library/user/ArtistName/StoryArc/comic.cbz
                ^
                used as Artist if metadata has none
```

---

## Cover Generation

Cover thumbnails are generated on demand, the first time `/api/cover/<id>` is requested for a comic whose cache file does not exist. Generated thumbnails are JPEG files stored in `cache/covers/<username>/<id>.jpg` at a maximum dimension of 300 pixels (preserving aspect ratio).

A buffered channel `coverGenSemaphore` limits concurrent cover generation to `min(NumCPU, 4)` goroutines. This prevents memory exhaustion when many covers are requested simultaneously (for example, on first library load).

For images larger than 20 megapixels or 30MB uncompressed, Gopherbook uses a multi-pass resize strategy: a fast nearest-neighbor pass reduces the image to 3x the target size, followed by a Lanczos3 pass to the final size. For very large reductions (ratio > 100), nearest-neighbor is used for both passes. For moderate reductions, Bilinear is used first.

After cover generation, `debug.SetGCPercent(10)` is restored and `runtime.GC()` plus `debug.FreeOSMemory()` are called explicitly to return memory to the OS. High-resolution comic scans can be 30-100MB per page; without this the Go runtime would hold onto that memory indefinitely.

### Category collage covers

Categories can have a generated cover that shows a 2x2 grid of the first four comic covers inside the category. If a category has only one comic, the cover is shown at full size. The collage is generated at 150x210 pixels per tile using `resize.Thumbnail` with Lanczos3.

Custom covers can also be uploaded for a category via `/api/category/upload-cover/<id>`. Uploaded covers replace the generated collage and are stored as `cache/covers/<username>/cat_custom_<id>.<ext>`.

---

## Database Layer

Gopherbook uses bbolt (formerly boltdb), an embedded key-value store backed by a memory-mapped file. There are no external database processes. The database file lives at `etc/gopherbooks.db`.

The bucket structure uses per-user namespacing:

```
config                      <- top-level config (users map, admin settings)
comics:<username>           <- one key per comic, value is JSON-encoded Comic struct
tags:<username>             <- one key per tag name, value is JSON-encoded Tag struct
passwords:<username>        <- single key "encrypted", value is AES-encrypted JSON blob
shares:<username>           <- one key per share link ID
categories:<username>       <- one key per category ID
```

User data is completely separated at the bucket level. There is no way for one user's data to appear in another user's queries because all reads and writes target the bucket for the current user.

### Write strategy

Most writes go through `debounceSave`, which sets a five-second `time.AfterFunc` timer. If another write happens before the timer fires, the old timer is stopped and a new one is set. This means rapid sequential changes (tagging, bookmarking, etc.) result in a single write to disk rather than one per action.

Passwords are always saved immediately via `savePasswords` because they represent security-critical state that must survive a crash.

### Reads at startup

On startup (via `initCore`), only the config bucket is read immediately. Per-user data (comics, tags, passwords, categories) is loaded during login via `loadComics`, `loadTags`, `loadPasswordsWithKey`, and `loadCategories`. This keeps startup fast regardless of library size.

---

## API Reference

All `/api/*` endpoints (except `/api/register`, `/api/login`, `/api/share/unlock/`, and `/s/`) require a valid session cookie named `session`.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/register` | Create a new user account |
| POST | `/api/login` | Log in, receive session cookie |
| POST | `/api/logout` | Invalidate session cookie |
| GET | `/api/user` | Get current username and admin status |

### Library

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/comics` | List all comics for the current user |
| POST | `/api/upload` | Upload a CBZ/CBT/CB7/EPUB file |
| DELETE | `/api/delete-comic/<id>` | Delete a comic (any authenticated user) |
| DELETE | `/api/admin/delete-comic/<id>` | Delete a comic (admin only) |
| GET | `/api/cover/<id>` | Get or generate the cover thumbnail |
| GET | `/api/pages/<id>` | Get page count for a comic |
| GET | `/api/comic/<id>/page/<n>` | Get a single page image |

### Passwords

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/set-password/<id>` | Set and validate a password for an encrypted comic |
| POST | `/api/try-passwords/<id>` | Try all known passwords against an encrypted comic |

### Tags

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/tags` | List all tags with counts and colors |
| POST | `/api/tags` | Create a new tag |
| POST | `/api/comic-tags/<id>` | Add a tag to a comic |
| DELETE | `/api/comic-tags/<id>/<tag>` | Remove a tag from a comic |

### Bookmarks

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/bookmark/<id>` | Add a bookmark (body: `{"page": N}`) |
| DELETE | `/api/bookmark/<id>/<page>` | Remove a bookmark |

### Sharing

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/share/create/<id>` | Create a share link for a comic |
| GET | `/api/share/list` | List all active share links |
| DELETE | `/api/share/delete/<token>` | Delete a share link |
| POST | `/api/share/unlock/<token>` | Unlock a password-protected share link |
| GET | `/s/<token>` | Access a shared comic (public, no auth required) |

### Categories

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/categories` | List all categories |
| POST | `/api/category/create` | Create a category |
| PUT | `/api/category/update/<id>` | Update name or comic list |
| DELETE | `/api/category/delete/<id>` | Delete a category |
| GET | `/api/category/cover/<id>` | Get or generate the category cover |
| POST | `/api/category/upload-cover/<id>` | Upload a custom category cover |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/admin/toggle-registration` | Get or toggle whether new registration is allowed |
| GET | `/api/watch-folder` | Get the current user's watch folder path and file list |

---

## Authentication and Sessions

Sessions are stored in the in-memory `sessions` map as `map[string]Session`, where the key is a random token and the value holds the username and expiry time. Tokens are generated by SHA-256 hashing the current nanosecond timestamp and base64 URL-encoding the result.

Session cookies are set with `HttpOnly: true` and expire after 24 hours. A background goroutine (`cleanupSessions`) runs every five minutes and removes expired sessions.

The `authMiddleware` wrapper checks for the `session` cookie, looks up the token in the sessions map, verifies the expiry time, and calls the next handler if valid. Failed checks return HTTP 401.

The first user to register automatically becomes the admin (`IsAdmin: true`). The admin can toggle whether new registrations are accepted. When registration is disabled, the `/api/register` endpoint returns HTTP 403.

---

## Sharing System

Share links allow a comic to be shared publicly without requiring the viewer to create an account. A share link is a `ShareLink` struct persisted in the `shares:<username>` bucket and served at `/s/<token>`.

Share links can be permanent or time-limited. Time-limited links include an `ExpiresAt` timestamp; expired links are removed by `cleanupExpiredShareLinks`, which runs every 10 minutes.

### Share-level passwords

Share links for encrypted comics can optionally have their own password, separate from the comic's encryption password. When a share password is set:

1. The share password is hashed with bcrypt and stored in `SharePasswordHash`.
2. The comic's encryption password is encrypted with AES-256-CFB using a key derived from the share password, and stored in `EncryptedComicPassword`.

When a viewer accesses the share link, they see a password gate. On correct entry, `/api/share/unlock/<token>` verifies the bcrypt hash, decrypts the comic password, and stores both in a temporary `shareUnlockSession` keyed by `token + ":" + nonce`. A cookie named `sul_<safeToken>` is set, scoped to the `/s/<token>` path, so subsequent page requests can retrieve the decrypted comic password.

This design means the comic's encryption password is never stored in plaintext anywhere on disk, even as part of the share link data.

### Share reader

The share reader at `/s/<token>` is a self-contained HTML page with no dependency on the authenticated frontend. It fetches page count from `/s/<token>/pages` and individual pages from `/s/<token>/page/<n>`. It supports zoom, pan, keyboard navigation, and fit-to-width/height, identical to the authenticated reader.

---

## Collections and Tagging

### Tags

Tags are stored globally per user with a name, a hex color string, and a count. The count reflects how many comics in the current library carry that tag. Counts are rebuilt from scratch by `rebuildTagCounts` whenever the comic set changes, which prevents count drift from partial updates.

Tags are added to comics either manually through the tag manager UI (which calls `/api/comic-tags/<id>`) or automatically by `injectArtistTag` during metadata extraction. The artist tag is always lowercase.

The library UI supports multi-tag filtering with AND semantics: selecting two tags shows only comics that have both of them.

### Collections

Collections (called "categories" in the API and code) are named groups of comics. A category stores a list of comic IDs. Comics can belong to multiple categories. Categories are not used for library organization (that is the `Artist/StoryArc` folder structure); they are purely a grouping tool for the UI.

---

## Watch Folder System

Each user gets a watch folder at `watch/<username>/`. Gopherbook polls this directory every 10 seconds using a `time.NewTicker`. When the directory's `mtime` changes (indicating a new file was dropped in), a debounced five-second timer fires `importWatchFolderFiles`.

Before importing, each file is stat'd twice with a 500ms gap. If the size changed between the two reads, the file is skipped (it is still being written). This prevents importing partially-written archives.

Files are moved (not copied) from the watch folder to `library/<username>/Unorganized/`. If a filename collision occurs, a numeric suffix is added: `comic_1.cbz`, `comic_2.cbz`, etc.

After moving, `processComic` runs immediately on the new file, which handles encryption detection, metadata extraction, tag registration, and cover pre-loading.

The watch folder only processes files for the currently logged-in user. If nobody is logged in, files accumulate in the watch folder and are imported on next login.

---

## Reader Features

The web reader is entirely client-side JavaScript that manipulates a single `<img>` element. There is no video, no canvas, no WebGL. This keeps it fast and compatible with basically everything.

### Fit modes

Three fit modes are supported via CSS class swapping on the image container:

- `fit-width`: image width matches the container width, height is unconstrained (scroll vertically)
- `fit-height`: image height matches the container height, width is unconstrained
- `fit-page`: image is constrained to both dimensions, showing the whole page at once

### Zoom and pan

Zoom is applied via CSS `transform: scale(N)`. Pan offsets are tracked in JavaScript and applied as `translate(X, Y)` within the same transform. The pan origin is divided by the zoom factor to keep the coordinate system consistent at all zoom levels.

Mouse and touch events are both supported. Touch pan requires calling `preventDefault()` on `touchmove` to stop the browser from scrolling the page while the reader is panning.

Keyboard shortcuts: arrow keys and A/D for page navigation, `+`/`-` for zoom, `0` to reset zoom, `Escape` to close the reader.

### Bookmarks

Bookmarks are stored as a sorted array of page numbers on the `Comic` struct. They are persisted to bbolt immediately on add or remove. The bookmark list panel shows all bookmarked pages and lets you jump to any of them or delete individual bookmarks.

A bookmark badge on the library grid card shows the bookmark count for each comic. Clicking the badge opens the reader directly at the first bookmark.

### Page pre-fetching

The reader does not pre-fetch pages. Each page is fetched on demand when navigation occurs. This is intentional: pre-fetching would waste bandwidth for large high-resolution archives, and the network round-trip to a local server is typically under a millisecond.

---

## Desktop Build

The desktop build uses the Fyne GUI toolkit (`fyne.io/fyne/v2`) to create a native window. Fyne handles platform-specific window management, file dialogs, and widget rendering.

The desktop main function starts the HTTP server, waits for it to signal readiness over a channel, then creates the Fyne app and window. The window is sized to 1280x820 on creation.

```go
ln, err := net.Listen("tcp", "127.0.0.1:0")
port := ln.Addr().(*net.TCPAddr).Port
baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
```

Using port 0 lets the OS pick an available port, which avoids conflicts if multiple instances are run or if the port is already in use.

The UI inside the Fyne window (`WebViewWidget`) is a custom Fyne widget that manages its own `*fyne.Container` and swaps content between login, library, and reader views. It proxies all API calls to the embedded server over HTTP using `http.DefaultClient`. This is the same server the browser version uses, so all features are available in both modes.

### Desktop theme

The desktop build applies a custom Fyne theme (`GopherbookTheme`) that matches the dark color palette of the web frontend:

| Role | Color |
|------|-------|
| Background | `#1b1e2c` |
| Card background | `#252836` |
| Header / button | `#395E62` |
| Accent | `#446B6E` |
| Accent light | `#64A9AD` |
| Body text | `#bfbcb7` |
| Dim text | `#8b949e` |
| Border | `#314C52` |
| Error | `#A55354` |

### File upload dialog

The desktop file picker uses Fyne's `dialog.NewFileOpen` with an extension filter set to `.cbz`, `.cbt`, `.cb7`, and `.epub`. The last-used directory is remembered in `lastUploadDir` so reopening the dialog starts in the same place.

Uploads stream directly from disk to the server using a `multipart.Writer` and `io.Pipe`, so large files do not need to be fully buffered in memory.

### Library grid focus handling

The library search entry is the trickiest part of the desktop widget. Rebuilding the entire library layout (to re-filter results) would destroy the search entry widget and lose keyboard focus. To avoid this, the stable parts of the layout (search entry, header, filter bars) are built once, and only the comics grid and pagination are rebuilt into `libraryGrid` and `libraryPagination` containers. `renderLibraryGrid` replaces the `Objects` slice of these containers and calls `Refresh` on them, which redraws without touching the search entry or its focus state.

---

## Memory Management

Gopherbook takes memory seriously because comic cover images can be very large. The key practices:

**Aggressive GC during image operations.** `debug.SetGCPercent(10)` is set before any image decode/resize operation and restored after. This causes GC to run much more frequently, at the cost of CPU, but prevents large image buffers from accumulating.

**Explicit GC and memory release.** After every cover generation call, `runtime.GC()` and `debug.FreeOSMemory()` are called. `FreeOSMemory` triggers `madvise(MADV_FREE)` or equivalent to return freed pages to the OS immediately rather than holding them in the Go heap for future allocations.

**Nil after use.** Large image objects are explicitly set to `nil` after resize operations so the GC can collect them before the next operation begins.

**Cover generation semaphore.** `coverGenSemaphore` is a buffered channel with a capacity of `min(NumCPU, 4)`. Each goroutine trying to generate a cover must send a token into the channel before starting and drain it when done. If all slots are full, the goroutine waits up to 30 seconds before giving up with a 503 response.

**Background GC.** A background goroutine calls `runtime.GC()` and `debug.FreeOSMemory()` every 30 seconds unconditionally, as a safety net for memory that was not explicitly freed.

---

## Deployment

### Standalone server

```bash
./gopherbook
# Listens on :8080 by default
```

Data is stored in the current working directory under `./library/`, `./cache/`, `./watch/`, and `./etc/`.

### Environment variable overrides

```
GOPHERBOOK_LIBRARY   path to the library root directory
GOPHERBOOK_CACHE     path to the cover cache directory
GOPHERBOOK_ETC       path to the etc directory (database lives here)
GOPHERBOOK_WATCH     path to the watch folder root
GBKPORT              port to listen on (default: 8080)
```

### Container

A `Containerfile` is provided for building OCI images. The image uses a multi-stage build to keep the final image small. `run-podman.sh` and `run-docker.sh` scripts in `scripts-bash/run-gb-container/` handle volume mounting and port mapping.

The container exposes port 12010 by default (the scripts map it to host port 12010).

### NGINX reverse proxy

When putting Gopherbook behind NGINX, set `client_max_body_size` to at least the size of your largest comic file (500MB is a reasonable default for most collections). Also increase `client_body_timeout` and `proxy_read_timeout` to handle slow uploads on poor connections.

```nginx
upstream gopherbook {
    server 127.0.0.1:8080;
}
server {
    listen 80;
    server_name gopherbook.example.com;
    location / {
        proxy_pass http://gopherbook;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        client_max_body_size 500M;
        client_body_timeout 5m;
        proxy_read_timeout 5m;
    }
}
```

Add TLS termination with certbot or your preferred CA. Do not expose Gopherbook on a public IP without TLS.

### AppImage

Linux AppImages bundle the binary and all Fyne dependencies into a single relocatable file. They do not require installation and run from anywhere in the filesystem. For AppImage installs, data is stored under `~/.config/gopherbook/` rather than the working directory.

---

## Security Considerations

**Password storage.** User login passwords are hashed with bcrypt at the default cost factor. Comic encryption passwords are stored AES-256-CFB encrypted on disk, keyed by a SHA-256 hash of the login password. Neither password type is ever stored in plaintext.

**Session tokens.** Session tokens are SHA-256 hashes of nanosecond timestamps, base64 URL-encoded. They are transmitted only via `HttpOnly` cookies. The 24-hour expiry is enforced both at login time and on every authenticated request.

**Share link isolation.** Share link cookies are scoped to `/s/<token>`, so they cannot be used to access other paths or other shares. The comic encryption password embedded in a share link is re-encrypted with a key derived from the share password, so it cannot be extracted from the database without knowing both the share password and the database access.

**No phone-home.** Gopherbook makes no outbound network connections. There is no telemetry, no update check, no CDN dependency. All assets are embedded in the binary.

**Local network assumption.** Gopherbook is designed for trusted local networks or reverse-proxy setups with proper TLS. It does not implement rate limiting, IP blocking, or brute-force protection on login. Do not expose the raw HTTP port to the internet.

**File deletion.** When a comic is deleted, the cover cache entry is removed and the source file is deleted from disk. Share links pointing to deleted comics are also removed. Page index cache entries are evicted to prevent stale data from being served.

---

## Configuration Reference

All configuration is done through environment variables. There is no config file for the server build. AppImage installs write a `gopherbook.conf` file to `~/.config/gopherbook/` but it uses the same variable names.

| Variable | Default | Description |
|----------|---------|-------------|
| `GOPHERBOOK_LIBRARY` | `./library` | Root directory for user library folders |
| `GOPHERBOOK_CACHE` | `./cache/covers` | Root directory for cover thumbnails |
| `GOPHERBOOK_ETC` | `./etc` | Directory containing `gopherbooks.db` |
| `GOPHERBOOK_WATCH` | `./watch` | Root directory for user watch folders |
| `GBKPORT` | `8080` | HTTP listen port (server build only) |

All paths are cleaned with `filepath.Clean` on load. Relative paths are resolved from the working directory at startup.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `go.etcd.io/bbolt` | Embedded key-value database |
| `github.com/yeka/zip` | AES-256 encrypted ZIP support (CBZ) |
| `github.com/bodgit/sevenzip` | 7-Zip archive support (CB7) |
| `github.com/kulaginds/lzma` | LZMA v1 decompressor for 7-Zip |
| `github.com/nfnt/resize` | Image resizing for cover thumbnails |
| `github.com/vegidio/avif-go` | AVIF image decode support |
| `golang.org/x/crypto/bcrypt` | Password hashing for user accounts |
| `fyne.io/fyne/v2` | Native desktop GUI (desktop build only) |

All dependencies are compiled into the binary. There are no shared libraries required at runtime beyond the system libc (glibc or musl on Linux, the standard DLLs on Windows).

---

*Gopherbook is developed by riomoo. Source is available on Codeberg, GitGud, and GitHub.*
