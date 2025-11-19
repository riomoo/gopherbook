# Gopherbook – Self-Hosted Comic Library & CBZ Reader

Gopherbook is a lightweight, single-binary, self-hosted web comic reader and library manager written in Go.  
It is designed for people who want full control over their digital comic collection (CBZ files), including support for password-protected/encrypted archives, per-user libraries, tagging, automatic organization, and a clean modern reader.

## License

[![Custom badge](https://img.shields.io/endpoint?style=for-the-badge&url=https%3A%2F%2Fshare.jester-designs.com%2Fview%2Fpil.json)](LICENSE)

## Features

- Upload & read `.cbz` (ZIP-based) comics directly in the browser
- Full support for password-protected/encrypted CBZ files (AES-256 via yeka/zip)
- Automatically tries all previously successful passwords when opening a new encrypted comic
- Persists discovered passwords securely (AES-encrypted on disk, key derived from your login password)
- Extracts ComicInfo.xml metadata (title, series, number, writer, inker, tags, story arc, etc.)
- Automatic folder organization: `Library/Artist/StoryArc/Comic.cbz`
- Manual reorganization via UI if needed
- Powerful tagging system with custom colors and counts
- Filter comics by any combination of tags
- Responsive grid view with cached JPEG covers
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
- No external database – everything stored in simple JSON files
- Single static Go binary + file storage – easy to deploy

## Installation / Running

### Prerequisites
[![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)](https://golang.org/dl/)
- Go 1.25.2+ (only needed to build)
- Or just download a pre-built binary from Releases (when available)

### Quick start (from source)

```bash
git clone https://codeberg.org/riomoo/gopherbook.git
cd gopherbook
go build -o gopherbook app/gopherbook/main.go
./gopherbook
```

Then open http://localhost:8080 in your browser.

## If you want to use this with podman:

```bash
git clone https://codeberg.org/riomoo/gopherbook.git
cd gopherbook
./bash-scripts/run.sh
```

Then open http://localhost:12010 in your browser.

### First launch
1. On first run there are no users → registration is open
2. Create the first account → this user automatically becomes admin
3. Log in → start uploading CBZ files

## Directory layout after first login

```
./library/username/                ← your comics (organized or Unorganized/)
./library/username/comics.json     ← metadata index
./library/username/tags.json       ← tag definitions & counts
./library/username/passwords.json  ← encrypted password vault (AES)
./cache/covers/username/           ← generated cover thumbnails
./etc/users.json                   ← user accounts (bcrypt hashes)
./etc/admin.json                   ← admin settings (registration toggle)
```

## How encrypted/password-protected comics work

- When you upload or scan an encrypted CBZ that has no known password yet, the server marks it as Encrypted = true.
- The first time you open it in the reader, a password prompt appears.
- If the password is correct, Gopherbook:
  - Stores the password (encrypted with a key derived from your login password)
  - Extracts ComicInfo.xml metadata
  - Auto-organizes the file into Artist/StoryArc folders
  - Updates tags and cover cache
- From then on the comic opens instantly, and that password is automatically tried on every future encrypted comic you upload (so whole collections that share one password "just work").

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
- OPDS catalog endpoint
- More metadata sources (ComicVine, etc.)

Please open an issue first for bigger changes.

## Thanks / Credits

- yeka/zip – password-protected ZIP support in pure Go
- The ComicRack ComicInfo.xml standard
- Everyone who hoards comics ❤️

Enjoy your library!  
— Happy reading with Gopherbook

<div align="center">

## Software Used but not included

![Arch](https://img.shields.io/badge/Arch%20Linux-1793D1?logo=arch-linux&logoColor=fff&style=for-the-badge)
![Gimp Gnu Image Manipulation Program](https://img.shields.io/badge/Gimp-657D8B?style=for-the-badge&logo=gimp&logoColor=FFFFFF)
![Vim](https://img.shields.io/badge/VIM-%2311AB00.svg?style=for-the-badge&logo=vim&logoColor=white)
![Git](https://img.shields.io/badge/git-%23F05033.svg?style=for-the-badge&logo=git&logoColor=white)
![Forgejo](https://img.shields.io/badge/forgejo-%23FB923C.svg?style=for-the-badge&logo=forgejo&logoColor=white)

</div>

## Creator:
- [Codeberg Riomoo](https://codeberg.org/riomoo)
- [GitGud Riomoo](https://gitgud.io/riomoo)
- [Github Riomoo](https://github.com/riomoo)
