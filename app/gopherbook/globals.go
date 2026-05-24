package main

// globals.go — Type definitions, global variables, and embedded file systems.
// No build tag: compiled for both the plain-server build and the desktop build.

import (
	"embed"
	"encoding/xml"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ── Embedded file systems ─────────────────────────────────────────────────────

//go:embed templates/index.html
var templateFS embed.FS

//go:embed all:static
var staticFS embed.FS

// ── Metadata types ────────────────────────────────────────────────────────────

// ComicInfo represents the standard ComicInfo.xml metadata.
type ComicInfo struct {
	XMLName   xml.Name `xml:"ComicInfo"`
	Title     string   `xml:"Title"`
	Series    string   `xml:"Series"`
	Number    string   `xml:"Number"`
	Writer    string   `xml:"Writer"`
	Artist    string   `xml:"Artist"`
	Inker     string   `xml:"Inker"`
	Publisher string   `xml:"Publisher"`
	Genre     string   `xml:"Genre"`
	TagsXml   string   `xml:"Tags"`
	StoryArc  string   `xml:"StoryArc"`
	Year      string   `xml:"Year"`
	Month     string   `xml:"Month"`
	Summary   string   `xml:"Summary"`
	PageCount int      `xml:"PageCount"`
}

// ── Domain types ──────────────────────────────────────────────────────────────

type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	IsAdmin      bool   `json:"is_admin"`
}

type Comic struct {
	ID           string    `json:"id"`
	Filename     string    `json:"filename"`
	Artist       string    `json:"artist"`
	Title        string    `json:"title"`
	Series       string    `json:"series"`
	StoryArc     string    `json:"story_arc"`
	Number       string    `json:"number"`
	Publisher    string    `json:"publisher"`
	Year         string    `json:"year"`
	PageCount    int       `json:"page_count"`
	CoverImage   string    `json:"cover_image"`
	FilePath     string    `json:"file_path"`
	FileType     string    `json:"file_type"`
	Encrypted    bool      `json:"encrypted"`
	HasPassword  bool      `json:"has_password"`
	Password     string    `json:"-"`
	Tags         []string  `json:"tags"`
	UploadedAt   time.Time `json:"uploaded_at"`
	Bookmarks    []int     `json:"bookmarks"`
	LastModified time.Time `json:"last_modified"`
}

type Session struct {
	Username  string
	ExpiresAt time.Time
}

type ShareLink struct {
	ID                     string     `json:"id"`
	ComicID                string     `json:"comic_id"`
	Username               string     `json:"username"`
	CreatedAt              time.Time  `json:"created_at"`
	ExpiresAt              *time.Time `json:"expires_at,omitempty"`
	Permanent              bool       `json:"permanent"`
	ComicPassword          string     `json:"-"`
	SharePasswordHash      string     `json:"share_password_hash,omitempty"`
	EncryptedComicPassword string     `json:"encrypted_comic_password,omitempty"`
	ComicEncrypted         bool       `json:"comic_encrypted"`
	ComicFilePath          string     `json:"comic_file_path"`
	ComicFileType          string     `json:"comic_file_type"`
	ComicTitle             string     `json:"comic_title"`
	ComicFilename          string     `json:"comic_filename"`
}

type Tag struct {
	Name  string `json:"name"`
	Color string `json:"color"`
	Count int    `json:"count"`
}

type Category struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	ComicIDs  []string  `json:"comic_ids"`
	CoverType string    `json:"cover_type"` // "collage" or "upload"
	CoverPath string    `json:"cover_path"`
	CreatedAt time.Time `json:"created_at"`
}

type TarFileInfo struct {
	Name string
	Size int64
	Data []byte
}

type shareUnlockSession struct {
	ComicPassword string
	ExpiresAt     time.Time
}

// ── Global state ──────────────────────────────────────────────────────────────

var (
	db                       *bolt.DB
	users                    = make(map[string]User)
	sessions                 = make(map[string]Session)
	comics                   = make(map[string]Comic)
	tags                     = make(map[string]Tag)
	comicPasswords           = make(map[string]string)
	shareLinks               = make(map[string]ShareLink)
	shareLinksMutex          sync.RWMutex
	shareUnlockSessions      = make(map[string]shareUnlockSession)
	shareUnlockSessionsMutex sync.RWMutex
	coverGenSemaphore        chan struct{}
	categories               = make(map[string]Category)
	categoriesMutex          sync.RWMutex
	comicsMutex              sync.RWMutex
	sessionsMutex            sync.RWMutex
	tagsMutex                sync.RWMutex
	passwordsMutex           sync.RWMutex
	currentEncryptionKey     []byte
	libraryPath              = "./library"
	cachePath                = "./cache/covers"
	etcPath                  = "./etc"
	currentUser              string
	registrationEnabled      = true
	saveTimer                *time.Timer
	watchFolders             = make(map[string]*time.Timer)
	watchMutex               sync.RWMutex
	watchPath                = "./watch"
	pageIndexCache           = make(map[string][]string)
	pageIndexCacheMutex      sync.RWMutex
	cb7Mutexes               sync.Map // map[filePath]*sync.Mutex
)
