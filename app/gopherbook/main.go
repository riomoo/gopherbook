package main

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"io/fs"
	"sync"
	"time"
	"runtime"
	"runtime/debug"
	"image"
	"image/jpeg"
	_ "image/gif"
	_ "image/png"

	"github.com/nfnt/resize"
	_ "github.com/gen2brain/avif"
	"golang.org/x/crypto/bcrypt"
	yzip "github.com/yeka/zip"
	bolt "go.etcd.io/bbolt"
)

//go:embed templates/index.html
var templateFS embed.FS

//go:embed all:static
var staticFS embed.FS

// ComicInfo represents the standard ComicInfo.xml metadata
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

type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	IsAdmin      bool   `json:"is_admin"`
}

type Comic struct {
	ID            string    `json:"id"`
	Filename      string    `json:"filename"`
	Artist        string    `json:"artist"`
	Title         string    `json:"title"`
	Series        string    `json:"series"`
	StoryArc      string    `json:"story_arc"`
	Number        string    `json:"number"`
	Publisher     string    `json:"publisher"`
	Year          string    `json:"year"`
	PageCount     int       `json:"page_count"`
	CoverImage    string    `json:"cover_image"`
	FilePath      string    `json:"file_path"`
	FileType      string    `json:"file_type"`
	Encrypted     bool      `json:"encrypted"`
	HasPassword   bool      `json:"has_password"`
	Password      string    `json:"-"`
	Tags          []string  `json:"tags"`
	UploadedAt    time.Time `json:"uploaded_at"`
	Bookmarks     []int     `json:"bookmarks"`
	LastModified  time.Time `json:"last_modified"`
}

type Session struct {
	Username  string
	ExpiresAt time.Time
}

type ShareLink struct {
	ID                    string     `json:"id"`
	ComicID               string     `json:"comic_id"`
	Username              string     `json:"username"`
	CreatedAt             time.Time  `json:"created_at"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"` // nil = permanent
	Permanent             bool       `json:"permanent"`
	ComicPassword         string     `json:"-"`                              // plaintext, in-memory only, never serialised
	SharePasswordHash     string     `json:"share_password_hash,omitempty"`  // bcrypt hash of the share-level password
	EncryptedComicPassword string    `json:"encrypted_comic_password,omitempty"` // AES(comicPassword, deriveKey(sharePassword)), base64
	ComicEncrypted        bool       `json:"comic_encrypted"`               // true when the underlying comic is encrypted
	ComicFilePath         string     `json:"comic_file_path"`               // snapshot so lookup works when user is offline
	ComicFileType         string     `json:"comic_file_type"`
	ComicTitle            string     `json:"comic_title"`
	ComicFilename         string     `json:"comic_filename"`
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
	CoverPath string    `json:"cover_path"` // path to custom cover if uploaded
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

var (
	db                   *bolt.DB
	users                = make(map[string]User)
	sessions             = make(map[string]Session)
	comics               = make(map[string]Comic)
	tags                 = make(map[string]Tag)
	comicPasswords       = make(map[string]string)
	shareLinks              = make(map[string]ShareLink) // token -> ShareLink
	shareLinksMutex         sync.RWMutex
	shareUnlockSessions     = make(map[string]shareUnlockSession) // key=(shareToken+":"+nonce)
	shareUnlockSessionsMutex sync.RWMutex
	coverGenSemaphore       = make(chan struct{}, 1) // Only ONE cover generation at a time
	categories           = make(map[string]Category)
	categoriesMutex      sync.RWMutex
	comicsMutex          sync.RWMutex
	sessionsMutex        sync.RWMutex
	tagsMutex            sync.RWMutex
	passwordsMutex       sync.RWMutex
	currentEncryptionKey []byte
	libraryPath          = "./library"
	cachePath            = "./cache/covers"
	etcPath              = "./etc"
	currentUser          string
	registrationEnabled  = true
	saveTimer            *time.Timer // For debounced saves
	watchFolders = make(map[string]*time.Timer)
	watchMutex   sync.RWMutex
	watchPath    = "./watch"
)

func main() {
	os.MkdirAll(libraryPath, 0755)
	os.MkdirAll(cachePath, 0755)
	os.MkdirAll(etcPath, 0755)
	os.MkdirAll(watchPath, 0755)

	var err error
	db, err = bolt.Open(filepath.Join(etcPath, "gopherbooks.db"), 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Ensure top-level buckets exist
	db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte("config"))
		return nil
	})

	loadUsers()
	initWatchFolders()
	// Create static sub-filesystem once
	staticSubFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal(fmt.Errorf("failed to create static sub-filesystem: %w", err))
	}

	// Create handlers once and reuse
	staticHandler := http.FileServer(http.FS(staticSubFS))

	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/comics", authMiddleware(handleComics))
	http.HandleFunc("/api/upload", authMiddleware(handleUpload))
	http.HandleFunc("/api/user", authMiddleware(handleUser))
	http.HandleFunc("/api/pages/", authMiddleware(handleComicPages))
	http.HandleFunc("/api/comic/", authMiddleware(handleComicFile))
	http.HandleFunc("/api/cover/", authMiddleware(handleCover))
	http.HandleFunc("/api/tags", authMiddleware(handleTags))
	http.HandleFunc("/api/comic-tags/", authMiddleware(handleComicTags))
	http.HandleFunc("/api/set-password/", authMiddleware(handleSetPassword))
	http.HandleFunc("/api/try-passwords/", authMiddleware(handleTryKnownPasswords))
	http.HandleFunc("/api/bookmark/", authMiddleware(handleBookmark))
	http.HandleFunc("/api/admin/toggle-registration", authMiddleware(handleToggleRegistration))
	http.HandleFunc("/api/admin/delete-comic/", authMiddleware(handleDeleteComic))
	http.HandleFunc("/api/delete-comic/", authMiddleware(handleUserDeleteComic))
	http.HandleFunc("/api/watch-folder", authMiddleware(handleWatchFolder))
	http.HandleFunc("/api/share/create/", authMiddleware(handleCreateShare))
	http.HandleFunc("/api/share/list", authMiddleware(handleListShares))
	http.HandleFunc("/api/share/delete/", authMiddleware(handleDeleteShare))
	http.HandleFunc("/api/share/unlock/", handleShareUnlock)
	http.HandleFunc("/api/categories", authMiddleware(handleCategories))
	http.HandleFunc("/api/category/create", authMiddleware(handleCreateCategory))
	http.HandleFunc("/api/category/update/", authMiddleware(handleUpdateCategory))
	http.HandleFunc("/api/category/delete/", authMiddleware(handleDeleteCategory))
	http.HandleFunc("/api/category/cover/", authMiddleware(handleCategorycover))
	http.HandleFunc("/api/category/upload-cover/", authMiddleware(handleCategoryUploadCover))
	http.HandleFunc("/s/", handleSharedComic)
	http.HandleFunc("/", serveUI)
	http.Handle("/static/", http.StripPrefix("/static/", staticHandler))

	go func() {
		for {
			time.Sleep(30 * time.Second)
			runtime.GC()
			debug.FreeOSMemory()
		}
	}()

	// Periodic session cleanup
	go cleanupSessions()
	// Periodic share link expiry cleanup
	go cleanupExpiredShareLinks()

	port := os.Getenv("GBKPORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("Server starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !registrationEnabled {
		http.Error(w, "Registration disabled", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	if _, exists := users[req.Username]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	users[req.Username] = User{
		Username:     req.Username,
		PasswordHash: string(hash),
		IsAdmin:      len(users) == 0,
	}
	saveUsers()

	// Create per-user bbolt buckets
	db.Update(func(tx *bolt.Tx) error {
		return ensureUserBuckets(tx, req.Username)
	})

	if len(users) == 1 {
		saveAdminConfig()
		registrationEnabled = true
	}

	userLibrary := filepath.Join("./library", req.Username)
	os.MkdirAll(filepath.Join(userLibrary, "Unorganized"), 0755)
	os.MkdirAll(filepath.Join("./cache/covers", req.Username), 0755)

	userWatchPath := filepath.Join(watchPath, req.Username)
	os.MkdirAll(userWatchPath, 0755)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created"})
}

func handleToggleRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getCurrentUser(r)
	if !user.IsAdmin {
		http.Error(w, "Admin only", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost {
		registrationEnabled = !registrationEnabled
		saveAdminConfig()
		debounceSave()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": registrationEnabled})
}

func handleUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getCurrentUser(r)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": user.Username,
		"is_admin": user.IsAdmin,
	})
}

func getCurrentUser(r *http.Request) User {
	cookie, err := r.Cookie("session")
	if err != nil {
		return User{}
	}
	sessionsMutex.RLock()
	session, exists := sessions[cookie.Value]
	sessionsMutex.RUnlock()
	if !exists {
		return User{}
	}
	return users[session.Username]
}

func handleWatchFolder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getCurrentUser(r)
	userWatchPath := filepath.Join(watchPath, user.Username)

	// Get list of files currently in watch folder
	files, err := os.ReadDir(userWatchPath)
	if err != nil {
		http.Error(w, "Error reading watch folder", http.StatusInternalServerError)
		return
	}

	var cbzFiles []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(file.Name()))
		if ext == ".cbz" {
			cbzFiles = append(cbzFiles, file.Name())
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"watch_path": userWatchPath,
		"files":      cbzFiles,
		"count":      len(cbzFiles),
	})
}

func moveFile(src, dst string) error {
	// Try rename first (fast if same filesystem)
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}

	// If rename fails (cross-filesystem), copy and delete
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Copy the file contents
	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	// Ensure data is written to disk
	err = destFile.Sync()
	if err != nil {
		return err
	}

	// Close files before removing source
	sourceFile.Close()
	destFile.Close()

	// Remove the source file
	return os.Remove(src)
}

func importWatchFolderFiles(username, watchDir string) {
	log.Printf("Processing watch folder for user: %s", username)

	files, err := os.ReadDir(watchDir)
	if err != nil {
		log.Printf("Error reading watch folder: %v", err)
		return
	}

	imported := 0
	failed := 0

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(file.Name()))
		// Support both CBZ and CBT
		if ext != ".cbz" && ext != ".cbt" {
			continue
		}

		sourcePath := filepath.Join(watchDir, file.Name())

		// Check if file is still being written
		info1, err := os.Stat(sourcePath)
		if err != nil {
			continue
		}
		time.Sleep(500 * time.Millisecond)
		info2, err := os.Stat(sourcePath)
		if err != nil {
			continue
		}

		if info1.Size() != info2.Size() {
			log.Printf("File still being written: %s", file.Name())
			continue
		}

		// Import the file
		destPath := filepath.Join(libraryPath, "Unorganized", file.Name())

		// Handle duplicate filenames
		counter := 1
		originalName := strings.TrimSuffix(file.Name(), ext)
		for {
			if _, err := os.Stat(destPath); os.IsNotExist(err) {
				break
			}
			destPath = filepath.Join(libraryPath, "Unorganized",
				fmt.Sprintf("%s_%d%s", originalName, counter, ext))
			counter++
		}

		// Move the file
		err = moveFile(sourcePath, destPath)
		if err != nil {
			log.Printf("Error moving file %s: %v", file.Name(), err)
			failed++
			continue
		}

		// Process the comic
		fileInfo, _ := os.Stat(destPath)
		comic := processComic(destPath, filepath.Base(destPath), fileInfo.ModTime())

		comicsMutex.Lock()
		comics[comic.ID] = comic
		comicsMutex.Unlock()

		imported++
		log.Printf("Imported: %s -> %s", file.Name(), comic.ID)
	}

	if imported > 0 || failed > 0 {
		log.Printf("Watch folder import complete: %d imported, %d failed", imported, failed)
		debounceSave()
		runtime.GC()
	}
}

func processWatchFolder(username, watchDir string) {
	// Check if this is the current logged-in user
	if currentUser != username {
		return
	}

	files, err := os.ReadDir(watchDir)
	if err != nil {
		return
	}

	hasFiles := false
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(file.Name()))
		if ext != ".cbz" && ext != ".cbt" {
			continue
		}

		hasFiles = true
		break
	}

	if !hasFiles {
		return
	}

	// Debounce: wait for all files to finish copying
	watchMutex.Lock()
	if timer, exists := watchFolders[username]; exists {
		timer.Stop()
	}

	watchFolders[username] = time.AfterFunc(5*time.Second, func() {
		importWatchFolderFiles(username, watchDir)
	})
	watchMutex.Unlock()
}

func startWatchingUser(username string) {
	userWatchPath := filepath.Join(watchPath, username)
	os.MkdirAll(userWatchPath, 0755)

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		log.Printf("Started watching folder for user: %s", username)

		for range ticker.C {
			processWatchFolder(username, userWatchPath)
		}
	}()
}

func initWatchFolders() {
	os.MkdirAll(watchPath, 0755)

	// Create watch folders for existing users
	for username := range users {
		userWatchPath := filepath.Join(watchPath, username)
		os.MkdirAll(userWatchPath, 0755)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, exists := users[req.Username]
	if !exists {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := generateToken()
	sessionsMutex.Lock()
	sessions[token] = Session{
		Username:  req.Username,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	sessionsMutex.Unlock()

	currentUser = req.Username
	key := deriveKey(req.Password)
	libraryPath = filepath.Join(baseLibraryPath, currentUser)
	cachePath = filepath.Join(baseCachePath, currentUser)
	os.MkdirAll(filepath.Join(libraryPath, "Unorganized"), 0755)
	os.MkdirAll(cachePath, 0755)

	// Ensure per-user buckets exist (handles existing users before migration)
	db.Update(func(tx *bolt.Tx) error {
		return ensureUserBuckets(tx, currentUser)
	})

	comicsMutex.Lock()
	comics = make(map[string]Comic)
	comicsMutex.Unlock()
	tagsMutex.Lock()
	tags = make(map[string]Tag)
	tagsMutex.Unlock()
	passwordsMutex.Lock()
	comicPasswords = make(map[string]string)
	passwordsMutex.Unlock()

	loadComics()
	loadTags()
	loadPasswordsWithKey(key)
	loadShareLinks(req.Username)
	loadCategories()
	currentEncryptionKey = key
	startWatchingUser(req.Username)

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
	})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Login successful",
		"token":    token,
		"is_admin": user.IsAdmin,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		sessionsMutex.Lock()
		delete(sessions, cookie.Value)
		sessionsMutex.Unlock()
	}

	comicsMutex.Lock()
	comics = make(map[string]Comic)
	comicsMutex.Unlock()
	tagsMutex.Lock()
	tags = make(map[string]Tag)
	tagsMutex.Unlock()
	passwordsMutex.Lock()
	comicPasswords = make(map[string]string)
	passwordsMutex.Unlock()
	categoriesMutex.Lock()
	categories = make(map[string]Category)
	categoriesMutex.Unlock()
	currentEncryptionKey = nil
	currentUser = ""
	libraryPath = baseLibraryPath
	cachePath = baseCachePath

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Path:     "/",
	})

	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out"})
}

func handleComics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Trigger scan if needed (lightweight now)
	if len(comics) == 0 {
		scanLibrary()
	}

	comicsMutex.RLock()
	defer comicsMutex.RUnlock()

	comicList := make([]Comic, 0, len(comics))
	for _, comic := range comics {
		// Check if we have a password for this comic
		passwordsMutex.RLock()
		_, hasPassword := comicPasswords[comic.ID]
		passwordsMutex.RUnlock()

		// Update HasPassword flag (lightweight)
		if hasPassword {
			comic.HasPassword = true
		}

		comicList = append(comicList, comic)
	}

	sort.Slice(comicList, func(i, j int) bool {
		if comicList[i].Artist != comicList[j].Artist {
			return comicList[i].Artist < comicList[j].Artist
		}
		if comicList[i].Series != comicList[j].Series {
			return comicList[i].Series < comicList[j].Series
		}
		return comicList[i].Number < comicList[j].Number
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comicList)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Error creating multipart reader", http.StatusBadRequest)
		return
	}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Error reading part", http.StatusInternalServerError)
			return
		}

		if part.FormName() == "file" {
			filename := part.FileName()

			// Validate file extension (CBZ or CBT)
			ext := strings.ToLower(filepath.Ext(filename))
			if ext != ".cbz" && ext != ".cbt" {
				http.Error(w, "Only .cbz and .cbt files are supported", http.StatusBadRequest)
				return
			}

			destPath := filepath.Join(libraryPath, "Unorganized", filename)
			destFile, err := os.Create(destPath)
			if err != nil {
				http.Error(w, "Error saving file", http.StatusInternalServerError)
				return
			}

			buf := make([]byte, 32*1024)
			_, err = io.CopyBuffer(destFile, part, buf)
			destFile.Close()
			if err != nil {
				http.Error(w, "Error saving file", http.StatusInternalServerError)
				return
			}

			fileInfo, _ := os.Stat(destPath)
			comic := processComic(destPath, filename, fileInfo.ModTime())

			comicsMutex.Lock()
			comics[comic.ID] = comic
			comicsMutex.Unlock()

			buf = nil
			runtime.GC()

			json.NewEncoder(w).Encode(comic)
			return
		}
	}
}

func logMemStats(label string) {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    log.Printf("[%s] Alloc=%dMB, TotalAlloc=%dMB, Sys=%dMB, NumGC=%d",
        label,
        m.Alloc/1024/1024,
        m.TotalAlloc/1024/1024,
        m.Sys/1024/1024,
        m.NumGC)
}

func handleDeleteComic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getCurrentUser(r)
	if !user.IsAdmin {
		http.Error(w, "Admin only", http.StatusForbidden)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/delete-comic/")
	decodedID, _ := url.QueryUnescape(id)
	comicsMutex.Lock()
	comic, exists := comics[decodedID]
	if exists {
		os.Remove(comic.FilePath)
		for _, tag := range comic.Tags {
			updateTagCount(tag, -1)
		}
		delete(comics, decodedID)
		debounceSave()
	}
	comicsMutex.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Deleted"})
}

// handleUserDeleteComic lets any authenticated user delete their own comics.
func handleUserDeleteComic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/delete-comic/")
	decodedID, _ := url.QueryUnescape(id)

	comicsMutex.Lock()
	comic, exists := comics[decodedID]
	if !exists {
		comicsMutex.Unlock()
		http.Error(w, "Comic not found", http.StatusNotFound)
		return
	}
	os.Remove(comic.FilePath)
	// Also remove cached cover
	cacheFile := filepath.Join(cachePath, comic.ID+".jpg")
	os.Remove(cacheFile)
	for _, tag := range comic.Tags {
		updateTagCount(tag, -1)
	}
	delete(comics, decodedID)
	comicsMutex.Unlock()

	// Remove any share links for this comic
	shareLinksMutex.Lock()
	for token, sl := range shareLinks {
		if sl.ComicID == decodedID {
			delete(shareLinks, token)
		}
	}
	shareLinksMutex.Unlock()
	saveShareLinks(getCurrentUser(r).Username)

	debounceSave()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Deleted"})
}

func handleCover(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/cover/")
	decodedID, err := url.QueryUnescape(id)
	if err != nil {
		decodedID = id
	}

	comicsMutex.RLock()
	comic, exists := comics[decodedID]
	if !exists {
		comic, exists = comics[id]
	}
	comicsMutex.RUnlock()

	if !exists {
		http.Error(w, "Comic not found", http.StatusNotFound)
		return
	}

	cacheFile := filepath.Join(cachePath, comic.ID+".jpg")

	// Check if cache exists
	if _, err := os.Stat(cacheFile); err == nil {
		http.ServeFile(w, r, cacheFile)
		return
	}

	// Check if we have password for encrypted comics
	passwordsMutex.RLock()
	password, hasPassword := comicPasswords[comic.ID]
	passwordsMutex.RUnlock()

	if comic.Encrypted && !hasPassword {
		w.WriteHeader(http.StatusLocked)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "password_required",
			"message": "Comic requires password",
		})
		return
	}

	// Set password if we have it
	if hasPassword {
		comicsMutex.Lock()
		c := comics[comic.ID]
		c.Password = password
		c.HasPassword = true
		comics[comic.ID] = c
		comic = c
		comicsMutex.Unlock()
	}

	// Load metadata if not already loaded
	if comic.Series == "" && comic.Title == "" {
		loadComicMetadataLazy(comic.ID)
		comicsMutex.RLock()
		comic = comics[comic.ID]
		comicsMutex.RUnlock()
	}

	log.Printf("Generating cover on-demand for: %s", comic.Filename)

	// Use semaphore for cover generation
	select {
	case coverGenSemaphore <- struct{}{}:
		defer func() { <-coverGenSemaphore }()
	case <-time.After(30 * time.Second):
		log.Printf("Timeout waiting for cover generation slot")
		http.Error(w, "Cover generation busy, try again later", http.StatusServiceUnavailable)
		return
	}

	// Double-check cache again
	if _, err := os.Stat(cacheFile); err == nil {
		http.ServeFile(w, r, cacheFile)
		return
	}

	// Generate based on file type
	var genErr error
	if comic.FileType == ".cbt" {
		genErr = generateCBTCover(&comic, cacheFile)
	} else if comic.FileType == ".cbz" {
		genErr = generateCoverCacheLazy(&comic, cacheFile)
	} else {
		genErr = fmt.Errorf("unsupported file type: %s", comic.FileType)
	}

	if genErr != nil {
		log.Printf("Failed to generate cover: %v", genErr)
		http.Error(w, "Failed to generate cover", http.StatusInternalServerError)
		return
	}

	// Serve the newly generated cache
	if _, err := os.Stat(cacheFile); err == nil {
		http.ServeFile(w, r, cacheFile)
		return
	}

	http.Error(w, "Cover generation failed", http.StatusInternalServerError)
}


func isTarEncrypted(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// Read first 512 bytes (tar header size)
	header := make([]byte, 512)
	n, err := f.Read(header)
	if err != nil && err != io.EOF {
		return false, err
	}

	// If we can successfully parse a tar header, it's not encrypted
	reader := tar.NewReader(bytes.NewReader(header[:n]))
	_, err = reader.Next()

	// If Next() succeeds, tar is valid (not encrypted)
	// If it fails, likely encrypted
	return err != nil, nil
}

func openEncryptedTar(filePath, password string) (*tar.Reader, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read entire file (we need it all for decryption)
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// Decrypt
	key := deriveKey(password)
	decrypted, err := decryptAES(data, key)
	if err != nil {
		return nil, err
	}

	// Create tar reader from decrypted data
	return tar.NewReader(bytes.NewReader(decrypted)), nil
}

func extractCBTMetadata(comic *Comic) {
	if comic.FileType != ".cbt" {
		return
	}

	var tr *tar.Reader
	var err error

	// Check if encrypted
	encrypted, _ := isTarEncrypted(comic.FilePath)

	if encrypted {
		if comic.Password == "" {
			return // Can't decrypt without password
		}
		tr, err = openEncryptedTar(comic.FilePath, comic.Password)
	} else {
		f, err := os.Open(comic.FilePath)
		if err != nil {
			return
		}
		defer f.Close()
		tr = tar.NewReader(f)
	}

	if err != nil {
		return
	}

	// Look for ComicInfo.xml
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}

		if strings.ToLower(header.Name) == "comicinfo.xml" ||
		   strings.HasSuffix(strings.ToLower(header.Name), "/comicinfo.xml") {

			// Read the XML data
			xmlData, err := io.ReadAll(tr)
			if err != nil {
				return
			}

			var info ComicInfo
			if err := xml.Unmarshal(xmlData, &info); err == nil {
				comic.Title = info.Title
				comic.Series = info.Series
				comic.StoryArc = info.StoryArc
				comic.Number = info.Number
				comic.Publisher = info.Publisher
				comic.Year = info.Year
				comic.PageCount = info.PageCount

				if info.Artist != "" {
					comic.Artist = info.Artist
				} else if info.Writer != "" {
					comic.Artist = info.Writer
				}

				// Extract tags
				tagsSource := info.TagsXml
				if tagsSource == "" {
					tagsSource = info.Genre
				}

				if tagsSource != "" {
					rawTags := strings.FieldsFunc(tagsSource, func(r rune) bool {
						return r == ',' || r == ';' || r == '|'
					})

					comic.Tags = make([]string, 0, len(rawTags))
					for _, tag := range rawTags {
						trimmed := strings.TrimSpace(tag)
						if trimmed != "" {
							comic.Tags = append(comic.Tags, trimmed)
						}
					}
				}
			}
			break
		}
	}
}

// Add this function to open a regular (unencrypted) tar file
func openTar(filePath string) (*tar.Reader, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	// Note: caller must close the underlying file
	return tar.NewReader(f), nil
}

func readTarFiles(tr *tar.Reader) ([]TarFileInfo, error) {
	var files []TarFileInfo

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Read file data
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}

		files = append(files, TarFileInfo{
			Name: header.Name,
			Size: header.Size,
			Data: data,
		})
	}

	return files, nil
}

func validateCBTPassword(filePath, password string) bool {
	tr, err := openEncryptedTar(filePath, password)
	if err != nil {
		return false
	}

	// Try to read first header
	_, err = tr.Next()
	return err == nil || err == io.EOF
}

// Add this function to generate cover from CBT
func generateCBTCover(comic *Comic, cacheFile string) error {
	var tr *tar.Reader
	var err error
	var closeFile func()

	// Check if encrypted
	encrypted, _ := isTarEncrypted(comic.FilePath)

	if encrypted {
		if comic.Password == "" {
			return fmt.Errorf("password required")
		}
		tr, err = openEncryptedTar(comic.FilePath, comic.Password)
		closeFile = func() {} // File already closed in openEncryptedTar
	} else {
		f, err := os.Open(comic.FilePath)
		if err != nil {
			return err
		}
		closeFile = func() { f.Close() }
		tr = tar.NewReader(f)
	}
	defer closeFile()

	if err != nil {
		return err
	}

	// Find first image file
	var imageData []byte

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}

		ext := strings.ToLower(filepath.Ext(header.Name))
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" ||
		   ext == ".gif" || ext == ".avif" || ext == ".webp" ||
		   ext == ".bmp" || ext == ".jp2" || ext == ".jxl" {

			// Found an image, read it
			imageData, err = io.ReadAll(tr)
			if err != nil {
				return err
			}
			// imageExt = ext
			break
		}
	}

	if len(imageData) == 0 {
		return fmt.Errorf("no images found in tar")
	}

	// Decode image
	img, _, err := image.Decode(bytes.NewReader(imageData))
	if err != nil {
		return err
	}

	// Resize
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	maxDim := 300
	var newWidth, newHeight int
	if width > height {
		newWidth = maxDim
		newHeight = int(float64(height) * float64(maxDim) / float64(width))
	} else {
		newHeight = maxDim
		newWidth = int(float64(width) * float64(maxDim) / float64(height))
	}

	resized := resize.Resize(uint(newWidth), uint(newHeight), img, resize.Lanczos3)

	// Save as JPEG
	out, err := os.Create(cacheFile)
	if err != nil {
		return err
	}
	defer out.Close()

	return jpeg.Encode(out, resized, &jpeg.Options{Quality: 75})
}

// Add this function to serve CBT pages
func serveCBTPage(w http.ResponseWriter, r *http.Request, comic Comic, pageNum string) {
	var tr *tar.Reader
	var err error
	var closeFile func()

	// Check if encrypted
	encrypted, _ := isTarEncrypted(comic.FilePath)

	if encrypted {
		// Prefer password already on the struct (e.g. from a share link),
		// fall back to the global in-memory map.
		password := comic.Password
		if password == "" {
			passwordsMutex.RLock()
			password = comicPasswords[comic.ID]
			passwordsMutex.RUnlock()
		}
		if password == "" {
			http.Error(w, "Password required", http.StatusUnauthorized)
			return
		}

		tr, err = openEncryptedTar(comic.FilePath, password)
		closeFile = func() {}
	} else {
		f, err := os.Open(comic.FilePath)
		if err != nil {
			http.Error(w, "Error opening comic", http.StatusInternalServerError)
			return
		}
		closeFile = func() { f.Close() }
		tr = tar.NewReader(f)
	}
	defer closeFile()

	if err != nil {
		http.Error(w, "Error reading comic", http.StatusInternalServerError)
		return
	}

	// Get all image files
	var imageFiles []TarFileInfo
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Error reading tar", http.StatusInternalServerError)
			return
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}

		ext := strings.ToLower(filepath.Ext(header.Name))
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" ||
		   ext == ".gif" || ext == ".avif" || ext == ".webp" ||
		   ext == ".bmp" || ext == ".jp2" || ext == ".jxl" {

			data, err := io.ReadAll(tr)
			if err != nil {
				continue
			}

			imageFiles = append(imageFiles, TarFileInfo{
				Name: header.Name,
				Size: header.Size,
				Data: data,
			})
		}
	}

	// Sort by name
	sort.Slice(imageFiles, func(i, j int) bool {
		return imageFiles[i].Name < imageFiles[j].Name
	})

	var pageIdx int
	fmt.Sscanf(pageNum, "%d", &pageIdx)

	if pageIdx < 0 || pageIdx >= len(imageFiles) {
		http.Error(w, "Page not found", http.StatusNotFound)
		return
	}

	targetFile := imageFiles[pageIdx]
	ext := strings.ToLower(filepath.Ext(targetFile.Name))
	contentType := getContentType(ext)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(targetFile.Data)
}

// Add this function to get CBT page count
func getCBTPageCount(comic Comic) (int, error) {
	var tr *tar.Reader
	var err error
	var closeFile func()

	// Check if encrypted
	encrypted, _ := isTarEncrypted(comic.FilePath)

	if encrypted {
		// Prefer password already on the struct (e.g. from a share link),
		// fall back to the global in-memory map.
		password := comic.Password
		if password == "" {
			passwordsMutex.RLock()
			password = comicPasswords[comic.ID]
			passwordsMutex.RUnlock()
		}
		if password == "" {
			return 0, fmt.Errorf("password required")
		}

		tr, err = openEncryptedTar(comic.FilePath, password)
		closeFile = func() {}
	} else {
		f, err := os.Open(comic.FilePath)
		if err != nil {
			return 0, err
		}
		closeFile = func() { f.Close() }
		tr = tar.NewReader(f)
	}
	defer closeFile()

	if err != nil {
		return 0, err
	}

	count := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}

		ext := strings.ToLower(filepath.Ext(header.Name))
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" ||
		   ext == ".gif" || ext == ".avif" || ext == ".webp" ||
		   ext == ".bmp" || ext == ".jp2" || ext == ".jxl" {
			count++
		}
	}

	return count, nil
}

func generateCoverCacheLazy(comic *Comic, cacheFile string) error {
	// CRITICAL: Set very aggressive GC for this operation
	oldGC := debug.SetGCPercent(10)
	defer func() {
		debug.SetGCPercent(oldGC)
		runtime.GC()
		debug.FreeOSMemory()
	}()

	if comic.FileType != ".cbz" {
		return fmt.Errorf("not a CBZ file")
	}

	// Check file size first - refuse to process huge files
	fi, err := os.Stat(comic.FilePath)
	if err != nil {
		return err
	}
	if fi.Size() > 900*1024*1024 { // 900MB max CBZ file
		log.Printf("CBZ too large (%d bytes), skipping thumbnail", fi.Size())
		return fmt.Errorf("file too large")
	}

	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
		return err
	}
	defer yr.Close()

	var imageFiles []*yzip.File
	for _, f := range yr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" ||
			ext == ".avif" || ext == ".jxl" || ext == ".webp" || ext == ".bmp" || ext == ".jp2" {
			imageFiles = append(imageFiles, f)
		}
	}

	if len(imageFiles) == 0 {
		return fmt.Errorf("no images found")
	}

	sort.Slice(imageFiles, func(i, j int) bool {
		return imageFiles[i].Name < imageFiles[j].Name
	})

	coverFile := imageFiles[0]

	if coverFile.UncompressedSize64 > 30*1024*1024 { // 30MB uncompressed
		log.Printf("Cover image too large (%d bytes), using direct resize", coverFile.UncompressedSize64)
		return resizeCoverDirectly(comic, coverFile, cacheFile, 300)
	}

	if coverFile.IsEncrypted() {
		if comic.Password != "" {
			coverFile.SetPassword(comic.Password)
		} else {
			return fmt.Errorf("encrypted without password")
		}
	}

	rc, err := coverFile.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	// NEW: First decode config to check dimensions
	config, format, err := image.DecodeConfig(rc)
	if err == nil {
		pixelCount := config.Width * config.Height
		log.Printf("Cover dimensions: %dx%d (%d pixels), format: %s", config.Width, config.Height, pixelCount, format)

		// If image is huge (>20 megapixels), use direct resize
		if pixelCount > 20*1000*1000 {
			rc.Close()
			log.Printf("Image too large (%d megapixels), using direct resize", pixelCount/1000000)
			return resizeCoverDirectly(comic, coverFile, cacheFile, 300)
		}
	}
	rc.Close()

	// Reopen for actual reading
	rc, err = coverFile.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	// Stream to temp file with size limit
	tempFile, err := os.CreateTemp(cachePath, "cover-*.tmp")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	// Copy with explicit limit
	written, err := io.CopyN(tempFile, rc, 30*1024*1024) // 30MB hard limit
	if err != nil && err != io.EOF {
		tempFile.Close()
		return err
	}
	tempFile.Close()

	if written == 0 {
		return fmt.Errorf("empty image file")
	}

	// Force GC before heavy operation
	runtime.GC()

	// Resize with aggressive memory management
	return resizeImageAggressively(tempPath, cacheFile, 300) // Reduced from 400
}


// New function: resize directly from reader for huge images
// NEW: Improved resizeCoverDirectly with streaming decode
func resizeCoverDirectly(comic *Comic, coverFile *yzip.File, cacheFile string, maxDim int) error {
	if coverFile.IsEncrypted() && comic.Password != "" {
		coverFile.SetPassword(comic.Password)
	}

	// 1. Extract and decrypt to disk first
	tmp, err := os.CreateTemp("", "cover-extract-*.img")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	defer tmp.Close()

	rc, err := coverFile.Open()
	if err != nil {
		return err
	}
	_, err = io.Copy(tmp, rc)
	rc.Close()
	if err != nil {
		return err
	}

	// 2. Decode from Disk-based reader
	tmp.Seek(0, 0)
	img, _, err := image.Decode(tmp)
	if err != nil {
		return err
	}
	tmp.Close() // Close early

	// 3. Resize logic
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	var newWidth, newHeight int
	if width > height {
		newWidth = maxDim
		newHeight = int(float64(height) * float64(maxDim) / float64(width))
	} else {
		newHeight = maxDim
		newWidth = int(float64(width) * float64(maxDim) / float64(height))
	}

	// Use Bilinear for better speed/memory balance on huge 33MP images
	resized := resize.Resize(uint(newWidth), uint(newHeight), img, resize.Bilinear)

	// CRITICAL: Nil the 132MB bitmap immediately
	img = nil
	runtime.GC()

	out, err := os.Create(cacheFile)
	if err != nil {
		return err
	}
	defer out.Close()

	err = jpeg.Encode(out, resized, &jpeg.Options{Quality: 75})
	resized = nil
	runtime.GC()

	return err
}


func resizeImageAggressively(inputPath, outputPath string, maxDimension int) error {
	f, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// First check dimensions WITHOUT decoding full image
	config, format, err := image.DecodeConfig(f)
	if err != nil {
		return err
	}

	log.Printf("Resizing %s image: %dx%d", format, config.Width, config.Height)

	// Seek back to start
	f.Seek(0, 0)

	// Decode with size awareness
	img, _, err := image.Decode(f)
	if err != nil {
		return err
	}
	f.Close()

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// Calculate target dimensions
	var newWidth, newHeight int
	if width > height {
		newWidth = maxDimension
		newHeight = int(float64(height) * float64(maxDimension) / float64(width))
	} else {
		newHeight = maxDimension
		newWidth = int(float64(width) * float64(maxDimension) / float64(height))
	}

	if newWidth < 1 {
		newWidth = 1
	}
	if newHeight < 1 {
		newHeight = 1
	}

	// Choose resize method based on size ratio
	var resizeMethod resize.InterpolationFunction
	ratio := float64(width*height) / float64(newWidth*newHeight)

	if ratio > 100 { // Massive reduction (>100x pixels)
		resizeMethod = resize.NearestNeighbor
		log.Printf("Using NearestNeighbor (ratio: %.1f)", ratio)
	} else if ratio > 25 {
		resizeMethod = resize.Bilinear
		log.Printf("Using Bilinear (ratio: %.1f)", ratio)
	} else {
		resizeMethod = resize.Lanczos3
		log.Printf("Using Lanczos3 (ratio: %.1f)", ratio)
	}

	// For VERY large images, do multi-pass resize
	if ratio > 50 {
		// First pass: reduce to intermediate size
		intermediateSize := maxDimension * 3
		var iWidth, iHeight int
		if width > height {
			iWidth = intermediateSize
			iHeight = int(float64(height) * float64(intermediateSize) / float64(width))
		} else {
			iHeight = intermediateSize
			iWidth = int(float64(width) * float64(intermediateSize) / float64(height))
		}

		log.Printf("Multi-pass resize: %dx%d -> %dx%d -> %dx%d",
			width, height, iWidth, iHeight, newWidth, newHeight)

		// First pass
		tempImg := resize.Resize(uint(iWidth), uint(iHeight), img, resize.NearestNeighbor)
		img = nil
		runtime.GC()

		// Second pass
		resized := resize.Resize(uint(newWidth), uint(newHeight), tempImg, resize.Lanczos3)
		tempImg = nil
		runtime.GC()

		// Save
		return saveJPEG(resized, outputPath)
	}

	// Single pass for smaller reductions
	resized := resize.Resize(uint(newWidth), uint(newHeight), img, resizeMethod)
	img = nil
	runtime.GC()

	return saveJPEG(resized, outputPath)
}

// Helper function to save JPEG and free memory
func saveJPEG(img image.Image, path string) error {
	out, err := os.Create(path)
	if err != nil {
		img = nil
		return err
	}
	defer out.Close()

	// Lower quality = smaller memory footprint during encoding
	err = jpeg.Encode(out, img, &jpeg.Options{Quality: 85})
	img = nil

	runtime.GC()
	debug.FreeOSMemory()

	return err
}

func handleTags(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		tagsMutex.RLock()
		tagList := make([]Tag, 0, len(tags))
		for _, tag := range tags {
			tagList = append(tagList, tag)
		}
		tagsMutex.RUnlock()

		sort.Slice(tagList, func(i, j int) bool {
			return tagList[i].Name < tagList[j].Name
		})

		json.NewEncoder(w).Encode(tagList)

	case http.MethodPost:
		var req struct {
			Name  string `json:"name"`
			Color string `json:"color"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			http.Error(w, "Tag name required", http.StatusBadRequest)
			return
		}

		if req.Color == "" {
			req.Color = "#446B6E"
		}

		tagsMutex.Lock()
		tags[req.Name] = Tag{
			Name:  req.Name,
			Color: req.Color,
			Count: 0,
		}
		tagsMutex.Unlock()

		debounceSave()
		json.NewEncoder(w).Encode(tags[req.Name])

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleComicTags(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/comic-tags/"), "/")
	if len(parts) == 0 {
		http.Error(w, "Comic ID required", http.StatusBadRequest)
		return
	}

	id := parts[0]
	decodedID, err := url.QueryUnescape(id)
	if err != nil {
		decodedID = id
	}

	comicsMutex.Lock()
	defer comicsMutex.Unlock()

	comic, exists := comics[decodedID]
	if !exists {
		comic, exists = comics[id]
		if !exists {
			http.Error(w, "Comic not found", http.StatusNotFound)
			return
		}
	}

	switch r.Method {
	case http.MethodPost:
		var req struct {
			Tag string `json:"tag"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		found := false
		for _, t := range comic.Tags {
			if t == req.Tag {
				found = true
				break
			}
		}

		if !found {
			comic.Tags = append(comic.Tags, req.Tag)
			comics[decodedID] = comic
			updateTagCount(req.Tag, 1)
			debounceSave()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(comic)

	case http.MethodDelete:
		if len(parts) < 2 {
			http.Error(w, "Tag required", http.StatusBadRequest)
			return
		}

		tagToRemove, _ := url.QueryUnescape(parts[1])
		newTags := []string{}
		removed := false

		for _, t := range comic.Tags {
			if t != tagToRemove {
				newTags = append(newTags, t)
			} else {
				removed = true
			}
		}

		if removed {
			comic.Tags = newTags
			comics[decodedID] = comic
			updateTagCount(tagToRemove, -1)
			debounceSave()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(comic)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleTryKnownPasswords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/try-passwords/")
	decodedID, err := url.QueryUnescape(id)
	if err != nil {
		decodedID = id
	}

	comicsMutex.RLock()
	comic, exists := comics[decodedID]
	comicsMutex.RUnlock()

	if !exists {
		http.Error(w, "Comic not found", http.StatusNotFound)
		return
	}

	if !comic.Encrypted {
		http.Error(w, "Comic not encrypted", http.StatusBadRequest)
		return
	}

	// Get all known passwords
	passwordsMutex.RLock()
	knownPasswords := make([]string, 0, len(comicPasswords))
	for _, pwd := range comicPasswords {
		found := false
		for _, existing := range knownPasswords {
			if existing == pwd {
				found = true
				break
			}
		}
		if !found {
			knownPasswords = append(knownPasswords, pwd)
		}
	}
	passwordsMutex.RUnlock()

	if len(knownPasswords) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "No known passwords to try",
		})
		return
	}

	// Try each password using the new validation function
	validPassword := ""
	for _, pwd := range knownPasswords {
		if validatePassword(comic.FilePath, pwd) {
			validPassword = pwd
			break
		}
	}

	if validPassword == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "None of the known passwords worked",
		})
		return
	}

	// Password worked! Save it and extract metadata
	comicsMutex.Lock()
	c := comics[decodedID]
	c.Password = validPassword
	c.HasPassword = true
	extractMetadata(&c)

	tagsMutex.Lock()
	for _, tag := range c.Tags {
		if tagData, exists := tags[tag]; exists {
			tagData.Count++
			tags[tag] = tagData
		} else {
			tags[tag] = Tag{Name: tag, Color: "#446B6E", Count: 1}
		}
	}
	tagsMutex.Unlock()

	if c.Artist != "Unknown" || c.StoryArc != "" {
		inker := sanitizeFilename(c.Artist)
		storyArc := sanitizeFilename(c.StoryArc)
		if inker == "" {
			inker = "Unknown"
		}
		if storyArc == "" {
			storyArc = "No_StoryArc"
		}
		newDir := filepath.Join(libraryPath, inker, storyArc)
		os.MkdirAll(newDir, 0755)
		filename := filepath.Base(c.FilePath)
		newPath := filepath.Join(newDir, filename)
		if newPath != c.FilePath {
			if err := os.Rename(c.FilePath, newPath); err == nil {
				c.FilePath = newPath
			}
		}
	}

	comics[decodedID] = c
	comicsMutex.Unlock()

	passwordsMutex.Lock()
	comicPasswords[decodedID] = validPassword
	passwordsMutex.Unlock()

	debounceSave()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Password found and applied",
		"comic":   c,
	})
}

func handleSetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/set-password/")
	decodedID, err := url.QueryUnescape(id)
	if err != nil {
		decodedID = id
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	comicsMutex.Lock()
	comic, exists := comics[decodedID]
	if !exists {
		comic, exists = comics[id]
	}
	comicsMutex.Unlock()

	if !exists {
		http.Error(w, "Comic not found", http.StatusNotFound)
		return
	}

	if !comic.Encrypted {
		http.Error(w, "Comic not encrypted", http.StatusBadRequest)
		return
	}

	// Use the validation function
	if !validatePassword(comic.FilePath, req.Password) {
		http.Error(w, "Invalid password", http.StatusBadRequest)
		return
	}

	// Password is valid - save it
	comicsMutex.Lock()
	c := comics[decodedID]
	c.Password = req.Password
	c.HasPassword = true
	comics[decodedID] = c
	comicsMutex.Unlock()

	passwordsMutex.Lock()
	comicPasswords[decodedID] = req.Password
	passwordsMutex.Unlock()

	// Extract metadata with the valid password
	comicsMutex.Lock()
	c = comics[decodedID]

	// IMPORTANT: Set password before extraction so it can decrypt
	if c.FileType == ".cbt" {
		extractCBTMetadata(&c)
	} else if c.FileType == ".cbz" {
		extractCBZMetadataInternal(&c)
	}

	// Update tags
	tagsMutex.Lock()
	for _, tag := range c.Tags {
		if tagData, exists := tags[tag]; exists {
			tagData.Count++
			tags[tag] = tagData
		} else {
			tags[tag] = Tag{Name: tag, Color: "#446B6E", Count: 1}
		}
	}
	tagsMutex.Unlock()

	// Auto-organize if we have metadata
	if c.Artist != "Unknown" || c.StoryArc != "" {
		inker := sanitizeFilename(c.Artist)
		storyArc := sanitizeFilename(c.StoryArc)
		if inker == "" {
			inker = "Unknown"
		}
		if storyArc == "" {
			storyArc = "No_StoryArc"
		}
		newDir := filepath.Join(libraryPath, inker, storyArc)
		os.MkdirAll(newDir, 0755)
		filename := filepath.Base(c.FilePath)
		newPath := filepath.Join(newDir, filename)
		if newPath != c.FilePath {
			if err := os.Rename(c.FilePath, newPath); err == nil {
				c.FilePath = newPath
			}
		}
	}

	comics[decodedID] = c
	comicsMutex.Unlock()

	debounceSave()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Password set successfully",
		"comic":   c,
	})
}

func validatePassword(filePath string, password string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	if ext == ".cbt" {
		return validateCBTPassword(filePath, password)
	}

	if ext == ".cbz" {
		yr, err := yzip.OpenReader(filePath)
		if err != nil {
			return false
		}
		defer yr.Close()

		// Try ComicInfo.xml first
		for _, f := range yr.File {
			if strings.ToLower(f.Name) == "comicinfo.xml" {
				if !f.IsEncrypted() {
					return true
				}

				f.SetPassword(password)
				rc, err := f.Open()
				if err != nil {
					return false
				}

				buf := make([]byte, 100)
				n, err := rc.Read(buf)
				rc.Close()

				if err != nil && err != io.EOF {
					return false
				}

				if n > 0 && strings.Contains(string(buf[:n]), "<?xml") {
					return true
				}
				return false
			}
		}

		// Try first image
		for _, f := range yr.File {
			if f.FileInfo().IsDir() {
				continue
			}

			ext := strings.ToLower(filepath.Ext(f.Name))
			isImage := ext == ".png" || ext == ".jpg" || ext == ".jpeg" ||
				ext == ".gif" || ext == ".avif" || ext == ".jxl" ||
				ext == ".webp" || ext == ".bmp" || ext == ".jp2"

			if !isImage {
				continue
			}

			if !f.IsEncrypted() {
				return true
			}

			f.SetPassword(password)
			rc, err := f.Open()
			if err != nil {
				return false
			}

			_, _, err = image.DecodeConfig(rc)
			rc.Close()

			return err == nil
		}
	}

	return false
}

func handleBookmark(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/bookmark/"), "/")
	if len(parts) == 0 {
		http.Error(w, "Comic ID required", http.StatusBadRequest)
		return
	}

	id := parts[0]
	decodedID, err := url.QueryUnescape(id)
	if err != nil {
		decodedID = id
	}

	comicsMutex.Lock()
	defer comicsMutex.Unlock()

	comic, exists := comics[decodedID]
	if !exists {
		comic, exists = comics[id]
		if !exists {
			http.Error(w, "Comic not found", http.StatusNotFound)
			return
		}
	}

	switch r.Method {
	case http.MethodPost:
		var req struct {
			Page int `json:"page"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if comic.Bookmarks == nil {
			comic.Bookmarks = []int{}
		}

		found := false
		for _, p := range comic.Bookmarks {
			if p == req.Page {
				found = true
				break
			}
		}

		if !found {
			comic.Bookmarks = append(comic.Bookmarks, req.Page)
			sort.Ints(comic.Bookmarks)
		}

		comics[decodedID] = comic
		debounceSave()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Bookmark added",
			"bookmarks": comic.Bookmarks,
		})

	case http.MethodDelete:
		if len(parts) < 2 {
			http.Error(w, "Page number required", http.StatusBadRequest)
			return
		}

		var pageNum int
		fmt.Sscanf(parts[1], "%d", &pageNum)

		if comic.Bookmarks == nil {
			comic.Bookmarks = []int{}
		}

		newBookmarks := []int{}
		for _, p := range comic.Bookmarks {
			if p != pageNum {
				newBookmarks = append(newBookmarks, p)
			}
		}

		comic.Bookmarks = newBookmarks
		comics[decodedID] = comic
		debounceSave()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Bookmark removed",
			"bookmarks": comic.Bookmarks,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleComicFile(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/comic/"), "/")
	id := parts[0]

	decodedID, err := url.QueryUnescape(id)
	if err != nil {
		decodedID = id
	}

	comicsMutex.RLock()
	comic, exists := comics[decodedID]
	if !exists {
		comic, exists = comics[id]
	}
	comicsMutex.RUnlock()

	if !exists {
		http.Error(w, "Comic not found", http.StatusNotFound)
		return
	}

	if len(parts) > 1 && parts[1] == "page" && len(parts) > 2 {
		pageNum := parts[2]
		serveComicPage(w, r, comic, pageNum)
		return
	}

	http.ServeFile(w, r, comic.FilePath)
}

func serveComicPage(w http.ResponseWriter, r *http.Request, comic Comic, pageNum string) {
	// Handle CBT files
	if comic.FileType == ".cbt" {
		serveCBTPage(w, r, comic, pageNum)
		return
	}

	// Handle CBZ files
	if comic.FileType != ".cbz" {
		http.Error(w, "Only CBZ and CBT formats supported for page viewing", http.StatusBadRequest)
		return
	}

	// Get password from memory if needed
	passwordsMutex.RLock()
	password, hasPassword := comicPasswords[comic.ID]
	passwordsMutex.RUnlock()

	if comic.Encrypted && !hasPassword {
		http.Error(w, "Password required", http.StatusUnauthorized)
		return
	}

	var pageIdx int
	fmt.Sscanf(pageNum, "%d", &pageIdx)

	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
		http.Error(w, "Error reading comic", http.StatusInternalServerError)
		return
	}
	defer yr.Close()

	var imageFiles []*yzip.File
	for _, f := range yr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".avif" ||
			ext == ".jxl" || ext == ".jp2" || ext == ".webp" || ext == ".gif" || ext == ".bmp" {
			imageFiles = append(imageFiles, f)
		}
	}

	sort.Slice(imageFiles, func(i, j int) bool {
		return imageFiles[i].Name < imageFiles[j].Name
	})

	if pageIdx < 0 || pageIdx >= len(imageFiles) {
		http.Error(w, "Page not found", http.StatusNotFound)
		return
	}

	targetFile := imageFiles[pageIdx]

	if targetFile.IsEncrypted() {
		if hasPassword {
			targetFile.SetPassword(password)
		} else {
			http.Error(w, "Comic requires password", http.StatusUnauthorized)
			return
		}
	}

	rc, err := targetFile.Open()
	if err != nil {
		http.Error(w, "Error reading page", http.StatusInternalServerError)
		return
	}
	defer rc.Close()

	ext := strings.ToLower(filepath.Ext(targetFile.Name))
	contentType := getContentType(ext)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")

	buf := make([]byte, 32*1024)
	_, err = io.CopyBuffer(w, rc, buf)
	if err != nil {
		log.Printf("Error streaming page to client: %v", err)
	}
}

func handleComicPages(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/pages/")
	decodedID, err := url.QueryUnescape(id)
	if err != nil {
		decodedID = id
	}

	comicsMutex.RLock()
	comic, exists := comics[decodedID]
	if !exists {
		comic, exists = comics[id]
	}
	comicsMutex.RUnlock()

	if !exists {
		http.Error(w, "Comic not found", http.StatusNotFound)
		return
	}

	// Check if we have password
	passwordsMutex.RLock()
	password, hasPassword := comicPasswords[comic.ID]
	passwordsMutex.RUnlock()

	if comic.Encrypted && !hasPassword {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"needs_password": true,
			"page_count":     0,
			"pages":          []string{},
		})
		return
	}

	// Load metadata on first access (if not already loaded)
	if comic.Series == "" && comic.Title == "" {
		loadComicMetadataLazy(comic.ID)
		comicsMutex.RLock()
		comic = comics[comic.ID]
		comicsMutex.RUnlock()
	}

	// Handle CBT files
	if comic.FileType == ".cbt" {
		count, err := getCBTPageCount(comic)
		if err != nil {
			http.Error(w, "Error reading comic", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"page_count": count,
			"pages":      []string{},
		})
		return
	}

	// Handle CBZ files
	if comic.FileType != ".cbz" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"page_count": 0,
			"pages":      []string{},
		})
		return
	}

	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
		http.Error(w, "Error reading comic", http.StatusInternalServerError)
		return
	}
	defer yr.Close()

	var imageFiles []string
	for _, f := range yr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".avif" ||
			ext == ".jxl" || ext == ".jp2" || ext == ".webp" || ext == ".gif" || ext == ".bmp" {

			// Set password if encrypted
			if f.IsEncrypted() && hasPassword {
				f.SetPassword(password)
			}

			imageFiles = append(imageFiles, f.Name)
		}
	}

	sort.Strings(imageFiles)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"page_count": len(imageFiles),
		"pages":      imageFiles,
	})
}

func processComic(filePath, filename string, modTime time.Time) Comic {
	comic := Comic{
		ID:           generateToken(),
		Filename:     filename,
		FilePath:     filePath,
		FileType:     strings.ToLower(filepath.Ext(filename)),
		UploadedAt:   time.Now(),
		Artist:       "Unknown",
		Tags:         []string{},
		Bookmarks:    []int{},
		LastModified: modTime,
		Encrypted:    false,
		HasPassword:  false,
	}

	// Check if encrypted based on file type
	if comic.FileType == ".cbz" {
		yr, err := yzip.OpenReader(comic.FilePath)
		if err == nil {
			for _, f := range yr.File {
				if f.IsEncrypted() {
					comic.Encrypted = true
					break
				}
			}
			yr.Close()
		}
	} else if comic.FileType == ".cbt" {
		encrypted, err := isTarEncrypted(comic.FilePath)
		if err == nil {
			comic.Encrypted = encrypted
		}

		// IMPORTANT: Extract metadata for unencrypted CBT files
		if !encrypted {
			extractCBTMetadata(&comic)

			// Update tag counts for newly discovered tags
			tagsMutex.Lock()
			for _, tag := range comic.Tags {
				if tagData, exists := tags[tag]; exists {
					tagData.Count++
					tags[tag] = tagData
				} else {
					tags[tag] = Tag{Name: tag, Color: "#446B6E", Count: 1}
				}
			}
			tagsMutex.Unlock()
		}
	}

	// Extract artist from directory structure
	parentDir := filepath.Dir(filePath)
	if filepath.Base(parentDir) != "Unorganized" {
		dirName := filepath.Base(filepath.Dir(parentDir))
		// Only override if metadata didn't provide an artist
		if comic.Artist == "Unknown" {
			comic.Artist = dirName
		}
	}

	comic.CoverImage = "/api/cover/" + url.QueryEscape(comic.ID)

	return comic
}


func loadComicMetadataLazy(comicID string) error {
	comicsMutex.Lock()
	defer comicsMutex.Unlock()

	comic, exists := comics[comicID]
	if !exists {
		return fmt.Errorf("comic not found")
	}

	// Already has metadata, skip
	if comic.Series != "" || comic.Title != "" {
		return nil
	}

	// Check if we have a password
	passwordsMutex.RLock()
	password, hasPassword := comicPasswords[comic.ID]
	passwordsMutex.RUnlock()

	if comic.Encrypted && !hasPassword {
		return fmt.Errorf("password required")
	}

	// Set password if we have it
	if hasPassword {
		comic.Password = password
		comic.HasPassword = true
	}

	// Extract metadata NOW (works for both CBZ and CBT)
	extractMetadata(&comic)

	// Update tags
	tagsMutex.Lock()
	for _, tag := range comic.Tags {
		if tagData, exists := tags[tag]; exists {
			tagData.Count++
			tags[tag] = tagData
		} else {
			tags[tag] = Tag{Name: tag, Color: "#446B6E", Count: 1}
		}
	}
	tagsMutex.Unlock()

	// Auto-organize if we have metadata
	if comic.Artist != "Unknown" || comic.StoryArc != "" {
		inker := sanitizeFilename(comic.Artist)
		storyArc := sanitizeFilename(comic.StoryArc)
		if inker == "" {
			inker = "Unknown"
		}
		if storyArc == "" {
			storyArc = "No_StoryArc"
		}
		newDir := filepath.Join(libraryPath, inker, storyArc)
		os.MkdirAll(newDir, 0755)
		filename := filepath.Base(comic.FilePath)
		newPath := filepath.Join(newDir, filename)
		if newPath != comic.FilePath {
			if err := os.Rename(comic.FilePath, newPath); err == nil {
				comic.FilePath = newPath
			}
		}
	}

	comics[comicID] = comic
	debounceSave()

	return nil
}

func extractMetadata(comic *Comic) {
	if comic.FileType == ".cbz" {
		extractCBZMetadataInternal(comic)
	} else if comic.FileType == ".cbt" {
		extractCBTMetadata(comic)
	}
}

func extractCBZMetadataInternal(comic *Comic) {
	if comic.FileType != ".cbz" {
		return
	}

	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
		return
	}
	defer yr.Close()

	for _, f := range yr.File {
		if strings.ToLower(f.Name) != "comicinfo.xml" {
			continue
		}

		if f.IsEncrypted() && comic.Password != "" {
			f.SetPassword(comic.Password)
		}

		tmp, err := os.CreateTemp("", "comic-metadata-*.xml")
		if err != nil {
			return
		}
		tmpPath := tmp.Name()
		defer os.Remove(tmpPath)
		defer tmp.Close()

		rc, err := f.Open()
		if err != nil {
			return
		}

		_, err = io.Copy(tmp, rc)
		rc.Close()
		if err != nil {
			return
		}

		tmp.Seek(0, 0)
		var info ComicInfo
		if err := xml.NewDecoder(tmp).Decode(&info); err == nil {
			comic.Title = info.Title
			comic.Series = info.Series
			comic.StoryArc = info.StoryArc
			comic.Number = info.Number
			comic.Publisher = info.Publisher
			comic.Year = info.Year
			comic.PageCount = info.PageCount

			if info.Artist != "" {
				comic.Artist = info.Artist
			} else if info.Writer != "" {
				comic.Artist = info.Writer
			}

			tagsSource := info.TagsXml
			if tagsSource == "" {
				tagsSource = info.Genre
			}

			if tagsSource != "" {
				rawTags := strings.FieldsFunc(tagsSource, func(r rune) bool {
					return r == ',' || r == ';' || r == '|'
				})

				comic.Tags = make([]string, 0, len(rawTags))
				for _, tag := range rawTags {
					trimmed := strings.TrimSpace(tag)
					if trimmed != "" {
						comic.Tags = append(comic.Tags, trimmed)
					}
				}
			}
		}
		break
	}
}

func scanLibrary() {
	comicsMutex.RLock()
	existingPaths := make(map[string]string)
	for id, comic := range comics {
		existingPaths[comic.FilePath] = id
	}
	comicsMutex.RUnlock()

	filepath.Walk(libraryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".cbz" && ext != ".cbt" {
			return nil
		}

		comicsMutex.RLock()
		id, exists := existingPaths[path]
		var currentMTime time.Time
		if exists {
			currentMTime = comics[id].LastModified
		}
		comicsMutex.RUnlock()

		// Skip if unchanged
		if exists && currentMTime.Equal(info.ModTime()) {
			return nil
		}

		// Modified or new file
		if exists {
			comicsMutex.Lock()
			c := comics[id]
			c.LastModified = info.ModTime()

			// Re-extract metadata if file changed
			if ext == ".cbt" {
				// Check if encrypted
				encrypted, _ := isTarEncrypted(path)
				if !encrypted {
					extractCBTMetadata(&c)
				}
			}

			comics[id] = c
			comicsMutex.Unlock()
		} else {
			// New file - process it fully
			comic := processComic(path, info.Name(), info.ModTime())
			comicsMutex.Lock()
			comics[comic.ID] = comic
			comicsMutex.Unlock()
		}

		return nil
	})

	// Remove deleted files
	comicsMutex.Lock()
	for id, comic := range comics {
		if _, err := os.Stat(comic.FilePath); os.IsNotExist(err) {
			for _, tag := range comic.Tags {
				updateTagCount(tag, -1)
			}
			delete(comics, id)
		}
	}
	comicsMutex.Unlock()

	debounceSave()
	runtime.GC()
	debug.FreeOSMemory()
}


func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		sessionsMutex.RLock()
		session, exists := sessions[cookie.Value]
		sessionsMutex.RUnlock()

		if !exists || time.Now().After(session.ExpiresAt) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}
// ── bbolt helpers ──────────────────────────────────────────────────────────

// userBucket returns the per-user bucket name for a given data type.
func userBucket(kind, username string) []byte {
	return []byte(kind + ":" + username)
}

// ensureUserBuckets creates per-user buckets inside a write transaction.
func ensureUserBuckets(tx *bolt.Tx, username string) error {
	for _, kind := range []string{"comics", "tags", "passwords", "shares", "categories"} {
		if _, err := tx.CreateBucketIfNotExists(userBucket(kind, username)); err != nil {
			return err
		}
	}
	return nil
}

// ── users / admin ──────────────────────────────────────────────────────────

func loadUsers() {
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		if b == nil {
			return nil
		}

		// Users
		if data := b.Get([]byte("users")); len(data) > 0 {
			if err := json.Unmarshal(data, &users); err != nil {
				log.Printf("Error unmarshaling users: %v", err)
			}
		}

		// Admin config
		if data := b.Get([]byte("admin")); len(data) > 0 {
			var adminConfig struct{ RegistrationEnabled bool }
			if err := json.Unmarshal(data, &adminConfig); err == nil {
				registrationEnabled = adminConfig.RegistrationEnabled
			}
		}
		return nil
	})
}

func saveUsers() {
	data, _ := json.Marshal(users)
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		if b == nil {
			return nil
		}
		return b.Put([]byte("users"), data)
	})
}

func saveAdminConfig() {
	config := struct{ RegistrationEnabled bool }{RegistrationEnabled: registrationEnabled}
	data, _ := json.Marshal(config)
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		if b == nil {
			return nil
		}
		return b.Put([]byte("admin"), data)
	})
}

// ── comics ─────────────────────────────────────────────────────────────────

func saveComics() {
	comicsMutex.RLock()
	snapshot := make(map[string]Comic, len(comics))
	for k, v := range comics {
		snapshot[k] = v
	}
	comicsMutex.RUnlock()

	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket("comics", currentUser))
		if b == nil {
			return nil
		}
		// Delete all existing keys then rewrite (simplest correctness guarantee)
		b.ForEach(func(k, _ []byte) error { return b.Delete(k) })
		for id, comic := range snapshot {
			data, _ := json.Marshal(comic)
			b.Put([]byte(id), data)
		}
		return nil
	})
}

func loadComics() {
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket("comics", currentUser))
		if b == nil {
			return nil
		}
		comicsMutex.Lock()
		defer comicsMutex.Unlock()
		b.ForEach(func(k, v []byte) error {
			var c Comic
			if err := json.Unmarshal(v, &c); err == nil {
				comics[string(k)] = c
			}
			return nil
		})
		return nil
	})
}

// ── tags ───────────────────────────────────────────────────────────────────

func saveTags() {
	tagsMutex.RLock()
	snapshot := make(map[string]Tag, len(tags))
	for k, v := range tags {
		snapshot[k] = v
	}
	tagsMutex.RUnlock()

	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket("tags", currentUser))
		if b == nil {
			return nil
		}
		b.ForEach(func(k, _ []byte) error { return b.Delete(k) })
		for name, tag := range snapshot {
			data, _ := json.Marshal(tag)
			b.Put([]byte(name), data)
		}
		return nil
	})
}

func loadTags() {
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket("tags", currentUser))
		if b == nil {
			return nil
		}
		tagsMutex.Lock()
		defer tagsMutex.Unlock()
		b.ForEach(func(k, v []byte) error {
			var t Tag
			if err := json.Unmarshal(v, &t); err == nil {
				tags[string(k)] = t
			}
			return nil
		})
		return nil
	})
}

// ── passwords ──────────────────────────────────────────────────────────────

func loadPasswordsWithKey(key []byte) {
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket("passwords", currentUser))
		if b == nil {
			return nil
		}
		b64data := b.Get([]byte("encrypted"))
		if len(b64data) == 0 {
			return nil
		}
		encrypted, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64data)))
		if err != nil {
			return nil
		}
		decrypted, err := decryptAES(encrypted, key)
		if err != nil {
			return nil
		}
		passwordsMutex.Lock()
		defer passwordsMutex.Unlock()
		json.Unmarshal(decrypted, &comicPasswords)
		return nil
	})
}

func savePasswords() {
	if len(currentEncryptionKey) == 0 {
		return
	}

	passwordsMutex.Lock()
	data, err := json.Marshal(comicPasswords)
	passwordsMutex.Unlock()
	if err != nil {
		return
	}

	encrypted, err := encryptAES(data, currentEncryptionKey)
	if err != nil {
		return
	}

	b64 := base64.StdEncoding.EncodeToString(encrypted)
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket("passwords", currentUser))
		if b == nil {
			return nil
		}
		return b.Put([]byte("encrypted"), []byte(b64))
	})
}

// ── share links ────────────────────────────────────────────────────────────

func loadShareLinks(username string) {
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket("shares", username))
		if b == nil {
			return nil
		}
		now := time.Now()
		shareLinksMutex.Lock()
		defer shareLinksMutex.Unlock()
		b.ForEach(func(k, v []byte) error {
			var sl ShareLink
			if err := json.Unmarshal(v, &sl); err != nil {
				return nil
			}
			if sl.Permanent || sl.ExpiresAt == nil || sl.ExpiresAt.After(now) {
				shareLinks[sl.ID] = sl
			}
			return nil
		})
		return nil
	})
}

func saveShareLinks(username string) {
	shareLinksMutex.RLock()
	toSave := make([]ShareLink, 0)
	for _, sl := range shareLinks {
		if sl.Username == username {
			toSave = append(toSave, sl)
		}
	}
	shareLinksMutex.RUnlock()

	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket("shares", username))
		if b == nil {
			return nil
		}
		// Clear existing entries for this user then rewrite
		b.ForEach(func(k, _ []byte) error { return b.Delete(k) })
		for _, sl := range toSave {
			data, _ := json.Marshal(sl)
			b.Put([]byte(sl.ID), data)
		}
		return nil
	})
}

// Debounced save for comics and tags
func debounceSave() {
	if saveTimer != nil {
		saveTimer.Stop()
	}
	saveTimer = time.AfterFunc(5*time.Second, func() {
		saveComics()
		saveTags()
		savePasswords() // Also save passwords if needed
	})
}

func updateTagCount(tagName string, delta int) {
	tagsMutex.Lock()
	defer tagsMutex.Unlock()

	if tag, exists := tags[tagName]; exists {
		tag.Count += delta
		if tag.Count < 0 {
			tag.Count = 0
		}
		tags[tagName] = tag
	}
}

func generateToken() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func sanitizeFilename(filename string) string {
	filename = strings.ReplaceAll(filename, " ", "_")
	reg, _ := regexp.Compile("[^a-zA-Z0-9-_]+")
	sanitized := reg.ReplaceAllString(filename, "_")
	sanitized = strings.Trim(sanitized, "_")
	if sanitized == "" {
		return "Unknown"
	}
	return sanitized
}

func getContentType(ext string) string {
	switch ext {
	case ".png":
		return "image/png"
	case ".webp":
		return "image/webp"
	case ".avif":
		return "image/avif"
	case ".jxl":
		return "image/jxl"
	case ".jp2":
		return "image/jp2"
	case ".gif":
		return "image/gif"
	case ".bmp":
		return "image/bmp"
	default:
		return "image/jpeg"
	}
}

func deriveKey(seed string) []byte {
	hash := sha256.Sum256([]byte(seed))
	return hash[:32]
}

func decryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// FIX: Allocate a separate slice for plaintext so the
	// original 'data' slice can be garbage collected.
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func encryptAES(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return append(iv, ciphertext...), nil
}

func serveUI(w http.ResponseWriter, r *http.Request) {
	data, err := templateFS.ReadFile("templates/index.html")
	if err != nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(data)
}

// Share link handlers

func cleanupExpiredShareLinks() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		now := time.Now()
		shareLinksMutex.Lock()
		// Group expired links by user so we can save per-user files
		toSave := make(map[string]bool)
		for token, sl := range shareLinks {
			if !sl.Permanent && sl.ExpiresAt != nil && sl.ExpiresAt.Before(now) {
				delete(shareLinks, token)
				toSave[sl.Username] = true
			}
		}
		shareLinksMutex.Unlock()
		for username := range toSave {
			saveShareLinks(username)
		}
	}
}

// POST /api/share/create/<comicID>
// Body: {"permanent": true} or {"expires_at": "2026-03-01T00:00:00Z"}
func handleCreateShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getCurrentUser(r)
	id := strings.TrimPrefix(r.URL.Path, "/api/share/create/")
	decodedID, _ := url.QueryUnescape(id)

	comicsMutex.RLock()
	comic, exists := comics[decodedID]
	comicsMutex.RUnlock()
	if !exists {
		http.Error(w, "Comic not found", http.StatusNotFound)
		return
	}

	var req struct {
		Permanent     bool       `json:"permanent"`
		ExpiresAt     *time.Time `json:"expires_at,omitempty"`
		SharePassword string     `json:"share_password,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if !req.Permanent && req.ExpiresAt == nil {
		http.Error(w, "Must set permanent:true or provide expires_at", http.StatusBadRequest)
		return
	}

	// Snapshot the comic's password so the share link is self-contained
	// (works even when the owner is not logged in)
	var comicPassword string
	if comic.Encrypted {
		passwordsMutex.RLock()
		comicPassword = comicPasswords[comic.ID]
		passwordsMutex.RUnlock()
		}

	sl := ShareLink{
		ID:             generateToken(),
		ComicID:        decodedID,
		Username:       user.Username,
		CreatedAt:      time.Now(),
		Permanent:      req.Permanent,
		ExpiresAt:      req.ExpiresAt,
		ComicPassword:  comicPassword, // in-memory only, never written to disk as plaintext
		ComicEncrypted: comic.Encrypted,
		ComicFilePath:  comic.FilePath,
		ComicFileType:  comic.FileType,
		ComicTitle:     comic.Title,
		ComicFilename:  comic.Filename,
	}

	if comic.Encrypted && req.SharePassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.SharePassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing share password", http.StatusInternalServerError)
			return
		}
		sl.SharePasswordHash = string(hash)

		if comicPassword != "" {
			key := deriveKey(req.SharePassword)
			enc, err := encryptAES([]byte(comicPassword), key)
			if err != nil {
				http.Error(w, "Error encrypting comic password", http.StatusInternalServerError)
				return
			}
			sl.EncryptedComicPassword = base64.StdEncoding.EncodeToString(enc)
		}
	}

	shareLinksMutex.Lock()
	shareLinks[sl.ID] = sl
	shareLinksMutex.Unlock()
	saveShareLinks(user.Username)

	// Never expose the plaintext comic password or the bcrypt hash via API
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":              sl.ID,
		"url":                "/s/" + sl.ID,
		"comic_encrypted":    sl.ComicEncrypted,
		"has_share_password": sl.SharePasswordHash != "",
	})
}

// POST /api/share/unlock/<token>
func handleShareUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/api/share/unlock/")

	shareLinksMutex.RLock()
	sl, exists := shareLinks[token]
	shareLinksMutex.RUnlock()

	if !exists {
		http.Error(w, "Share link not found", http.StatusNotFound)
		return
	}
	if !sl.Permanent && sl.ExpiresAt != nil && sl.ExpiresAt.Before(time.Now()) {
		http.Error(w, "Share link has expired", http.StatusGone)
		return
	}
	if sl.SharePasswordHash == "" {
		http.Error(w, "This share link does not require a password", http.StatusBadRequest)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		http.Error(w, "Password required", http.StatusBadRequest)
		return
	}

	// Verify the share-level password against the stored bcrypt hash
	if err := bcrypt.CompareHashAndPassword([]byte(sl.SharePasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	// Decrypt the comic password using a key derived from the share password
	var comicPassword string
	if sl.EncryptedComicPassword != "" {
		enc, err := base64.StdEncoding.DecodeString(sl.EncryptedComicPassword)
		if err != nil {
			http.Error(w, "Corrupt share data", http.StatusInternalServerError)
			return
		}
		key := deriveKey(req.Password)
		plain, err := decryptAES(enc, key)
		if err != nil {
			http.Error(w, "Failed to decrypt comic password", http.StatusInternalServerError)
			return
		}
		comicPassword = string(plain)
	}

	// Store an unlock session keyed by shareToken+":"+nonce
	nonce := generateToken()
	sessionKey := token + ":" + nonce
	shareUnlockSessionsMutex.Lock()
	shareUnlockSessions[sessionKey] = shareUnlockSession{
		ComicPassword: comicPassword,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	shareUnlockSessionsMutex.Unlock()

	// Cookie names cannot contain special chars like '=' (from base64 padding).
	// Use a hex-safe version of the token for the cookie name.
	safeCookieName := "sul_" + strings.NewReplacer("=", "", "+", "", "/", "").Replace(token)
	http.SetCookie(w, &http.Cookie{
		Name:     safeCookieName,
		Value:    nonce,
		Path:     "/s/" + token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Unlocked"})
}

// GET /api/share/list
func handleListShares(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	now := time.Now()

	shareLinksMutex.RLock()
	var links []ShareLink
	for _, sl := range shareLinks {
		if sl.Username == user.Username {
			if sl.Permanent || sl.ExpiresAt == nil || sl.ExpiresAt.After(now) {
				links = append(links, sl)
			}
		}
	}
	shareLinksMutex.RUnlock()

	// Sort by created
	sort.Slice(links, func(i, j int) bool {
		return links[i].CreatedAt.After(links[j].CreatedAt)
	})

	// Build a safe response that never exposes the bcrypt hash or encrypted comic password
	type SafeShareLink struct {
		ID             string     `json:"id"`
		ComicID        string     `json:"comic_id"`
		Username       string     `json:"username"`
		CreatedAt      time.Time  `json:"created_at"`
		ExpiresAt      *time.Time `json:"expires_at,omitempty"`
		Permanent      bool       `json:"permanent"`
		ComicEncrypted bool       `json:"comic_encrypted"`
		HasSharePassword bool     `json:"has_share_password"`
		ComicTitle     string     `json:"comic_title"`
		ComicFilename  string     `json:"comic_filename"`
	}
	safe := make([]SafeShareLink, 0, len(links))
	for _, sl := range links {
		safe = append(safe, SafeShareLink{
			ID:               sl.ID,
			ComicID:          sl.ComicID,
			Username:         sl.Username,
			CreatedAt:        sl.CreatedAt,
			ExpiresAt:        sl.ExpiresAt,
			Permanent:        sl.Permanent,
			ComicEncrypted:   sl.ComicEncrypted,
			HasSharePassword: sl.SharePasswordHash != "",
			ComicTitle:       sl.ComicTitle,
			ComicFilename:    sl.ComicFilename,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(safe)
}

// DELETE /api/share/delete/<token>
func handleDeleteShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getCurrentUser(r)
	token := strings.TrimPrefix(r.URL.Path, "/api/share/delete/")

	shareLinksMutex.Lock()
	sl, exists := shareLinks[token]
	if exists && sl.Username == user.Username {
		delete(shareLinks, token)
	}
	shareLinksMutex.Unlock()

	if !exists {
		http.Error(w, "Share not found", http.StatusNotFound)
		return
	}
	saveShareLinks(user.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Deleted"})
}

// GET /s/<token> public share page (no auth required)
func handleSharedComic(w http.ResponseWriter, r *http.Request) {
	// Strip the leading /s/ then split off the token (everything up to the next /)
	withoutPrefix := strings.TrimPrefix(r.URL.Path, "/s/")
	parts := strings.SplitN(withoutPrefix, "/", 2)
	token := parts[0]
	rest := ""
	if len(parts) > 1 {
		rest = "/" + parts[1]
	}

	shareLinksMutex.RLock()
	sl, exists := shareLinks[token]
	shareLinksMutex.RUnlock()

	if !exists {
		http.Error(w, "Share link not found or expired", http.StatusNotFound)
		return
	}
	if !sl.Permanent && sl.ExpiresAt != nil && sl.ExpiresAt.Before(time.Now()) {
		http.Error(w, "Share link has expired", http.StatusGone)
		return
	}

	var comicPassword string
	if sl.SharePasswordHash != "" {
		// Only grant the password if the visitor has a valid unlock cookie
		safeCookieName := "sul_" + strings.NewReplacer("=", "", "+", "", "/", "").Replace(token)
		if cookie, err := r.Cookie(safeCookieName); err == nil {
			sessionKey := token + ":" + cookie.Value
			shareUnlockSessionsMutex.RLock()
			us, ok := shareUnlockSessions[sessionKey]
			shareUnlockSessionsMutex.RUnlock()
			if ok && time.Now().Before(us.ExpiresAt) {
				comicPassword = us.ComicPassword
			}
		}
	} else {
		// No share-level password — use the in-memory plaintext directly
		comicPassword = sl.ComicPassword
	}

	// Build a lightweight Comic struct from the share link's snapshotted data.
	comic := Comic{
		ID:        sl.ComicID,
		FilePath:  sl.ComicFilePath,
		FileType:  sl.ComicFileType,
		Title:     sl.ComicTitle,
		Filename:  sl.ComicFilename,
		Password:  comicPassword,
		Encrypted: sl.ComicEncrypted,
		HasPassword: comicPassword != "",
	}

	switch {
	case rest == "" || rest == "/":
		serveSharedReaderPage(w, r, token, sl, comic)
	case rest == "/cover":
		ownerCachePath := filepath.Join(baseCachePath, sl.Username, comic.ID+".jpg")
		if _, err := os.Stat(ownerCachePath); err == nil {
			http.ServeFile(w, r, ownerCachePath)
		} else {
			// Try to generate cover on-the-fly using snapshotted data
			tmpCache := ownerCachePath
			os.MkdirAll(filepath.Dir(tmpCache), 0755)
			var genErr error
			if comic.FileType == ".cbt" {
				genErr = generateCBTCover(&comic, tmpCache)
			} else if comic.FileType == ".cbz" {
				genErr = generateCoverCacheLazy(&comic, tmpCache)
			}
			if genErr == nil {
				http.ServeFile(w, r, tmpCache)
			} else {
				http.Error(w, "Cover not available", http.StatusNotFound)
			}
		}
	case rest == "/pages":
		serveSharedPages(w, comic)
	case strings.HasPrefix(rest, "/page/"):
		pageNum := strings.TrimPrefix(rest, "/page/")
		serveSharedPage(w, r, comic, pageNum)
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

func serveSharedPages(w http.ResponseWriter, comic Comic) {
	w.Header().Set("Content-Type", "application/json")
	if comic.FileType == ".cbt" {
		count, err := getCBTPageCount(comic)
		if err != nil {
			http.Error(w, "Error reading comic", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"page_count": count})
		return
	}
	// CBZ
	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
		http.Error(w, "Error reading comic", http.StatusInternalServerError)
		return
	}
	defer yr.Close()
	count := 0
	for _, f := range yr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".avif" ||
			ext == ".jxl" || ext == ".jp2" || ext == ".webp" || ext == ".gif" || ext == ".bmp" {
			count++
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"page_count": count})
}

func serveSharedPage(w http.ResponseWriter, r *http.Request, comic Comic, pageNum string) {
	if comic.Encrypted && !comic.HasPassword {
		http.Error(w, "Comic requires password and none is stored for this share link", http.StatusUnauthorized)
		return
	}

	// For CBT, use the existing helper which accepts a Comic with Password set
	if comic.FileType == ".cbt" {
		// Temporarily register the password so serveCBTPage can find it
		if comic.HasPassword {
			passwordsMutex.Lock()
			prev, had := comicPasswords[comic.ID]
			comicPasswords[comic.ID] = comic.Password
			passwordsMutex.Unlock()
			defer func() {
				passwordsMutex.Lock()
				if had {
					comicPasswords[comic.ID] = prev
				} else {
					delete(comicPasswords, comic.ID)
				}
				passwordsMutex.Unlock()
			}()
		}
		serveCBTPage(w, r, comic, pageNum)
		return
	}

	// CBZ path inline implementation so we can inject the password directly
	// without touching the global comicPasswords map permanently
	var pageIdx int
	fmt.Sscanf(pageNum, "%d", &pageIdx)

	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
		http.Error(w, "Error reading comic", http.StatusInternalServerError)
		return
	}
	defer yr.Close()

	var imageFiles []*yzip.File
	for _, f := range yr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".avif" ||
			ext == ".jxl" || ext == ".jp2" || ext == ".webp" || ext == ".gif" || ext == ".bmp" {
			imageFiles = append(imageFiles, f)
		}
	}
	sort.Slice(imageFiles, func(i, j int) bool {
		return imageFiles[i].Name < imageFiles[j].Name
	})

	if pageIdx < 0 || pageIdx >= len(imageFiles) {
		http.Error(w, "Page not found", http.StatusNotFound)
		return
	}

	targetFile := imageFiles[pageIdx]
	if targetFile.IsEncrypted() {
		if comic.HasPassword {
			targetFile.SetPassword(comic.Password)
		} else {
			http.Error(w, "Comic requires password", http.StatusUnauthorized)
			return
		}
	}

	rc, err := targetFile.Open()
	if err != nil {
		http.Error(w, "Error reading page", http.StatusInternalServerError)
		return
	}
	defer rc.Close()

	ext := strings.ToLower(filepath.Ext(targetFile.Name))
	w.Header().Set("Content-Type", getContentType(ext))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	buf := make([]byte, 32*1024)
	io.CopyBuffer(w, rc, buf)
}

func serveSharedReaderPage(w http.ResponseWriter, r *http.Request, token string, sl ShareLink, comic Comic) {
	title := comic.Title
	if title == "" {
		title = comic.Filename
	}

	// If the share link has a share-level password and the comic is encrypted,
	// check whether the visitor has already unlocked. If not, show the password gate.
	needsUnlock := sl.SharePasswordHash != "" && sl.ComicEncrypted && !comic.HasPassword
	if needsUnlock {
		// They might have a valid unlock cookie that we failed to resolve (e.g. expired session).
		// Either way, show the gate.
		serveSharePasswordGate(w, token, title)
		return
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>` + title + ` – Gopherbook Share</title>
<link href="/static/images/favicon/favicon.ico" rel="shortcut icon" type="image/x-icon">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1b1e2c;color:#bfbcb7;font-family:system-ui,sans-serif;min-height:100vh;display:flex;flex-direction:column}
header{background:#395E62;padding:10px 20px;display:flex;align-items:center;gap:12px}
header h1{color:#1b1e2c;font-size:20px}
.sub{font-size:13px;color:#1b1e2c;opacity:.8}
.controls{background:#1b1e2c;border-bottom:1px solid #395E62;padding:10px 20px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.btn{background:#395E62;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:14px}
.btn:hover{background:#446B6E}
.btn:disabled{opacity:.4;cursor:not-allowed}
.page-info{color:#bfbcb7;font-size:14px}
.reader{flex:1;display:flex;justify-content:center;align-items:center;overflow:hidden;background:#111}
#comicImage{max-width:100%;max-height:calc(100vh - 100px);object-fit:contain}
</style>
</head>
<body>
<header>
  <div>
    <h1>` + title + `</h1>
    <div class="sub">Shared via Gopherbook</div>
  </div>
</header>
<div class="controls">
  <button class="btn" id="prevBtn" onclick="prevPage()">← Prev</button>
  <span class="page-info">Page <span id="cur">1</span> / <span id="tot">?</span></span>
  <button class="btn" id="nextBtn" onclick="nextPage()">Next →</button>
</div>
<div class="reader">
  <img id="comicImage" alt="Comic page">
</div>
<script>
var base='/s/` + token + `';
var cur=0,tot=0;
fetch(base+'/pages').then(r=>r.json()).then(d=>{
  tot=d.page_count||0;
  document.getElementById('tot').textContent=tot;
  if(tot>0) loadPage(0);
});
function loadPage(n){
  if(n<0||n>=tot) return;
  cur=n;
  document.getElementById('cur').textContent=cur+1;
  document.getElementById('comicImage').src=base+'/page/'+cur;
  document.getElementById('prevBtn').disabled=cur===0;
  document.getElementById('nextBtn').disabled=cur===tot-1;
}
function prevPage(){loadPage(cur-1)}
function nextPage(){loadPage(cur+1)}
document.addEventListener('keydown',function(e){
  if(e.key==='ArrowRight'||e.key==='d') nextPage();
  if(e.key==='ArrowLeft'||e.key==='a') prevPage();
});
</script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// serveSharePasswordGate renders a minimal password entry page for protected share links.
func serveSharePasswordGate(w http.ResponseWriter, token, title string) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>` + title + ` – Gopherbook Share</title>
<link href="/static/images/favicon/favicon.ico" rel="shortcut icon" type="image/x-icon">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1b1e2c;color:#bfbcb7;font-family:system-ui,sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gate{background:#252836;border:1px solid #395E62;border-radius:12px;padding:40px;max-width:380px;width:90%;text-align:center}
.gate h2{color:#bfbcb7;font-size:20px;margin-bottom:8px}
.gate p{color:#8b949e;font-size:13px;margin-bottom:24px}
.gate input{width:100%;padding:10px 14px;background:#1b1e2c;border:1px solid #446B6E;border-radius:6px;color:#bfbcb7;font-size:15px;margin-bottom:12px;outline:none}
.gate input:focus{border-color:#395E62}
.gate button{width:100%;padding:10px;background:#395E62;color:#fff;border:none;border-radius:6px;font-size:15px;cursor:pointer}
.gate button:hover{background:#446B6E}
.error{color:#A55354;font-size:13px;margin-top:8px;min-height:18px}
</style>
</head>
<body>
<div class="gate">
  <h2>&#128274; Password Required</h2>
  <p>This shared comic is protected. Enter the share password to continue.</p>
  <input type="password" id="pw" placeholder="Enter share password" onkeydown="if(event.key==='Enter')unlock()">
  <button onclick="unlock()">Unlock</button>
  <div class="error" id="err"></div>
</div>
<script>
function unlock(){
  var pw=document.getElementById('pw').value;
  if(!pw) return;
  fetch('/api/share/unlock/` + token + `',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})})
    .then(function(r){
      if(r.ok){ window.location.reload(); }
      else{ document.getElementById('err').textContent='Incorrect password. Please try again.'; }
    }).catch(function(){ document.getElementById('err').textContent='Network error. Please try again.'; });
}
</script>
</body>
</html>`))
}

// ── Categories ─────────────────────────────────────────────────────────────

func saveCategories() {
	categoriesMutex.RLock()
	snapshot := make(map[string]Category, len(categories))
	for k, v := range categories {
		snapshot[k] = v
	}
	categoriesMutex.RUnlock()

	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket("categories", currentUser))
		if b == nil {
			return nil
		}
		b.ForEach(func(k, _ []byte) error { return b.Delete(k) })
		for id, cat := range snapshot {
			data, _ := json.Marshal(cat)
			b.Put([]byte(id), data)
		}
		return nil
	})
}

func loadCategories() {
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket("categories", currentUser))
		if b == nil {
			return nil
		}
		categoriesMutex.Lock()
		defer categoriesMutex.Unlock()
		b.ForEach(func(k, v []byte) error {
			var c Category
			if err := json.Unmarshal(v, &c); err == nil {
				categories[string(k)] = c
			}
			return nil
		})
		return nil
	})
}

func handleCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	categoriesMutex.RLock()
	list := make([]Category, 0, len(categories))
	for _, c := range categories {
		list = append(list, c)
	}
	categoriesMutex.RUnlock()

	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.Before(list[j].CreatedAt)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func handleCreateCategory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name     string   `json:"name"`
		ComicIDs []string `json:"comic_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	cat := Category{
		ID:        generateToken()[:16],
		Name:      req.Name,
		ComicIDs:  req.ComicIDs,
		CoverType: "collage",
		CreatedAt: time.Now(),
	}
	categoriesMutex.Lock()
	categories[cat.ID] = cat
	categoriesMutex.Unlock()
	saveCategories()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cat)
}

func handleUpdateCategory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/category/update/")
	id, _ = url.QueryUnescape(id)

	var req struct {
		Name     string   `json:"name"`
		ComicIDs []string `json:"comic_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	categoriesMutex.Lock()
	cat, exists := categories[id]
	if !exists {
		categoriesMutex.Unlock()
		http.Error(w, "Category not found", http.StatusNotFound)
		return
	}
	if req.Name != "" {
		cat.Name = req.Name
	}
	if req.ComicIDs != nil {
		cat.ComicIDs = req.ComicIDs
	}
	categories[id] = cat
	categoriesMutex.Unlock()
	saveCategories()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cat)
}

func handleDeleteCategory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/category/delete/")
	id, _ = url.QueryUnescape(id)

	categoriesMutex.Lock()
	cat, exists := categories[id]
	if exists {
		// Remove custom cover if any
		if cat.CoverPath != "" {
			os.Remove(cat.CoverPath)
		}
		// Remove generated collage cache
		collageCache := filepath.Join(cachePath, "cat_"+id+".jpg")
		os.Remove(collageCache)
		delete(categories, id)
	}
	categoriesMutex.Unlock()

	if !exists {
		http.Error(w, "Category not found", http.StatusNotFound)
		return
	}
	saveCategories()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Deleted"})
}

// handleCategorycover serves the cover image for a category.
// If cover_type == "upload" it serves the uploaded file.
// If cover_type == "collage" it generates / serves a 2x2 collage.
func handleCategorycover(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/category/cover/")
	id, _ = url.QueryUnescape(id)

	categoriesMutex.RLock()
	cat, exists := categories[id]
	categoriesMutex.RUnlock()
	if !exists {
		http.Error(w, "Category not found", http.StatusNotFound)
		return
	}

	// Uploaded custom cover
	if cat.CoverType == "upload" && cat.CoverPath != "" {
		if _, err := os.Stat(cat.CoverPath); err == nil {
			http.ServeFile(w, r, cat.CoverPath)
			return
		}
	}

	// Collage path
	cacheFile := filepath.Join(cachePath, "cat_"+id+".jpg")

	// Invalidation: regenerate if the comic list changed
	// (simple approach: always regenerate if cat has comics and cache is older than 1s after last write -
	//  instead just regenerate if cache missing or explicitly requested via ?regen=1)
	regen := r.URL.Query().Get("regen") == "1"
	if !regen {
		if _, err := os.Stat(cacheFile); err == nil {
			http.ServeFile(w, r, cacheFile)
			return
		}
	}

	if len(cat.ComicIDs) == 0 {
		http.Error(w, "No comics in category", http.StatusNotFound)
		return
	}

	// Collect cover images (up to 4)
	select {
	case coverGenSemaphore <- struct{}{}:
		defer func() { <-coverGenSemaphore }()
	case <-time.After(30 * time.Second):
		http.Error(w, "Busy, try again", http.StatusServiceUnavailable)
		return
	}

	var coverImages []image.Image
	comicsMutex.RLock()
	for _, comicID := range cat.ComicIDs {
		if len(coverImages) >= 4 {
			break
		}
		comic, ok := comics[comicID]
		if !ok {
			continue
		}
		coverCache := filepath.Join(cachePath, comic.ID+".jpg")
		if _, err := os.Stat(coverCache); err != nil {
			// Try to generate the individual cover first
			if comic.FileType == ".cbz" {
				generateCoverCacheLazy(&comic, coverCache)
			} else if comic.FileType == ".cbt" {
				generateCBTCover(&comic, coverCache)
			}
		}
		if f, err := os.Open(coverCache); err == nil {
			img, _, decErr := image.Decode(f)
			f.Close()
			if decErr == nil {
				coverImages = append(coverImages, img)
			}
		}
	}
	comicsMutex.RUnlock()

	if len(coverImages) == 0 {
		http.Error(w, "No covers available", http.StatusNotFound)
		return
	}

	// Build collage
	const tileW, tileH = 150, 210
	cols := 2
	if len(coverImages) == 1 {
		cols = 1
	}
	rows := (len(coverImages) + cols - 1) / cols
	totalW := cols * tileW
	totalH := rows * tileH

	collage := image.NewRGBA(image.Rect(0, 0, totalW, totalH))
	for i, img := range coverImages {
		resized := resize.Thumbnail(uint(tileW), uint(tileH), img, resize.Lanczos3)
		col := i % cols
		row := i / cols
		offsetX := col * tileW
		offsetY := row * tileH
		bounds := resized.Bounds()
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				collage.Set(offsetX+x-bounds.Min.X, offsetY+y-bounds.Min.Y, resized.At(x, y))
			}
		}
	}

	f, err := os.Create(cacheFile)
	if err != nil {
		http.Error(w, "Failed to write collage", http.StatusInternalServerError)
		return
	}
	jpeg.Encode(f, collage, &jpeg.Options{Quality: 85})
	f.Close()

	http.ServeFile(w, r, cacheFile)
}

// handleCategoryUploadCover handles a multipart upload of a custom cover image for a category.
func handleCategoryUploadCover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/category/upload-cover/")
	id, _ = url.QueryUnescape(id)

	categoriesMutex.RLock()
	cat, exists := categories[id]
	categoriesMutex.RUnlock()
	if !exists {
		http.Error(w, "Category not found", http.StatusNotFound)
		return
	}

	r.ParseMultipartForm(10 << 20) // 10MB
	file, header, err := r.FormFile("cover")
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".webp" && ext != ".gif" {
		http.Error(w, "Unsupported image type", http.StatusBadRequest)
		return
	}

	destPath := filepath.Join(cachePath, "cat_custom_"+id+ext)
	out, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Failed to save", http.StatusInternalServerError)
		return
	}
	io.Copy(out, file)
	out.Close()

	// Remove old collage cache
	os.Remove(filepath.Join(cachePath, "cat_"+id+".jpg"))
	// Remove old custom cover if different path
	if cat.CoverPath != "" && cat.CoverPath != destPath {
		os.Remove(cat.CoverPath)
	}

	categoriesMutex.Lock()
	cat.CoverType = "upload"
	cat.CoverPath = destPath
	categories[id] = cat
	categoriesMutex.Unlock()
	saveCategories()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cat)
}

// Cleanup old sessions periodically
func cleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		sessionsMutex.Lock()
		for token, session := range sessions {
			if now.After(session.ExpiresAt) {
				delete(sessions, token)
			}
		}
		sessionsMutex.Unlock()

		// Also clean up expired share unlock sessions
		shareUnlockSessionsMutex.Lock()
		for key, us := range shareUnlockSessions {
			if now.After(us.ExpiresAt) {
				delete(shareUnlockSessions, key)
			}
		}
		shareUnlockSessionsMutex.Unlock()
	}
}
