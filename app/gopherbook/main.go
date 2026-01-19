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
)

//go:embed templates/index.html
var templateFS embed.FS

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

type Tag struct {
	Name  string `json:"name"`
	Color string `json:"color"`
	Count int    `json:"count"`
}

type TarFileInfo struct {
	Name string
	Size int64
	Data []byte
}

var (
	users                = make(map[string]User)
	sessions             = make(map[string]Session)
	comics               = make(map[string]Comic)
	tags                 = make(map[string]Tag)
	comicPasswords       = make(map[string]string)
	coverGenSemaphore    = make(chan struct{}, 1) // Only ONE cover generation at a time
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

	loadUsers()
	initWatchFolders()

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
	http.HandleFunc("/api/watch-folder", authMiddleware(handleWatchFolder))
	http.HandleFunc("/", serveUI)

	go func() {
		for {
			time.Sleep(30 * time.Second)
			runtime.GC()
			debug.FreeOSMemory()
		}
	}()

	// Periodic session cleanup
	go cleanupSessions()

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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
	// var imageExt string

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
		passwordsMutex.RLock()
		password, hasPassword := comicPasswords[comic.ID]
		passwordsMutex.RUnlock()

		if !hasPassword {
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
		passwordsMutex.RLock()
		password, hasPassword := comicPasswords[comic.ID]
		passwordsMutex.RUnlock()

		if !hasPassword {
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
	err = jpeg.Encode(out, img, &jpeg.Options{Quality: 70})
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
			req.Color = "#1f6feb"
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
			tags[tag] = Tag{Name: tag, Color: "#1f6feb", Count: 1}
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
			tags[tag] = Tag{Name: tag, Color: "#1f6feb", Count: 1}
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
					tags[tag] = Tag{Name: tag, Color: "#1f6feb", Count: 1}
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
			tags[tag] = Tag{Name: tag, Color: "#1f6feb", Count: 1}
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
func getUsersPath() string {
	return filepath.Join(etcPath, "users.json")
}

func getAdminPath() string {
	return filepath.Join(etcPath, "admin.json")
}

func loadUsers() {
	data, err := os.ReadFile(getUsersPath())
	if err != nil {
		return
	}
	if err := json.Unmarshal(data, &users); err != nil {
		log.Printf("Error unmarshaling users: %v", err)
	}

	adminData, err := os.ReadFile(getAdminPath())
	if err == nil && len(adminData) > 0 {
		var adminConfig struct{ RegistrationEnabled bool }
		if err := json.Unmarshal(adminData, &adminConfig); err == nil {
			registrationEnabled = adminConfig.RegistrationEnabled
		}
	}
}

func saveUsers() {
	data, _ := json.MarshalIndent(users, "", "  ")
	os.WriteFile(getUsersPath(), data, 0644)
}

func saveAdminConfig() {
	config := struct{ RegistrationEnabled bool }{RegistrationEnabled: registrationEnabled}
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(getAdminPath(), data, 0644)
}

func loadTags() {
	data, err := os.ReadFile(filepath.Join(libraryPath, "tags.json"))
	if err != nil {
		return
	}
	tagsMutex.Lock()
	defer tagsMutex.Unlock()
	json.Unmarshal(data, &tags)
}

func saveTags() {
	tagsMutex.RLock()
	defer tagsMutex.RUnlock()
	data, _ := json.MarshalIndent(tags, "", "  ")
	os.WriteFile(filepath.Join(libraryPath, "tags.json"), data, 0644)
}

func saveComics() {
	comicsMutex.RLock()
	defer comicsMutex.RUnlock()
	data, _ := json.MarshalIndent(comics, "", "  ")
	os.WriteFile(filepath.Join(libraryPath, "comics.json"), data, 0644)
}

func loadComics() {
	data, err := os.ReadFile(filepath.Join(libraryPath, "comics.json"))
	if err != nil {
		return
	}
	comicsMutex.Lock()
	defer comicsMutex.Unlock()
	json.Unmarshal(data, &comics)
}

func loadPasswordsWithKey(key []byte) {
	data, err := os.ReadFile(filepath.Join(libraryPath, "passwords.json"))
	if err != nil {
		return
	}

	b64data := strings.TrimSpace(string(data))
	encrypted, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return
	}

	decrypted, err := decryptAES(encrypted, key)
	if err != nil {
		return
	}

	passwordsMutex.Lock()
	defer passwordsMutex.Unlock()
	if err := json.Unmarshal(decrypted, &comicPasswords); err != nil {
		return
	}

}

func savePasswords() {
	if len(currentEncryptionKey) == 0 {
		return
	}

	passwordsMutex.Lock()
	defer passwordsMutex.Unlock()
	data, err := json.MarshalIndent(comicPasswords, "", "  ")
	if err != nil {
		return
	}

	encrypted, err := encryptAES(data, currentEncryptionKey)
	if err != nil {
		return
	}

	b64 := base64.StdEncoding.EncodeToString(encrypted)
	os.WriteFile(filepath.Join(libraryPath, "passwords.json"), []byte(b64), 0644)
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
	return base64.URLEncoding.EncodeToString(hash[:])
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

// Cleanup old sessions periodically
func cleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		sessionsMutex.Lock()
		for token, session := range sessions {
			if time.Now().After(session.ExpiresAt) {
				delete(sessions, token)
			}
		}
		sessionsMutex.Unlock()
	}
}
