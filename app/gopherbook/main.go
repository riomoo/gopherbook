package main

import (
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
)

func main() {
	os.MkdirAll(libraryPath, 0755)
	os.MkdirAll(cachePath, 0755)
	os.MkdirAll(etcPath, 0755)

	loadUsers()

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
	libraryPath = filepath.Join("./library", currentUser)
	cachePath = filepath.Join("./cache/covers", currentUser)
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
	libraryPath = "./library"
	cachePath = "./cache/covers"

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

    // FIX: Read from the raw Body stream rather than parsing multipart if possible,
    // but at minimum, clear the form immediately after use.
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
            destPath := filepath.Join(libraryPath, "Unorganized", filename)
            destFile, err := os.Create(destPath)
            if err != nil {
                http.Error(w, "Error saving file", http.StatusInternalServerError)
                return
            }

            // FIX: Small buffer for the actual write
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

            // FIX: Force GC after the write is finished
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

	// NEW: Use a channel-based semaphore for better control
	select {
	case coverGenSemaphore <- struct{}{}:
		// Got the lock
		defer func() { <-coverGenSemaphore }()
	case <-time.After(30 * time.Second):
		// Timeout waiting for cover generation slot
		log.Printf("Timeout waiting for cover generation slot")
		http.Error(w, "Cover generation busy, try again later", http.StatusServiceUnavailable)
		return
	}

	// Double-check cache again (another request might have generated it)
	if _, err := os.Stat(cacheFile); err == nil {
		http.ServeFile(w, r, cacheFile)
		return
	}

	// Generate with aggressive memory management
	err = generateCoverCacheLazy(&comic, cacheFile)
	if err != nil {
		log.Printf("Failed to generate cover: %v", err)
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
	extractCBZMetadata(&c)

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

	// Use the new validation function
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

	// NOW extract metadata with the valid password
	comicsMutex.Lock()
	c = comics[decodedID]
	extractCBZMetadata(&c)

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
	yr, err := yzip.OpenReader(filePath)
	if err != nil {
		return false
	}
	defer yr.Close()

	// Try ComicInfo.xml first if it exists
	for _, f := range yr.File {
		if strings.ToLower(f.Name) == "comicinfo.xml" {
			if !f.IsEncrypted() {
				return true // Not encrypted
			}

			f.SetPassword(password)
			rc, err := f.Open()
			if err != nil {
				return false
			}

			// Try to read a small amount
			buf := make([]byte, 100)
			n, err := rc.Read(buf)
			rc.Close()

			if err != nil && err != io.EOF {
				return false
			}

			// If we read something and it looks like XML, password is valid
			if n > 0 && strings.Contains(string(buf[:n]), "<?xml") {
				return true
			}
			return false
		}
	}

	// No ComicInfo.xml, try the first encrypted image file
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
			return true // Not encrypted
		}

		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			return false
		}

		// Try to decode the image config (lightweight check)
		_, _, err = image.DecodeConfig(rc)
		rc.Close()

		// If we can decode config, password is valid
		return err == nil
	}

	// No files to test
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
	if comic.FileType != ".cbz" {
		http.Error(w, "Only CBZ format supported for page viewing", http.StatusBadRequest)
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

	// FIX: Use an explicit 32KB buffer to stream the data.
	// This ensures that even if the image is 50MB, only 32KB is in RAM at once.
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
		// Re-fetch comic after metadata load
		comicsMutex.RLock()
		comic = comics[comic.ID]
		comicsMutex.RUnlock()
	}

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
        ID:            generateToken(),
        Filename:      filename,
        FilePath:      filePath,
        FileType:      strings.ToLower(filepath.Ext(filename)),
        UploadedAt:    time.Now(),
        Artist:        "Unknown",
        Tags:          []string{},
        Bookmarks:     []int{},
        LastModified:  modTime,
        Encrypted:     false,
        HasPassword:   false,
    }

    // Quick check if encrypted (ONLY check, don't decrypt)
    if comic.FileType == ".cbz" {
        yr, err := yzip.OpenReader(comic.FilePath)
        if err == nil {
            // Just check first file for encryption
            for _, f := range yr.File {
                if f.IsEncrypted() {
                    comic.Encrypted = true
                    break
                }
            }
            yr.Close()
        }
    }

    // Extract artist from directory structure only
    parentDir := filepath.Dir(filePath)
    if filepath.Base(parentDir) != "Unorganized" {
        dirName := filepath.Base(filepath.Dir(parentDir))
        comic.Artist = dirName
    }

    comic.CoverImage = "/api/cover/" + url.QueryEscape(comic.ID)

    // DO NOT: extract metadata
    // DO NOT: generate covers
    // DO NOT: try passwords

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

	// Extract metadata NOW
	extractCBZMetadata(&comic)

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

func extractCBZMetadata(comic *Comic) {
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

		// Create temp file for the XML to offload RAM
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

		// Decrypt stream directly to disk (32KB buffer usage)
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

			// --- FIX: TAG EXTRACTION LOGIC ---
			tagsSource := info.TagsXml
			if tagsSource == "" {
				tagsSource = info.Genre
			}

			if tagsSource != "" {
				// Split by common delimiters: comma, semicolon, or pipe
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
			// ---------------------------------
		}
		// Break only after we've processed everything in the XML
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
		if ext != ".cbz" {
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

		// Modified or new file - just update the record
		if exists {
			comicsMutex.Lock()
			c := comics[id]
			c.LastModified = info.ModTime()
			comics[id] = c
			comicsMutex.Unlock()
		} else {
			// New file - create lightweight entry
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

func loadUsers() {
	data, err := os.ReadFile("etc/users.json")
	if err != nil {
		return
	}
	if err := json.Unmarshal(data, &users); err != nil {
		log.Printf("Error unmarshaling users: %v", err)
	}

	adminData, err := os.ReadFile("etc/admin.json")
	if err == nil && len(adminData) > 0 {
		var adminConfig struct{ RegistrationEnabled bool }
		if err := json.Unmarshal(adminData, &adminConfig); err == nil {
			registrationEnabled = adminConfig.RegistrationEnabled
		}
	}
}

func saveUsers() {
	data, _ := json.MarshalIndent(users, "", "  ")
	os.WriteFile("etc/users.json", data, 0644)
}

func saveAdminConfig() {
	config := struct{ RegistrationEnabled bool }{RegistrationEnabled: registrationEnabled}
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile("etc/admin.json", data, 0644)
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
