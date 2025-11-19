package main

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	yzip "github.com/yeka/zip"
)

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
	Genre     string   `xml:"Genre"`   // Standard field
	TagsXml   string   `xml:"Tags"`    // User-requested field for flexibility
	StoryArc  string   `xml:"StoryArc"`
	Year      string   `xml:"Year"`
	Month     string   `xml:"Month"`
	Summary   string   `xml:"Summary"`
	PageCount int      `xml:"PageCount"`
}

type User struct {
    Username     string `json:"username"`
    PasswordHash string `json:"password_hash"`
    IsAdmin      bool   `json:"is_admin"`  // NEW
}

type Comic struct {
	ID          string    `json:"id"`
	Filename    string    `json:"filename"`
	Artist      string    `json:"artist"`
	Title       string    `json:"title"`
	Series      string    `json:"series"`
	StoryArc    string    `json:"story_arc"`
	Number      string    `json:"number"`
	Publisher   string    `json:"publisher"`
	Year        string    `json:"year"`
	PageCount   int       `json:"page_count"`
	CoverImage  string    `json:"cover_image"`
	FilePath    string    `json:"file_path"`
	FileType    string    `json:"file_type"`
	Encrypted   bool      `json:"encrypted"`
	HasPassword bool      `json:"has_password"`
	Password    string    `json:"-"` // Don't expose password in JSON
	Tags        []string  `json:"tags"`
	UploadedAt  time.Time `json:"uploaded_at"`
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
	users          = make(map[string]User)
	sessions       = make(map[string]Session)
	comics         = make(map[string]Comic)
	tags           = make(map[string]Tag)
	comicPasswords = make(map[string]string)
	comicsMutex    sync.RWMutex
	sessionsMutex  sync.RWMutex
	tagsMutex      sync.RWMutex
	passwordsMutex sync.RWMutex
	currentEncryptionKey []byte
	libraryPath    = "./library"
	cachePath      = "./cache/covers"
	etcPath      = "./etc"
	currentUser    string
	registrationEnabled = true
)

func main() {
	// Initialize directories
	os.MkdirAll(filepath.Join(libraryPath, "Unorganized"), 0755)
	os.MkdirAll(cachePath, 0755)
	os.MkdirAll(etcPath, 0755)

	// Load users, comics, and tags
	loadUsers()
	// Setup routes
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/comics", authMiddleware(handleComics))
	http.HandleFunc("/api/upload", authMiddleware(handleUpload))
	http.HandleFunc("/api/organize", authMiddleware(handleOrganize))
	http.HandleFunc("/api/pages/", authMiddleware(handleComicPages))
	http.HandleFunc("/api/comic/", authMiddleware(handleComicFile))
	http.HandleFunc("/api/cover/", authMiddleware(handleCover))
	http.HandleFunc("/api/tags", authMiddleware(handleTags))
	http.HandleFunc("/api/comic-tags/", authMiddleware(handleComicTags))
	http.HandleFunc("/api/set-password/", authMiddleware(handleSetPassword))
	http.HandleFunc("/api/admin/toggle-registration", authMiddleware(handleToggleRegistration))
	http.HandleFunc("/api/admin/delete-comic/", authMiddleware(handleDeleteComic))
	http.HandleFunc("/", serveUI)

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		log.Println("Register: Method not POST")
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
		log.Printf("Register: JSON decode error: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	log.Printf("Register attempt: username=%s", req.Username)

	if req.Username == "" || req.Password == "" {
		log.Println("Register: Empty username or password")
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	if _, exists := users[req.Username]; exists {
		log.Printf("Register: User %s already exists", req.Username)
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Register: Bcrypt error: %v", err)
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	// Replace the user creation block (after hash generation):
	users[req.Username] = User{
	    Username:     req.Username,
	    PasswordHash: string(hash),
	    IsAdmin:      len(users) == 0,  // NEW: First user is admin
	}
	saveUsers()
	if len(users) == 1 {  // NEW: Init admin config
	    saveAdminConfig()
	    registrationEnabled = true
	}
	// Create per-user directories
	userLibrary := filepath.Join("./library", req.Username)
	os.MkdirAll(filepath.Join(userLibrary, "Unorganized"), 0755)
	os.MkdirAll(filepath.Join("./cache/covers", req.Username), 0755)

	log.Printf("Register: User %s created successfully", req.Username)
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
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]bool{"enabled": registrationEnabled})
}

func getCurrentUser(r *http.Request) User {
    cookie, err := r.Cookie("session")
    if err != nil {
        return User{} // Empty user if no cookie
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
        log.Println("Login: Method not POST")
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("Login: JSON decode error: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    log.Printf("Login attempt: username=%s", req.Username)

    user, exists := users[req.Username]
    if !exists {
        log.Printf("Login: User %s not found", req.Username)
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
        log.Printf("Login: Password mismatch for %s", req.Username)
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
    scanLibrary()

    http.SetCookie(w, &http.Cookie{
        Name:     "session",
        Value:    token,
        Expires:  time.Now().Add(24 * time.Hour),
        HttpOnly: true,
        Path:     "/",
    })

    log.Printf("Login: User %s logged in successfully", req.Username)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message":   "Login successful",
        "token":     token,
        "is_admin":  user.IsAdmin,
    })
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		sessionsMutex.Lock()
		delete(sessions, cookie.Value)
		sessionsMutex.Unlock()
	}
	// Clear sensitive data from memory
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
	libraryPath = "./library"  // Reset to default
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

	comicsMutex.RLock()
	defer comicsMutex.RUnlock()

	comicList := make([]Comic, 0, len(comics))
	for _, comic := range comics {
		comicList = append(comicList, comic)
	}

	// Sort by artist, then series, then number
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

	r.ParseMultipartForm(100 << 20) // 100 MB max

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := header.Filename
	ext := strings.ToLower(filepath.Ext(filename))

	validExts := map[string]bool{
		".cbz": true,
	}

	if !validExts[ext] {
		http.Error(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	// Save to Unorganized initially
	destPath := filepath.Join(libraryPath, "Unorganized", filename)
	destFile, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, file); err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	// Process the comic
	comic := processComic(destPath, filename)

	// Must lock/unlock to ensure generateCoverCache sees the comic in the map,
	// especially if it finds a password and needs to persist it.
	comicsMutex.Lock()
	comics[comic.ID] = comic
	comicsMutex.Unlock()

	generateCoverCache(&comic) // Pass reference to updated comic struct

	saveComics()

	json.NewEncoder(w).Encode(comic)
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
        saveComics()
        saveTags()
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

	// Check cache first
	cacheFile := filepath.Join(cachePath, comic.ID+".jpg")
	if _, err := os.Stat(cacheFile); err == nil {
		http.ServeFile(w, r, cacheFile)
		return
	}

	// Generate on-the-fly
	if comic.FileType == ".cbz" {
		serveCoverFromCBZ(w, r, comic)
	} else {
		http.Error(w, "Cover not available", http.StatusNotFound)
	}
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

		saveTags()
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

		// Add tag if not already present
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
			saveComics()
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
			saveComics()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(comic)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
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

	// Verify password by trying to open ComicInfo.xml
	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
		http.Error(w, "Error reading comic", http.StatusInternalServerError)
		return
	}
	defer yr.Close()

	valid := false
	for _, f := range yr.File {
		if strings.ToLower(f.Name) == "comicinfo.xml" {
			f.SetPassword(req.Password)
			rc, err := f.Open()
			if err != nil {
				break
			}
			data, readErr := io.ReadAll(rc)
			rc.Close()
			if readErr != nil || len(data) == 0 {
				break
			}
			// Quick XML check
			var info ComicInfo
			if xml.Unmarshal(data, &info) == nil {
				valid = true
			}
			break
		}
	}

	if !valid {
		http.Error(w, "Invalid password", http.StatusBadRequest)
		return
	}

	// Set and save
	comicsMutex.Lock()
	c := comics[decodedID]
	c.Password = req.Password
	c.HasPassword = true
	comics[decodedID] = c
	comicsMutex.Unlock()

	passwordsMutex.Lock()
	comicPasswords[decodedID] = req.Password
	passwordsMutex.Unlock()
	savePasswords()

	// Extract metadata now that password is known
	comicsMutex.Lock()
	c = comics[decodedID]
	extractCBZMetadata(&c)
	// Organize comic based on extracted metadata
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
        } else {
            log.Printf("Failed to move comic %s to %s: %v", c.ID, newPath, err)
        }
    }
}

// Update tags counts for newly extracted tags
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
comics[decodedID] = c
comicsMutex.Unlock()

	saveComics()
	saveTags()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Password set successfully"})
}

func handleComicFile(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/comic/"), "/")
	id := parts[0]

	decodedID, err := url.QueryUnescape(id)
	if err != nil {
		log.Printf("Error decoding ID: %v", err)
		decodedID = id
	}

	comicsMutex.RLock()
	comic, exists := comics[decodedID]
	if !exists {
		comic, exists = comics[id]
	}
	comicsMutex.RUnlock()

	if !exists {
		log.Printf("Comic file not found for ID: %s or %s", decodedID, id)
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

	var pageIdx int
	fmt.Sscanf(pageNum, "%d", &pageIdx)

	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
		log.Printf("Error opening CBZ with yeka/zip: %v", err)
		serveComicPageStandard(w, r, comic, pageIdx)
		return
	}
	defer yr.Close()

	var imageFiles []*yzip.File
	for _, f := range yr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		// Broad image format support
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

	// Password handling
	if targetFile.IsEncrypted() {
		if comic.Password != "" {
			targetFile.SetPassword(comic.Password)
		} else {
			http.Error(w, "Comic requires password (contact admin or re-open reader)", http.StatusUnauthorized)
			return
		}
	}

	rc, err := targetFile.Open()
	if err != nil {
		log.Printf("Error opening page file: %v", err)
		http.Error(w, "Error reading page - file may be encrypted", http.StatusInternalServerError)
		return
	}
	defer rc.Close()

	imageData, err := io.ReadAll(rc)
	if err != nil {
		log.Printf("Error reading image data: %v", err)
		http.Error(w, "Error reading page", http.StatusInternalServerError)
		return
	}

	ext := strings.ToLower(filepath.Ext(targetFile.Name))
	contentType := getContentType(ext)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(imageData)
}

func serveComicPageStandard(w http.ResponseWriter, r *http.Request, comic Comic, pageIdx int) {
	zipReader, err := zip.OpenReader(comic.FilePath)
	if err != nil {
		http.Error(w, "Error reading comic", http.StatusInternalServerError)
		return
	}
	defer zipReader.Close()

	var imageFiles []*zip.File
	for _, f := range zipReader.File {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		// Broad image format support
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
	rc, err := targetFile.Open()
	if err != nil {
		http.Error(w, "Error reading page", http.StatusInternalServerError)
		return
	}
	defer rc.Close()

	imageData, err := io.ReadAll(rc)
	if err != nil {
		http.Error(w, "Error reading page", http.StatusInternalServerError)
		return
	}

	ext := strings.ToLower(filepath.Ext(targetFile.Name))
	contentType := getContentType(ext)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(imageData)
}

func extractCBZMetadataStandard(comic *Comic) {
	r, err := zip.OpenReader(comic.FilePath)
	if err != nil {
		return
	}
	defer r.Close()

	for _, f := range r.File {
		if strings.ToLower(f.Name) == "comicinfo.xml" {
			rc, err := f.Open()
			if err != nil {
				continue
			}

			data, err := io.ReadAll(rc)
			rc.Close()

			if err != nil {
				continue
			}

			var info ComicInfo
			if err := xml.Unmarshal(data, &info); err == nil {
				comic.Title = info.Title
				comic.Series = info.Series
				comic.StoryArc = info.StoryArc
				comic.Number = info.Number
				comic.Publisher = info.Publisher
				comic.Year = info.Year
				comic.PageCount = info.PageCount

				// Extract tags from TagsXml first, then fallback to Genre
				tagsSource := info.TagsXml
				if tagsSource == "" {
					tagsSource = info.Genre
				}

				if tagsSource != "" {
					tags := strings.FieldsFunc(tagsSource, func(r rune) bool {
						return r == ',' || r == ';' || r == '|'
					})
					comic.Tags = make([]string, 0, len(tags))
					for _, tag := range tags {
						if t := strings.TrimSpace(tag); t != "" {
							comic.Tags = append(comic.Tags, t)
						}
					}
				}

				if info.Inker != "" {
					comic.Artist = info.Inker
				} else if info.Artist != "" {
					comic.Artist = info.Artist
				} else if info.Writer != "" {
					comic.Artist = info.Writer
				}
			}
			break
		}
	}
}

func serveCoverFromCBZ(w http.ResponseWriter, r *http.Request, comic Comic) {
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
		// FIX 2: Expanded image types for serving covers
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".avif" || ext == ".jxl" || ext == ".webp" || ext == ".bmp" || ext == ".jp2" {
			imageFiles = append(imageFiles, f)
		}
	}

	if len(imageFiles) == 0 {
		http.Error(w, "No cover found", http.StatusNotFound)
		return
	}

	sort.Slice(imageFiles, func(i, j int) bool {
		return imageFiles[i].Name < imageFiles[j].Name
	})

	coverFile := imageFiles[0]

	// Password handling
	if coverFile.IsEncrypted() {
		if comic.Password != "" {
			coverFile.SetPassword(comic.Password)
		} else {
			http.Error(w, "Comic requires password (contact admin or re-open reader)", http.StatusUnauthorized)
			return
		}
	}

	rc, err := coverFile.Open()
	if err != nil {
		log.Printf("Error opening cover for ID %s: %v", comic.ID, err)
		http.Error(w, "Error reading cover - file may be encrypted", http.StatusInternalServerError)
		return
	}
	defer rc.Close()

	imageData, err := io.ReadAll(rc)
	if err != nil {
		http.Error(w, "Error reading cover", http.StatusInternalServerError)
		return
	}

	ext := strings.ToLower(filepath.Ext(coverFile.Name))
	w.Header().Set("Content-Type", getContentType(ext))
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(imageData)
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
	needsPassword := comic.Encrypted && comic.Password == "" && !comic.HasPassword
	for _, f := range yr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".avif" ||
			ext == ".jxl" || ext == ".jp2" || ext == ".webp" || ext == ".gif" || ext == ".bmp" {
			if f.IsEncrypted() && needsPassword {
				needsPassword = true
			}
			imageFiles = append(imageFiles, f.Name)
		}
	}

	sort.Strings(imageFiles)

	data := map[string]interface{}{
		"page_count": len(imageFiles),
		"pages":      imageFiles,
	}
	if needsPassword {
		data["needs_password"] = true
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func handleOrganize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ComicID  string `json:"comic_id"`
		Inker    string `json:"inker"`
		StoryArc string `json:"story_arc"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	comicsMutex.Lock()
	defer comicsMutex.Unlock()

	comic, exists := comics[req.ComicID]
	if !exists {
		http.Error(w, "Comic not found", http.StatusNotFound)
		return
	}

	inker := sanitizeFilename(req.Inker)
	storyArc := sanitizeFilename(req.StoryArc)
	if inker == "" {
		inker = "Unknown"
	}
	if storyArc == "" {
		storyArc = "No_StoryArc"
	}

	newDir := filepath.Join(libraryPath, inker, storyArc)
	os.MkdirAll(newDir, 0755)

	newPath := filepath.Join(newDir, filepath.Base(comic.FilePath))
	if err := os.Rename(comic.FilePath, newPath); err != nil {
		http.Error(w, "Error organizing comic", http.StatusInternalServerError)
		return
	}

	comic.FilePath = newPath
	comic.Artist = req.Inker
	comic.StoryArc = req.StoryArc
	comics[req.ComicID] = comic

	saveComics()
	json.NewEncoder(w).Encode(comic)
}

func processComic(filePath, filename string) Comic {
	comic := Comic{
		ID:         generateToken(),
		Filename:   filename,
		FilePath:   filePath,
		FileType:   strings.ToLower(filepath.Ext(filename)),
		UploadedAt: time.Now(),
		Artist:     "Unknown",
		Tags:       []string{},
	}

	if comic.FileType == ".cbz" {
		extractCBZMetadata(&comic)
		// Register extracted tags in global tags map
		tagsMutex.Lock()
		for _, tag := range comic.Tags {
			if _, exists := tags[tag]; !exists {
				tags[tag] = Tag{
					Name:  tag,
					Color: "#1f6feb", // Default color
					Count: 0,
				}
			}
			tagData := tags[tag]
			tagData.Count++
			tags[tag] = tagData
		}
		tagsMutex.Unlock()
		saveTags()

		// Create folder structure based on Inker and StoryArc
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

			newPath := filepath.Join(newDir, filename)
			if newPath != filePath {
				if err := os.Rename(filePath, newPath); err == nil {
					comic.FilePath = newPath
				}
			}
		}
	}

	parentDir := filepath.Dir(filePath)
	if filepath.Base(parentDir) != "Unorganized" {
		dirName := filepath.Base(filepath.Dir(parentDir))
		comic.Artist = dirName
	}

	return comic
}

func generateCoverCache(comic *Comic) {
	if comic.FileType != ".cbz" {
		return
	}

	cacheFile := filepath.Join(cachePath, comic.ID+".jpg")
	if _, err := os.Stat(cacheFile); err == nil {
		return
	}

	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
		return
	}
	defer yr.Close()

	var imageFiles []*yzip.File
	for _, f := range yr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		// FIX 2: Expanded image types for cover caching
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".avif" || ext == ".jxl" || ext == ".webp" || ext == ".bmp" || ext == ".jp2" {
			imageFiles = append(imageFiles, f)
		}
	}

	if len(imageFiles) == 0 {
		return
	}

	sort.Slice(imageFiles, func(i, j int) bool {
		return imageFiles[i].Name < imageFiles[j].Name
	})

	coverFile := imageFiles[0]

	// Password handling
	if coverFile.IsEncrypted() {
		if comic.Password != "" {
			coverFile.SetPassword(comic.Password)
		} else {
			log.Printf("Failed to open cover file for ID %s. File encrypted or corrupted.", comic.ID)
			return
		}
	}

	rc, err := coverFile.Open()
	if err != nil {
		log.Printf("Failed to open cover file for ID %s. File encrypted or corrupted. %v", comic.ID, err)
		return
	}
	defer rc.Close()

	out, err := os.Create(cacheFile)
	if err != nil {
		return
	}
	defer out.Close()

	io.Copy(out, rc)
}

func extractCBZMetadata(comic *Comic) {
	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
		extractCBZMetadataStandard(comic)
		return
	}
	defer yr.Close()

	isEncrypted := false
	for _, f := range yr.File {
		if f.IsEncrypted() {
			isEncrypted = true
			break
		}
	}
	comic.Encrypted = isEncrypted
	comic.HasPassword = false // Default until proven

	if !isEncrypted {
		// Use standard extraction if not encrypted
		extractCBZMetadataStandard(comic)
		comic.HasPassword = true // No password needed
		return
	}

	// Collect unique known passwords from other comics
	passwordsMutex.RLock()
	knownPwds := make(map[string]bool)
	for _, pwd := range comicPasswords {
		if pwd != "" {
			knownPwds[pwd] = true
		}
	}
	passwordsMutex.RUnlock()

	foundPwd := ""
	for _, f := range yr.File {
		if strings.ToLower(f.Name) == "comicinfo.xml" {
			var data []byte
			var readErr error

			if len(knownPwds) > 0 {
				// Try known passwords
				for pwd := range knownPwds {
					f.SetPassword(pwd)
					rc, err := f.Open()
					if err != nil {
						continue
					}
					data, readErr = io.ReadAll(rc)
					rc.Close()
					if err != nil {
						continue
					}
					if readErr == nil && len(data) > 0 {
						foundPwd = pwd
						break
					}
				}
			}

			if foundPwd != "" {
				// Success: persist
				comic.Password = foundPwd
				comic.HasPassword = true
				passwordsMutex.Lock()
				comicPasswords[comic.ID] = foundPwd
				passwordsMutex.Unlock()
				savePasswords()
			} else if !isEncrypted {
				// Fallback for non-encrypted
				rc, err := f.Open()
				if err != nil {
					continue
				}
				data, readErr = io.ReadAll(rc)
				rc.Close()
			}

			if readErr != nil || len(data) == 0 {
				continue
			}

			var info ComicInfo
			if err := xml.Unmarshal(data, &info); err == nil {
				comic.Title = info.Title
				comic.Series = info.Series
				comic.StoryArc = info.StoryArc
				comic.Number = info.Number
				comic.Publisher = info.Publisher
				comic.Year = info.Year
				comic.PageCount = info.PageCount

				// Extract tags from TagsXml first, then fallback to Genre
				tagsSource := info.TagsXml
				if tagsSource == "" {
					tagsSource = info.Genre
				}

				if tagsSource != "" {
					tags := strings.FieldsFunc(tagsSource, func(r rune) bool {
						return r == ',' || r == ';' || r == '|'
					})
					comic.Tags = make([]string, 0, len(tags))
					for _, tag := range tags {
						if t := strings.TrimSpace(tag); t != "" {
							comic.Tags = append(comic.Tags, t)
						}
					}
				}

				if info.Inker != "" {
					comic.Artist = info.Inker
				} else if info.Artist != "" {
					comic.Artist = info.Artist
				} else if info.Writer != "" {
					comic.Artist = info.Writer
				}
			}
			break
		}
	}
}

func scanLibrary() {
	// Create a map to track existing file paths for quick lookup
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
		comicsMutex.RUnlock()

		if exists {
			// Verify cache exists for this comic
			comic := comics[id]
			cacheFile := filepath.Join(cachePath, comic.ID+".jpg")
			if _, err := os.Stat(cacheFile); os.IsNotExist(err) && comic.FileType == ".cbz" {
				// Generate cache only if it doesn't exist
				comicsMutex.RLock()
				c := comics[id]
				comicsMutex.RUnlock()
				generateCoverCache(&c)
				comicsMutex.Lock()
				comics[id] = c // Update with any new password found
				comicsMutex.Unlock()
			}
			return nil
		}

		// Process new comic
		comic := processComic(path, info.Name())
		comicsMutex.Lock()
		comics[comic.ID] = comic
		comicsMutex.Unlock()

		// Generate cover cache for new comic
		comicsMutex.RLock()
		c := comics[comic.ID]
		comicsMutex.RUnlock()
		generateCoverCache(&c)
		comicsMutex.Lock()
		comics[comic.ID] = c // Write back potential password found
		comicsMutex.Unlock()

		return nil
	})

	// Clean up comics that no longer exist
	comicsMutex.Lock()
	for id, comic := range comics {
		if _, err := os.Stat(comic.FilePath); os.IsNotExist(err) {
			// Remove tags associated with this comic
			for _, tag := range comic.Tags {
				updateTagCount(tag, -1)
			}
			delete(comics, id)
		}
	}
	comicsMutex.Unlock()

	saveComics()
	saveTags()
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

// Replace loadUsers():
func loadUsers() {
    data, err := os.ReadFile("etc/users.json")
    if err != nil {
        log.Printf("Error reading users.json: %v", err)
        return
    }
    if err := json.Unmarshal(data, &users); err != nil {
        log.Printf("Error unmarshaling users: %v", err)
    }

    // Always load admin config to set registrationEnabled
    adminData, err := os.ReadFile("etc/admin.json")
    if err == nil && len(adminData) > 0 {
        var adminConfig struct{ RegistrationEnabled bool }
        if err := json.Unmarshal(adminData, &adminConfig); err == nil {
            registrationEnabled = adminConfig.RegistrationEnabled
        } else {
            log.Printf("Error unmarshaling admin.json: %v", err)
        }
    }
}

func saveUsers() {
	data, _ := json.MarshalIndent(users, "", "  ")
	os.WriteFile("etc/users.json", data, 0644)
}

// Add new function after saveUsers():
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
	data, _ := json.MarshalIndent(tags, "", "  ")
	os.WriteFile(filepath.Join(libraryPath, "tags.json"), data, 0644)
}

func saveComics() {
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
		log.Printf("No passwords file for user %s, starting fresh", currentUser)
		return
	}

	b64data := strings.TrimSpace(string(data))
	encrypted, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		log.Printf("Failed to decode passwords.json: %v", err)
		return
	}

	decrypted, err := decryptAES(encrypted, key)
	if err != nil {
		log.Printf("Failed to decrypt passwords: %v", err)
		return
	}

	passwordsMutex.Lock()
	defer passwordsMutex.Unlock()
	if err := json.Unmarshal(decrypted, &comicPasswords); err != nil {
		log.Printf("Failed to unmarshal passwords: %v", err)
		return
	}

	// Restore Password and HasPassword in comics map
	comicsMutex.Lock()
	defer comicsMutex.Unlock()
	for id, pwd := range comicPasswords {
		if c, exists := comics[id]; exists {
			c.Password = pwd
			c.HasPassword = (pwd != "")
			comics[id] = c
		}
	}
}

func savePasswords() {
	if len(currentEncryptionKey) == 0 {
		log.Println("No encryption key set, skipping save")
		return
	}

	passwordsMutex.Lock()
	defer passwordsMutex.Unlock()
	data, err := json.MarshalIndent(comicPasswords, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal passwords: %v", err)
		return
	}

	encrypted, err := encryptAES(data, currentEncryptionKey)
	if err != nil {
		log.Printf("Failed to encrypt passwords: %v", err)
		return
	}

	b64 := base64.StdEncoding.EncodeToString(encrypted)
	if err := os.WriteFile(filepath.Join(libraryPath, "passwords.json"), []byte(b64), 0644); err != nil {
		log.Printf("Failed to write passwords.json for user %s: %v", currentUser, err)
	}
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
		saveTags()
	}
}

func generateToken() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func sanitizeFilename(filename string) string {
	// Replace spaces explicitly with underscores
	filename = strings.ReplaceAll(filename, " ", "_")
	// Replace any character that isn't alphanumeric, hyphen, or underscore with underscore
	reg, _ := regexp.Compile("[^a-zA-Z0-9-_]+")
	sanitized := reg.ReplaceAllString(filename, "_")
	// Remove leading/trailing underscores
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

func isPlaintext(data []byte) bool {
	if len(data) < 4 {
		return true
	}

	if len(data) >= 4 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
		return true
	}
	if len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return true
	}
	if len(data) >= 3 && data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 {
		return true
	}
	if len(data) >= 12 && data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 &&
		data[8] == 0x57 && data[9] == 0x45 && data[10] == 0x42 && data[11] == 0x50 {
		return true
	}
	if data[0] == 0x3C {
		return true
	}

	return false
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
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

func encryptAES(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Create the cipher stream
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt the plaintext
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Prepend IV to ciphertext
	return append(iv, ciphertext...), nil
}

func serveUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(getHTML()))
}

func getHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gopherbook</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #1b1e2c;
            color: #bfbcb7;
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: #395E62;
            border-bottom: 1px solid #314C52;
            padding: 20px 0;
            margin-bottom: 30px;
        }

        .header-content {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        h1 {
            color: #1b1e2c;
            font-size: 24px;
        }

        .auth-section {
            background: #1b1e2c;
            border: 1px solid #446B6E;
            border-radius: 6px;
            padding: 30px;
            max-width: 400px;
            margin: 100px auto;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #bfbcb7;
            font-weight: 500;
        }

        input[type="text"],
        input[type="password"],
        input[type="file"],
        select {
            width: 100%;
            padding: 10px 12px;
            background: #1b1e2c;
            border: 1px solid #446B6E;
            border-radius: 6px;
            color: #bfbcb7;
            font-size: 14px;
        }

        input[type="text"]:focus,
        input[type="password"]:focus,
        select:focus {
            outline: none;
            border-color: #446B6E;
        }

        button {
            width: 100%;
            padding: 10px 16px;
            background: #395E62;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }

        button:hover {
            background: #446B6E;
        }

        .secondary-btn {
            background: #314C52;
            margin-top: 10px;
        }

        .secondary-btn:hover {
            background: #446B6E;
        }

        .upload-section {
            background: #1b1e2c;
            border: 1px solid #446B6E;
            border-radius: 6px;
            padding: 24px;
            margin-bottom: 30px;
        }

        .filter-section {
            background: #1b1e2c;
            border: 1px solid #446B6E;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .filter-controls {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: center;
        }

        .tag-filter {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: #1b1e2c;
            border: 1px solid #bfbcb7;
            border-radius: 16px;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .tag-filter:hover {
            border-color: #395E62;
        }

        .tag-filter.active {
            background: #446B6E;
            border-color: #446B6E;
        }

        .comics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 20px;
        }

        .comic-card {
            background: #1b1e2c;
            border: 1px solid #395E62;
            border-radius: 6px;
            overflow: hidden;
            transition: transform 0.2s, border-color 0.2s;
            cursor: pointer;
        }

        .comic-card:hover {
            transform: translateY(-2px);
            border-color: #395E62;
        }

        .comic-cover-container {
            width: 100%;
            height: 280px;
            background: #1b1e2c;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }

        .comic-cover {
            width: 100%;
            height: 100%;
            object-fit: cover;
            background: #1b1e2c;
        }

        .comic-cover-fallback {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #858380;
            font-size: 14px;
            background: #1b1e2c;
            border-bottom: 1px solid #A34346;
        }

        .comic-info {
            padding: 16px;
        }

        .comic-title {
            font-weight: 600;
            color: #446B6E;
            margin-bottom: 8px;
            font-size: 14px;
        }

        .comic-meta {
            font-size: 12px;
            color: #8b949e;
            line-height: 1.6;
            margin-bottom: 8px;
        }

        .comic-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            margin-top: 8px;
        }

        .comic-tag {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            color: white;
        }

        .comic-artist {
            display: inline-block;
            background: #1f6feb;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
        }

        .unorganized {
            background: #8b949e;
        }

        .hidden {
            display: none;
        }

        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 1px solid #30363d;
        }

        .tab {
            padding: 10px 20px;
            background: none;
            border: none;
            color: #8b949e;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            width: auto;
        }

        .tab.active {
            color: #395E62;
            border-bottom-color: #395E62;
        }

        .message {
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
        }

        .success {
            background: #446B6E;
            color: white;
        }

        .error {
            background: #A55354;
            color: white;
        }

        #readerModal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.95);
            z-index: 1000;
        }

        #readerModal.active {
            display: flex;
            flex-direction: column;
        }

        .reader-header {
            background: #1b1e2c;
            border-bottom: 1px solid #395E62;
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .reader-title {
            color: #395E62;
            font-weight: 600;
        }

        .reader-controls {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .reader-btn {
            background: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
            width: auto;
        }

        .reader-btn:hover {
            background: #30363d;
        }

        .reader-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .page-input {
            width: 80px;
            text-align: center;
            padding: 6px;
            background: #0d1117;
            border: 1px solid #30363d;
            color: #c9d1d9;
            border-radius: 6px;
        }

        .reader-content {
            flex: 1;
            display: flex;
            justify-content: center;
            align-items: center;
            overflow: hidden;
            position: relative;
        }

        #comicImage {
            max-width: 100%;
            max-height: 100%;
            object-fit: contain;
            transform-origin: center center;
            transition: transform 0.2s;
        }

        .zoom-controls {
            position: absolute;
            bottom: 20px;
            right: 20px;
            display: flex;
            gap: 8px;
            background: rgba(22, 27, 34, 0.95);
            padding: 8px;
            border-radius: 6px;
            border: 1px solid #30363d;
        }

        .zoom-btn {
            width: 40px;
            height: 40px;
            background: #21262d;
            border: 1px solid #30363d;
            color: #c9d1d9;
            border-radius: 6px;
            cursor: pointer;
            font-size: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .zoom-btn:hover {
            background: #30363d;
        }

        #tagModal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 2000;
            align-items: center;
            justify-content: center;
        }

        #tagModal.active {
            display: flex;
        }

        .modal-content {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 24px;
            max-width: 500px;
            width: 90%;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .modal-title {
            color: #58a6ff;
            font-size: 18px;
            font-weight: 600;
        }

        .close-btn {
            background: none;
            border: none;
            color: #8b949e;
            font-size: 24px;
            cursor: pointer;
            width: auto;
            padding: 0;
        }

        .tag-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 20px;
        }

        .tag-item {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 16px;
            font-size: 13px;
            color: white;
            cursor: pointer;
        }

        .tag-item .remove {
            background: rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            width: 16px;
            height: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }

        .add-tag-form {
            display: flex;
            gap: 8px;
        }

        .add-tag-input {
            flex: 1;
        }

        .color-picker {
            width: 60px;
            height: 38px;
            border: 1px solid #30363d;
            border-radius: 6px;
            cursor: pointer;
        }

        .available-tags {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #30363d;
        }

        .available-tags-title {
            font-size: 14px;
            color: #8b949e;
            margin-bottom: 12px;
        }

        .context-menu {
            position: absolute;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 8px 0;
            min-width: 150px;
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.4);
            z-index: 3000;
        }

        .context-menu-item {
            padding: 8px 16px;
            cursor: pointer;
            color: #c9d1d9;
            font-size: 14px;
            transition: background 0.2s;
        }

        .context-menu-item:hover {
            background: #21262d;
        }
	#passwordModal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.9);
    z-index: 2500;
    align-items: center;
    justify-content: center;
}

#passwordModal.active {
    display: flex;
}

.password-modal-content {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 30px;
    max-width: 400px;
    width: 90%;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
}

.password-modal-header {
    margin-bottom: 20px;
}

.password-modal-title {
    color: #58a6ff;
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 8px;
}

.password-modal-subtitle {
    color: #8b949e;
    font-size: 14px;
}

.password-input-group {
    margin-bottom: 20px;
}

.password-input-group label {
    display: block;
    margin-bottom: 8px;
    color: #c9d1d9;
    font-weight: 500;
}

.password-input-group input {
    width: 100%;
    padding: 10px 12px;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-size: 14px;
}

.password-input-group input:focus {
    outline: none;
    border-color: #58a6ff;
}

.password-modal-buttons {
    display: flex;
    gap: 10px;
}

.password-modal-buttons button {
    flex: 1;
}

.password-error {
    background: #da3633;
    color: white;
    padding: 10px;
    border-radius: 6px;
    margin-bottom: 16px;
    font-size: 13px;
}
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <h1>Gopherbook</h1>
            <div id="userInfo" class="hidden">
                <button onclick="logout()" class="secondary-btn" style="width: auto; padding: 8px 16px;">Logout</button>
            </div>
        </div>
    </header>

    <div class="container">
	<div id="authSection" class="auth-section">
	    <div id="authMessage" class="message hidden"></div>  <!-- NEW: Auth-specific message -->
	    <div class="tabs">
                <button class="tab active" onclick="showTab('login')">Login</button>
                <button class="tab" onclick="showTab('register')">Register</button>
            </div>

            <div id="loginForm">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="loginUsername" placeholder="Enter username">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="loginPassword" placeholder="Enter password">
                </div>
                <button onclick="login()">Login</button>
            </div>

            <div id="registerForm" class="hidden">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="regUsername" placeholder="Choose username">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="regPassword" placeholder="Choose password">
                </div>
                <button onclick="register()">Register</button>
            </div>
        </div>

        <div id="mainSection" class="hidden">
            <div id="message"></div>

            <div class="upload-section">
                <h2 style="margin-bottom: 16px; color: #c9d1d9;">Upload Comic</h2>
                <div class="form-group">
                    <label>Select File (CBZ)</label>
                    <input type="file" id="fileUpload" accept=".cbz">
                </div>
                <button onclick="uploadComic()">Upload</button>
            </div>

	    <div class="filter-section">
    <h3 style="margin-bottom: 12px; color: #c9d1d9; font-size: 16px;">Filter by Tags</h3>
    <div class="filter-controls">
        <div style="position: relative; width: 300px;">
            <input type="text" id="tagSearch" placeholder="Search tags..." style="width: 100%; padding-right: 30px;">
            <span style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); color: #8b949e;">🔍</span>
        </div>
        <div id="tagSuggestions" class="context-menu hidden" style="width: 300px; max-height: 200px; overflow-y: auto;"></div>
        <div id="selectedTagFilters" class="filter-controls" style="flex-wrap: wrap; gap: 8px; margin-top: 10px;"></div>
    </div>
		</div>

            <h2 style="margin-bottom: 20px; color: #c9d1d9;">Library</h2>
		<div id="adminPanel" class="upload-section hidden">
		    <h2>Admin Panel</h2>
		    <div class="form-group">
			<label>Registration: <span id="regStatus">Enabled</span></label>
			<button onclick="toggleRegistration()" class="secondary-btn">Toggle</button>
		    </div>
		    <div class="form-group">
			<label>Delete Comic ID:</label>
			<input type="text" id="deleteId" placeholder="Enter comic ID">
			<button onclick="deleteComic()" class="secondary-btn">Delete</button>
		    </div>
		</div>
            <div id="comicsGrid" class="comics-grid"></div>
        </div>
    </div>

    <div id="readerModal">
        <div class="reader-header">
            <div class="reader-title" id="readerTitle">Loading...</div>
            <div class="reader-controls">
                <button class="reader-btn" onclick="prevPage()" id="prevBtn">← Previous</button>
                <input type="number" class="page-input" id="pageInput" min="1" onchange="goToPage()">
                <span style="color: #8b949e;"> / <span id="totalPages">0</span></span>
                <button class="reader-btn" onclick="nextPage()" id="nextBtn">Next →</button>
                <button class="reader-btn" onclick="toggleFitMode()">Fit: <span id="fitMode">Width</span></button>
                <button class="reader-btn" onclick="closeReader()">Close</button>
            </div>
        </div>
        <div class="reader-content" id="readerContent">
            <img id="comicImage" alt="Comic page">
            <div class="zoom-controls">
                <button class="zoom-btn" onclick="zoomOut()">−</button>
                <button class="zoom-btn" onclick="resetZoom()">⊙</button>
                <button class="zoom-btn" onclick="zoomIn()">+</button>
            </div>
        </div>
    </div>

    <div id="tagModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Manage Tags</h3>
                <button class="close-btn" onclick="closeTagModal()">×</button>
            </div>

            <div class="tag-list" id="currentTags"></div>

            <div class="available-tags">
                <div class="available-tags-title">Available Tags (click to add):</div>
                <div class="tag-list" id="availableTags"></div>
            </div>

            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #30363d;">
                <h4 style="font-size: 14px; color: #8b949e; margin-bottom: 12px;">Create New Tag</h4>
                <div class="add-tag-form">
                    <input type="text" id="newTagName" class="add-tag-input" placeholder="Tag name">
                    <input type="color" id="newTagColor" class="color-picker" value="#1f6feb">
                    <button onclick="createTag()" style="width: auto; padding: 8px 16px;">Add</button>
                </div>
            </div>
        </div>
    </div>

    <div id="passwordModal">
    <div class="password-modal-content">
        <div class="password-modal-header">
            <div class="password-modal-title">🔒 Password Required</div>
            <div class="password-modal-subtitle" id="passwordComicTitle">This comic is encrypted</div>
        </div>

        <div id="passwordError" class="password-error hidden"></div>

        <div class="password-input-group">
            <label>Enter Password</label>
            <input type="password" id="passwordInput" placeholder="Enter password">
        </div>

        <div class="password-modal-buttons">
            <button onclick="cancelPassword()" class="secondary-btn">Cancel</button>
            <button onclick="submitPassword()">Unlock</button>
        </div>
    </div>
</div>

    <div id="contextMenu" class="context-menu hidden"></div>

    <script>
    let comics = [];
    let allTags = [];
    let currentComic = null;
    let currentPage = 0;
    let totalPages = 0;
    let zoomLevel = 1;
    let fitMode = 'width';
    let selectedTags = new Set();
    let managingComic = null;

    function showTab(tab) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        if (tab === 'register' && window.registrationEnabled === false) {
            showMessage('Registration disabled by admin', 'error', 'auth');
            return;
        }

        if (tab === 'login') {
            document.getElementById('loginForm').classList.remove('hidden');
            document.getElementById('registerForm').classList.add('hidden');
        } else {
            document.getElementById('loginForm').classList.add('hidden');
            document.getElementById('registerForm').classList.remove('hidden');
        }
    }

    async function register() {
        const username = document.getElementById('regUsername').value;
        const password = document.getElementById('regPassword').value;

        try {
            const res = await fetch('/api/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            });

            if (res.ok) {
                showMessage('Registration successful! Please login.', 'success', 'auth');
                document.getElementById('loginForm').classList.remove('hidden');
                document.getElementById('registerForm').classList.add('hidden');
                document.querySelectorAll('.tab')[0].classList.add('active');
                document.querySelectorAll('.tab')[1].classList.remove('active');
            } else {
                const data = await res.text();
                showMessage(data || 'Registration failed', 'error', 'auth');
            }
        } catch (err) {
            showMessage('Network error: ' + err.message, 'error', 'auth');
        }
    }

    async function login() {
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            });

            if (res.ok) {
                const data = await res.json();
                window.isAdmin = data.is_admin || false; // Ensure is_admin is defined
                window.registrationEnabled = true; // Default value
                document.getElementById('authSection').classList.add('hidden');
                document.getElementById('mainSection').classList.remove('hidden');
                document.getElementById('userInfo').classList.remove('hidden');

                if (window.isAdmin) {
                    try {
                        const adminRes = await fetch('/api/admin/toggle-registration');
                        if (adminRes.ok) {
                            const adminData = await adminRes.json();
                            window.registrationEnabled = adminData.enabled;
                            document.getElementById('regStatus').textContent = adminData.enabled ? 'Enabled' : 'Disabled';
                        } else {
                            console.error('Failed to fetch registration status:', await adminRes.text());
                            showMessage('Failed to load admin settings', 'error');
                        }
                    } catch (err) {
                        console.error('Error fetching admin settings:', err);
                        showMessage('Error loading admin settings', 'error');
                    }
                }

                await loadTags();
                await loadComics();
            } else {
                const error = await res.text();
                showMessage(error || 'Invalid credentials', 'error', 'auth');
            }
        } catch (err) {
            showMessage('Network error: ' + err.message, 'error', 'auth');
        }
    }

    async function logout() {
        await fetch('/api/logout', {method: 'POST'});
        location.reload();
    }

    async function uploadComic() {
        const fileInput = document.getElementById('fileUpload');
        const file = fileInput.files[0];

        if (!file) {
            showMessage('Please select a file', 'error');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);

        const res = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        if (res.ok) {
            showMessage('Comic uploaded successfully!', 'success');
            fileInput.value = '';
            loadComics();
        } else {
            showMessage('Upload failed', 'error');
        }
    }

    async function loadComics() {
        const res = await fetch('/api/comics');
        if (res.ok) {
            comics = await res.json();
            renderComics();
        } else {
            showMessage('Failed to load comics', 'error');
        }
    }

    async function loadTags() {
        const res = await fetch('/api/tags');
        if (res.ok) {
            allTags = await res.json();
            renderTagFilters();
        } else {
            showMessage('Failed to load tags', 'error');
        }
    }

    function renderTagFilters() {
        var container = document.getElementById('selectedTagFilters');
        container.innerHTML = '';

        selectedTags.forEach(function(tagName) {
            var tag = allTags.find(function(t) { return t.name === tagName; });
            var color = tag ? tag.color : '#1f6feb';
            var filter = document.createElement('div');
            filter.className = 'tag-filter';
            filter.style.background = color;
            filter.innerHTML = tagName + ' <span class="remove" style="cursor: pointer; margin-left: 8px;">x</span>';
            filter.querySelector('.remove').onclick = function(e) {
                e.stopPropagation();
                selectedTags.delete(tagName);
                renderTagFilters();
                renderComics();
            };
            container.appendChild(filter);
        });

        if (selectedTags.size > 0) {
            var clearBtn = document.createElement('button');
            clearBtn.textContent = 'Clear Filters';
            clearBtn.className = 'reader-btn';
            clearBtn.style.width = 'auto';
            clearBtn.onclick = function() {
                selectedTags.clear();
                renderTagFilters();
                renderComics();
            };
            container.appendChild(clearBtn);
        }

        var searchInput = document.getElementById('tagSearch');
        searchInput.oninput = function() {
            renderTagSuggestions(searchInput.value.toLowerCase());
        };
        searchInput.onclick = function() {
            renderTagSuggestions('');
        };
    }

    function renderTagSuggestions(searchTerm) {
        var container = document.getElementById('tagSuggestions');
        container.innerHTML = '';
        container.className = 'context-menu';

        var availableTags = allTags.filter(function(tag) {
            return !selectedTags.has(tag.name) &&
                   (searchTerm === '' || tag.name.toLowerCase().indexOf(searchTerm) !== -1);
        });

        if (availableTags.length === 0) {
            container.className = 'context-menu hidden';
            return;
        }

        availableTags.forEach(function(tag) {
            var item = document.createElement('div');
            item.className = 'context-menu-item';
            item.style.background = tag.color;
            item.textContent = tag.name + ' (' + tag.count + ')';
            item.onclick = function() {
                selectedTags.add(tag.name);
                renderTagFilters();
                renderComics();
                document.getElementById('tagSearch').value = '';
                container.className = 'context-menu hidden';
            };
            container.appendChild(item);
        });

        var searchInput = document.getElementById('tagSearch');
        var rect = searchInput.getBoundingClientRect();
        container.style.left = rect.left + 'px';
        container.style.top = (rect.bottom + window.scrollY) + 'px';
    }

    document.addEventListener('click', function(e) {
        var suggestions = document.getElementById('tagSuggestions');
        if (!e.target.closest('#tagSearch') && !e.target.closest('#tagSuggestions')) {
            suggestions.className = 'context-menu hidden';
        }
    });

    function renderComics() {
        if (window.isAdmin) {
            document.getElementById('adminPanel').classList.remove('hidden');
            document.getElementById('regStatus').textContent = window.registrationEnabled ? 'Enabled' : 'Disabled';
        } else {
            document.getElementById('adminPanel').classList.add('hidden');
        }

        const grid = document.getElementById('comicsGrid');
        grid.innerHTML = '';

        let filtered = comics;
        if (selectedTags.size > 0) {
            filtered = comics.filter(comic => {
                return Array.from(selectedTags).every(tag =>
                    comic.tags && comic.tags.includes(tag)
                );
            });
        }

        filtered.forEach(comic => {
            const card = document.createElement('div');
            card.className = 'comic-card';

            const coverContainer = document.createElement('div');
            coverContainer.className = 'comic-cover-container';

            const cover = document.createElement('img');
            cover.className = 'comic-cover';
            cover.src = '/api/cover/' + encodeURIComponent(comic.id);
            cover.alt = comic.title || comic.filename;

            const fallback = document.createElement('div');
            fallback.className = 'comic-cover-fallback hidden';
            fallback.textContent = 'COVER NOT AVAILABLE';
            fallback.style.background = '#21262d';

            cover.onerror = function() {
                cover.classList.add('hidden');
                fallback.classList.remove('hidden');
            };

            coverContainer.appendChild(cover);
            coverContainer.appendChild(fallback);
            card.appendChild(coverContainer);

            const info = document.createElement('div');
            info.className = 'comic-info';

            const artistClass = comic.artist === 'Unknown' ? 'unorganized' : '';

            let metaHTML = '';
            if (comic.series) metaHTML += '<div>Series: ' + comic.series + '</div>';
            if (comic.number) metaHTML += '<div>Issue: ' + comic.number + '</div>';
            if (comic.year) metaHTML += '<div>Year: ' + comic.year + '</div>';
            if (comic.page_count) metaHTML += '<div>Pages: ' + comic.page_count + '</div>';

            let tagsHTML = '';
            if (comic.tags && comic.tags.length > 0) {
                tagsHTML = '<div class="comic-tags">';
                comic.tags.forEach(tagName => {
                    const tag = allTags.find(t => t.name === tagName);
                    const color = tag ? tag.color : '#1f6feb';
                    tagsHTML += '<span class="comic-tag" style="background: ' + color + '">' + tagName + '</span>';
                });
                tagsHTML += '</div>';
            }

            info.innerHTML =
                '<div class="comic-title">' + (comic.title || comic.filename) + '</div>' +
                '<div class="comic-meta">' + metaHTML + '</div>' +
                '<span class="comic-artist' + artistClass + '">' + comic.artist + '</span>' +
                tagsHTML;

            card.appendChild(info);

            card.onclick = function(e) {
                if (e.target.classList.contains('comic-tag')) {
                    return;
                }
                openReader(comic);
            };

            card.oncontextmenu = function(e) {
                e.preventDefault();
                showContextMenu(e, comic);
            };

            grid.appendChild(card);
        });
    }

    function showContextMenu(e, comic) {
        const menu = document.getElementById('contextMenu');
        menu.className = 'context-menu';
        menu.innerHTML = '<div class="context-menu-item" onclick="openTagModal(\'' + comic.id + '\')">Manage Tags</div>';
        menu.style.left = e.pageX + 'px';
        menu.style.top = e.pageY + 'px';

        document.addEventListener('click', function hideMenu() {
            menu.className = 'context-menu hidden';
            document.removeEventListener('click', hideMenu);
        });
    }

    function openTagModal(comicId) {
        managingComic = comics.find(c => c.id === comicId);
        if (!managingComic) return;

        document.getElementById('tagModal').classList.add('active');
        renderCurrentTags();
        renderAvailableTags();
    }

    function closeTagModal() {
        document.getElementById('tagModal').classList.remove('active');
        managingComic = null;
        loadComics();
        loadTags();
    }

    function renderCurrentTags() {
        const container = document.getElementById('currentTags');
        container.innerHTML = '';

        if (!managingComic.tags || managingComic.tags.length === 0) {
            container.innerHTML = '<div style="color: #8b949e; font-size: 13px;">No tags assigned</div>';
            return;
        }

        managingComic.tags.forEach(tagName => {
            const tag = allTags.find(t => t.name === tagName);
            const color = tag ? tag.color : '#1f6feb';

            const item = document.createElement('div');
            item.className = 'tag-item';
            item.style.background = color;
            item.innerHTML = tagName + ' <span class="remove">×</span>';
            item.querySelector('.remove').onclick = function(e) {
                e.stopPropagation();
                removeTag(tagName);
            };
            container.appendChild(item);
        });
    }

    function renderAvailableTags() {
        const container = document.getElementById('availableTags');
        container.innerHTML = '';

        const available = allTags.filter(tag =>
            !managingComic.tags || !managingComic.tags.includes(tag.name)
        );

        if (available.length === 0) {
            container.innerHTML = '<div style="color: #8b949e; font-size: 13px;">All tags assigned</div>';
            return;
        }

        available.forEach(tag => {
            const item = document.createElement('div');
            item.className = 'tag-item';
            item.style.background = tag.color;
            item.textContent = tag.name;
            item.onclick = function() {
                addTagToComic(tag.name);
            };
            container.appendChild(item);
        });
    }

    async function addTagToComic(tagName) {
        const res = await fetch('/api/comic-tags/' + encodeURIComponent(managingComic.id), {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({tag: tagName})
        });

        if (res.ok) {
            const updated = await res.json();
            managingComic = updated;
            const idx = comics.findIndex(c => c.id === updated.id);
            if (idx >= 0) comics[idx] = updated;
            renderCurrentTags();
            renderAvailableTags();
        }
    }

    async function removeTag(tagName) {
        const res = await fetch('/api/comic-tags/' + encodeURIComponent(managingComic.id) + '/' + encodeURIComponent(tagName), {
            method: 'DELETE'
        });

        if (res.ok) {
            const updated = await res.json();
            managingComic = updated;
            const idx = comics.findIndex(c => c.id === updated.id);
            if (idx >= 0) comics[idx] = updated;
            renderCurrentTags();
            renderAvailableTags();
        }
    }

    async function createTag() {
        const name = document.getElementById('newTagName').value.trim();
        const color = document.getElementById('newTagColor').value;

        if (!name) {
            showMessage('Please enter a tag name', 'error');
            return;
        }

        const res = await fetch('/api/tags', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name, color})
        });

        if (res.ok) {
            document.getElementById('newTagName').value = '';
            document.getElementById('newTagColor').value = '#1f6feb';
            loadTags();
            renderAvailableTags();
            showMessage('Tag created!', 'success');
        } else {
            showMessage('Failed to create tag', 'error');
        }
    }

    async function openReader(comic) {
        currentComic = comic;
        currentPage = 0;

        document.getElementById('readerTitle').textContent = comic.title || comic.filename;
        document.getElementById('readerModal').classList.add('active');

	if (comic.encrypted && !comic.has_password) {
		await showPasswordModal(comic);
		return;
	}

        const encodedId = encodeURIComponent(currentComic.id);
        const url = '/api/pages/' + encodedId;

        try {
            const res = await fetch(url);

            if (res.ok) {
                const data = await res.json();
                if (data.needs_password) {
                    alert('Password required but not set. Please re-open the comic.');
                    closeReader();
                    return;
                }
                totalPages = data.page_count;
                document.getElementById('totalPages').textContent = totalPages;
                document.getElementById('pageInput').max = totalPages;

                if (totalPages > 0) {
                    loadPage(0);
                } else {
                    showMessage('No pages found in comic', 'error');
                }
            } else {
                const error = await res.text();
                showMessage('Error loading comic: ' + error, 'error');
            }
        } catch (err) {
            showMessage('Error: ' + err.message, 'error');
        }
    }

    function closeReader() {
        document.getElementById('readerModal').classList.remove('active');
        currentComic = null;
    }

    async function loadPage(pageNum) {
        if (pageNum < 0 || pageNum >= totalPages) return;

        currentPage = pageNum;
        document.getElementById('pageInput').value = currentPage + 1;

        const img = document.getElementById('comicImage');
        const encodedId = encodeURIComponent(currentComic.id);
        const imgUrl = '/api/comic/' + encodedId + '/page/' + currentPage;

        img.src = imgUrl;

        img.onerror = function() {
            showMessage('Failed to load page ' + (currentPage + 1), 'error');
        };

        document.getElementById('prevBtn').disabled = currentPage === 0;
        document.getElementById('nextBtn').disabled = currentPage === totalPages - 1;

        resetZoom();
    }

    function nextPage() {
        if (currentPage < totalPages - 1) {
            loadPage(currentPage + 1);
        }
    }

    function prevPage() {
        if (currentPage > 0) {
            loadPage(currentPage - 1);
        }
    }

    function goToPage() {
        const pageNum = parseInt(document.getElementById('pageInput').value) - 1;
        if (pageNum >= 0 && pageNum < totalPages) {
            loadPage(pageNum);
        }
    }

    function zoomIn() {
        zoomLevel = Math.min(zoomLevel + 0.25, 5);
        applyZoom();
    }

    function zoomOut() {
        zoomLevel = Math.max(zoomLevel - 0.25, 0.25);
        applyZoom();
    }

    function resetZoom() {
        zoomLevel = 1;
        applyZoom();
    }

    function applyZoom() {
        const img = document.getElementById('comicImage');
        img.style.transform = 'scale(' + zoomLevel + ')';
    }

    function toggleFitMode() {
        const modes = ['width', 'height', 'page'];
        const currentIndex = modes.indexOf(fitMode);
        fitMode = modes[(currentIndex + 1) % modes.length];

        const img = document.getElementById('comicImage');

        img.style.maxWidth = '';
        img.style.maxHeight = '';
        img.style.width = '';
        img.style.height = '';

        if (fitMode === 'width') {
            img.style.maxWidth = '100%';
            img.style.height = 'auto';
        } else if (fitMode === 'height') {
            img.style.maxHeight = '100%';
            img.style.width = 'auto';
        } else {
            img.style.maxWidth = '100%';
            img.style.maxHeight = '100%';
        }

        document.getElementById('fitMode').textContent = fitMode.charAt(0).toUpperCase() + fitMode.slice(1);
    }

    document.addEventListener('keydown', function(e) {
	if (document.getElementById('passwordModal').classList.contains('active')) {
	    if (e.key === 'Enter') {
		submitPassword();
		return;
	    }
	    if (e.key === 'Escape') {
		cancelPassword();
		return;
	    }
	}
        if (!currentComic) return;

        if (e.key === 'ArrowRight' || e.key === 'd') nextPage();
        if (e.key === 'ArrowLeft' || e.key === 'a') prevPage();
        if (e.key === 'Escape') closeReader();
        if (e.key === '+' || e.key === '=') zoomIn();
        if (e.key === '-' || e.key === '_') zoomOut();
        if (e.key === '0') resetZoom();
    });

    function showMessage(text, type, context = 'main') {
        let msg;
        if (context === 'auth') {
            msg = document.getElementById('authMessage');
        } else {
            msg = document.getElementById('message');
        }
        msg.textContent = text;
        msg.className = 'message ' + type;
        setTimeout(function() { msg.className = 'message hidden'; }, 5000);
    }

    async function toggleRegistration() {
        try {
            const res = await fetch('/api/admin/toggle-registration', {method: 'POST'});
            if (res.ok) {
                const data = await res.json();
                window.registrationEnabled = data.enabled;
                document.getElementById('regStatus').textContent = data.enabled ? 'Enabled' : 'Disabled';
                showMessage('Registration toggled!', 'success');
            } else {
                showMessage('Toggle failed: ' + (await res.text()), 'error');
            }
        } catch (err) {
            showMessage('Network error: ' + err.message, 'error');
        }
    }

    async function deleteComic() {
        const id = document.getElementById('deleteId').value.trim();
        if (!id) {
            showMessage('Please enter a comic ID', 'error');
            return;
        }
        if (!confirm('Delete comic ID: ' + id + '?')) return;
        try {
            const res = await fetch('/api/admin/delete-comic/' + encodeURIComponent(id), {method: 'DELETE'});
            if (res.ok) {
                loadComics();
                showMessage('Comic deleted!', 'success');
                document.getElementById('deleteId').value = '';
            } else {
                showMessage('Delete failed: ' + (await res.text()), 'error');
            }
        } catch (err) {
            showMessage('Network error: ' + err.message, 'error');
        }
    }
    let pendingPasswordComic = null;

async function showPasswordModal(comic) {
    pendingPasswordComic = comic;
    document.getElementById('passwordComicTitle').textContent = comic.title || comic.filename;
    document.getElementById('passwordInput').value = '';
    document.getElementById('passwordError').className = 'password-error hidden';
    document.getElementById('passwordModal').classList.add('active');
    document.getElementById('passwordInput').focus();
}

function cancelPassword() {
    document.getElementById('passwordModal').classList.remove('active');
    document.getElementById('readerModal').classList.remove('active');
    pendingPasswordComic = null;
}

async function submitPassword() {
    const pwd = document.getElementById('passwordInput').value;
    if (!pwd) {
        showPasswordError('Please enter a password');
        return;
    }

    const res = await fetch("/api/set-password/" + encodeURIComponent(pendingPasswordComic.id), {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({password: pwd})
    });

    if (!res.ok) {
        showPasswordError('Invalid password. Please try again.');
        document.getElementById('passwordInput').value = '';
        document.getElementById('passwordInput').focus();
        return;
    }

    document.getElementById('passwordModal').classList.remove('active');
    await loadComics();
    await loadTags();
    currentComic = comics.find(c => c.id === pendingPasswordComic.id);
    pendingPasswordComic = null;

    // Continue opening the reader
    continueOpenReader();
}

function showPasswordError(message) {
    const errorDiv = document.getElementById('passwordError');
    errorDiv.textContent = message;
    errorDiv.className = 'password-error';
}

async function continueOpenReader() {
    const encodedId = encodeURIComponent(currentComic.id);
    const url = '/api/pages/' + encodedId;

    try {
        const res = await fetch(url);

        if (res.ok) {
            const data = await res.json();
            if (data.needs_password) {
                alert('Password required but not set. Please re-open the comic.');
                closeReader();
                return;
            }
            totalPages = data.page_count;
            document.getElementById('totalPages').textContent = totalPages;
            document.getElementById('pageInput').max = totalPages;

            if (totalPages > 0) {
                loadPage(0);
            } else {
                showMessage('No pages found in comic', 'error');
            }
        } else {
            const error = await res.text();
            showMessage('Error loading comic: ' + error, 'error');
        }
    } catch (err) {
        showMessage('Error: ' + err.message, 'error');
    }
}

    // Initial check for logged-in user
    fetch('/api/comics')
        .then(function(res) {
            if (res.ok) {
                document.getElementById('authSection').classList.add('hidden');
                document.getElementById('mainSection').classList.remove('hidden');
                document.getElementById('userInfo').classList.remove('hidden');
                loadTags().then(loadComics);
            }
        })
        .catch(function(err) {
            console.error('Initial comics fetch failed:', err);
        });
</script>
</body>
</html>`
}
