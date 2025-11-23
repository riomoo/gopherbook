package main

import (
	"archive/zip"
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
	Password    string    `json:"-"`
	Tags        []string  `json:"tags"`
	UploadedAt  time.Time `json:"uploaded_at"`
	Bookmarks   []int     `json:"bookmarks"`
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
)

func main() {
	os.MkdirAll(filepath.Join(libraryPath, "Unorganized"), 0755)
	os.MkdirAll(cachePath, 0755)
	os.MkdirAll(etcPath, 0755)

	loadUsers()

	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/comics", authMiddleware(handleComics))
	http.HandleFunc("/api/upload", authMiddleware(handleUpload))
	http.HandleFunc("/api/user", authMiddleware(handleUser))
	http.HandleFunc("/api/organize", authMiddleware(handleOrganize))
	http.HandleFunc("/api/pages/", authMiddleware(handleComicPages))
	http.HandleFunc("/api/comic/", authMiddleware(handleComicFile))
	http.HandleFunc("/api/cover/", authMiddleware(handleCover))
	http.HandleFunc("/api/tags", authMiddleware(handleTags))
	http.HandleFunc("/api/comic-tags/", authMiddleware(handleComicTags))
	http.HandleFunc("/api/set-password/", authMiddleware(handleSetPassword))
	http.HandleFunc("/api/bookmark/", authMiddleware(handleBookmark))
	http.HandleFunc("/api/admin/toggle-registration", authMiddleware(handleToggleRegistration))
	http.HandleFunc("/api/admin/delete-comic/", authMiddleware(handleDeleteComic))
	http.HandleFunc("/", serveUI)

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
	scanLibrary()

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

	comicsMutex.RLock()
	defer comicsMutex.RUnlock()

	comicList := make([]Comic, 0, len(comics))
	for _, comic := range comics {
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

	r.ParseMultipartForm(100 << 20)

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := header.Filename
	ext := strings.ToLower(filepath.Ext(filename))

	if ext != ".cbz" {
		http.Error(w, "Invalid file type", http.StatusBadRequest)
		return
	}

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

	comic := processComic(destPath, filename)

	comicsMutex.Lock()
	comics[comic.ID] = comic
	comicsMutex.Unlock()

	generateCoverCache(&comic)

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

	cacheFile := filepath.Join(cachePath, comic.ID+".jpg")
	if _, err := os.Stat(cacheFile); err == nil {
		http.ServeFile(w, r, cacheFile)
		return
	}

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

	comicsMutex.Lock()
	c = comics[decodedID]
	extractCBZMetadata(&c)

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
		saveComics()

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
		saveComics()

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

	var pageIdx int
	fmt.Sscanf(pageNum, "%d", &pageIdx)

	yr, err := yzip.OpenReader(comic.FilePath)
	if err != nil {
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
		if comic.Password != "" {
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

	if coverFile.IsEncrypted() {
		if comic.Password != "" {
			coverFile.SetPassword(comic.Password)
		} else {
			http.Error(w, "Comic requires password", http.StatusUnauthorized)
			return
		}
	}

	rc, err := coverFile.Open()
	if err != nil {
		http.Error(w, "Error reading cover", http.StatusInternalServerError)
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
		Bookmarks:  []int{},
	}

	if comic.FileType == ".cbz" {
		extractCBZMetadata(&comic)
		tagsMutex.Lock()
		for _, tag := range comic.Tags {
			if _, exists := tags[tag]; !exists {
				tags[tag] = Tag{
					Name:  tag,
					Color: "#1f6feb",
					Count: 0,
				}
			}
			tagData := tags[tag]
			tagData.Count++
			tags[tag] = tagData
		}
		tagsMutex.Unlock()
		saveTags()

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

	if coverFile.IsEncrypted() {
		if comic.Password != "" {
			coverFile.SetPassword(comic.Password)
		} else {
			return
		}
	}

	rc, err := coverFile.Open()
	if err != nil {
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
	comic.HasPassword = false

	if !isEncrypted {
		extractCBZMetadataStandard(comic)
		comic.HasPassword = true
		return
	}

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
				comic.Password = foundPwd
				comic.HasPassword = true
				passwordsMutex.Lock()
				comicPasswords[comic.ID] = foundPwd
				passwordsMutex.Unlock()
				savePasswords()
			} else if !isEncrypted {
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
			comic := comics[id]
			cacheFile := filepath.Join(cachePath, comic.ID+".jpg")
			if _, err := os.Stat(cacheFile); os.IsNotExist(err) && comic.FileType == ".cbz" {
				comicsMutex.RLock()
				c := comics[id]
				comicsMutex.RUnlock()
				generateCoverCache(&c)
				comicsMutex.Lock()
				comics[id] = c
				comicsMutex.Unlock()
			}
			return nil
		}

		comic := processComic(path, info.Name())
		comicsMutex.Lock()
		comics[comic.ID] = comic
		comicsMutex.Unlock()

		comicsMutex.RLock()
		c := comics[comic.ID]
		comicsMutex.RUnlock()
		generateCoverCache(&c)
		comicsMutex.Lock()
		comics[comic.ID] = c
		comicsMutex.Unlock()

		return nil
	})

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
