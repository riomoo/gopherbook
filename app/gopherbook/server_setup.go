package main

// server_setup.go — shared between plain server build (!desktop) and the
// Fyne desktop build (desktop).  No build tags: both targets compile this.

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	bolt "go.etcd.io/bbolt"
)

// setupRoutes registers every HTTP handler and the static file server.
// Call once before starting the listener in either build mode.
func setupRoutes() {
	staticSubFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal(fmt.Errorf("failed to create static sub-filesystem: %w", err))
	}
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
}

// startBackgroundTasks launches all recurring goroutines shared by both builds.
func startBackgroundTasks() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			runtime.GC()
			debug.FreeOSMemory()
		}
	}()
	go cleanupSessions()
	go cleanupExpiredShareLinks()
}

// initCore opens the database, loads user data, and sets up the watch folders.
// The caller must defer db.Close() after calling this.
func initCore() {
	dbPath := filepath.Join(etcPath, "gopherbooks.db")
	var err error
	db, err = bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte("config"))
		return nil
	})

	loadUsers()
	for username := range users {
		loadShareLinks(username)
	}
	initWatchFolders()
}
