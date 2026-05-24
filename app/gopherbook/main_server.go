//go:build !desktop

package main

import (
	"log"
	"net/http"
	"os"
	"runtime"
)

func main() {
	os.MkdirAll(libraryPath, 0755)
	os.MkdirAll(cachePath, 0755)
	os.MkdirAll(etcPath, 0755)
	os.MkdirAll(watchPath, 0755)

	// Scale cover generation concurrency to CPU count, capped at 4
	coverWorkers := runtime.NumCPU()
	if coverWorkers > 4 {
		coverWorkers = 4
	}
	coverGenSemaphore = make(chan struct{}, coverWorkers)
	log.Printf("Cover generation semaphore width: %d", coverWorkers)

	initCore()
	defer db.Close()
	setupRoutes()
	startBackgroundTasks()

	port := os.Getenv("GBKPORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("Server starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

