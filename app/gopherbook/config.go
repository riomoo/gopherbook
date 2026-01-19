package main

import (
	"os"
	"path/filepath"
)

var (
	baseLibraryPath string
	baseCachePath   string
	baseEtcPath     string
	baseWatchPath   string
)

func init() {
	// Store the base paths (before user-specific paths are added)
	baseLibraryPath = libraryPath
	baseCachePath = cachePath
	baseEtcPath = etcPath
	baseWatchPath = watchPath

	// Override from environment variables if set
	if env := os.Getenv("GOPHERBOOK_LIBRARY"); env != "" {
		baseLibraryPath = filepath.Clean(env)
		libraryPath = baseLibraryPath
	}
	if env := os.Getenv("GOPHERBOOK_CACHE"); env != "" {
		baseCachePath = filepath.Clean(env)
		cachePath = baseCachePath
	}
	if env := os.Getenv("GOPHERBOOK_ETC"); env != "" {
		baseEtcPath = filepath.Clean(env)
		etcPath = baseEtcPath
	}
	if env := os.Getenv("GOPHERBOOK_WATCH"); env != "" {
		baseWatchPath = filepath.Clean(env)
		watchPath = baseWatchPath
	}
}
