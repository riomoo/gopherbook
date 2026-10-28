package main

// Saving the library to bbolt, and deleting comics.
//
// Most edits (tags, bookmarks, metadata) are saved through debounceSave,
// which batches them into one write 5 seconds after the last change. That
// delay used to lose changes: a save still pending when the user logged
// out ran with currentUser already cleared (so it wrote nothing), and one
// pending when the desktop window closed or the server was stopped never
// ran at all. A comic deleted just before that kept its database entry
// while its file was gone, and nothing ever removed the entry again.
//
// Now: deletions save immediately; logout, closing the desktop app and
// SIGINT/SIGTERM flush any pending save first; saves never overlap; and
// loading a library drops entries whose file no longer exists.

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var (
	saveMu      sync.Mutex // guards saveTimer and savePending
	savePending bool
	saveRunMu   sync.Mutex // serializes the saves themselves
)

// debounceSave schedules a save of comics, tags and passwords 5 seconds
// after the last call.
func debounceSave() {
	saveMu.Lock()
	defer saveMu.Unlock()
	savePending = true
	if saveTimer != nil {
		saveTimer.Stop()
	}
	saveTimer = time.AfterFunc(5*time.Second, runPendingSave)
}

// runPendingSave performs the scheduled save, if one is still pending.
func runPendingSave() {
	saveRunMu.Lock()
	defer saveRunMu.Unlock()
	saveMu.Lock()
	pending := savePending
	savePending = false
	saveMu.Unlock()
	if pending && currentUser != "" {
		saveComics()
		saveTags()
		savePasswords()
	}
}

// flushPendingSave runs a scheduled save right away instead of waiting
// for the timer, and waits for a save that's already running. Call it
// before anything that changes currentUser or ends the process.
func flushPendingSave() {
	saveMu.Lock()
	if saveTimer != nil {
		saveTimer.Stop()
	}
	saveMu.Unlock()
	runPendingSave()
}

// saveNow saves comics, tags and passwords immediately.
func saveNow() {
	saveMu.Lock()
	savePending = true
	saveMu.Unlock()
	flushPendingSave()
}

// flushOnSignal saves pending changes and exits cleanly on SIGINT/SIGTERM
// (Ctrl-C, `podman stop`, a desktop session logging out), instead of
// dying with up to 5 seconds of edits unsaved.
func flushOnSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-ch
		log.Printf("Received %v: saving library before exit", s)
		flushPendingSave()
		if db != nil {
			db.Close()
		}
		os.Exit(0)
	}()
}

var errComicNotFound = errors.New("comic not found")

// deleteComicByID deletes a comic's file, its cached cover, its share
// links and its library entry, and saves the library at once. If the file
// can't be deleted (permissions, or a lock on Windows), the entry is kept
// so the library and the disk don't disagree.
func deleteComicByID(id, username string) error {
	comicsMutex.Lock()
	comic, exists := comics[id]
	if !exists {
		comicsMutex.Unlock()
		return errComicNotFound
	}
	if err := os.Remove(comic.FilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		comicsMutex.Unlock()
		return fmt.Errorf("could not delete %s: %w", filepath.Base(comic.FilePath), err)
	}
	for _, tag := range comic.Tags {
		updateTagCount(tag, -1)
	}
	delete(comics, id)
	comicsMutex.Unlock()

	os.Remove(filepath.Join(cachePath, comic.ID+".jpg"))
	pageIndexCacheMutex.Lock()
	delete(pageIndexCache, id)
	pageIndexCacheMutex.Unlock()

	shareLinksMutex.Lock()
	removed := false
	for token, sl := range shareLinks {
		if sl.ComicID == id {
			delete(shareLinks, token)
			removed = true
		}
	}
	shareLinksMutex.Unlock()
	if removed && username != "" {
		saveShareLinks(username)
	}

	saveNow()
	return nil
}

// pruneMissingComics removes library entries whose file no longer exists
// (e.g. left behind by a deletion whose save was lost before this fix) and
// reports how many it removed. It does nothing when the library folder
// itself is missing, such as an unmounted drive, so a missing drive can't
// wipe everyone's tags and bookmarks.
func pruneMissingComics() int {
	if _, err := os.Stat(libraryPath); err != nil {
		return 0
	}
	comicsMutex.Lock()
	defer comicsMutex.Unlock()
	n := 0
	for id, c := range comics {
		if c.FilePath == "" {
			delete(comics, id)
			n++
			continue
		}
		if _, err := os.Stat(c.FilePath); errors.Is(err, os.ErrNotExist) {
			log.Printf("Removing library entry for missing file %s", c.FilePath)
			delete(comics, id)
			n++
		}
	}
	return n
}

// createUniqueFile creates dir/name, or dir/base_1.ext, dir/base_2.ext, ...
// if that name is taken, without ever replacing an existing file
// (O_EXCL makes the check and the creation one step, so two uploads of the
// same name can't race into one file).
func createUniqueFile(dir, name string) (string, *os.File, error) {
	ext := filepath.Ext(name)
	base := name[:len(name)-len(ext)]
	for i := 0; i < 10000; i++ {
		p := filepath.Join(dir, name)
		if i > 0 {
			p = filepath.Join(dir, fmt.Sprintf("%s_%d%s", base, i, ext))
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err == nil {
			return p, f, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, fmt.Errorf("no free name for %s in %s", name, dir)
}
