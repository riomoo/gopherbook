package main

// CB7 (7-zip) support.
//
// CB7 unencrypted  - pure Go via github.com/bodgit/sevenzip
// CB7 encrypted    - pure Go via github.com/bodgit/sevenzip (AES-256)
//
// bodgit/sevenzip ships its own LZMA2 codec but needs kulaginds/lzma
// registered to handle LZMA (v1) archives without "first byte not zero" errors.

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"

	"hash/crc32"

	"github.com/bodgit/sevenzip"
	"github.com/kulaginds/lzma"
	"github.com/nfnt/resize"
)

func init() {
	// Register kulaginds LZMA decompressor so bodgit/sevenzip handles
	// archives compressed with the older LZMA (v1) method correctly.
	sevenzip.RegisterDecompressor(
		[]byte{0x03, 0x01, 0x01},
		sevenzip.Decompressor(lzma.NewLZMADecompressorForSevenZip),
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers shared by both formats
// ─────────────────────────────────────────────────────────────────────────────

func isImageExt(ext string) bool {
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".avif", ".webp", ".bmp", ".jp2", ".jxl":
		return true
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// CB7 – 7-zip archives
// ─────────────────────────────────────────────────────────────────────────────

// lockCB7File returns a locked mutex for the given file path.
// The caller must call the returned unlock function when done.
// This serialises concurrent opens of the same 7z file because
// bodgit/sevenzip's LZMA range decoder is not goroutine-safe when
// two goroutines open and decompress the same file simultaneously.
func lockCB7File(filePath string) func() {
	v, _ := cb7Mutexes.LoadOrStore(filePath, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// openCB7 opens a CB7 archive with an optional password.
func openCB7(filePath, password string) (*sevenzip.ReadCloser, error) {
	if password != "" {
		return sevenzip.OpenReaderWithPassword(filePath, password)
	}
	return sevenzip.OpenReader(filePath)
}

// getCB7Password returns the active password for a comic (struct field takes
// priority over the global in-memory map).
func getCB7Password(comic Comic) string {
	if comic.Password != "" {
		return comic.Password
	}
	passwordsMutex.RLock()
	p := comicPasswords[comic.ID]
	passwordsMutex.RUnlock()
	return p
}

// getCB7PageIndex returns a cached, sorted slice of image filenames for a CB7,
// building it on the first call.  The index is stored in the shared
// pageIndexCache so it is evicted alongside CBZ entries on comic deletion.
func getCB7PageIndex(comic Comic) ([]string, error) {
	pageIndexCacheMutex.RLock()
	if idx, ok := pageIndexCache[comic.ID]; ok {
		pageIndexCacheMutex.RUnlock()
		return idx, nil
	}
	pageIndexCacheMutex.RUnlock()

	unlock := lockCB7File(comic.FilePath)
	defer unlock()

	r, err := openCB7(comic.FilePath, getCB7Password(comic))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// r.File is populated from the central directory; no decompression happens
	// here — iterating it is cheap regardless of archive size or compression.
	var names []string
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if isImageExt(strings.ToLower(filepath.Ext(f.Name))) {
			names = append(names, f.Name)
		}
	}
	sort.Strings(names)

	pageIndexCacheMutex.Lock()
	pageIndexCache[comic.ID] = names
	pageIndexCacheMutex.Unlock()

	return names, nil
}

// isCB7Encrypted returns true if the 7zip archive requires a password.
// Handles both content encryption and header encryption (-mhe=on).
func isCB7Encrypted(filePath string) bool {
	unlock := lockCB7File(filePath)
	defer unlock()

	r, err := sevenzip.OpenReader(filePath)
	if err != nil {
		// Any open error on a valid 7z file likely means header encryption.
		r2, err2 := sevenzip.OpenReaderWithPassword(filePath, "dummy_probe_password")
		if err2 == nil {
			r2.Close()
			return true
		}
		log.Printf("[CB7] %q needs decryption key (header-encrypted)", filepath.Base(filePath))
		return true
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return true
		}
		buf := make([]byte, 16)
		_, readErr := io.ReadAtLeast(rc, buf, 1)
		rc.Close()
		if readErr != nil {
			return true
		}
		return false
	}
	return false
}

// validateCB7Password checks a password against a 7zip archive.
//
// bodgit/sevenzip cannot reliably detect a wrong password via errors alone:
// - With compression+encryption, the wrong password causes a decompression error.
// - With encryption-only (-mx=0), the wrong password produces silent garbage.
//
// The only reliable method for all cases is to extract a file and verify its
// CRC32 against the value stored in the archive header.
func validateCB7Password(filePath, password string) bool {
	unlock := lockCB7File(filePath)
	defer unlock()

	r, err := sevenzip.OpenReaderWithPassword(filePath, password)
	if err != nil {
		log.Printf("[CB7 validate] OpenReaderWithPassword error: %v", err)
		return false
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			log.Printf("[CB7 validate] Open() error for %q: %v", f.Name, err)
			return false
		}

		h := crc32.NewIEEE()
		_, readErr := io.Copy(h, rc)
		rc.Close()

		if readErr != nil {
			return false
		}
		if f.CRC32 == 0 {
			return true
		}
		return h.Sum32() == f.CRC32
	}
	return false
}

// listCB7Images returns sorted image filenames from a CB7.
// Kept for any callers outside this file; uses the page index cache.
func listCB7Images(filePath, password string) ([]string, error) {
	// Build a minimal Comic stub so getCB7PageIndex can use the cache.
	// FilePath is the only field needed when Password is supplied directly.
	stub := Comic{ID: filePath, FilePath: filePath, Password: password}
	return getCB7PageIndex(stub)
}

// extractCB7Page reads the raw bytes of a single image page from a CB7.
func extractCB7Page(comic Comic, pageIdx int) ([]byte, string, error) {
	imageFiles, err := getCB7PageIndex(comic)
	if err != nil {
		return nil, "", err
	}
	if pageIdx < 0 || pageIdx >= len(imageFiles) {
		return nil, "", fmt.Errorf("page %d out of range (have %d)", pageIdx, len(imageFiles))
	}
	targetName := imageFiles[pageIdx]

	unlock := lockCB7File(comic.FilePath)
	defer unlock()

	r, err := openCB7(comic.FilePath, getCB7Password(comic))
	if err != nil {
		return nil, "", err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name != targetName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, "", err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, "", err
		}
		return data, targetName, nil
	}
	return nil, "", fmt.Errorf("page file %q not found in archive", targetName)
}

// generateCB7Cover generates a cover thumbnail for a CB7 comic.
func generateCB7Cover(comic *Comic, cacheFile string) error {
	oldGC := debug.SetGCPercent(10)
	defer func() {
		debug.SetGCPercent(oldGC)
		runtime.GC()
		debug.FreeOSMemory()
	}()

	// extractCB7Page acquires the per-file lock internally.
	data, _, err := extractCB7Page(*comic, 0)
	if err != nil {
		return fmt.Errorf("extractCB7Page: %w", err)
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	data = nil

	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	const maxDim = 300
	var nw, nh int
	if w > h {
		nw = maxDim
		nh = int(float64(h) * float64(maxDim) / float64(w))
	} else {
		nh = maxDim
		nw = int(float64(w) * float64(maxDim) / float64(h))
	}
	resized := resize.Resize(uint(nw), uint(nh), img, resize.Lanczos3)
	img = nil
	runtime.GC()

	out, err := os.Create(cacheFile)
	if err != nil {
		return err
	}
	defer out.Close()
	return jpeg.Encode(out, resized, &jpeg.Options{Quality: 75})
}

// getCB7PageCount returns the number of images in a CB7.
func getCB7PageCount(comic Comic) (int, error) {
	names, err := getCB7PageIndex(comic)
	return len(names), err
}

// serveCB7Page writes a single CB7 image page to the HTTP response.
func serveCB7Page(w http.ResponseWriter, r *http.Request, comic Comic, pageNum string) {
	var pageIdx int
	fmt.Sscanf(pageNum, "%d", &pageIdx)

	data, name, err := extractCB7Page(comic, pageIdx)
	if err != nil {
		http.Error(w, "Error reading page: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ext := strings.ToLower(filepath.Ext(name))
	w.Header().Set("Content-Type", getContentType(ext))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(data)
}

// extractCB7Metadata reads ComicInfo.xml from a CB7 archive.
func extractCB7Metadata(comic *Comic) {
	password := comic.Password
	if password == "" {
		passwordsMutex.RLock()
		password = comicPasswords[comic.ID]
		passwordsMutex.RUnlock()
	}

	unlock := lockCB7File(comic.FilePath)
	defer unlock()

	r, err := openCB7(comic.FilePath, password)
	if err != nil {
		return
	}
	defer r.Close()

	for _, f := range r.File {
		name := strings.ToLower(f.Name)
		if name != "comicinfo.xml" && !strings.HasSuffix(name, "/comicinfo.xml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return
		}
		parseComicInfoXML(data, comic)
		return // stop as soon as we've found and parsed it
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared XML parser (extracted so CBR/CB7/CBT can reuse it)
// ─────────────────────────────────────────────────────────────────────────────

func parseComicInfoXML(data []byte, comic *Comic) {
	var info ComicInfo
	if err := xmlUnmarshal(data, &info); err != nil {
		return
	}
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
			if t := strings.TrimSpace(tag); t != "" {
				comic.Tags = append(comic.Tags, t)
			}
		}
	}
}
