package main

// EPUB 3 support for Gopherbook.
//
// Encryption scheme:
//   Algorithm : AES-256-GCM
//   KDF       : SHA-256 double-hash with prefix "epub-comic-key-v1:"
//   Nonce     : 12-byte random prepended to each ciphertext blob
//   Tag       : 16-byte GCM tag appended (part of gcm.Seal output)
//   Scope     : Only OEBPS/images/* entries are encrypted; all XML/XHTML
//               structural files are always plaintext.
//   Detection : Presence of META-INF/encryption.xml with at least one
//               CipherReference entry.
//
// Password validation:
//   META-INF/key-hint.txt contains a base64-encoded SHA-256 hash of
//   "verify:" + password.  We verify this before attempting to decrypt
//   any image data so we can give a fast, deterministic "wrong password"
//   response without streaming a multi-MB image.

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png"
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

	"github.com/nfnt/resize"
)

// epubMutexes serialises concurrent opens of the same EPUB file.
// EPUB is a ZIP, and archive/zip is not goroutine-safe when two goroutines
// open and decompress the same file simultaneously.
var epubMutexes sync.Map // map[filePath]*sync.Mutex

func lockEPUBFile(filePath string) func() {
	v, _ := epubMutexes.LoadOrStore(filePath, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// ─── Encryption helpers ───────────────────────────────────────────────────────

// deriveEPUBKey derives a 32-byte AES-256 key from a password using the same
// double-SHA-256 scheme as the epub builder tool.
func deriveEPUBKey(password string) []byte {
	h := sha256.New()
	h.Write([]byte("epub-comic-key-v1:" + password))
	first := h.Sum(nil)
	h.Reset()
	h.Write(first)
	h.Write([]byte(password))
	return h.Sum(nil)
}

// decryptEPUBBytes decrypts a single AES-256-GCM blob produced by the builder.
// Format: nonce (12 bytes) || ciphertext+tag.
func decryptEPUBBytes(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// ─── Encryption detection ─────────────────────────────────────────────────────

// isEPUBEncrypted returns true if META-INF/encryption.xml lists at least one
// CipherReference — i.e. the file was built with a password.
func isEPUBEncrypted(filePath string) bool {
	unlock := lockEPUBFile(filePath)
	defer unlock()

	r, err := zip.OpenReader(filePath)
	if err != nil {
		return false
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name != "META-INF/encryption.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return false
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		return strings.Contains(string(data), "CipherReference")
	}
	return false
}

// ─── Password validation ──────────────────────────────────────────────────────

// validateEPUBPassword checks the password against the SHA-256 verify hash
// stored in META-INF/key-hint.txt.  Falls back to attempting decryption of
// the first encrypted image entry if key-hint.txt is absent (older files).
func validateEPUBPassword(filePath, password string) bool {
	unlock := lockEPUBFile(filePath)
	defer unlock()

	r, err := zip.OpenReader(filePath)
	if err != nil {
		return false
	}
	defer r.Close()

	// Fast path: check key-hint.txt verify hash.
	for _, f := range r.File {
		if f.Name != "META-INF/key-hint.txt" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			break
		}
		data, _ := io.ReadAll(rc)
		rc.Close()

		// Line format: "VerifyHash: <base64>"
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "VerifyHash:") {
				continue
			}
			storedB64 := strings.TrimSpace(strings.TrimPrefix(line, "VerifyHash:"))
			stored, err := base64.StdEncoding.DecodeString(storedB64)
			if err != nil {
				break
			}
			h := sha256.Sum256([]byte("verify:" + password))
			return bytes.Equal(h[:], stored)
		}
		break
	}

	// Slow path: try decrypting the first encrypted image.
	key := deriveEPUBKey(password)
	for _, f := range r.File {
		if !strings.HasPrefix(f.Name, "OEBPS/images/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return false
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		_, err = decryptEPUBBytes(data, key)
		return err == nil
	}
	return false
}

// ─── Active password lookup ───────────────────────────────────────────────────

func getEPUBPassword(comic Comic) string {
	if comic.Password != "" {
		return comic.Password
	}
	passwordsMutex.RLock()
	p := comicPasswords[comic.ID]
	passwordsMutex.RUnlock()
	return p
}

// ─── Encrypted path set ───────────────────────────────────────────────────────

// readEncryptedPaths parses META-INF/encryption.xml and returns the set of
// ZIP entry paths that have been encrypted.  The caller must already hold
// the per-file lock.
func readEncryptedPaths(r *zip.ReadCloser) map[string]bool {
	set := map[string]bool{}
	for _, f := range r.File {
		if f.Name != "META-INF/encryption.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return set
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		s := string(data)
		for {
			idx := strings.Index(s, `CipherReference URI="`)
			if idx < 0 {
				break
			}
			s = s[idx+len(`CipherReference URI="`):]
			end := strings.Index(s, `"`)
			if end < 0 {
				break
			}
			set[s[:end]] = true
			s = s[end+1:]
		}
		break
	}
	return set
}

// ─── Page index cache ─────────────────────────────────────────────────────────

// getEPUBPageIndex returns a cached, sorted slice of image filenames
// (paths inside the ZIP, e.g. "OEBPS/images/001.jpg") for the comic.
// It reads the spine from content.opf to preserve reading order, then
// falls back to a sorted directory scan if parsing fails.
func getEPUBPageIndex(comic Comic) ([]string, error) {
	pageIndexCacheMutex.RLock()
	if idx, ok := pageIndexCache[comic.ID]; ok {
		pageIndexCacheMutex.RUnlock()
		return idx, nil
	}
	pageIndexCacheMutex.RUnlock()

	unlock := lockEPUBFile(comic.FilePath)
	defer unlock()

	r, err := zip.OpenReader(comic.FilePath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	names := epubImageOrder(r)

	pageIndexCacheMutex.Lock()
	pageIndexCache[comic.ID] = names
	pageIndexCacheMutex.Unlock()

	return names, nil
}

// epubImageOrder returns image ZIP paths in spine order.
// The caller must already hold the per-file lock.
func epubImageOrder(r *zip.ReadCloser) []string {
	// Build a quick name→file map.
	fileMap := map[string]*zip.File{}
	for _, f := range r.File {
		fileMap[f.Name] = f
	}

	// Try to read OEBPS/content.opf and extract image hrefs in spine order.
	if opf, ok := fileMap["OEBPS/content.opf"]; ok {
		rc, err := opf.Open()
		if err == nil {
			data, _ := io.ReadAll(rc)
			rc.Close()
			if ordered := parseOPFImageOrder(data); len(ordered) > 0 {
				return ordered
			}
		}
	}

	// Fallback: sorted scan of OEBPS/images/.
	var names []string
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !strings.HasPrefix(f.Name, "OEBPS/images/") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		if isImageExt(ext) {
			names = append(names, f.Name)
		}
	}
	sort.Strings(names)
	return names
}

// parseOPFImageOrder extracts image zip paths from content.opf in spine order.
// It parses the <spine> itemrefs, resolves each to a manifest item, then maps
// the page XHTML href back to the image href embedded in that page.
// For simplicity we just extract manifest image items in document order
// (they are written in page order by the builder), which is equivalent.
func parseOPFImageOrder(data []byte) []string {
	s := string(data)

	// Collect all image item hrefs from the manifest in order.
	var images []string
	rest := s
	for {
		idx := strings.Index(rest, `media-type="image/`)
		if idx < 0 {
			// Also match avif which has media-type image/avif
			break
		}
		// Walk back to find href="..."
		seg := rest[:idx]
		hrefIdx := strings.LastIndex(seg, `href="`)
		if hrefIdx < 0 {
			rest = rest[idx+1:]
			continue
		}
		seg = seg[hrefIdx+len(`href="`):]
		end := strings.Index(seg, `"`)
		if end < 0 {
			rest = rest[idx+1:]
			continue
		}
		href := seg[:end]
		// href is relative to OEBPS/: e.g. "images/001.jpg"
		if strings.HasPrefix(href, "images/") {
			images = append(images, "OEBPS/"+href)
		}
		rest = rest[idx+1:]
	}
	return images
}

// ─── Metadata extraction ──────────────────────────────────────────────────────

// extractEPUBMetadata reads OEBPS/content.opf (always plaintext) and fills
// the comic's metadata fields.
func extractEPUBMetadata(comic *Comic) {
	unlock := lockEPUBFile(comic.FilePath)
	defer unlock()

	r, err := zip.OpenReader(comic.FilePath)
	if err != nil {
		return
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name != "OEBPS/content.opf" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		parseOPFMetadata(data, comic)
		return
	}
}

// parseOPFMetadata fills comic fields from a content.opf byte slice.
// We do a lightweight string-scan rather than full XML unmarshal to avoid
// importing encoding/xml here (it is already imported in main.go, but we
// keep this file self-contained for clarity).
func parseOPFMetadata(data []byte, comic *Comic) {
	s := string(data)

	comic.Title = opfMeta(s, "dc:title")
	if comic.Title == "" {
		comic.Title = opfMeta(s, "dc:Title")
	}

	// dc:creator → Artist
	if creator := opfMeta(s, "dc:creator"); creator != "" {
		comic.Artist = creator
	}

	// calibre:series
	if series := opfMetaNameContent(s, "calibre:series"); series != "" {
		comic.Series = series
	}
	if idx := opfMetaNameContent(s, "calibre:series_index"); idx != "" {
		comic.Number = idx
	}

	// belongs-to-collection → StoryArc
	if arc := opfMetaProperty(s, "belongs-to-collection"); arc != "" {
		comic.StoryArc = arc
	}

	// dc:date → Year (first 4 chars)
	if d := opfMeta(s, "dc:date"); len(d) >= 4 {
		comic.Year = d[:4]
	}

	// dc:subject → Tags (one per element)
	var tags []string
	rest := s
	for {
		idx := strings.Index(rest, "<dc:subject>")
		if idx < 0 {
			break
		}
		rest = rest[idx+len("<dc:subject>"):]
		end := strings.Index(rest, "</dc:subject>")
		if end < 0 {
			break
		}
		tag := strings.TrimSpace(xmlUnescape(rest[:end]))
		if tag != "" {
			tags = append(tags, tag)
		}
		rest = rest[end+1:]
	}
	if len(tags) > 0 {
		comic.Tags = tags
	}
}

// opfMeta returns the text content of the first <tagName>…</tagName> element.
func opfMeta(s, tag string) string {
	open := "<" + tag + ">"
	close_ := "</" + tag + ">"
	idx := strings.Index(s, open)
	if idx < 0 {
		// Try with attributes: <dc:creator opf:role="aut">
		attrOpen := "<" + tag + " "
		idx = strings.Index(s, attrOpen)
		if idx < 0 {
			return ""
		}
		closeAngle := strings.Index(s[idx:], ">")
		if closeAngle < 0 {
			return ""
		}
		idx += closeAngle + 1
	} else {
		idx += len(open)
	}
	end := strings.Index(s[idx:], close_)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(xmlUnescape(s[idx : idx+end]))
}

// opfMetaNameContent returns the content="…" attribute of
// <meta name="<name>" content="…"/>.
func opfMetaNameContent(s, name string) string {
	needle := `name="` + name + `"`
	idx := strings.Index(s, needle)
	if idx < 0 {
		return ""
	}
	seg := s[idx:]
	ci := strings.Index(seg, `content="`)
	if ci < 0 {
		return ""
	}
	seg = seg[ci+len(`content="`):]
	end := strings.Index(seg, `"`)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(xmlUnescape(seg[:end]))
}

// opfMetaProperty returns the text content of <meta property="<prop>">…</meta>.
func opfMetaProperty(s, prop string) string {
	needle := `property="` + prop + `"`
	idx := strings.Index(s, needle)
	if idx < 0 {
		return ""
	}
	// Walk forward to closing >
	seg := s[idx:]
	closeAngle := strings.Index(seg, ">")
	if closeAngle < 0 {
		return ""
	}
	seg = seg[closeAngle+1:]
	end := strings.Index(seg, "</meta>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(xmlUnescape(seg[:end]))
}

// xmlUnescape reverses the 4 XML entity escapes used by the builder.
func xmlUnescape(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	return s
}

// ─── Page count ───────────────────────────────────────────────────────────────

func getEPUBPageCount(comic Comic) (int, error) {
	names, err := getEPUBPageIndex(comic)
	return len(names), err
}

// ─── Page reading ─────────────────────────────────────────────────────────────

// extractEPUBPage returns the raw (decrypted if needed) bytes of a single image
// page together with its filename.
func extractEPUBPage(comic Comic, pageIdx int) ([]byte, string, error) {
	imageFiles, err := getEPUBPageIndex(comic)
	if err != nil {
		return nil, "", err
	}
	if pageIdx < 0 || pageIdx >= len(imageFiles) {
		return nil, "", fmt.Errorf("page %d out of range (have %d)", pageIdx, len(imageFiles))
	}
	targetPath := imageFiles[pageIdx]

	unlock := lockEPUBFile(comic.FilePath)
	defer unlock()

	r, err := zip.OpenReader(comic.FilePath)
	if err != nil {
		return nil, "", err
	}
	defer r.Close()

	// Determine which entries are encrypted (empty set = unencrypted EPUB).
	encSet := readEncryptedPaths(r)
	encrypted := len(encSet) > 0

	var key []byte
	if encrypted {
		pw := getEPUBPassword(comic)
		if pw == "" {
			return nil, "", fmt.Errorf("password required")
		}
		key = deriveEPUBKey(pw)
	}

	for _, f := range r.File {
		if f.Name != targetPath {
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

		if encrypted && encSet[f.Name] {
			data, err = decryptEPUBBytes(data, key)
			if err != nil {
				return nil, "", fmt.Errorf("decrypt page %d: %w", pageIdx, err)
			}
		}
		return data, filepath.Base(targetPath), nil
	}
	return nil, "", fmt.Errorf("page file %q not found in EPUB", targetPath)
}

// ─── Cover generation ─────────────────────────────────────────────────────────

func generateEPUBCover(comic *Comic, cacheFile string) error {
	oldGC := debug.SetGCPercent(10)
	defer func() {
		debug.SetGCPercent(oldGC)
		runtime.GC()
		debug.FreeOSMemory()
	}()

	data, _, err := extractEPUBPage(*comic, 0)
	if err != nil {
		return fmt.Errorf("extractEPUBPage: %w", err)
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decode cover image: %w", err)
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

// ─── HTTP page serving ────────────────────────────────────────────────────────

func serveEPUBPage(w http.ResponseWriter, r *http.Request, comic Comic, pageNum string) {
	var pageIdx int
	fmt.Sscanf(pageNum, "%d", &pageIdx)

	data, name, err := extractEPUBPage(comic, pageIdx)
	if err != nil {
		http.Error(w, "Error reading page: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ext := strings.ToLower(filepath.Ext(name))
	w.Header().Set("Content-Type", getContentType(ext))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(data)
}

// ─── processComic integration ─────────────────────────────────────────────────

// isEPUBFile returns true for the .epub extension.
func isEPUBFile(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".epub"
}

// logEPUBError logs a non-fatal EPUB processing error.
func logEPUBError(filename, msg string, err error) {
	log.Printf("[EPUB] %s — %s: %v", filename, msg, err)
}
