package main

// JPEG XL support.
//
// Decoding uses github.com/gen2brain/jxl: a pure-Go port of jxl-rs (no cgo,
// no WASM, no dependencies, BSD-3-Clause). It handles lossy (VarDCT) and
// lossless (modular) files, JPEG-recompressed JXL, 8-32 bit samples, alpha,
// and animation.
//
// (writePage also converts JPEG 2000 pages; see jp2_support.go.)
//
// Three consumers:
//
//   - Covers / collages go through decodeImage, a drop-in for image.Decode
//     that decodes JXL at codestream Level 10 (the jxl package's own
//     image.RegisterFormat hook uses Level 5, which rejects e.g. 16-bit
//     lossless files that cjxl marks as Level 10).
//   - The web reader gets pages through writePage: browsers mostly can't
//     display JPEG XL, so unless the request's Accept header names
//     image/jxl, a JXL page is converted to PNG (lossless, so the page looks
//     exactly as decoded) or, when animated, to APNG.
//   - The desktop reader sends "Accept: image/jxl", receives the original
//     bytes and decodes every frame itself (desktop_images.go).

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/draw"
	"image/png"
	"io"
	"log"
	"math"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/gen2brain/jxl"
)

// jxlOptions: Level 10 accepts every conforming file (Level 5 is the
// "web" profile and refuses >16-bit-ish features). FrameSizeLimit keeps
// its default, so a hostile header still can't demand a huge allocation.
var jxlOptions = jxl.Options{Level: 10}

// isJXL reports whether data starts with a JPEG XL signature: either a bare
// codestream (FF 0A) or the ISOBMFF container ("JXL " box).
func isJXL(data []byte) bool {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0x0A {
		return true
	}
	return len(data) >= 12 && bytes.Equal(data[:12],
		[]byte{0, 0, 0, 0x0C, 'J', 'X', 'L', ' ', 0x0D, 0x0A, 0x87, 0x0A})
}

// decodeImage is a drop-in replacement for image.Decode that decodes JPEG XL
// with jxlOptions (first frame for animations) and defers everything else to
// image.Decode.
func decodeImage(r io.Reader) (image.Image, string, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(12)
	if isJXL(head) {
		img, err := jxl.Decode(br, jxlOptions)
		return img, "jxl", err
	}
	return image.Decode(br)
}

// ── Web page delivery ───────────────────────────────────────────────────────

// pageNeedsConversion reports whether ext names a format that browsers
// can't be relied on to display, so writePage may convert it (and so it
// must be read whole rather than streamed).
func pageNeedsConversion(ext string) bool {
	switch ext {
	case ".jxl", ".jp2", ".j2k", ".j2c", ".jpf", ".jpx":
		return true
	}
	return false
}

// writePage writes one comic page. Most pages are sent as-is. JPEG XL and
// JPEG 2000 pages are sent as-is only to clients whose Accept header names
// image/jxl or image/jp2 (Safari, the desktop app) and are otherwise
// converted: to PNG, or APNG for animations. cacheKey identifies the page
// (comic ID + page index) for the in-memory conversion cache.
func writePage(w http.ResponseWriter, r *http.Request, name string, data []byte, cacheKey string) {
	ext := strings.ToLower(filepath.Ext(name))
	// Decide by content, not name: both formats always start with a fixed
	// signature, and a mislabelled file is better sent as it is.
	mediaType, label := "", ""
	switch {
	case isJXL(data):
		mediaType, label = "image/jxl", "JPEG XL"
	case isJP2(data):
		mediaType, label = "image/jp2", "JPEG 2000"
	}

	if mediaType == "" {
		ct := getContentType(ext)
		if pageNeedsConversion(ext) {
			// Named .jxl/.jp2/... but isn't one: report what it really is.
			ct = http.DetectContentType(data)
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(data)
		return
	}

	// The response depends on Accept from here on.
	w.Header().Set("Vary", "Accept")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	if acceptsType(r, mediaType) {
		w.Header().Set("Content-Type", mediaType)
		w.Write(data)
		return
	}

	out, err := convertedPage(cacheKey, data)
	if err != nil {
		log.Printf("%s page %s: %v", label, cacheKey, err)
		http.Error(w, "Could not decode "+label+" page: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "image/png") // APNG is served as image/png too
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.Write(out)
}

// acceptsType reports whether the Accept header explicitly lists mediaType
// with a non-zero quality. Wildcards don't count: "*/*" from a browser that
// can't render JPEG XL must still get the converted page.
func acceptsType(r *http.Request, mediaType string) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil || mt != mediaType {
			continue
		}
		if q, ok := params["q"]; ok {
			if v, err := strconv.ParseFloat(q, 64); err == nil && v <= 0 {
				return false
			}
		}
		return true
	}
	return false
}

// Conversion cache: memory only, never disk. Pages from password-protected
// comics pass through here, and writing their decoded pixels to the cache
// directory would leak them.
const jxlCacheBudget = 160 << 20 // bytes of converted output kept

var (
	jxlCacheMu    sync.Mutex
	jxlCache      = map[string]*jxlCacheEntry{}
	jxlCacheOrder []string // LRU order, oldest first
	jxlCacheBytes int

	// At most two conversions at once: a browser prefetching ahead can
	// request many pages in parallel, and each full-size decode holds a
	// few tens of MB.
	jxlConvertSem = make(chan struct{}, 2)
)

type jxlCacheEntry struct {
	done chan struct{} // closed when out/err are set
	out  []byte
	err  error
}

func convertedPage(key string, data []byte) ([]byte, error) {
	jxlCacheMu.Lock()
	if e, ok := jxlCache[key]; ok {
		jxlTouch(key)
		jxlCacheMu.Unlock()
		<-e.done // another request may still be converting this page
		return e.out, e.err
	}
	e := &jxlCacheEntry{done: make(chan struct{})}
	jxlCache[key] = e
	jxlCacheOrder = append(jxlCacheOrder, key)
	jxlCacheMu.Unlock()

	jxlConvertSem <- struct{}{}
	e.out, e.err = convertPage(data)
	<-jxlConvertSem
	close(e.done)

	jxlCacheMu.Lock()
	if jxlCache[key] == e { // not evicted or cleared while converting
		if e.err != nil {
			jxlForget(key) // don't pin failures; a retry may come with fixed data
		} else {
			jxlCacheBytes += len(e.out)
			for jxlCacheBytes > jxlCacheBudget && len(jxlCacheOrder) > 1 {
				jxlForget(jxlCacheOrder[0])
			}
		}
	}
	jxlCacheMu.Unlock()
	return e.out, e.err
}

// jxlTouch moves key to the most-recently-used end. Caller holds jxlCacheMu.
func jxlTouch(key string) {
	for i, k := range jxlCacheOrder {
		if k == key {
			jxlCacheOrder = append(append(jxlCacheOrder[:i:i], jxlCacheOrder[i+1:]...), key)
			return
		}
	}
}

// jxlForget drops key from the cache. Caller holds jxlCacheMu.
func jxlForget(key string) {
	if e, ok := jxlCache[key]; ok {
		select {
		case <-e.done:
			if e.err == nil {
				jxlCacheBytes -= len(e.out)
			}
		default: // still converting: its bytes were never counted
		}
		delete(jxlCache, key)
	}
	for i, k := range jxlCacheOrder {
		if k == key {
			jxlCacheOrder = append(jxlCacheOrder[:i:i], jxlCacheOrder[i+1:]...)
			break
		}
	}
}

// clearJXLCache empties the conversion cache (e.g. on logout).
func clearJXLCache() {
	jxlCacheMu.Lock()
	jxlCache = map[string]*jxlCacheEntry{}
	jxlCacheOrder = nil
	jxlCacheBytes = 0
	jxlCacheMu.Unlock()
}

// convertPage decodes a JPEG XL or JPEG 2000 page and re-encodes it as PNG,
// or as APNG for a JPEG XL animation.
func convertPage(data []byte) ([]byte, error) {
	if !isJXL(data) {
		img, _, err := decodeImage(bytes.NewReader(data)) // JPEG 2000 (jp2_support.go)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		enc := png.Encoder{CompressionLevel: png.BestSpeed}
		if err := enc.Encode(&buf, img); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	all, err := jxl.DecodeAll(bytes.NewReader(data), jxlOptions)
	if err != nil {
		return nil, err
	}
	if len(all.Image) == 0 {
		return nil, errors.New("no frames")
	}
	var buf bytes.Buffer
	if len(all.Image) == 1 {
		// Plain PNG keeps 16-bit pages at 16 bits.
		enc := png.Encoder{CompressionLevel: png.BestSpeed}
		err = enc.Encode(&buf, all.Image[0])
	} else {
		err = encodeAPNG(&buf, all.Image, all.Delay, all.Loops)
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ── APNG encoder ────────────────────────────────────────────────────────────

// encodeAPNG writes frames as an animated PNG. Every frame covers the full
// canvas (the JXL decoder already composites), so each is written whole with
// dispose=none, blend=source. delays are seconds; loops 0 means forever,
// matching both JPEG XL and APNG.
//
// Frames are written as 8-bit RGBA, or 8-bit RGB when every frame is opaque.
// (image/png can't be used per frame: it picks the color type from each
// image's contents, and APNG needs one color type for all frames.)
func encodeAPNG(w io.Writer, frames []image.Image, delays []float64, loops int) error {
	b := frames[0].Bounds()
	wd, ht := b.Dx(), b.Dy()

	nrgba := make([]*image.NRGBA, len(frames))
	opaque := true
	for i, f := range frames {
		if f.Bounds().Dx() != wd || f.Bounds().Dy() != ht {
			return fmt.Errorf("frame %d is %v, canvas is %dx%d", i, f.Bounds().Size(), wd, ht)
		}
		n, ok := f.(*image.NRGBA)
		if !ok || n.Rect.Min != (image.Point{}) {
			n = image.NewNRGBA(image.Rect(0, 0, wd, ht))
			draw.Draw(n, n.Rect, f, f.Bounds().Min, draw.Src)
		}
		nrgba[i] = n
		if opaque && !n.Opaque() {
			opaque = false
		}
	}
	colorType, bpp := byte(6), 4 // RGBA
	if opaque {
		colorType, bpp = 2, 3 // RGB
	}

	pw := &pngChunkWriter{w: w}
	pw.raw([]byte("\x89PNG\r\n\x1a\n"))

	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], uint32(wd))
	binary.BigEndian.PutUint32(ihdr[4:], uint32(ht))
	ihdr[8], ihdr[9] = 8, colorType // bit depth 8; compression, filter, interlace 0
	pw.chunk("IHDR", ihdr)

	actl := make([]byte, 8)
	binary.BigEndian.PutUint32(actl[0:], uint32(len(frames)))
	binary.BigEndian.PutUint32(actl[4:], uint32(max(loops, 0)))
	pw.chunk("acTL", actl)

	var seq uint32
	for i, img := range nrgba {
		num, den := apngDelay(delays, i)
		fctl := make([]byte, 26)
		binary.BigEndian.PutUint32(fctl[0:], seq)
		binary.BigEndian.PutUint32(fctl[4:], uint32(wd))
		binary.BigEndian.PutUint32(fctl[8:], uint32(ht))
		// x/y offset 0
		binary.BigEndian.PutUint16(fctl[20:], num)
		binary.BigEndian.PutUint16(fctl[22:], den)
		// dispose_op 0 (none), blend_op 0 (source)
		pw.chunk("fcTL", fctl)
		seq++

		z, err := apngFrameData(img, bpp)
		if err != nil {
			return err
		}
		if i == 0 {
			pw.chunk("IDAT", z) // the default image is the first frame
		} else {
			fd := make([]byte, 4+len(z))
			binary.BigEndian.PutUint32(fd, seq)
			copy(fd[4:], z)
			pw.chunk("fdAT", fd)
			seq++
		}
	}
	pw.chunk("IEND", nil)
	return pw.err
}

// apngDelay converts a frame delay in seconds to an APNG fraction. Zero or
// missing delays become 1/100 s rather than 0, since viewers treat 0
// inconsistently (some as "as fast as possible", some as 100 ms).
func apngDelay(delays []float64, i int) (uint16, uint16) {
	if i >= len(delays) || delays[i] <= 0 || math.IsNaN(delays[i]) {
		return 1, 100
	}
	ms := math.Round(delays[i] * 1000)
	if ms > 65535 {
		return uint16(min(math.Round(delays[i]*100), 65535)), 100
	}
	return uint16(max(ms, 1)), 1000
}

// apngFrameData returns the zlib-compressed, filtered scanlines of img.
// Each row uses the Sub filter (difference from the pixel to the left),
// which is cheap and compresses illustrations and gradients well.
func apngFrameData(img *image.NRGBA, bpp int) ([]byte, error) {
	wd, ht := img.Rect.Dx(), img.Rect.Dy()
	var z bytes.Buffer
	zw, err := zlib.NewWriterLevel(&z, zlib.BestSpeed)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, wd*bpp)
	row := make([]byte, 1+wd*bpp)
	for y := 0; y < ht; y++ {
		src := img.Pix[y*img.Stride : y*img.Stride+wd*4]
		if bpp == 4 {
			copy(raw, src)
		} else {
			for x := 0; x < wd; x++ {
				copy(raw[x*3:x*3+3], src[x*4:x*4+3])
			}
		}
		row[0] = 1 // Sub
		for x := 0; x < len(raw); x++ {
			left := byte(0)
			if x >= bpp {
				left = raw[x-bpp]
			}
			row[1+x] = raw[x] - left
		}
		if _, err := zw.Write(row); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return z.Bytes(), nil
}

type pngChunkWriter struct {
	w   io.Writer
	err error
}

func (p *pngChunkWriter) raw(b []byte) {
	if p.err == nil {
		_, p.err = p.w.Write(b)
	}
}

func (p *pngChunkWriter) chunk(typ string, data []byte) {
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(data)))
	copy(hdr[4:], typ)
	crc := crc32.NewIEEE()
	crc.Write(hdr[4:])
	crc.Write(data)
	var tail [4]byte
	binary.BigEndian.PutUint32(tail[:], crc.Sum32())
	p.raw(hdr[:])
	p.raw(data)
	p.raw(tail[:])
}
