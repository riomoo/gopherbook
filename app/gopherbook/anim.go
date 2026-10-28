package main

// Animated image decoding: GIF, APNG (animated PNG) and JPEG XL.
//
// decodeAnimation turns a file into a sequence of full-canvas frames, each
// already composited the way a browser shows it, so the desktop reader can
// simply show frame after frame. Frames are handed to a callback one at a
// time, so a caller that downscales them never holds every frame at full
// size.
//
// Covers and still pages don't need any of this: image.Decode already
// returns the first frame of a GIF and the default image of an APNG.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/draw"
	"image/gif"
	"image/png"

	"github.com/gen2brain/jxl"
)

// Limits for hostile or broken files.
const (
	maxAnimFrames     = 10000
	maxAnimCanvasArea = 16384 * 16384
)

// frameFunc receives frame i of n, which the callee owns, and how long to
// show it in seconds (0 when the file gives no delay).
type frameFunc func(i, n int, img image.Image, delay float64) error

// decodeAnimation decodes every frame of a GIF, APNG or JPEG XL file, or
// the single image of anything else image.Decode understands. loops is the
// number of times to play the animation, 0 meaning forever.
func decodeAnimation(data []byte, each frameFunc) (loops int, err error) {
	switch {
	case isJXL(data):
		all, err := jxl.DecodeAll(bytes.NewReader(data), jxlOptions)
		if err != nil {
			return 0, err
		}
		if len(all.Image) == 0 {
			return 0, errors.New("jxl: no frames")
		}
		for i, img := range all.Image {
			d := 0.0
			if i < len(all.Delay) {
				d = all.Delay[i]
			}
			if err := each(i, len(all.Image), img, d); err != nil {
				return 0, err
			}
			all.Image[i] = nil
		}
		return max(all.Loops, 0), nil

	case bytes.HasPrefix(data, []byte("GIF8")):
		return decodeGIFFrames(data, each)

	case isAPNG(data):
		return decodeAPNGFrames(data, each)
	}

	img, _, err := decodeImage(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	return 0, each(0, 1, img, 0)
}

// ── GIF ─────────────────────────────────────────────────────────────────────

// decodeGIFFrames composites GIF frames, which may each cover only part of
// the logical screen, honoring each frame's disposal method.
func decodeGIFFrames(data []byte, each frameFunc) (int, error) {
	g, err := gif.DecodeAll(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	n := len(g.Image)
	if n == 0 {
		return 0, errors.New("gif: no frames")
	}
	if n > maxAnimFrames {
		return 0, fmt.Errorf("gif: %d frames is too many", n)
	}

	w, h := g.Config.Width, g.Config.Height
	if w <= 0 || h <= 0 { // no logical screen size: use the union of the frames
		var r image.Rectangle
		for _, f := range g.Image {
			r = r.Union(f.Bounds())
		}
		w, h = r.Max.X, r.Max.Y
	}
	if w <= 0 || h <= 0 || w*h > maxAnimCanvasArea {
		return 0, fmt.Errorf("gif: bad canvas %dx%d", w, h)
	}

	// Like browsers, start from (and dispose to) transparent rather than
	// the GIF background colour.
	canvas := image.NewRGBA(image.Rect(0, 0, w, h))
	var saved *image.RGBA
	for i, f := range g.Image {
		disposal := byte(0)
		if i < len(g.Disposal) {
			disposal = g.Disposal[i]
		}
		r := f.Bounds().Intersect(canvas.Rect)
		if disposal == gif.DisposalPrevious {
			saved = copyRegion(canvas, r)
		}

		// Paletted frames carry transparency in the palette, so Over keeps
		// the pixels underneath wherever the frame is transparent.
		draw.Draw(canvas, r, f, r.Min, draw.Over)

		delay := 0.0
		if i < len(g.Delay) {
			delay = float64(g.Delay[i]) / 100
		}
		if err := each(i, n, cloneRGBA(canvas), delay); err != nil {
			return 0, err
		}

		switch disposal {
		case gif.DisposalBackground:
			draw.Draw(canvas, r, image.Transparent, image.Point{}, draw.Src)
		case gif.DisposalPrevious:
			if saved != nil {
				draw.Draw(canvas, r, saved, r.Min, draw.Src)
			}
		}
	}

	// image/gif: 0 loops forever, -1 plays once, n > 0 repeats n times
	// (n+1 plays in total).
	switch {
	case g.LoopCount == 0:
		return 0, nil
	case g.LoopCount < 0:
		return 1, nil
	default:
		return g.LoopCount + 1, nil
	}
}

// ── APNG ────────────────────────────────────────────────────────────────────

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

type pngChunk struct {
	typ  string
	data []byte
}

// readPNGChunks splits a PNG file into chunks, checking each CRC.
func readPNGChunks(data []byte) ([]pngChunk, error) {
	if !bytes.HasPrefix(data, pngSignature) {
		return nil, errors.New("png: bad signature")
	}
	var chunks []pngChunk
	p := data[len(pngSignature):]
	for len(p) > 0 {
		if len(p) < 12 {
			return nil, errors.New("png: truncated chunk")
		}
		n := binary.BigEndian.Uint32(p[:4])
		if uint64(n) > uint64(len(p)-12) {
			return nil, errors.New("png: truncated chunk")
		}
		typ := string(p[4:8])
		body := p[8 : 8+n]
		if crc32.ChecksumIEEE(p[4:8+n]) != binary.BigEndian.Uint32(p[8+n:12+n]) {
			return nil, fmt.Errorf("png: bad CRC in %s chunk", typ)
		}
		chunks = append(chunks, pngChunk{typ, body})
		p = p[12+n:]
		if typ == "IEND" {
			break
		}
	}
	return chunks, nil
}

// isAPNG reports whether data is a PNG with an animation control chunk
// (acTL) ahead of its image data, i.e. an animated PNG.
func isAPNG(data []byte) bool {
	if !bytes.HasPrefix(data, pngSignature) {
		return false
	}
	p := data[len(pngSignature):]
	for len(p) >= 8 {
		n := binary.BigEndian.Uint32(p[:4])
		switch string(p[4:8]) {
		case "acTL":
			return true
		case "IDAT", "IEND":
			return false
		}
		if uint64(n) > uint64(len(p)-12) {
			return false
		}
		p = p[12+n:]
	}
	return false
}

// apngFrame is one fcTL chunk and the image data that follows it.
type apngFrame struct {
	w, h, x, y int
	delay      float64
	dispose    byte // 0 none, 1 background, 2 previous
	blend      byte // 0 source, 1 over
	data       [][]byte
}

// decodeAPNGFrames decodes an animated PNG (https://wiki.mozilla.org/APNG_Specification).
// Each frame's image data is wrapped in a minimal standalone PNG and decoded
// with image/png, then composited onto the canvas with the frame's blend
// and dispose operations.
func decodeAPNGFrames(data []byte, each frameFunc) (int, error) {
	chunks, err := readPNGChunks(data)
	if err != nil {
		return 0, err
	}
	var ihdr []byte
	var header [][]byte // PLTE and tRNS, needed to decode every frame
	var plays int
	var frames []*apngFrame
	var cur *apngFrame
	seenIDAT := false

	for _, c := range chunks {
		switch c.typ {
		case "IHDR":
			if len(c.data) != 13 {
				return 0, errors.New("apng: bad IHDR")
			}
			ihdr = c.data
		case "PLTE", "tRNS":
			if !seenIDAT {
				header = append(header, chunkBytes(c.typ, c.data))
			}
		case "acTL":
			if len(c.data) != 8 {
				return 0, errors.New("apng: bad acTL")
			}
			plays = int(binary.BigEndian.Uint32(c.data[4:8]))
		case "fcTL":
			if len(c.data) != 26 {
				return 0, errors.New("apng: bad fcTL")
			}
			if len(frames) >= maxAnimFrames {
				return 0, fmt.Errorf("apng: more than %d frames", maxAnimFrames)
			}
			d := c.data
			num, den := binary.BigEndian.Uint16(d[20:22]), binary.BigEndian.Uint16(d[22:24])
			if den == 0 {
				den = 100 // per the spec, a denominator of 0 means 1/100 s
			}
			cur = &apngFrame{
				w:       int(binary.BigEndian.Uint32(d[4:8])),
				h:       int(binary.BigEndian.Uint32(d[8:12])),
				x:       int(binary.BigEndian.Uint32(d[12:16])),
				y:       int(binary.BigEndian.Uint32(d[16:20])),
				delay:   float64(num) / float64(den),
				dispose: d[24],
				blend:   d[25],
			}
			frames = append(frames, cur)
		case "IDAT":
			seenIDAT = true
			// IDAT is frame 0 only when an fcTL came before it; otherwise
			// it's a default image that isn't part of the animation.
			if cur != nil && len(frames) == 1 {
				cur.data = append(cur.data, c.data)
			}
		case "fdAT":
			if len(c.data) < 4 {
				return 0, errors.New("apng: bad fdAT")
			}
			if cur != nil {
				cur.data = append(cur.data, c.data[4:]) // skip sequence number
			}
		}
	}
	if ihdr == nil {
		return 0, errors.New("apng: missing IHDR")
	}
	cw := int(binary.BigEndian.Uint32(ihdr[0:4]))
	ch := int(binary.BigEndian.Uint32(ihdr[4:8]))
	if cw <= 0 || ch <= 0 || cw*ch > maxAnimCanvasArea {
		return 0, fmt.Errorf("apng: bad canvas %dx%d", cw, ch)
	}
	// Drop frames without image data (e.g. a truncated file).
	valid := frames[:0]
	for _, f := range frames {
		if len(f.data) > 0 {
			valid = append(valid, f)
		}
	}
	frames = valid
	if len(frames) == 0 {
		return 0, errors.New("apng: no frames")
	}

	canvas := image.NewRGBA(image.Rect(0, 0, cw, ch))
	for i, f := range frames {
		r := image.Rect(f.x, f.y, f.x+f.w, f.y+f.h)
		if f.w <= 0 || f.h <= 0 || !r.In(canvas.Rect) {
			return 0, fmt.Errorf("apng: frame %d (%v) outside the %dx%d canvas", i, r, cw, ch)
		}
		img, err := decodeAPNGFrame(ihdr, header, f)
		if err != nil {
			return 0, fmt.Errorf("apng: frame %d: %w", i, err)
		}

		dispose := f.dispose
		if i == 0 && dispose == 2 {
			dispose = 1 // the spec treats "previous" on the first frame as "background"
		}
		var saved *image.RGBA
		if dispose == 2 {
			saved = copyRegion(canvas, r)
		}

		op := draw.Src
		if f.blend == 1 {
			op = draw.Over
		}
		draw.Draw(canvas, r, img, img.Bounds().Min, op)

		if err := each(i, len(frames), cloneRGBA(canvas), f.delay); err != nil {
			return 0, err
		}

		switch dispose {
		case 1:
			draw.Draw(canvas, r, image.Transparent, image.Point{}, draw.Src)
		case 2:
			draw.Draw(canvas, r, saved, r.Min, draw.Src)
		}
	}
	return plays, nil // APNG: 0 means forever, same as ours
}

// decodeAPNGFrame decodes one frame by building a standalone PNG from the
// file's IHDR (with the frame's size), PLTE/tRNS and the frame's data.
func decodeAPNGFrame(ihdr []byte, header [][]byte, f *apngFrame) (image.Image, error) {
	var b bytes.Buffer
	b.Write(pngSignature)
	h := append([]byte(nil), ihdr...)
	binary.BigEndian.PutUint32(h[0:4], uint32(f.w))
	binary.BigEndian.PutUint32(h[4:8], uint32(f.h))
	b.Write(chunkBytes("IHDR", h))
	for _, c := range header {
		b.Write(c)
	}
	for _, d := range f.data {
		b.Write(chunkBytes("IDAT", d))
	}
	b.Write(chunkBytes("IEND", nil))
	return png.Decode(&b)
}

// chunkBytes serializes a PNG chunk: length, type, data, CRC.
func chunkBytes(typ string, data []byte) []byte {
	out := make([]byte, 12+len(data))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(data)))
	copy(out[4:8], typ)
	copy(out[8:], data)
	binary.BigEndian.PutUint32(out[8+len(data):], crc32.ChecksumIEEE(out[4:8+len(data)]))
	return out
}

// ── helpers ─────────────────────────────────────────────────────────────────

// The canvas is premultiplied RGBA: image/draw has fast paths for it, and
// it's the format Gio uploads without another copy.

func cloneRGBA(m *image.RGBA) *image.RGBA {
	c := image.NewRGBA(m.Rect)
	copy(c.Pix, m.Pix)
	return c
}

func copyRegion(m *image.RGBA, r image.Rectangle) *image.RGBA {
	c := image.NewRGBA(r)
	draw.Draw(c, r, m, r.Min, draw.Src)
	return c
}
