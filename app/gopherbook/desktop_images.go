//go:build desktop

package main

import (
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"math"
	"net/http"
	"sync"
	"time"

	"gioui.org/gesture"
	"gioui.org/io/event"
	"gioui.org/io/key"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	_ "golang.org/x/image/bmp"
	xdraw "golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

const (
	maxImgW = 2400
	maxImgH = 3400
)

type remoteImg struct {
	loading bool
	err     string
	op      paint.ImageOp
	w, h    int // native decoded pixel size — needed to compute true fit-width/fit-height render sizes
	ready   bool

	// Animated images (GIF, APNG, JPEG XL): every frame, with its display
	// time. op above is frames[0]. start is when playback began.
	frames []paint.ImageOp
	delays []time.Duration
	loops  int // 0 = forever
	start  time.Time
}

// maxAnimBytes caps the decoded RGBA held for one animation; frames are
// scaled down to fit, so a long full-page animation can't exhaust memory.
const maxAnimBytes = 384 << 20

// animFrame picks the frame to show after elapsed playback time, and how long
// until the next change. done is true once a finite loop count has run out,
// in which case the last frame stays up.
func animFrame(delays []time.Duration, loops int, elapsed time.Duration) (idx int, untilNext time.Duration, done bool) {
	var total time.Duration
	for _, d := range delays {
		total += d
	}
	if len(delays) == 0 || total <= 0 {
		return 0, 0, true
	}
	if loops > 0 && elapsed >= total*time.Duration(loops) {
		return len(delays) - 1, 0, true
	}
	t := elapsed % total
	for i, d := range delays {
		if t < d {
			return i, d - t, false
		}
		t -= d
	}
	return len(delays) - 1, 0, false // unreachable: t < total
}

// animate schedules a redraw for the next frame change of url, if it's an
// animation. Call it from any widget that displays imageState(url).
func (a *App) animate(gtx C, url string) {
	imgMu.Lock()
	e := imgCache[url]
	var wait time.Duration
	var done bool
	if e != nil && len(e.frames) > 1 {
		_, wait, done = animFrame(e.delays, e.loops, gtx.Now.Sub(e.start))
	}
	imgMu.Unlock()
	if e != nil && len(e.frames) > 1 && !done {
		gtx.Execute(op.InvalidateCmd{At: gtx.Now.Add(wait)})
	}
}

var (
	imgMu    sync.Mutex
	imgCache = map[string]*remoteImg{}
)

func (a *App) clearImageCache() {
	imgMu.Lock()
	imgCache = map[string]*remoteImg{}
	imgMu.Unlock()
}

func (a *App) clearImageErrors() {
	imgMu.Lock()
	for u, e := range imgCache {
		if !e.loading && e.err != "" {
			delete(imgCache, u)
		}
	}
	imgMu.Unlock()
}

// remoteImage lays out a fixed-size placeholder (loading/error text)
// or, once loaded, an aspect-correct image fit within maxW x maxH.
func (a *App) remoteImage(gtx C, url string, maxW, maxH float32) D {
	gtx.Constraints.Max.X = gtx.Dp(unit.Dp(maxW))
	gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(maxH))
	gtx.Constraints.Min = gtx.Constraints.Max
	return a.remoteImageFit(gtx, url, maxW, maxH)
}

// imageState returns the current cache entry for url, kicking off a
// background fetch on first request. Shared by every image-displaying
// widget so there's one cache and one loader, not three.
func (a *App) imageState(url string) (op paint.ImageOp, w, h int, loading bool, errStr string) {
	imgMu.Lock()
	defer imgMu.Unlock()
	e := imgCache[url]
	if e == nil {
		e = &remoteImg{loading: true}
		imgCache[url] = e
		go loadRemoteImage(a, url, e)
	}
	if e.ready {
		op, w, h = e.op, e.w, e.h
		if len(e.frames) > 1 {
			i, _, _ := animFrame(e.delays, e.loops, time.Since(e.start))
			op = e.frames[i]
		}
	}
	return op, w, h, e.loading, e.err
}

// remoteImageFit fits the image within a box where either w or h may
// be 0 (meaning: unconstrained on that axis — Contain still preserves
// aspect ratio using whichever axis is set).
func (a *App) remoteImageFit(gtx C, url string, w, h float32) D {
	th := a.theme
	op, _, _, loading, errStr := a.imageState(url)
	ready := !loading && errStr == ""

	if w > 0 {
		gtx.Constraints.Max.X = gtx.Dp(unit.Dp(w))
	}
	if h > 0 {
		gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(h))
	}

	if !ready {
		text := "Loading…"
		if errStr != "" {
			text = errStr
		}
		return layout.Center.Layout(gtx, material.Body2(th, text).Layout)
	}
	a.animate(gtx, url)
	img := widget.Image{Src: op, Fit: widget.Contain}
	return img.Layout(gtx)
}

func loadRemoteImage(a *App, url string, e *remoteImg) {
	finish := func(err error, op paint.ImageOp, w, h int) {
		imgMu.Lock()
		e.loading = false
		if err != nil {
			e.err = err.Error()
			log.Printf("image %s: %v", url, err)
		} else {
			e.op = op
			e.w, e.h = w, h
			e.ready = true
		}
		imgMu.Unlock()
		a.queue(func() {}) // wake the UI loop; the frame reads imgCache fresh
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		finish(err, paint.ImageOp{}, 0, 0)
		return
	}
	if c := getSessionCookie(); c != "" {
		req.Header.Set("Cookie", c)
	}
	// Ask for JPEG XL and JPEG 2000 pages as-is: we decode them (and any
	// animation frames) here, rather than getting the browser's PNG/APNG
	// conversion.
	req.Header.Set("Accept", "image/jxl,image/jp2,image/*;q=0.8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		finish(err, paint.ImageOp{}, 0, 0)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		finish(fmt.Errorf("HTTP %d", resp.StatusCode), paint.ImageOp{}, 0, 0)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 96<<20))
	if err != nil {
		finish(err, paint.ImageOp{}, 0, 0)
		return
	}

	loadFrames(data, e, finish)
}

// loadFrames decodes a page, keeping every frame of an animated GIF, APNG
// or JPEG XL (anim.go). Still images come through as a single frame.
func loadFrames(data []byte, e *remoteImg, finish func(error, paint.ImageOp, int, int)) {
	var (
		frames []paint.ImageOp
		delays []time.Duration
		w, h   int
		extra  = 1.0
	)
	loops, err := decodeAnimation(data, func(i, n int, img image.Image, delay float64) error {
		if i == 0 {
			frames = make([]paint.ImageOp, 0, n)
			// Shrink every frame further if the whole animation would
			// exceed maxAnimBytes.
			if n > 1 {
				b := img.Bounds()
				fw, fh := min(b.Dx(), maxImgW), min(b.Dy(), maxImgH)
				if total := float64(n) * float64(fw) * float64(fh) * 4; total > maxAnimBytes {
					extra = math.Sqrt(maxAnimBytes / total)
				}
			}
		}
		rgba := toDisplayRGBA(img, extra)
		frames = append(frames, paint.NewImageOp(rgba))
		w, h = rgba.Rect.Dx(), rgba.Rect.Dy()
		// Like browsers with GIFs: a zero or tiny delay plays at 100 ms
		// instead of spinning as fast as possible.
		if delay < 0.02 {
			delay = 0.1
		}
		delays = append(delays, time.Duration(delay*float64(time.Second)))
		return nil
	})
	if err == nil && len(frames) == 0 {
		err = fmt.Errorf("no image")
	}
	if err != nil {
		finish(fmt.Errorf("unsupported image (%v)", err), paint.ImageOp{}, 0, 0)
		return
	}
	if len(frames) > 1 {
		imgMu.Lock()
		e.frames, e.delays, e.loops, e.start = frames, delays, loops, time.Now()
		imgMu.Unlock()
	}
	finish(nil, frames[0], w, h)
}

// toDisplayRGBA converts img to an *image.RGBA (the format Gio uploads
// without another copy) no larger than maxImgW x maxImgH, additionally
// scaled by extra (<= 1).
func toDisplayRGBA(img image.Image, extra float64) *image.RGBA {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	s := extra
	if w > maxImgW || h > maxImgH {
		s *= min(float64(maxImgW)/float64(w), float64(maxImgH)/float64(h))
	}
	if s < 1 {
		nw, nh := max(int(float64(w)*s), 1), max(int(float64(h)*s), 1)
		dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
		xdraw.ApproxBiLinear.Scale(dst, dst.Bounds(), img, b, xdraw.Src, nil)
		return dst
	}
	if r, ok := img.(*image.RGBA); ok && r.Rect.Min == (image.Point{}) {
		return r
	}
	rgba := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(rgba, rgba.Bounds(), img, b.Min, draw.Src)
	return rgba
}

// readerPageView is the comic-reader's page display: unlike
// remoteImageFit (used for covers, which just contain-fits within a
// fixed box), this computes a TRUE fit-width or fit-height render
// size from the image's real native pixel dimensions, draws a
// visually distinct bordered viewport behind it so the page area
// reads as a separate region from the surrounding window, and lets
// the mouse wheel / trackpad / touch-drag pan around the image when
// the rendered size exceeds the viewport (using gesture.Scroll, the
// same mechanism Gio's own widget.List uses internally for
// scrolling — see layout/list.go).
func (a *App) readerPageView(gtx C, url string) D {
	th := a.theme
	viewport := gtx.Constraints.Max

	// A fixed-size bordered panel, drawn regardless of load state, so
	// the reading area is always visually distinct from the window
	// background — this alone addresses "the view area should be
	// distinct in color, with a line where it ends".
	gtx.Constraints.Min = viewport
	return widget.Border{Color: rgb(0x314C52), Width: unit.Dp(1)}.Layout(gtx, func(gtx C) D {
		fillRRect(gtx, image.Rectangle{Max: gtx.Constraints.Max}, 0, rgb(0x14161c))

		// Keyboard focus target for the reader's shortcuts (handled in
		// handleReaderKeys). Gio drops focus at the end of any frame in
		// which the focused tag either has no event.Op or did not read a
		// key.FocusFilter, so both happen on EVERY frame — including
		// while a page is still loading, otherwise turning a page would
		// silently lose keyboard focus.
		defer clip.Rect(image.Rectangle{Max: viewport}).Push(gtx.Ops).Pop()
		event.Op(gtx.Ops, &a.panFocus)
		for {
			if _, ok := gtx.Source.Event(key.FocusFilter{Target: &a.panFocus}); !ok {
				break
			}
		}
		if a.pendingPanFocus {
			gtx.Execute(key.FocusCmd{Tag: &a.panFocus})
			a.pendingPanFocus = false
		}

		imgOp, nativeW, nativeH, loading, errStr := a.imageState(url)
		ready := !loading && errStr == "" && nativeW > 0 && nativeH > 0
		if !ready {
			text := "Loading…"
			if errStr != "" {
				text = errStr
			}
			return layout.Stack{Alignment: layout.Center}.Layout(gtx,
				layout.Expanded(func(gtx C) D { return D{Size: gtx.Constraints.Max} }),
				layout.Stacked(material.Body2(th, text).Layout),
			)
		}

		// True fit-width/fit-height: scale from the REAL viewport and
		// the image's REAL aspect ratio, not a guessed fixed base
		// size — that mismatch was why both fit modes only "kind of"
		// worked before.
		aspect := float32(nativeW) / float32(nativeH)
		var renderW, renderH float32
		if a.fitMode == "width" {
			renderW = float32(viewport.X) * a.zoomFactor
			renderH = renderW / aspect
		} else {
			renderH = float32(viewport.Y) * a.zoomFactor
			renderW = renderH * aspect
		}
		renderSize := image.Pt(int(renderW), int(renderH))

		maxPanX := renderSize.X - viewport.X
		if maxPanX < 0 {
			maxPanX = 0
		}
		maxPanY := renderSize.Y - viewport.Y
		if maxPanY < 0 {
			maxPanY = 0
		}
		clampPan(&a.panOffX, maxPanX)
		clampPan(&a.panOffY, maxPanY)

		// Register the pan gesture over the whole viewport. xr/yr tell
		// Gio how much further panning is possible in each direction
		// from the CURRENT offset — the same min/max-from-current-
		// position pattern layout.List uses for its own scrolling.
		xr := pointer.ScrollRange{Min: -a.panOffX, Max: maxPanX - a.panOffX}
		yr := pointer.ScrollRange{Min: -a.panOffY, Max: maxPanY - a.panOffY}
		dx := a.panScrollX.Update(gtx.Metric, gtx.Source, gtx.Now, gesture.Horizontal, xr, pointer.ScrollRange{})
		dy := a.panScrollY.Update(gtx.Metric, gtx.Source, gtx.Now, gesture.Vertical, pointer.ScrollRange{}, yr)
		a.panOffX += dx
		a.panOffY += dy
		clampPan(&a.panOffX, maxPanX)
		clampPan(&a.panOffY, maxPanY)
		a.panScrollX.Add(gtx.Ops)
		a.panScrollY.Add(gtx.Ops)

		// Mouse-drag panning. gesture.Scroll (above) deliberately
		// ignores mouse-button drags on desktop — it only treats touch
		// (and Android, by OS convention) as a drag source — so
		// dragging with the mouse needs its own handling, on the same
		// panFocus tag registered above, so one click on the page also
		// gives it keyboard focus for the reader shortcuts.
		for {
			e, ok := gtx.Source.Event(pointer.Filter{
				Target: &a.panFocus,
				Kinds:  pointer.Press | pointer.Drag | pointer.Release | pointer.Cancel,
			})
			if !ok {
				break
			}
			pe, ok := e.(pointer.Event)
			if !ok {
				continue
			}
			switch pe.Kind {
			case pointer.Press:
				if !pe.Buttons.Contain(pointer.ButtonPrimary) {
					continue
				}
				a.dragging = true
				a.dragPID = pe.PointerID
				a.dragLastX = int(pe.Position.X)
				a.dragLastY = int(pe.Position.Y)
				gtx.Execute(key.FocusCmd{Tag: &a.panFocus})
			case pointer.Drag:
				if !a.dragging || pe.PointerID != a.dragPID {
					continue
				}
				x, y := int(pe.Position.X), int(pe.Position.Y)
				// Grab-and-pull convention: dragging right reveals
				// more of the image's left side, so the offset moves
				// opposite the drag direction.
				a.panOffX -= x - a.dragLastX
				a.panOffY -= y - a.dragLastY
				a.dragLastX, a.dragLastY = x, y
				clampPan(&a.panOffX, maxPanX)
				clampPan(&a.panOffY, maxPanY)
			case pointer.Release, pointer.Cancel:
				if pe.PointerID == a.dragPID {
					a.dragging = false
				}
			}
		}

		drawX := -a.panOffX
		if renderSize.X < viewport.X {
			drawX = (viewport.X - renderSize.X) / 2
		}
		drawY := -a.panOffY
		if renderSize.Y < viewport.Y {
			drawY = (viewport.Y - renderSize.Y) / 2
		}

		a.animate(gtx, url) // animated page: redraw when the next frame is due
		defer op.Offset(image.Pt(drawX, drawY)).Push(gtx.Ops).Pop()
		imgGtx := gtx
		imgGtx.Constraints = layout.Exact(renderSize)
		widget.Image{Src: imgOp, Fit: widget.Fill}.Layout(imgGtx)

		return D{Size: viewport}
	})
}

// clampPan keeps a pan offset within [0, max], written as a free
// function (not a method) since it's just arithmetic shared by both axes.
func clampPan(v *int, max int) {
	if *v > max {
		*v = max
	}
	if *v < 0 {
		*v = 0
	}
}
