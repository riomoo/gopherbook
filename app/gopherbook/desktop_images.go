//go:build desktop

package main

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"net/http"
	"sync"

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
	"github.com/vegidio/avif-go"
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

	var img image.Image
	if len(data) > 12 && string(data[4:8]) == "ftyp" &&
		(string(data[8:12]) == "avif" || string(data[8:12]) == "avis") {
		img, err = avif.Decode(bytes.NewReader(data))
	} else {
		img, _, err = image.Decode(bytes.NewReader(data))
		if err != nil {
			err = fmt.Errorf("unsupported image (%v)", err)
		}
	}
	if err != nil {
		finish(err, paint.ImageOp{}, 0, 0)
		return
	}

	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w > maxImgW || h > maxImgH {
		s := float64(maxImgW) / float64(w)
		if t := float64(maxImgH) / float64(h); t < s {
			s = t
		}
		nw, nh := int(float64(w)*s), int(float64(h)*s)
		dst := image.NewNRGBA(image.Rect(0, 0, nw, nh))
		xdraw.ApproxBiLinear.Scale(dst, dst.Bounds(), img, b, xdraw.Src, nil)
		img, b = dst, dst.Bounds()
	}
	nrgba := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(nrgba, nrgba.Bounds(), img, b.Min, draw.Src)

	finish(nil, paint.NewImageOp(nrgba), b.Dx(), b.Dy())
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
