//go:build desktop

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/io/event"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
	"gioui.org/x/explorer"
)

func main() {
	// ── Paths ────────────────────────────────────────────────────────────────
	os.MkdirAll(libraryPath, 0755)
	os.MkdirAll(cachePath, 0755)
	os.MkdirAll(etcPath, 0755)
	os.MkdirAll(watchPath, 0755)

	// ── Cover semaphore ──────────────────────────────────────────────────────
	coverWorkers := runtime.NumCPU()
	if coverWorkers > 4 {
		coverWorkers = 4
	}
	coverGenSemaphore = make(chan struct{}, coverWorkers)
	log.Printf("Cover generation semaphore width: %d", coverWorkers)

	// ── Database, users, routes, background tasks ────────────────────────────
	initCore()
	defer db.Close()
	flushOnSignal() // save pending edits if the session ends under us (persist.go)
	setupRoutes()
	startBackgroundTasks()

	// ── Embedded HTTP server on a random local port ──────────────────────────
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Cannot bind embedded server: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	globalBaseURL = fmt.Sprintf("http://127.0.0.1:%d", port)
	log.Printf("Embedded server on %s", globalBaseURL)

	go func() {
		if serveErr := http.Serve(ln, nil); serveErr != nil {
			log.Printf("HTTP server stopped: %v", serveErr)
		}
	}()

	// ── Gio application ──────────────────────────────────────────────────────
	go func() {
		w := new(app.Window)
		w.Option(app.Title("Gopherbook"), app.Size(unit.Dp(1280), unit.Dp(820)))
		err := runUI(w, ln)
		// os.Exit skips deferred calls, so save pending edits (e.g. a
		// comic deleted just before closing the window) explicitly.
		flushPendingSave()
		if err != nil {
			log.Fatal(err)
		}
		db.Close()
		os.Exit(0)
	}()
	app.Main()
}

// runUI is the whole Gio event loop.
//
// Gio is immediate-mode: there is no persistent widget tree between
// frames, only the *App struct (desktop_gui.go), which every widget
// reads fresh each frame. Critically, Gio's widgets (Editor,
// Clickable, Bool, ...) are NOT safe to touch from any goroutine other
// than the one running this loop. So background work (every HTTP call)
// never mutates App directly — it sends a func() on uiQueue, and only
// this loop ever executes those funcs, exactly the role QueueCommand
// played in the go-gui port. w.Event() blocks, so it runs in its own
// goroutine feeding an `events` channel, mirroring the pattern Gio's
// own maintained examples (gophers, explorer) use for the same reason.
func runUI(w *app.Window, ln net.Listener) error {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(gofont.Collection()))
	applyGopherbookPalette(th)

	expl := explorer.NewExplorer(w)

	a := &App{
		win:         w,
		theme:       th,
		explorer:    expl,
		uiQueue:     make(chan func(), 16),
		baseURL:     globalBaseURL,
		mode:        modeLogin,
		loginTab:    true,
		filterAlpha: "all",
		filterTags:  make(map[string]bool),
		fitMode:     "height",
		zoomFactor:  1.0,
		pageSize:    40,
	}
	globalApp = a

	events := make(chan event.Event)
	acks := make(chan struct{})
	go func() {
		for {
			e := w.Event()
			events <- e
			<-acks
			if _, ok := e.(app.DestroyEvent); ok {
				return
			}
		}
	}()

	var ops op.Ops
	for {
		select {
		case fn := <-a.uiQueue:
			fn()
			w.Invalidate()
		case e := <-events:
			a.explorer.ListenEvents(e)
			switch e := e.(type) {
			case app.DestroyEvent:
				ln.Close()
				acks <- struct{}{}
				return e.Err
			case app.FrameEvent:
				gtx := app.NewContext(&ops, e)
				a.layout(gtx)
				e.Frame(gtx.Ops)
			}
			acks <- struct{}{}
		}
	}
}

// applyGopherbookPalette recolors the stock Gio theme with the
// original site/Fyne palette (teal accent on a dark background).
func applyGopherbookPalette(th *material.Theme) {
	th.Palette.Bg = rgb(0x1b1e2c)
	th.Palette.Fg = rgb(0xe6e3de)
	th.Palette.ContrastBg = rgb(0x395e62)
	th.Palette.ContrastFg = rgb(0xe6e3de)
}
