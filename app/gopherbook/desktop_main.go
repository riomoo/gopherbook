//go:build desktop

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

var (
	desktopApp fyne.App
	desktopWin fyne.Window
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
	setupRoutes()
	startBackgroundTasks()

	// ── Embedded HTTP server on random port ──────────────────────────────────
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Cannot bind embedded server: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	log.Printf("Embedded server on %s", baseURL)

	serverReady := make(chan string, 1)
	go func() {
		serverReady <- baseURL
		if serveErr := http.Serve(ln, nil); serveErr != nil {
			log.Printf("HTTP server stopped: %v", serveErr)
		}
	}()

	// ── Fyne application ─────────────────────────────────────────────────────
	url := <-serverReady

	desktopApp = app.NewWithID("com.gopherbook.desktop")
	desktopApp.Settings().SetTheme(NewGopherbookTheme())
	desktopApp.SetIcon(loadAppIcon())

	desktopWin = desktopApp.NewWindow("Gopherbook")
	desktopWin.Resize(fyne.NewSize(1280, 820))
	desktopWin.SetMaster()

	desktopWin.SetContent(buildDesktopUI(url))
	desktopWin.SetOnClosed(func() { ln.Close() })
	desktopWin.ShowAndRun()
}

// buildDesktopUI constructs the full Fyne window layout.
func buildDesktopUI(baseURL string) fyne.CanvasObject {
	wv := NewWebViewWidget(baseURL, baseURL+"/")

	logoImg := loadLogoImage()
	var headerRight fyne.CanvasObject
	if logoImg != nil {
		headerRight = logoImg
	} else {
		lbl := widget.NewLabel("Gopherbook")
		lbl.TextStyle = fyne.TextStyle{Bold: true}
		headerRight = lbl
	}

	reloadBtn := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), func() { wv.Reload() })
	homeBtn := widget.NewButton("⌂ Library", func() { wv.LoadURL(baseURL + "/") })
	homeBtn.Importance = widget.HighImportance

	navLeft := container.NewHBox(reloadBtn, homeBtn)
	header := container.NewBorder(nil, nil, navLeft, headerRight, widget.NewLabel(""))

	statusLbl := widget.NewLabel(baseURL)
	statusLbl.TextStyle = fyne.TextStyle{Italic: true}
	status := container.NewPadded(statusLbl)

	return container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		container.NewVBox(widget.NewSeparator(), status),
		nil, nil,
		wv,
	)
}

// loadAppIcon reads the embedded favicon.
func loadAppIcon() fyne.Resource {
	data, err := staticFS.ReadFile("static/images/favicon/faviconbig.ico")
	if err != nil {
		log.Printf("Could not load app icon: %v", err)
		return nil
	}
	return fyne.NewStaticResource("gopherbook.ico", data)
}

// loadLogoImage reads the embedded logo as a Fyne canvas image.
func loadLogoImage() *canvas.Image {
	data, err := staticFS.ReadFile("static/images/pngs/LogoPose2.png")
	if err != nil {
		return nil
	}
	res := fyne.NewStaticResource("logo.png", data)
	img := canvas.NewImageFromResource(res)
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSize(32, 32))
	return img
}
