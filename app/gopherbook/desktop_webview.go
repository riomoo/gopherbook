//go:build desktop

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

// ── WebViewWidget ─────────────────────────────────────────────────────────────
// A Fyne-native comic reader / library browser that proxies the local HTTP
// server.  It has two modes:
//   1. Library mode  – fetches JSON from the API and renders a native grid UI
//      that mirrors the look of the HTML frontend (same colours, layout logic).
//   2. Reader mode   – fetches comic pages as images and shows them with
//      zoom / pan / navigation, identical to the JS reader in index.html.

type WebViewWidget struct {
	widget.BaseWidget

	baseURL    string
	currentURL string

	// state
	mu          sync.RWMutex
	mode        string // "login"|"library"|"reader"|"categories"
	sessionCook string // "session=<token>"

	// library state
	allComics    []ComicJSON
	allTags      []TagJSON
	filterTags   map[string]bool // multi-select tag filter
	filterAlpha  string
	filterSearch string // live search text
	page         int
	pageSize     int

	// reader state
	comicID    string
	comicTitle string
	pageIdx    int
	pageCount  int
	fitMode    string // "width"|"height"
	zoomFactor float32
	pageImg    image.Image
	bookmarks  []int

	// rendered Fyne content
	content        *fyne.Container
	rendered       fyne.CanvasObject
	contentMu      sync.Mutex
	libraryGrid    *fyne.Container  // swappable grid portion - avoids focus loss on search
	libraryPagination *fyne.Container

	// password dialog
	pendingComicID string
}

// ── JSON types that mirror the Go backend structs ──────────────────────────────

type ComicJSON struct {
	ID          string   `json:"id"`
	Filename    string   `json:"filename"`
	Artist      string   `json:"artist"`
	Title       string   `json:"title"`
	Series      string   `json:"series"`
	StoryArc    string   `json:"story_arc"`
	Number      string   `json:"number"`
	Publisher   string   `json:"publisher"`
	Year        string   `json:"year"`
	PageCount   int      `json:"page_count"`
	CoverImage  string   `json:"cover_image"`
	FileType    string   `json:"file_type"`
	Encrypted   bool     `json:"encrypted"`
	HasPassword bool     `json:"has_password"`
	Tags        []string `json:"tags"`
	Bookmarks   []int    `json:"bookmarks"`
}

type TagJSON struct {
	Name  string `json:"name"`
	Color string `json:"color"`
	Count int    `json:"count"`
}

type CategoryJSON struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	ComicIDs []string `json:"comic_ids"`
}

func NewWebViewWidget(baseURL, startURL string) *WebViewWidget {
	w := &WebViewWidget{
		baseURL:     baseURL,
		currentURL:  startURL,
		mode:        "login",
		filterAlpha: "all",
		filterTags:  make(map[string]bool),
		fitMode:     "height",
		zoomFactor:  1.0,
		pageSize:    40,
	}
	w.ExtendBaseWidget(w)
	w.content = container.NewStack()
	go w.showLogin()
	return w
}

// ── Fyne widget interface ──────────────────────────────────────────────────────

func (w *WebViewWidget) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(w.content)
}

func (w *WebViewWidget) MinSize() fyne.Size { return fyne.NewSize(800, 600) }

// ── Navigation helpers ─────────────────────────────────────────────────────────

func (w *WebViewWidget) Reload()          { w.refresh() }
func (w *WebViewWidget) LoadURL(u string) { w.navigateTo(u) }

func (w *WebViewWidget) navigateTo(u string) {
	if strings.Contains(u, "/") && !strings.Contains(u, "reader") {
		w.showLibrary()
	}
}

func (w *WebViewWidget) refresh() {
	switch w.mode {
	case "library", "categories":
		w.showLibrary()
	case "reader":
		w.showReader(w.comicID, w.comicTitle, w.pageIdx)
	default:
		w.showLogin()
	}
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

func (w *WebViewWidget) get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, w.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if w.sessionCook != "" {
		req.Header.Set("Cookie", w.sessionCook)
	}
	return http.DefaultClient.Do(req)
}

func (w *WebViewWidget) post(path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, w.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.sessionCook != "" {
		req.Header.Set("Cookie", w.sessionCook)
	}
	return http.DefaultClient.Do(req)
}

func (w *WebViewWidget) postStr(path, jsonBody string) (*http.Response, error) {
	return w.post(path, strings.NewReader(jsonBody))
}

func (w *WebViewWidget) deleteReq(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, w.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if w.sessionCook != "" {
		req.Header.Set("Cookie", w.sessionCook)
	}
	return http.DefaultClient.Do(req)
}

// ── Login screen ───────────────────────────────────────────────────────────────

func (w *WebViewWidget) showLogin() {
	w.mu.Lock()
	w.mode = "login"
	w.mu.Unlock()

	// Logo
	logoData, _ := staticFS.ReadFile("static/images/pngs/LogoPose2.png")
	var logoObj fyne.CanvasObject
	if len(logoData) > 0 {
		res := fyne.NewStaticResource("logo.png", logoData)
		img := canvas.NewImageFromResource(res)
		img.FillMode = canvas.ImageFillContain
		img.SetMinSize(fyne.NewSize(120, 120))
		logoObj = img
	} else {
		logoObj = widget.NewLabel("")
	}

	// Title
	title := canvas.NewText("Gopherbook", colorHeader)
	title.TextSize = 26
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	// Tab buttons
	loginTabActive := true
	var loginForm, registerForm *fyne.Container

	loginTab := widget.NewButton("Login", nil)
	registerTab := widget.NewButton("Register", nil)
	loginTab.Importance = widget.HighImportance

	// Login form
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username")
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")
	loginMsg := canvas.NewText("", colorError)
	loginMsg.TextSize = 12

	loginBtn := widget.NewButton("Login", func() {
		body := fmt.Sprintf(`{"username":%q,"password":%q}`,
			usernameEntry.Text, passwordEntry.Text)
		resp, err := w.postStr("/api/login", body)
		if err != nil {
			fyne.Do(func() { loginMsg.Text = "Network error"; loginMsg.Refresh() })
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			// Extract session cookie
			for _, ck := range resp.Cookies() {
				if ck.Name == "session" {
					w.sessionCook = "session=" + ck.Value
				}
			}
			go w.showLibrary()
		} else {
			fyne.Do(func() { loginMsg.Text = "Invalid username or password"; loginMsg.Refresh() })
		}
	})
	loginBtn.Importance = widget.HighImportance
	passwordEntry.OnSubmitted = func(_ string) { loginBtn.OnTapped() }

	loginForm = container.NewVBox(
		widget.NewLabel("Username"), usernameEntry,
		widget.NewLabel("Password"), passwordEntry,
		loginMsg,
		loginBtn,
	)

	// Register form
	regUserEntry := widget.NewEntry()
	regUserEntry.SetPlaceHolder("Username")
	regPassEntry := widget.NewPasswordEntry()
	regPassEntry.SetPlaceHolder("Password")
	regMsg := canvas.NewText("", colorError)
	regMsg.TextSize = 12

	registerBtn := widget.NewButton("Create Account", func() {
		body := fmt.Sprintf(`{"username":%q,"password":%q}`,
			regUserEntry.Text, regPassEntry.Text)
		resp, err := w.postStr("/api/register", body)
		if err != nil {
			fyne.Do(func() { regMsg.Text = "Network error"; regMsg.Refresh() })
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == 201 {
			// Auto-login after registration
			loginBody := fmt.Sprintf(`{"username":%q,"password":%q}`,
				regUserEntry.Text, regPassEntry.Text)
			resp2, err2 := w.postStr("/api/login", loginBody)
			if err2 == nil && resp2.StatusCode == 200 {
				for _, ck := range resp2.Cookies() {
					if ck.Name == "session" {
						w.sessionCook = "session=" + ck.Value
					}
				}
				resp2.Body.Close()
				go w.showLibrary()
				return
			}
		}
		data, _ := io.ReadAll(resp.Body)
		fyne.Do(func() { regMsg.Text = strings.TrimSpace(string(data)); regMsg.Refresh() })
	})
	registerBtn.Importance = widget.HighImportance

	registerForm = container.NewVBox(
		widget.NewLabel("Username"), regUserEntry,
		widget.NewLabel("Password"), regPassEntry,
		regMsg,
		registerBtn,
	)

	// Initially show login, hide register
	registerForm.Hide()

	switchForms := func() {
		loginTabActive = !loginTabActive
		if loginTabActive {
			loginTab.Importance = widget.HighImportance
			registerTab.Importance = widget.MediumImportance
			loginForm.Show()
			registerForm.Hide()
		} else {
			loginTab.Importance = widget.MediumImportance
			registerTab.Importance = widget.HighImportance
			loginForm.Hide()
			registerForm.Show()
		}
	}
	loginTab.OnTapped = func() {
		if !loginTabActive {
			switchForms()
		}
	}
	registerTab.OnTapped = func() {
		if loginTabActive {
			switchForms()
		}
	}

	tabs := container.NewHBox(loginTab, registerTab)

	card := container.NewVBox(
		container.NewCenter(logoObj),
		container.NewCenter(title),
		widget.NewSeparator(),
		tabs,
		widget.NewSeparator(),
		loginForm,
		registerForm,
	)

	// Wrap card in a styled box
	bg := canvas.NewRectangle(colorCard)
	bg.CornerRadius = 8
	styledCard := container.NewStack(bg, container.NewPadded(card))

	// Center with max-width
	centered := container.NewCenter(
		container.NewGridWrap(fyne.NewSize(380, 500), styledCard),
	)

	w.setContent(centered)
}

// ── Library screen ─────────────────────────────────────────────────────────────

func (w *WebViewWidget) showLibrary() {
	w.mu.Lock()
	w.mode = "library"
	w.mu.Unlock()

	// Show spinner while loading
	spin := container.NewCenter(widget.NewProgressBarInfinite())
	w.setContent(spin)

	go func() {
		// Fetch comics
		resp, err := w.get("/api/comics")
		if err != nil || resp.StatusCode == 401 {
			if resp != nil {
				resp.Body.Close()
			}
			go w.showLogin()
			return
		}
		var comicList []ComicJSON
		if err2 := json.NewDecoder(resp.Body).Decode(&comicList); err2 != nil {
			log.Printf("decode comics: %v", err2)
		}
		resp.Body.Close()

		// Fetch tags
		resp2, _ := w.get("/api/tags")
		var tagList []TagJSON
		if resp2 != nil {
			json.NewDecoder(resp2.Body).Decode(&tagList)
			resp2.Body.Close()
		}

		w.mu.Lock()
		w.allComics = comicList
		w.allTags = tagList
		w.page = 0
		w.mu.Unlock()

		w.renderLibrary()
	}()
}

func (w *WebViewWidget) renderLibrary() {
	w.mu.RLock()
	allComics := w.allComics
	allTags := w.allTags
	filterTags := make(map[string]bool, len(w.filterTags))
	for k, v := range w.filterTags {
		filterTags[k] = v
	}
	filterAlpha := w.filterAlpha
	filterSearch := w.filterSearch
	currentPage := w.page
	pageSize := w.pageSize
	w.mu.RUnlock()

	// ── Filter ────────────────────────────────────────────────────────────
	filtered := w.applyFilters(allComics, filterTags, filterAlpha, filterSearch)
	totalPages := (len(filtered) + pageSize - 1) / pageSize
	if currentPage >= totalPages {
		currentPage = 0
	}
	start := currentPage * pageSize
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	pageComics := filtered[start:end]

	// ── Header ────────────────────────────────────────────────────────────
	titleLbl := canvas.NewText("📚 Library", colorText)
	titleLbl.TextSize = 18
	titleLbl.TextStyle = fyne.TextStyle{Bold: true}

	logoutBtn := widget.NewButton("Logout", func() {
		w.postStr("/api/logout", "{}")
		w.sessionCook = ""
		go w.showLogin()
	})
	logoutBtn.Importance = widget.DangerImportance

	headerRow := container.NewBorder(nil, nil, titleLbl, logoutBtn, widget.NewLabel(""))

	// ── Tag filter bar ────────────────────────────────────────────────────
	tagBar := w.buildTagFilterBar(allTags, filterTags)

	// ── Alpha filter bar ─────────────────────────────────────────────────
	alphaBar := w.buildAlphaBar(filterAlpha)

	// ── Upload + search ───────────────────────────────────────────────────
	uploadBtn := widget.NewButton("+ Upload Comic (.cbz/.cbt/.cb7)", func() {
		w.showUploadDialog()
	})
	uploadBtn.Importance = widget.MediumImportance

	// Restore search text from widget state so it survives re-renders.
	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Search comics…")
	w.mu.RLock()
	searchEntry.SetText(w.filterSearch)
	w.mu.RUnlock()

	// OnChanged only saves to state + re-renders the grid/pagination — it does NOT
	// recreate the search entry itself, so focus is never lost.
	searchEntry.OnChanged = func(s string) {
		w.mu.Lock()
		w.filterSearch = strings.ToLower(s)
		w.page = 0
		w.mu.Unlock()
		w.renderLibraryGrid()
	}

	topControls := container.NewBorder(nil, nil, uploadBtn, nil, searchEntry)

	// ── Comics grid ───────────────────────────────────────────────────────
	grid := w.buildComicsGrid(pageComics)

	// ── Pagination ────────────────────────────────────────────────────────
	pagination := w.buildLibraryPagination(currentPage, totalPages, len(filtered))

	// ── Assemble ─────────────────────────────────────────────────────────
	top := container.NewVBox(
		headerRow,
		widget.NewSeparator(),
		topControls,
		tagBar,
		alphaBar,
		widget.NewSeparator(),
	)

	// Store mutable grid+pagination containers on the widget so that
	// renderLibraryGrid() can update them without rebuilding the whole layout
	// (which would destroy the search entry and lose keyboard focus).
	w.libraryGrid = container.NewStack(grid)
	w.libraryPagination = container.NewStack(pagination)

	scroll := container.NewVScroll(w.libraryGrid)

	bottom := container.NewVBox(widget.NewSeparator(), w.libraryPagination)

	w.setContent(container.NewBorder(top, bottom, nil, nil, scroll))
}

// renderLibraryGrid re-filters and redraws only the comics grid and pagination,
// leaving the header/search/filter bars (and their keyboard focus) untouched.
func (w *WebViewWidget) renderLibraryGrid() {
	w.mu.RLock()
	allComics := w.allComics
	filterTags := make(map[string]bool, len(w.filterTags))
	for k, v := range w.filterTags {
		filterTags[k] = v
	}
	filterAlpha := w.filterAlpha
	filterSearch := w.filterSearch
	currentPage := w.page
	pageSize := w.pageSize
	w.mu.RUnlock()

	// If the stable containers don't exist yet (first render not done), fall back.
	if w.libraryGrid == nil || w.libraryPagination == nil {
		w.renderLibrary()
		return
	}

	filtered := w.applyFilters(allComics, filterTags, filterAlpha, filterSearch)
	totalPages := (len(filtered) + pageSize - 1) / pageSize
	if currentPage >= totalPages {
		currentPage = 0
	}
	start := currentPage * pageSize
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	pageComics := filtered[start:end]

	grid := w.buildComicsGrid(pageComics)
	pagination := w.buildLibraryPagination(currentPage, totalPages, len(filtered))

	fyne.Do(func() {
		w.contentMu.Lock()
		w.libraryGrid.Objects = []fyne.CanvasObject{grid}
		w.libraryPagination.Objects = []fyne.CanvasObject{pagination}
		w.contentMu.Unlock()
		w.libraryGrid.Refresh()
		w.libraryPagination.Refresh()
	})
}

// applyFilters returns comics matching all active filters.
// buildLibraryPagination constructs the Prev/Next pagination bar for the library.
func (w *WebViewWidget) buildLibraryPagination(currentPage, totalPages, total int) *fyne.Container {
	pageInfo := widget.NewLabel(fmt.Sprintf("Page %d / %d  (%d comics)",
		currentPage+1, max1(totalPages), total))
	prevBtn := widget.NewButton("← Prev", func() {
		if currentPage > 0 {
			w.mu.Lock()
			w.page--
			w.mu.Unlock()
			w.renderLibraryGrid()
		}
	})
	nextBtn := widget.NewButton("Next →", func() {
		if currentPage < totalPages-1 {
			w.mu.Lock()
			w.page++
			w.mu.Unlock()
			w.renderLibraryGrid()
		}
	})
	if currentPage == 0 {
		prevBtn.Disable()
	}
	if currentPage >= totalPages-1 {
		nextBtn.Disable()
	}
	return container.NewHBox(prevBtn, container.NewCenter(pageInfo), nextBtn)
}

func (w *WebViewWidget) applyFilters(all []ComicJSON, tags map[string]bool, alpha, search string) []ComicJSON {
	out := make([]ComicJSON, 0, len(all))
	for _, c := range all {
		// Tag filter — comic must have ALL selected tags (AND logic)
		if len(tags) > 0 {
			match := true
			for wanted := range tags {
				wantedLower := strings.ToLower(wanted)
				found := false
				for _, t := range c.Tags {
					// Case-insensitive: artist tags are stored lowercase but the
					// tag dropdown may show the original-case name from the map.
					if strings.ToLower(t) == wantedLower {
						found = true
						break
					}
				}
				if !found {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}
		// Alpha filter — by Title, strip articles
		if alpha != "" && alpha != "all" {
			name := c.Title
			if name == "" {
				name = strings.TrimSuffix(c.Filename, filepath.Ext(c.Filename))
			}
			name = strings.ToUpper(strings.TrimSpace(name))
			for _, article := range []string{"THE ", "A ", "AN "} {
				if strings.HasPrefix(name, article) {
					name = name[len(article):]
					break
				}
			}
			if alpha == "0-9" {
				if len(name) == 0 || name[0] < '0' || name[0] > '9' {
					continue
				}
			} else {
				if !strings.HasPrefix(name, strings.ToUpper(alpha)) {
					continue
				}
			}
		}
		// Search filter — substring match across title, artist, series, filename
		if search != "" {
			haystack := strings.ToLower(c.Title + " " + c.Artist + " " + c.Series + " " + c.Filename)
			if !strings.Contains(haystack, search) {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}


func (w *WebViewWidget) buildTagFilterBar(tags []TagJSON, active map[string]bool) fyne.CanvasObject {
	if len(tags) == 0 {
		return widget.NewLabel("")
	}

	// Build label showing current selection
	tagLabel := func() string {
		w.mu.RLock()
		defer w.mu.RUnlock()
		if len(w.filterTags) == 0 {
			return "🏷 Filter by Tags ▾"
		}
		names := make([]string, 0, len(w.filterTags))
		for t := range w.filterTags {
			names = append(names, t)
		}
		sort.Strings(names)
		return "🏷 " + strings.Join(names, ", ") + " ▾"
	}

	// The button that opens the popover menu
	dropBtn := widget.NewButton(tagLabel(), nil)
	if len(active) > 0 {
		dropBtn.Importance = widget.HighImportance
	}

	dropBtn.OnTapped = func() {
		// Build a scrollable checklist popup
		items := make([]*widget.Check, 0, len(tags)+1)

		clearCheck := widget.NewCheck("— Clear All —", func(checked bool) {})
		items = append(items, clearCheck)

		for _, t := range tags {
			tCopy := t
			w.mu.RLock()
			isActive := w.filterTags[tCopy.Name]
			w.mu.RUnlock()
			ch := widget.NewCheck(tCopy.Name, func(checked bool) {})
			ch.Checked = isActive
			items = append(items, ch)
		}

		checkObjs := make([]fyne.CanvasObject, len(items))
		for i, ch := range items {
			checkObjs[i] = ch
		}
		checklist := container.NewVScroll(container.NewVBox(checkObjs...))
		checklist.SetMinSize(fyne.NewSize(220, 300))

		var pop *widget.PopUp
		applyBtn := widget.NewButton("Apply", func() {
			w.mu.Lock()
			w.filterTags = make(map[string]bool)
			if !clearCheck.Checked {
				for i, ch := range items[1:] {
					if ch.Checked {
						w.filterTags[tags[i].Name] = true
					}
				}
			}
			w.page = 0
			hasFilter := len(w.filterTags) > 0
			w.mu.Unlock()
			fyne.Do(func() {
				dropBtn.SetText(tagLabel())
				if hasFilter {
					dropBtn.Importance = widget.HighImportance
				} else {
					dropBtn.Importance = widget.MediumImportance
				}
				dropBtn.Refresh()
				if pop != nil {
					pop.Hide()
				}
			})
			w.renderLibrary()
		})
		applyBtn.Importance = widget.HighImportance

		clearCheck.OnChanged = func(checked bool) {
			if checked {
				for _, ch := range items[1:] {
					ch.Checked = false
					fyne.Do(ch.Refresh)
				}
			}
		}

		popContent := container.NewBorder(
			widget.NewLabel("Filter by Tags (multi-select):"),
			applyBtn,
			nil, nil,
			checklist,
		)
		pop = widget.NewPopUp(container.NewPadded(popContent), desktopWin.Canvas())
		pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(dropBtn)
		pos.Y += dropBtn.Size().Height
		pop.ShowAtPosition(pos)
	}

	return container.NewHBox(dropBtn)
}

func (w *WebViewWidget) buildAlphaBar(active string) fyne.CanvasObject {
	letters := append([]string{"all", "0-9"}, alphabetLetters()...)
	btns := make([]fyne.CanvasObject, 0, len(letters))
	for _, l := range letters {
		lCopy := l
		label := strings.ToUpper(lCopy)
		if lCopy == "all" {
			label = "All"
		}
		btn := widget.NewButton(label, func() {
			w.mu.Lock()
			w.filterAlpha = lCopy
			w.page = 0
			w.mu.Unlock()
			w.renderLibrary()
		})
		if lCopy == active {
			btn.Importance = widget.HighImportance
		} else {
			btn.Importance = widget.LowImportance
		}
		btns = append(btns, btn)
	}
	return container.NewHScroll(container.NewHBox(btns...))
}

func alphabetLetters() []string {
	out := make([]string, 26)
	for i := range out {
		out[i] = string(rune('A' + i))
	}
	return out
}

func (w *WebViewWidget) buildComicsGrid(comics []ComicJSON) fyne.CanvasObject {
	if len(comics) == 0 {
		lbl := canvas.NewText("No comics found", colorSubText)
		lbl.TextSize = 16
		return container.NewCenter(lbl)
	}

	tiles := make([]fyne.CanvasObject, 0, len(comics))
	for _, c := range comics {
		cCopy := c
		tiles = append(tiles, w.buildComicCard(cCopy))
	}
	// NewGridWrap enforces a fixed tile width so cards can never stretch wider.
	return container.NewGridWrap(fyne.NewSize(200, 0), tiles...)
}

func (w *WebViewWidget) buildComicCard(c ComicJSON) fyne.CanvasObject {
	// Cover image — FillContain so it scales to fill the tile width.
	// No SetMinSize: the GridWrap tile width drives the size.
	coverImg := canvas.NewImageFromImage(nil)
	coverImg.FillMode = canvas.ImageFillContain
	coverImg.SetMinSize(fyne.NewSize(190, 260))

	go func() {
		resp, err := w.get("/api/cover/" + url.QueryEscape(c.ID))
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			return
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		fyne.Do(func() {
			coverImg.Image = img
			coverImg.Refresh()
		})
	}()

	// Title — wraps within the tile width
	displayTitle := c.Title
	if displayTitle == "" {
		displayTitle = strings.TrimSuffix(c.Filename, c.FileType)
	}
	titleLbl := widget.NewLabel(displayTitle)
	titleLbl.Wrapping = fyne.TextWrapWord
	titleLbl.TextStyle = fyne.TextStyle{Bold: true}

	// Artist / series / year
	metaText := c.Artist
	if c.Series != "" {
		metaText += "\n" + c.Series
	}
	if c.Year != "" {
		metaText += " (" + c.Year + ")"
	}
	metaLbl := widget.NewLabel(metaText)
	metaLbl.Wrapping = fyne.TextWrapWord

	// Tags
	var tagObjs []fyne.CanvasObject
	if c.Encrypted {
		lockLbl := widget.NewLabel("🔒")
		lockLbl.TextStyle = fyne.TextStyle{Bold: true}
		tagObjs = append(tagObjs, lockLbl)
	}
	for _, tag := range c.Tags {
		tagObjs = append(tagObjs, newTagPill(tag))
	}

	// Action buttons at the top of the card, above title/meta/tags
	openBtn := widget.NewButton("Open", func() {
		if c.Encrypted && !c.HasPassword {
			go func() {
				resp, _ := w.postStr("/api/try-passwords/"+url.QueryEscape(c.ID), "{}")
				if resp != nil {
					var result struct {
						Success bool `json:"success"`
					}
					json.NewDecoder(resp.Body).Decode(&result)
					resp.Body.Close()
					if result.Success {
						w.showReader(c.ID, displayTitle, 0)
						return
					}
				}
				fyne.Do(func() { w.showPasswordDialog(c.ID, c.Filename) })
			}()
			return
		}
		go w.showReader(c.ID, displayTitle, 0)
	})
	openBtn.Importance = widget.HighImportance

	deleteBtn := widget.NewButton("Delete", func() {
		dialog.ShowConfirm("Delete Comic",
			"Delete "+displayTitle+"?",
			func(ok bool) {
				if ok {
					resp, _ := w.deleteReq("/api/delete-comic/" + url.QueryEscape(c.ID))
					if resp != nil {
						resp.Body.Close()
					}
					go w.showLibrary()
				}
			}, desktopWin)
	})
	deleteBtn.Importance = widget.DangerImportance

	// Cap visible tags at 8; show "+N more" if there are extras.
	const maxVisibleTags = 8
	visibleTags := tagObjs
	if len(tagObjs) > maxVisibleTags {
		visibleTags = tagObjs[:maxVisibleTags]
		more := canvas.NewText(fmt.Sprintf("+%d more", len(tagObjs)-maxVisibleTags), colorSubText)
		more.TextSize = 10
		visibleTags = append(visibleTags, more)
	}

	infoBox := container.NewVBox(titleLbl, metaLbl)
	if len(visibleTags) > 0 {
		infoBox.Add(newWrapContainer(4, visibleTags...))
	}

	cardBg := canvas.NewRectangle(colorCard)
	cardBg.CornerRadius = 6
	cardBorder := canvas.NewRectangle(color.Transparent)
	cardBorder.CornerRadius = 6
	cardBorder.StrokeWidth = 1
	cardBorder.StrokeColor = colorBorder

	cardContent := container.NewVBox(
		coverImg,
		container.NewHBox(openBtn, deleteBtn),
		container.NewPadded(infoBox),
	)

	return container.NewStack(cardBg, cardBorder, container.NewPadded(cardContent))
}

// newTagPill returns a compact pill whose width matches its text exactly.
func newTagPill(tag string) fyne.CanvasObject {
	bg := canvas.NewRectangle(colorBorder)
	bg.CornerRadius = 4

	// canvas.Text sizes itself to its content — no layout-forced height.
	lbl := canvas.NewText(tag, colorAccentLt)
	lbl.TextSize = 10

	// Pad 4px each side so the background rectangle has breathing room.
	padded := container.NewPadded(lbl)
	return container.NewStack(bg, padded)
}


// wrapTagLayout is a simple left-to-right wrapping layout (like CSS flex-wrap)
// that places children at their minimum size and wraps to the next row when
// the available width is exceeded.
type wrapTagLayout struct{ gap float32 }

func (l *wrapTagLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	// Report only the size of the widest single child so the parent container
	// is not forced to expand to fit all pills on one row.
	var maxW, maxH float32
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		min := o.MinSize()
		if min.Width > maxW {
			maxW = min.Width
		}
		if min.Height > maxH {
			maxH = min.Height
		}
	}
	return fyne.NewSize(maxW, maxH)
}
func (l *wrapTagLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	l.layout(objects, size, true)
}
func (l *wrapTagLayout) layout(objects []fyne.CanvasObject, size fyne.Size, apply bool) fyne.Size {
	x, y, rowH := float32(0), float32(0), float32(0)
	gap := l.gap
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		min := o.MinSize()
		if x > 0 && x+min.Width > size.Width {
			x = 0
			y += rowH + gap
			rowH = 0
		}
		if apply {
			o.Move(fyne.NewPos(x, y))
			o.Resize(min)
		}
		x += min.Width + gap
		if min.Height > rowH {
			rowH = min.Height
		}
	}
	return fyne.NewSize(size.Width, y+rowH)
}

// newWrapContainer wraps children into a left-to-right flowing container.
func newWrapContainer(gap float32, children ...fyne.CanvasObject) *fyne.Container {
	return container.New(&wrapTagLayout{gap: gap}, children...)
}

// ── Password dialog ────────────────────────────────────────────────────────────

func (w *WebViewWidget) showPasswordDialog(comicID, comicName string) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Enter comic password")
	errLbl := canvas.NewText("", colorError)
	errLbl.TextSize = 12

	form := dialog.NewCustom("🔒 Password Required",
		"Cancel",
		container.NewVBox(
			widget.NewLabel("Comic: "+comicName),
			passEntry,
			errLbl,
		),
		desktopWin,
	)

	unlockBtn := widget.NewButton("Unlock", func() {
		body := fmt.Sprintf(`{"password":%q}`, passEntry.Text)
		resp, err := w.postStr("/api/set-password/"+url.QueryEscape(comicID), body)
		if err != nil {
			fyne.Do(func() { errLbl.Text = "Network error"; errLbl.Refresh() })
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			form.Hide()
			go w.showReader(comicID, comicName, 0)
		} else {
			fyne.Do(func() { errLbl.Text = "Incorrect password"; errLbl.Refresh() })
		}
	})
	passEntry.OnSubmitted = func(_ string) { unlockBtn.OnTapped() }

	form.SetButtons([]fyne.CanvasObject{
		unlockBtn,
		widget.NewButton("Cancel", func() { form.Hide() }),
	})
	form.Show()
}

// ── Upload dialog ──────────────────────────────────────────────────────────────

// lastUploadDir remembers the folder the user last browsed to so re-opening
// the dialog starts in the same place.
var lastUploadDir string

func (w *WebViewWidget) showUploadDialog() {
	fd := dialog.NewFileOpen(func(f fyne.URIReadCloser, err error) {
		if err != nil || f == nil {
			return
		}
		filePath := f.URI().Path()
		f.Close()

		// Remember the directory for next time
		lastUploadDir = filepath.Dir(filePath)

		// Validate extension
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext != ".cbz" && ext != ".cbt" && ext != ".cb7" && ext != ".cbr" {
			dialog.ShowError(fmt.Errorf("unsupported file type %q\nSupported: .cbz .cbt .cb7 .cbr", ext), desktopWin)
			return
		}

		// Show progress while uploading
		progress := dialog.NewCustomWithoutButtons("Uploading…",
			container.NewVBox(
				widget.NewLabel(filepath.Base(filePath)),
				widget.NewProgressBarInfinite(),
			), desktopWin)
		progress.Show()

		go func() {
			uploadErr := w.uploadFile(filePath)
			fyne.Do(func() {
				progress.Hide()
				if uploadErr != nil {
					dialog.ShowError(uploadErr, desktopWin)
					return
				}
				// Reload the library immediately — no blocking modal.
				w.showLibrary()
			})
		}()
	}, desktopWin)

	// Filter matches exactly what handleUpload accepts on the server side
	fd.SetFilter(storage.NewExtensionFileFilter([]string{".cbz", ".cbt", ".cb7"}))

	// Give the dialog enough room so folder contents don't disappear —
	// Fyne's file dialog clips its list when the dialog is too small.
	fd.Resize(fyne.NewSize(900, 600))

	// Set starting directory: last-used → home → working dir, in that order.
	startDir := lastUploadDir
	if startDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			startDir = home
		}
	}
	if startDir != "" {
		if luri, err := storage.ListerForURI(storage.NewFileURI(startDir)); err == nil {
			fd.SetLocation(luri)
		}
	}

	fd.Show()
}

func (w *WebViewWidget) uploadFile(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	// Write the multipart body in a goroutine so the HTTP client can stream it.
	errCh := make(chan error, 1)
	go func() {
		part, err := mw.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			pw.CloseWithError(err)
			errCh <- err
			return
		}
		if _, err = io.Copy(part, f); err != nil {
			pw.CloseWithError(err)
			errCh <- err
			return
		}
		if err = mw.Close(); err != nil {
			pw.CloseWithError(err)
			errCh <- err
			return
		}
		pw.Close()
		errCh <- nil
	}()

	req, err := http.NewRequest(http.MethodPost, w.baseURL+"/api/upload", pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if w.sessionCook != "" {
		req.Header.Set("Cookie", w.sessionCook)
	}

	resp, err := http.DefaultClient.Do(req)
	// Always wait for the writer goroutine before inspecting the response.
	writeErr := <-errCh
	if writeErr != nil {
		return fmt.Errorf("write multipart: %w", writeErr)
	}
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", strings.TrimSpace(string(data)))
	}
	return nil
}

// ── Comic reader ───────────────────────────────────────────────────────────────

func (w *WebViewWidget) showReader(comicID, title string, startPage int) {
	w.mu.Lock()
	w.mode = "reader"
	w.comicID = comicID
	w.comicTitle = title
	w.pageIdx = startPage
	w.zoomFactor = 1.0
	w.mu.Unlock()

	// Spinner
	w.setContent(container.NewCenter(widget.NewProgressBarInfinite()))

	// Fetch page count
	resp, err := w.get("/api/pages/" + url.QueryEscape(comicID))
	if err != nil {
		log.Printf("showReader: %v", err)
		return
	}
	var pagesResult struct {
		PageCount int  `json:"page_count"`
		NeedsPwd  bool `json:"needs_password"`
	}
	json.NewDecoder(resp.Body).Decode(&pagesResult)
	resp.Body.Close()

	if pagesResult.NeedsPwd {
		w.showPasswordDialog(comicID, title)
		w.showLibrary()
		return
	}

	w.mu.Lock()
	w.pageCount = pagesResult.PageCount
	// Load bookmarks from the comic data
	for _, c := range w.allComics {
		if c.ID == comicID {
			w.bookmarks = c.Bookmarks
			break
		}
	}
	w.mu.Unlock()

	w.renderReaderPage()
}

func (w *WebViewWidget) renderReaderPage() {
	w.mu.RLock()
	pageIdx := w.pageIdx
	pageCount := w.pageCount
	comicID := w.comicID
	comicTitle := w.comicTitle
	fitMode := w.fitMode
	bookmarks := w.bookmarks
	w.mu.RUnlock()

	// ── Header ────────────────────────────────────────────────────────────
	titleLbl := widget.NewLabel(comicTitle)
	titleLbl.TextStyle = fyne.TextStyle{Bold: true}

	pageInfo := widget.NewLabel(fmt.Sprintf("Page %d / %d", pageIdx+1, pageCount))

	prevBtn := widget.NewButton("← Prev", func() {
		if pageIdx > 0 {
			w.mu.Lock()
			w.pageIdx--
			w.mu.Unlock()
			w.renderReaderPage()
		}
	})
	nextBtn := widget.NewButton("Next →", func() {
		if pageIdx < pageCount-1 {
			w.mu.Lock()
			w.pageIdx++
			w.mu.Unlock()
			w.renderReaderPage()
		}
	})
	if pageIdx == 0 {
		prevBtn.Disable()
	}
	if pageIdx >= pageCount-1 {
		nextBtn.Disable()
	}

	// Fit-mode buttons
	fitWidthBtn := widget.NewButton("Fit Width", func() {
		w.mu.Lock()
		w.fitMode = "width"
		w.mu.Unlock()
		w.renderReaderPage()
	})
	fitHeightBtn := widget.NewButton("Fit Height", func() {
		w.mu.Lock()
		w.fitMode = "height"
		w.mu.Unlock()
		w.renderReaderPage()
	})
	if fitMode == "width" {
		fitWidthBtn.Importance = widget.HighImportance
	} else {
		fitHeightBtn.Importance = widget.HighImportance
	}

	// Zoom
	zoomInBtn := widget.NewButton("+", func() {
		w.mu.Lock()
		if w.zoomFactor < 5 {
			w.zoomFactor += 0.25
		}
		w.mu.Unlock()
		w.renderReaderPage()
	})
	zoomOutBtn := widget.NewButton("−", func() {
		w.mu.Lock()
		if w.zoomFactor > 0.25 {
			w.zoomFactor -= 0.25
		}
		w.mu.Unlock()
		w.renderReaderPage()
	})
	resetZoomBtn := widget.NewButton("⊙", func() {
		w.mu.Lock()
		w.zoomFactor = 1.0
		w.mu.Unlock()
		w.renderReaderPage()
	})

	// Bookmark current page
	isBookmarked := false
	for _, b := range bookmarks {
		if b == pageIdx {
			isBookmarked = true
			break
		}
	}
	bookmarkLabel := "📖 Bookmark"
	if isBookmarked {
		bookmarkLabel = "📖 Bookmarked ✓"
	}
	bookmarkBtn := widget.NewButton(bookmarkLabel, func() {
		if isBookmarked {
			resp, _ := w.deleteReq(fmt.Sprintf("/api/bookmark/%s/%d",
				url.QueryEscape(comicID), pageIdx))
			if resp != nil {
				resp.Body.Close()
			}
		} else {
			body := fmt.Sprintf(`{"page":%d}`, pageIdx)
			resp, _ := w.postStr("/api/bookmark/"+url.QueryEscape(comicID), body)
			if resp != nil {
				resp.Body.Close()
			}
		}
		// Refresh bookmark list
		resp2, _ := w.get("/api/comics")
		if resp2 != nil {
			var cl []ComicJSON
			json.NewDecoder(resp2.Body).Decode(&cl)
			resp2.Body.Close()
			w.mu.Lock()
			w.allComics = cl
			for _, c := range cl {
				if c.ID == comicID {
					w.bookmarks = c.Bookmarks
				}
			}
			w.mu.Unlock()
		}
		w.renderReaderPage()
	})

	// Page jump
	pageEntry := widget.NewEntry()
	pageEntry.SetText(fmt.Sprintf("%d", pageIdx+1))
	pageEntry.SetMinRowsVisible(1)
	goBtn := widget.NewButton("Go", func() {
		var n int
		fmt.Sscanf(pageEntry.Text, "%d", &n)
		n--
		if n >= 0 && n < pageCount {
			w.mu.Lock()
			w.pageIdx = n
			w.mu.Unlock()
			w.renderReaderPage()
		}
	})

	// Bookmarks list button
	var bookmarkListShown bool
	bookmarkListBtn := widget.NewButton(fmt.Sprintf("📚 Bookmarks (%d)", len(bookmarks)), nil)

	closeBtn := widget.NewButton("✕ Close", func() {
		go w.showLibrary()
	})
	closeBtn.Importance = widget.DangerImportance

	header := container.NewHBox(
		closeBtn,
		widget.NewSeparator(),
		prevBtn, pageEntry, widget.NewLabel(fmt.Sprintf("/ %d", pageCount)), goBtn, nextBtn,
		widget.NewSeparator(),
		fitWidthBtn, fitHeightBtn,
		widget.NewSeparator(),
		zoomOutBtn, resetZoomBtn, zoomInBtn,
		widget.NewSeparator(),
		bookmarkBtn, bookmarkListBtn,
		layout.NewSpacer(),
		titleLbl,
		pageInfo,
	)

	// ── Page image area ───────────────────────────────────────────────────
	w.mu.RLock()
	zoom := w.zoomFactor
	w.mu.RUnlock()

	imgCanvas := canvas.NewImageFromImage(nil)
	imgCanvas.FillMode = canvas.ImageFillContain

	// Set fill mode based on fit
	switch fitMode {
	case "width":
		imgCanvas.FillMode = canvas.ImageFillContain // Fyne only has contain/cover/stretch
	default:
		imgCanvas.FillMode = canvas.ImageFillContain
	}

	// Scale relative to zoom
	baseW := float32(700)
	baseH := float32(1000)
	if fitMode == "width" {
		baseW = 1400
		baseH = 2000
	}
	imgCanvas.SetMinSize(fyne.NewSize(baseW*zoom, baseH*zoom))

	readerBg := canvas.NewRectangle(colorBlack)

	imageScroll := container.NewScroll(
		container.NewStack(readerBg,
			container.NewCenter(imgCanvas)))

	// Keyboard navigation (Fyne doesn't have keyboard focus on custom widgets
	// but we wire up buttons)
	_ = bookmarkListShown // suppress lint

	// Bookmark list panel
	var bookmarkItems []fyne.CanvasObject
	for _, b := range bookmarks {
		bCopy := b
		btn := widget.NewButton(fmt.Sprintf("Page %d", bCopy+1), func() {
			w.mu.Lock()
			w.pageIdx = bCopy
			w.mu.Unlock()
			w.renderReaderPage()
		})
		bookmarkItems = append(bookmarkItems, btn)
	}

	var bookmarkPanel fyne.CanvasObject
	if len(bookmarkItems) > 0 {
		bookmarkPanel = container.NewVScroll(container.NewVBox(bookmarkItems...))
	} else {
		bookmarkPanel = widget.NewLabel("No bookmarks")
	}
	bookmarkSide := container.NewBorder(
		widget.NewLabel("Bookmarks"), nil, nil, nil,
		bookmarkPanel,
	)
	bookmarkSide.Hide()

	bookmarkListBtn.OnTapped = func() {
		bookmarkListShown = !bookmarkListShown
		if bookmarkListShown {
			bookmarkSide.Show()
		} else {
			bookmarkSide.Hide()
		}
	}

	mainArea := container.NewBorder(nil, nil, nil, bookmarkSide, imageScroll)

	w.setContent(container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		nil, nil, nil,
		mainArea,
	))

	// Async fetch + display image
	go func() {
		imgURL := fmt.Sprintf("/api/comic/%s/page/%d", url.QueryEscape(comicID), pageIdx)
		resp, err := w.get(imgURL)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			return
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			log.Printf("decode page img: %v", err)
			return
		}
		fyne.Do(func() {
			imgCanvas.Image = img
			imgCanvas.Refresh()
		})
	}()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (w *WebViewWidget) setContent(obj fyne.CanvasObject) {
	fyne.Do(func() {
		w.contentMu.Lock()
		w.content.Objects = []fyne.CanvasObject{obj}
		w.contentMu.Unlock()
		w.content.Refresh()
	})
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// ── Stub types to avoid import cycle ─────────────────────────────────────────

// sortComics sorts a comic slice by Artist then Series then Number.
func sortComicsByArtist(comics []ComicJSON) {
	sort.Slice(comics, func(i, j int) bool {
		if comics[i].Artist != comics[j].Artist {
			return comics[i].Artist < comics[j].Artist
		}
		if comics[i].Series != comics[j].Series {
			return comics[i].Series < comics[j].Series
		}
		return comics[i].Number < comics[j].Number
	})
}
