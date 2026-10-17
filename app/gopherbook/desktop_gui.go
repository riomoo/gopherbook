//go:build desktop

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/png"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gioui.org/app"
	"gioui.org/gesture"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"gioui.org/x/explorer"
)

type (
	C = layout.Context
	D = layout.Dimensions
)

var (
	logoOnce sync.Once
	logoOp   paint.ImageOp
	logoOK   bool
)

// logoImage decodes the embedded LogoPose2.png once and caches it.
// Loaded lazily (not at startup) so a missing/corrupt asset degrades
// to "no logo" instead of crashing the app.
func logoImage() (paint.ImageOp, bool) {
	logoOnce.Do(func() {
		data, err := staticFS.ReadFile("static/images/pngs/LogoPose2.png")
		if err != nil {
			log.Printf("logo: %v", err)
			return
		}
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			log.Printf("logo decode: %v", err)
			return
		}
		logoOp = paint.NewImageOp(img)
		logoOK = true
	})
	return logoOp, logoOK
}

func rgb(hex uint32) color.NRGBA {
	return color.NRGBA{
		R: uint8(hex >> 16), G: uint8(hex >> 8), B: uint8(hex), A: 0xFF,
	}
}

// globalBaseURL/globalApp exist for the handful of places (cover/page
// URLs built inside widget builders that don't carry *App through
// every call) that need them without threading a parameter everywhere.
// Neither is mutated after startup except sessionCookie, which is its
// own guarded holder below.
var globalBaseURL string
var globalApp *App

// ── Session cookie ───────────────────────────────────────────────────────
// The one piece of App state read from goroutines OTHER than the UI
// loop (image-fetch goroutines attach it to every request), so unlike
// everything else it can't just live as a plain field mutated only via
// uiQueue. A tiny RWMutex-guarded string is the same approach used in
// the go-gui port for the same reason.
var (
	sessionCookieMu  sync.RWMutex
	sessionCookieVal string
)

func getSessionCookie() string {
	sessionCookieMu.RLock()
	defer sessionCookieMu.RUnlock()
	return sessionCookieVal
}

func setSessionCookie(v string) {
	sessionCookieMu.Lock()
	sessionCookieVal = v
	sessionCookieMu.Unlock()
}

type appMode int

const (
	modeLogin appMode = iota
	modeLibrary
	modeUnlock
	modeReader
)

// ── JSON types mirroring the Go backend structs ─────────────────────────────

type ComicJSON struct {
	ID          string   `json:"id"`
	Filename    string   `json:"filename"`
	Artist      string   `json:"artist"`
	Title       string   `json:"title"`
	Series      string   `json:"series"`
	Year        string   `json:"year"`
	PageCount   int      `json:"page_count"`
	Encrypted   bool     `json:"encrypted"`
	HasPassword bool     `json:"has_password"`
	Tags        []string `json:"tags"`
	Bookmarks   []int    `json:"bookmarks"`
}

type TagJSON struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// comicWidgets holds the per-comic-card widgets that must persist
// across frames (Clickables carry click/press state); built lazily
// and cached in App.cardWidgets, keyed by comic ID.
type comicWidgets struct {
	openBtn, deleteBtn widget.Clickable
}

// App is the single owner of all UI state. Every field is touched only
// from the goroutine running runUI's event loop — see the concurrency
// note on runUI in desktop_main.go. Background goroutines only ever
// read baseURL (immutable after construction) and getSessionCookie(),
// then push a func() onto uiQueue to apply their result.
type App struct {
	win      *app.Window
	theme    *material.Theme
	explorer *explorer.Explorer
	uiQueue  chan func()

	baseURL string
	mode    appMode

	// login / register
	loginTab       bool
	loginUserEd    widget.Editor
	loginPassEd    widget.Editor
	loginErr       string
	loginSubmit    widget.Clickable
	loginTabBtn    widget.Clickable
	registerTabBtn widget.Clickable
	regUserEd      widget.Editor
	regPassEd      widget.Editor
	regErr         string
	regSubmit      widget.Clickable

	// library
	allComics    []ComicJSON
	allTags      []TagJSON
	filterTags   map[string]bool
	filterAlpha  string
	filterSearch string
	searchEd     widget.Editor
	page         int
	pageSize     int
	loading      bool
	uploading    bool
	uploadErr    string
	showTagList  bool
	tagListBtn   widget.Clickable
	tagChecks    map[string]*widget.Bool
	uploadBtn    widget.Clickable
	logoutBtn    widget.Clickable
	alphaBtns    map[string]*widget.Clickable
	pagePrevBtn  widget.Clickable
	pageNextBtn  widget.Clickable
	cardWidgets  map[string]*comicWidgets

	// delete confirm (rendered as an overlay over the library)
	showDeleteConfirm bool
	pendingDeleteID   string
	pendingDeleteName string
	deleteConfirmBtn  widget.Clickable
	deleteCancelBtn   widget.Clickable

	// password unlock screen
	pendingComicID   string
	pendingComicName string
	pwEd             widget.Editor
	pwErr            string
	pwShow           widget.Bool
	pwUnlockBtn      widget.Clickable
	pwCancelBtn      widget.Clickable

	// reader
	comicID                                                                    string
	comicTitle                                                                 string
	pageIdx                                                                    int
	pageCount                                                                  int
	fitMode                                                                    string
	zoomFactor                                                                 float32
	panOffX, panOffY                                                           int
	panScrollX, panScrollY                                                     gesture.Scroll
	panFocus                                                                   struct{} // dedicated event tag for reader drag + keyboard panning
	pendingPanFocus                                                            bool     // set on page open; consumed by readerPageView, which has a live gtx to focus with
	dragging                                                                   bool
	dragPID                                                                    pointer.ID
	dragLastX, dragLastY                                                       int
	bookmarks                                                                  []int
	showBookmarks                                                              bool
	pageJumpEd                                                                 widget.Editor
	readerBackBtn, readerFirstBtn, readerPrevBtn, readerNextBtn, readerLastBtn widget.Clickable
	fitWBtn, fitHBtn, zoomOutBtn, zoomInBtn, bmToggleBtn, bmListBtn            widget.Clickable
	bookmarkJumpBtns                                                           map[int]*widget.Clickable
}

func (a *App) queue(fn func()) { a.uiQueue <- fn }

// ── HTTP helpers ─────────────────────────────────────────────────────────

func (a *App) get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c := getSessionCookie(); c != "" {
		req.Header.Set("Cookie", c)
	}
	return http.DefaultClient.Do(req)
}

func (a *App) post(path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, a.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c := getSessionCookie(); c != "" {
		req.Header.Set("Cookie", c)
	}
	return http.DefaultClient.Do(req)
}

func (a *App) postJSON(path string, v any) (*http.Response, error) {
	b, _ := json.Marshal(v)
	return a.post(path, strings.NewReader(string(b)))
}

func (a *App) deleteReq(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c := getSessionCookie(); c != "" {
		req.Header.Set("Cookie", c)
	}
	return http.DefaultClient.Do(req)
}

// ── Root layout dispatcher, called once per frame from runUI ───────────────

func (a *App) layout(gtx C) D {
	paint.Fill(gtx.Ops, a.theme.Palette.Bg)
	switch a.mode {
	case modeLibrary:
		return a.libraryLayout(gtx)
	case modeUnlock:
		return a.unlockLayout(gtx)
	case modeReader:
		return a.readerLayout(gtx)
	default:
		return a.loginLayout(gtx)
	}
}

// ── shared small helpers ─────────────────────────────────────────────────

func fillRRect(gtx C, r image.Rectangle, radius int, col color.NRGBA) {
	defer clip.RRect{Rect: r, SE: radius, SW: radius, NW: radius, NE: radius}.Push(gtx.Ops).Pop()
	paint.Fill(gtx.Ops, col)
}

// filledCard draws w on a rounded, filled background sized to w's
// OWN measured dimensions, not to gtx's incoming constraints. Gio's
// constraints often carry the full remaining window height (e.g.
// layout.Center loosens Min but Max still spans the window), so
// filling a rect sized from gtx.Constraints.Max — the naive approach —
// stretches the card's background down the whole window. This records
// w's drawing ops first (without emitting them), measures the real
// size that comes back, paints the background to THAT size, then
// replays the recorded content on top. This is the same record/
// measure/replay technique layout.Center itself uses internally.
func filledCard(gtx C, radius unit.Dp, bg color.NRGBA, w layout.Widget) D {
	macro := op.Record(gtx.Ops)
	dims := w(gtx)
	call := macro.Stop()
	fillRRect(gtx, image.Rectangle{Max: dims.Size}, gtx.Dp(radius), bg)
	call.Add(gtx.Ops)
	return dims
}

func errorLabel(th *material.Theme, msg string) layout.Widget {
	return func(gtx C) D {
		if msg == "" {
			return D{}
		}
		l := material.Body2(th, msg)
		l.Color = rgb(0xE07070)
		return l.Layout(gtx)
	}
}

func spacer(h int) layout.Widget {
	return func(gtx C) D {
		return D{Size: image.Point{X: gtx.Constraints.Max.X, Y: gtx.Dp(unit.Dp(h))}}
	}
}

// ── Login / Register ────────────────────────────────────────────────────

func (a *App) loginLayout(gtx C) D {
	th := a.theme

	// Drain editor events before laying anything out.
	for {
		ev, ok := a.loginUserEd.Update(gtx)
		if !ok {
			break
		}
		if _, ok := ev.(widget.SubmitEvent); ok {
			a.doLogin()
		}
	}
	for {
		ev, ok := a.loginPassEd.Update(gtx)
		if !ok {
			break
		}
		if _, ok := ev.(widget.SubmitEvent); ok {
			a.doLogin()
		}
	}
	for {
		ev, ok := a.regUserEd.Update(gtx)
		if !ok {
			break
		}
		_ = ev
	}
	for {
		ev, ok := a.regPassEd.Update(gtx)
		if !ok {
			break
		}
		if _, ok := ev.(widget.SubmitEvent); ok {
			a.doRegister()
		}
	}
	if a.loginTabBtn.Clicked(gtx) {
		a.loginTab = true
	}
	if a.registerTabBtn.Clicked(gtx) {
		a.loginTab = false
	}
	if a.loginSubmit.Clicked(gtx) {
		a.doLogin()
	}
	if a.regSubmit.Clicked(gtx) {
		a.doRegister()
	}

	a.loginUserEd.SingleLine = true
	a.loginUserEd.Submit = true
	a.loginPassEd.SingleLine = true
	a.loginPassEd.Submit = true
	a.loginPassEd.Mask = '•'
	a.regUserEd.SingleLine = true
	a.regUserEd.Submit = true
	a.regPassEd.SingleLine = true
	a.regPassEd.Submit = true
	a.regPassEd.Mask = '•'

	tabBtn := func(label string, active bool, click *widget.Clickable) layout.Widget {
		return func(gtx C) D {
			btn := material.Button(th, click, label)
			if !active {
				btn.Background = th.Palette.Bg
				btn.Color = th.Palette.Fg
			}
			return btn.Layout(gtx)
		}
	}

	var form []layout.Widget
	if a.loginTab {
		form = []layout.Widget{
			material.Editor(th, &a.loginUserEd, "Username").Layout,
			spacer(8),
			material.Editor(th, &a.loginPassEd, "Password").Layout,
			spacer(8),
			errorLabel(th, a.loginErr),
			spacer(8),
			material.Button(th, &a.loginSubmit, "Login").Layout,
		}
	} else {
		form = []layout.Widget{
			material.Editor(th, &a.regUserEd, "Username").Layout,
			spacer(8),
			material.Editor(th, &a.regPassEd, "Password").Layout,
			spacer(8),
			errorLabel(th, a.regErr),
			spacer(8),
			material.Button(th, &a.regSubmit, "Create Account").Layout,
		}
	}

	cardContent := append([]layout.Widget{
		func(gtx C) D {
			titleLabel := func(gtx C) D {
				l := material.H4(th, "Gopherbook")
				l.Alignment = text.Middle
				return l.Layout(gtx)
			}
			op, ok := logoImage()
			if !ok {
				return layout.Center.Layout(gtx, titleLabel)
			}
			logo := func(gtx C) D {
				gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(48))
				gtx.Constraints.Max.X = gtx.Dp(unit.Dp(48))
				return widget.Image{Src: op, Fit: widget.Contain}.Layout(gtx)
			}
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceEvenly}.Layout(gtx,
				layout.Rigid(logo),
				layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
				layout.Rigid(titleLabel),
			)
		},
		spacer(16),
		func(gtx C) D {
			return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceEvenly}.Layout(gtx,
				layout.Flexed(1, tabBtn("Login", a.loginTab, &a.loginTabBtn)),
				layout.Flexed(1, tabBtn("Register", !a.loginTab, &a.registerTabBtn)),
			)
		},
		spacer(16),
	}, form...)

	return layout.Center.Layout(gtx, func(gtx C) D {
		gtx.Constraints.Min.X = gtx.Dp(unit.Dp(380))
		gtx.Constraints.Max.X = gtx.Dp(unit.Dp(380))
		return widget.Border{Color: rgb(0x314C52), Width: unit.Dp(1), CornerRadius: unit.Dp(8)}.Layout(gtx, func(gtx C) D {
			return layout.UniformInset(unit.Dp(24)).Layout(gtx, func(gtx C) D {
				return filledCard(gtx, unit.Dp(8), rgb(0x252836), func(gtx C) D {
					children := make([]layout.FlexChild, len(cardContent))
					for i, w := range cardContent {
						children[i] = layout.Rigid(w)
					}
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
				})
			})
		})
	})
}

func (a *App) doLogin() {
	user, pass := a.loginUserEd.Text(), a.loginPassEd.Text()
	go func() {
		resp, err := a.postJSON("/api/login", map[string]string{"username": user, "password": pass})
		a.queue(func() {
			if err != nil {
				a.loginErr = "Network error"
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				for _, ck := range resp.Cookies() {
					if ck.Name == "session" {
						setSessionCookie("session=" + ck.Value)
					}
				}
				a.loginErr = ""
				a.mode = modeLibrary
				a.fetchLibrary()
			} else {
				a.loginErr = "Invalid username or password"
			}
		})
	}()
}

func (a *App) doRegister() {
	user, pass := a.regUserEd.Text(), a.regPassEd.Text()
	go func() {
		resp, err := a.postJSON("/api/register", map[string]string{"username": user, "password": pass})
		if err != nil {
			a.queue(func() { a.regErr = "Network error" })
			return
		}
		if resp.StatusCode == 201 {
			resp.Body.Close()
			resp2, err2 := a.postJSON("/api/login", map[string]string{"username": user, "password": pass})
			if err2 == nil && resp2.StatusCode == 200 {
				var cookie string
				for _, ck := range resp2.Cookies() {
					if ck.Name == "session" {
						cookie = "session=" + ck.Value
					}
				}
				resp2.Body.Close()
				a.queue(func() {
					setSessionCookie(cookie)
					a.regErr = ""
					a.mode = modeLibrary
					a.fetchLibrary()
				})
				return
			}
			if resp2 != nil {
				resp2.Body.Close()
			}
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		a.queue(func() { a.regErr = strings.TrimSpace(string(data)) })
	}()
}

// ── Library ──────────────────────────────────────────────────────────────

func (a *App) fetchLibrary() {
	a.loading = true
	go func() {
		resp, err := a.get("/api/comics")
		if err != nil || resp.StatusCode == 401 {
			if resp != nil {
				resp.Body.Close()
			}
			a.queue(func() {
				a.mode = modeLogin
				a.loading = false
			})
			return
		}
		var comics []ComicJSON
		json.NewDecoder(resp.Body).Decode(&comics)
		resp.Body.Close()

		var tags []TagJSON
		if resp2, err2 := a.get("/api/tags"); err2 == nil {
			json.NewDecoder(resp2.Body).Decode(&tags)
			resp2.Body.Close()
		}

		a.queue(func() {
			a.allComics = comics
			a.allTags = tags
			a.loading = false
			a.page = 0
			a.clearImageErrors()
		})
	}()
}

func applyLibraryFilters(all []ComicJSON, tags map[string]bool, alpha, search string) []ComicJSON {
	out := make([]ComicJSON, 0, len(all))
	for _, c := range all {
		if len(tags) > 0 {
			match := true
			for wanted := range tags {
				found := false
				for _, t := range c.Tags {
					if strings.EqualFold(t, wanted) {
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
			} else if !strings.HasPrefix(name, strings.ToUpper(alpha)) {
				continue
			}
		}
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

func (a *App) libraryLayout(gtx C) D {
	th := a.theme

	if a.uploadBtn.Clicked(gtx) {
		a.showUploadPicker()
	}
	if a.logoutBtn.Clicked(gtx) {
		go a.postJSON("/api/logout", map[string]string{})
		setSessionCookie("")
		a.clearImageCache()
		a.mode = modeLogin
	}
	if a.tagListBtn.Clicked(gtx) {
		a.showTagList = !a.showTagList
	}
	if a.pagePrevBtn.Clicked(gtx) && a.page > 0 {
		a.page--
	}
	for {
		ev, ok := a.searchEd.Update(gtx)
		if !ok {
			break
		}
		if _, ok := ev.(widget.ChangeEvent); ok {
			a.filterSearch = strings.ToLower(a.searchEd.Text())
			a.page = 0
		}
	}
	a.searchEd.SingleLine = true

	if a.deleteConfirmBtn.Clicked(gtx) {
		id := a.pendingDeleteID
		a.showDeleteConfirm = false
		go func() {
			resp, _ := a.deleteReq("/api/delete-comic/" + url.QueryEscape(id))
			if resp != nil {
				resp.Body.Close()
			}
			a.queue(func() { a.fetchLibrary() })
		}()
	}
	if a.deleteCancelBtn.Clicked(gtx) {
		a.showDeleteConfirm = false
	}

	filtered := applyLibraryFilters(a.allComics, a.filterTags, a.filterAlpha, a.filterSearch)
	pageSize := a.pageSize
	if pageSize <= 0 {
		pageSize = 40
	}
	totalPages := (len(filtered) + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	if a.page >= totalPages {
		a.page = 0
	}
	start := a.page * pageSize
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	var pageComics []ComicJSON
	if start < len(filtered) {
		pageComics = filtered[start:end]
	}
	if a.pageNextBtn.Clicked(gtx) && a.page < totalPages-1 {
		a.page++
	}

	rows := []layout.Widget{
		func(gtx C) D {
			return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(material.H5(th, "Library").Layout),
				layout.Rigid(func(gtx C) D {
					btn := material.Button(th, &a.logoutBtn, "Logout")
					btn.Background = rgb(0xA55354)
					return btn.Layout(gtx)
				}),
			)
		},
		spacer(8),
	}

	if a.loading && len(a.allComics) == 0 {
		return layout.Center.Layout(gtx, material.Loader(th).Layout)
	}

	rows = append(rows,
		func(gtx C) D {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(material.Button(th, &a.uploadBtn, "+ Upload Comic").Layout),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Flexed(1, material.Editor(th, &a.searchEd, "Search comics…").Layout),
			)
		},
		spacer(8),
		a.tagFilterWidget(),
		spacer(4),
		a.alphaBarWidget(),
		spacer(8),
	)
	if a.uploading {
		rows = append(rows, material.Loader(th).Layout, spacer(4))
	}
	if a.uploadErr != "" {
		rows = append(rows, errorLabel(th, a.uploadErr), spacer(4))
	}
	rows = append(rows,
		a.comicsGridWidget(gtx, pageComics),
		spacer(8),
		func(gtx C) D {
			return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceEvenly, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(material.Button(th, &a.pagePrevBtn, "← Prev").Layout),
				layout.Rigid(material.Body1(th, fmt.Sprintf("Page %d / %d (%d comics)", a.page+1, totalPages, len(filtered))).Layout),
				layout.Rigid(material.Button(th, &a.pageNextBtn, "Next →").Layout),
			)
		},
	)

	children := make([]layout.FlexChild, len(rows))
	for i, w := range rows {
		children[i] = layout.Rigid(w)
	}
	base := layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	})

	if a.showDeleteConfirm {
		return a.deleteConfirmOverlay(gtx, base)
	}
	return base
}

func (a *App) deleteConfirmOverlay(gtx C, base D) D {
	th := a.theme
	layout.Stack{Alignment: layout.Center}.Layout(gtx,
		layout.Expanded(func(gtx C) D {
			paint.Fill(gtx.Ops, color.NRGBA{A: 0x99})
			return D{Size: gtx.Constraints.Max}
		}),
		layout.Stacked(func(gtx C) D {
			gtx.Constraints.Min.X = gtx.Dp(unit.Dp(320))
			return layout.UniformInset(unit.Dp(20)).Layout(gtx, func(gtx C) D {
				return filledCard(gtx, unit.Dp(8), rgb(0x252836), func(gtx C) D {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(material.H6(th, "Delete Comic").Layout),
						layout.Rigid(spacer(8)),
						layout.Rigid(material.Body1(th, "Delete "+a.pendingDeleteName+"?").Layout),
						layout.Rigid(spacer(12)),
						layout.Rigid(func(gtx C) D {
							return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceEvenly}.Layout(gtx,
								layout.Rigid(func(gtx C) D {
									btn := material.Button(th, &a.deleteConfirmBtn, "Delete")
									btn.Background = rgb(0xA55354)
									return btn.Layout(gtx)
								}),
								layout.Rigid(material.Button(th, &a.deleteCancelBtn, "Cancel").Layout),
							)
						}),
					)
				})
			})
		}),
	)
	return D{Size: gtx.Constraints.Max}
}

func (a *App) tagFilterWidget() layout.Widget {
	return func(gtx C) D {
		th := a.theme
		if len(a.allTags) == 0 {
			return D{}
		}
		label := fmt.Sprintf("Tags (%d selected) %s", len(a.filterTags), map[bool]string{true: "▲", false: "▼"}[a.showTagList])
		header := material.Button(th, &a.tagListBtn, label)
		if !a.showTagList {
			return header.Layout(gtx)
		}

		if a.tagChecks == nil {
			a.tagChecks = make(map[string]*widget.Bool)
		}
		names := make([]string, 0, len(a.allTags))
		for _, t := range a.allTags {
			names = append(names, t.Name)
			if a.tagChecks[t.Name] == nil {
				b := &widget.Bool{Value: a.filterTags[t.Name]}
				a.tagChecks[t.Name] = b
			}
		}
		sort.Strings(names)

		for _, name := range names {
			b := a.tagChecks[name]
			if b.Update(gtx) {
				if b.Value {
					if a.filterTags == nil {
						a.filterTags = make(map[string]bool)
					}
					a.filterTags[name] = true
				} else {
					delete(a.filterTags, name)
				}
				a.page = 0
			}
		}

		items := make([]layout.FlexChild, 0, len(names)+1)
		items = append(items, layout.Rigid(header.Layout))
		list := &widget.List{List: layout.List{Axis: layout.Vertical}}
		checklist := func(gtx C) D {
			return list.Layout(gtx, len(names), func(gtx C, i int) D {
				return material.CheckBox(th, a.tagChecks[names[i]], names[i]).Layout(gtx)
			})
		}
		items = append(items, layout.Rigid(func(gtx C) D {
			gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(180))
			gtx.Constraints.Min.X = gtx.Dp(unit.Dp(260))
			return widget.Border{Color: rgb(0x314C52), Width: unit.Dp(1)}.Layout(gtx, checklist)
		}))
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, items...)
	}
}

func (a *App) alphaBarWidget() layout.Widget {
	return func(gtx C) D {
		th := a.theme
		if a.alphaBtns == nil {
			a.alphaBtns = make(map[string]*widget.Clickable)
		}
		letters := append([]string{"all", "0-9"}, alphabetLetters()...)
		list := &widget.List{List: layout.List{Axis: layout.Horizontal}}
		return list.Layout(gtx, len(letters), func(gtx C, i int) D {
			l := letters[i]
			if a.alphaBtns[l] == nil {
				a.alphaBtns[l] = new(widget.Clickable)
			}
			btn := a.alphaBtns[l]
			if btn.Clicked(gtx) {
				a.filterAlpha = l
				a.page = 0
			}
			label := strings.ToUpper(l)
			if l == "all" {
				label = "All"
			}
			b := material.Button(th, btn, label)
			if l != a.filterAlpha {
				b.Background = th.Palette.Bg
				b.Color = th.Palette.Fg
			}
			return layout.Inset{Right: unit.Dp(4)}.Layout(gtx, b.Layout)
		})
	}
}

func alphabetLetters() []string {
	out := make([]string, 26)
	for i := range out {
		out[i] = string(rune('A' + i))
	}
	return out
}

const cardWidth = 200

func (a *App) comicsGridWidget(gtx C, comics []ComicJSON) layout.Widget {
	return func(gtx C) D {
		th := a.theme
		if len(comics) == 0 {
			return layout.Center.Layout(gtx, material.Body1(th, "No comics found").Layout)
		}
		if a.cardWidgets == nil {
			a.cardWidgets = make(map[string]*comicWidgets)
		}
		perRow := gtx.Constraints.Max.X / gtx.Dp(unit.Dp(cardWidth+12))
		if perRow < 1 {
			perRow = 1
		}
		rowCount := (len(comics) + perRow - 1) / perRow
		list := &widget.List{List: layout.List{Axis: layout.Vertical}}
		return list.Layout(gtx, rowCount, func(gtx C, row int) D {
			start := row * perRow
			end := start + perRow
			if end > len(comics) {
				end = len(comics)
			}
			children := make([]layout.FlexChild, 0, end-start)
			for _, c := range comics[start:end] {
				c := c
				children = append(children, layout.Rigid(func(gtx C) D {
					return layout.Inset{Right: unit.Dp(12), Bottom: unit.Dp(12)}.Layout(gtx, func(gtx C) D {
						return a.comicCard(gtx, c)
					})
				}))
			}
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
		})
	}
}

func (a *App) comicCard(gtx C, c ComicJSON) D {
	th := a.theme
	if a.cardWidgets[c.ID] == nil {
		a.cardWidgets[c.ID] = &comicWidgets{}
	}
	cw := a.cardWidgets[c.ID]

	if cw.openBtn.Clicked(gtx) {
		a.openComic(c)
	}
	if cw.deleteBtn.Clicked(gtx) {
		a.showDeleteConfirm = true
		a.pendingDeleteID = c.ID
		a.pendingDeleteName = displayTitleOf(c)
	}

	gtx.Constraints.Min.X = gtx.Dp(unit.Dp(cardWidth))
	gtx.Constraints.Max.X = gtx.Dp(unit.Dp(cardWidth))
	return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx C) D {
		return filledCard(gtx, unit.Dp(6), rgb(0x252836), func(gtx C) D {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx C) D {
					gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(240))
					return a.remoteImage(gtx, coverURL(c.ID), 190, 240)
				}),
				layout.Rigid(spacer(4)),
				layout.Rigid(func(gtx C) D {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Rigid(material.Button(th, &cw.openBtn, "Open").Layout),
						layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
						layout.Rigid(func(gtx C) D {
							btn := material.Button(th, &cw.deleteBtn, "Delete")
							btn.Background = rgb(0xA55354)
							return btn.Layout(gtx)
						}),
					)
				}),
				layout.Rigid(material.Body2(th, displayTitleOf(c)).Layout),
				layout.Rigid(material.Caption(th, strings.Join(c.Tags, ", ")).Layout),
			)
		})
	})
}

func displayTitleOf(c ComicJSON) string {
	if c.Title != "" {
		return c.Title
	}
	return strings.TrimSuffix(c.Filename, filepath.Ext(c.Filename))
}

func coverURL(comicID string) string {
	return globalBaseURL + "/api/cover/" + url.QueryEscape(comicID)
}

func (a *App) openComic(c ComicJSON) {
	if c.Encrypted && !c.HasPassword {
		go func() {
			resp, _ := a.postJSON("/api/try-passwords/"+url.QueryEscape(c.ID), map[string]string{})
			success := false
			if resp != nil {
				var result struct {
					Success bool `json:"success"`
				}
				json.NewDecoder(resp.Body).Decode(&result)
				resp.Body.Close()
				success = result.Success
			}
			a.queue(func() {
				if success {
					a.openReader(c.ID, displayTitleOf(c), 0)
				} else {
					a.showPasswordScreen(c.ID, c.Filename)
				}
			})
		}()
		return
	}
	a.openReader(c.ID, displayTitleOf(c), 0)
}

// ── Upload ───────────────────────────────────────────────────────────────

func (a *App) showUploadPicker() {
	go func() {
		file, err := a.explorer.ChooseFile("cbz", "cbt", "cb7", "cbr", "epub")
		if err != nil {
			a.queue(func() { a.uploadErr = err.Error() })
			return
		}
		defer file.Close()
		name := "upload"
		if named, ok := file.(interface{ Name() string }); ok {
			name = filepath.Base(named.Name())
		}
		a.queue(func() {
			a.uploading = true
			a.uploadErr = ""
		})
		err = a.uploadFile(file, name)
		a.queue(func() {
			a.uploading = false
			if err != nil {
				a.uploadErr = err.Error()
				return
			}
			a.fetchLibrary()
		})
	}()
}

func (a *App) uploadFile(src io.Reader, name string) error {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	errCh := make(chan error, 1)
	go func() {
		part, err := mw.CreateFormFile("file", name)
		if err != nil {
			pw.CloseWithError(err)
			errCh <- err
			return
		}
		if _, err = io.Copy(part, src); err != nil {
			pw.CloseWithError(err)
			errCh <- err
			return
		}
		errCh <- mw.Close()
		pw.Close()
	}()

	req, err := http.NewRequest(http.MethodPost, a.baseURL+"/api/upload", pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if c := getSessionCookie(); c != "" {
		req.Header.Set("Cookie", c)
	}
	resp, err := http.DefaultClient.Do(req)
	if writeErr := <-errCh; writeErr != nil {
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

// ── Password unlock screen ──────────────────────────────────────────────

func (a *App) showPasswordScreen(comicID, comicName string) {
	a.pendingComicID = comicID
	a.pendingComicName = comicName
	a.pwEd = widget.Editor{SingleLine: true, Submit: true}
	a.pwErr = ""
	a.pwShow.Value = false
	a.mode = modeUnlock
}

func (a *App) unlockLayout(gtx C) D {
	th := a.theme

	for {
		ev, ok := a.pwEd.Update(gtx)
		if !ok {
			break
		}
		if _, ok := ev.(widget.SubmitEvent); ok {
			a.submitPassword()
		}
	}
	if a.pwShow.Update(gtx) {
		// toggled — Mask is applied below from current value
	}
	if a.pwUnlockBtn.Clicked(gtx) {
		a.submitPassword()
	}
	if a.pwCancelBtn.Clicked(gtx) {
		a.mode = modeLibrary
	}
	if !a.pwShow.Value {
		a.pwEd.Mask = '•'
	} else {
		a.pwEd.Mask = 0
	}

	content := []layout.Widget{
		material.H5(th, "🔒 Password Required").Layout,
		spacer(8),
		material.Body1(th, "Comic: "+a.pendingComicName).Layout,
		spacer(8),
		material.Editor(th, &a.pwEd, "Password").Layout,
		spacer(4),
		material.Body2(th, fmt.Sprintf("%d characters", len([]rune(a.pwEd.Text())))).Layout,
		spacer(4),
		material.CheckBox(th, &a.pwShow, "Show password").Layout,
		spacer(8),
		errorLabel(th, a.pwErr),
		spacer(8),
		func(gtx C) D {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(material.Button(th, &a.pwUnlockBtn, "Unlock").Layout),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Rigid(material.Button(th, &a.pwCancelBtn, "Cancel").Layout),
			)
		},
	}
	children := make([]layout.FlexChild, len(content))
	for i, w := range content {
		children[i] = layout.Rigid(w)
	}
	return layout.Center.Layout(gtx, func(gtx C) D {
		gtx.Constraints.Min.X = gtx.Dp(unit.Dp(440))
		gtx.Constraints.Max.X = gtx.Dp(unit.Dp(440))
		return layout.UniformInset(unit.Dp(24)).Layout(gtx, func(gtx C) D {
			return filledCard(gtx, unit.Dp(8), rgb(0x252836), func(gtx C) D {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
			})
		})
	})
}

func (a *App) submitPassword() {
	comicID, comicName, pw := a.pendingComicID, a.pendingComicName, a.pwEd.Text()
	go func() {
		resp, err := a.postJSON("/api/set-password/"+url.QueryEscape(comicID), map[string]string{"password": pw})
		a.queue(func() {
			if err != nil {
				a.pwErr = "Network error"
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				a.pwErr = ""
				a.openReader(comicID, comicName, 0)
			} else {
				data, _ := io.ReadAll(resp.Body)
				a.pwErr = "Unlock failed: " + strings.TrimSpace(string(data))
			}
		})
	}()
}

func alphaCheck() { _ = strconv.Itoa(0) } // keeps strconv imported until reader.go lands
