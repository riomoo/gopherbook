//go:build desktop

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"gioui.org/io/key"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

func (a *App) openReader(comicID, title string, startPage int) {
	go func() {
		resp, err := a.get("/api/pages/" + url.QueryEscape(comicID))
		var res struct {
			PageCount int  `json:"page_count"`
			NeedsPwd  bool `json:"needs_password"`
		}
		var failMsg string
		if err != nil {
			failMsg = err.Error()
		} else {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				failMsg = fmt.Sprintf("Server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
			} else if json.Unmarshal(raw, &res) != nil {
				failMsg = "Unreadable response from server"
			} else if !res.NeedsPwd && res.PageCount == 0 {
				failMsg = "This comic has no readable pages (wrong password, or an unsupported archive)."
			}
		}
		a.queue(func() {
			if failMsg != "" {
				a.uploadErr = failMsg // reuse the library's error line; simplest surface for this
				a.mode = modeLibrary
				return
			}
			if res.NeedsPwd {
				a.showPasswordScreen(comicID, title)
				return
			}
			a.comicID = comicID
			a.comicTitle = title
			a.pageIdx = startPage
			a.pageCount = res.PageCount
			a.zoomFactor = 1.0
			a.panOffX, a.panOffY = 0, 0
			a.pendingPanFocus = true // let arrow/HJKL panning work immediately, no click needed first
			a.showBookmarks = false
			a.bookmarks = nil
			for _, c := range a.allComics {
				if c.ID == comicID {
					a.bookmarks = c.Bookmarks
					break
				}
			}
			a.pageJumpEd = widget.Editor{SingleLine: true, Submit: true}
			a.bookmarkJumpBtns = make(map[int]*widget.Clickable)
			a.mode = modeReader
		})
	}()
}

func (a *App) refreshBookmarks() {
	comicID := a.comicID
	go func() {
		resp, err := a.get("/api/comics")
		if err != nil {
			return
		}
		var cl []ComicJSON
		json.NewDecoder(resp.Body).Decode(&cl)
		resp.Body.Close()
		a.queue(func() {
			a.allComics = cl
			for _, c := range cl {
				if c.ID == comicID {
					a.bookmarks = c.Bookmarks
				}
			}
		})
	}()
}

func (a *App) toggleBookmark(isBookmarked bool) {
	comicID, page := a.comicID, a.pageIdx
	go func() {
		if isBookmarked {
			if resp, _ := a.deleteReq(fmt.Sprintf("/api/bookmark/%s/%d", url.QueryEscape(comicID), page)); resp != nil {
				resp.Body.Close()
			}
		} else {
			if resp, _ := a.postJSON("/api/bookmark/"+url.QueryEscape(comicID), map[string]int{"page": page}); resp != nil {
				resp.Body.Close()
			}
		}
		a.queue(func() { a.refreshBookmarks() })
	}()
}

func (a *App) goToPage(p int) {
	if p < 0 {
		p = 0
	}
	if p >= a.pageCount {
		p = a.pageCount - 1
	}
	a.pageIdx = p
	a.panOffX, a.panOffY = 0, 0 // a new page is a new image; don't carry over the old one's pan position
}

func (a *App) zoomIn() {
	if a.zoomFactor < 4 {
		a.zoomFactor += 0.15
	}
}

func (a *App) zoomOut() {
	if a.zoomFactor > 0.3 {
		a.zoomFactor -= 0.15
	}
}

// handleReaderKeys processes the reader's keyboard shortcuts while the
// page area has focus (it gets focus when a comic opens and whenever
// the page is clicked):
//
//	H / ←  pan left        Shift+H / Shift+←  previous page
//	L / →  pan right       Shift+L / Shift+→  next page
//	K / ↑  pan up          Shift+K / Shift+↑  zoom in
//	J / ↓  pan down        Shift+J / Shift+↓  zoom out
//	+      zoom in         -                  zoom out
//	=      reset zoom to 100% (and pan back to the top-left)
//
// It runs at the top of readerLayout, before the page URL is built, so
// a page turn takes effect in the same frame. Pan offsets are only
// floored at 0 here; readerPageView clamps the upper bound against the
// real rendered image size later in the same frame.
func (a *App) handleReaderKeys(gtx C) {
	f := &a.panFocus
	panStep := gtx.Dp(unit.Dp(60))

	// +, - and = are matched on the CHARACTER typed (key.EditEvent), not
	// the key name: on Windows Gio names the "=/+" key "+" whether or
	// not Shift is held, so "=" can't be told apart by name. The typed
	// text is the same on every OS and keyboard layout, and covers the
	// numpad + and - too. Reading key.FocusFilter here is also what
	// keeps the page focusable (readerPageView reads it as well).
	for {
		e, ok := gtx.Source.Event(key.FocusFilter{Target: f})
		if !ok {
			break
		}
		ee, ok := e.(key.EditEvent)
		if !ok {
			continue
		}
		for _, r := range ee.Text {
			switch r {
			case '+':
				a.zoomIn()
			case '-':
				a.zoomOut()
			case '=':
				a.zoomFactor = 1
				a.panOffX, a.panOffY = 0, 0
			}
		}
	}

	for {
		e, ok := gtx.Source.Event(
			key.Filter{Focus: f, Name: key.NameLeftArrow, Optional: key.ModShift},
			key.Filter{Focus: f, Name: key.NameRightArrow, Optional: key.ModShift},
			key.Filter{Focus: f, Name: key.NameUpArrow, Optional: key.ModShift},
			key.Filter{Focus: f, Name: key.NameDownArrow, Optional: key.ModShift},
			key.Filter{Focus: f, Name: "H", Optional: key.ModShift},
			key.Filter{Focus: f, Name: "J", Optional: key.ModShift},
			key.Filter{Focus: f, Name: "K", Optional: key.ModShift},
			key.Filter{Focus: f, Name: "L", Optional: key.ModShift},
		)
		if !ok {
			break
		}
		ke, ok := e.(key.Event)
		if !ok || ke.State != key.Press {
			continue
		}
		shift := ke.Modifiers.Contain(key.ModShift)
		switch ke.Name {
		case key.NameLeftArrow, "H":
			if shift {
				a.goToPage(a.pageIdx - 1)
			} else {
				a.panOffX -= panStep
			}
		case key.NameRightArrow, "L":
			if shift {
				a.goToPage(a.pageIdx + 1)
			} else {
				a.panOffX += panStep
			}
		case key.NameUpArrow, "K":
			if shift {
				a.zoomIn()
			} else {
				a.panOffY -= panStep
			}
		case key.NameDownArrow, "J":
			if shift {
				a.zoomOut()
			} else {
				a.panOffY += panStep
			}
		}
		if a.panOffX < 0 {
			a.panOffX = 0
		}
		if a.panOffY < 0 {
			a.panOffY = 0
		}
	}
}

func (a *App) readerLayout(gtx C) D {
	th := a.theme

	if a.readerBackBtn.Clicked(gtx) {
		a.mode = modeLibrary
		a.fetchLibrary()
	}
	if a.readerFirstBtn.Clicked(gtx) {
		a.goToPage(0)
	}
	if a.readerPrevBtn.Clicked(gtx) {
		a.goToPage(a.pageIdx - 1)
	}
	if a.readerNextBtn.Clicked(gtx) {
		a.goToPage(a.pageIdx + 1)
	}
	if a.readerLastBtn.Clicked(gtx) {
		a.goToPage(a.pageCount - 1)
	}
	if a.fitWBtn.Clicked(gtx) {
		a.fitMode = "width"
		a.zoomFactor = 1
		a.panOffX, a.panOffY = 0, 0
	}
	if a.fitHBtn.Clicked(gtx) {
		a.fitMode = "height"
		a.zoomFactor = 1
		a.panOffX, a.panOffY = 0, 0
	}
	if a.zoomOutBtn.Clicked(gtx) {
		a.zoomOut()
	}
	if a.zoomInBtn.Clicked(gtx) {
		a.zoomIn()
	}
	a.handleReaderKeys(gtx)
	isBookmarked := false
	for _, b := range a.bookmarks {
		if b == a.pageIdx {
			isBookmarked = true
			break
		}
	}
	if a.bmToggleBtn.Clicked(gtx) {
		a.toggleBookmark(isBookmarked)
	}
	if a.bmListBtn.Clicked(gtx) {
		a.showBookmarks = !a.showBookmarks
	}
	for {
		ev, ok := a.pageJumpEd.Update(gtx)
		if !ok {
			break
		}
		if _, ok := ev.(widget.SubmitEvent); ok {
			if n, err := strconv.Atoi(a.pageJumpEd.Text()); err == nil {
				a.goToPage(n - 1)
			}
			// Hand focus back to the page so the keyboard shortcuts
			// work again without having to click the page first.
			a.pendingPanFocus = true
		}
	}

	bmLabel := "Bookmark"
	if isBookmarked {
		bmLabel = "Bookmarked ✓"
	}

	toolbarItems := []layout.Widget{
		material.Button(th, &a.readerBackBtn, "← Library").Layout,
		material.Button(th, &a.readerFirstBtn, "|<").Layout,
		material.Button(th, &a.readerPrevBtn, "<").Layout,
		material.Body1(th, fmt.Sprintf("Page %d / %d", a.pageIdx+1, a.pageCount)).Layout,
		material.Button(th, &a.readerNextBtn, ">").Layout,
		material.Button(th, &a.readerLastBtn, ">|").Layout,
		func(gtx C) D {
			gtx.Constraints.Max.X = gtx.Dp(unit.Dp(80))
			return material.Editor(th, &a.pageJumpEd, "Go to…").Layout(gtx)
		},
		fitButton(th, &a.fitWBtn, "Fit Width", a.fitMode == "width"),
		fitButton(th, &a.fitHBtn, "Fit Height", a.fitMode == "height"),
		material.Button(th, &a.zoomOutBtn, "−").Layout,
		material.Body1(th, fmt.Sprintf("%d%%", int(a.zoomFactor*100))).Layout,
		material.Button(th, &a.zoomInBtn, "+").Layout,
		fitButton(th, &a.bmToggleBtn, bmLabel, isBookmarked),
		material.Button(th, &a.bmListBtn, fmt.Sprintf("Bookmarks (%d)", len(a.bookmarks))).Layout,
	}
	toolbar := func(gtx C) D {
		list := &widget.List{List: layout.List{Axis: layout.Horizontal}}
		return list.Layout(gtx, len(toolbarItems), func(gtx C, i int) D {
			return layout.Inset{Right: unit.Dp(6)}.Layout(gtx, toolbarItems[i])
		})
	}

	pageURL := fmt.Sprintf("%s/api/comic/%s/page/%d", globalBaseURL, url.QueryEscape(a.comicID), a.pageIdx)
	pageArea := func(gtx C) D {
		return a.readerPageView(gtx, pageURL)
	}

	main := layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(material.H6(th, a.comicTitle).Layout),
		layout.Rigid(toolbar),
		layout.Flexed(1, func(gtx C) D {
			if !a.showBookmarks {
				return pageArea(gtx)
			}
			if a.bookmarkJumpBtns == nil {
				a.bookmarkJumpBtns = make(map[int]*widget.Clickable)
			}
			for _, b := range a.bookmarks {
				if a.bookmarkJumpBtns[b] == nil {
					a.bookmarkJumpBtns[b] = new(widget.Clickable)
				}
				if a.bookmarkJumpBtns[b].Clicked(gtx) {
					a.goToPage(b)
				}
			}
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Flexed(1, pageArea),
				layout.Rigid(func(gtx C) D {
					gtx.Constraints.Min.X = gtx.Dp(unit.Dp(180))
					gtx.Constraints.Max.X = gtx.Dp(unit.Dp(180))
					items := make([]layout.FlexChild, 0, len(a.bookmarks)+1)
					items = append(items, layout.Rigid(material.Body1(th, "Bookmarks").Layout))
					if len(a.bookmarks) == 0 {
						items = append(items, layout.Rigid(material.Body2(th, "No bookmarks").Layout))
					}
					for _, b := range a.bookmarks {
						items = append(items, layout.Rigid(material.Button(th, a.bookmarkJumpBtns[b], fmt.Sprintf("Page %d", b+1)).Layout))
					}
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, items...)
				}),
			)
		}),
	)
	return main
}

func fitButton(th *material.Theme, click *widget.Clickable, label string, active bool) layout.Widget {
	return func(gtx C) D {
		btn := material.Button(th, click, label)
		if !active {
			btn.Background = th.Palette.Bg
			btn.Color = th.Palette.Fg
		}
		return btn.Layout(gtx)
	}
}
