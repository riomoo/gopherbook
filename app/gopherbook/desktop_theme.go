//go:build desktop

package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// ── Gopherbook color palette ─────────────────────────────────────────────────
// Taken directly from the original HTML/CSS.
var (
	colorBG       = color.NRGBA{R: 0x1b, G: 0x1e, B: 0x2c, A: 0xff} // #1b1e2c  body background
	colorHeader   = color.NRGBA{R: 0x39, G: 0x5e, B: 0x62, A: 0xff} // #395E62  teal header/buttons
	colorAccent   = color.NRGBA{R: 0x44, G: 0x6b, B: 0x6e, A: 0xff} // #446B6E  hover / accent
	colorAccentLt = color.NRGBA{R: 0x64, G: 0xa9, B: 0xad, A: 0xff} // #64A9AD  active/highlight
	colorText     = color.NRGBA{R: 0xbf, G: 0xbc, B: 0xb7, A: 0xff} // #bfbcb7  body text
	colorSubText  = color.NRGBA{R: 0x8b, G: 0x94, B: 0x9e, A: 0xff} // #8b949e  dim text
	colorCard     = color.NRGBA{R: 0x25, G: 0x28, B: 0x36, A: 0xff} // #252836  card bg
	colorBorder   = color.NRGBA{R: 0x31, G: 0x4c, B: 0x52, A: 0xff} // #314C52  border/divider
	colorError    = color.NRGBA{R: 0xa5, G: 0x53, B: 0x54, A: 0xff} // #A55354  error/danger
	colorBlack    = color.NRGBA{R: 0x11, G: 0x11, B: 0x11, A: 0xff} // reader bg
)

// GopherbookTheme implements fyne.Theme using the exact palette from index.html.
type GopherbookTheme struct{}

func NewGopherbookTheme() fyne.Theme { return &GopherbookTheme{} }

var _ fyne.Theme = (*GopherbookTheme)(nil)

func (t *GopherbookTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return colorBG
	case theme.ColorNameForeground:
		return colorText
	case theme.ColorNameButton:
		return colorHeader
	case theme.ColorNameHover: // Fyne 2.4/2.5: ColorNameHover (not Hovered)
		return colorAccent
	case theme.ColorNameFocus:
		return colorAccent
	case theme.ColorNamePlaceHolder:
		return colorSubText
	case theme.ColorNameDisabled:
		return colorSubText
	case theme.ColorNameDisabledButton:
		return colorBorder
	case theme.ColorNamePrimary:
		return colorHeader
	case theme.ColorNameError:
		return colorError
	case theme.ColorNameInputBackground:
		return colorBG
	case theme.ColorNameInputBorder:
		return colorAccent
	case theme.ColorNameMenuBackground:
		return colorCard
	case theme.ColorNameOverlayBackground:
		return colorCard
	case theme.ColorNameScrollBar:
		return colorBorder
	case theme.ColorNameShadow:
		return color.NRGBA{A: 0x88}
	case theme.ColorNameSelection:
		return colorAccentLt
	case theme.ColorNameHeaderBackground:
		return colorHeader
	case theme.ColorNameSeparator:
		return colorBorder
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (t *GopherbookTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *GopherbookTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *GopherbookTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 4
	case theme.SizeNameText:
		return 13
	case theme.SizeNameHeadingText:
		return 18
	case theme.SizeNameSubHeadingText:
		return 15
	case theme.SizeNameCaptionText:
		return 11
	case theme.SizeNameInputBorder:
		return 1.5
	case theme.SizeNameScrollBar:
		return 6
	case theme.SizeNameScrollBarSmall:
		return 3
	default:
		return theme.DefaultTheme().Size(name)
	}
}
