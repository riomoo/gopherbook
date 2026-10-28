package main

// JPEG 2000 support (.jp2 / .j2k / .jpf / .jpx pages).
//
// Decoding uses seehuhn.de/go/jpx, a pure-Go JPEG 2000 decoder (BSD-3). In
// testing it matched OpenJPEG, the reference decoder, to within one 8-bit
// level on lossless, lossy, tiled, layered, precinct and every progression
// order file, and bit-exactly on lossless and 16-bit pages.
//
// This file registers JPEG 2000 with Go's image package, so image.Decode
// (and decodeImage, covers, the desktop reader) read it like any other
// format. No browser displays JPEG 2000 any more, so writePage
// (jxl_support.go) converts these pages to PNG for the web reader.

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"runtime"

	"seehuhn.de/go/jpx"
	"seehuhn.de/go/membudget"
)

// jp2Budget bounds what one decode may allocate and work through. go-jpx
// charges every input-dependent allocation and one unit per coefficient per
// coding pass, so this also caps CPU time for a hostile file. A 2000x3000
// lossless colour page uses well under a tenth of it.
const jp2Budget = 8 << 30

const (
	jp2Signature = "\x00\x00\x00\x0cjP  \r\n\x87\n" // JP2/JPX file
	j2kSignature = "\xff\x4f\xff\x51"               // raw codestream (SOC + SIZ)
)

func init() {
	image.RegisterFormat("jp2", jp2Signature, decodeJP2, decodeJP2Config)
	image.RegisterFormat("j2k", j2kSignature, decodeJP2, decodeJP2Config)
}

// isJP2 reports whether data is a JPEG 2000 file or codestream.
func isJP2(data []byte) bool {
	return bytes.HasPrefix(data, []byte(jp2Signature)) || bytes.HasPrefix(data, []byte(j2kSignature))
}

// Enumerated colour spaces (ISO/IEC 15444-1 Annex I) we act on.
const (
	jp2CMYK = 12
	jp2SRGB = 16
	jp2Gray = 17
	jp2SYCC = 18
)

func decodeJP2(r io.Reader) (image.Image, error) {
	budget := membudget.New(jp2Budget)
	img, err := jpx.Decode(r, &jpx.Options{Budget: budget, Workers: runtime.GOMAXPROCS(0)})
	if err != nil {
		return nil, err
	}
	if img, err = jpx.ApplyPalette(img, budget); err != nil {
		return nil, err
	}
	if img, err = jpx.Upsample(img, budget); err != nil {
		return nil, err
	}

	space := 0
	for _, cs := range img.ColorSpecs {
		if cs.Method == 1 {
			space = cs.Enumerated
			break
		}
	}
	if space == jp2SYCC && len(img.Planes) >= 3 {
		if err := jpx.SYCCToRGB(img); err != nil {
			return nil, err
		}
	}

	bits := 8
	for _, c := range img.Components {
		if c.Depth-c.Truncation > 8 {
			bits = 16
		}
	}
	if img, err = jpx.ToUnsigned(img, bits, budget); err != nil {
		return nil, err
	}
	return jp2ToImage(img, space, bits)
}

// jp2ToImage assembles the decoded planes into a Go image: grey, grey with
// alpha, RGB, RGB with alpha, or CMYK converted to RGB.
func jp2ToImage(img *jpx.Image, space, bits int) (image.Image, error) {
	n := len(img.Planes)
	if n == 0 {
		return nil, errors.New("jpeg2000: no components")
	}
	w, h := img.Planes[0].Width, img.Planes[0].Height
	for _, p := range img.Planes {
		if p.Width != w || p.Height != h {
			return nil, errors.New("jpeg2000: components differ in size")
		}
	}

	// Which planes are colour and which (if any) is alpha. Without a
	// channel definition box, a trailing extra plane is alpha.
	var colour []int
	alpha, premult := -1, false
	if len(img.Channels) == n {
		for i, c := range img.Channels {
			switch c.Kind {
			case jpx.ChannelOpacity, jpx.ChannelPremultipliedOpacity:
				if alpha < 0 {
					alpha, premult = i, c.Kind == jpx.ChannelPremultipliedOpacity
				}
			case jpx.ChannelColor:
				colour = append(colour, i)
			}
		}
	} else {
		for i := range n {
			colour = append(colour, i)
		}
		want := 3
		if space == jp2Gray || n == 1 || n == 2 {
			want = 1
		} else if space == jp2CMYK {
			want = 4
		}
		if len(colour) > want {
			alpha = colour[want]
			colour = colour[:want]
		}
	}
	if len(colour) == 0 {
		return nil, errors.New("jpeg2000: no colour channels")
	}

	maxV := float64(int(1)<<bits - 1)
	at := func(c, i int) float64 { return float64(img.Planes[c].Pix[i]) / maxV } // 0..1
	rect := image.Rect(0, 0, w, h)

	// Greyscale without alpha keeps its own image type.
	if len(colour) < 3 && alpha < 0 {
		if bits == 8 {
			g := image.NewGray(rect)
			for i := range g.Pix {
				g.Pix[i] = uint8(img.Planes[colour[0]].Pix[i])
			}
			return g, nil
		}
		g := image.NewGray16(rect)
		for i := range w * h {
			v := uint16(img.Planes[colour[0]].Pix[i])
			g.Pix[2*i], g.Pix[2*i+1] = byte(v>>8), byte(v)
		}
		return g, nil
	}

	// The common case, 8-bit RGB without alpha: copy straight across.
	if bits == 8 && len(colour) == 3 && alpha < 0 {
		out := image.NewNRGBA(rect)
		R, G, B := img.Planes[colour[0]].Pix, img.Planes[colour[1]].Pix, img.Planes[colour[2]].Pix
		for i := range w * h {
			p := out.Pix[4*i : 4*i+4 : 4*i+4]
			p[0], p[1], p[2], p[3] = uint8(R[i]), uint8(G[i]), uint8(B[i]), 0xff
		}
		return out, nil
	}

	out := image.NewNRGBA64(rect)
	for i := range w * h {
		var r, g, b float64
		switch {
		case len(colour) >= 4 && space == jp2CMYK:
			c, m, y, k := at(colour[0], i), at(colour[1], i), at(colour[2], i), at(colour[3], i)
			r, g, b = (1-c)*(1-k), (1-m)*(1-k), (1-y)*(1-k)
		case len(colour) >= 3:
			r, g, b = at(colour[0], i), at(colour[1], i), at(colour[2], i)
		default:
			r = at(colour[0], i)
			g, b = r, r
		}
		a := 1.0
		if alpha >= 0 {
			a = at(alpha, i)
			if premult && a > 0 { // un-premultiply for NRGBA64
				r, g, b = min(r/a, 1), min(g/a, 1), min(b/a, 1)
			}
		}
		out.SetNRGBA64(i%w, i/w, color.NRGBA64{
			R: uint16(r*65535 + 0.5), G: uint16(g*65535 + 0.5),
			B: uint16(b*65535 + 0.5), A: uint16(a*65535 + 0.5),
		})
	}
	if bits == 8 { // keep 8-bit pages 8-bit: half the memory, same pixels
		return toNRGBA8(out), nil
	}
	return out, nil
}

func toNRGBA8(m *image.NRGBA64) *image.NRGBA {
	out := image.NewNRGBA(m.Rect)
	for i := 0; i < len(out.Pix); i++ {
		out.Pix[i] = m.Pix[2*i] // high byte; exact for values scaled from 8 bits
	}
	return out
}

func decodeJP2Config(r io.Reader) (image.Config, error) {
	hdr, err := jpx.ReadHeader(r, membudget.New(64<<20))
	if err != nil {
		return image.Config{}, err
	}
	if hdr.Width <= 0 || hdr.Height <= 0 {
		return image.Config{}, fmt.Errorf("jpeg2000: bad size %dx%d", hdr.Width, hdr.Height)
	}
	var model color.Model = color.NRGBAModel
	if len(hdr.Components) == 1 {
		model = color.GrayModel
	}
	return image.Config{ColorModel: model, Width: hdr.Width, Height: hdr.Height}, nil
}
