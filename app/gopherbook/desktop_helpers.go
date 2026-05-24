//go:build desktop

package main

import (
	"encoding/json"
	"io"
)

// jsonDecoder returns a *json.Decoder for the given reader.
func jsonDecoder(r io.Reader) *json.Decoder {
	return json.NewDecoder(r)
}
