package h0neytr4p

import (
	"encoding/json"
	"fmt"
	"os"
)

// Fallback holds the responses served when no trap matches (Unmatched) and
// when a payload exceeds the size limits (TooLarge). It lets the honeypot keep
// one consistent server persona on every path instead of Go's empty 200 and
// plain-text 413.
type Fallback struct {
	Unmatched Response `json:"Unmatched"`
	TooLarge  Response `json:"TooLarge"`
}

var fallback *Fallback

// LoadFallback reads a Fallback JSON file and installs it as the package
// fallback. An empty path disables the fallback (legacy behaviour).
func LoadFallback(path string) (*Fallback, error) {
	if path == "" {
		SetFallback(nil)
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fallback %s: %w", path, err)
	}
	fb := &Fallback{}
	if err := json.Unmarshal(data, fb); err != nil {
		return nil, fmt.Errorf("parse fallback %s: %w", path, err)
	}
	SetFallback(fb)
	return fb, nil
}

// SetFallback installs (or, with nil, removes) the package fallback.
func SetFallback(f *Fallback) {
	fallback = f
}
