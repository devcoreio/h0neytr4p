package h0neytr4p

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(fb); err != nil {
		return nil, fmt.Errorf("parse fallback %s: %w", path, err)
	}
	if err := validateFallbackResponse("Unmatched", fb.Unmatched); err != nil {
		return nil, fmt.Errorf("fallback %s: %w", path, err)
	}
	if err := validateFallbackResponse("TooLarge", fb.TooLarge); err != nil {
		return nil, fmt.Errorf("fallback %s: %w", path, err)
	}
	SetFallback(fb)
	return fb, nil
}

// validateFallbackResponse fails fast on mistakes that would otherwise turn
// every unmatched request into a Go-flavoured 500 or an empty 200 at runtime.
func validateFallbackResponse(name string, resp Response) error {
	if resp.Statuscode == 0 {
		return fmt.Errorf("%s: StatusCode is missing or 0", name)
	}
	if resp.Type == "file" {
		if _, err := os.Stat(resp.Body); err != nil {
			return fmt.Errorf("%s: body file: %w", name, err)
		}
	}
	for key := range convertMap(resp.Headers) {
		if strings.EqualFold(key, "Content-Type") {
			return nil
		}
	}
	return fmt.Errorf("%s: Headers must set Content-Type explicitly (Go would sniff one)", name)
}

// SetFallback installs (or, with nil, removes) the package fallback.
func SetFallback(f *Fallback) {
	fallback = f
}
