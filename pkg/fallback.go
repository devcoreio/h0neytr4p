package h0neytr4p

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Fallback holds the response served when no trap matches (Unmatched). It lets
// the honeypot keep one consistent server persona on every path instead of
// Go's empty 200.
type Fallback struct {
	Unmatched Response `json:"Unmatched"`
	Timing    Timing   `json:"Timing"`
}

// Timing shapes how long PHP-generated responses (those carrying
// X-Powered-By) take, in milliseconds: on a real Apache + PHP host a static
// 404 answers in ~0.4 ms, a PHP page in ~5-7 ms, and a PHP page receiving a
// multipart upload pays extra while PHP parses the body before the script
// runs. All fields are optional; zero turns the delay off.
type Timing struct {
	PhpBaseMs   float64 `json:"PhpBaseMs"`
	PhpJitterMs float64 `json:"PhpJitterMs"`
	PhpPerMBMs  float64 `json:"PhpPerMBMs"`
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
	if err := validateTiming(fb.Timing); err != nil {
		return nil, fmt.Errorf("fallback %s: Timing: %w", path, err)
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

// validateTiming rejects negative values and a jitter wider than the base,
// which could drive the PHP delay below zero (a PHP page faster than Apache's
// static 404).
func validateTiming(t Timing) error {
	if t.PhpBaseMs < 0 || t.PhpJitterMs < 0 || t.PhpPerMBMs < 0 {
		return fmt.Errorf("values must not be negative (%+v)", t)
	}
	if t.PhpJitterMs > t.PhpBaseMs {
		return fmt.Errorf("PhpJitterMs %v exceeds PhpBaseMs %v", t.PhpJitterMs, t.PhpBaseMs)
	}
	return nil
}

// currentTiming returns the loaded fallback's Timing (zero, i.e. no delay,
// when no fallback is installed).
func currentTiming() Timing {
	if fallback == nil {
		return Timing{}
	}
	return fallback.Timing
}

// SetFallback installs (or, with nil, removes) the package fallback.
func SetFallback(f *Fallback) {
	fallback = f
}
