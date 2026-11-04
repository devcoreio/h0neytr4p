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
	Unmatched Response      `json:"Unmatched"`
	Timing    Timing        `json:"Timing"`
	Methods   *MethodPolicy `json:"Methods,omitempty"`
}

// MethodPolicy is how Apache answers a method no trap matched. mod_php runs
// any verb but TRACE on a PHP path (handled by the relaxed trap pass); on a
// non-PHP path Apache's default handler judges the verb before the file:
// a verb it never registered gets NotImplemented (501), TRACE gets Trace
// (405, empty Allow), OPTIONS gets Options (200, Allow, empty body) and any
// other registered verb it will not serve gets NotAllowed (405, Allow).
// Registered overrides Apache 2.4's built-in registry; GET, HEAD, POST,
// OPTIONS and TRACE always count as registered.
type MethodPolicy struct {
	Registered     []string `json:"Registered,omitempty"`
	NotImplemented Response `json:"NotImplemented"`
	NotAllowed     Response `json:"NotAllowed"`
	Trace          Response `json:"Trace"`
	Options        Response `json:"Options"`
	// ContentTypes maps a path extension (".ico") to the Content-Type Apache
	// puts on an OPTIONS answer for a path with no trap; a trap's own
	// Content-Type wins, Go's MIME table is the last resort.
	ContentTypes map[string]string `json:"ContentTypes,omitempty"`
}

// apacheRegisteredMethods is Apache 2.4's built-in method registry
// (server/core.c ap_method_registry_init), the verbs that get 405 rather
// than 501 when a handler will not serve them.
var apacheRegisteredMethods = []string{
	"GET", "PUT", "POST", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
	"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
	"VERSION-CONTROL", "CHECKOUT", "UNCHECKOUT", "CHECKIN", "UPDATE", "LABEL",
	"REPORT", "MKWORKSPACE", "MKACTIVITY", "BASELINE-CONTROL", "MERGE",
}

// isRegistered reports whether Apache knows the verb (case-sensitive, as
// Apache's lookup is).
func (p *MethodPolicy) isRegistered(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "OPTIONS", "TRACE":
		return true
	}
	list := p.Registered
	if len(list) == 0 {
		list = apacheRegisteredMethods
	}
	for _, m := range list {
		if m == method {
			return true
		}
	}
	return false
}

// currentMethods returns the loaded fallback's method policy, or nil when
// there is no fallback or it has no Methods section (legacy behaviour).
func currentMethods() *MethodPolicy {
	if fallback == nil {
		return nil
	}
	return fallback.Methods
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
	if err := validateMethods(fb.Methods); err != nil {
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

// validateMethods checks every response of a Methods section the way the
// Unmatched response is checked, except Options, whose empty body needs no
// Content-Type (Apache sets one from the path's type, or none).
func validateMethods(p *MethodPolicy) error {
	if p == nil {
		return nil
	}
	for name, resp := range map[string]Response{
		"Methods.NotImplemented": p.NotImplemented,
		"Methods.NotAllowed":     p.NotAllowed,
		"Methods.Trace":          p.Trace,
	} {
		if err := validateFallbackResponse(name, resp); err != nil {
			return err
		}
	}
	if p.Options.Statuscode == 0 {
		return fmt.Errorf("Methods.Options: StatusCode is missing or 0")
	}
	return nil
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
