package h0neytr4p

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFallback() *Fallback {
	headers := map[string]interface{}{"Server": "Apache/2.4.58 (Ubuntu)", "Content-Type": "text/html; charset=iso-8859-1"}
	return &Fallback{
		Unmatched: Response{Statuscode: http.StatusNotFound, Body: "<h1>Not Found</h1>", Headers: headers, Type: "string"},
	}
}

func TestLoadFallbackParsesUnmatchedResponse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fallback.json")
	content := `{
  "Unmatched": {"StatusCode": 404, "Body": "<h1>Not Found</h1>", "Type": "string",
                "Headers": {"Server": "Apache/2.4.58 (Ubuntu)", "Content-Type": "text/html"}}
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { SetFallback(nil) })

	fb, err := LoadFallback(path)
	if err != nil {
		t.Fatalf("LoadFallback() error = %v", err)
	}
	if fb.Unmatched.Statuscode != 404 || fb.Unmatched.Body != "<h1>Not Found</h1>" || fb.Unmatched.Type != "string" {
		t.Fatalf("Unmatched parsed wrong: %+v", fb.Unmatched)
	}
	if got := convertMap(fb.Unmatched.Headers)["Server"]; got != "Apache/2.4.58 (Ubuntu)" {
		t.Fatalf("Unmatched Server header = %q", got)
	}
	if fallback != fb {
		t.Fatal("LoadFallback did not set the package fallback")
	}
}

func TestLoadFallbackEmptyPathDisables(t *testing.T) {
	SetFallback(testFallback())
	fb, err := LoadFallback("")
	if err != nil || fb != nil || fallback != nil {
		t.Fatalf("LoadFallback(\"\") = %v, %v, package fallback %v; want nil, nil, nil", fb, err, fallback)
	}
}

func TestAllHandlerUnmatchedUsesFallback(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, "PROPFIND"} {
		t.Run(method, func(t *testing.T) {
			logPath, _ := configureTestIO(t)
			SetFallback(testFallback())
			t.Cleanup(func() { SetFallback(nil) })

			req := httptest.NewRequest(method, "/nope", nil)
			rec := httptest.NewRecorder()
			allHandler(nil, true).ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
			if rec.Header().Get("Server") == "" {
				t.Fatal("Server header missing on fallback response")
			}
			body := rec.Body.String()
			if method == http.MethodHead {
				if body != "" {
					t.Fatalf("HEAD body = %q, want empty", body)
				}
			} else if !strings.Contains(body, "Not Found") {
				t.Fatalf("body = %q, want Not Found page", body)
			}
			if !strings.Contains(readTestLog(t, logPath), `"trapped":"false"`) {
				t.Fatal("unmatched request was not logged as trapped=false")
			}
		})
	}
}

func TestAllHandlerUnmatchedWithoutFallbackIsLegacy(t *testing.T) {
	configureTestIO(t)
	SetFallback(nil)

	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rec := httptest.NewRecorder()
	allHandler(nil, true).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("legacy unmatched = %d %q, want empty 200", rec.Code, rec.Body.String())
	}
}

func writeFallbackFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fallback.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFallbackRejectsBadFiles(t *testing.T) {
	t.Cleanup(func() { SetFallback(nil) })
	ok := `"StatusCode": 404, "Body": "x", "Type": "string", "Headers": {"Content-Type": "text/html"}`
	cases := map[string]string{
		"missing body file":     `{"Unmatched": {"StatusCode": 404, "Body": "/nonexistent/404.html", "Type": "file", "Headers": {"Content-Type": "text/html"}}}`,
		"zero status":           `{"Unmatched": {"StatusCode": 0, "Body": "x", "Type": "string", "Headers": {"Content-Type": "text/html"}}}`,
		"no Content-Type":       `{"Unmatched": {"StatusCode": 404, "Body": "x", "Type": "string", "Headers": {"Server": "x"}}}`,
		"unknown top-level key": `{"Unmatch": {` + ok + `}}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadFallback(writeFallbackFile(t, content)); err == nil {
				t.Fatalf("LoadFallback accepted a fallback with %s", name)
			}
		})
	}
}

// timingFallbackFile writes a valid fallback with the given extra top-level
// JSON (e.g. a Timing block) and clears the package fallback after the test.
func timingFallbackFile(t *testing.T, extra string) string {
	t.Helper()
	t.Cleanup(func() { SetFallback(nil) })
	return writeFallbackFile(t, `{
  "Unmatched": {"StatusCode": 404, "Body": "<h1>Not Found</h1>", "Type": "string",
                "Headers": {"Content-Type": "text/html"}}`+extra+`
}`)
}

func TestLoadFallbackParsesTiming(t *testing.T) {
	path := timingFallbackFile(t, `,
  "Timing": {"PhpBaseMs": 6, "PhpJitterMs": 2, "PhpPerMBMs": 20}`)
	fb, err := LoadFallback(path)
	if err != nil {
		t.Fatalf("LoadFallback() error = %v", err)
	}
	if want := (Timing{PhpBaseMs: 6, PhpJitterMs: 2, PhpPerMBMs: 20}); fb.Timing != want {
		t.Fatalf("Timing = %+v, want %+v", fb.Timing, want)
	}
	if currentTiming() != fb.Timing {
		t.Fatalf("currentTiming() = %+v, want the loaded Timing", currentTiming())
	}
}

func TestLoadFallbackTimingOptional(t *testing.T) {
	fb, err := LoadFallback(timingFallbackFile(t, ""))
	if err != nil {
		t.Fatalf("LoadFallback() error = %v", err)
	}
	if fb.Timing != (Timing{}) {
		t.Fatalf("Timing = %+v, want zero", fb.Timing)
	}
	SetFallback(nil)
	if currentTiming() != (Timing{}) {
		t.Fatalf("currentTiming() with no fallback = %+v, want zero", currentTiming())
	}
}

func TestLoadFallbackRejectsBadTiming(t *testing.T) {
	for name, timing := range map[string]string{
		"negative base":     `{"PhpBaseMs": -1}`,
		"negative jitter":   `{"PhpBaseMs": 6, "PhpJitterMs": -1}`,
		"negative per-MB":   `{"PhpBaseMs": 6, "PhpPerMBMs": -1}`,
		"jitter above base": `{"PhpBaseMs": 6, "PhpJitterMs": 10}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFallback(timingFallbackFile(t, `,
  "Timing": `+timing))
			if err == nil || !strings.Contains(err.Error(), "Timing") {
				t.Fatalf("LoadFallback() error = %v, want a Timing error", err)
			}
			if fallback != nil {
				t.Fatal("invalid fallback was installed")
			}
		})
	}
}

// methodsFallbackFile writes a valid fallback whose Methods section is the
// given JSON object body and clears the package fallback after the test.
func methodsFallbackFile(t *testing.T, methods string) string {
	t.Helper()
	return timingFallbackFile(t, `,
  "Methods": `+methods)
}

const testMethodsJSON = `{
    "NotImplemented": {"StatusCode": 501, "Type": "string", "Body": "<p>{{req_method}} not supported for current URL.<br />",
                       "Headers": {"Content-Type": "text/html; charset=iso-8859-1", "Allow": "GET,POST,OPTIONS,HEAD", "Connection": "close"}},
    "NotAllowed":     {"StatusCode": 405, "Type": "string", "Body": "<p>The requested method {{req_method}} is not allowed for this URL.</p>",
                       "Headers": {"Content-Type": "text/html; charset=iso-8859-1", "Allow": "GET,POST,OPTIONS,HEAD"}},
    "Trace":          {"StatusCode": 405, "Type": "string", "Body": "<p>The requested method {{req_method}} is not allowed for this URL.</p>",
                       "Headers": {"Content-Type": "text/html; charset=iso-8859-1", "Allow": ""}},
    "Options":        {"StatusCode": 200, "Type": "string", "Body": "",
                       "Headers": {"Allow": "GET,POST,OPTIONS,HEAD", "Content-Length": "0"}}
  }`

func TestLoadFallbackParsesMethods(t *testing.T) {
	fb, err := LoadFallback(methodsFallbackFile(t, testMethodsJSON))
	if err != nil {
		t.Fatalf("LoadFallback() error = %v", err)
	}
	if fb.Methods == nil {
		t.Fatal("Methods not parsed")
	}
	if fb.Methods.NotImplemented.Statuscode != 501 || fb.Methods.NotAllowed.Statuscode != 405 ||
		fb.Methods.Trace.Statuscode != 405 || fb.Methods.Options.Statuscode != 200 {
		t.Fatalf("Methods statuses parsed wrong: %+v", fb.Methods)
	}
	if got := convertMap(fb.Methods.Trace.Headers)["Allow"]; got != "" {
		t.Fatalf("Trace Allow = %q, want empty", got)
	}
	for method, want := range map[string]bool{"PUT": true, "TRACE": true, "GET": true, "PROPFIND": true, "DOOD": false, "get": false} {
		if got := fb.Methods.isRegistered(method); got != want {
			t.Errorf("isRegistered(%q) = %v, want %v", method, got, want)
		}
	}
	if currentMethods() != fb.Methods {
		t.Fatal("currentMethods() did not return the loaded policy")
	}
}

func TestLoadFallbackMethodsRegisteredOverride(t *testing.T) {
	fb, err := LoadFallback(methodsFallbackFile(t, strings.Replace(testMethodsJSON, `"NotImplemented"`, `"Registered": ["GET", "BREW"], "NotImplemented"`, 1)))
	if err != nil {
		t.Fatalf("LoadFallback() error = %v", err)
	}
	if !fb.Methods.isRegistered("BREW") || fb.Methods.isRegistered("PUT") {
		t.Fatalf("Registered override not honoured: BREW=%v PUT=%v", fb.Methods.isRegistered("BREW"), fb.Methods.isRegistered("PUT"))
	}
	for _, always := range []string{"GET", "HEAD", "POST", "OPTIONS", "TRACE"} {
		if !fb.Methods.isRegistered(always) {
			t.Errorf("%s must always count as registered", always)
		}
	}
}

func TestLoadFallbackMethodsOptional(t *testing.T) {
	fb, err := LoadFallback(timingFallbackFile(t, ""))
	if err != nil {
		t.Fatalf("LoadFallback() error = %v", err)
	}
	if fb.Methods != nil || currentMethods() != nil {
		t.Fatalf("Methods = %+v, currentMethods() = %+v; want nil without a Methods section", fb.Methods, currentMethods())
	}
}

func TestLoadFallbackRejectsBadMethods(t *testing.T) {
	cases := map[string]struct{ json, want string }{
		"zero status":     {strings.Replace(testMethodsJSON, `"StatusCode": 501`, `"StatusCode": 0`, 1), "Methods.NotImplemented"},
		"no Content-Type": {strings.Replace(testMethodsJSON, `"Content-Type": "text/html; charset=iso-8859-1", "Allow": "GET,POST,OPTIONS,HEAD"}},`, `"Allow": "GET,POST,OPTIONS,HEAD"}},`, 1), "Content-Type"},
		"missing Trace":   {strings.Replace(testMethodsJSON, `"Trace"`, `"Tracer"`, 1), "Trace"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFallback(methodsFallbackFile(t, c.json))
			if err == nil {
				t.Fatalf("LoadFallback accepted a Methods section with %s", name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// --- B004 GlobalProtect: ConnectionStyle ---

func TestLoadFallbackParsesConnectionStyle(t *testing.T) {
	SetFallback(nil)
	t.Cleanup(func() { SetFallback(nil) })
	path := writeFallbackFile(t, `{"Unmatched":{"StatusCode":404,"Type":"string","Body":"x","Headers":{"Content-Type":"text/html"}},"ConnectionStyle":"keepalive"}`)
	fb, err := LoadFallback(path)
	if err != nil {
		t.Fatalf("LoadFallback() error = %v", err)
	}
	if fb.ConnStyle != connStyleKeepAlive {
		t.Errorf("ConnStyle = %q, want %q", fb.ConnStyle, connStyleKeepAlive)
	}
	if currentConnStyle() != connStyleKeepAlive {
		t.Errorf("currentConnStyle() = %q, want %q", currentConnStyle(), connStyleKeepAlive)
	}
}

func TestLoadFallbackConnectionStyleOptional(t *testing.T) {
	SetFallback(nil)
	t.Cleanup(func() { SetFallback(nil) })
	path := writeFallbackFile(t, `{"Unmatched":{"StatusCode":404,"Type":"string","Body":"x","Headers":{"Content-Type":"text/html"}}}`)
	fb, err := LoadFallback(path)
	if err != nil {
		t.Fatalf("LoadFallback() error = %v", err)
	}
	if fb.ConnStyle != "" {
		t.Errorf("ConnStyle = %q, want empty (Apache default)", fb.ConnStyle)
	}
}

func TestLoadFallbackRejectsUnknownConnectionStyle(t *testing.T) {
	t.Cleanup(func() { SetFallback(nil) })
	path := writeFallbackFile(t, `{"Unmatched":{"StatusCode":404,"Type":"string","Body":"x","Headers":{"Content-Type":"text/html"}},"ConnectionStyle":"nginx-ish"}`)
	if _, err := LoadFallback(path); err == nil {
		t.Fatal("LoadFallback accepted an unknown ConnectionStyle")
	}
}
