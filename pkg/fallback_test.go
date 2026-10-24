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
		TooLarge:  Response{Statuscode: http.StatusRequestEntityTooLarge, Body: "<h1>Request Entity Too Large</h1>", Headers: headers, Type: "string"},
	}
}

func TestLoadFallbackParsesBothResponses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fallback.json")
	content := `{
  "Unmatched": {"StatusCode": 404, "Body": "<h1>Not Found</h1>", "Type": "string",
                "Headers": {"Server": "Apache/2.4.58 (Ubuntu)", "Content-Type": "text/html"}},
  "TooLarge":  {"StatusCode": 413, "Body": "<h1>Request Entity Too Large</h1>", "Type": "string",
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
	if fb.TooLarge.Statuscode != 413 || fb.TooLarge.Body != "<h1>Request Entity Too Large</h1>" {
		t.Fatalf("TooLarge parsed wrong: %+v", fb.TooLarge)
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
