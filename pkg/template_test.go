package h0neytr4p

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestRenderTemplateSid(t *testing.T) {
	a, b := RenderTemplate("{{sid}}"), RenderTemplate("{{sid}}")
	re := regexp.MustCompile(`^[0-9a-v]{26}$`)
	if !re.MatchString(a) || !re.MatchString(b) {
		t.Fatalf("sid renders = %q, %q; want 26 chars of [0-9a-v]", a, b)
	}
	if a == b {
		t.Fatalf("two sid renders are identical: %q", a)
	}
}

func TestRenderTemplateRandHexAndAlnum(t *testing.T) {
	if got := RenderTemplate("{{rand_hex:32}}"); !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(got) {
		t.Fatalf("rand_hex:32 = %q", got)
	}
	if got := RenderTemplate("{{rand_alnum:32}}"); !regexp.MustCompile(`^[A-Za-z0-9]{32}$`).MatchString(got) {
		t.Fatalf("rand_alnum:32 = %q", got)
	}
	if got := RenderTemplate("x {{nope}} y"); got != "x {{nope}} y" {
		t.Fatalf("unknown token changed: %q", got)
	}
}

func TestWriteTrapResponseRendersHeadersAndBody(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	writeTrapResponse(rec, req, Behaviour{Response: Response{
		Statuscode: 200, Type: "string", Body: "t={{rand_hex:8}}",
		Headers: map[string]interface{}{"X-Token": "h-{{rand_hex:4}}", "Content-Type": "text/plain"},
	}})
	if !regexp.MustCompile(`^t=[0-9a-f]{8}$`).MatchString(rec.Body.String()) {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if !regexp.MustCompile(`^h-[0-9a-f]{4}$`).MatchString(rec.Header().Get("X-Token")) {
		t.Fatalf("X-Token = %q", rec.Header().Get("X-Token"))
	}
}

func TestWriteTrapResponseSetsCookieOnlyWhenMissing(t *testing.T) {
	behaviour := Behaviour{Response: Response{
		Statuscode: 200, Type: "string", Body: "ok",
		Headers: map[string]interface{}{"Set-Cookie-If-Missing": "MoodleSession={{sid}}; path=/; HttpOnly", "Content-Type": "text/html"},
	}}

	rec := httptest.NewRecorder()
	writeTrapResponse(rec, httptest.NewRequest(http.MethodGet, "/", nil), behaviour)
	got := rec.Header().Values("Set-Cookie")
	if len(got) != 1 || !regexp.MustCompile(`^MoodleSession=[0-9a-v]{26}; path=/; HttpOnly$`).MatchString(got[0]) {
		t.Fatalf("Set-Cookie without request cookie = %q", got)
	}
	if rec.Header().Get("Set-Cookie-If-Missing") != "" {
		t.Fatal("Set-Cookie-If-Missing leaked into the response")
	}

	for _, cookie := range []string{"MoodleSession=abc", "MoodleSession="} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Cookie", cookie)
		writeTrapResponse(rec, req, behaviour)
		if v := rec.Header().Values("Set-Cookie"); len(v) != 0 {
			t.Fatalf("request with %q got Set-Cookie %q", cookie, v)
		}
	}
}

func TestFileResponseIsRendered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(path, []byte("<input value=\"{{sid}}\">"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	writeTrapResponse(rec, httptest.NewRequest(http.MethodGet, "/", nil), Behaviour{Response: Response{
		Statuscode: 200, Type: "file", Body: path, Headers: map[string]interface{}{"Content-Type": "text/html"},
	}})
	if !regexp.MustCompile(`^<input value="[0-9a-v]{26}">$`).MatchString(rec.Body.String()) {
		t.Fatalf("file body not rendered: %q", rec.Body.String())
	}
}
