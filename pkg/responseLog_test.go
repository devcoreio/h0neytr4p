package h0neytr4p

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestResponseDetailsFields(t *testing.T) {
	rr := newResponseRecorder(httptest.NewRecorder())
	rr.WriteHeader(303)
	rr.Write([]byte("abc"))
	h := http.Header{"X-Powered-By": {"PHP/8.3.6"}, "Location": {"/login/index.php"}}
	d := responseDetails(rr, h, "traps/x.html", time.Now().Add(-5*time.Millisecond), 7*time.Millisecond)
	want := map[string]string{
		"response_status":              "303",
		"response_bytes":               "3",
		"response_sha256":              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"response_header_x-powered-by": "PHP/8.3.6",
		"response_header_location":     "/login/index.php",
		"response_delay_ms":            "7",
		"response_source":              "traps/x.html",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %q, want %q", k, d[k], v)
		}
	}
	ms, err := strconv.Atoi(d["response_ms"])
	if err != nil || ms < 5 {
		t.Errorf("response_ms = %q, want integer >= 5", d["response_ms"])
	}
}

func TestResponseDetailsOmitsHashWhenEmpty(t *testing.T) {
	rr := newResponseRecorder(httptest.NewRecorder())
	d := responseDetails(rr, http.Header{}, "none", time.Now(), 0)
	if _, ok := d["response_sha256"]; ok {
		t.Errorf("response_sha256 present on an empty body: %q", d["response_sha256"])
	}
	if d["response_bytes"] != "0" || d["response_status"] != "200" || d["response_delay_ms"] != "0" {
		t.Errorf("bytes=%q status=%q delay=%q", d["response_bytes"], d["response_status"], d["response_delay_ms"])
	}
}

func TestResponseDetailsJoinsMultiValueHeaders(t *testing.T) {
	rr := newResponseRecorder(httptest.NewRecorder())
	h := http.Header{"Set-Cookie": {"MoodleSession=a", "MOODLEID1_=b"}}
	d := responseDetails(rr, h, "inline", time.Now(), 0)
	if got := d["response_header_set-cookie"]; got != "MoodleSession=a, MOODLEID1_=b" {
		t.Errorf("response_header_set-cookie = %q", got)
	}
}

func TestResponseSource(t *testing.T) {
	cases := []struct {
		b     Behaviour
		route string
		want  string
	}{
		{Behaviour{Response: Response{Type: "file", Body: "traps/login.html"}}, routeExact, "traps/login.html"},
		{Behaviour{Response: Response{Type: "", Body: "<html>"}}, routePHPAny, "inline"},
		{Behaviour{Response: Response{Type: "file", Body: "501.html"}}, routeNotImplemented, "fallback:not-implemented"},
		{Behaviour{}, routeUnmatched, "fallback:unmatched"},
	}
	for _, c := range cases {
		if got := responseSource(c.b, c.route); got != c.want {
			t.Errorf("responseSource(%+v, %q) = %q, want %q", c.b.Response, c.route, got, c.want)
		}
	}
}

func TestPhpDelayReturnsSleptDuration(t *testing.T) {
	SetFallback(nil)
	t.Cleanup(func() { SetFallback(nil) })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	var d time.Duration = phpDelay(req, Response{}, 0)
	if d != 0 {
		t.Errorf("phpDelay with no timing = %v, want 0", d)
	}
}

// fileTrap is a GET /page trap answered from a file on disk.
func fileTrap(path string) Trap {
	return Trap{
		Basicinfo: BasicInfo{Name: "page-trap", Port: "80"},
		Behaviour: []Behaviour{{
			Request: Request{URL: "/page", Method: http.MethodGet, Headers: map[string]interface{}{}},
			Response: Response{
				Statuscode: http.StatusOK,
				Body:       path,
				Type:       "file",
				Headers:    map[string]interface{}{"X-Powered-By": "PHP/8.3.6"},
			},
		}},
	}
}

func serveAndReadLog(t *testing.T, traps []Trap, catchall bool, req *http.Request) (string, *httptest.ResponseRecorder) {
	t.Helper()
	logPath, _ := configureTestIO(t)
	rec := httptest.NewRecorder()
	allHandler(traps, catchall).ServeHTTP(rec, req)
	return readTestLog(t, logPath), rec
}

func mustContain(t *testing.T, logLine string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(logLine, s) {
			t.Errorf("log line lacks %s\nline: %s", s, logLine)
		}
	}
}

func TestAllHandlerLogsResponseForFileTrap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	logLine, rec := serveAndReadLog(t, []Trap{fileTrap(path)}, true, req)
	if rec.Code != 200 || rec.Body.String() != "hello" {
		t.Fatalf("response = %d %q", rec.Code, rec.Body.String())
	}
	mustContain(t, logLine,
		`"response_status":"200"`,
		`"response_bytes":"5"`,
		`"response_sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"`,
		`"response_header_x-powered-by":"PHP/8.3.6"`,
		`"response_source":"`+path+`"`,
		`"response_delay_ms":"0"`,
		`"response_ms":"`,
	)
}

func TestAllHandlerLogsHeadWithoutBodyFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodHead, "/page", nil)
	logLine, rec := serveAndReadLog(t, []Trap{fileTrap(path)}, true, req)
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("response = %d, %d body bytes", rec.Code, rec.Body.Len())
	}
	mustContain(t, logLine, `"response_status":"200"`, `"response_bytes":"0"`)
	if strings.Contains(logLine, "response_sha256") {
		t.Errorf("HEAD line carries response_sha256: %s", logLine)
	}
}

func TestAllHandlerLogsFileReadError500(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.html")
	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	logLine, rec := serveAndReadLog(t, []Trap{fileTrap(path)}, true, req)
	if rec.Code != 500 {
		t.Fatalf("response = %d, want 500", rec.Code)
	}
	mustContain(t, logLine, `"response_status":"500"`, `"response_bytes":"22"`, `"response_source":"`+path+`"`)
}

func TestAllHandlerLogsNoFallbackPath(t *testing.T) {
	SetFallback(nil)
	t.Cleanup(func() { SetFallback(nil) })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	logLine, _ := serveAndReadLog(t, nil, true, req)
	mustContain(t, logLine, `"request_uri":"/x"`, `"response_status":"200"`, `"response_bytes":"0"`, `"response_source":"none"`)
}

func TestAllHandlerLogsFallbackRouteSource(t *testing.T) {
	fb := testFallbackWithMethods()
	SetFallback(fb)
	t.Cleanup(func() { SetFallback(nil) })
	req := httptest.NewRequest("DOOD", "/nope.txt", nil)
	logLine, rec := serveAndReadLog(t, nil, true, req)
	wantStatus := fb.Methods.NotImplemented.Statuscode
	if rec.Code != wantStatus {
		t.Fatalf("response = %d, want %d", rec.Code, wantStatus)
	}
	mustContain(t, logLine,
		`"method_route":"not-implemented"`,
		`"response_source":"fallback:not-implemented"`,
		`"response_status":"`+strconv.Itoa(wantStatus)+`"`,
	)
}

func TestAllHandlerLogLineIsWrittenOnce(t *testing.T) {
	SetFallback(nil)
	t.Cleanup(func() { SetFallback(nil) })
	req := httptest.NewRequest(http.MethodGet, "/once", nil)
	logLine, _ := serveAndReadLog(t, nil, true, req)
	if n := strings.Count(logLine, "\n"); n != 1 {
		t.Errorf("log has %d lines, want 1:\n%s", n, logLine)
	}
}
