package h0neytr4p

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// methodTraps is a tiny persona: one PHP page with GET and POST behaviours,
// one GET-only PHP page, one static asset.
func methodTraps() []Trap {
	php := map[string]interface{}{"Server": "Apache/2.4.58 (Ubuntu)", "X-Powered-By": "PHP/8.3.6", "Content-Type": "text/html; charset=utf-8"}
	static := map[string]interface{}{"Server": "Apache/2.4.58 (Ubuntu)", "Content-Type": "text/javascript", "Content-Length": "5"}
	req := func(method, url string) Request {
		return Request{URL: url, Method: method, Headers: map[string]interface{}{}, Params: map[string]interface{}{}}
	}
	return []Trap{
		{Basicinfo: BasicInfo{Name: "php_page", Port: "80"}, Behaviour: []Behaviour{
			{Request: req(http.MethodGet, "/index.php"), Response: Response{Statuscode: 303, Body: "PAGE", Headers: php, Type: "string"}},
			{Request: req(http.MethodGet, "/only-get.php"), Response: Response{Statuscode: 200, Body: "ONLYGET", Headers: php, Type: "string"}},
		}},
		{Basicinfo: BasicInfo{Name: "php_post", Port: "80"}, Behaviour: []Behaviour{
			{Request: req(http.MethodPost, "/index.php"), Response: Response{Statuscode: 200, Body: "POSTED", Headers: php, Type: "string"}},
		}},
		{Basicinfo: BasicInfo{Name: "asset", Port: "80"}, Behaviour: []Behaviour{
			{Request: req(http.MethodGet, "/static.js"), Response: Response{Statuscode: 200, Body: "// js", Headers: static, Type: "string"}},
		}},
	}
}

func testFallbackWithMethods() *Fallback {
	fb := testFallback()
	html := map[string]interface{}{"Server": "Apache/2.4.58 (Ubuntu)", "Content-Type": "text/html; charset=iso-8859-1"}
	with := func(extra map[string]interface{}) map[string]interface{} {
		m := map[string]interface{}{}
		for k, v := range html {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	fb.Methods = &MethodPolicy{
		NotImplemented: Response{Statuscode: 501, Type: "string", Body: "<p>{{req_method}} not supported for current URL.<br />",
			Headers: with(map[string]interface{}{"Allow": "GET,POST,OPTIONS,HEAD", "Connection": "close"})},
		NotAllowed: Response{Statuscode: 405, Type: "string", Body: "<p>The requested method {{req_method}} is not allowed for this URL.</p>",
			Headers: with(map[string]interface{}{"Allow": "GET,POST,OPTIONS,HEAD"})},
		Trace: Response{Statuscode: 405, Type: "string", Body: "<p>The requested method {{req_method}} is not allowed for this URL.</p>",
			Headers: with(map[string]interface{}{"Allow": ""})},
		Options: Response{Statuscode: 200, Type: "string", Body: "",
			Headers: map[string]interface{}{"Server": "Apache/2.4.58 (Ubuntu)", "Allow": "GET,POST,OPTIONS,HEAD", "Content-Length": "0"}},
		ContentTypes: map[string]string{".ico": "image/vnd.microsoft.icon"},
	}
	return fb
}

// serve runs one request through allHandler with the method persona and the
// Methods policy installed, returning the recorder and the log line(s).
func serveMethod(t *testing.T, fb *Fallback, catchall bool, method, path string, body *bytes.Buffer, contentType string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	logPath, _ := configureTestIO(t)
	SetFallback(fb)
	t.Cleanup(func() { SetFallback(nil) })
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, body)
		req.Header.Set("Content-Type", contentType)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	allHandler(methodTraps(), catchall).ServeHTTP(rec, req)
	return rec, readTestLog(t, logPath)
}

func TestAllHandlerTraceIs405(t *testing.T) {
	for _, path := range []string{"/index.php", "/static.js", "/nope", "/nope.php"} {
		t.Run(path, func(t *testing.T) {
			rec, logs := serveMethod(t, testFallbackWithMethods(), false, "TRACE", path, nil, "")
			if rec.Code != 405 {
				t.Fatalf("status = %d, want 405", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "method TRACE is not allowed") {
				t.Fatalf("body = %q", rec.Body.String())
			}
			if v, ok := rec.Header()["Allow"]; !ok || len(v) != 1 || v[0] != "" {
				t.Fatalf("Allow = %v, want present and empty", v)
			}
			if !strings.Contains(logs, `"method_route":"trace"`) || !strings.Contains(logs, `"request_method":"TRACE"`) {
				t.Fatalf("log = %s", logs)
			}
		})
	}
}

func TestAllHandlerAnyVerbOnPHPPageRunsPage(t *testing.T) {
	for _, method := range []string{"DOOD", http.MethodOptions, http.MethodPut, "PROPFIND"} {
		t.Run(method, func(t *testing.T) {
			rec, logs := serveMethod(t, testFallbackWithMethods(), false, method, "/index.php", nil, "")
			if rec.Code != 303 || rec.Body.String() != "PAGE" {
				t.Fatalf("status = %d body = %q, want 303 PAGE", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("X-Powered-By") == "" {
				t.Fatal("X-Powered-By missing: the PHP page was not served")
			}
			for _, want := range []string{`"trapped_for":"php_page"`, `"method_route":"php-any-method"`, `"request_method":"` + method + `"`, `"trapped":"true"`} {
				if !strings.Contains(logs, want) {
					t.Fatalf("log lacks %s: %s", want, logs)
				}
			}
		})
	}
}

func TestAllHandlerPostOnGetOnlyPHPPageRunsPage(t *testing.T) {
	rec, logs := serveMethod(t, testFallbackWithMethods(), false, http.MethodPost, "/only-get.php", bytes.NewBufferString("a=b"), "application/x-www-form-urlencoded")
	if rec.Code != 200 || rec.Body.String() != "ONLYGET" {
		t.Fatalf("status = %d body = %q, want 200 ONLYGET", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs, `"method_route":"php-any-method"`) {
		t.Fatalf("log = %s", logs)
	}
}

func TestAllHandlerExactMethodBeatsRelaxedPass(t *testing.T) {
	rec, logs := serveMethod(t, testFallbackWithMethods(), false, http.MethodPost, "/index.php", bytes.NewBufferString("a=b"), "application/x-www-form-urlencoded")
	if rec.Code != 200 || rec.Body.String() != "POSTED" {
		t.Fatalf("status = %d body = %q, want 200 POSTED", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs, `"method_route":"exact"`) || !strings.Contains(logs, `"trapped_for":"php_post"`) {
		t.Fatalf("log = %s", logs)
	}
}

func TestAllHandlerNonPHPPathMethodFallbacks(t *testing.T) {
	cases := []struct {
		method, path string
		status       int
		route, body  string
		headers      map[string]string
	}{
		{"DOOD", "/static.js", 501, "not-implemented", "DOOD not supported for current URL", map[string]string{"Allow": "GET,POST,OPTIONS,HEAD", "Connection": "close"}},
		{"DOOD", "/nope", 501, "not-implemented", "DOOD not supported", map[string]string{"Allow": "GET,POST,OPTIONS,HEAD", "Connection": "close"}},
		{"DOOD", "/favicon.ico", 501, "not-implemented", "DOOD not supported", nil},
		{"PUT", "/static.js", 405, "not-allowed", "method PUT is not allowed", map[string]string{"Allow": "GET,POST,OPTIONS,HEAD"}},
		{"PROPFIND", "/static.js", 405, "not-allowed", "method PROPFIND is not allowed", nil},
		{"PUT", "/favicon.ico", 405, "not-allowed", "method PUT is not allowed", nil},
		{"OPTIONS", "/static.js", 200, "options", "", map[string]string{"Allow": "GET,POST,OPTIONS,HEAD", "Content-Type": "text/javascript", "Content-Length": "0"}},
		{"OPTIONS", "/nope.ico", 200, "options", "", map[string]string{"Allow": "GET,POST,OPTIONS,HEAD", "Content-Type": "image/vnd.microsoft.icon"}},
		{"OPTIONS", "/nope", 200, "options", "", map[string]string{"Allow": "GET,POST,OPTIONS,HEAD", "Content-Type": ""}},
		{"GET", "/nope", 404, "unmatched", "Not Found", nil},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			rec, logs := serveMethod(t, testFallbackWithMethods(), false, c.method, c.path, nil, "")
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, c.status, rec.Body.String())
			}
			if c.body == "" && rec.Body.Len() != 0 {
				t.Fatalf("body = %q, want empty", rec.Body.String())
			}
			if c.body != "" && !strings.Contains(rec.Body.String(), c.body) {
				t.Fatalf("body = %q, want it to contain %q", rec.Body.String(), c.body)
			}
			for k, want := range c.headers {
				if got := rec.Header().Get(k); got != want {
					t.Errorf("header %s = %q, want %q", k, got, want)
				}
			}
			if !strings.Contains(logs, `"method_route":"`+c.route+`"`) {
				t.Fatalf("log lacks route %s: %s", c.route, logs)
			}
		})
	}
}

func TestAllHandlerMissingPHPPathIs404ForEveryVerb(t *testing.T) {
	for _, method := range []string{"DOOD", http.MethodOptions, http.MethodPut, http.MethodHead} {
		for _, path := range []string{"/nope.php", "/theme/image.php/boost/core/1/i/zzz"} {
			t.Run(method+" "+path, func(t *testing.T) {
				rec, logs := serveMethod(t, testFallbackWithMethods(), false, method, path, nil, "")
				if rec.Code != 404 {
					t.Fatalf("status = %d, want 404", rec.Code)
				}
				if !strings.Contains(logs, `"method_route":"unmatched"`) {
					t.Fatalf("log = %s", logs)
				}
			})
		}
	}
}

func TestAllHandlerHeadUnchangedByMethodPolicy(t *testing.T) {
	cases := []struct {
		path   string
		status int
		route  string
	}{{"/index.php", 303, "exact"}, {"/static.js", 200, "exact"}, {"/nope", 404, "unmatched"}}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			rec, logs := serveMethod(t, testFallbackWithMethods(), false, http.MethodHead, c.path, nil, "")
			if rec.Code != c.status || rec.Body.Len() != 0 {
				t.Fatalf("status = %d body = %q, want %d and empty", rec.Code, rec.Body.String(), c.status)
			}
			if !strings.Contains(logs, `"method_route":"`+c.route+`"`) {
				t.Fatalf("log = %s", logs)
			}
		})
	}
}

func TestAllHandlerPHPAnyMethodCapturesBody(t *testing.T) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("a", "b"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	rec, logs := serveMethod(t, testFallbackWithMethods(), true, "DOOD", "/index.php", &body, w.FormDataContentType())
	if rec.Code != 303 {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if !strings.Contains(logs, `"payload_parameter":"`) || !strings.Contains(logs, `a=b`) {
		t.Fatalf("multipart body on a relaxed-method request was not captured: %s", logs)
	}
}

func TestAllHandlerMethodPolicyAbsentIsLegacy(t *testing.T) {
	for _, c := range []struct{ method, path string }{{"DOOD", "/index.php"}, {"TRACE", "/index.php"}, {"DOOD", "/static.js"}} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			rec, logs := serveMethod(t, testFallback(), false, c.method, c.path, nil, "")
			if rec.Code != 404 {
				t.Fatalf("status = %d, want legacy 404", rec.Code)
			}
			if strings.Contains(logs, `"method_route":"php-any-method"`) {
				t.Fatalf("relaxed pass ran without a Methods policy: %s", logs)
			}
		})
	}
}
