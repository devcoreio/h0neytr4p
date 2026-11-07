package h0neytr4p

import (
	"net/http"
	"net/http/httptest"
	"strconv"
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
		"response_status":               "303",
		"response_bytes":                "3",
		"response_sha256":               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"response_header_x-powered-by":  "PHP/8.3.6",
		"response_header_location":      "/login/index.php",
		"response_delay_ms":             "7",
		"response_source":               "traps/x.html",
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
