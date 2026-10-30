package h0neytr4p

import (
	"bufio"
	"bytes"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Real-server tests: httptest.Recorder hides HEAD framing, mux routing of
// CONNECT, and MaxBytesReader behaviour on chunked bodies.

func loginTrap() Trap {
	return Trap{
		Basicinfo: BasicInfo{Name: "moodle", Port: "80"},
		Behaviour: []Behaviour{{
			Request: Request{URL: "/login/index.php", Method: http.MethodGet, Headers: map[string]interface{}{}, Params: map[string]interface{}{}},
			Response: Response{Statuscode: 200, Type: "string", Body: strings.Repeat("<p>login</p>\n", 400),
				Headers: map[string]interface{}{"Content-Type": "text/html; charset=utf-8", "Server": "Apache/2.4.58 (Ubuntu)"}},
		}},
	}
}

func startServer(t *testing.T, traps []Trap) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(newTrapRouter(traps, true))
	t.Cleanup(srv.Close)
	return srv
}

func TestServerHeadMatchesGetTrap(t *testing.T) {
	logPath, _ := configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	srv := startServer(t, []Trap{loginTrap()})

	resp, err := http.Head(srv.URL + "/login/index.php")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("HEAD status = %d, want 200 (the GET trap's status)", resp.StatusCode)
	}
	if resp.Header.Get("Server") != "Apache/2.4.58 (Ubuntu)" {
		t.Fatalf("HEAD Server header = %q", resp.Header.Get("Server"))
	}
	// Apache sends no Content-Length on HEAD for dynamic pages and error
	// documents; only static assets (traps that set it explicitly) carry one.
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		t.Fatalf("HEAD Content-Length = %q, want none when the trap sets none", cl)
	}
	if len(body) != 0 {
		t.Fatalf("HEAD body length = %d, want 0", len(body))
	}
	if !strings.Contains(readTestLog(t, logPath), `"trapped_for":"moodle"`) {
		t.Fatal("HEAD was not logged against the GET trap")
	}
}

func TestServerHeadKeepsExplicitContentLength(t *testing.T) {
	configureTestIO(t)
	trap := loginTrap()
	trap.Behaviour[0].Response.Headers["Content-Length"] = strconv.Itoa(len(trap.Behaviour[0].Response.Body))
	srv := startServer(t, []Trap{trap})

	resp, err := http.Head(srv.URL + "/login/index.php")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if want := strconv.Itoa(len(trap.Behaviour[0].Response.Body)); resp.Header.Get("Content-Length") != want {
		t.Fatalf("HEAD Content-Length = %q, want explicit %q", resp.Header.Get("Content-Length"), want)
	}
}

func TestServerHeadSpecificBehaviourWinsOverGet(t *testing.T) {
	configureTestIO(t)
	trap := loginTrap()
	headBehaviour := Behaviour{
		Request:  Request{URL: "/login/index.php", Method: http.MethodHead, Headers: map[string]interface{}{}, Params: map[string]interface{}{}},
		Response: Response{Statuscode: 204, Type: "string", Body: "", Headers: map[string]interface{}{"Content-Type": "text/html"}},
	}
	trap.Behaviour = append([]Behaviour{headBehaviour}, trap.Behaviour...)
	srv := startServer(t, []Trap{trap})

	resp, err := http.Head(srv.URL + "/login/index.php")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("HEAD status = %d, want 204 from the HEAD-specific behaviour", resp.StatusCode)
	}
}

func TestServerConnectIsLoggedAndGetsFallback(t *testing.T) {
	logPath, _ := configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	srv := startServer(t, nil)

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: proxy-probe\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 404 || resp.Header.Get("Server") == "" || !strings.Contains(string(body), "Not Found") {
		t.Fatalf("CONNECT got %d %q body %q; want the fallback 404 with Server header", resp.StatusCode, resp.Header, body)
	}
	if resp.Header.Get("X-Content-Type-Options") != "" {
		t.Fatal("CONNECT answered by Go's/mux's default handler (X-Content-Type-Options present)")
	}
	logContent := readTestLog(t, logPath)
	if !strings.Contains(logContent, `"request_method":"CONNECT"`) || !strings.Contains(logContent, `"user-agent":"proxy-probe"`) {
		t.Fatalf("CONNECT not logged: %s", logContent)
	}
}

func TestServerChunkedOverCapNo413(t *testing.T) {
	logPath, _ := configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	srv := startServer(t, nil)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormField("PHP_SESSION_UPLOAD_PROGRESS")
	fw.Write(bytes.Repeat([]byte("A"), 9*1024*1024))
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/upload", io.NopCloser(&buf))
	req.ContentLength = -1 // forces Transfer-Encoding: chunked
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed (connection reset?): %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Fatalf("status = 413, want PHP-shaped non-413")
	}
	logContent := readTestLog(t, logPath)
	if !strings.Contains(logContent, `"payload_truncated":"true"`) {
		t.Fatalf("chunked over-cap multipart not flagged: %.300s", logContent)
	}
}

func TestNewServerDisablesHTTP2(t *testing.T) {
	srv := newServer("443", http.NotFoundHandler())
	// An empty, non-nil TLSNextProto map is net/http's documented switch for
	// turning HTTP/2 off; stock Ubuntu Apache does not speak h2.
	if srv.TLSNextProto == nil || len(srv.TLSNextProto) != 0 {
		t.Fatalf("TLSNextProto = %v, want empty non-nil map (HTTP/2 disabled)", srv.TLSNextProto)
	}
	if srv.Addr != ":443" {
		t.Fatalf("Addr = %q", srv.Addr)
	}
}

func TestServerManyPartMultipartNo413KeepsPrefix(t *testing.T) {
	t.Setenv("GODEBUG", "multipartmaxparts=1000")
	logPath, _ := configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	srv := startServer(t, nil)

	body, contentType := manyPartMultipart(t, 1500)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed (connection reset?): %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(respBody), "<h1>Not Found</h1>") {
		t.Fatalf("status %d body %.120q, want the fallback persona page", resp.StatusCode, respBody)
	}
	// Apache reads the whole body and keeps the connection open; an unread
	// body makes net/http add Connection: close, which is a tell.
	if resp.Header.Get("Connection") == "close" || resp.Close {
		t.Fatalf("response closed the connection on an under-cap body")
	}
	logContent := readTestLog(t, logPath)
	for _, want := range []string{`"payload_truncated":"true"`, `"payload":"`, "PHP_SESSION_UPLOAD_PROGRESS"} {
		if !strings.Contains(logContent, want) {
			t.Fatalf("log missing %s: %.300s", want, logContent)
		}
	}
}

// countingReader counts the body bytes the client actually sent, so a test can
// prove the server read the whole body: a server that answers early and closes
// makes the client's write stop short of the body length.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func postKeepAlive(t *testing.T, srv *httptest.Server, path, contentType string, body []byte, declareLength bool) (*http.Response, *countingReader) {
	t.Helper()
	return sendKeepAlive(t, srv, http.MethodPost, path, contentType, body, declareLength)
}

func sendKeepAlive(t *testing.T, srv *httptest.Server, method, path, contentType string, body []byte, declareLength bool) (*http.Response, *countingReader) {
	t.Helper()
	cr := &countingReader{r: bytes.NewReader(body)}
	req, _ := http.NewRequest(method, srv.URL+path, io.NopCloser(cr))
	if declareLength {
		req.ContentLength = int64(len(body))
	} else {
		req.ContentLength = -1 // forces Transfer-Encoding: chunked
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connection", "keep-alive")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed (server answered early?): %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp, cr
}

// assertDrainedKeepAlive checks Apache's behaviour: the whole body was read
// before the answer and the connection was left open.
func assertDrainedKeepAlive(t *testing.T, resp *http.Response, cr *countingReader, want int64) {
	t.Helper()
	if cr.n != want {
		t.Fatalf("server read %d of %d body bytes", cr.n, want)
	}
	if resp.Close || resp.Header.Get("Connection") == "close" {
		t.Fatalf("response closed the connection")
	}
}

func overCapMultipart(t *testing.T) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormField("PHP_SESSION_UPLOAD_PROGRESS")
	fw.Write(bytes.Repeat([]byte("A"), 9*1024*1024))
	mw.Close()
	return buf.Bytes(), mw.FormDataContentType()
}

func TestServerDeclaredOverCapMultipartIsDrainedKeepAlive(t *testing.T) {
	logPath, _ := configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	srv := startServer(t, nil)

	body, contentType := overCapMultipart(t)
	resp, cr := postKeepAlive(t, srv, "/", contentType, body, true)
	assertDrainedKeepAlive(t, resp, cr, int64(len(body)))
	if logContent := readTestLog(t, logPath); !strings.Contains(logContent, `"payload_truncated":"true"`) {
		t.Fatalf("declared over-cap multipart not flagged: %.300s", logContent)
	}
}

func TestServerChunkedOverCapMultipartIsDrainedKeepAlive(t *testing.T) {
	logPath, _ := configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	srv := startServer(t, nil)

	body, contentType := overCapMultipart(t)
	resp, cr := postKeepAlive(t, srv, "/", contentType, body, false)
	assertDrainedKeepAlive(t, resp, cr, int64(len(body)))
	if logContent := readTestLog(t, logPath); !strings.Contains(logContent, `"payload_truncated":"true"`) {
		t.Fatalf("chunked over-cap multipart not flagged: %.300s", logContent)
	}
}

func TestServerOverCapJSONIsDrainedKeepAlive(t *testing.T) {
	configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	srv := startServer(t, nil)

	body := append([]byte(`{"a":"`), bytes.Repeat([]byte("A"), 9*1024*1024)...)
	body = append(body, `"}`...)
	resp, cr := postKeepAlive(t, srv, "/", "application/json", body, true)
	assertDrainedKeepAlive(t, resp, cr, int64(len(body)))
}

func TestServerGetWithBodyIsDrainedKeepAlive(t *testing.T) {
	configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	srv := startServer(t, nil)

	body := bytes.Repeat([]byte("x"), 1024*1024)
	resp, cr := sendKeepAlive(t, srv, http.MethodGet, "/", "text/plain", body, true)
	assertDrainedKeepAlive(t, resp, cr, int64(len(body)))
}

func TestServerMalformedMultipartKeepsWholePrefix(t *testing.T) {
	logPath, _ := configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	srv := startServer(t, nil)

	// The parser gives up after its first 4 KB buffer; the stored prefix must
	// still hold the whole (under MaxStoredPayload) body, tail included.
	body := append([]byte("no-boundary-here\r\n"), bytes.Repeat([]byte("B"), 30000)...)
	body = append(body, "TAILMARK"...)
	resp, cr := postKeepAlive(t, srv, "/", "multipart/form-data; boundary=XYZ", body, true)
	assertDrainedKeepAlive(t, resp, cr, int64(len(body)))
	if logContent := readTestLog(t, logPath); !strings.Contains(logContent, "TAILMARK") {
		t.Fatalf("malformed multipart prefix lost the body tail: %.300s", logContent)
	}
}
