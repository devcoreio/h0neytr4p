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
	"time"
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
	srv := httptest.NewUnstartedServer(newTrapRouter(traps, true))
	configureServer(srv.Config) // same ConnContext and timeouts as production
	srv.Start()
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

func TestServerChunkedSmallJSONIsDrainedKeepAlive(t *testing.T) {
	configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	srv := startServer(t, nil)

	// Under cap, so the capture step reads the whole body itself.
	body := append([]byte(`{"a":"`), bytes.Repeat([]byte("A"), 3*1024)...)
	body = append(body, `"}`...)
	resp, cr := postKeepAlive(t, srv, "/", "application/json", body, false)
	assertDrainedKeepAlive(t, resp, cr, int64(len(body)))
}

// rawExchange sends the given request texts on ONE connection and returns the
// parsed responses in order, so a test sees exactly what went over the wire
// (Go's client would hide Connection/Keep-Alive handling).
func rawExchange(t *testing.T, addr string, reqs ...string) []*http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	resps := make([]*http.Response, 0, len(reqs))
	for i, req := range reqs {
		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatalf("request %d: write: %v", i, err)
		}
		method, _, _ := strings.Cut(req, " ")
		resp, err := http.ReadResponse(br, &http.Request{Method: method})
		if err != nil {
			t.Fatalf("request %d: read response (connection closed?): %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("request %d: read body: %v", i, err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resps = append(resps, resp)
	}
	return resps
}

func startKeepAliveServer(t *testing.T) string {
	t.Helper()
	configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	return strings.TrimPrefix(startServer(t, []Trap{loginTrap()}).URL, "http://")
}

func rawRequest(method, path, proto, connection string) string {
	req := method + " " + path + " " + proto + "\r\nHost: example.com\r\n"
	if connection != "" {
		req += "Connection: " + connection + "\r\n"
	}
	return req + "\r\n"
}

func TestServerKeepAliveHeadersWhenAsked(t *testing.T) {
	addr := startKeepAliveServer(t)
	req := rawRequest("GET", "/login/index.php", "HTTP/1.1", "keep-alive")
	resps := rawExchange(t, addr, req, req)

	// Apache with KeepAlive On, KeepAliveTimeout 5, MaxKeepAliveRequests 100
	// counts max down by one per request on the connection.
	if got := resps[0].Header.Get("Keep-Alive"); got != "timeout=5, max=100" {
		t.Errorf("first Keep-Alive = %q", got)
	}
	if got := resps[0].Header.Get("Connection"); got != "Keep-Alive" {
		t.Errorf("first Connection = %q", got)
	}
	if got := resps[1].Header.Get("Keep-Alive"); got != "timeout=5, max=99" {
		t.Errorf("second Keep-Alive = %q", got)
	}
	if got := resps[1].Header.Get("Connection"); got != "Keep-Alive" {
		t.Errorf("second Connection = %q", got)
	}
}

func TestServerNoKeepAliveHeadersWithoutToken(t *testing.T) {
	addr := startKeepAliveServer(t)
	// Apache sends neither header to an HTTP/1.1 client that sent no
	// Connection header or only an unknown token.
	for _, connection := range []string{"", "xxxxx"} {
		resp := rawExchange(t, addr, rawRequest("GET", "/login/index.php", "HTTP/1.1", connection))[0]
		if ka, c := resp.Header.Get("Keep-Alive"), resp.Header.Get("Connection"); ka != "" || c != "" {
			t.Errorf("Connection %q: got Keep-Alive %q Connection %q, want neither", connection, ka, c)
		}
	}
}

func TestServerHTTP10WithoutTokenCloses(t *testing.T) {
	addr := startKeepAliveServer(t)
	resp := rawExchange(t, addr, rawRequest("GET", "/login/index.php", "HTTP/1.0", ""))[0]
	if got := resp.Header.Get("Connection"); got != "close" {
		t.Errorf("Connection = %q, want close", got)
	}
	if got := resp.Header.Get("Keep-Alive"); got != "" {
		t.Errorf("Keep-Alive = %q, want none", got)
	}
}

func TestServerHTTP10KeepAliveGetsContentLengthAndStaysOpen(t *testing.T) {
	addr := startKeepAliveServer(t)
	req := rawRequest("GET", "/login/index.php", "HTTP/1.0", "keep-alive")
	resps := rawExchange(t, addr, req, req) // the second response proves reuse

	body, _ := io.ReadAll(resps[0].Body)
	if got := resps[0].Header.Get("Keep-Alive"); got != "timeout=5, max=100" {
		t.Errorf("Keep-Alive = %q", got)
	}
	if got := resps[0].Header.Get("Connection"); got != "Keep-Alive" {
		t.Errorf("Connection = %q", got)
	}
	// Apache buffers an HTTP/1.0 keep-alive response to frame it with a length.
	if got, want := resps[0].Header.Get("Content-Length"), strconv.Itoa(len(body)); got != want || len(body) == 0 {
		t.Errorf("Content-Length = %q, body %d bytes", got, len(body))
	}
	if got := resps[1].Header.Get("Keep-Alive"); got != "timeout=5, max=99" {
		t.Errorf("second Keep-Alive = %q", got)
	}
}

func TestServerHTTP10KeepAliveHeadIsReusable(t *testing.T) {
	addr := startKeepAliveServer(t)
	req := rawRequest("HEAD", "/login/index.php", "HTTP/1.0", "keep-alive")
	resps := rawExchange(t, addr, req, req)

	want := strconv.Itoa(len(loginTrap().Behaviour[0].Response.Body))
	if got := resps[0].Header.Get("Content-Length"); got != want {
		t.Errorf("HEAD Content-Length = %q, want the GET body length %s", got, want)
	}
	if body, _ := io.ReadAll(resps[0].Body); len(body) != 0 {
		t.Errorf("HEAD body length = %d, want 0", len(body))
	}
	if got := resps[0].Header.Get("Connection"); got != "Keep-Alive" {
		t.Errorf("HEAD Connection = %q", got)
	}
	if got := resps[1].Header.Get("Keep-Alive"); got != "timeout=5, max=99" {
		t.Errorf("second HEAD Keep-Alive = %q", got)
	}
}

func TestServerKeepAliveOnFallback404(t *testing.T) {
	addr := startKeepAliveServer(t)
	resp := rawExchange(t, addr, rawRequest("GET", "/nope", "HTTP/1.1", "keep-alive"))[0]
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want the fallback 404", resp.StatusCode)
	}
	if got := resp.Header.Get("Keep-Alive"); got != "timeout=5, max=100" {
		t.Errorf("Keep-Alive = %q", got)
	}
	if got := resp.Header.Get("Connection"); got != "Keep-Alive" {
		t.Errorf("Connection = %q", got)
	}
}

func TestServerKeepAliveClosesAfterMaxRequests(t *testing.T) {
	addr := startKeepAliveServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	// http.ReadResponse strips a close token from an HTTP/1.1 response's
	// Connection header (it sets resp.Close instead), so keep the raw bytes of
	// each response to check what went over the wire. Requests are sent one
	// at a time, so the buffer holds exactly one response.
	var raw bytes.Buffer
	br := bufio.NewReader(io.TeeReader(conn, &raw))
	req := rawRequest("GET", "/login/index.php", "HTTP/1.1", "keep-alive")
	get := func(i int) (*http.Response, error) {
		raw.Reset()
		if _, err := io.WriteString(conn, req); err != nil {
			return nil, err
		}
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(io.Discard, resp.Body)
		return resp, err
	}

	// MaxKeepAliveRequests 100: Apache counts max down to 1 on request 100,
	// then answers request 101 with Connection: close and closes.
	for i := 1; i <= 101; i++ {
		resp, err := get(i)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		switch i {
		case 100:
			if got := resp.Header.Get("Keep-Alive"); got != "timeout=5, max=1" {
				t.Fatalf("request 100 Keep-Alive = %q", got)
			}
		case 101:
			head, _, _ := strings.Cut(raw.String(), "\r\n\r\n")
			if !strings.Contains(head, "\r\nConnection: close\r\n") || !resp.Close {
				t.Fatalf("request 101 not answered with Connection: close:\n%s", head)
			}
			if strings.Contains(head, "Keep-Alive:") {
				t.Fatalf("request 101 carries a Keep-Alive header:\n%s", head)
			}
		}
	}
	if _, err := get(102); err == nil {
		t.Fatal("request 102 succeeded; want the connection closed after request 101")
	}
}

func TestServerPHPResponseIsDelayedStaticIsNot(t *testing.T) {
	configureTestIO(t)
	fb := testFallback()
	fb.Timing = Timing{PhpBaseMs: 80, PhpJitterMs: 0}
	SetFallback(fb)
	t.Cleanup(func() { SetFallback(nil) })
	trap := loginTrap()
	trap.Behaviour[0].Response.Headers["X-Powered-By"] = "PHP/8.3.6"
	srv := startServer(t, []Trap{trap})

	timeGet := func(path string) time.Duration {
		t.Helper()
		start := time.Now()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return time.Since(start)
	}

	if elapsed := timeGet("/login/index.php"); elapsed < 70*time.Millisecond {
		t.Fatalf("PHP page answered in %v, want >= 70ms (PhpBaseMs 80)", elapsed)
	}
	if elapsed := timeGet("/nope"); elapsed >= 40*time.Millisecond {
		t.Fatalf("static 404 answered in %v, want < 40ms (no X-Powered-By, no delay)", elapsed)
	}
}
