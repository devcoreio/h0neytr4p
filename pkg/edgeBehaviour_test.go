package h0neytr4p

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rawSend writes req to addr and returns everything the server sent before closing.
func rawSend(t *testing.T, addr, req string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(bufio.NewReader(conn))
	return string(out)
}

// A Go reverse proxy in front of the application (PAN-OS GlobalProtect) refuses
// a request without a Host header, HTTP/1.0 included, with the reason in the
// status line. net/http only does that for HTTP/1.1.
func TestServerRejectMissingHostOnHTTP10(t *testing.T) {
	configureTestIO(t)
	fb := testFallback()
	fb.RejectMissingHost = true
	SetFallback(fb)
	t.Cleanup(func() { SetFallback(nil) })
	addr := strings.TrimPrefix(startServer(t, []Trap{loginTrap()}).URL, "http://")

	got := rawSend(t, addr, "GET /login/index.php HTTP/1.0\r\n\r\n")
	head, body, _ := strings.Cut(got, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	if lines[0] != "HTTP/1.1 400 Bad Request: missing required Host header" {
		t.Fatalf("status line = %q", lines[0])
	}
	if body != "400 Bad Request: missing required Host header" {
		t.Fatalf("body = %q", body)
	}
	for _, want := range []string{"Content-Type: text/plain; charset=utf-8", "Connection: close"} {
		if !strings.Contains(head, "\r\n"+want) {
			t.Errorf("missing header %q in %q", want, head)
		}
	}
	if !strings.Contains(head, "\r\nDate: ") {
		t.Errorf("no Date header in %q", head)
	}

	// The HTTP/2 preface is not a missing-Host case; it goes to the traps and fallback.
	if got := rawSend(t, addr, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); strings.Contains(got, "missing required Host header") {
		t.Fatalf("preface answered as missing Host: %q", strings.SplitN(got, "\r\n", 2)[0])
	}

	// With a Host header the same request is served normally.
	if got := rawSend(t, addr, "GET /login/index.php HTTP/1.0\r\nHost: example.test\r\n\r\n"); !strings.HasPrefix(got, "HTTP/1.0 200 ") {
		t.Fatalf("with Host: %q", strings.SplitN(got, "\r\n", 2)[0])
	}
}

// Without the option an HTTP/1.0 request with no Host header is served, as before.
func TestServerMissingHostServedByDefault(t *testing.T) {
	configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })
	addr := strings.TrimPrefix(startServer(t, []Trap{loginTrap()}).URL, "http://")
	if got := rawSend(t, addr, "GET /login/index.php HTTP/1.0\r\n\r\n"); !strings.HasPrefix(got, "HTTP/1.0 200 ") {
		t.Fatalf("status line = %q", strings.SplitN(got, "\r\n", 2)[0])
	}
}

func writeTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)
	return certFile, keyFile
}

// The NoALPN listener answers a client that offers h2 and http/1.1 with no
// protocol, and still serves HTTP/1.1 over the connection.
func TestTLSListenerWithoutALPNNegotiatesNothing(t *testing.T) {
	configureTestIO(t)
	certFile, keyFile := writeTestCert(t)
	ln, err := newTLSListenerWithoutALPN("127.0.0.1:0", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	server := newServer("0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	go server.Serve(ln)
	t.Cleanup(func() { server.Close() })

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "" {
		t.Fatalf("negotiated ALPN %q, want none", got)
	}
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("request over the no-ALPN listener: %v %v", resp, err)
	}
}
