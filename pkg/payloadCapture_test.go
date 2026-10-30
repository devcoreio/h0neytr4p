package h0neytr4p

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Capture-path contract for bodies the multipart parser cannot finish: the
// request is answered with the normal persona page, logged once, flagged
// payload_truncated, and a bounded raw prefix of the body is kept as evidence.
// Body params stay empty, as PHP's superglobals do past its limits.

// manyPartMultipart returns a body whose first field is the upload-progress
// marker followed by n empty fields (the CVE-2026-109618 "nested empty file"
// shape), well under the byte cap.
func manyPartMultipart(t *testing.T, n int) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormField("PHP_SESSION_UPLOAD_PROGRESS")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("k")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := mw.CreateFormField(fmt.Sprintf("f[%d][x]", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), mw.FormDataContentType()
}

// headerFloodMultipart returns a body with one file part whose headers never
// end: lines of "a:b" with no blank line before the closing boundary.
func headerFloodMultipart(lines int) ([]byte, string) {
	var buf bytes.Buffer
	buf.WriteString("--flood\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"a.txt\"\r\n")
	buf.WriteString(strings.Repeat("a:b\r\n", lines))
	buf.WriteString("--flood--\r\n")
	return buf.Bytes(), "multipart/form-data; boundary=flood"
}

// assertBodyNotDropped drives body through the catch-all handler with the
// fallback persona and checks the no-drop contract, then returns the payload
// captureRequestPayload produces for the same body.
func assertBodyNotDropped(t *testing.T, body []byte, contentType string, wantInPrefix string) requestPayload {
	t.Helper()
	logPath, _ := configureTestIO(t)
	SetFallback(testFallback())
	t.Cleanup(func() { SetFallback(nil) })

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	allHandler(nil, true).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "<h1>Not Found</h1>") {
		t.Fatalf("status %d body %.120q, want the fallback persona page", rec.Code, rec.Body.String())
	}
	logContent := readTestLog(t, logPath)
	if entries := strings.Count(strings.TrimSpace(logContent), "\n") + 1; entries != 1 {
		t.Fatalf("log entries = %d, want 1: %.300s", entries, logContent)
	}
	for _, want := range []string{`"payload_truncated":"true"`, `"payload":"`, wantInPrefix} {
		if !strings.Contains(logContent, want) {
			t.Fatalf("log missing %s: %.300s", want, logContent)
		}
	}
	if strings.Contains(logContent, `"payload_parameter"`) {
		t.Fatalf("log merged body params for an unparseable body: %.300s", logContent)
	}
	if len(logContent) > 2*MaxStoredPayload {
		t.Fatalf("log entry %d bytes, stored prefix not bounded", len(logContent))
	}

	req2 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	if contentType != "" {
		req2.Header.Set("Content-Type", contentType)
	}
	got, err := captureRequestPayload(httptest.NewRecorder(), req2, newRequestPayload(req2))
	if err != nil {
		t.Fatalf("captureRequestPayload() error = %v, want nil (request must not be dropped)", err)
	}
	if len(got.params) != 0 {
		t.Fatalf("body params merged: %d params", len(got.params))
	}
	if !got.truncated || len(got.data) == 0 || len(got.data) > MaxStoredPayload {
		t.Fatalf("truncated=%v stored=%d bytes, want truncated and 1..%d bytes", got.truncated, len(got.data), MaxStoredPayload)
	}
	return got
}

func TestAllHandlerManyPartMultipartNotDropped(t *testing.T) {
	t.Setenv("GODEBUG", "multipartmaxparts=1000")
	body, contentType := manyPartMultipart(t, 1001)
	if len(body) >= MaxMultipartSize {
		t.Fatalf("test body %d bytes is not under the byte cap", len(body))
	}
	assertBodyNotDropped(t, body, contentType, "PHP_SESSION_UPLOAD_PROGRESS")
}

func TestAllHandlerMalformedMultipartNotDropped(t *testing.T) {
	body := []byte("--abc\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nv\r\n--zzz garbage without a closing boundary")
	got := assertBodyNotDropped(t, body, "multipart/form-data; boundary=abc", "garbage without")
	if got.data != string(body) {
		t.Fatalf("prefix of a short unparseable body not kept whole: %q", got.data)
	}
}

func TestAllHandlerHeaderFloodMultipartNotDropped(t *testing.T) {
	t.Setenv("GODEBUG", "multipartmaxheaders=10000")
	body, contentType := headerFloodMultipart(20000)
	assertBodyNotDropped(t, body, contentType, "a.txt")
}

func TestAllHandlerDeclaredOverCapMultipartKeepsPrefix(t *testing.T) {
	logPath, _ := configureTestIO(t)
	req, _ := oversizedMultipartRequest(t, "/upload", overCapSize)
	if req.ContentLength <= MaxMultipartSize {
		t.Fatalf("ContentLength %d not over cap", req.ContentLength)
	}
	rec := httptest.NewRecorder()
	allHandler(nil, true).ServeHTTP(rec, req)

	logContent := readTestLog(t, logPath)
	for _, want := range []string{`"payload_truncated":"true"`, `"payload":"`, `blob`} {
		if !strings.Contains(logContent, want) {
			t.Fatalf("log missing %s: %.300s", want, logContent)
		}
	}
	if strings.Contains(logContent, `"payload_parameter"`) {
		t.Fatalf("over-cap body merged params: %.300s", logContent)
	}

	req2, _ := oversizedMultipartRequest(t, "/upload", overCapSize)
	got, err := captureRequestPayload(httptest.NewRecorder(), req2, newRequestPayload(req2))
	if err != nil {
		t.Fatalf("captureRequestPayload() error = %v", err)
	}
	if len(got.params) != 0 || !got.truncated || len(got.data) != MaxStoredPayload {
		t.Fatalf("params=%d truncated=%v stored=%d, want 0/true/%d", len(got.params), got.truncated, len(got.data), MaxStoredPayload)
	}
}
