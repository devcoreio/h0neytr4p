package h0neytr4p

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecorderCapturesStatusBytesHash(t *testing.T) {
	rr := newResponseRecorder(httptest.NewRecorder())
	rr.WriteHeader(http.StatusSeeOther)
	if _, err := rr.Write([]byte("abc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if rr.Status() != 303 || rr.Bytes() != 3 || rr.SHA256() != want {
		t.Fatalf("status=%d bytes=%d sha=%q", rr.Status(), rr.Bytes(), rr.SHA256())
	}
}

func TestRecorderImplicit200(t *testing.T) {
	rr := newResponseRecorder(httptest.NewRecorder())
	rr.Write([]byte("x"))
	if rr.Status() != 200 || rr.Bytes() != 1 {
		t.Fatalf("status=%d bytes=%d", rr.Status(), rr.Bytes())
	}
}

func TestRecorderNothingWritten(t *testing.T) {
	rr := newResponseRecorder(httptest.NewRecorder())
	if rr.Status() != 200 || rr.Bytes() != 0 || rr.SHA256() != "" {
		t.Fatalf("status=%d bytes=%d sha=%q", rr.Status(), rr.Bytes(), rr.SHA256())
	}
}

func TestRecorderFirstStatusWins(t *testing.T) {
	rr := newResponseRecorder(httptest.NewRecorder())
	rr.WriteHeader(404)
	rr.WriteHeader(500)
	if rr.Status() != 404 {
		t.Fatalf("status=%d, want 404", rr.Status())
	}
}

// shortWriter accepts only the first two bytes of any write and reports a closed pipe.
type shortWriter struct{ h http.Header }

func (s *shortWriter) Header() http.Header {
	if s.h == nil {
		s.h = http.Header{}
	}
	return s.h
}
func (s *shortWriter) WriteHeader(int) {}
func (s *shortWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n > 2 {
		n = 2
	}
	return n, io.ErrClosedPipe
}

func TestRecorderCountsOnlyAcceptedBytes(t *testing.T) {
	rr := newResponseRecorder(&shortWriter{})
	n, err := rr.Write([]byte("abcd"))
	if n != 2 || err == nil {
		t.Fatalf("n=%d err=%v, want 2 and an error", n, err)
	}
	want := "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"
	if rr.Bytes() != 2 || rr.SHA256() != want {
		t.Fatalf("bytes=%d sha=%q", rr.Bytes(), rr.SHA256())
	}
}
