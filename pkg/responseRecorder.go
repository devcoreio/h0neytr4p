package h0neytr4p

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"net/http"
)

// responseRecorder wraps an http.ResponseWriter and remembers what was
// actually sent: the first status code written, the number of body bytes the
// underlying writer accepted, and a running SHA-256 of those bytes.
type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	hash   hash.Hash
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w, hash: sha256.New()}
}

// WriteHeader records the first status code only; later calls are passed
// through (net/http ignores them) but do not change the recorded value.
func (rr *responseRecorder) WriteHeader(code int) {
	if rr.status == 0 {
		rr.status = code
	}
	rr.ResponseWriter.WriteHeader(code)
}

// Write delegates to the wrapped writer and counts and hashes only the bytes
// it accepted, so a client that disconnects mid-body is logged truthfully.
func (rr *responseRecorder) Write(p []byte) (int, error) {
	n, err := rr.ResponseWriter.Write(p)
	if n > 0 {
		rr.bytes += int64(n)
		rr.hash.Write(p[:n])
	}
	return n, err
}

// Status is the recorded status code, or 200 when the handler never called
// WriteHeader (Go's implicit status).
func (rr *responseRecorder) Status() int {
	if rr.status == 0 {
		return http.StatusOK
	}
	return rr.status
}

func (rr *responseRecorder) Bytes() int64 { return rr.bytes }

// SHA256 is the lower-case hex digest of the body bytes sent, or "" when none.
func (rr *responseRecorder) SHA256() string {
	if rr.bytes == 0 {
		return ""
	}
	return hex.EncodeToString(rr.hash.Sum(nil))
}
