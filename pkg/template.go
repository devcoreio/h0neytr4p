package h0neytr4p

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Response templating. Tokens are rendered per response so that persona
// values which a real server generates per request (session ids, CSRF
// tokens) do not repeat across captures.
//
//	{{sid}}           26 chars of [0-9a-v] (PHP 8.3 default session id)
//	{{rand_hex:N}}    N lowercase hex chars
//	{{rand_alnum:N}}  N chars of [A-Za-z0-9]
//
// Unknown tokens are left untouched.
var templateToken = regexp.MustCompile(`\{\{(sid|rand_hex:\d+|rand_alnum:\d+)\}\}`)

const (
	sidAlphabet   = "0123456789abcdefghijklmnopqrstuv"
	alnumAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	sidLength     = 26
)

func randomString(alphabet string, n int) string {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("crypto/rand unavailable: " + err.Error())
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out)
}

func randomHex(n int) string {
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(buf)[:n]
}

func newSID() string {
	return randomString(sidAlphabet, sidLength)
}

// RenderTemplate substitutes every supported token in s with a fresh value.
func RenderTemplate(s string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return templateToken.ReplaceAllStringFunc(s, func(tok string) string {
		inner := tok[2 : len(tok)-2]
		switch {
		case inner == "sid":
			return newSID()
		case strings.HasPrefix(inner, "rand_hex:"):
			n, _ := strconv.Atoi(strings.TrimPrefix(inner, "rand_hex:"))
			return randomHex(n)
		case strings.HasPrefix(inner, "rand_alnum:"):
			n, _ := strconv.Atoi(strings.TrimPrefix(inner, "rand_alnum:"))
			return randomString(alnumAlphabet, n)
		}
		return tok
	})
}

// requestHasCookie reports whether any Cookie header names the cookie, even
// with an empty value (PHP treats "PHPSESSID=" as a present cookie).
func requestHasCookie(r *http.Request, name string) bool {
	for _, header := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			if strings.HasPrefix(strings.TrimSpace(part), name+"=") {
				return true
			}
		}
	}
	return false
}
