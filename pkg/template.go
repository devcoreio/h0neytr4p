package h0neytr4p

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
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

// Request-derived tokens let a captured page reflect the live request the way
// Apache and PHP do (error-page footers, phpinfo's $_SERVER rows). Values are
// HTML-escaped, so attacker-controlled headers cannot inject markup.
//
//	{{req_host}}         Host header without port (RemoteAddr host if absent)
//	{{req_port}}         server port as seen by the request (Host port, else 443/80)
//	{{req_ip}}           client IP (RemoteAddr)
//	{{req_remote_port}}  client port
//	{{req_ua}}           User-Agent header
//	{{req_accept}}       Accept header
//	{{req_time}}         unix seconds; {{req_time_float}} with 4 decimals
var requestToken = regexp.MustCompile(`\{\{(req_host|req_port|req_ip|req_remote_port|req_ua|req_accept|req_time|req_time_float)\}\}`)

// RenderRequestTemplate substitutes the request-derived tokens in s.
func RenderRequestTemplate(s string, r *http.Request) string {
	if r == nil || !strings.Contains(s, "{{req_") {
		return s
	}
	now := time.Now()
	return requestToken.ReplaceAllStringFunc(s, func(tok string) string {
		var v string
		switch tok[2 : len(tok)-2] {
		case "req_host":
			v = GetHostname(r)
			if v == "" {
				v = GetIP(r)
			}
		case "req_port":
			v = GetPort(r)
		case "req_ip":
			v = GetIP(r)
		case "req_remote_port":
			if _, port, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				v = port
			}
		case "req_ua":
			v = r.Header.Get("User-Agent")
		case "req_accept":
			v = r.Header.Get("Accept")
		case "req_time":
			v = strconv.FormatInt(now.Unix(), 10)
		case "req_time_float":
			v = fmt.Sprintf("%.4f", float64(now.UnixMicro())/1e6)
		}
		return html.EscapeString(v)
	})
}
