package h0neytr4p

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/ryanuber/go-glob"
	"github.com/ua-parser/uap-go/uaparser"
)

var uaParser *uaparser.Parser

type requestPayload struct {
	data      string
	parameter string
	hashMD5   string
	filename  string
	mimeType  string
	params    map[string]string
	truncated bool // body exceeded a cap or the stored raw body was cut to MaxStoredPayload
}

func init() {
	uaParser = uaparser.NewFromSaved() // Loads the default regexes
}

func computeMD5(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func convertMap(mapInterface map[string]interface{}) map[string]string {
	mapString := make(map[string]string)
	for key, value := range mapInterface {
		strKey := fmt.Sprintf("%v", key)
		strValue := fmt.Sprintf("%v", value)
		mapString[strKey] = strValue
	}
	return mapString
}

func match(first string, second string) bool {
	return glob.Glob(first, second)
}

func getRequestHeader(ruleHeader string, requestHeaders http.Header) string {
	if strings.EqualFold(ruleHeader, "Authorization-Basic-Decoded") {
		return decodeBasicAuthorization(requestHeaders.Get("Authorization"))
	}
	return requestHeaders.Get(ruleHeader)
}

func getRequestHeaderValue(ruleHeader string, requestHeaders http.Header) (string, bool) {
	if strings.EqualFold(ruleHeader, "Authorization-Basic-Decoded") {
		decoded := decodeBasicAuthorization(requestHeaders.Get("Authorization"))
		return decoded, decoded != ""
	}
	values := requestHeaders.Values(ruleHeader)
	return requestHeaders.Get(ruleHeader), len(values) > 0
}

func decodeBasicAuthorization(headerValue string) string {
	scheme, value, found := strings.Cut(headerValue, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return string(decoded)
}

func CheckHeaders(ruleHeaders map[string]string, requestHeaders http.Header) bool {
	for k, v := range ruleHeaders {
		requestValue, found := getRequestHeaderValue(k, requestHeaders)
		if v != "" && !found {
			return false
		}
		if !match(v, requestValue) {
			return false
		}
	}
	return true
}

func CheckParams(ruleParams map[string]string, requestParams map[string]string) bool {
	for k, v := range ruleParams {
		requestValue, found := requestParams[k]
		if v != "" && !found {
			return false
		}
		if !match(v, requestValue) {
			return false
		}
	}
	return true
}

func CheckProto(ruleProto string, requestProto string) bool {
	if ruleProto == "" {
		return true
	}
	return match(ruleProto, requestProto)
}

func GetFlatHeaders(r *http.Request) map[string]string {
	flatHeaders := make(map[string]string)
	for key, values := range r.Header {
		if len(values) == 0 {
			continue
		}
		if strings.EqualFold(key, "Content-Type") {
			flatHeaders["header_"+strings.ToLower(key)] = normalizeContentType(values[0])
		} else {
			flatHeaders["header_"+strings.ToLower(key)] = strings.Join(values, ", ")
		}
	}
	return flatHeaders
}

func GetFlatCookies(r *http.Request) map[string]string {
	flatCookies := make(map[string]string)
	for _, cookie := range r.Cookies() {
		flatCookies["cookie_"+strings.ToLower(cookie.Name)] = cookie.Value
	}
	return flatCookies
}

func GetHostname(r *http.Request) string {
	host := r.Host
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(parsedHost, "[]")
	}
	if strings.Count(host, ":") == 1 {
		parsedHost, _, _ := strings.Cut(host, ":")
		return parsedHost
	}
	return strings.Trim(host, "[]")
}

// GetIP returns the peer address of the TCP connection. X-Forwarded-For is
// deliberately ignored: this honeypot is never behind a trusted proxy and the
// header is attacker-controlled. It is still logged as header_x-forwarded-for.
func GetIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return ip
	}
	return r.RemoteAddr
}

func GetPort(r *http.Request) string {
	if _, port, err := net.SplitHostPort(r.Host); err == nil {
		return port
	}
	if strings.Count(r.Host, ":") == 1 {
		_, port, _ := strings.Cut(r.Host, ":")
		return port
	}
	if r.TLS != nil {
		return "443"
	}
	return "80"
}

func GetProtocol(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func normalizeContentType(raw string) string {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err == nil {
		return strings.ToLower(mediaType)
	}
	return strings.ToLower(strings.TrimSpace(strings.Split(raw, ";")[0]))
}

func requestContentType(r *http.Request) string {
	return normalizeContentType(r.Header.Get("Content-Type"))
}

func isPayloadMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func payloadSizeLimit(contentType string) int64 {
	if contentType == "multipart/form-data" {
		return MaxMultipartSize
	}
	return MaxJSONFormSize
}

func flattenValues(values url.Values) map[string]string {
	params := make(map[string]string, len(values))
	for key, vals := range values {
		params[key] = strings.Join(vals, "|")
	}
	return params
}

func cloneParams(params map[string]string) map[string]string {
	cloned := make(map[string]string, len(params))
	for key, value := range params {
		cloned[key] = value
	}
	return cloned
}

func mergeParams(dst map[string]string, src map[string]string) {
	for key, value := range src {
		dst[key] = value
	}
}

func formatParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, params[key]))
	}
	return strings.Join(parts, ",")
}

func splitParams(raw string) map[string]string {
	params := make(map[string]string)
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		key, value, found := strings.Cut(part, "=")
		if !found {
			value = ""
		}
		params[key] = value
	}
	return params
}

func parseBodyParams(raw string) map[string]string {
	if raw == "" {
		return map[string]string{}
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return splitParams(raw)
	}
	return flattenValues(values)
}

func parseJSONBodyParams(body []byte) map[string]string {
	if len(body) == 0 {
		return map[string]string{}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()

	var values map[string]interface{}
	if err := decoder.Decode(&values); err != nil {
		return map[string]string{}
	}
	return convertMap(values)
}

// readLimited reads at most limit bytes. When the reader holds more, it
// returns the first limit bytes and overflow=true.
func readLimited(reader io.Reader, limit int64) (data []byte, overflow bool, err error) {
	data, err = io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

// storeRaw keeps at most MaxStoredPayload bytes of a raw body in the payload.
func (p *requestPayload) storeRaw(s string) {
	if len(s) > MaxStoredPayload {
		s = s[:MaxStoredPayload]
		p.truncated = true
	}
	p.data = s
}

// storeParameter keeps at most MaxStoredPayload bytes of the formatted body
// params in the log entry; trap matching still sees the full values.
func (p *requestPayload) storeParameter(s string) {
	if len(s) > MaxStoredPayload {
		s = s[:MaxStoredPayload]
		p.truncated = true
	}
	p.parameter = s
}

// overCap mimics PHP past post_max_size: body superglobals stay empty, only a
// bounded prefix of the raw body is kept, and the request is flagged.
func (p *requestPayload) overCap(body io.Reader, prefix []byte) {
	p.truncated = true
	if body != nil {
		rest, _ := io.ReadAll(io.LimitReader(body, int64(MaxStoredPayload-len(prefix))))
		prefix = append(prefix, rest...)
	}
	if len(prefix) > MaxStoredPayload {
		prefix = prefix[:MaxStoredPayload]
	}
	p.data = string(prefix)
}

// reparsePrefixParams recovers the leading form fields from the bounded raw
// multipart prefix kept when the full parse failed. A flood body (variant B:
// thousands of empty parts) carries its real fields up front, inside the 64 KB
// prefix, so the first complete value parts are still readable even though the
// whole body was not. This mirrors PHP keeping the first max_input_vars (1000)
// variables and dropping the overflow, and lets the upload-progress trap fire
// on these bodies. The prefix usually cuts the final part short, so a read
// error ends the scan and the fields before it are kept; a header flood
// (variant A) leaves no complete part in the prefix and yields nothing.
func reparsePrefixParams(contentTypeHeader, prefix string) map[string]string {
	_, params, err := mime.ParseMediaType(contentTypeHeader)
	if err != nil {
		return nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}
	mr := multipart.NewReader(strings.NewReader(prefix), boundary)
	recovered := make(map[string]string)
	const maxParts = 1000      // PHP max_input_vars; also bounds the scan
	const maxValueBytes = 8192 // a field value is small; the flood is not
	for i := 0; i < maxParts; i++ {
		part, err := mr.NextPart()
		if err != nil {
			break // clean EOF, or the prefix cut the stream mid-part
		}
		name := part.FormName()
		if name == "" || part.FileName() != "" {
			_ = part.Close()
			continue // only named value fields are form params
		}
		val, readErr := io.ReadAll(io.LimitReader(part, maxValueBytes))
		_ = part.Close()
		// Keep only a field whose value ended on a boundary; a read error
		// means the prefix cut this part short (or the body never closes it),
		// so the value is unreliable. Empty flood parts carry nothing.
		if readErr != nil || len(val) == 0 {
			continue
		}
		if _, seen := recovered[name]; !seen {
			recovered[name] = string(val)
		}
	}
	return recovered
}

// prefixCapture is an io.Writer that keeps the first max bytes it sees and
// silently discards the rest, so it can tee a body of any size.
type prefixCapture struct {
	buf []byte
	max int
}

func (p *prefixCapture) Write(b []byte) (int, error) {
	if room := p.max - len(p.buf); room > 0 {
		if len(b) > room {
			p.buf = append(p.buf, b[:room]...)
		} else {
			p.buf = append(p.buf, b...)
		}
	}
	return len(b), nil
}

// teeBody tees a request body through a prefixCapture while keeping Close.
type teeBody struct {
	io.Reader
	io.Closer
}

// errOverCap is returned by capReader once a body runs past its cap.
var errOverCap = errors.New("body exceeds cap")

// capReader fails reads with errOverCap once more than limit bytes have passed
// through it. Unlike http.MaxBytesReader it does not tell the server the body
// was too large, so net/http never forces Connection: close and the handler
// can still drain the remainder and keep the connection alive, as Apache does.
type capReader struct {
	r         io.Reader
	remaining int64
}

func newCapReader(r io.Reader, limit int64) *capReader {
	return &capReader{r: r, remaining: limit}
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.remaining < 0 {
		return 0, errOverCap
	}
	// Ask for at most one byte past the cap: enough to detect the overrun
	// without consuming far beyond it.
	if int64(len(p)) > c.remaining+1 {
		p = p[:c.remaining+1]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	if c.remaining < 0 {
		return n, errOverCap
	}
	return n, err
}

// drainBody reads and discards up to limit bytes of body and returns how many
// it drained. Apache reads a request body in full before answering, so the
// connection stays reusable; the time spent is bounded by the server
// ReadTimeout and the bytes by MaxDrainSize.
func drainBody(body io.Reader, limit int64) int64 {
	if body == nil {
		return 0
	}
	n, _ := io.Copy(io.Discard, io.LimitReader(body, limit))
	return n
}

// countingBody counts every byte read from a request body, by the capture step
// and the drain alike, so a chunked body's real length is known.
type countingBody struct {
	io.ReadCloser
	n int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	return n, err
}

// requestBodyLength is the declared Content-Length, or for a chunked body the
// number of bytes actually read from it.
func requestBodyLength(r *http.Request, counted int64) int64 {
	if r.ContentLength >= 0 {
		return r.ContentLength
	}
	return counted
}

func newRequestPayload(r *http.Request) requestPayload {
	return requestPayload{
		params: flattenValues(r.URL.Query()),
	}
}

func captureRequestPayload(w http.ResponseWriter, r *http.Request, payload requestPayload) (requestPayload, error) {
	payload.params = cloneParams(payload.params)
	if !isPayloadMethod(r.Method) {
		return payload, nil
	}

	contentType := requestContentType(r)
	sizeLimit := payloadSizeLimit(contentType)
	// Over-cap bodies are never rejected (PHP answers 200 with empty
	// superglobals); a declared oversize length skips parsing entirely.
	if r.ContentLength > sizeLimit {
		payload.overCap(r.Body, nil)
		return payload, nil
	}

	switch contentType {
	case "application/json":
		bodyBytes, overflow, err := readLimited(r.Body, sizeLimit)
		if err != nil {
			return payload, fmt.Errorf("read JSON body: %w", err)
		}
		if overflow {
			payload.overCap(nil, bodyBytes)
			return payload, nil
		}
		payload.storeRaw(string(bodyBytes))
		mergeParams(payload.params, parseJSONBodyParams(bodyBytes))
	case "multipart/form-data":
		// The body is teed into a bounded prefix so evidence survives when the
		// parser gives up. Go's part and header limits (multipartmaxparts=1000,
		// multipartmaxheaders=10000) are deliberately left at their defaults:
		// PHP's max_input_vars is 1000 too, the raw prefix already shows the
		// shape of a flood, and a higher limit only buys heap for the attacker.
		// capReader (not http.MaxBytesReader) enforces the cap so net/http is
		// never told the body was too large and does not close the connection.
		// r.Body is restored afterwards so the handler drains the remainder.
		orig := r.Body
		prefix := &prefixCapture{max: MaxStoredPayload}
		capped := newCapReader(orig, sizeLimit)
		r.Body = teeBody{Reader: io.TeeReader(capped, prefix), Closer: orig}
		defer func() { r.Body = orig }()
		if err := r.ParseMultipartForm(sizeLimit); err != nil {
			// Any parse failure (over cap, too many parts or headers, malformed
			// boundary) mimics PHP past its limits: empty superglobals, normal
			// response. The parser may stop after one buffer, so the prefix is
			// topped up from the body; the handler drains whatever is left.
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
			payload.overCap(orig, prefix.buf)
			// Recover the leading fields from the prefix so the
			// upload-progress trap can still match and
			// payload_parameter is populated on these bodies.
			if recovered := reparsePrefixParams(r.Header.Get("Content-Type"), payload.data); len(recovered) > 0 {
				mergeParams(payload.params, recovered)
				payload.storeParameter(formatParams(recovered))
			}
			log.Printf("multipart parse failed, kept %d-byte prefix: %v", len(payload.data), err)
			return payload, nil
		}
		if r.MultipartForm == nil {
			return payload, nil
		}
		defer r.MultipartForm.RemoveAll()

		bodyParams := make(map[string]string)
		payloadParams := make(map[string]string)
		for key, values := range r.MultipartForm.Value {
			joined := strings.Join(values, "|")
			bodyParams[key] = joined
			if key != "file" {
				payloadParams[key] = joined
			}
		}
		mergeParams(payload.params, bodyParams)
		payload.storeParameter(formatParams(payloadParams))

		for _, files := range r.MultipartForm.File {
			for _, fileHeader := range files {
				file, err := fileHeader.Open()
				if err != nil {
					log.Printf("Error opening file: %v", err)
					continue
				}
				fileBytes, _, err := readLimited(file, MaxMultipartSize)
				closeErr := file.Close()
				if err != nil {
					log.Printf("Error reading file: %v", err)
					continue
				}
				if closeErr != nil {
					log.Printf("Error closing file: %v", closeErr)
					continue
				}

				payload.hashMD5 = computeMD5(fileBytes)
				payload.filename = filepath.Join(payloadFolder, payload.hashMD5)
				payload.mimeType = fileHeader.Header.Get("Content-Type")
				if payload.mimeType == "" {
					payload.mimeType = http.DetectContentType(fileBytes)
				}

				if err := os.WriteFile(payload.filename, fileBytes, RuntimeFileMode); err != nil {
					log.Printf("Error saving file: %v", err)
					continue
				}
				if err := os.Chmod(payload.filename, RuntimeFileMode); err != nil {
					log.Printf("Error setting payload file mode: %v", err)
					continue
				}
			}
		}
	case "application/x-www-form-urlencoded":
		bodyBytes, overflow, err := readLimited(r.Body, sizeLimit)
		if err != nil {
			return payload, fmt.Errorf("read form body: %w", err)
		}
		if overflow {
			payload.overCap(nil, bodyBytes)
			return payload, nil
		}
		bodyParams := parseBodyParams(string(bodyBytes))
		mergeParams(payload.params, bodyParams)
		payload.storeRaw(formatParams(bodyParams))
	case "text/plain":
		bodyBytes, overflow, err := readLimited(r.Body, sizeLimit)
		if err != nil {
			return payload, fmt.Errorf("read text body: %w", err)
		}
		if overflow {
			payload.overCap(nil, bodyBytes)
			return payload, nil
		}
		payload.storeRaw(string(bodyBytes))
		mergeParams(payload.params, parseBodyParams(string(bodyBytes)))
	default:
		// No or unlisted Content-Type (octet-stream, xml, ...): PHP leaves
		// $_POST empty but php://input has the body, so keep a bounded raw
		// prefix and merge nothing.
		bodyBytes, overflow, err := readLimited(r.Body, sizeLimit)
		if err != nil {
			return payload, fmt.Errorf("read raw body: %w", err)
		}
		if overflow {
			payload.overCap(nil, bodyBytes)
			return payload, nil
		}
		payload.storeRaw(string(bodyBytes))
	}

	return payload, nil
}

// methodMatches compares a trap's Method with the request's. HEAD is served
// by GET behaviours (as Apache and net/http do) unless a HEAD-specific
// behaviour appears earlier in trap order.
func methodMatches(ruleMethod string, requestMethod string) bool {
	if ruleMethod == requestMethod {
		return true
	}
	return requestMethod == http.MethodHead && ruleMethod == http.MethodGet
}

func hasMatchingRequest(trapConfig []Trap, method string, path string) bool {
	for _, trap := range trapConfig {
		for _, behaviour := range trap.Behaviour {
			if methodMatches(behaviour.Request.Method, method) && match(behaviour.Request.URL, path) {
				return true
			}
		}
	}
	return false
}

func headerContainsMatch(ruleHeaders map[string][]string, requestHeaders http.Header) bool {
	for headerKey, substrings := range ruleHeaders {
		reqHeaderVal := getRequestHeader(headerKey, requestHeaders)
		for _, substr := range substrings {
			if strings.Contains(reqHeaderVal, substr) {
				return true
			}
		}
	}
	return false
}

func buildLogDetails(r *http.Request, ua *uaparser.Client, payload requestPayload, trapped bool) map[string]string {
	details := map[string]string{
		"timestamp":          time.Now().Format(time.RFC3339),
		"src_ip":             GetIP(r),
		"dest_port":          GetPort(r),
		"request_method":     r.Method,
		"protocol":           GetProtocol(r),
		"request_proto":      r.Proto,
		"hostname":           GetHostname(r),
		"request_uri":        r.RequestURI,
		"user-agent_browser": ua.UserAgent.Family,
		"user-agent_os":      ua.Os.Family,
		"trapped":            strconv.FormatBool(trapped),
		"user-agent":         r.Header.Get("User-Agent"),
	}
	if payload.parameter != "" {
		details["payload_parameter"] = payload.parameter
	}
	if payload.hashMD5 != "" {
		details["payload_hash_md5"] = payload.hashMD5
		details["payload_filename"] = payload.filename
		details["payload_mime_type"] = payload.mimeType
	}
	if payload.truncated {
		details["payload_truncated"] = "true"
	}
	if payload.data != "" {
		details["payload"] = payload.data
	}
	for key, value := range GetFlatHeaders(r) {
		details[key] = value
	}
	for key, value := range GetFlatCookies(r) {
		details[key] = value
	}
	if ua.Device.Brand != "" {
		details["user-agent_device_brand"] = ua.Device.Brand
	}
	if ua.Device.Model != "" {
		details["user-agent_device_model"] = ua.Device.Model
	}
	if ua.UserAgent.Major != "" || ua.UserAgent.Minor != "" {
		details["user-agent_browser_version"] = fmt.Sprintf("%s.%s", ua.UserAgent.Major, ua.UserAgent.Minor)
	}
	if ua.Os.Major != "" || ua.Os.Minor != "" {
		details["user-agent_os_version"] = fmt.Sprintf("%s.%s", ua.Os.Major, ua.Os.Minor)
	}
	return details
}

func logDetails(details map[string]string) {
	if err := LogEntry(details); err != nil {
		log.Printf("Error writing log entry: %v", err)
	}
}

// connRequestCount counts the requests served on one connection.
type connRequestCount struct{ n int32 }

type connCountKey struct{}

type reqNumKey struct{}

// maxKeepAliveRequests is Apache's MaxKeepAliveRequests default.
const maxKeepAliveRequests = 100

// requestNumber increments and returns the connection's request counter (1
// for the first request); 1 when the connection has no counter.
func requestNumber(r *http.Request) int32 {
	c, ok := r.Context().Value(connCountKey{}).(*connRequestCount)
	if !ok {
		return 1
	}
	return atomic.AddInt32(&c.n, 1)
}

// reqNumFrom returns the request number allHandler stored on the request
// context (1 when absent).
func reqNumFrom(r *http.Request) int32 {
	if n, ok := r.Context().Value(reqNumKey{}).(int32); ok {
		return n
	}
	return 1
}

// wantsKeepAlive reports whether the client's Connection header carries a
// keep-alive token and no close token.
func wantsKeepAlive(h http.Header) bool {
	keepAlive := false
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			switch {
			case strings.EqualFold(strings.TrimSpace(tok), "close"):
				return false
			case strings.EqualFold(strings.TrimSpace(tok), "keep-alive"):
				keepAlive = true
			}
		}
	}
	return keepAlive
}

// applyApacheConnectionHeaders mimics Apache 2.4 with KeepAlive On,
// KeepAliveTimeout 5, MaxKeepAliveRequests 100: a client that asks for
// keep-alive gets Keep-Alive/Connection headers with max counting down per
// request; an HTTP/1.1 client that does not ask gets neither; an HTTP/1.0
// client that does not ask gets Connection: close. Apache buffers an HTTP/1.0
// keep-alive response to frame it with a Content-Length (and Go would
// otherwise close the connection and drop the Connection header), so set one
// unless the trap did; bodyLen is the body a GET would carry, so HEAD reports
// the same length. Past MaxKeepAliveRequests (request 101 on a connection)
// Apache answers Connection: close with no Keep-Alive header and closes; Go
// closes the connection when the handler sets Connection: close.
func applyApacheConnectionHeaders(w http.ResponseWriter, r *http.Request, n int32, bodyLen int) {
	h := w.Header()
	if n > maxKeepAliveRequests {
		h.Set("Connection", "close")
		return
	}
	if wantsKeepAlive(r.Header) {
		h.Set("Keep-Alive", fmt.Sprintf("timeout=5, max=%d", maxKeepAliveRequests+1-n))
		h.Set("Connection", "Keep-Alive")
		if !r.ProtoAtLeast(1, 1) && h.Get("Content-Length") == "" {
			h.Set("Content-Length", strconv.Itoa(bodyLen))
		}
		return
	}
	if !r.ProtoAtLeast(1, 1) {
		h.Set("Connection", "close")
	}
}

// isPHPResponse reports whether a response is one PHP would have generated:
// the persona's PHP pages carry X-Powered-By, while static assets and Apache's
// own error documents do not.
func isPHPResponse(resp Response) bool {
	for key := range resp.Headers {
		if strings.EqualFold(key, "X-Powered-By") {
			return true
		}
	}
	return false
}

// responseDelay is how long a PHP response waits before it is written, so
// that a scanner timing a PHP path against a static 404 sees PHP's cost:
// PhpBaseMs plus the caller's jitter sample, plus PhpPerMBMs per MB of a
// multipart body PHP would have parsed (bodies over MaxMultipartSize are
// rejected before PHP sees them, so they pay nothing extra). Static responses
// get no delay. The result never goes below zero.
func responseDelay(resp Response, contentType string, bodyLen int64, t Timing, jitter float64) time.Duration {
	if !isPHPResponse(resp) {
		return 0
	}
	ms := t.PhpBaseMs + jitter
	if contentType == "multipart/form-data" && bodyLen <= MaxMultipartSize {
		ms += t.PhpPerMBMs * float64(bodyLen) / 1048576
	}
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms * float64(time.Millisecond))
}

// sampledJitter draws a uniform jitter in [-PhpJitterMs, +PhpJitterMs).
func sampledJitter(t Timing) float64 {
	return rand.Float64()*2*t.PhpJitterMs - t.PhpJitterMs
}

// phpDelay sleeps for the response's PHP-shaped delay. It runs after the
// body drain: Apache reads the request body, then PHP runs the page.
func phpDelay(r *http.Request, resp Response, bodyLen int64) {
	t := currentTiming()
	if d := responseDelay(resp, requestContentType(r), bodyLen, t, sampledJitter(t)); d > 0 {
		time.Sleep(d)
	}
}

func writeTrapResponse(w http.ResponseWriter, r *http.Request, behaviour Behaviour) {
	var body []byte
	if behaviour.Response.Type == "file" {
		content, err := os.ReadFile(behaviour.Response.Body)
		if err != nil {
			log.Printf("[RESPONSE-ERROR]: unable to read file %s: %v", behaviour.Response.Body, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		body = content
	} else {
		body = []byte(behaviour.Response.Body)
	}

	render := func(s string) string { return RenderTemplate(RenderRequestTemplate(s, r)) }
	if bytes.Contains(body, []byte("{{")) {
		body = []byte(render(string(body)))
	}
	for key, value := range convertMap(behaviour.Response.Headers) {
		switch {
		// "Set-Cookie-If-Missing" or "Set-Cookie-If-Missing-<anything>": one
		// conditional cookie per key, so a response can set several.
		case strings.HasPrefix(strings.ToLower(key), "set-cookie-if-missing"):
			name, _, _ := strings.Cut(value, "=")
			if r != nil && !requestHasCookie(r, strings.TrimSpace(name)) {
				w.Header().Add("Set-Cookie", render(value))
			}
		case strings.EqualFold(key, "Set-Cookie"):
			w.Header().Add("Set-Cookie", render(value)) // never wipe a conditional cookie added earlier
		default:
			w.Header().Set(key, render(value))
		}
	}
	statusCode := behaviour.Response.Statuscode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	if r != nil {
		applyApacheConnectionHeaders(w, r, reqNumFrom(r), len(body))
	}
	// HEAD sends no body. Content-Length is only advertised when the trap sets
	// it explicitly (static assets) or for an HTTP/1.0 keep-alive response;
	// Apache omits it for dynamic pages and error documents, and so does Go
	// when nothing is written.
	w.WriteHeader(statusCode)
	if r != nil && r.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(body); err != nil {
		log.Printf("Unable to write response content: %v", err)
	}
}

// Passing `trapConfig` parameter so each instance can handle its own traps independently.
func allHandler(trapConfig []Trap, catchall bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Count the request once against its connection, for Keep-Alive max.
		r = r.WithContext(context.WithValue(r.Context(), reqNumKey{}, requestNumber(r)))
		ua := uaParser.Parse(r.Header.Get("User-Agent"))
		payload := newRequestPayload(r)
		isMatchedRequest := hasMatchingRequest(trapConfig, r.Method, r.URL.Path)
		body := &countingBody{ReadCloser: r.Body}
		if r.Body != nil {
			r.Body = body
		}

		if isMatchedRequest || catchall {
			capturedPayload, err := captureRequestPayload(w, r, payload)
			payload = capturedPayload
			if err != nil {
				log.Printf("Error processing payload: %v", err)
			}
		}
		// Apache reads the whole body before answering and keeps the
		// connection open; answering mid-upload makes net/http close it.
		drainBody(r.Body, MaxDrainSize)
		bodyLen := requestBodyLength(r, body.n)

		for _, trap := range trapConfig {
			for _, behaviour := range trap.Behaviour {
				if !methodMatches(behaviour.Request.Method, r.Method) || !match(behaviour.Request.URL, r.URL.Path) {
					continue
				}

				protoMatch := CheckProto(behaviour.Request.Proto, r.Proto)
				headerMatch := CheckHeaders(convertMap(behaviour.Request.Headers), r.Header)
				paramMatch := CheckParams(convertMap(behaviour.Request.Params), payload.params)
				containsMatch := headerContainsMatch(behaviour.Request.HeaderContains, r.Header)
				if !protoMatch || (!(headerMatch && paramMatch) && !containsMatch) {
					continue
				}

				details := buildLogDetails(r, ua, payload, true)
				details["trapped_for"] = trap.Basicinfo.Name
				if trap.Basicinfo.RiskRating != "" {
					details["trapped_risk_rating"] = trap.Basicinfo.RiskRating
				}
				if trap.Basicinfo.References != "" {
					details["trapped_references"] = trap.Basicinfo.References
				}
				logDetails(details)
				phpDelay(r, behaviour.Response, bodyLen)
				writeTrapResponse(w, r, behaviour)
				return
			}
		}

		logDetails(buildLogDetails(r, ua, payload, false))
		if fallback != nil {
			phpDelay(r, fallback.Unmatched, bodyLen)
			writeTrapResponse(w, r, Behaviour{Response: fallback.Unmatched})
		}
	})
}

func newTrapRouter(trapConfig []Trap, catchall bool) *mux.Router {
	r := mux.NewRouter()
	r.SkipClean(true)
	handler := allHandler(trapConfig, catchall)
	r.PathPrefix("/").Handler(handler)
	// CONNECT has an empty URL.Path and never matches PathPrefix("/"); route
	// mux's own 404/405 to the honeypot so no request is unlogged or answered
	// by mux's Go-flavoured text/plain page.
	r.NotFoundHandler = handler
	r.MethodNotAllowedHandler = handler
	return r
}

// newServer builds the listener for one port. HTTP/2 is disabled: the persona
// is a stock Ubuntu Apache, which does not enable mod_http2, and Go would
// otherwise advertise h2 in the TLS ALPN.
func newServer(port string, handler http.Handler) *http.Server {
	s := &http.Server{Addr: ":" + port, Handler: handler}
	configureServer(s)
	return s
}

// configureServer applies the listener settings shared by production and the
// real-server tests. IdleTimeout matches the timeout=5 advertised in Apache's
// Keep-Alive header (KeepAliveTimeout 5). ConnContext gives every connection
// a request counter so Keep-Alive max can count down as Apache's does.
func configureServer(s *http.Server) {
	s.ReadHeaderTimeout = 10 * time.Second
	s.ReadTimeout = 30 * time.Second
	s.WriteTimeout = 30 * time.Second
	s.IdleTimeout = 5 * time.Second
	s.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	s.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, connCountKey{}, &connRequestCount{})
	}
}

func StartHandler(port string, trapConfig []Trap, cert string, key string, catchall bool) error {
	r := newTrapRouter(trapConfig, catchall)
	fmt.Println("[~>] Loaded " + strconv.Itoa(len(trapConfig)) + " trap(s) on Port:" + port + ". Let's get the ball rolling!")

	server := newServer(port, r)

	var err error
	if port == "443" {
		err = server.ListenAndServeTLS(cert, key)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
