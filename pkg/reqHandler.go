package h0neytr4p

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
		prefix := &prefixCapture{max: MaxStoredPayload}
		limited := http.MaxBytesReader(w, r.Body, sizeLimit)
		r.Body = teeBody{Reader: io.TeeReader(limited, prefix), Closer: limited}
		if err := r.ParseMultipartForm(sizeLimit); err != nil {
			// Any parse failure (over cap, too many parts or headers, malformed
			// boundary) mimics PHP past its limits: empty superglobals, normal
			// response. Drain what is left so the prefix fills up and the
			// connection stays reusable, as Apache would.
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
			_, _ = io.Copy(io.Discard, r.Body)
			log.Printf("multipart parse failed, kept %d-byte prefix: %v", len(prefix.buf), err)
			payload.overCap(nil, prefix.buf)
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
	// HEAD sends no body. Content-Length is only advertised when the trap sets
	// it explicitly (static assets); Apache omits it for dynamic pages and
	// error documents, and so does Go when nothing is written.
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
		ua := uaParser.Parse(r.Header.Get("User-Agent"))
		payload := newRequestPayload(r)
		isMatchedRequest := hasMatchingRequest(trapConfig, r.Method, r.URL.Path)

		if isMatchedRequest || catchall {
			capturedPayload, err := captureRequestPayload(w, r, payload)
			payload = capturedPayload
			if err != nil {
				log.Printf("Error processing payload: %v", err)
			}
		}

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
				writeTrapResponse(w, r, behaviour)
				return
			}
		}

		logDetails(buildLogDetails(r, ua, payload, false))
		if fallback != nil {
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
	return &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
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
