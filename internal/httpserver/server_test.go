package httpserver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"pwpush/internal/auth"
	"pwpush/internal/config"
	"pwpush/internal/crypto"
	"pwpush/internal/ratelimit"
	"pwpush/internal/storage"
)

func testConfig(t *testing.T, mode string) config.Config {
	t.Helper()
	env := map[string]string{
		"PUBLIC_ORIGIN":       "https://secrets.example",
		"DATA_DIR":            t.TempDir(),
		"ADMIN_PASSWORD_FILE": "/unused",
		"TLS_MODE":            mode,
	}
	if mode == config.ModeProxy {
		env["TRUSTED_PROXY_IPS"] = "127.0.0.1"
	} else {
		env["TLS_CERT_FILE"] = "/tmp/cert"
		env["TLS_KEY_FILE"] = "/tmp/key"
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newServer(t *testing.T, mode string, rules Rules) *Server {
	t.Helper()
	cfg := testConfig(t, mode)
	db, err := storage.Open(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	srv, err := New(cfg, db, nil, rules, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func tightRules() Rules {
	rule := ratelimit.Rule{Capacity: 2, RefillPerSec: 0}
	return Rules{Login: rule, Create: rule, Reveal: rule}
}

func (s *Server) call(method, path, body string, hdr map[string]string, remote string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Host = "secrets.example"
	if remote != "" {
		req.RemoteAddr = remote
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func originHeaders(extra map[string]string) map[string]string {
	h := map[string]string{
		"Content-Type": "application/json",
		"Origin":       "https://secrets.example",
	}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

func TestViewerIdenticalWithClosedDB(t *testing.T) {
	s := newServer(t, config.ModeProxy, ProductionRules())
	a := s.call(http.MethodGet, "/p/aaaaaaaaaaaaaaaaaaaaaa", "", nil, "")
	b := s.call(http.MethodGet, "/p/zzzzzzzzzzzzzzzzzzzzzz", "", nil, "")
	if a.Code != 200 || !bytes.Equal(a.Body.Bytes(), b.Body.Bytes()) {
		t.Fatal("viewer bytes differ")
	}
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	c := s.call(http.MethodGet, "/p/not-a-real-id", "", nil, "")
	if c.Code != 200 || !bytes.Equal(a.Body.Bytes(), c.Body.Bytes()) || a.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("closed db changed the viewer: %d", c.Code)
	}
}

func assertCSPMatchesBody(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if bytes.Contains(rr.Body.Bytes(), []byte("style=")) {
		t.Fatal("style attribute present")
	}
	csp := rr.Header().Get("Content-Security-Policy")
	script := between(rr.Body.Bytes(), "<script>", "</script>")
	style := between(rr.Body.Bytes(), "<style>", "</style>")
	if !strings.Contains(csp, "'sha256-"+cspHash(script)+"'") || !strings.Contains(csp, "'sha256-"+cspHash(style)+"'") {
		t.Fatalf("csp does not match body hashes: %s", csp)
	}
}

func TestCSPHashesMatchBody(t *testing.T) {
	s := newServer(t, config.ModeDirect, ProductionRules())
	rr := s.call(http.MethodGet, "/p/abc", "", nil, "")
	assertCSPMatchesBody(t, rr)
	home := s.call(http.MethodGet, "/", "", nil, "")
	if home.Code != 200 || !bytes.Contains(home.Body.Bytes(), []byte(`data-max="65536"`)) {
		t.Fatalf("home missing ciphertext ceiling: %d", home.Code)
	}
	assertCSPMatchesBody(t, home)
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatal(csp)
	}
	if rr.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("direct mode missing HSTS")
	}
	proxy := newServer(t, config.ModeProxy, ProductionRules())
	got := proxy.call(http.MethodGet, "/p/abc", "", nil, "")
	if got.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("proxy mode sent HSTS")
	}
}

func TestSecurityHeadersOn404And421(t *testing.T) {
	s := newServer(t, config.ModeProxy, ProductionRules())
	missing := s.call(http.MethodGet, "/missing", "", nil, "")
	if missing.Code != 404 {
		t.Fatal(missing.Code)
	}
	assertSecurity(t, missing.Header())
	req := httptest.NewRequest(http.MethodGet, "/p/abc", nil)
	req.Host = "evil.example"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("host status %d", rr.Code)
	}
	assertSecurity(t, rr.Header())
}

func assertSecurity(t *testing.T, h http.Header) {
	t.Helper()
	for _, k := range []string{
		"Content-Security-Policy",
		"Referrer-Policy",
		"X-Content-Type-Options",
		"X-Robots-Tag",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
		"Permissions-Policy",
		"Cache-Control",
	} {
		if h.Get(k) == "" {
			t.Fatalf("missing %s", k)
		}
	}
	if h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("permissive CORS")
	}
}

func TestRevealFailuresMatchAndWrongTokenDoesNotConsume(t *testing.T) {
	s := newServer(t, config.ModeProxy, Rules{
		Login:  ratelimit.LoginRule,
		Create: ratelimit.CreateRule,
		Reveal: ratelimit.Rule{Capacity: 100, RefillPerSec: 0},
	})
	id := mustID(t)
	nonce := []byte("0123456789ab")
	ct := bytes.Repeat([]byte{3}, 24)
	token := bytes.Repeat([]byte{4}, 32)
	plain := []byte("PLAINTEXT-MARKER-0123456789")
	master := bytes.Repeat([]byte{0xab}, 32)
	exp := time.Now().Add(time.Hour)
	if err := s.db.InsertSecretForTest(id, nonce, ct, crypto.HashToken(token), exp); err != nil {
		t.Fatal(err)
	}
	ok := s.postReveal(id, base64.RawURLEncoding.EncodeToString(token), "192.0.2.10:1")
	if ok.Code != 200 {
		t.Fatalf("reveal %d %s", ok.Code, ok.Body.String())
	}
	var body struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
		Version    int    `json:"version"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	gotNonce, _ := base64.RawURLEncoding.DecodeString(body.Nonce)
	gotCT, _ := base64.RawURLEncoding.DecodeString(body.Ciphertext)
	if !bytes.Equal(gotNonce, nonce) || !bytes.Equal(gotCT, ct) || body.Version != 1 {
		t.Fatal("reveal bytes differ from storage")
	}
	file := readDB(t, s)
	if bytes.Contains(file, plain) || bytes.Contains(file, master) || bytes.Contains(file, token) {
		t.Fatal("plaintext, key, or auth token is in the database file")
	}
	again := s.postReveal(id, base64.RawURLEncoding.EncodeToString(token), "192.0.2.11:1")
	unknown := s.postReveal(mustID(t), base64.RawURLEncoding.EncodeToString(token), "192.0.2.12:1")
	if again.Code != unknown.Code || !bytes.Equal(again.Body.Bytes(), unknown.Body.Bytes()) {
		t.Fatal("consumed and unknown differ")
	}

	id2 := mustID(t)
	if err := s.db.InsertSecretForTest(id2, nonce, ct, crypto.HashToken(token), exp); err != nil {
		t.Fatal(err)
	}
	wrong := s.postReveal(id2, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "192.0.2.13:1")
	missing := s.postReveal(id2, "", "192.0.2.14:1")
	if wrong.Code != 404 || missing.Code != 404 || !bytes.Equal(wrong.Body.Bytes(), unknown.Body.Bytes()) || !bytes.Equal(missing.Body.Bytes(), unknown.Body.Bytes()) {
		t.Fatal("wrong token is distinguishable")
	}
	n, _ := s.db.SecretCount()
	if n != 1 {
		t.Fatalf("wrong token consumed the secret, count %d", n)
	}
	expiredID := mustID(t)
	if err := s.db.InsertSecretForTest(expiredID, nonce, ct, crypto.HashToken(token), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	expired := s.postReveal(expiredID, base64.RawURLEncoding.EncodeToString(token), "192.0.2.15:1")
	if expired.Code != unknown.Code || !bytes.Equal(expired.Body.Bytes(), unknown.Body.Bytes()) {
		t.Fatal("expired differs")
	}
}

func TestParallelReveal(t *testing.T) {
	s := newServer(t, config.ModeProxy, Rules{
		Login:  ratelimit.LoginRule,
		Create: ratelimit.CreateRule,
		Reveal: ratelimit.Rule{Capacity: 100, RefillPerSec: 0},
	})
	id := mustID(t)
	token := bytes.Repeat([]byte{5}, 32)
	if err := s.db.InsertSecretForTest(id, []byte("0123456789ab"), bytes.Repeat([]byte{1}, 16), crypto.HashToken(token), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rr := s.postReveal(id, base64.RawURLEncoding.EncodeToString(token), "192.0.2.20:1")
			codes[i] = rr.Code
		}(i)
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == 200 {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("successes = %d", ok)
	}
}

func TestRevealRateLimits(t *testing.T) {
	s := newServer(t, config.ModeProxy, tightRules())
	if s.postReveal(mustID(t), "", "198.51.100.1:1").Code == 429 {
		t.Fatal("first reveal limited")
	}
	if s.postReveal(mustID(t), "", "198.51.100.1:1").Code == 429 {
		t.Fatal("second reveal limited")
	}
	fake := s.postReveal(mustID(t), "", "198.51.100.1:1")
	id := mustID(t)
	token := bytes.Repeat([]byte{6}, 32)
	if err := s.db.InsertSecretForTest(id, []byte("0123456789ab"), bytes.Repeat([]byte{1}, 16), crypto.HashToken(token), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	real := s.postReveal(id, base64.RawURLEncoding.EncodeToString(token), "198.51.100.1:1")
	if fake.Code != 429 || real.Code != 429 || !bytes.Equal(fake.Body.Bytes(), real.Body.Bytes()) || !bytes.Equal(fake.Body.Bytes(), unavailable) {
		t.Fatalf("rate bodies differ fake=%d real=%d", fake.Code, real.Code)
	}
	n, _ := s.db.SecretCount()
	if n != 1 {
		t.Fatal("rate limit consumed the secret")
	}
	s2 := newServer(t, config.ModeProxy, tightRules())
	shared := mustID(t)
	if s2.postReveal(shared, "", "198.51.100.2:1").Code == 429 || s2.postReveal(shared, "", "198.51.100.3:1").Code == 429 {
		t.Fatal("id bucket drained too early")
	}
	if s2.postReveal(shared, "", "198.51.100.4:1").Code != 429 {
		t.Fatal("id bucket was not enforced")
	}
}

func TestCreateReservationRules(t *testing.T) {
	s := newServer(t, config.ModeProxy, Rules{
		Login:  ratelimit.LoginRule,
		Create: ratelimit.Rule{Capacity: 2, RefillPerSec: 0},
		Reveal: ratelimit.Rule{Capacity: 100, RefillPerSec: 0},
	})
	cookie, csrf := s.plantSession(t)
	hdr := originHeaders(map[string]string{"X-CSRF-Token": csrf, "Cookie": cookie})
	first := s.call(http.MethodPost, "/api/id", "{}", hdr, "203.0.113.5:9")
	if first.Code != 200 {
		t.Fatalf("reserve %d %s", first.Code, first.Body.String())
	}
	var reserved struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &reserved); err != nil {
		t.Fatal(err)
	}
	payload := `{"id":"` + reserved.ID + `","nonce":"` + b64(bytes.Repeat([]byte{1}, 12)) + `","ciphertext":"` + b64(bytes.Repeat([]byte{2}, 16)) + `","version":1,"ttl":3600,"authToken":"` + b64(bytes.Repeat([]byte{3}, 32)) + `"}`
	created := s.call(http.MethodPost, "/api/create", payload, hdr, "203.0.113.5:9")
	if created.Code != 200 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	again := s.call(http.MethodPost, "/api/id", "{}", hdr, "203.0.113.5:9")
	if again.Code != 429 {
		t.Fatalf("shared bucket status %d", again.Code)
	}
	secondCreate := s.call(http.MethodPost, "/api/create", payload, hdr, "203.0.113.5:9")
	if secondCreate.Code != 429 {
		t.Fatalf("second create was not limited: %d", secondCreate.Code)
	}

	otherCookie, otherCSRF := s.plantSession(t)
	other := originHeaders(map[string]string{"X-CSRF-Token": otherCSRF, "Cookie": otherCookie})
	wide := newServer(t, config.ModeProxy, ProductionRules())
	c1, tok1 := wide.plantSession(t)
	c2, tok2 := wide.plantSession(t)
	h1 := originHeaders(map[string]string{"X-CSRF-Token": tok1, "Cookie": c1})
	h2 := originHeaders(map[string]string{"X-CSRF-Token": tok2, "Cookie": c2})
	res := wide.call(http.MethodPost, "/api/id", "{}", h1, "203.0.113.8:1")
	var got struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &got)
	body := `{"id":"` + got.ID + `","nonce":"` + b64(bytes.Repeat([]byte{1}, 12)) + `","ciphertext":"` + b64(bytes.Repeat([]byte{2}, 16)) + `","version":1,"ttl":3600,"authToken":"` + b64(bytes.Repeat([]byte{8}, 32)) + `"}`
	if wide.call(http.MethodPost, "/api/create", body, h2, "203.0.113.8:1").Code == 200 {
		t.Fatal("other session created the secret")
	}
	n, _ := wide.db.ReservationCount()
	if n != 1 {
		t.Fatalf("reservation count %d", n)
	}
	if wide.call(http.MethodPost, "/api/create", body, h1, "203.0.113.9:1").Code != 200 {
		t.Fatal("owner create failed")
	}
	if wide.call(http.MethodPost, "/api/create", body, h1, "203.0.113.10:1").Code == 200 {
		t.Fatal("second create succeeded")
	}
	_ = other

	before, _ := wide.db.ReservationCount()
	_ = wide.call(http.MethodPost, "/api/reveal", `{"id":"`+mustID(t)+`","authToken":"`+b64(bytes.Repeat([]byte{1}, 32))+`"}`, map[string]string{"Content-Type": "application/json"}, "203.0.113.40:1")
	after, _ := wide.db.ReservationCount()
	if before != after {
		t.Fatal("reveal deleted a reservation")
	}
}

func TestOpenReservationCap(t *testing.T) {
	s := newServer(t, config.ModeProxy, ProductionRules())
	cookie, csrf := s.plantSession(t)
	hdr := originHeaders(map[string]string{"X-CSRF-Token": csrf, "Cookie": cookie})
	for i := 0; i < 10; i++ {
		rr := s.call(http.MethodPost, "/api/id", "{}", hdr, "203.0.113.20:1")
		if rr.Code != 200 {
			t.Fatalf("reserve %d status %d", i, rr.Code)
		}
	}
	rr := s.call(http.MethodPost, "/api/id", "{}", hdr, "203.0.113.20:1")
	if rr.Code != 429 {
		t.Fatalf("cap status %d", rr.Code)
	}
}

func TestForwardedFor(t *testing.T) {
	s := newServer(t, config.ModeProxy, tightRules())
	s.cfg.TrustedProxies = map[string]struct{}{"192.0.2.1": {}}
	var n int
	req := func(lines ...string) *httptest.ResponseRecorder {
		n++
		id := "id" + strings.Repeat("a", 18) + string(rune('a'+n))
		r := httptest.NewRequest(http.MethodPost, "/api/reveal", strings.NewReader(`{"id":"`+id+`","authToken":"aaaa"}`))
		r.Host = "secrets.example"
		r.RemoteAddr = "192.0.2.1:443"
		r.Header.Set("Content-Type", "application/json")
		for _, line := range lines {
			r.Header.Add("X-Forwarded-For", line)
		}
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, r)
		return rr
	}
	if req("1.1.1.1, 198.51.100.50").Code == 429 || req("8.8.8.8, 198.51.100.50").Code == 429 {
		t.Fatal("rightmost bucket drained too early")
	}
	if req("9.9.9.9, 198.51.100.50").Code != 429 {
		t.Fatal("rightmost address was not the rate-limit key")
	}
	if req("1.1.1.1, 198.51.100.77").Code == 429 {
		t.Fatal("a different rightmost address shared the bucket")
	}
	first := req("8.8.8.8", "not-an-ip")
	second := req()
	third := req("1.2.3.4", "still-bad")
	if first.Code == 429 || second.Code == 429 || third.Code != 429 {
		t.Fatalf("invalid last item did not stay on the proxy address: %d %d %d", first.Code, second.Code, third.Code)
	}

	untrusted := newServer(t, config.ModeDirect, tightRules())
	r := httptest.NewRequest(http.MethodPost, "/api/reveal", strings.NewReader(`{"id":"abcdefghijklmnopqrstuv","authToken":"aaaa"}`))
	r.Host = "secrets.example"
	r.RemoteAddr = "203.0.113.9:9"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-For", "198.51.100.8")
	rr := httptest.NewRecorder()
	untrusted.ServeHTTP(rr, r)
	r2 := httptest.NewRequest(http.MethodPost, "/api/reveal", strings.NewReader(`{"id":"bbcdefghijklmnopqrstuv","authToken":"aaaa"}`))
	r2.Host = "secrets.example"
	r2.RemoteAddr = "203.0.113.9:9"
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Set("X-Forwarded-For", "198.51.100.9")
	rr2 := httptest.NewRecorder()
	untrusted.ServeHTTP(rr2, r2)
	r3 := httptest.NewRequest(http.MethodPost, "/api/reveal", strings.NewReader(`{"id":"cbcdefghijklmnopqrstuv","authToken":"aaaa"}`))
	r3.Host = "secrets.example"
	r3.RemoteAddr = "203.0.113.9:9"
	r3.Header.Set("Content-Type", "application/json")
	r3.Header.Set("X-Forwarded-For", "198.51.100.10")
	rr3 := httptest.NewRecorder()
	untrusted.ServeHTTP(rr3, r3)
	if rr.Code == 429 || rr2.Code == 429 || rr3.Code != 429 {
		t.Fatalf("untrusted header affected the bucket: %d %d %d", rr.Code, rr2.Code, rr3.Code)
	}
}

func TestOriginAndCSRF(t *testing.T) {
	s := newServer(t, config.ModeProxy, ProductionRules())
	cookie, csrf := s.plantSession(t)
	badOrigin := originHeaders(map[string]string{"X-CSRF-Token": csrf, "Cookie": cookie, "Origin": "https://evil.example"})
	if s.call(http.MethodPost, "/api/id", "{}", badOrigin, "").Code != 403 {
		t.Fatal("bad origin accepted")
	}
	cross := originHeaders(map[string]string{"X-CSRF-Token": csrf, "Cookie": cookie, "Sec-Fetch-Site": "cross-site"})
	if s.call(http.MethodPost, "/api/id", "{}", cross, "").Code != 403 {
		t.Fatal("cross-site accepted")
	}
	sameSite := originHeaders(map[string]string{"X-CSRF-Token": csrf, "Cookie": cookie, "Sec-Fetch-Site": "same-site"})
	if s.call(http.MethodPost, "/api/id", "{}", sameSite, "").Code != 403 {
		t.Fatal("same-site accepted")
	}
	noCSRF := originHeaders(map[string]string{"Cookie": cookie})
	if s.call(http.MethodPost, "/api/id", "{}", noCSRF, "").Code != 403 {
		t.Fatal("missing csrf accepted")
	}
}

func TestHealthIgnoresDB(t *testing.T) {
	s := newServer(t, config.ModeProxy, ProductionRules())
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	rr := s.call(http.MethodGet, "/healthz", "", nil, "")
	if rr.Code != 200 || rr.Body.String() != "ok" {
		t.Fatalf("health %d %s", rr.Code, rr.Body.String())
	}
}

func (s *Server) postReveal(id, token, remote string) *httptest.ResponseRecorder {
	body := `{"id":"` + id + `","authToken":"` + token + `"}`
	return s.call(http.MethodPost, "/api/reveal", body, map[string]string{"Content-Type": "application/json"}, remote)
}

func (s *Server) plantSession(t *testing.T) (cookie, csrf string) {
	t.Helper()
	token := make([]byte, 32)
	raw := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.db.CreateSession(crypto.HashToken(token), raw, now, now.Add(12*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return "__Host-session=" + base64.RawURLEncoding.EncodeToString(token), base64.RawURLEncoding.EncodeToString(raw)
}

func mustID(t *testing.T) string {
	t.Helper()
	id, err := crypto.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func between(page []byte, open, close string) []byte {
	i := bytes.Index(page, []byte(open))
	rest := page[i+len(open):]
	j := bytes.Index(rest, []byte(close))
	return rest[:j]
}

func TestHomeCreatesWithoutSignIn(t *testing.T) {
	s := newServer(t, config.ModeProxy, ProductionRules())
	page := s.call(http.MethodGet, "/", "", nil, "")
	if page.Code != 200 || bytes.Contains(page.Body.Bytes(), []byte("Sign in")) || bytes.Contains(page.Body.Bytes(), []byte("style=")) {
		t.Fatalf("home %d", page.Code)
	}
	res := s.call(http.MethodPost, "/api/id", "{}", originHeaders(nil), "203.0.113.70:1")
	if res.Code != 200 {
		t.Fatalf("anonymous reserve %d %s", res.Code, res.Body.String())
	}
	var reserved struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &reserved); err != nil {
		t.Fatal(err)
	}
	tooMany := `{"id":"` + reserved.ID + `","nonce":"` + b64(bytes.Repeat([]byte{1}, 12)) + `","ciphertext":"` + b64(bytes.Repeat([]byte{2}, 16)) + `","version":1,"ttl":3600,"views":21,"authToken":"` + b64(bytes.Repeat([]byte{3}, 32)) + `"}`
	if s.call(http.MethodPost, "/api/create", tooMany, originHeaders(nil), "203.0.113.70:1").Code != 400 {
		t.Fatal("views above 20 accepted")
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	s := newServer(t, config.ModeProxy, ProductionRules())
	cookie, csrf := s.plantSession(t)
	hdr := originHeaders(map[string]string{"X-CSRF-Token": csrf, "Cookie": cookie})
	res := s.call(http.MethodPost, "/api/id", "{}", hdr, "203.0.113.50:1")
	var reserved struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &reserved); err != nil || res.Code != 200 {
		t.Fatal(res.Code, res.Body.String(), err)
	}
	bad := `{"id":"` + reserved.ID + `","nonce":"` + b64(bytes.Repeat([]byte{1}, 12)) + `","ciphertext":"` + b64(bytes.Repeat([]byte{2}, 16)) + `","version":2,"ttl":3600,"authToken":"` + b64(bytes.Repeat([]byte{3}, 32)) + `"}`
	if s.call(http.MethodPost, "/api/create", bad, hdr, "203.0.113.50:1").Code != 400 {
		t.Fatal("bad version accepted")
	}
	n, _ := s.db.ReservationCount()
	if n != 1 {
		t.Fatalf("bad create consumed the reservation: %d", n)
	}
}

func TestLoginCookieAndPasswordChange(t *testing.T) {
	s := newServer(t, config.ModeProxy, ProductionRules())
	pwPath := s.cfg.DataDir + "/password"
	if err := os.WriteFile(pwPath, []byte("long-enough-pw\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.cfg.AdminPasswordFile = pwPath
	if err := auth.EnsureAdmin(s.db, s.cfg); err != nil {
		t.Fatal(err)
	}
	rr := s.call(http.MethodPost, "/api/login", `{"password":"long-enough-pw"}`, originHeaders(nil), "203.0.113.60:1")
	if rr.Code != 200 {
		t.Fatalf("login %d %s", rr.Code, rr.Body.String())
	}
	setCookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "__Host-session=") || !strings.Contains(setCookie, "HttpOnly") || !strings.Contains(setCookie, "Secure") || !strings.Contains(setCookie, "SameSite=Strict") || !strings.Contains(setCookie, "Path=/") || strings.Contains(setCookie, "Domain=") {
		t.Fatalf("cookie flags: %s", setCookie)
	}
	parsed := rr.Result().Cookies()
	if len(parsed) != 1 {
		t.Fatalf("cookies %#v", parsed)
	}
	cookie := parsed[0].Name + "=" + parsed[0].Value
	var body struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	hdr := originHeaders(map[string]string{"X-CSRF-Token": body.CSRF, "Cookie": cookie})
	changed := s.call(http.MethodPost, "/api/admin/password", `{"password":"another-long-pw"}`, hdr, "203.0.113.60:1")
	if changed.Code != 200 {
		t.Fatalf("change %d %s", changed.Code, changed.Body.String())
	}
	if s.call(http.MethodPost, "/api/id", "{}", hdr, "203.0.113.60:1").Code == 200 {
		t.Fatal("old session survived password change")
	}
	lock, err := s.db.LoadLock()
	if err != nil || lock.Failures != 0 {
		t.Fatal("lockout was not cleared")
	}
}

func TestSessionTokenIsHashed(t *testing.T) {
	s := newServer(t, config.ModeProxy, ProductionRules())
	cookie, _ := s.plantSession(t)
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(cookie, "__Host-session="))
	if err != nil {
		t.Fatal(err)
	}
	file := readDB(t, s)
	if bytes.Contains(file, raw) {
		t.Fatal("raw session token stored")
	}
	sum := sha256.Sum256(raw)
	if !bytes.Contains(file, sum[:]) {
		t.Fatal("session hash missing")
	}
}

func readDB(t *testing.T, s *Server) []byte {
	t.Helper()
	if err := s.db.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(s.db.Path())
	if err != nil {
		t.Fatal(err)
	}
	if wal, err := os.ReadFile(s.db.Path() + "-wal"); err == nil {
		file = append(file, wal...)
	}
	return file
}
