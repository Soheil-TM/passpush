// Package httpserver is the HTTP application. The viewer route never touches SQLite.
package httpserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pwpush/internal/auth"
	"pwpush/internal/clientip"
	"pwpush/internal/config"
	"pwpush/internal/crypto"
	"pwpush/internal/ratelimit"
	"pwpush/internal/storage"
	"pwpush/web"
)

const maxBody = 128 * 1024

var (
	unavailable  = []byte("{\"error\":\"unavailable\"}\n")
	limited      = []byte("{\"error\":\"limited\"}\n")
	unauthorized = []byte("{\"error\":\"unauthorized\"}\n")
	forbidden    = []byte("{\"error\":\"forbidden\"}\n")
	rejected     = []byte("{\"error\":\"rejected\"}\n")
	permissions  = "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=(), interest-cohort=()"
)

// Rules are the token buckets for this process.
type Rules struct {
	Login  ratelimit.Rule
	Create ratelimit.Rule
	Reveal ratelimit.Rule
}

// ProductionRules returns the spec limits.
func ProductionRules() Rules {
	return Rules{Login: ratelimit.LoginRule, Create: ratelimit.CreateRule, Reveal: ratelimit.RevealRule}
}

// Server serves one deployment.
type Server struct {
	cfg    config.Config
	db     *storage.DB
	lim    *ratelimit.Limiter
	gate   *auth.Gate
	rules  Rules
	now    func() time.Time
	viewer []byte
	admin  []byte
	csp    string
}

// New builds the server and the CSP hashes from the pages that will be served.
func New(cfg config.Config, db *storage.DB, lim *ratelimit.Limiter, rules Rules, now func() time.Time) (*Server, error) {
	if lim == nil {
		lim = ratelimit.New(now)
	}
	if now == nil {
		now = time.Now
	}
	if rules.Login.Capacity == 0 {
		rules = ProductionRules()
	}
	admin := bytes.ReplaceAll(web.Admin, []byte("__PUBLIC_ORIGIN__"), []byte(html.EscapeString(cfg.PublicOrigin.String())))
	admin = bytes.ReplaceAll(admin, []byte("__MAX_CIPHERTEXT__"), []byte(strconv.Itoa(cfg.MaxCiphertext)))
	csp, err := contentSecurityPolicy(web.Viewer, admin)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:    cfg,
		db:     db,
		lim:    lim,
		gate:   auth.NewGate(),
		rules:  rules,
		now:    now,
		viewer: append([]byte(nil), web.Viewer...),
		admin:  admin,
		csp:    csp,
	}, nil
}

func contentSecurityPolicy(pages ...[]byte) (string, error) {
	var scripts, styles []string
	for _, page := range pages {
		script, err := extractOne(page, "script")
		if err != nil {
			return "", err
		}
		style, err := extractOne(page, "style")
		if err != nil {
			return "", err
		}
		scripts = append(scripts, "'sha256-"+cspHash(script)+"'")
		styles = append(styles, "'sha256-"+cspHash(style)+"'")
	}
	return "default-src 'none'; script-src " + strings.Join(unique(scripts), " ") +
		"; connect-src 'self'; style-src " + strings.Join(unique(styles), " ") +
		"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", nil
}

func extractOne(page []byte, tag string) ([]byte, error) {
	open := []byte("<" + tag + ">")
	close := []byte("</" + tag + ">")
	if bytes.Count(page, open) != 1 || bytes.Count(page, close) != 1 {
		return nil, errors.New("page must contain one " + tag + " block")
	}
	i := bytes.Index(page, open)
	rest := page[i+len(open):]
	j := bytes.Index(rest, close)
	return rest[:j], nil
}

func cspHash(b []byte) string {
	sum := sha256.Sum256(b)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.applyHeaders(w)
	lw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	route := "other"
	defer func() {
		log.Printf("event=http route=%s status=%d", route, lw.status)
	}()
	if !s.cfg.RequestHostOK(r.Host) {
		route = "host"
		writePlain(lw, http.StatusMisdirectedRequest, []byte("misdirected\n"))
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/healthz":
		route = "health"
		s.health(lw)
	case r.Method == http.MethodGet && (r.URL.Path == "/p" || strings.HasPrefix(r.URL.Path, "/p/")):
		route = "viewer"
		s.viewerPage(lw)
	case r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/admin"):
		route = "admin"
		s.adminPage(lw)
	case r.Method == http.MethodPost && r.URL.Path == "/api/login":
		route = "login"
		s.login(lw, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/admin/password":
		route = "password"
		s.changePassword(lw, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/id":
		route = "reserve"
		s.reserve(lw, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/create":
		route = "create"
		s.create(lw, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/reveal":
		route = "reveal"
		s.reveal(lw, r)
	default:
		route = "missing"
		writePlain(lw, http.StatusNotFound, []byte("not found\n"))
	}
}

func (s *Server) applyHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", s.csp)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", permissions)
	h.Set("Cache-Control", "no-store")
	if s.cfg.HSTS() {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
}

func (s *Server) health(w http.ResponseWriter) {
	writePlain(w, http.StatusOK, []byte("ok"))
}

func (s *Server) viewerPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.viewer)
}

func (s *Server) adminPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.admin)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.originOK(r) || !exactJSON(r) {
		writeJSON(w, http.StatusForbidden, forbidden)
		return
	}
	ip := clientip.FromRequest(r, s.cfg.TrustedProxies)
	if !s.lim.AllowIP("login:"+hashKey(ip), s.rules.Login) {
		writeJSON(w, http.StatusTooManyRequests, limited)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, rejected)
		return
	}
	pw := []byte(req.Password)
	defer crypto.Wipe(pw)
	res, err := auth.Login(s.db, s.gate, pw, s.now())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, rejected)
		return
	}
	if res.Busy || res.Locked {
		writeJSON(w, http.StatusTooManyRequests, limited)
		return
	}
	if !res.OK {
		writeJSON(w, http.StatusUnauthorized, unauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-session",
		Value:    base64.RawURLEncoding.EncodeToString(res.Token),
		Path:     "/",
		Expires:  s.now().Add(12 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	body, _ := json.Marshal(struct {
		CSRF string `json:"csrf"`
	}{CSRF: base64.RawURLEncoding.EncodeToString(res.CSRF)})
	writeJSON(w, http.StatusOK, append(body, '\n'))
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminAuth(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, rejected)
		return
	}
	pw := []byte(req.Password)
	defer crypto.Wipe(pw)
	if err := auth.ChangePassword(s.db, s.gate, s.cfg, pw); err != nil {
		if errors.Is(err, auth.ErrBusy) {
			writeJSON(w, http.StatusTooManyRequests, limited)
			return
		}
		writeJSON(w, http.StatusBadRequest, rejected)
		return
	}
	_ = sess
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, []byte("{\"ok\":true}\n"))
}

func (s *Server) reserve(w http.ResponseWriter, r *http.Request) {
	sum, ok := s.createOwner(w, r)
	if !ok {
		return
	}
	id, err := crypto.NewID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, rejected)
		return
	}
	if err := s.db.Reserve(sum, id, s.now()); err != nil {
		if errors.Is(err, storage.ErrCap) {
			writeJSON(w, http.StatusTooManyRequests, limited)
			return
		}
		writeJSON(w, http.StatusInternalServerError, rejected)
		return
	}
	body, _ := json.Marshal(struct {
		ID string `json:"id"`
	}{ID: id})
	writeJSON(w, http.StatusOK, append(body, '\n'))
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	sum, ok := s.createOwner(w, r)
	if !ok {
		return
	}
	var req struct {
		ID         string `json:"id"`
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
		Version    *int   `json:"version"`
		TTL        *int   `json:"ttl"`
		Views      *int   `json:"views"`
		AuthToken  string `json:"authToken"`
	}
	if err := decode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, rejected)
		return
	}
	idOK := decodeFixed(req.ID, 16) != nil
	nonce := decodeFixed(req.Nonce, 12)
	token := decodeFixed(req.AuthToken, 32)
	cipher, err := base64.RawURLEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		cipher = nil
	}
	views := 1
	if req.Views != nil {
		views = *req.Views
	}
	if !idOK || nonce == nil || token == nil || req.Version == nil || *req.Version != 1 || req.TTL == nil || *req.TTL <= 0 || *req.TTL > 604800 || views < 1 || views > 20 || len(cipher) < 16 || len(cipher) > s.cfg.MaxCiphertext {
		writeJSON(w, http.StatusBadRequest, rejected)
		return
	}
	expires := s.now().Add(time.Duration(*req.TTL) * time.Second)
	err = s.db.CreateSecret(sum, req.ID, nonce, cipher, crypto.HashToken(token), 1, views, expires, s.now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, rejected)
		return
	}
	body, _ := json.Marshal(struct {
		ID string `json:"id"`
	}{ID: req.ID})
	writeJSON(w, http.StatusOK, append(body, '\n'))
}

func (s *Server) reveal(w http.ResponseWriter, r *http.Request) {
	ip := clientip.FromRequest(r, s.cfg.TrustedProxies)
	if !exactJSON(r) {
		s.finishReveal(w, ip, "malformed", nil, false)
		return
	}
	var req struct {
		ID        string `json:"id"`
		AuthToken string `json:"authToken"`
	}
	if err := decode(r, &req); err != nil {
		s.finishReveal(w, ip, "malformed", nil, false)
		return
	}
	token := decodeFixed(req.AuthToken, 32)
	var authHash []byte
	if token == nil {
		authHash = crypto.HashToken([]byte(req.AuthToken))
	} else {
		authHash = crypto.HashToken(token)
	}
	s.finishReveal(w, ip, req.ID, authHash, true)
}

func (s *Server) finishReveal(w http.ResponseWriter, ip, id string, authHash []byte, query bool) {
	if !s.lim.AllowIPAndID("reveal:"+hashKey(ip), "reveal:"+hashKey(id), s.rules.Reveal) {
		writeJSON(w, http.StatusTooManyRequests, unavailable)
		return
	}
	if !query {
		writeJSON(w, http.StatusNotFound, unavailable)
		return
	}
	secret, err := s.db.Reveal(id, authHash, s.now())
	if err != nil || !secret.Present {
		writeJSON(w, http.StatusNotFound, unavailable)
		return
	}
	body, _ := json.Marshal(struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
		Version    int    `json:"version"`
		Remaining  int    `json:"remaining"`
	}{
		Nonce:      base64.RawURLEncoding.EncodeToString(secret.Nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(secret.Ciphertext),
		Version:    secret.Version,
		Remaining:  secret.Remaining,
	})
	writeJSON(w, http.StatusOK, append(body, '\n'))
}

// createOwner allows a page on this origin to reserve and create without a session.
// A presented session cookie still has to be valid, so a dead login cannot act as anonymous.
func (s *Server) createOwner(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if !exactJSON(r) || !s.originOK(r) {
		writeJSON(w, http.StatusForbidden, forbidden)
		return nil, false
	}
	ip := clientip.FromRequest(r, s.cfg.TrustedProxies)
	if _, err := r.Cookie("__Host-session"); err != nil {
		if !s.lim.AllowIP("create:"+hashKey(ip), s.rules.Create) {
			writeJSON(w, http.StatusTooManyRequests, limited)
			return nil, false
		}
		return crypto.HashToken([]byte(ip)), true
	}
	sess, sum, ok := s.session(r)
	if !ok {
		if !s.lim.AllowIP("create:"+hashKey(ip), s.rules.Create) {
			writeJSON(w, http.StatusTooManyRequests, limited)
			return nil, false
		}
		writeJSON(w, http.StatusUnauthorized, unauthorized)
		return nil, false
	}
	if !csrfEqual(r.Header.Get("X-CSRF-Token"), sess.CSRF) {
		writeJSON(w, http.StatusForbidden, forbidden)
		return nil, false
	}
	if !s.lim.AllowIPAndSession("create:"+hashKey(ip), "create:"+hex.EncodeToString(sum), s.rules.Create) {
		writeJSON(w, http.StatusTooManyRequests, limited)
		return nil, false
	}
	return sum, true
}

func (s *Server) adminAuth(w http.ResponseWriter, r *http.Request) (storage.Session, bool) {
	if !exactJSON(r) || !s.originOK(r) {
		writeJSON(w, http.StatusForbidden, forbidden)
		return storage.Session{}, false
	}
	sess, _, ok := s.session(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, unauthorized)
		return storage.Session{}, false
	}
	if !csrfEqual(r.Header.Get("X-CSRF-Token"), sess.CSRF) {
		writeJSON(w, http.StatusForbidden, forbidden)
		return storage.Session{}, false
	}
	return sess, true
}

func (s *Server) session(r *http.Request) (storage.Session, []byte, bool) {
	c, err := r.Cookie("__Host-session")
	if err != nil {
		return storage.Session{}, nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 32 {
		return storage.Session{}, nil, false
	}
	sess, sum, ok, err := auth.Authenticate(s.db, raw, s.now())
	if err != nil || !ok {
		return storage.Session{}, nil, false
	}
	return sess, sum, true
}

func (s *Server) originOK(r *http.Request) bool {
	if !s.cfg.OriginOK(r.Header.Get("Origin")) {
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	return true
}

func csrfEqual(header string, want []byte) bool {
	got := decodeFixed(header, len(want))
	if got == nil || len(want) == 0 {
		return false
	}
	return crypto.Equal(got, want)
}

func exactJSON(r *http.Request) bool {
	return r.Header.Get("Content-Type") == "application/json"
}

func decode(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func decodeFixed(s string, n int) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != n {
		return nil
	}
	return b
}

func hashKey(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writePlain(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}
