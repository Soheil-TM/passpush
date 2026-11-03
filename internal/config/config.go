// Package config loads deployment settings from the environment.
// It never infers a public origin from interfaces or the Host header.
package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	argon2MemoryFloorKiB uint32 = 19 * 1024
	argon2TimeFloor      uint32 = 2
	argon2ThreadsFloor   uint8  = 1
	ciphertextDefault           = 64 * 1024
	ciphertextCeiling           = 1 << 20
	minPasswordLen              = 12
	maxPasswordLen              = 1024
)

// ModeDirect terminates TLS inside this process.
// ModeProxy expects a reverse proxy to terminate TLS.
const (
	ModeDirect = "direct"
	ModeProxy  = "proxy"
)

// Config is the validated process configuration.
type Config struct {
	ListenAddr        string
	PublicOrigin      *url.URL
	AlsoOrigins       []*url.URL
	DataDir           string
	AdminPasswordFile string
	TLSMode           string
	CertFile          string
	KeyFile           string
	TrustedProxies    map[string]struct{}
	Argon2MemoryKiB   uint32
	Argon2Time        uint32
	Argon2Threads     uint8
	MaxCiphertext     int
}

// HSTS reports whether this process sends Strict-Transport-Security.
// Only direct TLS termination does. A proxy must send it itself.
func (c Config) HSTS() bool { return c.TLSMode == ModeDirect }

// Load reads configuration from getenv (typically os.Getenv).
func Load(getenv func(string) string) (Config, error) {
	var cfg Config
	cfg.ListenAddr = getenv("LISTEN_ADDR")
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8443"
	}
	origin := strings.TrimSpace(getenv("PUBLIC_ORIGIN"))
	if origin == "" {
		return Config{}, fmt.Errorf("PUBLIC_ORIGIN is required")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return Config{}, fmt.Errorf("PUBLIC_ORIGIN is invalid")
	}
	if err := validateOrigin(u); err != nil {
		return Config{}, err
	}
	cfg.PublicOrigin = u
	also, err := parseAlsoOrigins(getenv("ALSO_ORIGINS"))
	if err != nil {
		return Config{}, err
	}
	cfg.AlsoOrigins = also

	cfg.DataDir = getenv("DATA_DIR")
	if cfg.DataDir == "" {
		return Config{}, fmt.Errorf("DATA_DIR is required")
	}
	cfg.AdminPasswordFile = getenv("ADMIN_PASSWORD_FILE")
	if cfg.AdminPasswordFile == "" {
		return Config{}, fmt.Errorf("ADMIN_PASSWORD_FILE is required")
	}

	cfg.TLSMode = getenv("TLS_MODE")
	switch cfg.TLSMode {
	case ModeDirect:
		cfg.CertFile = getenv("TLS_CERT_FILE")
		cfg.KeyFile = getenv("TLS_KEY_FILE")
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return Config{}, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE are required in direct mode")
		}
	case ModeProxy:
	default:
		return Config{}, fmt.Errorf("TLS_MODE must be direct or proxy")
	}

	proxies, err := parseProxies(getenv("TRUSTED_PROXY_IPS"))
	if err != nil {
		return Config{}, err
	}
	if cfg.TLSMode == ModeProxy && len(proxies) == 0 {
		return Config{}, fmt.Errorf("TRUSTED_PROXY_IPS is required in proxy mode")
	}
	cfg.TrustedProxies = proxies

	mem, err := uintEnv(getenv, "ARGON2_MEMORY_KIB", argon2MemoryFloorKiB)
	if err != nil {
		return Config{}, err
	}
	timeCost, err := uintEnv(getenv, "ARGON2_ITERATIONS", argon2TimeFloor)
	if err != nil {
		return Config{}, err
	}
	threads, err := uintEnv(getenv, "ARGON2_PARALLELISM", uint32(argon2ThreadsFloor))
	if err != nil {
		return Config{}, err
	}
	if mem < argon2MemoryFloorKiB || timeCost < argon2TimeFloor || threads < uint32(argon2ThreadsFloor) || threads > 255 {
		return Config{}, fmt.Errorf("Argon2 parameters are below the floor")
	}
	cfg.Argon2MemoryKiB = mem
	cfg.Argon2Time = timeCost
	cfg.Argon2Threads = uint8(threads)

	maxCT := ciphertextDefault
	if raw := getenv("MAX_CIPHERTEXT_BYTES"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("MAX_CIPHERTEXT_BYTES is invalid")
		}
		maxCT = n
	}
	if maxCT < 16 || maxCT > ciphertextCeiling {
		return Config{}, fmt.Errorf("MAX_CIPHERTEXT_BYTES is outside %d..%d", 16, ciphertextCeiling)
	}
	cfg.MaxCiphertext = maxCT
	return cfg, nil
}

func validateOrigin(u *url.URL) error {
	if u.Scheme != "https" || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("PUBLIC_ORIGIN must be an https origin")
	}
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("PUBLIC_ORIGIN must not include userinfo, a path, a query, a fragment, or a trailing slash")
	}
	return nil
}

func parseAlsoOrigins(raw string) ([]*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []*url.URL
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("ALSO_ORIGINS contains an empty entry")
		}
		u, err := url.Parse(part)
		if err != nil {
			return nil, fmt.Errorf("ALSO_ORIGINS contains an invalid origin")
		}
		if err := validateOrigin(u); err != nil {
			return nil, fmt.Errorf("ALSO_ORIGINS contains an invalid origin")
		}
		out = append(out, u)
	}
	return out, nil
}

func parseProxies(raw string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out, nil
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("TRUSTED_PROXY_IPS contains an empty entry")
		}
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, fmt.Errorf("TRUSTED_PROXY_IPS contains a value that is not an IP address")
		}
		out[ip.String()] = struct{}{}
	}
	return out, nil
}

func uintEnv(getenv func(string) string, key string, def uint32) (uint32, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s is invalid", key)
	}
	return uint32(n), nil
}

// ValidatePassword enforces the minimum length. Length is necessary, not sufficient.
func ValidatePassword(password []byte) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("admin password is shorter than %d characters", minPasswordLen)
	}
	if len(password) > maxPasswordLen {
		return fmt.Errorf("admin password is longer than %d characters", maxPasswordLen)
	}
	return nil
}

// ReadPasswordFile reads the admin password and trims one trailing newline.
// The caller must wipe the returned slice.
func ReadPasswordFile(path string, read func(string) ([]byte, error)) ([]byte, error) {
	b, err := read(path)
	if err != nil {
		return nil, fmt.Errorf("admin password file is missing")
	}
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
		if len(b) > 0 && b[len(b)-1] == '\r' {
			b = b[:len(b)-1]
		}
	}
	if err := ValidatePassword(b); err != nil {
		for i := range b {
			b[i] = 0
		}
		return nil, err
	}
	return b, nil
}

// HostAllowed reports whether the request Host matches PUBLIC_ORIGIN.
// An absent host is rejected. The default HTTPS port is 443.
func HostAllowed(origin *url.URL, hostHeader string) bool {
	if origin == nil || hostHeader == "" {
		return false
	}
	wantHost := origin.Hostname()
	wantPort := origin.Port()
	if wantPort == "" {
		wantPort = "443"
	}
	gotHost, gotPort, err := net.SplitHostPort(hostHeader)
	if err != nil {
		gotHost = hostHeader
		gotPort = "443"
	}
	gotHost = strings.Trim(gotHost, "[]")
	return strings.EqualFold(gotHost, wantHost) && gotPort == wantPort
}

// RequestHostOK accepts the public origin and any ALSO_ORIGINS host.
func (c Config) RequestHostOK(hostHeader string) bool {
	if HostAllowed(c.PublicOrigin, hostHeader) {
		return true
	}
	for _, origin := range c.AlsoOrigins {
		if HostAllowed(origin, hostHeader) {
			return true
		}
	}
	return false
}

// OriginOK accepts the public origin and any ALSO_ORIGINS value.
func (c Config) OriginOK(origin string) bool {
	if c.PublicOrigin != nil && origin == c.PublicOrigin.String() {
		return true
	}
	for _, extra := range c.AlsoOrigins {
		if origin == extra.String() {
			return true
		}
	}
	return false
}
