package config

import (
	"net"
	"testing"
)

func envWith(values map[string]string) func(string) string {
	return func(k string) string { return values[k] }
}

func baseEnv() map[string]string {
	return map[string]string{
		"PUBLIC_ORIGIN":       "https://secrets.example",
		"DATA_DIR":            "/data",
		"ADMIN_PASSWORD_FILE": "/run/secrets/admin_password",
		"TLS_MODE":            "direct",
		"TLS_CERT_FILE":       "/certs/tls.crt",
		"TLS_KEY_FILE":        "/certs/tls.key",
	}
}

func TestLoadRejectsMissingOrigin(t *testing.T) {
	env := baseEnv()
	delete(env, "PUBLIC_ORIGIN")
	if _, err := Load(envWith(env)); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadRejectsInsecureOrigin(t *testing.T) {
	for _, origin := range []string{
		"http://secrets.example",
		"https://secrets.example/",
		"https://secrets.example/app",
		"https://user@secrets.example",
		"https://secrets.example?x=1",
		"https://secrets.example#frag",
	} {
		env := baseEnv()
		env["PUBLIC_ORIGIN"] = origin
		if _, err := Load(envWith(env)); err == nil {
			t.Fatalf("origin %q was accepted", origin)
		}
	}
}

func TestLoadRejectsEmptyProxyList(t *testing.T) {
	env := baseEnv()
	env["TLS_MODE"] = "proxy"
	delete(env, "TLS_CERT_FILE")
	delete(env, "TLS_KEY_FILE")
	if _, err := Load(envWith(env)); err == nil {
		t.Fatal("proxy mode without TRUSTED_PROXY_IPS was accepted")
	}
}

func TestLoadRejectsArgon2BelowFloor(t *testing.T) {
	env := baseEnv()
	env["ARGON2_MEMORY_KIB"] = "1024"
	if _, err := Load(envWith(env)); err == nil {
		t.Fatal("low argon2 memory was accepted")
	}
	env["ARGON2_MEMORY_KIB"] = "19456"
	env["ARGON2_ITERATIONS"] = "1"
	if _, err := Load(envWith(env)); err == nil {
		t.Fatal("low argon2 iterations were accepted")
	}
}

func TestLoadRejectsCiphertextCeiling(t *testing.T) {
	env := baseEnv()
	env["MAX_CIPHERTEXT_BYTES"] = "2000000"
	if _, err := Load(envWith(env)); err == nil {
		t.Fatal("ciphertext above 1 MiB was accepted")
	}
}

func TestLoadDirectAndProxy(t *testing.T) {
	cfg, err := Load(envWith(baseEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HSTS() {
		t.Fatal("direct mode must send HSTS")
	}
	if cfg.MaxCiphertext != 64*1024 {
		t.Fatalf("default ciphertext = %d", cfg.MaxCiphertext)
	}
	env := baseEnv()
	env["TLS_MODE"] = "proxy"
	env["TRUSTED_PROXY_IPS"] = "127.0.0.1, ::1"
	delete(env, "TLS_CERT_FILE")
	delete(env, "TLS_KEY_FILE")
	cfg, err = Load(envWith(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HSTS() {
		t.Fatal("proxy mode must not send HSTS")
	}
	if _, ok := cfg.TrustedProxies[net.ParseIP("::1").String()]; !ok {
		t.Fatal("trusted proxy was not canonicalised")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword([]byte("short")); err == nil {
		t.Fatal("short password accepted")
	}
	if err := ValidatePassword([]byte("long-enough-pw")); err != nil {
		t.Fatal(err)
	}
}

func TestHostAllowed(t *testing.T) {
	cfg, err := Load(envWith(baseEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if !HostAllowed(cfg.PublicOrigin, "secrets.example") {
		t.Fatal("bare host rejected")
	}
	if !HostAllowed(cfg.PublicOrigin, "secrets.example:443") {
		t.Fatal("explicit 443 rejected")
	}
	if HostAllowed(cfg.PublicOrigin, "secrets.example:8443") {
		t.Fatal("wrong port accepted")
	}
	if HostAllowed(cfg.PublicOrigin, "evil.example") {
		t.Fatal("foreign host accepted")
	}
	if HostAllowed(cfg.PublicOrigin, "") {
		t.Fatal("empty host accepted")
	}
}

func TestAlsoOrigins(t *testing.T) {
	env := baseEnv()
	env["ALSO_ORIGINS"] = "https://192.0.2.10:8443"
	cfg, err := Load(envWith(env))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequestHostOK("secrets.example") || !cfg.RequestHostOK("192.0.2.10:8443") {
		t.Fatal("allowed host rejected")
	}
	if cfg.RequestHostOK("evil.example") || !cfg.OriginOK("https://192.0.2.10:8443") || cfg.OriginOK("https://evil.example") {
		t.Fatal("foreign origin accepted")
	}
}
