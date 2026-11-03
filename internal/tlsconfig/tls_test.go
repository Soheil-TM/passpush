package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pwpush/internal/config"
)

func writeCert(t *testing.T, host string, ip net.IP, notBefore, notAfter time.Time) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func directCfg(origin, cert, key string) config.Config {
	env := map[string]string{
		"PUBLIC_ORIGIN":       origin,
		"DATA_DIR":            "/tmp/unused",
		"ADMIN_PASSWORD_FILE": "/tmp/unused-pw",
		"TLS_MODE":            "direct",
		"TLS_CERT_FILE":       cert,
		"TLS_KEY_FILE":        key,
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		panic(err)
	}
	return cfg
}

func TestSANSuccessDNSAndIP(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cert, key := writeCert(t, "secrets.example", nil, now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := Load(directCfg("https://secrets.example", cert, key), now); err != nil {
		t.Fatal(err)
	}
	cert, key = writeCert(t, "203.0.113.10", net.ParseIP("203.0.113.10"), now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := Load(directCfg("https://203.0.113.10", cert, key), now); err != nil {
		t.Fatal(err)
	}
}

func TestWrongSANAndExpired(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cert, key := writeCert(t, "other.example", nil, now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := Load(directCfg("https://secrets.example", cert, key), now); err == nil {
		t.Fatal("wrong SAN accepted")
	}
	cert, key = writeCert(t, "secrets.example", nil, now.Add(-48*time.Hour), now.Add(-time.Hour))
	if _, err := Load(directCfg("https://secrets.example", cert, key), now); err == nil {
		t.Fatal("expired cert accepted")
	}
}

func TestProxySkipsCertificates(t *testing.T) {
	env := map[string]string{
		"PUBLIC_ORIGIN":       "https://secrets.example",
		"DATA_DIR":            "/tmp/unused",
		"ADMIN_PASSWORD_FILE": "/tmp/unused-pw",
		"TLS_MODE":            "proxy",
		"TRUSTED_PROXY_IPS":   "127.0.0.1",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("proxy mode returned a tls config")
	}
}
