package app

import (
	"context"
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

func load(t *testing.T, extra map[string]string) config.Config {
	t.Helper()
	dir := t.TempDir()
	pw := filepath.Join(dir, "password")
	pass := "long-enough-pw"
	if v, ok := extra["PASSWORD"]; ok {
		pass = v
		delete(extra, "PASSWORD")
	}
	if err := os.WriteFile(pw, []byte(pass+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"PUBLIC_ORIGIN":       "https://secrets.example",
		"DATA_DIR":            dir,
		"ADMIN_PASSWORD_FILE": pw,
		"TLS_MODE":            "proxy",
		"TRUSTED_PROXY_IPS":   "127.0.0.1",
		"LISTEN_ADDR":         "127.0.0.1:0",
	}
	for k, v := range extra {
		env[k] = v
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func assertClosed(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatalf("port %s accepted a connection", addr)
	}
}

func TestShortPasswordDoesNotListen(t *testing.T) {
	addr := closedAddr(t)
	cfg := load(t, map[string]string{"PASSWORD": "short", "LISTEN_ADDR": addr})
	if _, err := Prepare(cfg); err == nil {
		t.Fatal("short password started")
	}
	assertClosed(t, addr)
}

func TestBadCertificateDoesNotListen(t *testing.T) {
	addr := closedAddr(t)
	dir := t.TempDir()
	cert, key := writeCert(t, "other.example", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cfg := load(t, map[string]string{
		"LISTEN_ADDR":   addr,
		"TLS_MODE":      "direct",
		"TLS_CERT_FILE": cert,
		"TLS_KEY_FILE":  key,
		"DATA_DIR":      dir,
	})
	if _, err := Prepare(cfg); err == nil {
		t.Fatal("wrong SAN started")
	}
	assertClosed(t, addr)

	cert, key = writeCert(t, "secrets.example", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	cfg = load(t, map[string]string{
		"LISTEN_ADDR":   addr,
		"TLS_MODE":      "direct",
		"TLS_CERT_FILE": cert,
		"TLS_KEY_FILE":  key,
	})
	if _, err := Prepare(cfg); err == nil {
		t.Fatal("expired certificate started")
	}
	assertClosed(t, addr)
}

func TestValidCertificateDoesNotListenUntilServe(t *testing.T) {
	addr := closedAddr(t)
	cert, key := writeCert(t, "secrets.example", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	cfg := load(t, map[string]string{
		"LISTEN_ADDR":   addr,
		"TLS_MODE":      "direct",
		"TLS_CERT_FILE": cert,
		"TLS_KEY_FILE":  key,
	})
	rt, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.DB.Close()
	assertClosed(t, addr)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- rt.Serve(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	var healthy bool
	for time.Now().Before(deadline) {
		if err := Healthcheck(cfg); err == nil {
			healthy = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !healthy {
		t.Fatal("server did not become healthy")
	}
	assertClosed(t, addr)
}

func writeCert(t *testing.T, host string, notBefore, notAfter time.Time) (string, string) {
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
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
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

func TestPrepareDoesNotListen(t *testing.T) {
	addr := closedAddr(t)
	cfg := load(t, map[string]string{"LISTEN_ADDR": addr})
	rt, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.DB.Close()
	assertClosed(t, addr)
}
