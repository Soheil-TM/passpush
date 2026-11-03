// Package tlsconfig loads and checks the certificate before any listener exists.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"pwpush/internal/config"
)

// Load reads the direct-mode certificate and checks the SAN against PUBLIC_ORIGIN.
// Proxy mode returns a nil config. This function does not listen.
func Load(cfg config.Config, now time.Time) (*tls.Config, error) {
	if cfg.TLSMode != config.ModeDirect {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls certificate or key could not be loaded")
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("tls certificate is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("tls certificate could not be parsed")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("tls certificate is expired or not yet valid")
	}
	host := cfg.PublicOrigin.Hostname()
	if !sanMatches(leaf, host) {
		return nil, fmt.Errorf("tls certificate SAN does not match PUBLIC_ORIGIN")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

func sanMatches(leaf *x509.Certificate, host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		for _, candidate := range leaf.IPAddresses {
			if candidate.Equal(ip) {
				return true
			}
		}
		return false
	}
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, host) {
			return true
		}
	}
	return false
}
