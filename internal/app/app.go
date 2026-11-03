// Package app prepares the process and only then listens.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"pwpush/internal/auth"
	"pwpush/internal/config"
	"pwpush/internal/httpserver"
	"pwpush/internal/storage"
	"pwpush/internal/tlsconfig"
)

// Runtime is a validated process that has not listened yet.
type Runtime struct {
	Cfg  config.Config
	DB   *storage.DB
	TLS  *tls.Config
	HTTP *httpserver.Server
}

// Prepare validates TLS, opens SQLite, and initialises the admin password.
// It does not open a port.
func Prepare(cfg config.Config) (*Runtime, error) {
	return prepare(cfg, httpserver.ProductionRules())
}

func prepare(cfg config.Config, rules httpserver.Rules) (*Runtime, error) {
	tlsConf, err := tlsconfig.Load(cfg, time.Now())
	if err != nil {
		return nil, err
	}
	db, err := storage.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if err := auth.EnsureAdmin(db, cfg); err != nil {
		db.Close()
		return nil, err
	}
	srv, err := httpserver.New(cfg, db, nil, rules, time.Now)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Runtime{Cfg: cfg, DB: db, TLS: tlsConf, HTTP: srv}, nil
}

// Serve listens only after Prepare has succeeded. Cancellation shuts the server down
// and runs a WAL checkpoint.
func (rt *Runtime) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", rt.Cfg.ListenAddr)
	if err != nil {
		return err
	}
	go rt.cleanup(ctx)
	hs := &http.Server{
		Handler:           rt.HTTP,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 14,
	}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(shut)
	}()
	var serveErr error
	if rt.TLS != nil {
		serveErr = hs.Serve(tls.NewListener(ln, rt.TLS))
	} else {
		serveErr = hs.Serve(ln)
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	if err := rt.DB.Checkpoint(); err != nil && serveErr == nil {
		serveErr = err
	}
	return serveErr
}

func (rt *Runtime) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := rt.DB.Cleanup(now); err != nil {
				log.Printf("event=cleanup status=error")
			}
		}
	}
}

// ResetAdmin opens the database, replaces the password, and does not listen.
func ResetAdmin(cfg config.Config) error {
	db, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()
	return auth.ResetAdmin(db, cfg)
}

// Healthcheck requests /healthz. It does not open the database.
func Healthcheck(cfg config.Config) error {
	host, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, port)
	client := &http.Client{Timeout: 3 * time.Second}
	url := "http://" + addr + "/healthz"
	if cfg.TLSMode == config.ModeDirect {
		url = "https://" + addr + "/healthz"
		pemBytes, err := os.ReadFile(cfg.CertFile)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return errors.New("tls certificate file has no certificates")
		}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: cfg.PublicOrigin.Hostname(),
				RootCAs:    pool,
			},
		}
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Host = cfg.PublicOrigin.Hostname()
	if port := cfg.PublicOrigin.Port(); port != "" {
		req.Host = net.JoinHostPort(cfg.PublicOrigin.Hostname(), port)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		return errors.New("healthcheck failed")
	}
	return nil
}
