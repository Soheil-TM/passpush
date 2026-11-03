package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"pwpush/internal/app"
	"pwpush/internal/config"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		rt, err := app.Prepare(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "startup: %v\n", err)
			os.Exit(1)
		}
		defer rt.DB.Close()
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := rt.Serve(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "server: %v\n", err)
			os.Exit(1)
		}
	case "reset-admin":
		if err := app.ResetAdmin(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "reset-admin: %v\n", err)
			os.Exit(1)
		}
	case "healthcheck":
		if err := app.Healthcheck(cfg); err != nil {
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "usage: pwpush [serve|reset-admin|healthcheck]\n")
		os.Exit(2)
	}
}
