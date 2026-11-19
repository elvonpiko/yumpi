package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"yumpi/internal/api"
	"yumpi/internal/auth"
	"yumpi/internal/config"
	"yumpi/internal/daemon"
	"yumpi/internal/state"
	"yumpi/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "init-config" {
		if err := initConfig(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "yumpi:", err)
			os.Exit(1)
		}
		return
	}
	fs := flag.NewFlagSet("yumpi", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("config", "/etc/yumpi/config.toml", "configuration file")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg, err := config.Load(*path)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	store, err := state.Open(cfg.Paths.State)
	if err != nil {
		log.Error("state", "err", err)
		os.Exit(1)
	}
	passwords, err := auth.New(cfg.Auth.PasswordHash)
	if err != nil {
		log.Error("auth", "err", err)
		os.Exit(1)
	}
	d := daemon.New(cfg, *path, store, passwords, log, nil)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go d.Run(ctx)
	handler := api.New(d, web.FS, log)
	httpsAddr := httpsListen(cfg.Listen)
	cert, key, err := api.EnsureCert(filepath.Join(filepath.Dir(cfg.Paths.State), "tls"), certHosts(cfg))
	if err != nil {
		log.Error("https certificate", "err", err)
		os.Exit(1)
	}
	log.Info("listening", "addr", httpsAddr, "tls", true)
	if err := api.ServeTLS(ctx, httpsAddr, cert, key, handler); err != nil {
		log.Error("https", "err", err)
		os.Exit(1)
	}
}

func httpsListen(httpAddr string) string {
	host, port, err := net.SplitHostPort(httpAddr)
	if err != nil || port != "8080" {
		return net.JoinHostPort(host, "8443")
	}
	return net.JoinHostPort(host, "8443")
}

func certHosts(cfg config.Config) []string {
	var hosts []string
	if n, err := cfg.LANNet(); err == nil {
		hosts = append(hosts, n.Gateway.String())
	}
	if n, err := cfg.WiFiNet(); err == nil {
		hosts = append(hosts, n.Gateway.String())
	}
	if n, err := cfg.GuestNet(); err == nil {
		hosts = append(hosts, n.Gateway.String())
	}
	return hosts
}
