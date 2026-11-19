package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"yumpi/internal/auth"
	"yumpi/internal/config"
)

func initConfig(args []string) error {
	fs := flag.NewFlagSet("init-config", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("path", "/etc/yumpi/config.toml", "config path")
	force := fs.Bool("force", false, "replace an existing config")
	listen := fs.String("listen", ":8080", "dashboard listen address")
	model := fs.String("model", "", "device name shown in the footer")
	ssid := fs.String("ssid", "YumPi", "access point name")
	country := fs.String("country", "US", "Wi-Fi regulatory country")
	channel := fs.Int("channel", 36, "Wi-Fi channel")
	wifiIf := fs.String("wifi-if", "wlan0", "access point interface")
	wifiCIDR := fs.String("wifi-cidr", "10.23.46.1/24", "access point address")
	wifiStart := fs.String("wifi-dhcp-start", "10.23.46.50", "access point DHCP start")
	wifiEnd := fs.String("wifi-dhcp-end", "10.23.46.200", "access point DHCP end")
	lanIf := fs.String("lan-if", "eth0", "upstream interface")
	lanCIDR := fs.String("lan-cidr", "", "upstream address in CIDR form")
	lanStart := fs.String("lan-dhcp-start", "", "LAN DHCP start")
	lanEnd := fs.String("lan-dhcp-end", "", "LAN DHCP end")
	upstream := fs.String("upstream", "", "upstream router address")
	statePath := fs.String("state", "/var/lib/yumpi/state.json", "state file")
	runDir := fs.String("run", "/run/yumpi", "runtime directory")
	leases := fs.String("leases", "/var/lib/yumpi/leases", "DHCP lease file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*path); err == nil && !*force {
		fmt.Fprintln(os.Stderr, "config already exists, leaving it in place")
		return nil
	}
	admin := os.Getenv("YUMPI_ADMIN_PASSWORD")
	wifiPass := os.Getenv("YUMPI_WIFI_PASSPHRASE")
	if len(admin) < 12 {
		return errors.New("YUMPI_ADMIN_PASSWORD must be at least 12 characters")
	}
	if len(wifiPass) < 8 || len(wifiPass) > 63 {
		return errors.New("YUMPI_WIFI_PASSPHRASE must be 8 to 63 characters")
	}
	if *lanCIDR == "" || *upstream == "" || *lanStart == "" || *lanEnd == "" {
		return errors.New("lan address, dhcp range, and upstream are required")
	}
	hash, err := auth.HashPassword(admin)
	if err != nil {
		return err
	}
	cfg := config.Config{
		Listen: *listen,
		Model:  strings.TrimSpace(*model),
		Auth:   config.Auth{PasswordHash: hash},
		WiFi: config.WiFi{
			Interface: *wifiIf, SSID: *ssid, Passphrase: wifiPass,
			Country: strings.ToUpper(*country), Channel: *channel,
			Address: *wifiCIDR, DHCPStart: *wifiStart, DHCPEnd: *wifiEnd, Lease: "12h",
		},
		LAN: config.LAN{
			Interface: *lanIf, Address: *lanCIDR,
			DHCPStart: *lanStart, DHCPEnd: *lanEnd, Lease: "12h", Upstream: *upstream,
		},
		DNS:     config.DNS{Tunnel: "10.64.0.1", Direct: "1.1.1.1"},
		Mullvad: config.Mullvad{Interface: "wg0-mullvad"},
		Paths:   config.Paths{State: *statePath, Run: *runDir, Leases: *leases},
	}
	if err := config.Save(*path, cfg); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "wrote", *path)
	return nil
}
