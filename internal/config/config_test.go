package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig() Config {
	return Config{
		Listen: ":8080",
		Auth:   Auth{PasswordHash: "$2a$04$012345678901234567890u012345678901234567890123456789012"},
		WiFi: WiFi{
			Interface: "wlan0", SSID: "YumPi", Passphrase: "correct horse",
			Country: "US", Channel: 36, Address: "10.23.46.1/24",
			DHCPStart: "10.23.46.50", DHCPEnd: "10.23.46.200", Lease: "12h",
		},
		LAN: LAN{
			Interface: "eth0", Address: "10.23.45.2/24",
			DHCPStart: "10.23.45.100", DHCPEnd: "10.23.45.200", Lease: "12h",
			Upstream: "10.23.45.1",
		},
		DNS:     DNS{Tunnel: "10.64.0.1", Direct: "1.1.1.1"},
		Mullvad: Mullvad{Interface: "wg0-mullvad"},
		Paths:   Paths{State: "/var/lib/yumpi/state.json", Run: "/run/yumpi", Leases: "/var/lib/yumpi/leases"},
	}
}

func TestValidateAcceptsTheGateway(t *testing.T) {
	cfg := testConfig()
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	wifi, err := cfg.WiFiNet()
	if err != nil {
		t.Fatal(err)
	}
	if wifi.Gateway.String() != "10.23.46.1" || wifi.Prefix.String() != "10.23.46.0/24" {
		t.Fatalf("wifi net: %+v", wifi)
	}
	if PoolSize(wifi.DHCPStart, wifi.DHCPEnd) != 151 {
		t.Fatalf("pool %d", PoolSize(wifi.DHCPStart, wifi.DHCPEnd))
	}
}

func TestValidateRejectsOverlapAndShortSecrets(t *testing.T) {
	cfg := testConfig()
	cfg.LAN.Address = "10.23.46.2/24"
	cfg.LAN.DHCPStart = "10.23.46.100"
	cfg.LAN.DHCPEnd = "10.23.46.120"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("got %v", err)
	}
	cfg = testConfig()
	cfg.WiFi.Passphrase = "short"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected passphrase error")
	}
	cfg = testConfig()
	cfg.WiFi.SSID = "bad\nssid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected ssid error")
	}
}

func TestSaveIsPrivate(t *testing.T) {
	cfg := testConfig()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.WiFi.Passphrase != cfg.WiFi.Passphrase || loaded.LAN.Upstream != "10.23.45.1" {
		t.Fatalf("%+v", loaded)
	}
}

func TestBandChoiceKeepsAnExistingChannel(t *testing.T) {
	wifi := testConfig().WiFi
	if wifi.Band() != "5" {
		t.Fatal(wifi.Band())
	}
	got, err := wifi.ChannelForBand("5")
	if err != nil || got != 36 {
		t.Fatalf("%d %v", got, err)
	}
	wifi.Channel = 149
	got, err = wifi.ChannelForBand("5")
	if err != nil || got != 149 {
		t.Fatalf("kept %d %v", got, err)
	}
	got, err = wifi.ChannelForBand("2.4")
	if err != nil || got != Channel24 || wifi.Band() != "5" {
		t.Fatalf("switch %d %v", got, err)
	}
	wifi.Channel = 11
	if wifi.Band() != "2.4" {
		t.Fatal(wifi.Band())
	}
	got, err = wifi.ChannelForBand("2.4")
	if err != nil || got != 11 {
		t.Fatalf("kept 2.4 %d %v", got, err)
	}
	got, err = wifi.ChannelForBand("5")
	if err != nil || got != Channel5 {
		t.Fatalf("back %d %v", got, err)
	}
	if _, err := wifi.ChannelForBand("6"); err == nil {
		t.Fatal("accepted a bad band")
	}
}
