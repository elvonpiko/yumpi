package netmgr

import (
	"strings"
	"testing"

	"yumpi/internal/config"
	"yumpi/internal/state"
)

func cfg() config.Config {
	c := config.Config{
		WiFi: config.WiFi{
			Interface: "wlan0", SSID: "IEEE", Passphrase: "password", Country: "US", Channel: 36,
			Address: "10.23.46.1/24", DHCPStart: "10.23.46.50", DHCPEnd: "10.23.46.200", Lease: "12h",
		},
		LAN: config.LAN{
			Interface: "eth0", Address: "10.23.45.2/24",
			DHCPStart: "10.23.45.100", DHCPEnd: "10.23.45.200", Lease: "12h", Upstream: "10.23.45.1",
		},
		DNS:   config.DNS{Tunnel: "10.64.0.1", Direct: "1.1.1.1"},
		Paths: config.Paths{Leases: "/var/lib/yumpi/leases"},
	}
	return c
}

func TestWPA2VectorAndHostapd(t *testing.T) {
	if got := WPA2PSK("IEEE", "password"); got != "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e" {
		t.Fatal(got)
	}
	conf := HostapdConf(cfg().WiFi, config.Guest{}, false, "/run/yumpi/hostapd.deny", "/run/yumpi/hostapd")
	if strings.Contains(conf, "password") {
		t.Fatal("passphrase leaked into hostapd.conf")
	}
	if !strings.Contains(conf, "wpa_psk=f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e") {
		t.Fatal(conf)
	}
	if !strings.Contains(conf, "hw_mode=a") || !strings.Contains(conf, "ieee80211ac=1") {
		t.Fatal(conf)
	}
	low := cfg().WiFi
	low.Channel = 6
	lowConf := HostapdConf(low, config.Guest{}, false, "/run/yumpi/hostapd.deny", "/run/yumpi/hostapd")
	if !strings.Contains(lowConf, "hw_mode=g") || !strings.Contains(lowConf, "channel=6") || !strings.Contains(lowConf, "ieee80211ac=0") {
		t.Fatal(lowConf)
	}
	guest := config.Guest{Interface: "wlan0_0", SSID: "YumPi-Guest", Passphrase: "guestpass"}
	with := HostapdConf(cfg().WiFi, guest, true, "/run/yumpi/hostapd.deny", "/run/yumpi/hostapd")
	if strings.Contains(with, "guestpass") || !strings.Contains(with, "bss=wlan0_0") || !strings.Contains(with, "ap_isolate=1") {
		t.Fatal(with)
	}
}

func TestDNSMasqIsDHCPOnly(t *testing.T) {
	conf, err := DNSMasqConf(cfg(), "/var/lib/yumpi/leases", state.State{
		Reservations: []state.Reservation{{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.23.46.10", Name: "tv"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "port=0\n") {
		t.Fatal(conf)
	}
	if !strings.Contains(conf, "dhcp-option=tag:wifi,6,10.64.0.1") || !strings.Contains(conf, "dhcp-host=aa:bb:cc:dd:ee:ff,10.23.46.10,tv") {
		t.Fatal(conf)
	}
	if strings.Contains(conf, "server=") {
		t.Fatal("dnsmasq should not forward DNS")
	}
}
