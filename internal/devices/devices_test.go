package devices

import (
	"net/netip"
	"testing"
	"time"

	"yumpi/internal/config"
	"yumpi/internal/state"
)

func TestAssembleLeasesStationsAndBypass(t *testing.T) {
	wifi := config.Network{
		Iface: "wlan0", Gateway: netip.MustParseAddr("10.23.46.1"), Prefix: netip.MustParsePrefix("10.23.46.0/24"),
		DHCPStart: netip.MustParseAddr("10.23.46.50"), DHCPEnd: netip.MustParseAddr("10.23.46.200"),
	}
	lan := config.Network{
		Iface: "eth0", Gateway: netip.MustParseAddr("10.23.45.2"), Prefix: netip.MustParsePrefix("10.23.45.0/24"),
		DHCPStart: netip.MustParseAddr("10.23.45.100"), DHCPEnd: netip.MustParseAddr("10.23.45.200"),
	}
	now := time.Unix(1_700_000_000, 0)
	leases := "1700003600 aa:bb:cc:dd:ee:01 10.23.46.50 Phone *\n1700080000 98:28:a6:48:a4:0f 10.23.45.145 DESKTOP *\n1700080000 aa:bb:cc:dd:ee:09 10.23.46.80 Left *\n"
	stations := "Station aa:bb:cc:dd:ee:01 (on wlan0)\n"
	neigh := "10.23.45.145 dev eth0 lladdr 98:28:a6:48:a4:0f REACHABLE\n10.23.45.1 dev eth0 lladdr 82:9a:a7:54:51:30 REACHABLE\n10.23.45.201 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
	st := state.State{BypassIPs: []string{"10.23.45.145"}, BlockedMACs: []string{"aa:bb:cc:dd:ee:01"}}
	snap := Assemble(now, wifi, lan, []netip.Addr{wifi.Gateway, lan.Gateway}, netip.MustParseAddr("10.23.45.1"), leases, stations, neigh, st)
	if snap.LeasesUsed != 3 || snap.Online != 2 || snap.Expiring != 1 || len(snap.Devices) != 2 {
		t.Fatalf("counts leases=%d online=%d expiring=%d devices=%d", snap.LeasesUsed, snap.Online, snap.Expiring, len(snap.Devices))
	}
	var phone, desk *Device
	for i := range snap.Devices {
		d := &snap.Devices[i]
		switch d.IP {
		case "10.23.46.50":
			phone = d
		case "10.23.45.145":
			desk = d
		case "10.23.45.201":
			t.Fatal("a wired neighbor without a lease is not a YumPi client")
		case "10.23.46.80":
			t.Fatal("a Wi-Fi lease without a connection should stay off the list")
		case "10.23.45.1":
			t.Fatal("upstream router should be hidden")
		}
	}
	if phone == nil || !phone.Online || !phone.VPN || !phone.Blocked || phone.Source != "wifi" {
		t.Fatalf("phone %+v", phone)
	}
	if desk == nil || desk.VPN || desk.Name != "DESKTOP" || !desk.Online {
		t.Fatalf("desk %+v", desk)
	}
}
