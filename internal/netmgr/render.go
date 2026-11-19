package netmgr

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"yumpi/internal/config"
	"yumpi/internal/netconv"
	"yumpi/internal/state"
)

// WPA2PSK is the 256-bit PSK from PBKDF2-HMAC-SHA1, which is what WPA2-PSK specifies.
func WPA2PSK(ssid, passphrase string) string {
	sum := pbkdf2.Key([]byte(passphrase), []byte(ssid), 4096, 32, sha1.New)
	return hex.EncodeToString(sum)
}

// HostapdConf renders a 5 GHz or 2.4 GHz AP config. The passphrase is stored only as a PSK.
func HostapdConf(wifi config.WiFi, denyPath, ctrlDir string) string {
	mode := "a"
	ac := "1"
	if wifi.Channel <= 14 {
		mode = "g"
		ac = "0"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "interface=%s\n", wifi.Interface)
	b.WriteString("driver=nl80211\n")
	fmt.Fprintf(&b, "ssid=%s\n", wifi.SSID)
	fmt.Fprintf(&b, "hw_mode=%s\n", mode)
	fmt.Fprintf(&b, "channel=%d\n", wifi.Channel)
	b.WriteString("ieee80211n=1\n")
	fmt.Fprintf(&b, "ieee80211ac=%s\n", ac)
	b.WriteString("ieee80211d=1\n")
	b.WriteString("wmm_enabled=1\n")
	fmt.Fprintf(&b, "country_code=%s\n", wifi.Country)
	b.WriteString("auth_algs=1\n")
	b.WriteString("wpa=2\n")
	fmt.Fprintf(&b, "wpa_psk=%s\n", WPA2PSK(wifi.SSID, wifi.Passphrase))
	b.WriteString("wpa_key_mgmt=WPA-PSK\n")
	b.WriteString("rsn_pairwise=CCMP\n")
	b.WriteString("macaddr_acl=0\n")
	fmt.Fprintf(&b, "deny_mac_file=%s\n", denyPath)
	fmt.Fprintf(&b, "ctrl_interface=%s\n", ctrlDir)
	b.WriteString("ctrl_interface_group=0\n")
	return b.String()
}

// DenyFile is the hostapd MAC deny list.
func DenyFile(macs []string) string {
	var b strings.Builder
	for _, m := range macs {
		if mac, ok := netconv.MAC(m); ok {
			fmt.Fprintf(&b, "%s\n", mac)
		}
	}
	return b.String()
}

// DNSMasqConf is DHCP only. Clients are told to use Mullvad DNS; the firewall
// rewrites that for bypassed devices and for everyone when the tunnel is down.
func DNSMasqConf(cfg config.Config, leases string, st state.State) (string, error) {
	wifi, err := cfg.WiFiNet()
	if err != nil {
		return "", err
	}
	lan, err := cfg.LANNet()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("port=0\n")
	b.WriteString("bind-dynamic\n")
	fmt.Fprintf(&b, "interface=%s\n", wifi.Iface)
	fmt.Fprintf(&b, "interface=%s\n", lan.Iface)
	b.WriteString("except-interface=lo\n")
	b.WriteString("except-interface=docker0\n")
	fmt.Fprintf(&b, "dhcp-range=set:wifi,%s,%s,%s,%s\n", wifi.DHCPStart, wifi.DHCPEnd, maskString(wifi.Prefix), wifi.Lease)
	fmt.Fprintf(&b, "dhcp-option=tag:wifi,3,%s\n", wifi.Gateway)
	fmt.Fprintf(&b, "dhcp-option=tag:wifi,6,%s\n", cfg.TunnelDNS())
	fmt.Fprintf(&b, "dhcp-range=set:lan,%s,%s,%s,%s\n", lan.DHCPStart, lan.DHCPEnd, maskString(lan.Prefix), lan.Lease)
	fmt.Fprintf(&b, "dhcp-option=tag:lan,3,%s\n", lan.Gateway)
	fmt.Fprintf(&b, "dhcp-option=tag:lan,6,%s\n", cfg.TunnelDNS())
	fmt.Fprintf(&b, "dhcp-leasefile=%s\n", leases)
	b.WriteString("log-facility=-\n")
	for _, r := range st.Reservations {
		mac, ok := netconv.MAC(r.MAC)
		if !ok {
			continue
		}
		if name, ok := netconv.Hostname(r.Name); ok && name != "" {
			fmt.Fprintf(&b, "dhcp-host=%s,%s,%s\n", mac, r.IP, name)
			continue
		}
		fmt.Fprintf(&b, "dhcp-host=%s,%s\n", mac, r.IP)
	}
	return b.String(), nil
}

func maskString(p interface{ Bits() int }) string {
	bits := p.Bits()
	var m uint32
	if bits > 0 && bits <= 32 {
		m = ^uint32(0) << (32 - bits)
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(m>>24), byte(m>>16), byte(m>>8), byte(m))
}

// Write materialises hostapd and dnsmasq config under dir.
func Write(dir string, cfg config.Config, st state.State) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	ctrl := filepath.Join(dir, "hostapd")
	if err := os.MkdirAll(ctrl, 0o750); err != nil {
		return err
	}
	deny := filepath.Join(dir, "hostapd.deny")
	if err := os.WriteFile(deny, []byte(DenyFile(st.BlockedMACs)), 0o644); err != nil {
		return err
	}
	hostapd := HostapdConf(cfg.WiFi, deny, ctrl)
	if err := os.WriteFile(filepath.Join(dir, "hostapd.conf"), []byte(hostapd), 0o600); err != nil {
		return err
	}
	dns, err := DNSMasqConf(cfg, cfg.Paths.Leases, st)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "dnsmasq.conf"), []byte(dns), 0o644)
}
