package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/pelletier/go-toml/v2"
)

// Config is the gateway's on-disk configuration. Secrets live only here, mode 0600.
type Config struct {
	Listen  string  `toml:"listen"`
	Model   string  `toml:"model"`
	Auth    Auth    `toml:"auth"`
	WiFi    WiFi    `toml:"wifi"`
	LAN     LAN     `toml:"lan"`
	DNS     DNS     `toml:"dns"`
	Mullvad Mullvad `toml:"mullvad"`
	Paths   Paths   `toml:"paths"`
}

type Auth struct {
	PasswordHash string `toml:"password_hash"`
}

type WiFi struct {
	Interface  string `toml:"interface"`
	SSID       string `toml:"ssid"`
	Passphrase string `toml:"passphrase"`
	Country    string `toml:"country"`
	Channel    int    `toml:"channel"`
	Address    string `toml:"address"`
	DHCPStart  string `toml:"dhcp_start"`
	DHCPEnd    string `toml:"dhcp_end"`
	Lease      string `toml:"lease"`
}

type LAN struct {
	Interface string `toml:"interface"`
	Address   string `toml:"address"`
	DHCPStart string `toml:"dhcp_start"`
	DHCPEnd   string `toml:"dhcp_end"`
	Lease     string `toml:"lease"`
	Upstream  string `toml:"upstream"`
}

type DNS struct {
	Tunnel string `toml:"tunnel"`
	Direct string `toml:"direct"`
}

type Mullvad struct {
	Interface string `toml:"interface"`
	// Chroot, when set, runs the mullvad CLI inside that root so the container
	// uses the host daemon and matching CLI without mounting the host filesystem writable.
	Chroot string `toml:"chroot"`
}

type Paths struct {
	State  string `toml:"state"`
	Run    string `toml:"run"`
	Leases string `toml:"leases"`
}

// Network is one side of the gateway after validation.
type Network struct {
	Iface     string
	Gateway   netip.Addr
	Prefix    netip.Prefix
	DHCPStart netip.Addr
	DHCPEnd   netip.Addr
	Lease     string
}

var (
	ifaceName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,14}$`)
	leaseTime = regexp.MustCompile(`^(infinite|[1-9][0-9]*[smhdw])$`)
	countryRE = regexp.MustCompile(`^[A-Z]{2}$`)
)

// Load reads and validates a config file.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := toml.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Save writes the config atomically, readable only by root.
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	b, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.toml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.WiFi.Country == "" {
		c.WiFi.Country = "US"
	}
	if c.WiFi.Channel == 0 {
		c.WiFi.Channel = 36
	}
	if c.WiFi.Lease == "" {
		c.WiFi.Lease = "12h"
	}
	if c.LAN.Lease == "" {
		c.LAN.Lease = "12h"
	}
	if c.DNS.Tunnel == "" {
		c.DNS.Tunnel = "10.64.0.1"
	}
	if c.DNS.Direct == "" {
		c.DNS.Direct = "1.1.1.1"
	}
	if c.Mullvad.Interface == "" {
		c.Mullvad.Interface = "wg0-mullvad"
	}
	if c.Paths.State == "" {
		c.Paths.State = "/var/lib/yumpi/state.json"
	}
	if c.Paths.Run == "" {
		c.Paths.Run = "/run/yumpi"
	}
	if c.Paths.Leases == "" {
		c.Paths.Leases = "/var/lib/yumpi/leases"
	}
}

// Validate checks every field the control plane will interpolate into system config.
func (c Config) Validate() error {
	var errs []string
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, "listen must be host:port")
	}
	if !strings.HasPrefix(c.Auth.PasswordHash, "$2") {
		errs = append(errs, "auth.password_hash must be a bcrypt hash")
	}
	if err := validateIface(c.WiFi.Interface); err != nil {
		errs = append(errs, "wifi.interface: "+err.Error())
	}
	if err := validateIface(c.LAN.Interface); err != nil {
		errs = append(errs, "lan.interface: "+err.Error())
	}
	if c.WiFi.Interface == c.LAN.Interface {
		errs = append(errs, "wifi and lan interfaces must differ")
	}
	if err := validateSSID(c.WiFi.SSID); err != nil {
		errs = append(errs, "wifi.ssid: "+err.Error())
	}
	if err := validatePassphrase(c.WiFi.Passphrase); err != nil {
		errs = append(errs, "wifi.passphrase: "+err.Error())
	}
	if !countryRE.MatchString(c.WiFi.Country) {
		errs = append(errs, "wifi.country must be two uppercase letters")
	}
	if c.WiFi.Channel < 1 || c.WiFi.Channel > 196 {
		errs = append(errs, "wifi.channel is out of range")
	}
	if _, err := parseNet(c.WiFi.Interface, c.WiFi.Address, c.WiFi.DHCPStart, c.WiFi.DHCPEnd, c.WiFi.Lease); err != nil {
		errs = append(errs, "wifi: "+err.Error())
	}
	if _, err := parseNet(c.LAN.Interface, c.LAN.Address, c.LAN.DHCPStart, c.LAN.DHCPEnd, c.LAN.Lease); err != nil {
		errs = append(errs, "lan: "+err.Error())
	}
	wifi, wifiErr := parseNet(c.WiFi.Interface, c.WiFi.Address, c.WiFi.DHCPStart, c.WiFi.DHCPEnd, c.WiFi.Lease)
	lan, lanErr := parseNet(c.LAN.Interface, c.LAN.Address, c.LAN.DHCPStart, c.LAN.DHCPEnd, c.LAN.Lease)
	if wifiErr == nil && lanErr == nil && wifi.Prefix.Overlaps(lan.Prefix) {
		errs = append(errs, "wifi and lan networks overlap")
	}
	if _, err := netip.ParseAddr(c.LAN.Upstream); err != nil || !mustAddr(c.LAN.Upstream).Is4() {
		errs = append(errs, "lan.upstream must be an ipv4 address")
	}
	if _, err := netip.ParseAddr(c.DNS.Tunnel); err != nil || !mustAddr(c.DNS.Tunnel).Is4() {
		errs = append(errs, "dns.tunnel must be an ipv4 address")
	}
	if _, err := netip.ParseAddr(c.DNS.Direct); err != nil || !mustAddr(c.DNS.Direct).Is4() {
		errs = append(errs, "dns.direct must be an ipv4 address")
	}
	if err := validateIface(c.Mullvad.Interface); err != nil {
		errs = append(errs, "mullvad.interface: "+err.Error())
	}
	if c.Mullvad.Chroot != "" && !filepath.IsAbs(c.Mullvad.Chroot) {
		errs = append(errs, "mullvad.chroot must be absolute")
	}
	if len(c.Model) > 80 || (c.Model != "" && !printable(c.Model)) {
		errs = append(errs, "model is invalid")
	}
	for _, p := range []struct{ name, path string }{
		{"paths.state", c.Paths.State},
		{"paths.run", c.Paths.Run},
		{"paths.leases", c.Paths.Leases},
	} {
		if !filepath.IsAbs(p.path) || strings.Contains(p.path, "..") {
			errs = append(errs, p.name+" must be an absolute path")
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (c Config) WiFiNet() (Network, error) {
	return parseNet(c.WiFi.Interface, c.WiFi.Address, c.WiFi.DHCPStart, c.WiFi.DHCPEnd, c.WiFi.Lease)
}

func (c Config) LANNet() (Network, error) {
	return parseNet(c.LAN.Interface, c.LAN.Address, c.LAN.DHCPStart, c.LAN.DHCPEnd, c.LAN.Lease)
}

func (c Config) TunnelDNS() netip.Addr { return mustAddr(c.DNS.Tunnel) }
func (c Config) DirectDNS() netip.Addr { return mustAddr(c.DNS.Direct) }
func (c Config) Upstream() netip.Addr  { return mustAddr(c.LAN.Upstream) }

func parseNet(iface, cidr, start, end, lease string) (Network, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is4() {
		return Network{}, errors.New("address must be an ipv4 CIDR")
	}
	if p.Bits() < 16 || p.Bits() > 30 {
		return Network{}, errors.New("prefix length must be between 16 and 30")
	}
	gw := p.Addr()
	network := p.Masked()
	s, err := netip.ParseAddr(start)
	if err != nil || !s.Is4() {
		return Network{}, errors.New("dhcp start must be ipv4")
	}
	e, err := netip.ParseAddr(end)
	if err != nil || !e.Is4() {
		return Network{}, errors.New("dhcp end must be ipv4")
	}
	if !network.Contains(s) || !network.Contains(e) {
		return Network{}, errors.New("dhcp range is outside the subnet")
	}
	if addrLess(e, s) {
		return Network{}, errors.New("dhcp end is before dhcp start")
	}
	if s == gw || e == gw {
		return Network{}, errors.New("dhcp range includes the gateway")
	}
	if !leaseTime.MatchString(lease) {
		return Network{}, errors.New("lease must look like 12h")
	}
	return Network{Iface: iface, Gateway: gw, Prefix: network, DHCPStart: s, DHCPEnd: e, Lease: lease}, nil
}

func addrLess(a, b netip.Addr) bool {
	ab, bb := a.As4(), b.As4()
	for i := 0; i < 4; i++ {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	return false
}

// PoolSize is the number of addresses in a DHCP range, inclusive.
func PoolSize(start, end netip.Addr) int {
	return int(addrUint(end)-addrUint(start)) + 1
}

func addrUint(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func validateIface(name string) error {
	if !ifaceName.MatchString(name) {
		return errors.New("invalid interface name")
	}
	return nil
}

func validateSSID(ssid string) error {
	if ssid == "" || len(ssid) > 32 || strings.TrimSpace(ssid) == "" {
		return errors.New("must be 1 to 32 characters")
	}
	if !printable(ssid) {
		return errors.New("contains unsupported characters")
	}
	return nil
}

func validatePassphrase(p string) error {
	if len(p) < 8 || len(p) > 63 {
		return errors.New("must be 8 to 63 characters")
	}
	if !printable(p) {
		return errors.New("contains unsupported characters")
	}
	return nil
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}
