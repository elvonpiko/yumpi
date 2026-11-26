package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"yumpi/internal/auth"
	"yumpi/internal/config"
	"yumpi/internal/devices"
	"yumpi/internal/firewall"
	"yumpi/internal/mullvad"
	"yumpi/internal/netconv"
	"yumpi/internal/netmgr"
	"yumpi/internal/state"
	"yumpi/internal/system"
)

// InputError is a request the API should reject with a 400.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func invalid(msg string) error { return &InputError{Msg: msg} }

// Status is the dashboard payload.
type Status struct {
	Model       string           `json:"model"`
	Uptime      string           `json:"uptime"`
	DHCPEnabled bool             `json:"dhcp_enabled"`
	Online      int              `json:"online"`
	LeasesUsed  int              `json:"leases_used"`
	PoolSize    int              `json:"pool_size"`
	Expiring    int              `json:"expiring"`
	Mullvad     MullvadView      `json:"mullvad"`
	WiFi        WiFiView         `json:"wifi"`
	Guest       GuestView        `json:"guest"`
	Pools       PoolsView        `json:"pools"`
	DNS         DNSView          `json:"dns"`
	Devices     []devices.Device `json:"devices"`
}

type MullvadView struct {
	Connected     bool   `json:"connected"`
	State         string `json:"state"`
	Relay         string `json:"relay"`
	Location      string `json:"location"`
	ExitIP        string `json:"exit_ip"`
	Obfuscated    bool   `json:"obfuscated"`
	Pinned        string `json:"pinned"`
	BlockWhenDown bool   `json:"block_when_down"`
}

type WiFiView struct {
	SSID    string `json:"ssid"`
	Channel int    `json:"channel"`
	Country string `json:"country"`
	Address string `json:"address"`
}

type GuestView struct {
	Enabled bool   `json:"enabled"`
	SSID    string `json:"ssid"`
	Address string `json:"address"`
}

type PoolView struct {
	Start   string `json:"start"`
	End     string `json:"end"`
	Gateway string `json:"gateway"`
	Lease   string `json:"lease"`
	Size    int    `json:"size"`
	Used    int    `json:"used"`
}

type PoolsView struct {
	WiFi PoolView `json:"wifi"`
	LAN  PoolView `json:"lan"`
}

type DNSView struct {
	Tunnel string `json:"tunnel"`
	Direct string `json:"direct"`
}

// Daemon is the control plane.
type Daemon struct {
	log     *slog.Logger
	run     system.Runner
	auth    *auth.Manager
	store   *state.Store
	mv      *mullvad.Client
	super   *netmgr.Supervisor
	started time.Time
	path    string

	mu  sync.Mutex
	cfg config.Config

	trigger chan struct{}
}

func New(cfg config.Config, path string, store *state.Store, passwords *auth.Manager, log *slog.Logger, run system.Runner) *Daemon {
	if log == nil {
		log = slog.Default()
	}
	if run == nil {
		run = system.Local{}
	}
	return &Daemon{
		log: log, run: run, auth: passwords, store: store, cfg: cfg, started: time.Now(), path: path,
		mv:      &mullvad.Client{Run: run, Chroot: cfg.Mullvad.Chroot},
		super:   &netmgr.Supervisor{Log: log, Run: run, RunDir: cfg.Paths.Run, WiFi: cfg.WiFi.Interface},
		trigger: make(chan struct{}, 1),
	}
}

// Run prepares interfaces, starts hostapd and dnsmasq, reconciles the firewall, and returns when ctx is cancelled.
// The HTTP server is started by the caller; Run blocks on the reconcile loop.
func (d *Daemon) Run(ctx context.Context) {
	cfg := d.config()
	if err := os.MkdirAll(cfg.Paths.Run, 0o750); err != nil {
		d.log.Error("run dir", "err", err)
	}
	netmgr.PrepareLink(ctx, d.run, cfg.WiFi.Interface, cfg.WiFi.Address)
	if err := d.writeLocked(); err != nil {
		d.log.Error("write config", "err", err)
	}
	d.super.SetDHCP(!d.store.Get().DHCPDisabled)
	d.super.Start(ctx)
	go d.keepGuestAddress(ctx)
	if pin := d.store.Get().PinnedLocation; pin != "" {
		go func() {
			if err := d.mv.SetLocation(ctx, pin); err != nil {
				d.log.Warn("pinned location", "err", err)
			}
		}()
	}
	d.reconcile(ctx)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.super.SetDHCP(false)
			d.super.RestartAP()
			return
		case <-ticker.C:
			d.reconcile(ctx)
		case <-d.trigger:
			d.reconcile(ctx)
		}
	}
}

func (d *Daemon) kick() {
	select {
	case d.trigger <- struct{}{}:
	default:
	}
}

func (d *Daemon) config() config.Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg
}

func (d *Daemon) Login(remote, password string) (string, error) {
	return d.auth.Login(remote, password)
}

func (d *Daemon) Logout(token string) { d.auth.Logout(token) }

func (d *Daemon) Valid(token string) bool { return d.auth.Valid(token) }

func (d *Daemon) Relays(ctx context.Context) ([]mullvad.Country, error) {
	return d.mv.Relays(ctx)
}

func (d *Daemon) Status(ctx context.Context) (Status, error) {
	cfg := d.config()
	st := d.store.Get()
	vpn, _ := d.tunnel(ctx)
	wifi, err := cfg.WiFiNet()
	if err != nil {
		return Status{}, err
	}
	lan, err := cfg.LANNet()
	if err != nil {
		return Status{}, err
	}
	stations, _ := d.run.Run(ctx, "iw", "dev", cfg.WiFi.Interface, "station", "dump")
	if st.GuestEnabled {
		if extra, err := d.run.Run(ctx, "iw", "dev", cfg.GuestWithDefaults().Interface, "station", "dump"); err == nil {
			stations += "\n" + extra
		}
	}
	neigh, _ := d.run.Run(ctx, "ip", "-4", "neigh", "show")
	rawLeases, _ := os.ReadFile(cfg.Paths.Leases)
	self := []netip.Addr{wifi.Gateway, lan.Gateway}
	if gn, err := cfg.GuestNet(); err == nil {
		self = append(self, gn.Gateway)
	}
	snap := devices.Assemble(time.Now(), wifi, lan, self, cfg.Upstream(), string(rawLeases), stations, neigh, st)
	if snap.Devices == nil {
		snap.Devices = []devices.Device{}
	}
	model := cfg.Model
	if model == "" {
		model = readModel()
	}
	if model == "" {
		model = "Raspberry Pi"
	}
	return Status{
		Model: model, Uptime: devices.FormatUptime(time.Since(d.started)),
		DHCPEnabled: !st.DHCPDisabled,
		Online:      snap.Online, LeasesUsed: snap.LeasesUsed, PoolSize: snap.PoolSize, Expiring: snap.Expiring,
		Mullvad: MullvadView{Connected: vpn.Connected, State: vpn.State, Relay: vpn.Relay, Location: vpn.Location, ExitIP: vpn.ExitIP, Obfuscated: vpn.Obfuscated, Pinned: st.PinnedLocation, BlockWhenDown: st.BlockWhenDown},
		WiFi:    WiFiView{SSID: cfg.WiFi.SSID, Channel: cfg.WiFi.Channel, Country: cfg.WiFi.Country, Address: cfg.WiFi.Address},
		Guest:   GuestView{Enabled: st.GuestEnabled && cfg.Guest.Passphrase != "", SSID: cfg.GuestWithDefaults().SSID, Address: cfg.GuestWithDefaults().Address},
		Pools: PoolsView{
			WiFi: PoolView{Start: wifi.DHCPStart.String(), End: wifi.DHCPEnd.String(), Gateway: wifi.Gateway.String(), Lease: wifi.Lease, Size: config.PoolSize(wifi.DHCPStart, wifi.DHCPEnd), Used: snap.WiFiUsed},
			LAN:  PoolView{Start: lan.DHCPStart.String(), End: lan.DHCPEnd.String(), Gateway: lan.Gateway.String(), Lease: lan.Lease, Size: config.PoolSize(lan.DHCPStart, lan.DHCPEnd), Used: snap.LANUsed},
		},
		DNS:     DNSView{Tunnel: cfg.DNS.Tunnel, Direct: cfg.DNS.Direct},
		Devices: snap.Devices,
	}, nil
}

func (d *Daemon) SetVPN(ctx context.Context, ip string, enabled bool) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return invalid("Enter an IPv4 address.")
	}
	cfg := d.config()
	wifi, _ := cfg.WiFiNet()
	lan, _ := cfg.LANNet()
	if !wifi.Prefix.Contains(addr) && !lan.Prefix.Contains(addr) {
		return invalid("That address is outside this gateway.")
	}
	if gn, err := cfg.GuestNet(); err == nil && gn.Prefix.Contains(addr) {
		return invalid("Visitor Wi-Fi always uses Mullvad.")
	}
	if addr == wifi.Gateway || addr == lan.Gateway || addr == cfg.Upstream() {
		return invalid("That address belongs to the gateway.")
	}
	mac := d.macForIP(addr.String())
	if err := d.store.Update(func(st *state.State) error {
		st.BypassIPs = without(st.BypassIPs, addr.String())
		if mac != "" {
			st.DirectMACs = without(st.DirectMACs, mac)
			if !enabled {
				st.DirectMACs = append(st.DirectMACs, mac)
			}
			return nil
		}
		if !enabled {
			st.BypassIPs = append(st.BypassIPs, addr.String())
		}
		return nil
	}); err != nil {
		return err
	}
	d.kick()
	return nil
}

func (d *Daemon) SetBlock(ctx context.Context, mac string, blocked bool) error {
	norm, ok := netconv.MAC(mac)
	if !ok {
		return invalid("Enter a MAC address.")
	}
	if err := d.store.Update(func(st *state.State) error {
		st.BlockedMACs = without(st.BlockedMACs, norm)
		if blocked {
			st.BlockedMACs = append(st.BlockedMACs, norm)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := d.writeLocked(); err != nil {
		return err
	}
	d.super.Block(ctx, norm, blocked)
	return nil
}

func (d *Daemon) AddReservation(ctx context.Context, mac, ip, name string) error {
	norm, ok := netconv.MAC(mac)
	if !ok {
		return invalid("Enter a MAC address.")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is4() {
		return invalid("Enter an IPv4 address.")
	}
	host, ok := netconv.Hostname(name)
	if !ok {
		return invalid("Use a short name: letters, numbers, dots, and dashes.")
	}
	cfg := d.config()
	wifi, _ := cfg.WiFiNet()
	lan, _ := cfg.LANNet()
	if !wifi.Prefix.Contains(addr) && !lan.Prefix.Contains(addr) {
		return invalid("That address is outside this gateway.")
	}
	if addr == wifi.Gateway || addr == lan.Gateway {
		return invalid("That address belongs to the gateway.")
	}
	if err := d.store.Update(func(st *state.State) error {
		next := st.Reservations[:0]
		for _, r := range st.Reservations {
			if r.MAC == norm || r.IP == addr.String() {
				continue
			}
			next = append(next, r)
		}
		st.Reservations = append(next, state.Reservation{MAC: norm, IP: addr.String(), Name: host})
		return nil
	}); err != nil {
		return err
	}
	return d.restartDHCP()
}

func (d *Daemon) DeleteReservation(ctx context.Context, mac string) error {
	norm, ok := netconv.MAC(mac)
	if !ok {
		return invalid("Enter a MAC address.")
	}
	if err := d.store.Update(func(st *state.State) error {
		next := st.Reservations[:0]
		for _, r := range st.Reservations {
			if r.MAC != norm {
				next = append(next, r)
			}
		}
		st.Reservations = next
		return nil
	}); err != nil {
		return err
	}
	return d.restartDHCP()
}

func (d *Daemon) SetDHCP(ctx context.Context, enabled bool) error {
	if err := d.store.Update(func(st *state.State) error {
		st.DHCPDisabled = !enabled
		return nil
	}); err != nil {
		return err
	}
	d.super.SetDHCP(enabled)
	return nil
}

// SetPassword checks the current dashboard password and stores a new one.
// The session in keep stays signed in. Other sessions are signed out.
func (d *Daemon) SetPassword(ctx context.Context, remote, current, next, keep string) error {
	if len(next) < 12 || len(next) > 72 {
		return invalid("Use 12 to 72 characters.")
	}
	hash, err := d.auth.HashIfCurrent(remote, current, next)
	if errors.Is(err, auth.ErrDenied) {
		return invalid("Current password is incorrect.")
	}
	if err != nil {
		return err
	}
	d.mu.Lock()
	cfg := d.cfg
	cfg.Auth.PasswordHash = hash
	if err := config.Save(d.path, cfg); err != nil {
		d.mu.Unlock()
		return err
	}
	d.cfg = cfg
	d.mu.Unlock()
	d.auth.UseHash(hash, keep)
	return nil
}

// SetPause blocks internet for Mullvad devices while the tunnel is down.
func (d *Daemon) SetPause(ctx context.Context, enabled bool) error {
	if err := d.store.Update(func(st *state.State) error {
		st.BlockWhenDown = enabled
		return nil
	}); err != nil {
		return err
	}
	d.kick()
	return nil
}

func (d *Daemon) MullvadAction(ctx context.Context, action, location string) error {
	switch action {
	case "connect":
		if err := d.mv.Connect(ctx); err != nil {
			return err
		}
	case "disconnect":
		if err := d.mv.Disconnect(ctx); err != nil {
			return err
		}
	case "location":
		if err := d.mv.SetLocation(ctx, location); err != nil {
			return invalid(err.Error())
		}
		if err := d.store.Update(func(st *state.State) error {
			st.PinnedLocation = strings.TrimSpace(strings.ToLower(location))
			return nil
		}); err != nil {
			return err
		}
	case "unpin":
		if err := d.mv.ClearLocation(ctx); err != nil {
			return err
		}
		if err := d.store.Update(func(st *state.State) error {
			st.PinnedLocation = ""
			return nil
		}); err != nil {
			return err
		}
	default:
		return invalid("Unknown action.")
	}
	d.kick()
	return nil
}

func (d *Daemon) SetWiFi(ctx context.Context, ssid, passphrase string) error {
	d.mu.Lock()
	cfg := d.cfg
	ssid = strings.TrimSpace(ssid)
	if ssid == "" {
		ssid = cfg.WiFi.SSID
	}
	if passphrase == "" {
		passphrase = cfg.WiFi.Passphrase
	}
	cfg.WiFi.SSID = ssid
	cfg.WiFi.Passphrase = passphrase
	if err := cfg.Validate(); err != nil {
		d.mu.Unlock()
		return invalid("SSID must be 1–32 characters and the password 8–63.")
	}
	if err := config.Save(d.path, cfg); err != nil {
		d.mu.Unlock()
		return err
	}
	d.cfg = cfg
	d.mu.Unlock()
	if err := d.writeLocked(); err != nil {
		return err
	}
	d.super.RestartAP()
	return nil
}

func (d *Daemon) SetGuest(ctx context.Context, enabled bool, ssid, passphrase string) error {
	d.mu.Lock()
	cfg := d.cfg
	g := cfg.GuestWithDefaults()
	if strings.TrimSpace(ssid) != "" {
		g.SSID = strings.TrimSpace(ssid)
	}
	if passphrase != "" {
		g.Passphrase = passphrase
	}
	if enabled && len(g.Passphrase) < 8 {
		d.mu.Unlock()
		return invalid("Set a guest password of at least 8 characters.")
	}
	cfg.Guest = g
	if err := cfg.Validate(); err != nil {
		d.mu.Unlock()
		return invalid("Check the guest network name and password.")
	}
	if err := config.Save(d.path, cfg); err != nil {
		d.mu.Unlock()
		return err
	}
	d.cfg = cfg
	d.mu.Unlock()
	if err := d.store.Update(func(st *state.State) error {
		st.GuestEnabled = enabled
		return nil
	}); err != nil {
		return err
	}
	if err := d.writeLocked(); err != nil {
		return err
	}
	d.super.RestartAP()
	d.super.RestartDHCP()
	d.kick()
	return nil
}

func (d *Daemon) keepGuestAddress(ctx context.Context) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !d.store.Get().GuestEnabled {
				continue
			}
			cfg := d.config()
			g := cfg.GuestWithDefaults()
			if g.Passphrase == "" {
				continue
			}
			netmgr.PrepareLink(ctx, d.run, g.Interface, g.Address)
		}
	}
}

func (d *Daemon) macForIP(ip string) string {
	raw, err := os.ReadFile(d.config().Paths.Leases)
	if err != nil {
		return ""
	}
	for _, l := range devices.ParseLeases(string(raw)) {
		if l.IP.String() == ip && l.MAC != "" {
			if mac, ok := netconv.MAC(l.MAC); ok {
				return mac
			}
		}
	}
	return ""
}

func (d *Daemon) restartDHCP() error {
	if err := d.writeLocked(); err != nil {
		return err
	}
	d.super.RestartDHCP()
	return nil
}

func (d *Daemon) writeLocked() error {
	return netmgr.Write(d.config().Paths.Run, d.config(), d.store.Get())
}

func (d *Daemon) reconcile(ctx context.Context) {
	cfg := d.config()
	st := d.store.Get()
	vpn, _ := d.tunnel(ctx)
	rawLeases, _ := os.ReadFile(cfg.Paths.Leases)
	in, err := firewallInput(cfg, st, vpn.Connected, string(rawLeases))
	if err != nil {
		d.log.Error("firewall input", "err", err)
		return
	}
	if err := firewall.Apply(ctx, d.run, cfg.Paths.Run, in); err != nil {
		d.log.Error("reconcile", "err", err)
	}
}

func (d *Daemon) tunnel(ctx context.Context) (mullvad.Status, error) {
	st, err := d.mv.Status(ctx)
	if err == nil {
		return st, nil
	}
	d.log.Warn("mullvad status", "err", err)
	if _, linkErr := d.run.Run(ctx, "ip", "link", "show", "dev", d.config().Mullvad.Interface); linkErr == nil {
		return mullvad.Status{State: "unknown", Connected: true}, err
	}
	return mullvad.Status{State: "unknown"}, err
}

func firewallInput(cfg config.Config, st state.State, up bool, leases string) (firewall.Input, error) {
	wifi, err := cfg.WiFiNet()
	if err != nil {
		return firewall.Input{}, err
	}
	lan, err := cfg.LANNet()
	if err != nil {
		return firewall.Input{}, err
	}
	direct := map[string]struct{}{}
	for _, mac := range st.DirectMACs {
		direct[mac] = struct{}{}
	}
	var bypass []netip.Addr
	seen := map[netip.Addr]struct{}{}
	add := func(a netip.Addr) {
		if _, ok := seen[a]; ok {
			return
		}
		seen[a] = struct{}{}
		bypass = append(bypass, a)
	}
	for _, ip := range st.BypassIPs {
		if a, err := netip.ParseAddr(ip); err == nil {
			add(a)
		}
	}
	for _, l := range devices.ParseLeases(leases) {
		if _, ok := direct[l.MAC]; ok {
			add(l.IP)
		}
	}
	in := firewall.Input{
		WiFiIface:      wifi.Iface,
		LANIface:       lan.Iface,
		VPNIface:       cfg.Mullvad.Interface,
		TunnelDNS:      cfg.TunnelDNS(),
		DirectDNS:      cfg.DirectDNS(),
		WiFiNet:        wifi.Prefix,
		LANNet:         lan.Prefix,
		Bypass:         bypass,
		VPNUp:          up,
		BlockWhenDown:  st.BlockWhenDown,
	}
	if st.GuestEnabled && cfg.Guest.Passphrase != "" {
		if gn, err := cfg.GuestNet(); err == nil {
			g := cfg.GuestWithDefaults()
			in.GuestOn = true
			in.GuestIface = g.Interface
			in.GuestGW = gn.Gateway
			in.GuestNet = gn.Prefix
		}
	}
	return in, nil
}

func without(in []string, v string) []string {
	out := in[:0]
	for _, s := range in {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

func readModel() string {
	b, err := os.ReadFile("/proc/device-tree/model")
	if err != nil {
		b, err = os.ReadFile("/sys/firmware/devicetree/base/model")
		if err != nil {
			return ""
		}
	}
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
}
