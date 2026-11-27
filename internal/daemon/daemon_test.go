package daemon

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"yumpi/internal/auth"
	"yumpi/internal/config"
	"yumpi/internal/state"
)

func TestRetryAfterBacksOff(t *testing.T) {
	if retryAfter(0) != 0 || retryAfter(1) != 15*time.Second || retryAfter(2) != 30*time.Second {
		t.Fatalf("%s %s %s", retryAfter(0), retryAfter(1), retryAfter(2))
	}
	if retryAfter(8) != 5*time.Minute {
		t.Fatal(retryAfter(8))
	}
}

func TestReconcileReconnectsUntilDisconnect(t *testing.T) {
	d, run := testDaemon(t)
	run.status = `{"state":"disconnected"}`
	d.reconcile(context.Background())
	if run.count("mullvad reconnect") != 1 {
		t.Fatalf("calls %v", run.calls)
	}
	d.reconcile(context.Background())
	if run.count("mullvad reconnect") != 1 {
		t.Fatal("retried inside the backoff")
	}
	d.mu.Lock()
	d.lastTry = time.Now().Add(-20 * time.Second)
	d.mu.Unlock()
	d.reconcile(context.Background())
	if run.count("mullvad reconnect") != 2 {
		t.Fatalf("calls %v", run.calls)
	}
	if err := d.MullvadAction(context.Background(), "disconnect", ""); err != nil {
		t.Fatal(err)
	}
	if !d.store.Get().ManualDisconnect {
		t.Fatal("disconnect was not remembered")
	}
	before := run.count("mullvad reconnect")
	d.mu.Lock()
	d.lastTry = time.Time{}
	d.tries = 0
	d.mu.Unlock()
	d.reconcile(context.Background())
	if run.count("mullvad reconnect") != before {
		t.Fatal("manual disconnect was brought back")
	}
}

func TestReconcileFlushesClientsWhenTheTunnelReturns(t *testing.T) {
	d, run := testDaemon(t)
	run.status = `{"state":"connected","details":{"location":{"ipv4":"1.2.3.4","hostname":"us-nyc-wg-501","city":"New York, NY","country":"USA"}}}`
	run.hand = "peer 9999999999\n"
	d.reconcile(context.Background())
	if run.count("conntrack -D") != 0 {
		t.Fatal("flushed on the first look")
	}
	run.status = `{"state":"disconnected"}`
	run.hand = ""
	d.mu.Lock()
	d.lastTry = time.Time{}
	d.tries = 0
	d.mu.Unlock()
	d.reconcile(context.Background())
	run.status = `{"state":"connected","details":{"location":{"ipv4":"1.2.3.4","hostname":"us-nyc-wg-501","city":"New York, NY","country":"USA"}}}`
	run.hand = "peer 9999999999\n"
	d.reconcile(context.Background())
	if run.count("conntrack -D") != 2 {
		t.Fatalf("conntrack %d in %v", run.count("conntrack -D"), run.calls)
	}
}

func testDaemon(t *testing.T) (*Daemon, *script) {
	t.Helper()
	dir := t.TempDir()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Listen: ":8080",
		Auth:   config.Auth{PasswordHash: string(hash)},
		WiFi: config.WiFi{
			Interface: "wlan0", SSID: "YumPi", Passphrase: "correct horse", Country: "US", Channel: 36,
			Address: "10.23.46.1/24", DHCPStart: "10.23.46.50", DHCPEnd: "10.23.46.200", Lease: "12h",
		},
		LAN: config.LAN{
			Interface: "eth0", Address: "10.23.45.2/24",
			DHCPStart: "10.23.45.100", DHCPEnd: "10.23.45.200", Lease: "12h", Upstream: "10.23.45.1",
		},
		DNS:     config.DNS{Tunnel: "10.64.0.1", Direct: "1.1.1.1"},
		Mullvad: config.Mullvad{Interface: "wg0-mullvad"},
		Paths:   config.Paths{State: dir + "/state.json", Run: dir + "/run", Leases: dir + "/leases"},
	}
	if err := config.Save(dir+"/config.toml", cfg); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(cfg.Paths.State)
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := auth.New(cfg.Auth.PasswordHash)
	if err != nil {
		t.Fatal(err)
	}
	run := &script{status: `{"state":"disconnected"}`}
	d := New(cfg, dir+"/config.toml", store, passwords, nil, run)
	d.started = time.Now().Add(-time.Minute)
	return d, run
}

func TestConnectingAndANewHandshakeAreLeftAlone(t *testing.T) {
	d, run := testDaemon(t)
	run.status = `{"state":"connecting"}`
	d.reconcile(context.Background())
	if run.count("mullvad reconnect") != 0 {
		t.Fatal("reconnected while Mullvad was already connecting")
	}

	run.status = `{"state":"connected","details":{"location":{"ipv4":"1.2.3.4","hostname":"us-nyc-wg-501","city":"New York, NY","country":"USA"}}}`
	run.hand = "peer 0\n"
	st, retry := d.observe(context.Background())
	if !st.Connected || retry {
		t.Fatalf("connected %v retry %v", st.Connected, retry)
	}
	d.reconcile(context.Background())
	if run.count("mullvad reconnect") != 0 {
		t.Fatal("reconnected before the first handshake")
	}

	run.hand = "peer 100\n"
	st, retry = d.observe(context.Background())
	if st.Connected || !retry {
		t.Fatalf("stale connected %v retry %v", st.Connected, retry)
	}
}

func TestSetWiFiLeavesTheRadioAloneWhenNothingChanges(t *testing.T) {
	d, _ := testDaemon(t)
	if err := d.SetWiFi(context.Background(), "YumPi", "", "5"); err != nil {
		t.Fatal(err)
	}
	if d.config().WiFi.Channel != 36 || d.config().WiFi.SSID != "YumPi" {
		t.Fatalf("%+v", d.config().WiFi)
	}
	if _, err := os.Stat(d.config().Paths.Run + "/hostapd.conf"); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestSetWiFiBandRestartsTheAccessPointOnThatChannel(t *testing.T) {
	d, _ := testDaemon(t)
	if err := d.SetWiFi(context.Background(), "", "", "2.4"); err != nil {
		t.Fatal(err)
	}
	wifi := d.config().WiFi
	if wifi.Channel != 6 || wifi.Band() != "2.4" || wifi.Passphrase != "correct horse" || wifi.SSID != "YumPi" {
		t.Fatalf("%+v", wifi)
	}
	conf := readHostapd(t, d)
	if !strings.Contains(conf, "hw_mode=g\n") || !strings.Contains(conf, "channel=6\n") || strings.Contains(conf, "correct horse") {
		t.Fatal(conf)
	}

	d.mu.Lock()
	d.cfg.WiFi.Channel = 11
	d.mu.Unlock()
	if err := d.SetWiFi(context.Background(), "", "", "2.4"); err != nil {
		t.Fatal(err)
	}
	if d.config().WiFi.Channel != 11 {
		t.Fatal(d.config().WiFi.Channel)
	}

	if err := d.SetWiFi(context.Background(), "", "", "5"); err != nil {
		t.Fatal(err)
	}
	if d.config().WiFi.Channel != 36 || d.config().WiFi.Band() != "5" {
		t.Fatalf("%+v", d.config().WiFi)
	}
	conf = readHostapd(t, d)
	if !strings.Contains(conf, "hw_mode=a\n") || !strings.Contains(conf, "channel=36\n") || !strings.Contains(conf, "ieee80211ac=1\n") {
		t.Fatal(conf)
	}
	if err := d.SetWiFi(context.Background(), "", "", "6"); err == nil {
		t.Fatal("accepted a bad band")
	}
	if d.config().WiFi.Channel != 36 {
		t.Fatal(d.config().WiFi.Channel)
	}
}

func readHostapd(t *testing.T, d *Daemon) string {
	t.Helper()
	b, err := os.ReadFile(d.config().Paths.Run + "/hostapd.conf")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestStartupGraceDoesNotAbortTheFirstHandshake(t *testing.T) {
	d, run := testDaemon(t)
	d.started = time.Now()
	d.reconcile(context.Background())
	if run.count("mullvad reconnect") != 0 {
		t.Fatal("startup grace still called reconnect")
	}
}

type script struct {
	mu     sync.Mutex
	calls  []string
	status string
	hand   string
}

func (s *script) Run(_ context.Context, name string, args ...string) (string, error) {
	s.mu.Lock()
	line := name + " " + strings.Join(args, " ")
	s.calls = append(s.calls, line)
	status, hand := s.status, s.hand
	s.mu.Unlock()
	if name == "mullvad" && len(args) > 1 && args[0] == "status" && args[1] == "-j" {
		return status, nil
	}
	if name == "wg" {
		return hand, nil
	}
	return "", nil
}

func (s *script) count(part string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if strings.Contains(c, part) {
			n++
		}
	}
	return n
}
