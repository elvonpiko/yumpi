package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"yumpi/internal/auth"
	"yumpi/internal/config"
	"yumpi/internal/daemon"
	"yumpi/internal/state"
	"yumpi/web"
)

func TestLoginCookieAndDevicePolicy(t *testing.T) {
	d, _ := newDaemon(t)
	srv := httptest.NewServer(New(d, web.FS, nil))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", res.StatusCode)
	}
	res.Body.Close()

	health, err := http.Get(srv.URL + "/healthz")
	if err != nil || health.StatusCode != 200 {
		t.Fatalf("health %v %v", health, err)
	}
	health.Body.Close()

	for _, path := range []string{"/", "/favicon.svg", "/favicon.png", "/favicon-180.png", "/styles.css", "/app.js", "/fonts/DMMono-Regular.ttf"} {
		page, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(page.Body)
		page.Body.Close()
		if page.StatusCode != 200 || len(body) == 0 {
			t.Fatalf("%s -> %d (%d bytes)", path, page.StatusCode, len(body))
		}
		if path == "/" && !strings.Contains(string(body), "This network") {
			t.Fatal("dashboard markup missing")
		}
	}

	login, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{"password":"wrong-password-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if login.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login %d", login.StatusCode)
	}
	login.Body.Close()

	login, err = http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{"password":"correct-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	if login.StatusCode != 200 || len(login.Cookies()) != 1 {
		t.Fatalf("login ok %d cookies %d", login.StatusCode, len(login.Cookies()))
	}
	c := login.Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie %+v", c)
	}
	login.Body.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/status", nil)
	req.AddCookie(c)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var st daemon.Status
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if !st.Mullvad.Connected || st.Mullvad.Relay != "us-nyc-wg-501" || len(st.Devices) != 1 {
		t.Fatalf("%+v devices %d", st.Mullvad, len(st.Devices))
	}
	if st.Devices[0].Name != "Phone" || !st.Devices[0].VPN {
		t.Fatalf("%+v", st.Devices[0])
	}

	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/device/vpn", strings.NewReader(`{"ip":"10.23.46.1","enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://evil.example")
	req.Host = req.URL.Host
	req.AddCookie(c)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("origin %d %s", res.StatusCode, body)
	}
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/device/vpn", strings.NewReader(`{"ip":"10.23.46.1","enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(c)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("gateway toggle %d", res.StatusCode)
	}
	res.Body.Close()

	if err := d.SetVPN(context.Background(), "10.23.46.50", false); err != nil {
		t.Fatal(err)
	}
	st2, err := d.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st2.Devices) != 1 || st2.Devices[0].VPN {
		t.Fatalf("device %+v", st2.Devices)
	}
}

func newDaemon(t *testing.T) (*daemon.Daemon, *recording) {
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
		Paths:   config.Paths{State: filepath.Join(dir, "state.json"), Run: filepath.Join(dir, "run"), Leases: filepath.Join(dir, "leases")},
	}
	if err := config.Save(filepath.Join(dir, "config.toml"), cfg); err != nil {
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
	run := &recording{}
	if err := os.WriteFile(cfg.Paths.Leases, []byte("1700000000 aa:bb:cc:dd:ee:01 10.23.46.50 Phone *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return daemon.New(cfg, filepath.Join(dir, "config.toml"), store, passwords, nil, run), run
}

type recording struct{}

func (recording) Run(_ context.Context, name string, _ ...string) (string, error) {
	switch name {
	case "mullvad":
		return `{"state":"connected","details":{"location":{"ipv4":"146.70.165.29","hostname":"us-nyc-wg-501","city":"New York, NY","country":"USA"}}}`, nil
	case "iw":
		return "Station aa:bb:cc:dd:ee:01 (on wlan0)\n", nil
	case "ip":
		return "10.23.46.50 dev wlan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n", nil
	default:
		return "", nil
	}
}
