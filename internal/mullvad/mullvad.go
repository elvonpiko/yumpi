package mullvad

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"yumpi/internal/system"
)

// Status is the tunnel state the dashboard shows.
type Status struct {
	State      string
	Connected  bool
	Relay      string
	Location   string
	ExitIP     string
	Obfuscated bool
}

// City is one Mullvad city code. The JSON names match the dashboard.
type City struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

// Country is one Mullvad country and its cities.
type Country struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Cities []City `json:"cities"`
}

// Client talks to the Mullvad CLI.
type Client struct {
	Run    system.Runner
	Bin    string
	Chroot string

	mu       sync.Mutex
	cached   []Country
	cachedAt time.Time
}

var locationRE = regexp.MustCompile(`^[a-z]{2}(?: [a-z0-9]{2,8})?$`)

func (c *Client) Status(ctx context.Context) (Status, error) {
	out, err := c.run(ctx, "status", "-j")
	if err != nil {
		return Status{}, err
	}
	st, err := ParseStatus(out)
	if err != nil || !st.Connected || st.Obfuscated {
		return st, err
	}
	text, textErr := c.run(ctx, "status")
	if textErr == nil {
		st.Obfuscated = ObfuscatedText(text)
	}
	return st, nil
}

func (c *Client) Connect(ctx context.Context) error {
	_, err := c.run(ctx, "connect")
	return err
}

func (c *Client) Disconnect(ctx context.Context) error {
	_, err := c.run(ctx, "disconnect")
	return err
}

// Reconnect asks Mullvad to build the tunnel again.
// A disconnected tunnel is connected. A stuck one is replaced.
func (c *Client) Reconnect(ctx context.Context) error {
	_, err := c.run(ctx, "reconnect")
	return err
}

// SetLocation selects a country or "country city" and connects.
func (c *Client) SetLocation(ctx context.Context, location string) error {
	location = strings.TrimSpace(strings.ToLower(location))
	if !locationRE.MatchString(location) {
		return fmt.Errorf("location must look like \"us\" or \"us nyc\"")
	}
	args := []string{"relay", "set", "location"}
	args = append(args, strings.Fields(location)...)
	if _, err := c.run(ctx, args...); err != nil {
		return err
	}
	return c.Connect(ctx)
}

// ClearLocation removes a pinned country or city.
func (c *Client) ClearLocation(ctx context.Context) error {
	_, err := c.run(ctx, "relay", "set", "location", "any")
	return err
}

// Relays returns countries and cities, cached for ten minutes.
func (c *Client) Relays(ctx context.Context) ([]Country, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cached) > 0 && time.Since(c.cachedAt) < 10*time.Minute {
		return c.cached, nil
	}
	out, err := c.run(ctx, "relay", "list")
	if err != nil {
		return nil, err
	}
	list := ParseRelays(out)
	if len(list) == 0 {
		return nil, fmt.Errorf("mullvad returned no relays")
	}
	c.cached = list
	c.cachedAt = time.Now()
	return list, nil
}

func (c *Client) run(ctx context.Context, args ...string) (string, error) {
	if c.Run == nil {
		return "", fmt.Errorf("mullvad runner is not configured")
	}
	bin := c.Bin
	if bin == "" {
		bin = "mullvad"
	}
	if c.Chroot != "" {
		full := append([]string{c.Chroot, bin}, args...)
		return c.Run.Run(ctx, "chroot", full...)
	}
	return c.Run.Run(ctx, bin, args...)
}

type statusJSON struct {
	State   string `json:"state"`
	Details struct {
		Location struct {
			IPv4     string `json:"ipv4"`
			Hostname string `json:"hostname"`
			City     string `json:"city"`
			Country  string `json:"country"`
		} `json:"location"`
	} `json:"details"`
}

// ParseStatus reads `mullvad status -j`.
func ParseStatus(raw string) (Status, error) {
	var doc statusJSON
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return Status{}, fmt.Errorf("mullvad status: %w", err)
	}
	st := Status{State: doc.State, Connected: doc.State == "connected", Obfuscated: ObfuscatedText(raw)}
	loc := doc.Details.Location
	st.Relay = loc.Hostname
	st.ExitIP = loc.IPv4
	switch {
	case loc.Country != "" && loc.City != "":
		st.Location = loc.Country + ", " + loc.City
	case loc.Country != "":
		st.Location = loc.Country
	default:
		st.Location = loc.City
	}
	return st, nil
}

var (
	countryLine = regexp.MustCompile(`^([^ \t].*?) \(([a-z]{2})\)$`)
	// Mullvad indents cities with a tab or spaces, and some versions omit the coordinates.
	cityLine = regexp.MustCompile(`^[ \t]+(.+?) \(([a-z0-9]{2,8})\)(?: @[^@]*)?$`)
)

// ParseRelays reads `mullvad relay list`.
func ParseRelays(raw string) []Country {
	var out []Country
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := countryLine.FindStringSubmatch(line); m != nil {
			out = append(out, Country{Name: m[1], Code: m[2]})
			continue
		}
		if len(out) == 0 {
			continue
		}
		if m := cityLine.FindStringSubmatch(line); m != nil {
			cur := &out[len(out)-1]
			cur.Cities = append(cur.Cities, City{Name: m[1], Code: m[2]})
		}
	}
	return out
}

// freshHandshake is how long a WireGuard handshake may be before the path is dead.
// Mullvad keepalives are much shorter than this.
const freshHandshake = 90 * time.Second

// ParseHandshake reads `wg show <iface> latest-handshakes` and returns the age of the newest peer.
// A timestamp of 0 means that peer has never completed a handshake.
func ParseHandshake(raw string, now time.Time) (time.Duration, bool) {
	var newest int64
	found := false
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ts, err := strconv.ParseInt(f[len(f)-1], 10, 64)
		if err != nil || ts <= 0 {
			continue
		}
		if !found || ts > newest {
			newest = ts
			found = true
		}
	}
	if !found {
		return 0, false
	}
	age := now.Sub(time.Unix(newest, 0))
	if age < 0 {
		return 0, true
	}
	return age, true
}

// HandshakeFresh reports a handshake new enough that the tunnel can pass traffic.
func HandshakeFresh(raw string, now time.Time) bool {
	age, ok := ParseHandshake(raw, now)
	return ok && age <= freshHandshake
}

// HandshakeStale reports a completed handshake that is too old to trust.
// A missing handshake, or a timestamp of 0, is not stale: the session may still be starting.
func HandshakeStale(raw string, now time.Time) bool {
	age, ok := ParseHandshake(raw, now)
	return ok && age > freshHandshake
}

// ObfuscatedText reports Mullvad anti-censorship wrappers, which are often slower.
func ObfuscatedText(raw string) bool {
	low := strings.ToLower(raw)
	for _, word := range []string{"lwo", "shadowsocks", "udp2tcp", "udp-over-tcp"} {
		if strings.Contains(low, word) {
			return true
		}
	}
	return false
}
