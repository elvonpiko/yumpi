package devices

import (
	"bufio"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"yumpi/internal/config"
	"yumpi/internal/state"
)

// Device is one client the dashboard can show or steer.
type Device struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Name     string `json:"name"`
	Source   string `json:"source"`
	Online   bool   `json:"online"`
	VPN      bool   `json:"vpn"`
	Blocked  bool   `json:"blocked"`
	Lease    string `json:"lease"`
	Reserved bool   `json:"reserved"`
	Usage    string `json:"usage"`
}

// Snapshot is the device list plus the figures for the three stat blocks.
type Snapshot struct {
	Devices    []Device
	Online     int
	LeasesUsed int
	PoolSize   int
	Expiring   int
	WiFiUsed   int
	LANUsed    int
}

type lease struct {
	Expiry time.Time
	MAC    string
	IP     netip.Addr
	Name   string
}

// Assemble merges DHCP leases, Wi-Fi stations, and neighbors into one list.
func Assemble(now time.Time, wifi, lan config.Network, self []netip.Addr, upstream netip.Addr, leases, stations, neigh string, st state.State) Snapshot {
	bypass := setOf(st.BypassIPs)
	directMAC := setOf(st.DirectMACs)
	blocked := setOf(st.BlockedMACs)
	reservedByMAC := map[string]state.Reservation{}
	reservedByIP := map[string]state.Reservation{}
	for _, r := range st.Reservations {
		reservedByMAC[r.MAC] = r
		reservedByIP[r.IP] = r
	}
	stationDump := ParseStationDump(stations)
	stationMAC := map[string]struct{}{}
	for mac := range stationDump {
		stationMAC[mac] = struct{}{}
	}
	neighbors := ParseNeigh(neigh)

	byIP := map[string]*Device{}
	var snap Snapshot
	snap.PoolSize = config.PoolSize(wifi.DHCPStart, wifi.DHCPEnd) + config.PoolSize(lan.DHCPStart, lan.DHCPEnd)

	for _, l := range ParseLeases(leases) {
		if !wifi.Prefix.Contains(l.IP) && !lan.Prefix.Contains(l.IP) {
			continue
		}
		if skipAddr(l.IP, self, upstream) {
			continue
		}
		source := "lan"
		if wifi.Prefix.Contains(l.IP) {
			source = "wifi"
			snap.WiFiUsed++
		} else {
			snap.LANUsed++
		}
		expired := !l.Expiry.IsZero() && !l.Expiry.After(now)
		_, onStation := stationMAC[l.MAC]
		online := false
		if source == "wifi" {
			online = onStation || neighborUp(neighbors[l.IP])
		} else {
			online = neighborUp(neighbors[l.IP])
		}
		if !expired {
			snap.LeasesUsed++
			expiring := l.Expiry.After(now) && l.Expiry.Sub(now) <= time.Hour
			if expiring {
				snap.Expiring++
			}
		}
		// A lease outlives the client. The list is who is connected now.
		if !online {
			continue
		}
		name := cleanName(l.Name)
		res, isRes := reservedByMAC[l.MAC]
		if name == "" && isRes {
			name = res.Name
		}
		if name == "" {
			name = fallbackName(source)
		}
		d := &Device{
			IP: l.IP.String(), MAC: l.MAC, Name: name, Source: source, Online: online,
			VPN: !has(bypass, l.IP.String()) && !has(directMAC, l.MAC), Blocked: has(blocked, l.MAC),
			Lease: formatLease(l.Expiry, now, false), Reserved: isRes || hasIP(reservedByIP, l.IP.String()),
			Usage: usageOf(stationDump, l.MAC),
		}
		byIP[d.IP] = d
	}

	for _, r := range st.Reservations {
		if _, ok := byIP[r.IP]; ok {
			continue
		}
		ip, err := netip.ParseAddr(r.IP)
		if err != nil {
			continue
		}
		source := "lan"
		if wifi.Prefix.Contains(ip) {
			source = "wifi"
		}
		name := r.Name
		if name == "" {
			name = fallbackName(source)
		}
		byIP[r.IP] = &Device{
			IP: r.IP, MAC: r.MAC, Name: name, Source: source,
			Online: neighborUp(neighbors[ip]) || (source == "wifi" && has(stationMAC, r.MAC)),
			VPN:    !has(bypass, r.IP) && !has(directMAC, r.MAC), Blocked: has(blocked, r.MAC),
			Lease: "Reserved", Reserved: true, Usage: usageOf(stationDump, r.MAC),
		}
	}

	// A Wi-Fi client can associate before its lease is written. Wired neighbors
	// without a lease are just other machines on the upstream LAN.
	for ip, n := range neighbors {
		if !neighborUp(n) || skipAddr(ip, self, upstream) || !wifi.Prefix.Contains(ip) {
			continue
		}
		if _, ok := byIP[ip.String()]; ok {
			continue
		}
		if _, on := stationMAC[n.MAC]; !on {
			continue
		}
		name := fallbackName("wifi")
		if r, ok := reservedByMAC[n.MAC]; ok && r.Name != "" {
			name = r.Name
		}
		byIP[ip.String()] = &Device{
			IP: ip.String(), MAC: n.MAC, Name: name, Source: "wifi", Online: true,
			VPN: !has(bypass, ip.String()) && !has(directMAC, n.MAC), Blocked: has(blocked, n.MAC),
			Lease: "—", Reserved: hasIP(reservedByIP, ip.String()), Usage: usageOf(stationDump, n.MAC),
		}
	}

	for _, d := range byIP {
		if d.Online {
			snap.Online++
		}
		snap.Devices = append(snap.Devices, *d)
	}
	sort.Slice(snap.Devices, func(i, j int) bool {
		if snap.Devices[i].Online != snap.Devices[j].Online {
			return snap.Devices[i].Online
		}
		return lessIP(snap.Devices[i].IP, snap.Devices[j].IP)
	})
	return snap
}

func fallbackName(source string) string {
	if source == "wifi" {
		return "Wi-Fi device"
	}
	return "Wired device"
}

func cleanName(name string) string {
	name = strings.TrimSpace(name)
	if name == "*" || name == "" {
		return ""
	}
	return name
}

func formatLease(exp time.Time, now time.Time, reserved bool) string {
	if exp.IsZero() {
		if reserved {
			return "Reserved"
		}
		return "—"
	}
	d := exp.Sub(now)
	if d <= 0 {
		return "Expired"
	}
	return FormatRemain(d)
}

// FormatRemain renders a duration the way the dashboard lease column does.
func FormatRemain(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	hours := d / time.Hour
	d -= hours * time.Hour
	mins := d / time.Minute
	if hours > 0 {
		return fmt.Sprintf("%dh %02dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

// FormatUptime renders how long the control plane has been up.
func FormatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	mins := d / time.Minute
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %02dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

type Neigh struct {
	MAC   string
	State string
}

// ParseLeases reads a dnsmasq lease file.
func ParseLeases(raw string) []lease {
	var out []lease
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		var exp time.Time
		var sec int64
		if _, err := fmt.Sscan(f[0], &sec); err == nil && sec > 0 {
			exp = time.Unix(sec, 0)
		}
		ip, err := netip.ParseAddr(f[2])
		if err != nil {
			continue
		}
		out = append(out, lease{Expiry: exp, MAC: strings.ToLower(f[1]), IP: ip, Name: f[3]})
	}
	return out
}

var stationRE = regexp.MustCompile(`(?i)Station ([0-9a-f:]{17})`)

// Station is one associated Wi-Fi client and the bytes the AP has moved for it.
type Station struct {
	RX uint64
	TX uint64
}

// ParseStations returns MACs currently associated to the AP.
func ParseStations(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for mac := range ParseStationDump(raw) {
		out[mac] = struct{}{}
	}
	return out
}

// ParseStationDump reads `iw dev … station dump`.
func ParseStationDump(raw string) map[string]Station {
	out := map[string]Station{}
	cur := ""
	for _, line := range strings.Split(raw, "\n") {
		if m := stationRE.FindStringSubmatch(line); m != nil {
			cur = strings.ToLower(m[1])
			out[cur] = Station{}
			continue
		}
		if cur == "" {
			continue
		}
		line = strings.TrimSpace(line)
		st := out[cur]
		switch {
		case strings.HasPrefix(line, "rx bytes:"):
			fmt.Sscan(strings.TrimSpace(strings.TrimPrefix(line, "rx bytes:")), &st.RX)
		case strings.HasPrefix(line, "tx bytes:"):
			fmt.Sscan(strings.TrimSpace(strings.TrimPrefix(line, "tx bytes:")), &st.TX)
		}
		out[cur] = st
	}
	return out
}

// FormatBytes renders a byte count for the device list.
func FormatBytes(n uint64) string {
	if n == 0 {
		return ""
	}
	units := []string{"B", "KB", "MB", "GB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func usageOf(dump map[string]Station, mac string) string {
	st, ok := dump[mac]
	if !ok {
		return ""
	}
	return FormatBytes(st.RX + st.TX)
}

// ParseNeigh reads `ip -4 neigh`.
func ParseNeigh(raw string) map[netip.Addr]Neigh {
	out := map[netip.Addr]Neigh{}
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		n := Neigh{State: f[len(f)-1]}
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "lladdr" && i+1 < len(f) {
				n.MAC = strings.ToLower(f[i+1])
			}
		}
		out[ip] = n
	}
	return out
}

func neighborUp(n Neigh) bool {
	switch n.State {
	case "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT":
		return n.MAC != ""
	default:
		return false
	}
}

func skipAddr(ip netip.Addr, self []netip.Addr, upstream netip.Addr) bool {
	if ip == upstream {
		return true
	}
	for _, s := range self {
		if ip == s {
			return true
		}
	}
	return false
}

func setOf(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, v := range in {
		out[v] = struct{}{}
	}
	return out
}

func has(m map[string]struct{}, k string) bool {
	_, ok := m[k]
	return ok
}

func hasIP(m map[string]state.Reservation, ip string) bool {
	_, ok := m[ip]
	return ok
}

func lessIP(a, b string) bool {
	aa, aerr := netip.ParseAddr(a)
	bb, berr := netip.ParseAddr(b)
	if aerr != nil || berr != nil {
		return a < b
	}
	ab, bb4 := aa.As4(), bb.As4()
	for i := 0; i < 4; i++ {
		if ab[i] != bb4[i] {
			return ab[i] < bb4[i]
		}
	}
	return false
}
