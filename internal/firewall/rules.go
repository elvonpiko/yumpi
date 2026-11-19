package firewall

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Input is everything the ruleset is allowed to depend on.
type Input struct {
	WiFiIface string
	LANIface  string
	VPNIface  string
	TunnelDNS netip.Addr
	DirectDNS netip.Addr
	WiFiNet   netip.Prefix
	LANNet    netip.Prefix
	Bypass    []netip.Addr
	VPNUp     bool
}

var ifaceRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,14}$`)

// Render builds an nftables script that replaces the yumpi table in one transaction.
//
// Mullvad installs its own routing policy. Traffic marked 0x6d6f6c65 ("mole") stays
// on the normal default route; everything else is pulled into the tunnel. The mark
// chain runs after dstnat so a rewritten DNS packet is marked as public, not as a
// query still aimed at 10.64.0.1.
func Render(in Input) (string, error) {
	if !ifaceRE.MatchString(in.WiFiIface) || !ifaceRE.MatchString(in.LANIface) {
		return "", fmt.Errorf("invalid interface")
	}
	if in.VPNUp && in.VPNIface != "" && !ifaceRE.MatchString(in.VPNIface) {
		return "", fmt.Errorf("invalid vpn interface")
	}
	if !in.TunnelDNS.Is4() || !in.DirectDNS.Is4() {
		return "", fmt.Errorf("dns addresses must be ipv4")
	}
	bypass := uniqueAddrs(in.Bypass)

	var b strings.Builder
	b.WriteString("add table inet yumpi\n")
	b.WriteString("flush table inet yumpi\n")
	b.WriteString("add set inet yumpi bypass { type ipv4_addr ; }\n")
	b.WriteString("add set inet yumpi clients { type ipv4_addr ; flags interval ; }\n")
	if len(bypass) > 0 {
		fmt.Fprintf(&b, "add element inet yumpi bypass { %s }\n", joinAddrs(bypass))
	}
	fmt.Fprintf(&b, "add element inet yumpi clients { %s, %s }\n", in.WiFiNet, in.LANNet)

	b.WriteString("add chain inet yumpi dstnat { type nat hook prerouting priority dstnat ; policy accept ; }\n")
	who := "@bypass"
	if !in.VPNUp {
		who = "@clients"
	}
	fmt.Fprintf(&b, "add rule inet yumpi dstnat ip saddr %s ip daddr %s udp dport 53 dnat ip to %s:53\n", who, in.TunnelDNS, in.DirectDNS)
	fmt.Fprintf(&b, "add rule inet yumpi dstnat ip saddr %s ip daddr %s tcp dport 53 dnat ip to %s:53\n", who, in.TunnelDNS, in.DirectDNS)

	// -90 is after dstnat (-100) and after Mullvad's own prerouting (-199).
	// The chain cannot be named "mark": that word is an nftables keyword.
	b.WriteString("add chain inet yumpi exclude { type filter hook prerouting priority -90 ; policy accept ; }\n")
	markWho := "@bypass"
	if !in.VPNUp {
		markWho = "@clients"
	}
	fmt.Fprintf(&b, "add rule inet yumpi exclude ip saddr %s ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } ct mark set 0x00000f41 meta mark set 0x6d6f6c65\n", markWho)

	b.WriteString("add chain inet yumpi srcnat { type nat hook postrouting priority srcnat ; policy accept ; }\n")
	if in.VPNUp && in.VPNIface != "" {
		fmt.Fprintf(&b, "add rule inet yumpi srcnat oifname %q meta nfproto ipv4 masquerade\n", in.VPNIface)
		b.WriteString("add rule inet yumpi srcnat ip saddr @bypass oifname " + quote(in.LANIface) + " meta nfproto ipv4 masquerade\n")
	} else {
		b.WriteString("add rule inet yumpi srcnat ip saddr @clients oifname " + quote(in.LANIface) + " meta nfproto ipv4 masquerade\n")
	}
	return b.String(), nil
}

func quote(s string) string { return strconv.Quote(s) }

func uniqueAddrs(in []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]struct{}{}
	var out []netip.Addr
	for _, a := range in {
		if !a.Is4() {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}

func joinAddrs(in []netip.Addr) string {
	parts := make([]string, len(in))
	for i, a := range in {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

// ForwardRules are the filter rules for the YUMPI iptables chain.
// iptables is separate from nft: Docker sets FORWARD policy DROP, so an nft
// accept does not by itself let a packet through.
func ForwardRules(in Input) [][]string {
	var rules [][]string
	if in.VPNUp && in.VPNIface != "" {
		rules = append(rules,
			[]string{"-i", in.WiFiIface, "-o", in.VPNIface, "-j", "ACCEPT"},
			[]string{"-i", in.LANIface, "-o", in.VPNIface, "-j", "ACCEPT"},
			[]string{"-i", in.VPNIface, "-o", in.WiFiIface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			[]string{"-i", in.VPNIface, "-o", in.LANIface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			[]string{"-i", in.LANIface, "-o", in.LANIface, "-m", "connmark", "--mark", "0x00000f41", "-j", "ACCEPT"},
		)
	} else {
		rules = append(rules,
			[]string{"-i", in.LANIface, "-o", in.LANIface, "-j", "ACCEPT"},
		)
	}
	rules = append(rules,
		[]string{"-i", in.WiFiIface, "-o", in.LANIface, "-j", "ACCEPT"},
		[]string{"-i", in.LANIface, "-o", in.WiFiIface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	)
	return rules
}

// DHCPPlan says which Mullvad input rules to delete and which interfaces still
// need a single DHCP accept inserted at the top of the chain.
type DHCPPlan struct {
	Delete []int
	Add    []string
}

var (
	handleRE  = regexp.MustCompile(`# handle (\d+)`)
	iifRE     = regexp.MustCompile(`iifname "([^"]+)"`)
	commentRE = regexp.MustCompile(`comment "([^"]*)"`)
)

// PlanDHCP keeps one commented yumpi DHCP rule per interface and drops the rest.
// Uncommented copies are the legacy installer bug and are always removed.
func PlanDHCP(listing string, ifaces []string) DHCPPlan {
	type hit struct {
		handle    int
		commented bool
	}
	found := map[string][]hit{}
	for _, line := range strings.Split(listing, "\n") {
		if !strings.Contains(line, "udp dport 67") || !strings.Contains(line, "accept") {
			continue
		}
		im := iifRE.FindStringSubmatch(line)
		hm := handleRE.FindStringSubmatch(line)
		if im == nil || hm == nil {
			continue
		}
		h, err := strconv.Atoi(hm[1])
		if err != nil {
			continue
		}
		commented := false
		if cm := commentRE.FindStringSubmatch(line); cm != nil && cm[1] == "yumpi" {
			commented = true
		}
		found[im[1]] = append(found[im[1]], hit{handle: h, commented: commented})
	}
	var plan DHCPPlan
	for _, iface := range ifaces {
		hits := found[iface]
		var commented []int
		for _, h := range hits {
			if h.commented {
				commented = append(commented, h.handle)
				continue
			}
			plan.Delete = append(plan.Delete, h.handle)
		}
		if len(commented) == 0 {
			plan.Add = append(plan.Add, iface)
			continue
		}
		sort.Ints(commented)
		plan.Delete = append(plan.Delete, commented[1:]...)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(plan.Delete)))
	return plan
}
