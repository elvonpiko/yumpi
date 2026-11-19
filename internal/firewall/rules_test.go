package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
)

func sampleInput(up bool) Input {
	return Input{
		WiFiIface: "wlan0",
		LANIface:  "eth0",
		VPNIface:  "wg0-mullvad",
		TunnelDNS: netip.MustParseAddr("10.64.0.1"),
		DirectDNS: netip.MustParseAddr("1.1.1.1"),
		WiFiNet:   netip.MustParsePrefix("10.23.46.0/24"),
		LANNet:    netip.MustParsePrefix("10.23.45.0/24"),
		Bypass:    []netip.Addr{netip.MustParseAddr("10.23.45.145")},
		VPNUp:     up,
	}
}

func TestRenderMarksBypassAfterDNAT(t *testing.T) {
	script, err := Render(sampleInput(true))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"priority -90",
		"add chain inet yumpi exclude",
		"ip saddr @bypass ip daddr 10.64.0.1 udp dport 53 dnat ip to 1.1.1.1:53",
		`oifname "wg0-mullvad"`,
		"meta mark set 0x6d6f6c65",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q\n%s", want, script)
		}
	}
	down, err := Render(sampleInput(false))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(down, "wg0-mullvad") {
		t.Fatal("down script still names the tunnel")
	}
	if !strings.Contains(down, "ip saddr @clients ip daddr 10.64.0.1") {
		t.Fatal(down)
	}
}

func TestForwardRulesCoverWiredBypass(t *testing.T) {
	all := joinRules(ForwardRules(sampleInput(true)))
	if !strings.Contains(all, "-i eth0 -o eth0 -m connmark --mark 0x00000f41 -j ACCEPT") {
		t.Fatal(all)
	}
	if !strings.Contains(all, "-i wlan0 -o wg0-mullvad -j ACCEPT") {
		t.Fatal(all)
	}
	down := joinRules(ForwardRules(sampleInput(false)))
	if !strings.Contains(down, "-i eth0 -o eth0 -j ACCEPT") {
		t.Fatal(down)
	}
}

func TestPlanDHCPDropsDuplicates(t *testing.T) {
	listing := `
	iifname "eth0" udp dport 67 accept # handle 4
	iifname "eth0" udp dport 67 accept # handle 9
	iifname "wlan0" udp dport 67 accept comment "yumpi" # handle 3
	iifname "wlan0" udp dport 67 accept comment "yumpi" # handle 8
	iifname "other0" udp dport 67 accept # handle 1
`
	plan := PlanDHCP(listing, []string{"wlan0", "eth0"})
	if !sameInts(plan.Delete, []int{9, 4, 8}) {
		t.Fatalf("delete %v", plan.Delete)
	}
	if len(plan.Add) != 1 || plan.Add[0] != "eth0" {
		t.Fatalf("add %v", plan.Add)
	}
}

func TestApplyReconcilesOnce(t *testing.T) {
	f := &fakeRun{}
	dir := t.TempDir()
	if err := Apply(context.Background(), f, dir, sampleInput(true)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(dir + "/rules.nft"); err != nil {
		t.Fatal(err)
	}
	cmds := strings.Join(f.cmds, "\n")
	if !strings.Contains(cmds, "nft delete rule inet mullvad input handle 9") {
		t.Fatal(cmds)
	}
	if !strings.Contains(cmds, "nft insert rule inet mullvad input iifname eth0 udp dport 67 accept comment yumpi") {
		t.Fatal(cmds)
	}
	if strings.Count(cmds, "iptables -w 5 -I FORWARD") != 1 {
		t.Fatal(cmds)
	}
	before := len(f.cmds)
	f.synced = true
	if err := Apply(context.Background(), f, dir, sampleInput(true)); err != nil {
		t.Fatal(err)
	}
	again := strings.Join(f.cmds[before:], "\n")
	if strings.Contains(again, "-I FORWARD") || strings.Contains(again, "-F YUMPI") {
		t.Fatalf("second apply changed iptables:\n%s", again)
	}
}

type fakeRun struct {
	mu     sync.Mutex
	cmds   []string
	chain  bool
	jump   bool
	synced bool
}

func (f *fakeRun) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	if name == "nft" && len(args) > 0 && args[0] == "-a" {
		return "iifname \"eth0\" udp dport 67 accept # handle 4\niifname \"eth0\" udp dport 67 accept # handle 9\niifname \"wlan0\" udp dport 67 accept comment \"yumpi\" # handle 3\n", nil
	}
	if name != "iptables" {
		return "", nil
	}
	switch {
	case hasArg(args, "-N"):
		if f.chain {
			return "", fmt.Errorf("iptables: Chain already exists")
		}
		f.chain = true
	case hasArg(args, "-C"):
		if !f.jump {
			f.jump = true
			return "", fmt.Errorf("iptables: Bad rule (does a matching rule exist in that chain?)")
		}
	case hasArg(args, "-S"):
		if !f.synced {
			return "-N YUMPI\n", nil
		}
		var b strings.Builder
		b.WriteString("-N YUMPI\n")
		for _, rule := range ForwardRules(sampleInput(true)) {
			b.WriteString("-A YUMPI " + strings.Join(rule, " ") + "\n")
		}
		return b.String(), nil
	}
	return "", nil
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func joinRules(rules [][]string) string {
	parts := make([]string, len(rules))
	for i, r := range rules {
		parts[i] = strings.Join(r, " ")
	}
	return strings.Join(parts, "\n")
}

func sameInts(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[int]int{}
	for _, n := range got {
		seen[n]++
	}
	for _, n := range want {
		seen[n]--
		if seen[n] < 0 {
			return false
		}
	}
	return true
}
