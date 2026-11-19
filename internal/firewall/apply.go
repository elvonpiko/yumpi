package firewall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"yumpi/internal/system"
)

// Apply replaces the yumpi nftables table and makes the iptables and Mullvad
// DHCP rules match. nftables is one transaction. iptables is left alone when
// the YUMPI chain already matches, so a reconcile does not open a gap.
func Apply(ctx context.Context, run system.Runner, dir string, in Input) error {
	script, err := Render(in)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(dir, "rules.nft")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		return err
	}
	if _, err := run.Run(ctx, "nft", "-c", "-f", path); err != nil {
		return fmt.Errorf("nft check: %w", err)
	}
	if _, err := run.Run(ctx, "nft", "-f", path); err != nil {
		return fmt.Errorf("nft apply: %w", err)
	}
	if err := syncIptables(ctx, run, in); err != nil {
		return err
	}
	ifaces := []string{in.WiFiIface, in.LANIface}
	if in.GuestOn && in.GuestIface != "" {
		ifaces = append(ifaces, in.GuestIface)
	}
	if err := syncDHCP(ctx, run, ifaces); err != nil {
		return err
	}
	return nil
}

func syncIptables(ctx context.Context, run system.Runner, in Input) error {
	rules := ForwardRules(in)
	if _, err := run.Run(ctx, "iptables", "-w", "5", "-N", "YUMPI"); err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("iptables chain: %w", err)
	}
	if _, err := run.Run(ctx, "iptables", "-w", "5", "-C", "FORWARD", "-j", "YUMPI"); err != nil {
		if _, err := run.Run(ctx, "iptables", "-w", "5", "-I", "FORWARD", "1", "-j", "YUMPI"); err != nil {
			return fmt.Errorf("iptables jump: %w", err)
		}
	}
	have, err := run.Run(ctx, "iptables", "-w", "5", "-S", "YUMPI")
	if err == nil && iptablesSame(have, rules) {
		return nil
	}
	if _, err := run.Run(ctx, "iptables", "-w", "5", "-F", "YUMPI"); err != nil {
		return fmt.Errorf("iptables flush: %w", err)
	}
	for _, rule := range rules {
		args := append([]string{"-w", "5", "-A", "YUMPI"}, rule...)
		if _, err := run.Run(ctx, "iptables", args...); err != nil {
			return fmt.Errorf("iptables rule: %w", err)
		}
	}
	return nil
}

func iptablesSame(have string, rules [][]string) bool {
	var got []string
	for _, line := range strings.Split(have, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-A YUMPI ") {
			got = append(got, strings.TrimPrefix(line, "-A YUMPI "))
		}
	}
	if len(got) != len(rules) {
		return false
	}
	for i, rule := range rules {
		if got[i] != strings.Join(rule, " ") {
			return false
		}
	}
	return true
}

func syncDHCP(ctx context.Context, run system.Runner, ifaces []string) error {
	out, err := run.Run(ctx, "nft", "-a", "list", "chain", "inet", "mullvad", "input")
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist") || strings.Contains(msg, "No such chain") {
			return nil
		}
		return fmt.Errorf("mullvad dhcp: %w", err)
	}
	plan := PlanDHCP(out, ifaces)
	sort.Sort(sort.Reverse(sort.IntSlice(plan.Delete)))
	for _, handle := range plan.Delete {
		if _, err := run.Run(ctx, "nft", "delete", "rule", "inet", "mullvad", "input", "handle", fmt.Sprint(handle)); err != nil {
			return fmt.Errorf("delete dhcp rule %d: %w", handle, err)
		}
	}
	for _, iface := range plan.Add {
		if _, err := run.Run(ctx, "nft", "insert", "rule", "inet", "mullvad", "input", "iifname", iface, "udp", "dport", "67", "accept", "comment", "yumpi"); err != nil {
			return fmt.Errorf("insert dhcp rule: %w", err)
		}
	}
	return nil
}
