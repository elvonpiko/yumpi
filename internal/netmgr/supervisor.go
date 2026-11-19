package netmgr

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"yumpi/internal/system"
)

// Supervisor keeps hostapd and dnsmasq running. It does not render config;
// the daemon writes the files, then restarts the process that should re-read them.
type Supervisor struct {
	Log    *slog.Logger
	Run    system.Runner
	RunDir string
	WiFi   string

	ap   proc
	dhcp proc
}

// Start launches both supervisors. DHCP stays stopped until SetDHCP(true).
func (s *Supervisor) Start(ctx context.Context) {
	s.ap.init("hostapd", s.Log, func() []string {
		return []string{bin("hostapd"), filepath.Join(s.RunDir, "hostapd.conf")}
	}, func() bool { return true })
	s.dhcp.init("dnsmasq", s.Log, func() []string {
		return []string{bin("dnsmasq"), "-k", "-C", filepath.Join(s.RunDir, "dnsmasq.conf"), "-x", filepath.Join(s.RunDir, "dnsmasq.pid"), "-u", "root"}
	}, nil)
	go s.ap.loop(ctx)
	go s.dhcp.loop(ctx)
}

// SetDHCP starts or stops the DHCP server without touching the access point.
func (s *Supervisor) SetDHCP(on bool) {
	s.dhcp.setEnabled(on)
	if on {
		s.dhcp.wake()
		return
	}
	s.dhcp.stop()
}

// RestartAP asks hostapd to exit so it is started again with the current files.
func (s *Supervisor) RestartAP() { s.ap.stop() }

// RestartDHCP restarts dnsmasq when it is enabled.
func (s *Supervisor) RestartDHCP() {
	if s.dhcp.enabled != nil && s.dhcp.enabled() {
		s.dhcp.stop()
	}
}

// Block updates the live ACL. The deny file is already on disk for the next start.
func (s *Supervisor) Block(ctx context.Context, mac string, blocked bool) {
	action := "ADD_MAC"
	if !blocked {
		action = "DEL_MAC"
	}
	base := []string{"-p", filepath.Join(s.RunDir, "hostapd")}
	if _, err := s.Run.Run(ctx, "hostapd_cli", append(base, "deny_acl", action, mac)...); err != nil {
		s.Log.Warn("hostapd acl", "err", err, "mac", mac)
	}
	if blocked {
		if _, err := s.Run.Run(ctx, "hostapd_cli", append(base, "deauthenticate", mac)...); err != nil {
			s.Log.Warn("hostapd deauth", "err", err, "mac", mac)
		}
	}
}

// PrepareLink turns forwarding on and gives the AP interface its address.
func PrepareLink(ctx context.Context, run system.Runner, iface, cidr string) {
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("0\n"), 0o644)
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+iface+"/disable_ipv6", []byte("1\n"), 0o644)
	_, _ = run.Run(ctx, "ip", "link", "set", iface, "up")
	_, _ = run.Run(ctx, "ip", "addr", "replace", cidr, "dev", iface)
	_, _ = run.Run(ctx, "iw", "dev", iface, "set", "power_save", "off")
}

type proc struct {
	name    string
	log     *slog.Logger
	argv    func() []string
	enabled func() bool
	wakeCh  chan struct{}

	mu  sync.Mutex
	cmd *exec.Cmd
	on  bool
}

func (p *proc) init(name string, log *slog.Logger, argv func() []string, enabled func() bool) {
	if log == nil {
		log = slog.Default()
	}
	p.name = name
	p.log = log
	p.argv = argv
	p.wakeCh = make(chan struct{}, 1)
	if enabled == nil {
		p.enabled = func() bool {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.on
		}
		return
	}
	p.enabled = enabled
	p.on = true
}

func (p *proc) setEnabled(on bool) {
	p.mu.Lock()
	p.on = on
	p.mu.Unlock()
}

func (p *proc) isOn() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.on
}

func (p *proc) wake() {
	if p.wakeCh == nil {
		return
	}
	select {
	case p.wakeCh <- struct{}{}:
	default:
	}
}

func (p *proc) stop() {
	p.mu.Lock()
	cmd := p.cmd
	p.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
}

func (p *proc) loop(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if !p.enabled() {
			select {
			case <-ctx.Done():
				return
			case <-p.wakeCh:
			}
			continue
		}
		argv := p.argv()
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdout = &logWriter{log: p.log, name: p.name}
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			p.log.Error("start failed", "proc", p.name, "err", err)
			if !sleep(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		p.mu.Lock()
		p.cmd = cmd
		p.mu.Unlock()
		waitDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = cmd.Process.Signal(syscall.SIGTERM)
			case <-waitDone:
			}
		}()
		started := time.Now()
		err := cmd.Wait()
		close(waitDone)
		p.mu.Lock()
		if p.cmd == cmd {
			p.cmd = nil
		}
		p.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > 30*time.Second {
			backoff = time.Second
		}
		p.log.Warn("exited", "proc", p.name, "err", err)
		if !sleep(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > 15*time.Second {
		return 15 * time.Second
	}
	return d
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

type logWriter struct {
	mu   sync.Mutex
	log  *slog.Logger
	name string
	buf  []byte
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := indexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := string(w.buf[:i])
		w.buf = w.buf[i+1:]
		if line != "" {
			w.log.Info(line, "proc", w.name)
		}
	}
	return len(p), nil
}

func bin(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return "/usr/sbin/" + name
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}
