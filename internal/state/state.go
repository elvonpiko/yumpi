package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Reservation pins a DHCP address to a MAC.
type Reservation struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name,omitempty"`
}

// State is mutable gateway policy. It is rewritten atomically.
type State struct {
	BypassIPs      []string      `json:"bypass_ips"`
	DirectMACs     []string      `json:"direct_macs"`
	BlockedMACs    []string      `json:"blocked_macs"`
	Reservations   []Reservation `json:"reservations"`
	DHCPDisabled   bool          `json:"dhcp_disabled"`
	PinnedLocation string        `json:"pinned_location"`
	GuestEnabled   bool          `json:"guest_enabled"`
	// BlockWhenDown pauses internet for devices set to Mullvad while the tunnel is down.
	// Devices set to direct, and traffic inside the house, keep working.
	BlockWhenDown bool `json:"block_when_down"`
}

var pinnedRE = regexp.MustCompile(`^[a-z]{2}(?: [a-z]{3})?$`)

// Store is the process-wide copy of State.
type Store struct {
	mu   sync.Mutex
	path string
	cur  State
}

// Open loads state, or starts from an empty policy if the file does not exist yet.
func Open(path string) (*Store, error) {
	s := &Store{path: path, cur: State{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.cur = normalize(s.cur)
			return s, nil
		}
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &s.cur); err != nil {
			return nil, err
		}
	}
	s.cur = normalize(s.cur)
	return s, nil
}

// Get returns a copy.
func (s *Store) Get() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.cur)
}

// Update mutates state under the lock and persists it before returning.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.cur)
	if err := fn(&next); err != nil {
		return err
	}
	next = normalize(next)
	if err := write(s.path, next); err != nil {
		return err
	}
	s.cur = next
	return nil
}

func clone(in State) State {
	out := in
	out.BypassIPs = append([]string(nil), in.BypassIPs...)
	out.DirectMACs = append([]string(nil), in.DirectMACs...)
	out.BlockedMACs = append([]string(nil), in.BlockedMACs...)
	out.Reservations = append([]Reservation(nil), in.Reservations...)
	return out
}

func normalize(in State) State {
	in.BypassIPs = uniqSorted(in.BypassIPs)
	in.DirectMACs = uniqSorted(in.DirectMACs)
	in.BlockedMACs = uniqSorted(in.BlockedMACs)
	in.PinnedLocation = strings.TrimSpace(strings.ToLower(in.PinnedLocation))
	if !pinnedRE.MatchString(in.PinnedLocation) {
		in.PinnedLocation = ""
	}
	if in.Reservations == nil {
		in.Reservations = []Reservation{}
	}
	sort.Slice(in.Reservations, func(i, j int) bool { return in.Reservations[i].MAC < in.Reservations[j].MAC })
	return in
}

func uniqSorted(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func write(path string, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.json")
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
