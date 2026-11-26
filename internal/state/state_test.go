package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpdatePersistsAndNormalizes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error {
		st.BypassIPs = []string{"10.0.0.2", "10.0.0.2", "10.0.0.1"}
		st.BlockedMACs = []string{"AA:BB:CC:DD:EE:FF"}
		st.Reservations = []Reservation{{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.0.0.9", Name: "tv"}}
		st.BlockWhenDown = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if len(got.BypassIPs) != 2 || got.BypassIPs[0] != "10.0.0.1" {
		t.Fatalf("%v", got.BypassIPs)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Get().Reservations[0].Name != "tv" || !again.Get().BlockWhenDown {
		t.Fatalf("%+v", again.Get())
	}
}
