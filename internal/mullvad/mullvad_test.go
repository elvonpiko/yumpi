package mullvad

import (
	"encoding/json"
	"strings"
	"testing"
)

const connected = `{"state":"connected","details":{"location":{"ipv4":"146.70.165.29","hostname":"us-nyc-wg-501","city":"New York, NY","country":"USA"}}}`

func TestParseStatus(t *testing.T) {
	st, err := ParseStatus(connected)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Connected || st.Relay != "us-nyc-wg-501" || st.Location != "USA, New York, NY" || st.ExitIP != "146.70.165.29" {
		t.Fatalf("%+v", st)
	}
	down, err := ParseStatus(`{"state":"disconnected"}`)
	if err != nil || down.Connected {
		t.Fatalf("%+v %v", down, err)
	}
}

func TestCityJSONUsesDashboardNames(t *testing.T) {
	b, err := json.Marshal(Country{Name: "Sweden", Code: "se", Cities: []City{{Name: "Gothenburg", Code: "got"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"name":"Gothenburg"`) || !strings.Contains(string(b), `"code":"got"`) {
		t.Fatal(string(b))
	}
}

func TestObfuscatedText(t *testing.T) {
	if !ObfuscatedText("Features: LAN Sharing, LWO, Quantum Resistance") {
		t.Fatal("lwo")
	}
	if ObfuscatedText("Features: LAN Sharing, Quantum Resistance") {
		t.Fatal("plain tunnel")
	}
}

func TestParseRelays(t *testing.T) {
	raw := "Albania (al)\n\tTirana (tia) @ 41.3°N, 19.8°W\n\t\tal-tia-wg-001\nUnited States (us)\n\tNew York, NY (nyc) @ 40°N, -73°W\n\tLos Angeles, CA (lax) @ 34°N, -118°W\n"
	got := ParseRelays(raw)
	if len(got) != 2 || got[0].Code != "al" || len(got[0].Cities) != 1 || got[0].Cities[0].Code != "tia" {
		t.Fatalf("%+v", got)
	}
	if got[1].Code != "us" || len(got[1].Cities) != 2 || got[1].Cities[1].Code != "lax" {
		t.Fatalf("%+v", got[1])
	}
}

func TestParseRelaysWithoutCoordinates(t *testing.T) {
	raw := "Sweden (se)\n    Stockholm (sto)\n        se-sto-wg-001 (1.2.3.4) - hosted by Mullvad (Mullvad-owned)\n    Gothenburg (got)\nFrance (fr)\n\tParis (par)\n"
	got := ParseRelays(raw)
	if len(got) != 2 || got[0].Code != "se" || len(got[0].Cities) != 2 || got[0].Cities[0].Code != "sto" || got[0].Cities[1].Code != "got" {
		t.Fatalf("%+v", got)
	}
	if got[1].Code != "fr" || len(got[1].Cities) != 1 || got[1].Cities[0].Code != "par" {
		t.Fatalf("%+v", got[1])
	}
}
