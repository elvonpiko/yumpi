package mullvad

import "testing"

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
