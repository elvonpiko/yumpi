package netconv

import (
	"net"
	"regexp"
	"strings"
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)

// MAC returns a lowercase colon-separated address, or false.
func MAC(in string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(in))
	if err != nil || len(hw) != 6 {
		return "", false
	}
	parts := make([]string, len(hw))
	for i, b := range hw {
		parts[i] = hexByte(b)
	}
	return strings.Join(parts, ":"), true
}

func hexByte(b byte) string {
	const d = "0123456789abcdef"
	return string([]byte{d[b>>4], d[b&0x0f]})
}

// Hostname accepts a short DNS-like label, or an empty name.
func Hostname(in string) (string, bool) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", true
	}
	if !nameRE.MatchString(in) {
		return "", false
	}
	return in, true
}
