package auth

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestLoginSessionAndLimit(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(string(hash))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m.now = func() time.Time { return now }
	if _, err := m.Login("10.0.0.8", "nope"); err != ErrDenied {
		t.Fatalf("got %v", err)
	}
	token, err := m.Login("10.0.0.8", "correct-password")
	if err != nil || !m.Valid(token) {
		t.Fatalf("login: %v %q", err, token)
	}
	m.Logout(token)
	if m.Valid(token) {
		t.Fatal("session survived logout")
	}
	for i := 0; i < failLimit; i++ {
		if _, err := m.Login("10.0.0.9", "nope"); err != ErrDenied {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := m.Login("10.0.0.9", "correct-password"); err != ErrLimited {
		t.Fatalf("got %v", err)
	}
	now = now.Add(failWindow + time.Second)
	if _, err := m.Login("10.0.0.9", "correct-password"); err != nil {
		t.Fatal(err)
	}
}
