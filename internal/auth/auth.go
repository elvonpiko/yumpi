package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionTTL = 12 * time.Hour
	failWindow = 10 * time.Minute
	failLimit  = 5
)

var (
	// ErrDenied is a wrong password.
	ErrDenied = errors.New("incorrect password")
	// ErrLimited means this address tried too many times.
	ErrLimited = errors.New("too many attempts")
)

// Manager holds login sessions in memory. A restart signs everyone out.
type Manager struct {
	hash     []byte
	mu       sync.Mutex
	sessions map[string]time.Time
	failures map[string][]time.Time
	now      func() time.Time
}

func New(passwordHash string) (*Manager, error) {
	if _, err := bcrypt.Cost([]byte(passwordHash)); err != nil {
		return nil, errors.New("password hash is not bcrypt")
	}
	return &Manager{
		hash:     []byte(passwordHash),
		sessions: map[string]time.Time{},
		failures: map[string][]time.Time{},
		now:      time.Now,
	}, nil
}

// HashPassword hashes an admin password for init-config.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// HashIfCurrent checks the current password and returns a hash of the next one.
// It does not install that hash. A wrong current password counts toward the login limit.
func (m *Manager) HashIfCurrent(remote, current, next string) (string, error) {
	m.mu.Lock()
	now := m.now()
	if m.limited(remote, now) {
		m.mu.Unlock()
		return "", ErrLimited
	}
	have := append([]byte(nil), m.hash...)
	m.mu.Unlock()
	if bcrypt.CompareHashAndPassword(have, []byte(current)) != nil {
		m.mu.Lock()
		m.failures[remote] = append(m.recent(remote, m.now()), m.now())
		m.mu.Unlock()
		return "", ErrDenied
	}
	return HashPassword(next)
}

// UseHash installs a hash from HashIfCurrent and drops every session except keep.
func (m *Manager) UseHash(hash, keep string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hash = []byte(hash)
	for token := range m.sessions {
		if token != keep {
			delete(m.sessions, token)
		}
	}
}

// Login checks the password and returns a new session token.
func (m *Manager) Login(remote, password string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if m.limited(remote, now) {
		return "", ErrLimited
	}
	if bcrypt.CompareHashAndPassword(m.hash, []byte(password)) != nil {
		m.failures[remote] = append(m.recent(remote, now), now)
		return "", ErrDenied
	}
	delete(m.failures, remote)
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	m.sessions[token] = now.Add(sessionTTL)
	return token, nil
}

// Valid reports whether the token is a live session.
func (m *Manager) Valid(token string) bool {
	if len(token) != 64 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.sessions[token]
	if !ok {
		return false
	}
	if m.now().After(exp) {
		delete(m.sessions, token)
		return false
	}
	return true
}

// Logout drops a session. Unknown tokens are ignored.
func (m *Manager) Logout(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
}

func (m *Manager) limited(remote string, now time.Time) bool {
	return len(m.recent(remote, now)) >= failLimit
}

func (m *Manager) recent(remote string, now time.Time) []time.Time {
	in := m.failures[remote]
	out := in[:0]
	for _, t := range in {
		if now.Sub(t) < failWindow {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		delete(m.failures, remote)
		return nil
	}
	m.failures[remote] = out
	return out
}
