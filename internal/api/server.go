package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"yumpi/internal/auth"
	"yumpi/internal/daemon"
	"yumpi/internal/mullvad"
)

const cookieName = "yumpi_session"

// Service is the control plane the HTTP API calls.
type Service interface {
	Status(ctx context.Context) (daemon.Status, error)
	Login(remote, password string) (string, error)
	Logout(token string)
	Valid(token string) bool
	SetVPN(ctx context.Context, ip string, enabled bool) error
	SetBlock(ctx context.Context, mac string, blocked bool) error
	AddReservation(ctx context.Context, mac, ip, name string) error
	DeleteReservation(ctx context.Context, mac string) error
	SetDHCP(ctx context.Context, enabled bool) error
	MullvadAction(ctx context.Context, action, location string) error
	SetWiFi(ctx context.Context, ssid, passphrase string) error
	Relays(ctx context.Context) ([]mullvad.Country, error)
}

// New mux serves the dashboard and the JSON API.
func New(svc Service, assets fs.FS, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	s := &server{svc: svc, assets: assets, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST /api/login", s.login)
	mux.Handle("POST /api/logout", s.auth(http.HandlerFunc(s.logout)))
	mux.Handle("GET /api/status", s.auth(http.HandlerFunc(s.status)))
	mux.Handle("GET /api/relays", s.auth(http.HandlerFunc(s.relays)))
	mux.Handle("POST /api/device/vpn", s.auth(http.HandlerFunc(s.vpn)))
	mux.Handle("POST /api/device/block", s.auth(http.HandlerFunc(s.block)))
	mux.Handle("POST /api/reservation", s.auth(http.HandlerFunc(s.addReservation)))
	mux.Handle("POST /api/reservation/delete", s.auth(http.HandlerFunc(s.deleteReservation)))
	mux.Handle("POST /api/dhcp", s.auth(http.HandlerFunc(s.dhcp)))
	mux.Handle("POST /api/mullvad", s.auth(http.HandlerFunc(s.mullvad)))
	mux.Handle("POST /api/wifi", s.auth(http.HandlerFunc(s.wifi)))
	mux.HandleFunc("GET /{$}", s.static)
	mux.HandleFunc("GET /{path...}", s.static)
	return securityHeaders(mux)
}

type server struct {
	svc    Service
	assets fs.FS
	log    *slog.Logger
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if !originOK(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request was rejected")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "Send a password.")
		return
	}
	token, err := s.svc.Login(clientIP(r), body.Password)
	if errors.Is(err, auth.ErrLimited) {
		writeErr(w, http.StatusTooManyRequests, "Too many attempts. Wait a few minutes.")
		return
	}
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Incorrect password.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.svc.Logout(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	st, err := s.svc.Status(r.Context())
	if err != nil {
		s.log.Error("status", "err", err)
		writeErr(w, http.StatusInternalServerError, "Status is unavailable.")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *server) relays(w http.ResponseWriter, r *http.Request) {
	list, err := s.svc.Relays(r.Context())
	if err != nil {
		s.log.Warn("relays", "err", err)
		writeErr(w, http.StatusBadGateway, "Relay list is unavailable.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"countries": list})
}

func (s *server) vpn(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP      string `json:"ip"`
		Enabled bool   `json:"enabled"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "Missing address.")
		return
	}
	s.writeCall(w, r, s.svc.SetVPN(r.Context(), body.IP, body.Enabled))
}

func (s *server) block(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MAC     string `json:"mac"`
		Blocked bool   `json:"blocked"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "Missing MAC address.")
		return
	}
	s.writeCall(w, r, s.svc.SetBlock(r.Context(), body.MAC, body.Blocked))
}

func (s *server) addReservation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MAC  string `json:"mac"`
		IP   string `json:"ip"`
		Name string `json:"name"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "Missing reservation.")
		return
	}
	s.writeCall(w, r, s.svc.AddReservation(r.Context(), body.MAC, body.IP, body.Name))
}

func (s *server) deleteReservation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MAC string `json:"mac"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "Missing MAC address.")
		return
	}
	s.writeCall(w, r, s.svc.DeleteReservation(r.Context(), body.MAC))
}

func (s *server) dhcp(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "Missing DHCP setting.")
		return
	}
	s.writeCall(w, r, s.svc.SetDHCP(r.Context(), body.Enabled))
}

func (s *server) mullvad(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action   string `json:"action"`
		Location string `json:"location"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "Missing action.")
		return
	}
	s.writeCall(w, r, s.svc.MullvadAction(r.Context(), body.Action, body.Location))
}

func (s *server) wifi(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SSID       string `json:"ssid"`
		Passphrase string `json:"passphrase"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "Missing Wi-Fi settings.")
		return
	}
	s.writeCall(w, r, s.svc.SetWiFi(r.Context(), body.SSID, body.Passphrase))
}

func (s *server) writeCall(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	var ie *daemon.InputError
	if errors.As(err, &ie) {
		writeErr(w, http.StatusBadRequest, ie.Msg)
		return
	}
	s.log.Error("api", "err", err, "path", r.URL.Path)
	writeErr(w, http.StatusInternalServerError, "That change did not apply.")
}

func (s *server) static(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("path")
	if name == "" {
		name = "index.html"
	}
	if strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	f, err := s.assets.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(name, ".ttf"):
		w.Header().Set("Content-Type", "font/ttf")
	case strings.HasSuffix(name, ".txt"):
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-cache")
	var rs io.ReadSeeker
	if s, ok := f.(io.ReadSeeker); ok {
		rs = s
	} else {
		b, err := io.ReadAll(f)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		rs = bytes.NewReader(b)
	}
	http.ServeContent(w, r, name, st.ModTime(), rs)
}

func (s *server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || !s.svc.Valid(c.Value) {
			writeErr(w, http.StatusUnauthorized, "Sign in.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !originOK(r) {
			writeErr(w, http.StatusForbidden, "cross-origin request was rejected")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func originOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// Serve runs the HTTP server until ctx is cancelled.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
