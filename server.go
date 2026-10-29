package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFiles embed.FS

type loginBucket struct {
	count int
	since time.Time
}
type Panel struct {
	store      *Store
	core       *Core
	tunnels    *Tunnels
	adapters   *Adapters
	admin      [32]byte
	secure     bool
	mu         sync.Mutex
	sessions   map[string]time.Time
	attempts   map[string]loginBucket
	ops        sync.Mutex
	speedSlots chan struct{}
}

func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, e error) {
	jsonReply(w, status, map[string]string{"error": e.Error()})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("expected one JSON document")
	}
	return nil
}
func (p *Panel) auth(r *http.Request) bool {
	if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		h := sha256.Sum256([]byte(token))
		return subtle.ConstantTimeCompare(h[:], p.admin[:]) == 1
	}
	cookie, e := r.Cookie("vpnsopr_session")
	if e != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	expires, ok := p.sessions[cookie.Value]
	if ok && time.Now().Before(expires) {
		return true
	}
	delete(p.sessions, cookie.Value)
	return false
}
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return e == nil && u.Host == r.Host && (u.Scheme == scheme || u.Scheme == "https")
}
func (p *Panel) handler() http.Handler {
	sub, _ := fs.Sub(webFiles, "web")
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if !sameOrigin(r) {
			fail(w, 403, errors.New("cross-origin request rejected"))
			return
		}
		if r.URL.Path == "/api/login" {
			p.login(w, r)
			return
		}
		if r.URL.Path == "/healthz" {
			jsonReply(w, 200, map[string]string{"status": "ok", "owner": "VPNSOPR"})
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			files.ServeHTTP(w, r)
			return
		}
		if !p.auth(r) {
			fail(w, 401, errors.New("authentication required"))
			return
		}
		if r.Method == "GET" {
			p.get(w, r)
			return
		}
		if r.Method != "POST" && r.Method != "PUT" {
			w.WriteHeader(405)
			return
		}
		p.mutate(w, r)
	})
}
func (p *Panel) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	p.mu.Lock()
	now := time.Now()
	b := p.attempts[ip]
	if now.Sub(b.since) > time.Minute {
		b = loginBucket{since: now}
	}
	b.count++
	if len(p.attempts) > 4096 {
		for k, v := range p.attempts {
			if now.Sub(v.since) > time.Minute {
				delete(p.attempts, k)
			}
		}
	}
	if len(p.attempts) >= 8192 {
		p.mu.Unlock()
		w.WriteHeader(429)
		return
	}
	p.attempts[ip] = b
	p.mu.Unlock()
	if b.count > 10 {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, errors.New("too many login attempts"))
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if e := decode(w, r, &body); e != nil {
		fail(w, 400, e)
		return
	}
	h := sha256.Sum256([]byte(body.Token))
	if subtle.ConstantTimeCompare(h[:], p.admin[:]) != 1 {
		fail(w, 401, errors.New("invalid token"))
		return
	}
	id := randomHex(32)
	p.mu.Lock()
	for k, v := range p.sessions {
		if now.After(v) {
			delete(p.sessions, k)
		}
	}
	if len(p.sessions) >= 128 {
		p.mu.Unlock()
		fail(w, 429, errors.New("session limit reached"))
		return
	}
	p.sessions[id] = now.Add(8 * time.Hour)
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "vpnsopr_session", Value: id, Path: "/", HttpOnly: true, Secure: p.secure || r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func (p *Panel) get(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/config", "/api/backup":
		if r.URL.Path == "/api/backup" {
			w.Header().Set("Content-Disposition", `attachment; filename="vpnsopr-backup.json"`)
		}
		jsonReply(w, 200, p.store.snapshot())
	case "/api/status":
		jsonReply(w, 200, map[string]any{"owner": "VPNSOPR", "core": p.core.status(), "tunnels": p.tunnels.status(), "adapters": p.adapters.status()})
	case "/api/catalog":
		jsonReply(w, 200, p.adapters.list())
	case "/api/links":
		jsonReply(w, 200, links(p.store.snapshot(), time.Now()))
	case "/api/core/export":
		w.Header().Set("Content-Disposition", `attachment; filename="xray.json"`)
		jsonReply(w, 200, buildCore(p.store.snapshot(), time.Now()))
	case "/api/speed/download":
		p.speedDownload(w, r)
	case "/api/ping":
		jsonReply(w, 200, map[string]int64{"time": time.Now().UnixMilli()})
	default:
		fail(w, 404, errors.New("not found"))
	}
}
func (p *Panel) mutate(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/speed/upload" {
		p.speedUpload(w, r)
		return
	}
	p.ops.Lock()
	defer p.ops.Unlock()
	var e error
	switch r.URL.Path {
	case "/api/logout":
		if cookie, ce := r.Cookie("vpnsopr_session"); ce == nil {
			p.mu.Lock()
			delete(p.sessions, cookie.Value)
			p.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "vpnsopr_session", Value: "", Path: "/", HttpOnly: true, Secure: p.secure || r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	case "/api/config":
		var cfg Config
		if e = decode(w, r, &cfg); e == nil {
			for name, v := range p.adapters.status() {
				status := v.(map[string]any)
				if status["running"] == true {
					found := false
					for _, a := range cfg.Adapters {
						if a.Name == name {
							found = true
						}
					}
					if !found {
						e = errors.New("stop running adapter before removing it: " + name)
						break
					}
				}
			}
			if e == nil {
				e = p.store.save(cfg)
			}
		}
	case "/api/user/new":
		var u struct {
			Name    string `json:"name"`
			Expires int64  `json:"expires"`
		}
		if e = decode(w, r, &u); e == nil {
			cfg := p.store.snapshot()
			cfg.Users = append(cfg.Users, User{ID: uuid(), Name: u.Name, Enabled: true, Expires: u.Expires})
			e = p.store.save(cfg)
		}
	case "/api/core/start":
		e = p.core.start(p.store.snapshot())
	case "/api/core/stop":
		p.core.stop()
	case "/api/tunnels/start":
		e = p.tunnels.start(p.store.snapshot().Tunnels)
	case "/api/tunnels/stop":
		p.tunnels.stop()
	case "/api/adapters/start", "/api/adapters/stop":
		var req struct {
			Name string `json:"name"`
		}
		if e = decode(w, r, &req); e == nil {
			found := false
			for _, a := range p.store.snapshot().Adapters {
				if a.Name == req.Name {
					found = true
					if r.URL.Path == "/api/adapters/start" {
						e = p.adapters.start(a)
					} else {
						p.adapters.stop(a.Name)
					}
					break
				}
			}
			if !found {
				e = errors.New("adapter not found")
			}
		}
	default:
		fail(w, 404, errors.New("not found"))
		return
	}
	if e != nil {
		fail(w, 400, e)
		return
	}
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func (p *Panel) speedDownload(w http.ResponseWriter, r *http.Request) {
	select {
	case p.speedSlots <- struct{}{}:
		defer func() { <-p.speedSlots }()
	default:
		fail(w, 429, errors.New("speed test busy"))
		return
	}
	n, e := strconv.Atoi(r.URL.Query().Get("bytes"))
	if e != nil || n < 1024 || n > 32<<20 {
		n = 8 << 20
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.Header().Set("Content-Encoding", "identity")
	b := make([]byte, 32768)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	for n > 0 {
		k := len(b)
		if k > n {
			k = n
		}
		if _, e = w.Write(b[:k]); e != nil {
			return
		}
		n -= k
	}
}
func (p *Panel) speedUpload(w http.ResponseWriter, r *http.Request) {
	select {
	case p.speedSlots <- struct{}{}:
		defer func() { <-p.speedSlots }()
	default:
		fail(w, 429, errors.New("speed test busy"))
		return
	}
	start := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	n, e := io.Copy(io.Discard, r.Body)
	if e != nil {
		fail(w, 413, e)
		return
	}
	jsonReply(w, 200, map[string]any{"bytes": n, "seconds": time.Since(start).Seconds()})
}
