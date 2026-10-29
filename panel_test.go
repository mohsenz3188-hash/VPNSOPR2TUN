package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func sampleConfig() Config {
	c := defaults()
	c.Domains = []Domain{{"vpn.example.com", "/cert.pem", "/key.pem"}}
	c.Users = []User{{ID: "12345678-1234-4234-8234-123456789012", Name: "one", Enabled: true}, {ID: "22345678-1234-4234-8234-123456789012", Name: "expired", Enabled: true, Expires: 1}, {ID: "32345678-1234-4234-8234-123456789012", Name: "disabled", Enabled: false}}
	c.Inbounds = []Inbound{{Tag: "vpn", Listen: "127.0.0.1", Port: 8443, Domain: "vpn.example.com", Path: "/vpnsopr", Outbound: "direct"}}
	return c
}
func TestCoreFiltersCredentialsAndRoutes(t *testing.T) {
	c := sampleConfig()
	if e := validate(c); e != nil {
		t.Fatal(e)
	}
	core := buildCore(c, time.Now())
	b, _ := json.Marshal(core)
	if strings.Contains(string(b), c.Users[1].ID) || strings.Contains(string(b), c.Users[2].ID) {
		t.Fatal("expired or disabled credentials leaked into core")
	}
	if !strings.Contains(string(b), c.Users[0].ID) {
		t.Fatal("active credential missing")
	}
	result := links(c, time.Now())
	if len(result) != 1 || !strings.Contains(result[0]["url"], "security=tls") || !strings.Contains(result[0]["url"], "path=%2Fvpnsopr") {
		t.Fatal(result)
	}
}
func TestInvalidConfigurationRejected(t *testing.T) {
	c := sampleConfig()
	c.Inbounds[0].Outbound = "missing"
	if validate(c) == nil {
		t.Fatal("unknown outbound accepted")
	}
	c = sampleConfig()
	c.Users = append(c.Users, c.Users[0])
	if validate(c) == nil {
		t.Fatal("duplicate UUID accepted")
	}
	c = sampleConfig()
	c.Adapters = []Adapter{{Name: "bad", Driver: "sh"}}
	if validate(c) == nil {
		t.Fatal("arbitrary driver accepted")
	}
}
func TestStoreDurabilityAndPermissions(t *testing.T) {
	dir := t.TempDir()
	s, e := openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	c := sampleConfig()
	c.Owner = "someone"
	if e = s.save(c); e != nil {
		t.Fatal(e)
	}
	loaded, e := openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	if loaded.snapshot().Owner != "VPNSOPR" {
		t.Fatal("owner not enforced")
	}
	f, e := os.Stat(filepath.Join(dir, "panel.json"))
	if e != nil || f.Mode().Perm() != 0600 {
		t.Fatal("config must be private", e)
	}
	copy := loaded.snapshot()
	copy.Users[0].Name = "mutated"
	if loaded.snapshot().Users[0].Name == "mutated" {
		t.Fatal("snapshot aliases mutable state")
	}
}
func testPanel(t *testing.T) *Panel {
	t.Helper()
	dir := t.TempDir()
	s, e := openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	return &Panel{store: s, core: &Core{dir: dir, binary: "/missing/xray"}, tunnels: &Tunnels{}, adapters: &Adapters{dir: dir, bins: map[string]string{}, runs: map[string]*adapterRun{}}, admin: sha256.Sum256([]byte(strings.Repeat("a", 32))), sessions: map[string]time.Time{}, attempts: map[string]loginBucket{}, speedSlots: make(chan struct{}, 2)}
}
func TestAuthAndCSRF(t *testing.T) {
	p := testPanel(t)
	h := p.handler()
	request := func(method, path, body, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "http://example.com/api/config", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := request("POST", "http://example.com/api/login", `{"token":"`+strings.Repeat("a", 32)+`"}`, "http://example.com", nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	if w = request("GET", "http://example.com/api/config", "", "", cookie); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = request("PUT", "http://example.com/api/config", `{}`, "https://evil.example", cookie); w.Code != 403 {
		t.Fatal("CSRF accepted", w.Code)
	}
	if w = request("POST", "http://example.com/api/logout", "", "", cookie); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = request("GET", "http://example.com/api/config", "", "", cookie); w.Code != 401 {
		t.Fatal("logout did not revoke session")
	}
}
func TestLoginRateLimitAndStrictJSON(t *testing.T) {
	p := testPanel(t)
	for i := 0; i < 11; i++ {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"token":"wrong"}`))
		w := httptest.NewRecorder()
		p.handler().ServeHTTP(w, r)
		if i == 10 && w.Code != 429 {
			t.Fatal("no login rate limit")
		}
	}
	r := httptest.NewRequest("POST", "/api/config", strings.NewReader(`{} {}`))
	var cfg Config
	if decode(httptest.NewRecorder(), r, &cfg) == nil {
		t.Fatal("trailing JSON accepted")
	}
}
func TestAdapterMustBeOperatorEnabled(t *testing.T) {
	p := testPanel(t)
	if e := p.adapters.start(Adapter{Name: "test", Driver: "chisel", Args: []string{"server"}}); e == nil {
		t.Fatal("unapproved binary launched")
	}
}
func TestSpeedAuthenticationAndPayload(t *testing.T) {
	p := testPanel(t)
	r := httptest.NewRequest("GET", "/api/speed/download?bytes=4096", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	w := httptest.NewRecorder()
	p.handler().ServeHTTP(w, r)
	if w.Code != 200 || w.Body.Len() != 4096 {
		t.Fatal(w.Code, w.Body.Len())
	}
}
func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if e != nil {
		t.Fatal(e)
	}
	key, e := x509.MarshalPKCS8PrivateKey(priv)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if e = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); e != nil {
		t.Fatal(e)
	}
	return cp, kp
}
func TestNativeTCPAndUDP(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			cert, key := testCertificate(t)
			var target string
			if proto == "tcp" {
				ln, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer ln.Close()
				target = ln.Addr().String()
				go func() {
					for {
						c, e := ln.Accept()
						if e != nil {
							return
						}
						go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
					}
				}()
			} else {
				pc, e := net.ListenPacket("udp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer pc.Close()
				target = pc.LocalAddr().String()
				go func() {
					b := make([]byte, 65535)
					for {
						n, a, e := pc.ReadFrom(b)
						if e != nil {
							return
						}
						_, _ = pc.WriteTo(b[:n], a)
					}
				}()
			}
			server, client := &Tunnels{}, &Tunnels{}
			defer server.stop()
			defer client.stop()
			token := strings.Repeat("t", 32)
			if e := server.start([]Tunnel{{Name: "s", Mode: "server", Protocol: proto, Listen: "127.0.0.1:0", Target: target, Token: token, Cert: cert, Key: key}}); e != nil {
				t.Fatal(e)
			}
			if e := client.start([]Tunnel{{Name: "c", Mode: "client", Protocol: proto, Listen: "127.0.0.1:0", Remote: server.runs[0].listener.Addr().String(), Token: token, ServerName: "localhost", CA: cert}}); e != nil {
				t.Fatal(e)
			}
			addr := ""
			if proto == "tcp" {
				addr = client.runs[0].listener.Addr().String()
			} else {
				addr = client.runs[0].packet.LocalAddr().String()
			}
			var wg sync.WaitGroup
			for i := 0; i < 3; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c, e := net.DialTimeout(proto, addr, 3*time.Second)
					if e != nil {
						t.Error(e)
						return
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					payload := bytes.Repeat([]byte("VPNSOPR"), 200)
					if _, e = c.Write(payload); e != nil {
						t.Error(e)
						return
					}
					reply := make([]byte, len(payload))
					if proto == "tcp" {
						_, e = io.ReadFull(c, reply)
					} else {
						var n int
						n, e = c.Read(reply)
						reply = reply[:n]
					}
					if e != nil || !bytes.Equal(payload, reply) {
						t.Error("tunnel data mismatch", e)
					}
				}()
			}
			wg.Wait()
		})
	}
}
func TestTunnelRejectsWrongToken(t *testing.T) {
	cert, key := testCertificate(t)
	s := &Tunnels{}
	defer s.stop()
	if e := s.start([]Tunnel{{Name: "server", Mode: "server", Listen: "127.0.0.1:0", Target: "127.0.0.1:1", Token: strings.Repeat("a", 32), Cert: cert, Key: key}}); e != nil {
		t.Fatal(e)
	}
	r, e := prepareTunnel(Tunnel{Name: "client", Mode: "client", ServerName: "localhost", CA: cert, Token: strings.Repeat("b", 32)})
	if e != nil {
		t.Fatal(e)
	}
	r.cfg.Remote = s.runs[0].listener.Addr().String()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if e = r.handle(a); e == nil {
		t.Fatal("wrong token accepted")
	}
}

func TestAdapterLifecycleAndLiteralArguments(t *testing.T) {
	binaryPath := "/bin/echo"
	if _, e := os.Stat(binaryPath); e != nil {
		t.Skip("echo fixture unavailable")
	}
	p := testPanel(t)
	p.adapters.bins["chisel"] = binaryPath
	sentinel := filepath.Join(t.TempDir(), "must-not-exist")
	literal := "hello; touch " + sentinel
	if e := p.adapters.start(Adapter{Name: "fixture", Driver: "chisel", Args: []string{literal}}); e != nil {
		t.Fatal(e)
	}
	p.adapters.mu.Lock()
	done := p.adapters.runs["fixture"].done
	p.adapters.mu.Unlock()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("adapter did not exit")
	}
	status := p.adapters.status()["fixture"].(map[string]any)
	if status["running"] != false || !strings.Contains(status["log"].(string), literal) {
		t.Fatal(status)
	}
	if _, e := os.Stat(sentinel); !os.IsNotExist(e) {
		t.Fatal("argument was interpreted as shell code")
	}
	t.Setenv("VPNSOPR_ADMIN_TOKEN", "private-panel-secret")
	for _, v := range childEnv(t.TempDir()) {
		if strings.Contains(v, "private-panel-secret") || strings.HasPrefix(v, "VPNSOPR_ADMIN_TOKEN=") {
			t.Fatal("admin credential passed to child")
		}
	}
}
