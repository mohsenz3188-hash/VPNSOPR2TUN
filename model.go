package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type User struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Expires int64  `json:"expires"`
}
type Domain struct {
	Name string `json:"name"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}
type Inbound struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Outbound string `json:"outbound"`
}
type Tunnel struct {
	Name       string `json:"name"`
	Mode       string `json:"mode"`
	Protocol   string `json:"protocol"`
	Listen     string `json:"listen"`
	Remote     string `json:"remote"`
	Target     string `json:"target"`
	Token      string `json:"token"`
	ServerName string `json:"serverName"`
	CA         string `json:"ca"`
	Cert       string `json:"cert"`
	Key        string `json:"key"`
}
type Config struct {
	Owner     string           `json:"owner"`
	Domains   []Domain         `json:"domains"`
	Users     []User           `json:"users"`
	Inbounds  []Inbound        `json:"inbounds"`
	Outbounds []map[string]any `json:"outbounds"`
	Tunnels   []Tunnel         `json:"tunnels"`
	Adapters  []Adapter        `json:"adapters"`
}
type Store struct {
	mu  sync.RWMutex
	cfg Config
	dir string
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func uuid() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func defaults() Config {
	return Config{Owner: "VPNSOPR", Domains: []Domain{}, Users: []User{}, Inbounds: []Inbound{}, Outbounds: []map[string]any{{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}}, Tunnels: []Tunnel{}, Adapters: []Adapter{}}
}
func openStore(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if e := os.Chmod(dir, 0700); e != nil {
		return nil, e
	}
	s := &Store{dir: dir, cfg: defaults()}
	b, e := os.ReadFile(filepath.Join(dir, "panel.json"))
	if e == nil {
		e = json.Unmarshal(b, &s.cfg)
		if e == nil {
			e = validate(s.cfg)
		}
	}
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	return s, nil
}
func (s *Store) snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(s.cfg)
	var c Config
	_ = json.Unmarshal(b, &c)
	return c
}
func (s *Store) save(c Config) error {
	c.Owner = "VPNSOPR"
	if e := validate(c); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	if e = atomicWrite(filepath.Join(s.dir, "panel.json"), b); e != nil {
		return e
	}
	s.cfg = c
	return nil
}
func atomicWrite(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".vpnsopr-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), path)
}

var tagRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var domainRE = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

func hostport(s string) bool {
	h, p, e := net.SplitHostPort(s)
	n, pe := strconv.Atoi(p)
	return e == nil && pe == nil && h != "" && n > 0 && n < 65536
}
func validate(c Config) error {
	if e := validateAdapters(c.Adapters); e != nil {
		return e
	}
	if len(c.Users) > 5000 || len(c.Inbounds) > 128 || len(c.Tunnels) > 64 || len(c.Outbounds) > 128 {
		return errors.New("configuration limit exceeded")
	}
	domains := map[string]bool{}
	for _, d := range c.Domains {
		if !domainRE.MatchString(d.Name) || strings.Contains(d.Name, "..") || d.Cert == "" || d.Key == "" || domains[d.Name] {
			return errors.New("invalid or duplicate domain / missing certificate paths")
		}
		domains[d.Name] = true
	}
	users := map[string]bool{}
	for _, u := range c.Users {
		if !uuidRE.MatchString(u.ID) || users[u.ID] || len(u.Name) < 1 || len(u.Name) > 100 || u.Expires < 0 {
			return errors.New("invalid or duplicate user")
		}
		users[u.ID] = true
	}
	tags := map[string]bool{}
	out := map[string]bool{}
	for _, o := range c.Outbounds {
		t, _ := o["tag"].(string)
		p, _ := o["protocol"].(string)
		if !tagRE.MatchString(t) || tags[t] || p == "" {
			return errors.New("outbounds require unique tag and protocol")
		}
		tags[t] = true
		out[t] = true
	}
	if len(out) == 0 {
		return errors.New("at least one outbound required")
	}
	ports := map[string]bool{}
	for _, i := range c.Inbounds {
		key := net.JoinHostPort(i.Listen, strconv.Itoa(i.Port))
		if !tagRE.MatchString(i.Tag) || tags[i.Tag] || net.ParseIP(i.Listen) == nil || i.Port < 1 || i.Port > 65535 || !domains[i.Domain] || !out[i.Outbound] || !strings.HasPrefix(i.Path, "/") || strings.ContainsAny(i.Path, "\r\n?#") || ports[key] {
			return errors.New("invalid inbound: tag, address, port, domain, path or outbound")
		}
		tags[i.Tag] = true
		ports[key] = true
	}
	names := map[string]bool{}
	for _, t := range c.Tunnels {
		if !tagRE.MatchString(t.Name) || names[t.Name] || !hostport(t.Listen) || len(t.Token) < 32 || len(t.Token) > 256 || strings.ContainsAny(t.Token, "\r\n") {
			return errors.New("invalid tunnel name, listener or token (32–256 characters)")
		}
		if t.Protocol != "" && t.Protocol != "tcp" && t.Protocol != "udp" {
			return errors.New("native tunnel protocol must be tcp or udp")
		}
		names[t.Name] = true
		if ports[t.Listen] {
			return errors.New("duplicate listener")
		}
		ports[t.Listen] = true
		switch t.Mode {
		case "server":
			if !hostport(t.Target) || t.Cert == "" || t.Key == "" {
				return errors.New("server tunnel needs target and TLS certificate")
			}
		case "client":
			if !hostport(t.Remote) || t.ServerName == "" {
				return errors.New("client tunnel needs remote and TLS serverName")
			}
		default:
			return errors.New("tunnel mode must be server or client")
		}
	}
	return nil
}
func buildCore(c Config, now time.Time) map[string]any {
	users := []map[string]any{}
	for _, u := range c.Users {
		if u.Enabled && (u.Expires == 0 || u.Expires > now.Unix()) {
			users = append(users, map[string]any{"id": u.ID, "email": u.ID + "@vpnsopr.local", "level": 0})
		}
	}
	ins := []map[string]any{}
	rules := []map[string]any{}
	for _, i := range c.Inbounds {
		var d Domain
		for _, v := range c.Domains {
			if v.Name == i.Domain {
				d = v
			}
		}
		ins = append(ins, map[string]any{"tag": i.Tag, "listen": i.Listen, "port": i.Port, "protocol": "vless", "settings": map[string]any{"users": users, "decryption": "none"}, "streamSettings": map[string]any{"network": "ws", "security": "tls", "tlsSettings": map[string]any{"minVersion": "1.2", "certificates": []map[string]string{{"certificateFile": d.Cert, "keyFile": d.Key}}}, "wsSettings": map[string]any{"path": i.Path}}})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{i.Tag}, "outboundTag": i.Outbound})
	}
	return map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": ins, "outbounds": c.Outbounds, "routing": map[string]any{"domainStrategy": "AsIs", "rules": rules}}
}
func links(c Config, now time.Time) []map[string]string {
	result := []map[string]string{}
	for _, u := range c.Users {
		if !u.Enabled || (u.Expires > 0 && u.Expires <= now.Unix()) {
			continue
		}
		for _, i := range c.Inbounds {
			q := url.Values{"encryption": {"none"}, "security": {"tls"}, "type": {"ws"}, "sni": {i.Domain}, "host": {i.Domain}, "path": {i.Path}}
			link := url.URL{Scheme: "vless", User: url.User(u.ID), Host: net.JoinHostPort(i.Domain, strconv.Itoa(i.Port)), RawQuery: q.Encode(), Fragment: "VPNSOPR-" + u.Name + "-" + i.Tag}
			result = append(result, map[string]string{"name": u.Name, "inbound": i.Tag, "url": link.String()})
		}
	}
	return result
}
