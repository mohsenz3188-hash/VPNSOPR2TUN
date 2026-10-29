package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Driver struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Repository string   `json:"repository"`
	Features   string   `json:"features"`
	Args       []string `json:"args"`
	Note       string   `json:"note"`
}

var catalog = []Driver{
	{"sing-box", "sing-box", "https://github.com/SagerNet/sing-box", "Multi-protocol proxy, TUN, QUIC protocols", []string{"run", "-c", "{config}"}, "Native JSON; TUN requires device access and routing setup."},
	{"xray", "Xray advanced", "https://github.com/XTLS/Xray-core", "VLESS, VMess, Trojan, Shadowsocks, REALITY, transports", []string{"run", "-config", "{config}"}, "Native full Xray JSON, independent of the simplified VPN builder."},
	{"v2ray", "V2Ray", "https://github.com/v2fly/v2ray-core", "Multi-protocol proxy and transports", []string{"run", "-c", "{config}"}, "Native configuration for your installed version."},
	{"wstunnel", "wstunnel", "https://github.com/erebe/wstunnel", "TCP/UDP over WebSocket, HTTP/2", []string{}, "Use native arguments. Require trusted TLS and access restrictions."},
	{"cloudflared", "Cloudflare Tunnel", "https://github.com/cloudflare/cloudflared", "HTTP, TCP via Cloudflare Tunnel", []string{"tunnel", "--config", "{config}", "run"}, "Requires your Cloudflare account, tunnel credentials, DNS and native YAML."},
	{"brook", "Brook", "https://github.com/txthinking/brook", "TCP, UDP, WS, WSS", []string{}, "Native argument array; configure password and verified TLS."},
	{"ssserver", "Shadowsocks server", "https://github.com/shadowsocks/shadowsocks-rust", "Encrypted TCP/UDP proxy", []string{"-c", "{config}"}, "Native JSON; choose a supported modern cipher and random password."},
	{"sslocal", "Shadowsocks client", "https://github.com/shadowsocks/shadowsocks-rust", "Encrypted TCP/UDP proxy", []string{"-c", "{config}"}, "Native JSON matching the server cipher and password."},
	{"openvpn", "OpenVPN", "https://github.com/OpenVPN/openvpn", "Layer 3 VPN over UDP/TCP", []string{"--config", "{config}"}, "Native .ovpn configuration. Requires TUN, PKI, routing and appropriate capabilities; keep foreground mode."},
	{"nebula", "Nebula", "https://github.com/slackhq/nebula", "Encrypted overlay mesh VPN", []string{"-config", "{config}"}, "Native YAML. Requires Nebula CA/host certificates, TUN and lighthouse setup."},

	{"frpc", "FRP client", "https://github.com/fatedier/frp", "TCP, UDP, reverse, QUIC, KCP, WebSocket", []string{"-c", "{config}"}, "Native FRP TOML; enable TLS and token authentication on both ends."},
	{"frps", "FRP server", "https://github.com/fatedier/frp", "TCP, UDP, reverse, QUIC, KCP, WebSocket", []string{"-c", "{config}"}, "Native FRP TOML; configure TLS certificate and token."},
	{"rathole", "Rathole", "https://github.com/rapiz1/rathole", "TCP, UDP, reverse, Noise/TLS", []string{"{config}"}, "Native TOML; choose server/client and configure transport encryption."},
	{"gost", "GOST v3", "https://github.com/go-gost/gost", "TCP, UDP, HTTP, SOCKS, TLS, WS, QUIC, SSH", []string{"-C", "{config}"}, "Native GOST configuration; features depend on installed version."},
	{"chisel", "Chisel", "https://github.com/jpillora/chisel", "TCP, UDP forwarding, HTTP/WebSocket, SSH, reverse", []string{}, "Use argument array; set authentication AND client server fingerprint or trusted TLS."},
	{"hysteria", "Hysteria 2", "https://github.com/HyNetworks/hysteria", "TCP/UDP over QUIC, SOCKS, HTTP", []string{"server", "-c", "{config}"}, "Native YAML; switch first argument to client on the client node."},
	{"backhaul", "Backhaul", "https://github.com/Musixal/Backhaul", "TCP, TCPMUX, UDP, WS, WSS, reverse", []string{"-c", "{config}"}, "Native TOML; use encrypted transport for sensitive traffic."},
	{"realm", "Realm", "https://github.com/zhboner/realm", "TCP, UDP, TLS, WS", []string{"-c", "{config}"}, "Native TOML; options depend on installed release/build."},
	{"bore", "Bore", "https://github.com/ekzhang/bore", "TCP reverse forwarding", []string{}, "Native argument array. Secret authenticates; use an encrypted application transport."},
	{"kcptun-client", "kcptun client", "https://github.com/xtaci/kcptun", "TCP over KCP/UDP", []string{"-c", "{config}"}, "Native JSON; set a unique key on both ends."},
	{"kcptun-server", "kcptun server", "https://github.com/xtaci/kcptun", "TCP over KCP/UDP", []string{"-c", "{config}"}, "Native JSON; choose cipher and key explicitly."},
	{"udp2raw", "udp2raw", "https://github.com/wangyu-/udp2raw", "UDP over FakeTCP, UDP, ICMP", []string{}, "Raw sockets/capabilities and firewall setup required; no privilege changes are made by the panel."},
	{"phantun-client", "Phantun client", "https://github.com/dndx/phantun", "UDP over FakeTCP", []string{}, "TUN and network setup required. Phantun itself does not provide VPN encryption."},
	{"phantun-server", "Phantun server", "https://github.com/dndx/phantun", "UDP over FakeTCP", []string{}, "TUN and network setup required. Pair with an encrypted VPN."},
	{"ssh", "OpenSSH", "https://github.com/openssh/openssh-portable", "TCP local/reverse/SOCKS forwarding", []string{"-N", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"}, "Preconfigure known_hosts and key authentication; append host and forwarding flags."},
}

type Adapter struct {
	Name   string   `json:"name"`
	Driver string   `json:"driver"`
	Args   []string `json:"args"`
	Config string   `json:"config"`
}

func driver(id string) (Driver, bool) {
	for _, d := range catalog {
		if d.ID == id {
			return d, true
		}
	}
	return Driver{}, false
}
func validateAdapters(items []Adapter) error {
	if len(items) > 64 {
		return errors.New("too many adapters")
	}
	seen := map[string]bool{}
	for _, a := range items {
		if _, ok := driver(a.Driver); !ok {
			return fmt.Errorf("unknown adapter driver: %s", a.Driver)
		}
		if !tagRE.MatchString(a.Name) || seen[a.Name] || len(a.Config) > 65536 || len(a.Args) > 64 {
			return errors.New("invalid adapter name, arguments or config size")
		}
		seen[a.Name] = true
		for _, arg := range a.Args {
			if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
				return errors.New("invalid argument")
			}
		}
	}
	return nil
}

type adapterRun struct {
	cmd       *exec.Cmd
	done      chan struct{}
	log       *boundedLog
	lastError string
}
type Adapters struct {
	mu   sync.Mutex
	bins map[string]string
	runs map[string]*adapterRun
	dir  string
}

func (a *Adapters) list() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []map[string]any{}
	for _, d := range catalog {
		path := a.bins[d.ID]
		installed := false
		if filepath.IsAbs(path) {
			if f, e := os.Stat(path); e == nil && !f.IsDir() && f.Mode()&0111 != 0 {
				installed = true
			}
		}
		out = append(out, map[string]any{"driver": d, "installed": installed})
	}
	return out
}
func (a *Adapters) status() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]any{}
	for n, r := range a.runs {
		out[n] = map[string]any{"running": r.cmd != nil, "error": r.lastError, "log": r.log.String()}
	}
	return out
}
func (a *Adapters) start(item Adapter) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r := a.runs[item.Name]; r != nil && r.cmd != nil {
		return errors.New("adapter already running")
	}
	binary := a.bins[item.Driver]
	if !filepath.IsAbs(binary) {
		return errors.New("driver not enabled: set its absolute executable path in VPNSOPR_ADAPTER_BINARIES")
	}
	path := filepath.Join(a.dir, "adapter-"+item.Name+".conf")
	if e := atomicWrite(path, []byte(item.Config)); e != nil {
		return e
	}
	args := append([]string{}, item.Args...)
	for i := range args {
		args[i] = strings.ReplaceAll(args[i], "{config}", path)
	}
	cmd := exec.Command(binary, args...)
	cmd.Dir = a.dir
	buf := &boundedLog{}
	cmd.Stdout = buf
	cmd.Stderr = buf
	// Do not pass the panel admin token or deployment credentials to adapters.
	cmd.Env = childEnv(a.dir)
	if e := cmd.Start(); e != nil {
		return e
	}
	r := &adapterRun{cmd: cmd, done: make(chan struct{}), log: buf}
	a.runs[item.Name] = r
	go func() {
		e := cmd.Wait()
		a.mu.Lock()
		r.cmd = nil
		if e != nil {
			r.lastError = e.Error()
		}
		close(r.done)
		a.mu.Unlock()
	}()
	return nil
}
func (a *Adapters) stop(name string) {
	a.mu.Lock()
	r := a.runs[name]
	if r == nil || r.cmd == nil {
		a.mu.Unlock()
		return
	}
	cmd, done := r.cmd, r.done
	_ = cmd.Process.Signal(os.Interrupt)
	a.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}
func (a *Adapters) stopAll() {
	a.mu.Lock()
	names := []string{}
	for name := range a.runs {
		names = append(names, name)
	}
	a.mu.Unlock()
	for _, n := range names {
		a.stop(n)
	}
}

func childEnv(dir string) []string {
	result := []string{"PATH=" + env("PATH", "/usr/bin:/bin"), "HOME=" + dir, "LANG=C.UTF-8"}
	for _, key := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "XRAY_LOCATION_ASSET"} {
		if v := os.Getenv(key); v != "" {
			result = append(result, key+"="+v)
		}
	}
	return result
}
