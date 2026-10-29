package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const idleTimeout = 5 * time.Minute

var buffers = sync.Pool{New: func() any { return make([]byte, 32*1024) }}

type tunnelRun struct {
	cfg       Tunnel
	listener  net.Listener
	packet    net.PacketConn
	mu        sync.Mutex
	peers     map[net.Conn]bool
	stopped   bool
	slots     chan struct{}
	up        atomic.Int64
	down      atomic.Int64
	active    atomic.Int64
	failures  atomic.Int64
	tlsConfig *tls.Config
}
type Tunnels struct {
	mu   sync.Mutex
	runs []*tunnelRun
}

func prepareTunnel(c Tunnel) (*tunnelRun, error) {
	r := &tunnelRun{cfg: c, peers: map[net.Conn]bool{}, slots: make(chan struct{}, 128)}
	r.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	if c.Mode == "server" {
		cert, e := tls.LoadX509KeyPair(c.Cert, c.Key)
		if e != nil {
			return nil, e
		}
		r.tlsConfig.Certificates = []tls.Certificate{cert}
	} else {
		r.tlsConfig.ServerName = c.ServerName
		if c.CA != "" {
			b, e := os.ReadFile(c.CA)
			if e != nil {
				return nil, e
			}
			pool, e := x509.SystemCertPool()
			if e != nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(b) {
				return nil, errors.New("invalid CA PEM")
			}
			r.tlsConfig.RootCAs = pool
		}
	}
	return r, nil
}
func (m *Tunnels) start(cfg []Tunnel) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.runs) > 0 {
		return errors.New("stop tunnels before applying new settings")
	}
	pending := []*tunnelRun{}
	for _, c := range cfg {
		r, e := prepareTunnel(c)
		if e != nil {
			return fmt.Errorf("%s: %w", c.Name, e)
		}
		pending = append(pending, r)
	}
	for _, r := range pending {
		var e error
		if r.cfg.Mode == "server" {
			r.listener, e = tls.Listen("tcp", r.cfg.Listen, r.tlsConfig)
		} else {
			if r.cfg.Protocol == "udp" {
				r.packet, e = net.ListenPacket("udp", r.cfg.Listen)
			} else {
				r.listener, e = net.Listen("tcp", r.cfg.Listen)
			}
		}
		if e != nil {
			for _, p := range pending {
				if p.listener != nil {
					_ = p.listener.Close()
				}
				if p.packet != nil {
					_ = p.packet.Close()
				}
			}
			return e
		}
	}
	m.runs = pending
	for _, r := range pending {
		if r.packet != nil {
			go r.acceptUDP()
		} else {
			go r.accept()
		}
	}
	return nil
}
func (m *Tunnels) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.runs {
		r.mu.Lock()
		r.stopped = true
		if r.listener != nil {
			_ = r.listener.Close()
		}
		if r.packet != nil {
			_ = r.packet.Close()
		}
		for c := range r.peers {
			_ = c.Close()
		}
		r.mu.Unlock()
	}
	m.runs = nil
}
func (m *Tunnels) status() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []map[string]any{}
	for _, r := range m.runs {
		out = append(out, map[string]any{"name": r.cfg.Name, "mode": r.cfg.Mode, "active": r.active.Load(), "up": r.up.Load(), "down": r.down.Load(), "failures": r.failures.Load()})
	}
	return out
}
func (r *tunnelRun) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		_ = c.Close()
		return false
	}
	r.peers[c] = true
	return true
}
func (r *tunnelRun) untrack(c net.Conn) {
	_ = c.Close()
	r.mu.Lock()
	delete(r.peers, c)
	r.mu.Unlock()
}
func (r *tunnelRun) accept() {
	for {
		c, e := r.listener.Accept()
		if e != nil {
			return
		}
		select {
		case r.slots <- struct{}{}:
			if !r.track(c) {
				<-r.slots
				return
			}
			go func() {
				defer func() { <-r.slots; r.untrack(c) }()
				r.active.Add(1)
				defer r.active.Add(-1)
				if e := r.handle(c); e != nil {
					r.failures.Add(1)
				}
			}()
		default:
			_ = c.Close()
			r.failures.Add(1)
		}
	}
}
func (r *tunnelRun) handle(c net.Conn) error {
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	var peer net.Conn
	var e error
	secret := sha256.Sum256([]byte(r.cfg.Token))
	if r.cfg.Mode == "server" {
		tc := c.(*tls.Conn)
		if e = tc.Handshake(); e != nil {
			return e
		}
		var supplied [32]byte
		if _, e = io.ReadFull(c, supplied[:]); e != nil {
			return e
		}
		if subtle.ConstantTimeCompare(supplied[:], secret[:]) != 1 {
			return errors.New("authentication failed")
		}
		network := "tcp"
		if r.cfg.Protocol == "udp" {
			network = "udp"
		}
		peer, e = net.DialTimeout(network, r.cfg.Target, 10*time.Second)
		if e != nil {
			return e
		}
		if !r.track(peer) {
			return net.ErrClosed
		}
		defer r.untrack(peer)
		if _, e = c.Write([]byte{1}); e != nil {
			return e
		}
	} else {
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		peer, e = tls.DialWithDialer(d, "tcp", r.cfg.Remote, r.tlsConfig)
		if e != nil {
			return e
		}
		if !r.track(peer) {
			return net.ErrClosed
		}
		defer r.untrack(peer)
		_ = peer.SetDeadline(time.Now().Add(15 * time.Second))
		if _, e = peer.Write(secret[:]); e != nil {
			return e
		}
		var ack [1]byte
		if _, e = io.ReadFull(peer, ack[:]); e != nil {
			return e
		}
		if ack[0] != 1 {
			return errors.New("invalid acknowledgement")
		}
	}
	_ = c.SetDeadline(time.Time{})
	_ = peer.SetDeadline(time.Time{})
	if r.cfg.Protocol == "udp" {
		r.udpServer(c, peer)
	} else {
		relay(c, peer, &r.up, &r.down)
	}
	return nil
}

type idleReader struct {
	net.Conn
	counter *atomic.Int64
}

func (c idleReader) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(idleTimeout))
	n, e := c.Conn.Read(p)
	c.counter.Add(int64(n))
	return n, e
}

type idleWriter struct{ net.Conn }

func (c idleWriter) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(idleTimeout))
	return c.Conn.Write(p)
}
func pump(dst, src net.Conn, counter *atomic.Int64) {
	b := buffers.Get().([]byte)
	defer buffers.Put(b)
	_, e := io.CopyBuffer(idleWriter{dst}, idleReader{Conn: src, counter: counter}, b)
	if e != nil {
		_ = dst.Close()
		_ = src.Close()
		return
	}
	if v, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = v.CloseWrite()
	} else {
		_ = dst.Close()
	}
}
func relay(a, b net.Conn, up, down *atomic.Int64) {
	done := make(chan struct{})
	go func() { pump(b, a, up); close(done) }()
	pump(a, b, down)
	<-done
}
