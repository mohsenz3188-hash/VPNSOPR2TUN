package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const maxDatagram = 65507

func readFrame(c net.Conn, b []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return 0, e
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > len(b) {
		return 0, errors.New("oversize datagram")
	}
	_, e := io.ReadFull(c, b[:n])
	return n, e
}
func writeFrame(c net.Conn, b []byte) error {
	if len(b) > maxDatagram {
		return errors.New("oversize datagram")
	}
	_ = c.SetWriteDeadline(time.Now().Add(idleTimeout))
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(b)))
	if _, e := c.Write(h[:]); e != nil {
		return e
	}
	for len(b) > 0 {
		n, e := c.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func (r *tunnelRun) udpServer(stream, target net.Conn) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer stream.Close()
		defer target.Close()
		b := make([]byte, maxDatagram)
		for {
			n, e := readFrame(stream, b)
			if e != nil {
				return
			}
			_ = target.SetWriteDeadline(time.Now().Add(idleTimeout))
			if _, e = target.Write(b[:n]); e != nil {
				return
			}
			r.up.Add(int64(n))
		}
	}()
	b := make([]byte, maxDatagram)
	for {
		_ = target.SetReadDeadline(time.Now().Add(idleTimeout))
		n, e := target.Read(b)
		if e != nil {
			break
		}
		if e = writeFrame(stream, b[:n]); e != nil {
			break
		}
		r.down.Add(int64(n))
	}
	_ = target.Close()
	_ = stream.Close()
	<-done
}

type udpSession struct {
	queue chan []byte
	done  chan struct{}
}

func (r *tunnelRun) acceptUDP() {
	var mu sync.Mutex
	sessions := map[string]*udpSession{}
	b := make([]byte, maxDatagram+1)
	for {
		n, addr, e := r.packet.ReadFrom(b)
		if e != nil {
			return
		}
		if n > maxDatagram {
			r.failures.Add(1)
			continue
		}
		key := addr.String()
		mu.Lock()
		s := sessions[key]
		if s == nil {
			if len(sessions) >= 128 {
				mu.Unlock()
				r.failures.Add(1)
				continue
			}
			s = &udpSession{queue: make(chan []byte, 8), done: make(chan struct{})}
			sessions[key] = s
			go func(s *udpSession, addr net.Addr, key string) {
				r.active.Add(1)
				defer r.active.Add(-1)
				defer func() { mu.Lock(); delete(sessions, key); close(s.done); mu.Unlock() }()
				if e := r.udpClient(addr, s); e != nil {
					r.failures.Add(1)
				}
			}(s, addr, key)
		}
		select {
		case s.queue <- append([]byte{}, b[:n]...):
		default:
			r.failures.Add(1)
		}
		mu.Unlock()
	}
}
func (r *tunnelRun) udpClient(addr net.Addr, s *udpSession) error {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	c, e := tls.DialWithDialer(d, "tcp", r.cfg.Remote, r.tlsConfig)
	if e != nil {
		return e
	}
	if !r.track(c) {
		return net.ErrClosed
	}
	defer r.untrack(c)
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	secret := sha256.Sum256([]byte(r.cfg.Token))
	if _, e = c.Write(secret[:]); e != nil {
		return e
	}
	var ack [1]byte
	if _, e = io.ReadFull(c, ack[:]); e != nil {
		return e
	}
	if ack[0] != 1 {
		return errors.New("invalid acknowledgement")
	}
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c.Close()
		b := make([]byte, maxDatagram)
		for {
			n, e := readFrame(c, b)
			if e != nil {
				return
			}
			if _, e = r.packet.WriteTo(b[:n], addr); e != nil {
				return
			}
			r.down.Add(int64(n))
		}
	}()
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-timer.C:
			_ = c.Close()
			<-done
			return nil
		case b := <-s.queue:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idleTimeout)
			if e = writeFrame(c, b); e != nil {
				_ = c.Close()
				<-done
				return e
			}
			r.up.Add(int64(len(b)))
		}
	}
}
