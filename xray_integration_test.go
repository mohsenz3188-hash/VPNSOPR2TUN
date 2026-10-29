package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Optional end-to-end test against the operator-selected real Xray executable.
// No Internet destination is contacted: VLESS/WS/TLS exits to a local HTTP fixture.
func TestXrayVLESSRoundTrip(t *testing.T) {
	binaryPath := os.Getenv("VPNSOPR_TEST_XRAY")
	if binaryPath == "" {
		t.Skip("set VPNSOPR_TEST_XRAY to run real Xray integration")
	}
	cert, key := testCertificate(t)
	c := sampleConfig()
	c.Domains[0] = Domain{Name: "localhost", Cert: cert, Key: key}
	c.Inbounds[0].Domain = "localhost"
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	c.Inbounds[0].Port = port
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("target received HTTP", r.URL.String())
		_, _ = w.Write([]byte("VPNSOPR-XRAY-OK"))
	}))
	defer target.Close()
	_, targetPort, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	tp, _ := strconv.Atoi(targetPort)
	// Recent Xray releases block private destinations by default. Allow only this test fixture.
	c.Outbounds[0]["settings"] = map[string]any{"finalRules": []map[string]any{{"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": tp}}}
	core := &Core{dir: t.TempDir(), binary: binaryPath}
	if e = core.start(c); e != nil {
		t.Fatal(e)
	}
	defer core.stop()
	defer func() {
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(core.dir, "xray.log"))
			t.Log(string(b))
		}
	}()
	pemBytes, e := os.ReadFile(cert)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	tlsCfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	var conn *tls.Conn
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, e = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), tlsCfg)
		if e == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, e = io.WriteString(conn, "GET /vpnsopr HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	if e != nil {
		t.Fatal(e)
	}
	reader := bufio.NewReader(conn)
	resp, e := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if e != nil {
		t.Fatal(e)
	}
	if resp.StatusCode != 101 {
		t.Fatal("WebSocket upgrade", resp.Status)
	}
	id, e := hex.DecodeString(strings.ReplaceAll(c.Users[0].ID, "-", ""))
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte{0}
	payload = append(payload, id...)
	payload = append(payload, 0, 1, byte(tp>>8), byte(tp), 1, 127, 0, 0, 1)
	payload = append(payload, []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")...)
	frame := []byte{0x82}
	if len(payload) < 126 {
		frame = append(frame, 0x80|byte(len(payload)))
	} else {
		frame = append(frame, 0xfe, byte(len(payload)>>8), byte(len(payload)))
	}
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	if _, e = conn.Write(frame); e != nil {
		t.Fatal(e)
	}
	all := []byte{}
	for len(all) < 65536 {
		var head [2]byte
		if _, e = io.ReadFull(reader, head[:]); e != nil {
			t.Fatal("VLESS response", e, string(all))
		}
		size := uint64(head[1] & 127)
		if size == 126 {
			var b [2]byte
			if _, e = io.ReadFull(reader, b[:]); e != nil {
				t.Fatal(e)
			}
			size = uint64(binaryBigEndian(b[:]))
		} else if size == 127 {
			var b [8]byte
			if _, e = io.ReadFull(reader, b[:]); e != nil {
				t.Fatal(e)
			}
			size = binary.BigEndian.Uint64(b[:])
		}
		if size > 65536 {
			t.Fatal("oversized response")
		}
		data := make([]byte, int(size))
		if _, e = io.ReadFull(reader, data); e != nil {
			t.Fatal(e)
		}
		all = append(all, data...)
		if bytes.Contains(all, []byte("VPNSOPR-XRAY-OK")) {
			return
		}
	}
	t.Fatal("HTTP response marker missing")
}
func binaryBigEndian(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
