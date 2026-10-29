package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func main() {
	addr := flag.String("listen", env("VPNSOPR_LISTEN", "127.0.0.1:8080"), "panel listener")
	dir := flag.String("data", env("VPNSOPR_DATA", "./data"), "private configuration directory")
	gen := flag.Bool("generate-token", false, "print a new random admin/tunnel token and exit")
	flag.Parse()
	if *gen {
		log.SetFlags(0)
		_, _ = os.Stdout.WriteString(randomHex(32) + "\n")
		return
	}
	token := os.Getenv("VPNSOPR_ADMIN_TOKEN")
	if len(token) < 32 {
		log.Fatal("set VPNSOPR_ADMIN_TOKEN to a random value of at least 32 characters")
	}
	cert, key := os.Getenv("VPNSOPR_PANEL_CERT"), os.Getenv("VPNSOPR_PANEL_KEY")
	proxyHTTPS := os.Getenv("VPNSOPR_PUBLIC_HTTPS") == "1"
	host, _, e := net.SplitHostPort(*addr)
	if e != nil {
		log.Fatal(e)
	}
	ip := net.ParseIP(host)
	if (ip == nil || !ip.IsLoopback()) && cert == "" && !proxyHTTPS {
		log.Fatal("public panel requires TLS certificate or VPNSOPR_PUBLIC_HTTPS=1 behind a trusted HTTPS reverse proxy")
	}
	if (cert == "") != (key == "") {
		log.Fatal("panel certificate and key must be set together")
	}
	abs, e := filepath.Abs(*dir)
	if e != nil {
		log.Fatal(e)
	}
	store, e := openStore(abs)
	if e != nil {
		log.Fatal(e)
	}
	bins := map[string]string{}
	if raw := os.Getenv("VPNSOPR_ADAPTER_BINARIES"); raw != "" {
		if e = json.Unmarshal([]byte(raw), &bins); e != nil {
			log.Fatal("invalid adapter binary map: ", e)
		}
	}
	p := &Panel{store: store, core: &Core{dir: abs, binary: env("VPNSOPR_XRAY", "xray")}, tunnels: &Tunnels{}, adapters: &Adapters{dir: abs, bins: bins, runs: map[string]*adapterRun{}}, admin: sha256.Sum256([]byte(token)), secure: proxyHTTPS || cert != "", sessions: map[string]time.Time{}, attempts: map[string]loginBucket{}, speedSlots: make(chan struct{}, 2)}
	srv := &http.Server{Addr: *addr, Handler: p.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var jobs sync.WaitGroup
	jobs.Add(1)
	go func() {
		defer jobs.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.ops.Lock()
				p.core.expire(store.snapshot())
				p.ops.Unlock()
			}
		}
	}()
	go func() {
		log.Printf("VPNSOPR panel on %s (owner VPNSOPR)", *addr)
		var se error
		if cert != "" {
			se = srv.ListenAndServeTLS(cert, key)
		} else {
			se = srv.ListenAndServe()
		}
		if se != nil && se != http.ErrServerClosed {
			log.Print(se)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	jobs.Wait()
	p.ops.Lock()
	p.core.stop()
	p.tunnels.stop()
	p.adapters.stopAll()
	p.ops.Unlock()
}
