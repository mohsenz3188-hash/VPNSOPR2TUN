package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type Core struct {
	mu          sync.Mutex
	cmd         *exec.Cmd
	done        chan struct{}
	lastError   string
	dir, binary string
	fingerprint string
}

func (c *Core) status() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{"running": c.cmd != nil, "error": c.lastError}
}
func (c *Core) start(cfg Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != nil {
		return errors.New("core already running; stop it before applying configuration")
	}
	if len(cfg.Inbounds) == 0 {
		return errors.New("create at least one inbound first")
	}
	return c.launch(cfg)
}

// Caller holds mu. Xray validates configuration before any managed process is launched.
func (c *Core) launch(cfg Config) error {
	b, e := json.MarshalIndent(buildCore(cfg, time.Now()), "", "  ")
	if e != nil {
		return e
	}
	path := filepath.Join(c.dir, "xray.json")
	if e = atomicWrite(path, b); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	test := exec.CommandContext(ctx, c.binary, "run", "-test", "-config", path)
	// Limit diagnostics retained in memory even if a configured binary produces excessive output.
	output := &boundedLog{}
	test.Env = childEnv(c.dir)
	test.Stdout = output
	test.Stderr = output
	if e = test.Run(); e != nil {
		return fmt.Errorf("Xray config test failed: %v: %s", e, output.String())
	}
	logFile, e := os.OpenFile(filepath.Join(c.dir, "xray.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	cmd := exec.Command(c.binary, "run", "-config", path)
	cmd.Env = childEnv(c.dir)
	sink := &cappedFile{file: logFile, remaining: 10 << 20}
	cmd.Stdout = sink
	cmd.Stderr = sink
	if e = cmd.Start(); e != nil {
		_ = logFile.Close()
		return e
	}
	c.cmd = cmd
	c.done = make(chan struct{})
	c.lastError = ""
	c.fingerprint = string(b)
	done := c.done
	go func() {
		e := cmd.Wait()
		_ = logFile.Close()
		c.mu.Lock()
		if c.cmd == cmd {
			c.cmd = nil
			if e != nil {
				c.lastError = e.Error()
			}
		}
		close(done)
		c.mu.Unlock()
	}()
	return nil
}
func (c *Core) stop() {
	c.mu.Lock()
	cmd, done := c.cmd, c.done
	if cmd == nil {
		c.mu.Unlock()
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	c.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

// Expiration removes credentials from Xray within one minute, including existing connections on restart.
func (c *Core) expire(cfg Config) {
	b, _ := json.MarshalIndent(buildCore(cfg, time.Now()), "", "  ")
	c.mu.Lock()
	changed := c.cmd != nil && c.fingerprint != string(b)
	c.mu.Unlock()
	if !changed {
		return
	}
	c.stop()
	if e := c.start(cfg); e != nil {
		c.mu.Lock()
		c.lastError = e.Error()
		c.mu.Unlock()
	}
}

type boundedLog struct {
	mu sync.Mutex
	b  []byte
}

func (b *boundedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := 8192 - len(b.b)
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.b = append(b.b, p...)
	}
	return n, nil
}
func (b *boundedLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.b) }

// Cap each core run's diagnostic file at 10 MiB.
type cappedFile struct {
	mu        sync.Mutex
	file      *os.File
	remaining int
}

func (c *cappedFile) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	if c.remaining <= 0 {
		return n, nil
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	written, e := c.file.Write(p)
	c.remaining -= written
	if e != nil {
		return written, e
	}
	return n, nil
}
