// The writer half of the observation record. The page server lives in the other
// binary and reads every observed-*.jsonl in the shared directory, the same way
// pinned leaf hashes already travel between these processes.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	kindQUIC     = "quic"
	kindConnect  = "connect"
	kindSession  = "session"
	kindRefused  = "refused"
	kindDeclined = "declined"
	kindClosed   = "closed"
)

type observation struct {
	At     time.Time `json:"t"`
	Addr   string    `json:"a"`
	Port   int       `json:"port"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail,omitempty"`
}

type observer struct {
	mu   sync.Mutex
	path string
	size int64
}

const observationCeiling = 1 << 20

var watch *observer

func newObserver(dir, label string) *observer {
	path := filepath.Join(dir, fmt.Sprintf("observed-%s.jsonl", label))
	os.Remove(path)
	return &observer{path: path}
}

func (o *observer) record(address string, port int, kind, detail string) {
	if o == nil {
		return
	}
	line, err := json.Marshal(observation{
		At: time.Now().UTC(), Addr: address, Port: port, Kind: kind, Detail: detail,
	})
	if err != nil {
		return
	}
	line = append(line, '\n')

	o.mu.Lock()
	defer o.mu.Unlock()
	if o.size+int64(len(line)) > observationCeiling {
		os.Remove(o.path)
		o.size = 0
	}
	file, err := os.OpenFile(o.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	if n, err := file.Write(line); err == nil {
		o.size += int64(n)
	}
}

func closeReason(ctx context.Context) string {
	if cause := context.Cause(ctx); cause != nil {
		return cause.Error()
	}
	return ""
}

// must agree with the page server's spelling of the same address, or a session
// recorded here will not be found by the client that opened it
func normalizeAddress(address string) string {
	ip := net.ParseIP(address)
	if ip == nil {
		return address
	}
	if ip.IsLoopback() {
		return "127.0.0.1"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
