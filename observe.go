// A failed WebTransport handshake reaches a web developer as one
// WebTransportError with an empty message — on every engine, for every cause.
// The server watched the whole exchange, so each listener writes down where it
// stopped and the page reads that back for the address asking.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// the kinds, in the order a healthy session produces them. the gap between
// kindQUIC and kindConnect is the whole diagnostic: a client that completes
// QUIC, reads the server's SETTINGS and then leaves without asking for a
// session has rejected the handshake on what it was offered
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

// one file per process rather than a shared append target, so two listeners
// writing at the same moment cannot interleave a line
type observer struct {
	mu   sync.Mutex
	path string
	size int64
}

// a rolling window for a diagnostic page, not a log
const observationCeiling = 1 << 20

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

// what the page is handed. the address keys the file and is never sent back:
// the caller supplied it by asking
type observedEvent struct {
	At     time.Time `json:"t"`
	Port   int       `json:"port"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail,omitempty"`
}

// readObservations collects what every listener in this deployment saw from one
// address inside the window, oldest first.
func readObservations(dir, address string, window time.Duration) []observedEvent {
	paths, _ := filepath.Glob(filepath.Join(dir, "observed-*.jsonl"))
	cutoff := time.Now().UTC().Add(-window)

	var found []observation
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" {
				continue
			}
			var event observation
			if json.Unmarshal([]byte(line), &event) != nil {
				continue
			}
			if event.Addr != address || event.At.Before(cutoff) {
				continue
			}
			found = append(found, event)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].At.Before(found[j].At) })

	events := make([]observedEvent, 0, len(found))
	for _, event := range found {
		events = append(events, observedEvent{At: event.At, Port: event.Port, Kind: event.Kind, Detail: event.Detail})
	}
	return events
}

// closeReason names why a QUIC connection went away. an empty-reason 0x100 from
// the peer is the shape a refusal leaves behind.
func closeReason(ctx context.Context) string {
	if cause := context.Cause(ctx); cause != nil {
		return cause.Error()
	}
	return ""
}

// behind Fly's TCP proxy the page server sees the proxy while the UDP listeners
// see the real client, so the two only line up if the header wins
func clientAddress(r *http.Request) string {
	if ip := r.Header.Get("Fly-Client-IP"); ip != "" {
		return normalizeAddress(ip)
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return normalizeAddress(strings.TrimSpace(strings.Split(forwarded, ",")[0]))
	}
	return addressOf(r.RemoteAddr)
}

// the page arrives over TCP and the sessions over UDP, which on a dual-stack
// host can reach the same machine by different spellings of one address. this
// settles the two that actually collide in practice — loopback, and the
// v4-mapped form — and leaves anything else alone
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
