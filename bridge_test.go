package pcscid

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestBridgeHubRingAndBroadcast pins the hub contract: monotonic IDs,
// ring-buffer retention and replay-by-cursor for the polling fallback.
func TestBridgeHubRingAndBroadcast(t *testing.T) {
	t.Parallel()
	h := newBridgeHub(4)
	ch, cancel := h.subscribe()
	defer cancel()
	for range 6 {
		h.add("aaa-01", "card000001")
	}
	if len(h.since(0)) != 4 {
		t.Fatalf("ring buffer must retain 4 events, got %d", len(h.since(0)))
	}
	all := h.since(0)
	if all[0].ID != 3 || all[3].ID != 6 {
		t.Fatalf("replay must return the newest 4 events, got %+v", all)
	}
	if got := h.since(4); len(got) != 2 || got[0].ID != 5 {
		t.Fatalf("after=4 must return IDs 5 and 6, got %+v", got)
	}
	select {
	case ev := <-ch:
		if ev.ID != 1 {
			t.Fatalf("first broadcast must be ID 1, got %d", ev.ID)
		}
	default:
		t.Fatal("add must broadcast to subscribers")
	}
}

// TestBridgeDedupWindowAndGrace pins the Feed filter: events inside the
// startup grace window are dropped (Watch reports cards already present
// at its start, which must never serve HTTP after a service restart),
// and the same reader+card pair inside the dedup window is suppressed.
func TestBridgeDedupWindowAndGrace(t *testing.T) {
	t.Parallel()
	dd := newBridgeDedup(50*time.Millisecond, 10*time.Millisecond)
	if dd.allow("aaa-01", "card000001") {
		t.Fatal("startup grace must suppress the initial presence report")
	}
	time.Sleep(15 * time.Millisecond)
	if !dd.allow("aaa-01", "card000001") {
		t.Fatal("first event after the grace window must pass")
	}
	if dd.allow("aaa-01", "card000001") {
		t.Fatal("same reader+card inside the dedup window must be suppressed")
	}
	if !dd.allow("bbb-02", "card000001") {
		t.Fatal("a different reader must not be suppressed by the pair filter")
	}
	time.Sleep(60 * time.Millisecond)
	if !dd.allow("aaa-01", "card000001") {
		t.Fatal("the same pair must pass again after the window elapsed")
	}
}

// TestBridgeFeedDerivesTags pins the Feed wiring: insertions with a card
// become {ReaderTag, btag} events (the reader name hashed to its stable
// hardware tag, volatile hotplug indices stripped), removals and
// card-less events are ignored, and the BridgeOptions defaults are
// filled in.
func TestBridgeFeedDerivesTags(t *testing.T) {
	t.Parallel()
	// Zero grace via a positive override is not possible, so this test
	// feeds after constructing with an explicit zero-grace option set:
	// StartupGrace 1ns, so the grace window is over before the first
	// Feed.
	b := NewBridge(&BridgeOptions{Capacity: 8, StartupGrace: time.Nanosecond})
	time.Sleep(time.Millisecond)
	b.Feed(Event{Kind: KindInsert, Reader: "ACS ACR122U 01 00 00", Card: &Card{ID: "r3v-401-5gmr"}})
	b.Feed(Event{Kind: KindRemove, Reader: "ACS ACR122U 01 00 00"})
	b.Feed(Event{Kind: KindInsert, Reader: "REINER cyberJack 00 00"})
	got := b.hub.since(0)
	if len(got) != 1 {
		t.Fatalf("exactly one card event expected, got %+v", got)
	}
	if len(got[0].Reader) != 6 || !strings.Contains(got[0].Reader, "-") {
		t.Fatalf("reader must be a canonical xxx-xx tag, got %q", got[0].Reader)
	}
	if got[0].Card != "r3v-401-5gmr" {
		t.Fatalf("card btag must be forwarded unchanged, got %q", got[0].Card)
	}
}

// TestBridgeHealthAndPending exercises the polling surface of the
// Handler: /health answers the liveness probe, /pending replays events
// by cursor, both with permissive CORS headers for HTTPS kiosk pages.
func TestBridgeHealthAndPending(t *testing.T) {
	t.Parallel()
	b := NewBridge(&BridgeOptions{Capacity: 8, StartupGrace: time.Nanosecond})
	time.Sleep(time.Millisecond)
	b.Feed(Event{Kind: KindInsert, Reader: "aaa-01 00 00", Card: &Card{ID: "card000001"}})
	b.Feed(Event{Kind: KindInsert, Reader: "bbb-02 00 00", Card: &Card{ID: "card000002"}})
	srv := httptest.NewServer(b.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/pending?after=1")
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	defer resp.Body.Close()
	if ao := resp.Header.Get("Access-Control-Allow-Origin"); ao != "*" {
		t.Fatalf("pending must send CORS *, got %q", ao)
	}
	var body bridgePendingResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode pending: %v", err)
	}
	if len(body.Events) != 1 || body.Events[0].ID != 2 || body.Events[0].Card != "card000002" {
		t.Fatalf("after=1 must return exactly event 2, got %+v", body.Events)
	}

	resp, err = http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	defer resp.Body.Close()
	var health struct {
		OK      bool   `json:"ok"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if !health.OK {
		t.Fatal("health must report ok=true")
	}
}

// TestBridgeEventsStream verifies the SSE surface: the hello event on
// connect and a card event carrying the derived tags.
func TestBridgeEventsStream(t *testing.T) {
	t.Parallel()
	b := NewBridge(&BridgeOptions{Capacity: 8, StartupGrace: time.Nanosecond})
	srv := httptest.NewServer(b.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/events")
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q", ct)
	}
	if ao := resp.Header.Get("Access-Control-Allow-Origin"); ao != "*" {
		t.Fatalf("events must send CORS *, got %q", ao)
	}

	b.Feed(Event{Kind: KindInsert, Reader: "aaa-01 00 00", Card: &Card{ID: "card000001"}})
	sc := bufio.NewScanner(resp.Body)
	var joined strings.Builder
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sc.Scan() {
			joined.WriteString(sc.Text())
			joined.WriteByte('\n')
			if strings.Contains(joined.String(), "card000001") {
				break
			}
		} else {
			break
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan events stream: %v", err)
	}
	got := joined.String()
	if !strings.Contains(got, "event: hello") {
		t.Fatalf("stream must start with the hello event, got %q", got)
	}
	if !strings.Contains(got, "event: card") || !strings.Contains(got, "card000001") {
		t.Fatalf("stream must carry the card event, got %q", got)
	}
}

// TestBridgeServeShutdown pins the Serve lifecycle: the surface answers
// while the context lives and cancelling it shuts the listener down
// gracefully, Serve returns nil.
func TestBridgeServeShutdown(t *testing.T) {
	t.Parallel()
	// Grab a free loopback port, then hand it to Serve.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	b := NewBridge(nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.Serve(ctx, addr) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/health")
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve must return nil on cancel, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve must return after the context is cancelled")
	}
}

// TestRequireLoopback pins the deployment guard: without allowRemote only
// loopback listeners are accepted, so card identities can never leave the
// kiosk by accident.
func TestRequireLoopback(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{"127.0.0.1:8976", "localhost:8976", "[::1]:8976"} {
		if err := RequireLoopback(addr, false); err != nil {
			t.Errorf("%q must be allowed, got %v", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:8976", "192.168.1.5:8976", "kiosk.example.com:8976", "bad"} {
		if err := RequireLoopback(addr, false); err == nil {
			t.Errorf("%q must be rejected without allowRemote", addr)
		}
	}
	if err := RequireLoopback("0.0.0.0:8976", true); err != nil {
		t.Errorf("explicit allowRemote must lift the guard, got %v", err)
	}
}
