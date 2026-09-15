// Bridge: loopback HTTP for browser pages.
//
// A browser sandbox cannot reach the pcscd Unix socket, neither WebAssembly
// nor page JavaScript may open one, and Firefox implements neither WebUSB
// nor WebHID. A Bridge fans the pcscid watch events out to such pages: it
// serves every card presentation's stable hardware identities — the reader
// tag (ReaderTag, "xx-xxxx-xx") and the card btag (Btag, "xxx-xxx-xxxx") — on
// a small CORS-permissive HTTP surface made for a loopback listener:
//
//	GET /health           → {"ok":true,"version":...} liveness probe
//	GET /events           → SSE stream (hello + one card event per scan)
//	GET /pending?after=N  → JSON {events:[...]} polling fallback by cursor
//
// Loopback is a potentially trustworthy origin, so a page served over
// HTTPS may read the plain http://127.0.0.1:PORT answers without mixed
// content trouble. RequireLoopback guards the default deployment posture:
// card identities must never leave the kiosk by accident. The permissive
// CORS is a deliberate trade-off for kiosk pages from any HTTPS origin:
// it also means every page open in a browser on the kiosk itself can
// read the stream, the bridge must only ever run on a locked-down
// terminal.

package pcscid

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// BridgeDefaults are applied for every zero BridgeOptions field.
const (
	// bridgeCapacity is how many presentations the /pending ring retains.
	bridgeCapacity = 64
	// bridgeDedupWindow suppresses the same reader+card pair for this
	// long, against the repeated insert events a card lying on a reader
	// can produce.
	bridgeDedupWindow = 3 * time.Second
	// bridgeStartupGrace suppresses events this close to NewBridge, so
	// the "cards already present" report of Watch never triggers an
	// HTTP event after a service restart with a card left on a reader.
	bridgeStartupGrace = 2 * time.Second
	// bridgeDedupMax bounds the dedup memory: beyond that many distinct
	// reader+card pairs the stale entries are pruned, so a kiosk serving
	// many different cards for weeks cannot leak.
	bridgeDedupMax = 1024
	// bridgeReadHeaderTimeout bounds an HTTP request head, a guard
	// against slowloris style stalls of the single bridge listener.
	bridgeReadHeaderTimeout = 10 * time.Second
)

// BridgeOptions tunes NewBridge. A nil *BridgeOptions selects every
// default.
type BridgeOptions struct {
	// Capacity is how many presentations the /pending ring retains,
	// default 64.
	Capacity int
	// DedupWindow is how long the same reader+card pair is suppressed
	// after one presentation, default 3s.
	DedupWindow time.Duration
	// StartupGrace is how long every event is suppressed after
	// NewBridge, default 2s. It must cover the initial "already
	// present" reports of Watch.
	StartupGrace time.Duration
}

// BridgeEvent is one card presentation served over the bridge HTTP
// surface. Reader is the reader tag (xx-xxxx-xx), Card the card btag
// (xxx-xxx-xxxx). ID is the monotonic cursor the /pending polling
// fallback replays with (after=last seen ID).
type BridgeEvent struct {
	ID     int64  `json:"id"`
	Reader string `json:"reader"`
	Card   string `json:"card"`
}

// Bridge feeds Watch events through the tag derivation and the dedup
// filter and serves the result as SSE and polling JSON over HTTP. The
// zero value is not usable, use NewBridge.
type Bridge struct {
	hub *bridgeHub
	dd  *bridgeDedup
}

// NewBridge returns a Bridge recording presentations with the given
// options.
func NewBridge(opts *BridgeOptions) *Bridge {
	capacity, window, grace := bridgeCapacity, bridgeDedupWindow, bridgeStartupGrace
	if opts != nil {
		if opts.Capacity > 0 {
			capacity = opts.Capacity
		}
		if opts.DedupWindow > 0 {
			window = opts.DedupWindow
		}
		if opts.StartupGrace > 0 {
			grace = opts.StartupGrace
		}
	}
	return &Bridge{hub: newBridgeHub(capacity), dd: newBridgeDedup(window, grace)}
}

// Feed applies one Watch event. Insertions with an identified card become
// one bridge presentation, {reader tag, card btag}, filtered by the dedup
// guard; removals and card-less events are ignored — one presentation per
// scan. The reader tag carries the reader serial, or its USB port path
// when no usable serial exists, so two units of the same reader model
// serve distinct tags. Feed never blocks.
func (b *Bridge) Feed(ev Event) {
	if ev.Kind != KindInsert || ev.Card == nil {
		return
	}
	reader, card := ReaderTagWithUnit(ev.Reader, ev.ReaderSerial, ev.ReaderPort), ev.Card.ID
	if b.dd.allow(reader, card) {
		b.hub.add(reader, card)
	}
}

// Handler returns the HTTP surface of the bridge: the liveness probe,
// the SSE stream and the polling fallback, all with permissive CORS
// headers so a kiosk page served from an HTTPS origin may read them from
// a loopback http origin.
func (b *Bridge) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprintf(w, `{"ok":true,"version":%q}`, Version())
	})
	mux.HandleFunc("GET /pending", func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		body, err := json.Marshal(bridgePendingResponse{Events: b.hub.since(after)})
		if err != nil {
			http.Error(w, "marshal error", http.StatusInternalServerError)
			return
		}
		w.Write(body)
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		ch, cancel := b.hub.subscribe()
		defer cancel()
		fmt.Fprintf(w, "event: hello\ndata: {\"version\":%q}\n\n", Version())
		flusher.Flush()
		// Heartbeat so intermediaries keep the stream alive.
		heartbeat := time.NewTicker(20 * time.Second)
		defer heartbeat.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case ev := <-ch:
				body, err := json.Marshal(ev)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "event: card\ndata: %s\n\n", body)
				flusher.Flush()
			case <-heartbeat.C:
				fmt.Fprint(w, ": keep-alive\n\n")
				flusher.Flush()
			}
		}
	})
	return mux
}

// Serve listens on addr and serves the bridge HTTP surface until ctx is
// cancelled (graceful shutdown, a nil return) or the listener fails.
// RequireLoopback should be consulted first, Serve itself does not
// guard the address.
func (b *Bridge) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bridge listen on %q: %w", addr, err)
	}
	return b.ServeListener(ctx, ln)
}

// ServeListener serves the bridge HTTP surface on an already bound
// listener until ctx is cancelled (graceful shutdown, a nil return)
// or the listener fails. Binding the listener in the caller makes a
// bad address fail fast instead of asynchronously.
func (b *Bridge) ServeListener(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           b.Handler(),
		ReadHeaderTimeout: bridgeReadHeaderTimeout,
		// Requests share the Serve ctx: cancelling it ends the long
		// lived SSE streams too, so Shutdown does not have to time
		// out on them.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			// Belt and braces: a handler ignoring its request
			// context must not outlive ServeListener either.
			srv.Close()
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// RequireLoopback guards the default deployment posture of a Bridge: card
// identities must never leave the kiosk. Only a loopback address (or the
// literal localhost) is accepted without the explicit allowRemote escape
// hatch.
func RequireLoopback(addr string, allowRemote bool) error {
	if allowRemote {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not loopback; card identities must not leave the kiosk (override with the allowRemote escape hatch)", addr)
	}
	return nil
}

// bridgePendingResponse is the JSON body of GET /pending: every buffered
// event with an ID greater than the requested cursor, oldest first.
type bridgePendingResponse struct {
	Events []BridgeEvent `json:"events"`
}

// bridgeHub fans presentations out to every SSE subscriber and keeps a
// small ring buffer so the polling fallback can catch up after a page
// reload or a browser without EventSource.
type bridgeHub struct {
	mu   sync.Mutex
	next int64
	cap  int
	buf  []BridgeEvent
	subs map[chan BridgeEvent]struct{}
}

// newBridgeHub creates a hub retaining the last capacity presentations.
// The retention is tracked explicitly, because append can grow the slice
// beyond the requested capacity, so the builtin cap() must never be the
// source of truth.
func newBridgeHub(capacity int) *bridgeHub {
	return &bridgeHub{
		cap:  capacity,
		buf:  make([]BridgeEvent, 0, capacity),
		subs: make(map[chan BridgeEvent]struct{}),
	}
}

// add records one presentation, broadcasts it to every subscriber and
// returns the assigned event.
func (h *bridgeHub) add(reader, card string) BridgeEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	ev := BridgeEvent{ID: h.next, Reader: reader, Card: card}
	h.buf = append(h.buf, ev)
	if len(h.buf) > h.cap {
		h.buf = h.buf[len(h.buf)-h.cap:]
	}
	for ch := range h.subs {
		select {
		case ch <- ev:
		default: // a stuck subscriber never blocks the watch loop
		}
	}
	return ev
}

// since returns every buffered event with an ID greater than after, oldest
// first.
func (h *bridgeHub) since(after int64) []BridgeEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	events := make([]BridgeEvent, 0, len(h.buf))
	for _, ev := range h.buf {
		if ev.ID > after {
			events = append(events, ev)
		}
	}
	return events
}

// subscribe registers a new SSE subscriber. The returned channel is
// buffered so a slow consumer rides over short bursts; the cancel func
// always removes it.
func (h *bridgeHub) subscribe() (chan BridgeEvent, func()) {
	ch := make(chan BridgeEvent, 16)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subs[ch] = struct{}{}
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.subs, ch)
	}
}

// bridgeDedup suppresses the repeated insert events a card lying on a
// reader can produce: the same reader+card pair within the window is
// dropped. The startup grace suppresses Watch's initial "cards already
// present" report so a card left on a reader never serves an HTTP event
// after a service restart.
type bridgeDedup struct {
	window time.Duration
	grace  time.Duration
	start  time.Time
	mu     sync.Mutex
	last   map[string]time.Time
}

func newBridgeDedup(window, grace time.Duration) *bridgeDedup {
	return &bridgeDedup{
		window: window,
		grace:  grace,
		start:  time.Now(),
		last:   make(map[string]time.Time),
	}
}

// allow reports whether the reader+card pair should be forwarded now.
func (d *bridgeDedup) allow(reader, card string) bool {
	now := time.Now()
	if now.Sub(d.start) < d.grace {
		return false
	}
	key := reader + "|" + card
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.last[key]; ok && now.Sub(t) < d.window {
		d.last[key] = now
		return false
	}
	if len(d.last) >= bridgeDedupMax {
		// The pair table is bounded: drop the stale entries, and if a
		// burst keeps them all fresh, drop the table entirely, the
		// window is a few seconds of history at most.
		for k, t := range d.last {
			if now.Sub(t) >= d.window {
				delete(d.last, k)
			}
		}
		if len(d.last) >= bridgeDedupMax {
			clear(d.last)
		}
	}
	d.last[key] = now
	return true
}
