// Package pcscid identifies any smart card presented to a reader
// registered with the local pcscd: NFC, mifare, RFID, contact smart
// cards and everything else the daemon manages.
//
// It is pure Go without cgo, on Unix it speaks the pcscd daemon wire
// protocol directly. The identifier of a card, its btag, is a short
// hash over the card type and the unique tag of the individual card,
// normally its UID read through the PC/SC part 3 GET DATA APDU. When
// no UID can be read the ATR is used, which identifies the card on
// type level only.
package pcscid

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"paepcke.de/pcscid/pcsc"
)

// Kind describes the reader event that produced an Event.
type Kind uint8

const (
	// KindInsert reports a card that became present on a reader.
	KindInsert Kind = iota
	// KindRemove reports a card that is no longer present.
	KindRemove
)

// String implements fmt.Stringer.
func (k Kind) String() string {
	switch k {
	case KindInsert:
		return "insert"
	case KindRemove:
		return "remove"
	default:
		return fmt.Sprintf("kind(%d)", uint8(k))
	}
}

// Card is the identification of one presented smart card.
type Card struct {
	// ID is the btag, the short unique identifier, the output of Btag.
	ID string
	// Type is the detected card type name, see DetectType.
	Type string
	// UID is the unique tag of the individual card, nil when it
	// could not be read.
	UID []byte
	// ATR is the answer to reset of the card.
	ATR []byte
	// Reader is the reader name the card was seen on. The same card
	// reports the same ID on every reader.
	Reader string
	// Source is what the ID was derived from: "uid" for a card
	// unique tag, "atr" for a type level fallback when neither card nor
	// reader provides a UID.
	Source string
}

// Event is one reader state change.
type Event struct {
	// Kind is what happened.
	Kind Kind
	// Card is set for KindInsert.
	Card *Card
	// Reader is the reader name the event belongs to.
	Reader string
}

// Options tunes Watch. A nil Options selects every default.
type Options struct {
	// Logger receives the verbose debug trace. In normal operation a
	// discarded logger keeps the library silent. The cmd/pcscid
	// sample app wires DEBUG=1 to it.
	Logger *slog.Logger
	// SocketPath overrides the pcscd socket path. Empty selects the
	// platform default, PCSCLITE_CSOCK_NAME overrides it on Unix.
	SocketPath string
}

// btagAlphabet is the alphabet the btag and reader tag encode their
// digests in: digits and lower case letters only.
const btagAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

// btagFormat groups n digest characters at the given dash positions.
func btagFormat(sum []byte, n int, dashes ...int) string {
	id := make([]byte, 0, n+len(dashes))
	for i, b := range sum[:n] {
		for _, d := range dashes {
			if i == d {
				id = append(id, '-')
			}
		}
		id = append(id, btagAlphabet[int(b)%len(btagAlphabet)])
	}
	return string(id)
}

// Btag derives the btag, the short unique identifier of a card,
// from its type and the unique tag of the individual card, its UID,
// or its ATR when no UID is available. The btag is 10 characters from
// the digits and lower case letters in three dash separated groups,
// xxx-xxx-xxxx, stable across readers and re-presentations, and
// different for two cards of the same type with different tags.
func Btag(cardType string, tag []byte) string {
	sum := sha256.Sum256(append(
		append(append([]byte("pcscid/v1|"), cardType...), '|'),
		tag...))
	return btagFormat(sum[:], 10, 3, 6)
}

// ReaderTag derives the stable short unique identifier of a reader
// from its pcscd reader name. The tag is 5 characters from the digits
// and lower case letters in two dash separated groups, xxx-xx, the
// same for the same reader across restarts.
func ReaderTag(reader string) string {
	sum := sha256.Sum256(append([]byte("pcscid/reader/v1|"), reader...))
	return btagFormat(sum[:], 5, 3)
}

// Watch starts watching all readers of the local pcscd and reports
// card insertions and removals on the returned channel. Cards that
// are already present when Watch starts are reported as inserted.
//
// When the pcscd socket cannot be reached, Watch fails with that
// error, the pcscd service is a hard requirement.
//
// The channel is closed once ctx is cancelled.
func Watch(ctx context.Context, opts *Options) (<-chan Event, error) {
	lg, socketPath := watchOptions(opts)
	cl, err := pcsc.New(socketPath, lg)
	if err != nil {
		return nil, fmt.Errorf("pcscid: pcscd unavailable: %w", err)
	}
	ch := make(chan Event, 8)
	go watchLoop(ctx, cl, socketPath, lg, ch)
	return ch, nil
}

func watchOptions(opts *Options) (lg *slog.Logger, socketPath string) {
	lg = slog.New(slog.DiscardHandler)
	if opts != nil {
		if opts.Logger != nil {
			lg = opts.Logger
		}
		socketPath = opts.SocketPath
	}
	return lg, socketPath
}

// reconnectDelay is the pause between two pcscd reconnection
// attempts in the watch loop.
const reconnectDelay = 500 * time.Millisecond

// waitTick bounds one daemon side reader state wait. A change can slip
// between the state fetch and the wait registration, so the tick also
// bounds the worst case latency of an event to roughly one tick.
const waitTick = time.Second

// watchLoop keeps a client alive across pcscd restarts and drives
// the state change handling.
func watchLoop(ctx context.Context, cl *pcsc.Client, socketPath string, lg *slog.Logger, ch chan<- Event) {
	defer close(ch)
	tracking := newTracking()
	for {
		// Closing the connection is the cancellation path of a
		// blocked WaitChange.
		stopClose := context.AfterFunc(ctx, func() { cl.Close() })
		err := pollLoop(ctx, cl, tracking, lg, ch)
		stopClose()
		cl.Close()
		if ctx.Err() != nil {
			return
		}
		lg.Debug("pcscd connection lost, reconnecting", "error", err)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(reconnectDelay):
			}
			next, dialErr := pcsc.New(socketPath, lg)
			if dialErr != nil {
				lg.Debug("pcscd reconnect failed", "error", dialErr)
				continue
			}
			cl = next
			break
		}
	}
}

// readerTracking remembers the last known presence of every reader so
// a daemon restart does not re-report cards that never moved.
type readerTracking struct {
	present  map[string]bool
	counters map[string]uint32
}

func newTracking() *readerTracking {
	return &readerTracking{
		present:  make(map[string]bool),
		counters: make(map[string]uint32),
	}
}

// pollLoop processes reader state changes until the transport breaks
// or ctx is cancelled.
func pollLoop(ctx context.Context, cl *pcsc.Client, tracking *readerTracking, lg *slog.Logger, ch chan<- Event) error {
	for {
		states, err := cl.States()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		lg.Debug("reader states", "readers", len(states))
		seen := make(map[string]bool, len(states))
		for _, st := range states {
			seen[st.Reader] = true
			present := st.State&pcsc.ReaderPresent != 0
			wasPresent := tracking.present[st.Reader]
			if present {
				if !wasPresent || tracking.counters[st.Reader] != st.EventCounter {
					card := identify(cl, lg, st)
					if !emit(ctx, ch, Event{Kind: KindInsert, Card: card, Reader: st.Reader}) {
						return nil
					}
				}
			} else if wasPresent {
				if !emit(ctx, ch, Event{Kind: KindRemove, Reader: st.Reader}) {
					return nil
				}
				lg.Debug("card removed", "reader", st.Reader)
			}
			tracking.present[st.Reader] = present
			if present {
				tracking.counters[st.Reader] = st.EventCounter
			} else {
				delete(tracking.counters, st.Reader)
			}
		}
		for reader, wasPresent := range tracking.present {
			if seen[reader] {
				continue
			}
			delete(tracking.present, reader)
			delete(tracking.counters, reader)
			if wasPresent {
				if !emit(ctx, ch, Event{Kind: KindRemove, Reader: reader}) {
					return nil
				}
				lg.Debug("reader gone", "reader", reader)
			}
		}
		if len(states) == 0 {
			// With no reader registered the daemon answers the wait
			// immediately, there is nothing to wait on: poll gently
			// for a hot plugged reader instead of spinning.
			if !sleepCtx(ctx, reconnectDelay) {
				return nil
			}
			continue
		}
		if err := cl.WaitChange(waitTick); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, pcsc.ErrTimeout) {
				continue // refresh states anyway, cheap and race free
			}
			return err
		}
	}
}

// identify builds the Card for a present reader state.
func identify(cl *pcsc.Client, lg *slog.Logger, st pcsc.ReaderState) *Card {
	cardType := DetectType(st.ATR)
	card := &Card{Type: cardType, ATR: st.ATR, Reader: st.Reader}
	uid, protocol := probeUID(cl, lg, st.Reader)
	card.UID = uid
	if len(uid) > 0 {
		card.ID = Btag(cardType, uid)
		card.Source = "uid"
	} else {
		card.ID = Btag(cardType, st.ATR)
		card.Source = "atr"
	}
	lg.Debug("card inserted",
		"reader", st.Reader,
		"id", card.ID,
		"reader-tag", ReaderTag(st.Reader),
		"type", cardType,
		"source", card.Source,
		"uid", fmt.Sprintf("% X", uid),
		"atr", fmt.Sprintf("% X", st.ATR),
		"protocol", protocolName(protocol))
	return card
}

// emit sends an event unless ctx is done, it reports whether the
// event reached the channel.
func emit(ctx context.Context, ch chan<- Event, ev Event) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// sleepCtx pauses for d unless ctx is done first, it reports whether
// the full pause elapsed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
