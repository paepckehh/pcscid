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
	"strings"
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
	// ReaderTag is the reader tag as derived by Watch from every
	// identity source the Options enabled: the reader name, the unit
	// facts (ReaderSerial, ReaderPort) and the machine identity
	// (Options.MACID). It is set for KindInsert events, empty for
	// KindRemove, which carries no card connection to probe facts
	// with. It equals ReaderTagWithUnit(ev.Reader, ev.ReaderSerial,
	// ev.ReaderPort) unless MACID mixed the machine in.
	ReaderTag string
	// ReaderSerial is the hardware serial number of the reader
	// (SCARD_ATTR_VENDOR_IFD_SERIAL_NO, the USB iSerial string of the
	// unit) when the driver serves a usable one, empty otherwise.
	// Constant vendor placeholders, for example the all zero serial of
	// the ACS ACR122U family, are filtered and also answer empty. It is
	// probed with the card connection of an insertion, so only
	// insertions carry it. See ReaderTagWithUnit.
	ReaderSerial string
	// ReaderPort is the kernel physical USB port path of the reader
	// (sysfs devpath, for example "2-1.3"), resolved through its
	// SCARD_ATTR_CHANNEL_ID bus/device address when the driver serves
	// no usable serial and Options.USBPathID allows it. It anchors the
	// unit to its port: stable across daemon restarts and reboots, but
	// moving the reader to another port changes it. Only insertions
	// carry it.
	ReaderPort string
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
	// SysfsUSBRoot overrides the sysfs root scanned to resolve a
	// reader's USB bus/device address to its physical port path,
	// default /sys/bus/usb/devices. It exists to test the port based
	// reader identity fallback against a fake device tree.
	SysfsUSBRoot string
	// USBPathID allows the physical USB port path as the per-unit
	// fallback for readers serving no usable hardware serial (the ACS
	// ACR122U family). Off by default, because the port path is stable
	// only as long as the reader stays in its port: moving the reader
	// to another port or machine changes the tag. The sample app wires
	// PCSCID_USB_PATH_ID to it.
	USBPathID bool
	// MACID mixes the machine identity, the stable hardware MAC
	// addresses of the physical ethernet ports (MachineID), into every
	// reader tag: identical readers on different machines get distinct
	// tags, at the price of the tag no longer following the reader to
	// another machine. Off by default. The sample app wires
	// PCSCID_MAC_ID to it.
	MACID bool
	// MachineID overrides the machine identity used when MACID is
	// enabled. Empty uses MachineID(), which is empty again on machines
	// without a physical ethernet port; those then keep the unit level
	// tags. It exists as the injection point of a caller chosen
	// machine identity and for tests.
	MachineID string
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

// digestID returns the SHA-256 digest of the domain separated identity
// parts, concatenated in order.
func digestID(parts ...[]byte) [sha256.Size]byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// Btag derives the btag, the short unique identifier of a card,
// from its type and the unique tag of the individual card, its UID,
// or its ATR when no UID is available. The btag is 10 characters from
// the digits and lower case letters in three dash separated groups,
// xxx-xxx-xxxx, stable across readers and re-presentations, and
// different for two cards of the same type with different tags.
func Btag(cardType string, tag []byte) string {
	sum := digestID([]byte("pcscid/v1|"), []byte(cardType), []byte("|"), tag)
	return btagFormat(sum[:], 10, 3, 6)
}

// ReaderTag derives the stable short unique identifier of a reader
// from its pcscd reader name. The tag is 8 characters from the digits
// and lower case letters in three dash separated groups, xx-xxxx-xx,
// the same for the same reader across restarts, sockets, machines and
// USB ports.
//
// pcscd reader names end in volatile hotplug indices, for example
// "ACS ACR122U 01 00 00", where the trailing number groups change
// with the USB port, the boot order and the machine. Those groups are
// stripped before hashing, so the tag follows the reader hardware,
// not its point of attachment. Two identical reader models whose
// names carry no serial number share one tag, ReaderTagWithSerial
// fixes that with the serial from the driver when one is available.
func ReaderTag(reader string) string {
	sum := digestID([]byte("pcscid/reader/v1|"), []byte(normalizeReaderName(reader)))
	return btagFormat(sum[:], 8, 2, 6)
}

// ReaderTagWithSerial derives the reader tag from the reader name and
// the hardware serial number of the unit (Event.ReaderSerial, the USB
// iSerial string from SCARD_ATTR_VENDOR_IFD_SERIAL_NO). Readers of the
// same model, whose names hash to the same ReaderTag, get distinct
// tags, one per physical unit, still stable across machines, sockets,
// USB ports and daemon restarts: the serial is burned into the reader
// hardware. An empty serial falls back to the plain name based tag.
func ReaderTagWithSerial(reader, serial string) string {
	return ReaderTagWithUnit(reader, serial, "")
}

// ReaderTagWithUnit derives the reader tag from every per-unit fact
// the driver could serve, in decreasing portability:
//
//   - a usable hardware serial (ReaderTagWithSerial semantics, hash
//     domain pcscid/reader/v2): one tag per unit, portable across
//     machines and USB ports.
//   - the kernel physical USB port path (Event.ReaderPort, hash domain
//     pcscid/reader/v3): one tag per unit as long as it stays in its
//     port, stable across daemon restarts and reboots, but moving the
//     reader or re-plugging it into another port changes the tag.
//   - neither: the model level ReaderTag.
func ReaderTagWithUnit(reader, serial, port string) string {
	switch {
	case serial != "":
		sum := digestID([]byte("pcscid/reader/v2|"),
			[]byte(normalizeReaderName(reader)), []byte("|"), []byte(serial))
		return btagFormat(sum[:], 8, 2, 6)
	case port != "":
		sum := digestID([]byte("pcscid/reader/v3|"),
			[]byte(normalizeReaderName(reader)), []byte("|"), []byte(port))
		return btagFormat(sum[:], 8, 2, 6)
	default:
		return ReaderTag(reader)
	}
}

// ReaderTagWithMachine adds the machine identity to the reader tag:
// the machine component (MachineID or an explicit override, wired by
// Options.MACID / PCSCID_MAC_ID) is mixed into every derivation when
// it is not empty, so identical readers on different machines serve
// distinct tags. The price is portability: a tag derived with a
// machine component does not follow the reader to another machine.
// The hash domain is pcscid/reader/m1 with the unit fact kind
// prefixed ("serial:...", "port:...", or "model"), so a serial and a
// port path of the same text can never collide. An empty machine
// falls back to ReaderTagWithUnit.
func ReaderTagWithMachine(reader, serial, port, machine string) string {
	if machine == "" {
		return ReaderTagWithUnit(reader, serial, port)
	}
	var unit string
	switch {
	case serial != "":
		unit = "serial:" + serial
	case port != "":
		unit = "port:" + port
	default:
		unit = "model"
	}
	sum := digestID([]byte("pcscid/reader/m1|"),
		[]byte(normalizeReaderName(reader)), []byte("|"), []byte(unit), []byte("|"), []byte(machine))
	return btagFormat(sum[:], 8, 2, 6)
}

// normalizeReaderName strips the trailing pcscd hotplug index groups
// (space separated one or two digit decimal numbers) from a reader name,
// keeping the stable product part.
func normalizeReaderName(reader string) string {
	for {
		last := strings.LastIndexByte(reader, ' ')
		if last < 0 || last == len(reader)-1 {
			return reader
		}
		tail := reader[last+1:]
		if !isHotplugIndex(tail) {
			return reader
		}
		reader = reader[:last]
	}
}

// isHotplugIndex reports whether s is one pcscd hotplug index group:
// one or two decimal digits (pcscd formats them %02d).
func isHotplugIndex(s string) bool {
	if len(s) == 0 || len(s) > 2 {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
	lg, env := watchOptions(opts)
	if env.socketPath == "" {
		lg.Debug("watch configuration",
			"socket", "default (/run/pcscd/pcscd.comm, /var/run/pcscd/pcscd.comm, PCSCLITE_CSOCK_NAME override)",
			"sysfs_usb_root", env.sysfsRoot,
			"usb_path_id", env.useUSBPath,
			"machine_id", env.machine)
	} else {
		lg.Debug("watch configuration",
			"socket", env.socketPath,
			"sysfs_usb_root", env.sysfsRoot,
			"usb_path_id", env.useUSBPath,
			"machine_id", env.machine)
	}
	cl, err := pcsc.New(env.socketPath, lg)
	if err != nil {
		return nil, fmt.Errorf("pcscid: pcscd unavailable: %w", err)
	}
	ch := make(chan Event, 8)
	if env.machine != "" {
		lg.Debug("machine identity mixed into reader tags", "machine", env.machine)
	}
	go watchLoop(ctx, cl, env, lg, ch)
	return ch, nil
}

// watchEnv carries the identity configuration of one watch loop.
type watchEnv struct {
	socketPath string
	sysfsRoot  string
	useUSBPath bool
	machine    string
}

func watchOptions(opts *Options) (lg *slog.Logger, env watchEnv) {
	lg = slog.New(slog.DiscardHandler)
	env = watchEnv{
		sysfsRoot: defaultSysfsUSB,
		machine:   "",
	}
	if opts != nil {
		if opts.Logger != nil {
			lg = opts.Logger
		}
		env.socketPath = opts.SocketPath
		if opts.SysfsUSBRoot != "" {
			env.sysfsRoot = opts.SysfsUSBRoot
		}
		env.useUSBPath = opts.USBPathID
		if opts.MACID {
			env.machine = opts.MachineID
			if env.machine == "" {
				env.machine = MachineID()
			}
		}
	}
	return lg, env
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
func watchLoop(ctx context.Context, cl *pcsc.Client, env watchEnv, lg *slog.Logger, ch chan<- Event) {
	defer close(ch)
	tracking := newTracking()
	for {
		// Closing the connection is the cancellation path of a
		// blocked WaitChange.
		stopClose := context.AfterFunc(ctx, func() { cl.Close() })
		err := pollLoop(ctx, cl, tracking, env, lg, ch)
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
			next, dialErr := pcsc.New(env.socketPath, lg)
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
// a daemon restart does not re-report cards that never moved, and the
// per-session unit identities of the readers (see unitRegistry).
type readerTracking struct {
	present  map[string]bool
	counters map[string]uint32
	units    *unitRegistry
}

func newTracking() *readerTracking {
	return &readerTracking{
		present:  make(map[string]bool),
		counters: make(map[string]uint32),
		units:    newUnitRegistry(),
	}
}

// pollLoop processes reader state changes until the transport breaks
// or ctx is cancelled.
func pollLoop(ctx context.Context, cl *pcsc.Client, tracking *readerTracking, env watchEnv, lg *slog.Logger, ch chan<- Event) error {
	// The event counters of a fresh connection mean nothing yet: a
	// restarted daemon counts from zero again, so a still present
	// card must not be re-reported just because its counter moved.
	// Presence alone decides until the counters are known again. The
	// unit identities start over too: a daemon restart re-enumerates
	// the volatile reader name suffixes, remembered facts would answer
	// to the wrong physical unit.
	tracking.counters = make(map[string]uint32)
	tracking.units = newUnitRegistry()
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
				prev, known := tracking.counters[st.Reader]
				if !wasPresent || (known && prev != st.EventCounter) {
					// The unit attributes and the card UID need an open
					// card connection, so both are probed now, while the
					// card is there, over one connection whose exchanges
					// also carry the USB traffic that pins the unit.
					facts := probeReaderCard(cl, lg, st.Reader, env.sysfsRoot, env.useUSBPath, tracking.units.byPort)
					facts = tracking.units.adopt(lg, st.Reader, facts)
					card := identify(lg, st, facts, env.machine)
					tag := ReaderTagWithMachine(st.Reader, facts.serial, facts.port, env.machine)
					if !emit(ctx, ch, Event{Kind: KindInsert, Card: card, Reader: st.Reader, ReaderTag: tag, ReaderSerial: facts.serial, ReaderPort: facts.port}) {
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
			tracking.units.forget(reader)
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

// identify builds the Card for a present reader state from the facts
// the merged probe gathered over its card connection.
func identify(lg *slog.Logger, st pcsc.ReaderState, facts readerFacts, machine string) *Card {
	cardType := DetectType(st.ATR)
	card := &Card{Type: cardType, ATR: st.ATR, Reader: st.Reader}
	uid := facts.uid
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
		"reader-tag", ReaderTagWithMachine(st.Reader, facts.serial, facts.port, machine),
		"reader-serial", facts.serial,
		"reader-port", facts.port,
		"type", cardType,
		"source", card.Source,
		"uid", fmt.Sprintf("% X", uid),
		"atr", fmt.Sprintf("% X", st.ATR),
		"protocol", protocolName(facts.protocol))
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
