// Package pcscfake implements an in-process fake pcscd daemon.
//
// It is a fully self-contained re-implementation of the pcscd wire
// protocol, deliberately independent of the codecs in the pcsc
// package: the client and the fake encoding the same protocol twice
// means their agreement is itself under test.
package pcscfake

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Wire constants, mirroring pcsc-lite src/winscard_msg.h.
const (
	cmdEstablishContext      uint32 = 0x01
	cmdReleaseContext        uint32 = 0x02
	cmdConnect               uint32 = 0x04
	cmdDisconnect            uint32 = 0x06
	cmdTransmit              uint32 = 0x09
	cmdVersion               uint32 = 0x11
	cmdGetReadersState       uint32 = 0x12
	cmdWaitReaderStateChange uint32 = 0x13
)

// SCARD error codes and limits, mirroring pcsc-lite src/pcsclite.h.
const (
	errInvalidHandle  uint32 = 0x80100003
	errUnknownReader  uint32 = 0x80100009
	errTimeout        uint32 = 0x8010000A
	errNoSmartcard    uint32 = 0x8010000C
	errServiceStopped uint32 = 0x8010001E

	maxATRSize = 33
	maxReaders = 16

	stateAbsent      uint32 = 0x0002
	statePresent     uint32 = 0x0004
	statePresentBits uint32 = statePresent | 0x0010 | 0x0020 | 0x0040

	protocolT1 uint32 = 0x0002

	uidProbeA byte = 0xFF // FF CA 00 00 00, PC/SC part 3 GET DATA UID
	uidProbeB byte = 0xCA
)

const readerStateWireSz = 184

// Server is a fake pcscd listening on a Unix stream socket in a
// temporary directory. It serves reader states, card connections and
// APDU exchanges for the UID pseudo-APDU FF CA 00 00 00.
type Server struct {
	// OfferedMinor is the protocol minor version the daemon claims,
	// 4 by default. Set it to 2 before the first client connects to
	// exercise the client downgrade negotiation.
	OfferedMinor uint32

	path   string
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	readers map[string]*Reader
	waiters map[chan struct{}]struct{}
	conns   map[net.Conn]struct{}
	cards   map[uint32]*card
	handles uint32
}

// Reader is the state of one fake reader.
type Reader struct {
	ATR          []byte
	UID          []byte // response to FF CA 00 00 00, nil means unsupported
	Present      bool
	EventCounter uint32
}

type card struct {
	reader *Reader
}

// New starts a fake pcscd with an empty reader set.
func New() (*Server, error) {
	dir, err := os.MkdirTemp("", "pcscfake-*")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "pcscd.comm")
	ln, err := net.Listen("unix", path)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		OfferedMinor: 4,
		path:         path,
		ln:           ln,
		ctx:          ctx,
		cancel:       cancel,
		readers:      make(map[string]*Reader),
		waiters:      make(map[chan struct{}]struct{}),
		conns:        make(map[net.Conn]struct{}),
		cards:        make(map[uint32]*card),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// Addr returns the Unix socket path of the fake daemon.
func (s *Server) Addr() string {
	return s.path
}

// InsertCard creates the reader if needed and inserts a card with the
// given ATR. A nil UID makes the card answer 63 00 to the UID probe.
func (s *Server) InsertCard(reader string, atr []byte, uid []byte) {
	s.mu.Lock()
	r, ok := s.readers[reader]
	if !ok {
		r = &Reader{}
		s.readers[reader] = r
	}
	r.ATR = append([]byte(nil), atr...)
	r.UID = append([]byte(nil), uid...)
	r.Present = true
	r.EventCounter++
	s.mu.Unlock()
	s.wakeWaiters()
}

// RemoveCard removes the card from the reader.
func (s *Server) RemoveCard(reader string) {
	s.mu.Lock()
	if r, ok := s.readers[reader]; ok {
		r.Present = false
		r.EventCounter++
	}
	s.mu.Unlock()
	s.wakeWaiters()
}

func (s *Server) wakeWaiters() {
	s.mu.Lock()
	for ch := range s.waiters {
		close(ch)
		delete(s.waiters, ch)
	}
	s.mu.Unlock()
}

// Close stops the fake daemon, closes all client connections to
// unblock the serving goroutines and waits for them to finish.
func (s *Server) Close() error {
	s.cancel()
	err := s.ln.Close()
	s.mu.Lock()
	for conn := range s.conns {
		conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return errors.Join(err, os.RemoveAll(filepath.Dir(s.path)))
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		if s.ctx.Err() != nil {
			conn.Close()
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Go(func() {
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				conn.Close()
			}()
			s.serve(conn)
		})
	}
}

func (s *Server) serve(conn net.Conn) {
	if !s.negotiate(conn) {
		return
	}
	for {
		command, body, err := readMessage(conn)
		if err != nil {
			return
		}
		done, err := s.dispatch(conn, command, body)
		if err != nil || done {
			return
		}
	}
}

// negotiate handles the header-less CMD_VERSION exchange. A client
// proposing a different 4.x minor gets one SCARD_E_SERVICE_STOPPED
// carrying the version to retry with, as a real daemon does. A
// protocol 4.5 daemon also accepts 4.4 clients through backward
// compatibility.
func (s *Server) negotiate(conn net.Conn) bool {
	for {
		command, body, err := readMessage(conn)
		if err != nil || command != cmdVersion || len(body) != 12 {
			return false
		}
		req := decodeVersion(body)
		accepted := req.major == 4 && req.minor == s.OfferedMinor ||
			(s.OfferedMinor == 5 && req.minor == 4)
		if accepted {
			_, err := conn.Write(encodeVersion(versionMsg{major: 4, minor: s.OfferedMinor}))
			return err == nil
		}
		_, err = conn.Write(encodeVersion(versionMsg{
			major: 4,
			minor: s.OfferedMinor,
			rv:    errServiceStopped,
		}))
		if err != nil {
			return false
		}
	}
}

func (s *Server) dispatch(conn net.Conn, command uint32, body []byte) (done bool, err error) {
	switch command {
	case cmdEstablishContext:
		resp := make([]byte, 12)
		copy(resp[0:4], body[0:4]) // scope
		binary.LittleEndian.PutUint32(resp[4:], 1)
		// Responses are the raw struct, no message header.
		_, err := conn.Write(resp)
		return false, err

	case cmdReleaseContext:
		_, err := conn.Write(body[:8])
		return true, err

	case cmdGetReadersState:
		return false, s.writeStates(conn)

	case cmdWaitReaderStateChange:
		if s.OfferedMinor >= 5 {
			return false, s.waitNew(conn)
		}
		timeoutMS := binary.LittleEndian.Uint32(body[0:4])
		rv, err := s.waitForChange(timeoutMS)
		if err != nil {
			return true, err
		}
		resp := make([]byte, 8)
		binary.LittleEndian.PutUint32(resp[0:], timeoutMS)
		binary.LittleEndian.PutUint32(resp[4:], rv)
		_, err = conn.Write(resp)
		return false, err

	case cmdConnect:
		return false, s.connect(conn, body)

	case cmdTransmit:
		return false, s.transmit(conn, body)

	case cmdDisconnect:
		s.mu.Lock()
		delete(s.cards, binary.LittleEndian.Uint32(body[0:4]))
		s.mu.Unlock()
		_, err := conn.Write(body[:12])
		return false, err
	}
	return true, fmt.Errorf("pcscfake: unknown command 0x%02X", command)
}

// waitForChange blocks until a state change, the timeout or shutdown.
// It implements the protocol 4.4 wait with the server side timeout.
func (s *Server) waitForChange(timeoutMS uint32) (uint32, error) {
	ch := s.registerWaiter()
	defer s.unregisterWaiter(ch)
	timer := time.NewTimer(time.Duration(timeoutMS) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ch:
		return 0, nil
	case <-timer.C:
		return errTimeout, nil
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	}
}

// waitNew implements the protocol 4.5+ reader state wait: the request
// carries no body, the answer is the full reader state array as soon
// as a change happens or the client sends anything, a stop request
// additionally gets its own 8 byte answer, mirroring pcscd 2.x.
func (s *Server) waitNew(conn net.Conn) error {
	stopped := make(chan struct{}, 1)
	go func() {
		// Any client data unblocks the wait, as in the daemon. A stop
		// request is exactly its 8 byte header, so consuming it here
		// keeps the dispatch loop in sync.
		head := make([]byte, 8)
		if _, err := io.ReadFull(conn, head); err == nil {
			stopped <- struct{}{}
		}
	}()
	change := s.registerWaiter()
	defer s.unregisterWaiter(change)

	var writeErr error
	select {
	case <-change:
		// Cancel the stop watcher and restore the socket for the next
		// dispatch read.
		_ = conn.SetReadDeadline(time.Now())
		_ = conn.SetReadDeadline(time.Time{})
		writeErr = s.writeStates(conn)
		select {
		case <-stopped:
			// A stop raced the change, answer it too to stay in sync.
			_, writeErr = conn.Write(make([]byte, 8))
		default:
		}
	case <-stopped:
		writeErr = s.writeStates(conn)
		if writeErr == nil {
			_, writeErr = conn.Write(make([]byte, 8))
		}
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
	return writeErr
}

// writeStates answers with the raw 16 entry reader state array.
func (s *Server) writeStates(conn net.Conn) error {
	buf := make([]byte, maxReaders*readerStateWireSz)
	s.mu.Lock()
	for i, name := range slices.Sorted(maps.Keys(s.readers)) {
		if i >= maxReaders {
			break
		}
		encodeReaderStateInto(buf[i*readerStateWireSz:], name, s.readers[name])
	}
	s.mu.Unlock()
	_, err := conn.Write(buf)
	return err
}

func (s *Server) registerWaiter() chan struct{} {
	ch := make(chan struct{})
	s.mu.Lock()
	s.waiters[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

func (s *Server) unregisterWaiter(ch chan struct{}) {
	s.mu.Lock()
	delete(s.waiters, ch)
	s.mu.Unlock()
}

func (s *Server) connect(conn net.Conn, body []byte) error {
	name := cString(body[4:132])
	s.mu.Lock()
	r, known := s.readers[name]
	isPresent := known && r.Present
	handle := uint32(0)
	if isPresent {
		s.handles++
		handle = s.handles
		s.cards[handle] = &card{reader: r}
	}
	s.mu.Unlock()
	var rv uint32
	switch {
	case !known:
		rv = errUnknownReader
	case !isPresent:
		rv = errNoSmartcard
	}
	resp := make([]byte, 152)
	copy(resp, body[:132])
	copy(resp[132:140], body[132:140]) // share mode and preferred protocols
	binary.LittleEndian.PutUint32(resp[140:], handle)
	if isPresent {
		binary.LittleEndian.PutUint32(resp[144:], protocolT1)
	}
	binary.LittleEndian.PutUint32(resp[148:], rv)
	_, err := conn.Write(resp)
	return err
}

func (s *Server) transmit(conn net.Conn, body []byte) error {
	cardHandle := binary.LittleEndian.Uint32(body[0:4])
	sendLength := binary.LittleEndian.Uint32(body[12:16])
	send := make([]byte, sendLength)
	if _, err := io.ReadFull(conn, send); err != nil {
		return err
	}
	s.mu.Lock()
	var uid []byte
	known := false
	if c, ok := s.cards[cardHandle]; ok {
		known = true
		uid = append([]byte(nil), c.reader.UID...)
	}
	s.mu.Unlock()
	var resp []byte
	var rv uint32
	isUIDProbe := len(send) == 5 &&
		send[0] == uidProbeA && send[1] == uidProbeB && send[2] == 0 && send[3] == 0 && send[4] == 0
	switch {
	case !known:
		rv = errInvalidHandle
	case isUIDProbe:
		if uid == nil {
			resp = []byte{0x63, 0x00} // uid not available
		} else {
			resp = append(uid, 0x90, 0x00)
		}
	default:
		resp = []byte{0x6D, 0x00} // instruction not supported
	}
	pci := binary.LittleEndian.Uint32(body[4:8])
	head := make([]byte, 32)
	binary.LittleEndian.PutUint32(head[0:], cardHandle)
	binary.LittleEndian.PutUint32(head[4:], pci)
	binary.LittleEndian.PutUint32(head[8:], 8)
	binary.LittleEndian.PutUint32(head[12:], sendLength)
	binary.LittleEndian.PutUint32(head[16:], pci)
	binary.LittleEndian.PutUint32(head[20:], 8)
	binary.LittleEndian.PutUint32(head[24:], uint32(len(resp)))
	binary.LittleEndian.PutUint32(head[28:], rv)
	if _, err := conn.Write(head); err != nil {
		return err
	}
	if len(resp) > 0 {
		_, err := conn.Write(resp)
		return err
	}
	return nil
}

type versionMsg struct {
	major uint32
	minor uint32
	rv    uint32
}

func encodeVersion(v versionMsg) []byte {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[0:], v.major)
	binary.LittleEndian.PutUint32(buf[4:], v.minor)
	binary.LittleEndian.PutUint32(buf[8:], v.rv)
	return buf
}

func decodeVersion(b []byte) versionMsg {
	return versionMsg{
		major: binary.LittleEndian.Uint32(b[0:4]),
		minor: binary.LittleEndian.Uint32(b[4:8]),
		rv:    binary.LittleEndian.Uint32(b[8:12]),
	}
}

// encodeReaderStateInto packs one READER_STATE entry, the same layout
// as pcsc-lite src/readers.h, 184 bytes little endian.
func encodeReaderStateInto(buf []byte, name string, r *Reader) {
	copy(buf[0:], name)
	binary.LittleEndian.PutUint32(buf[128:], r.EventCounter)
	state := uint32(stateAbsent)
	if r.Present {
		state = statePresentBits
	}
	binary.LittleEndian.PutUint32(buf[132:], state)
	atr := r.ATR[:min(len(r.ATR), maxATRSize)]
	copy(buf[140:], atr)
	binary.LittleEndian.PutUint32(buf[176:], uint32(len(atr)))
	var proto uint32
	if r.Present {
		proto = protocolT1
	}
	binary.LittleEndian.PutUint32(buf[180:], proto)
}

func readMessage(r io.Reader) (command uint32, body []byte, err error) {
	head := make([]byte, 8)
	if _, err = io.ReadFull(r, head); err != nil {
		return 0, nil, err
	}
	size := binary.LittleEndian.Uint32(head[0:4])
	command = binary.LittleEndian.Uint32(head[4:8])
	body = make([]byte, size)
	if size > 0 {
		if _, err = io.ReadFull(r, body); err != nil {
			return command, nil, err
		}
	}
	return command, body, nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
