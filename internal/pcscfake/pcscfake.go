// Package pcscfake implements an in-process fake pcscd daemon.
//
// It is a fully self-contained re-implementation of the pcscd wire
// protocol, deliberately independent of the codecs in the pcsc
// package: the client and the fake encoding the same protocol twice
// means their agreement is itself under test.
package pcscfake

import (
	"bytes"
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
)

// Wire constants, mirroring pcsc-lite src/winscard_msg.h.
const (
	cmdEstablishContext             uint32 = 0x01
	cmdReleaseContext               uint32 = 0x02
	cmdConnect                      uint32 = 0x04
	cmdDisconnect                   uint32 = 0x06
	cmdTransmit                     uint32 = 0x09
	cmdGetAttrib                    uint32 = 0x0F
	cmdVersion                      uint32 = 0x11
	cmdGetReadersState              uint32 = 0x12
	cmdWaitReaderStateChange        uint32 = 0x13
	cmdStopWaitingReaderStateChange uint32 = 0x14
)

// SCARD error codes and limits, mirroring pcsc-lite src/pcsclite.h.
const (
	errInvalidHandle      uint32 = 0x80100003
	errUnknownReader      uint32 = 0x80100009
	errNoSmartcard        uint32 = 0x8010000C
	errUnsupportedFeature uint32 = 0x80100022
	errServiceStopped     uint32 = 0x8010001E

	attrVendorIFDSerialNo uint32 = 0x0103
	attrChannelID         uint32 = 0x0110

	maxATRSize = 33
	maxReaders = 16
	maxAttrSz  = 264

	stateAbsent      uint32 = 0x0002
	statePresent     uint32 = 0x0004
	statePresentBits uint32 = statePresent | 0x0010 | 0x0020 | 0x0040

	protocolT1 uint32 = 0x0002

	uidProbeA byte = 0xFF // FF CA 00 00 00, PC/SC part 3 GET DATA UID
	uidProbeB byte = 0xCA
)

const readerStateWireSz = 184

// waitMsg mirrors struct wait_reader_state_change: 8 bytes, the
// timeOut field is vestigial in every protocol version, only rv is
// meaningful in the signal and the stop response.
type waitMsg struct {
	timeoutMS uint32
	rv        uint32
}

func encodeWait(w waitMsg) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:], w.timeoutMS)
	binary.LittleEndian.PutUint32(buf[4:], w.rv)
	return buf
}

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
	// waiters holds the connections registered for reader state
	// change signals, mirroring the daemon client list.
	waiters map[net.Conn]struct{}
	conns   map[net.Conn]struct{}
	cards   map[uint32]*card
	handles uint32
}

// Reader is the state of one fake reader.
type Reader struct {
	ATR          []byte
	UID          []byte // response to FF CA 00 00 00, nil means unsupported
	Serial       string // SCARD_ATTR_VENDOR_IFD_SERIAL_NO answer, empty means unsupported
	ChannelID    uint32 // SCARD_ATTR_CHANNEL_ID answer, 0x0020BBAA, 0 means unsupported
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
		waiters:      make(map[net.Conn]struct{}),
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

// SetSerial configures the SCARD_ATTR_VENDOR_IFD_SERIAL_NO answer of
// the reader, creating it if needed. An empty serial makes the reader
// answer the unsupported feature error, like a device without a USB
// serial number.
func (s *Server) SetSerial(reader, serial string) {
	s.mu.Lock()
	if r, ok := s.readers[reader]; ok {
		r.Serial = serial
	} else {
		s.readers[reader] = &Reader{Serial: serial}
	}
	s.mu.Unlock()
}

// SetChannelID configures the SCARD_ATTR_CHANNEL_ID answer of the
// reader, creating it if needed. The value mirrors the CCID driver
// packing 0x0020<<16 | bus<<8 | device; zero disables the attribute.
func (s *Server) SetChannelID(reader string, id uint32) {
	s.mu.Lock()
	if r, ok := s.readers[reader]; ok {
		r.ChannelID = id
	} else {
		s.readers[reader] = &Reader{ChannelID: id}
	}
	s.mu.Unlock()
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
	// The daemon writes one 8 byte wait_reader_state_change struct
	// to every registered connection and drops it from the list, the
	// registration does not survive a signal.
	signal := encodeWait(waitMsg{})
	s.mu.Lock()
	for conn := range s.waiters {
		delete(s.waiters, conn)
		_, _ = conn.Write(signal)
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
	defer func() {
		s.mu.Lock()
		delete(s.waiters, conn)
		s.mu.Unlock()
	}()
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
		if len(body) != 12 {
			return true, fmt.Errorf("pcscfake: establish body %d bytes, want 12", len(body))
		}
		resp := make([]byte, 12)
		copy(resp[0:4], body[0:4]) // scope
		binary.LittleEndian.PutUint32(resp[4:], 1)
		// Responses are the raw struct, no message header.
		_, err := conn.Write(resp)
		return false, err

	case cmdReleaseContext:
		if len(body) != 8 {
			return true, fmt.Errorf("pcscfake: release body %d bytes, want 8", len(body))
		}
		_, err := conn.Write(body)
		return true, err

	case cmdGetReadersState:
		return false, s.writeStates(conn)

	case cmdWaitReaderStateChange:
		if s.OfferedMinor < 4 {
			// Protocol 4.3 and older: the request carries the 8 byte
			// wait struct, the daemon stays silent until a change.
			if len(body) != 8 {
				return true, fmt.Errorf("pcscfake: wait body %d bytes, want 8", len(body))
			}
			s.register(conn)
			return false, nil
		}
		// Protocol 4.4+: no request body, the daemon registers the
		// connection and immediately dumps the reader state array.
		if err := s.registerAndDump(conn); err != nil {
			return true, err
		}
		return false, nil

	case cmdStopWaitingReaderStateChange:
		if s.OfferedMinor < 4 && len(body) != 8 {
			return true, fmt.Errorf("pcscfake: stop body %d bytes, want 8", len(body))
		}
		// The response is sent only when the connection was still
		// registered, as in the daemon.
		if s.unregister(conn) {
			_, err := conn.Write(encodeWait(waitMsg{}))
			return false, err
		}
		return false, nil

	case cmdConnect:
		if len(body) != 152 {
			return true, fmt.Errorf("pcscfake: connect body %d bytes, want 152", len(body))
		}
		return false, s.connect(conn, body)

	case cmdTransmit:
		if len(body) != 32 {
			return true, fmt.Errorf("pcscfake: transmit body %d bytes, want 32", len(body))
		}
		return false, s.transmit(conn, body)

	case cmdGetAttrib:
		if len(body) != 8+maxAttrSz+8 {
			return true, fmt.Errorf("pcscfake: get attrib body %d bytes, want %d", len(body), 8+maxAttrSz+8)
		}
		return false, s.getAttrib(conn, body)

	case cmdDisconnect:
		if len(body) != 12 {
			return true, fmt.Errorf("pcscfake: disconnect body %d bytes, want 12", len(body))
		}
		s.mu.Lock()
		delete(s.cards, binary.LittleEndian.Uint32(body[0:4]))
		s.mu.Unlock()
		_, err := conn.Write(body)
		return false, err
	}
	return true, fmt.Errorf("pcscfake: unknown command 0x%02X", command)
}

// register adds conn to the reader state change waiter list.
func (s *Server) register(conn net.Conn) {
	s.mu.Lock()
	s.waiters[conn] = struct{}{}
	s.mu.Unlock()
}

// registerAndDump adds conn to the waiter list and answers with the
// full reader state array, both under the server lock: a change in
// between would signal before the dump and desync the client stream,
// the daemon serializes both through its client list lock the same
// way.
func (s *Server) registerAndDump(conn net.Conn) error {
	// The dump write itself must stay under the lock: releasing it
	// before the write would let wakeWaiters put the change signal on
	// the socket before the dump, desyncing the client stream.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waiters[conn] = struct{}{}
	buf := s.encodeStatesLocked()
	_, err := conn.Write(buf)
	return err
}

// unregister removes conn from the waiter list and reports whether
// it was registered.
func (s *Server) unregister(conn net.Conn) bool {
	s.mu.Lock()
	_, ok := s.waiters[conn]
	delete(s.waiters, conn)
	s.mu.Unlock()
	return ok
}

// writeStates answers with the raw 16 entry reader state array.
func (s *Server) writeStates(conn net.Conn) error {
	s.mu.Lock()
	buf := s.encodeStatesLocked()
	s.mu.Unlock()
	_, err := conn.Write(buf)
	return err
}

// encodeStatesLocked packs the current reader set into the fixed 16
// entry READER_STATE array, zero padded, sorted by reader name. The
// server lock must be held.
func (s *Server) encodeStatesLocked() []byte {
	buf := make([]byte, maxReaders*readerStateWireSz)
	for i, name := range slices.Sorted(maps.Keys(s.readers)) {
		if i >= maxReaders {
			break
		}
		encodeReaderStateInto(buf[i*readerStateWireSz:], name, s.readers[name])
	}
	return buf
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

// getAttrib answers a SCARD_GET_ATTRIB request with the raw 280 byte
// getset struct, the value embedded in the fixed buffer like the real
// daemon does. Only the vendor serial attribute is served, everything
// else answers the unsupported feature error, like a driver without
// that capability.
func (s *Server) getAttrib(conn net.Conn, body []byte) error {
	cardHandle := binary.LittleEndian.Uint32(body[0:4])
	attrID := binary.LittleEndian.Uint32(body[4:8])
	s.mu.Lock()
	var value []byte
	known := false
	if c, ok := s.cards[cardHandle]; ok {
		known = true
		switch {
		case attrID == attrVendorIFDSerialNo && c.reader.Serial != "":
			value = []byte(c.reader.Serial)
		case attrID == attrChannelID && c.reader.ChannelID != 0:
			value = make([]byte, 4)
			binary.LittleEndian.PutUint32(value, c.reader.ChannelID)
		}
	}
	s.mu.Unlock()
	var rv uint32
	switch {
	case !known:
		rv = errInvalidHandle
	case value == nil:
		rv = errUnsupportedFeature
	}
	resp := make([]byte, 8+maxAttrSz+8)
	binary.LittleEndian.PutUint32(resp[0:], cardHandle)
	binary.LittleEndian.PutUint32(resp[4:], attrID)
	copy(resp[8:], value)
	binary.LittleEndian.PutUint32(resp[8+maxAttrSz:], uint32(len(value)))
	binary.LittleEndian.PutUint32(resp[8+maxAttrSz+4:], rv)
	_, err := conn.Write(resp)
	return err
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
	if size > 1<<20 {
		return command, nil, fmt.Errorf("pcscfake: oversized message body %d", size)
	}
	body = make([]byte, size)
	if size > 0 {
		if _, err = io.ReadFull(r, body); err != nil {
			return command, nil, err
		}
	}
	return command, body, nil
}

func cString(b []byte) string {
	if before, _, ok := bytes.Cut(b, []byte{0}); ok {
		return string(before)
	}
	return string(b)
}
