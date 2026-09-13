//go:build linux

package pcsc

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

// dialTimeout bounds each connection attempt to a candidate socket.
const dialTimeout = 2 * time.Second

// commandTimeout bounds each request/response exchange except the
// reader state wait, which gets its own slack.
const commandTimeout = 30 * time.Second

// waitSlack is the deadline for draining the responses of a timed
// out reader state wait.
const waitSlack = 15 * time.Second

// waitMargin is added on top of a reader state wait timeout for the
// client side read deadline, to absorb scheduling delay.
const waitMargin = 100 * time.Millisecond

// defaultSockets are the pcscd daemon socket paths used on Unix
// systems, tried in order. PCSCLITE_CSOCK_NAME overrides them.
var defaultSockets = []string{
	"/run/pcscd/pcscd.comm",
	"/var/run/pcscd/pcscd.comm",
}

// ipcClient speaks the pcscd daemon wire protocol over a Unix stream
// socket. One connection carries one SCARDCONTEXT. It is driven by a
// single goroutine; Close may be called from another goroutine to
// unblock a pending WaitChange.
type ipcClient struct {
	conn    net.Conn
	context uint32
	major   uint32
	minor   uint32
	body    []byte // response body of the last exchange, single goroutine
	log     *slog.Logger
}

// dialIPC connects to a pcscd daemon socket, performs the version
// handshake and establishes the context.
func dialIPC(socketPath string, logger *slog.Logger) (*ipcClient, error) {
	var conn net.Conn
	var path string
	var lastErr error
	for _, candidate := range socketCandidates(socketPath) {
		c, err := net.DialTimeout("unix", candidate, dialTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		conn, path = c, candidate
		break
	}
	if conn == nil {
		return nil, fmt.Errorf("pcsc: pcscd socket unavailable: %w", lastErr)
	}
	cl := &ipcClient{conn: conn, log: logger}
	if err := cl.handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := cl.establish(); err != nil {
		conn.Close()
		return nil, err
	}
	logger.Debug("pcscd connected",
		"socket", path,
		"version", fmt.Sprintf("%d.%d", cl.major, cl.minor),
		"context", cl.context)
	return cl, nil
}

func socketCandidates(socketPath string) []string {
	if socketPath != "" {
		return []string{socketPath}
	}
	if env := os.Getenv("PCSCLITE_CSOCK_NAME"); env != "" {
		return []string{env}
	}
	return defaultSockets
}

// handshake exchanges the CMD_VERSION message, mirroring the
// downgrade retry of libpcsclite's SCardEstablishContext.
func (c *ipcClient) handshake() error {
	major := protocolVersionMajor
	minor := protocolVersionMinor
	for range 2 {
		req := versionMsg{major: major, minor: minor}
		if err := writeMessage(c.conn, cmdVersion, encodeVersion(req)); err != nil {
			return fmt.Errorf("pcsc: sending version: %w", err)
		}
		// The CMD_VERSION response is header-less, unlike every other
		// message: the framing is not agreed on before the version is.
		body, err := readRaw(c.conn, 12)
		if err != nil {
			return fmt.Errorf("pcsc: receiving version: %w", err)
		}
		resp := decodeVersion(body)
		if resp.rv == 0 {
			c.major, c.minor = resp.major, resp.minor
			return nil
		}
		if resp.rv == errServiceStopped &&
			resp.major == protocolVersionMajor &&
			resp.minor >= protocolVersionMinorBackward {
			// The daemon proposes an older minor, retry with it.
			major, minor = resp.major, resp.minor
			continue
		}
		return Error(resp.rv)
	}
	return Error(errServiceStopped)
}

// establish performs SCardEstablishContext on the negotiated context.
func (c *ipcClient) establish() error {
	req := establishMsg{scope: ScopeUser}
	if err := c.exchange(cmdEstablishContext, encodeEstablish(req), 12); err != nil {
		return err
	}
	resp := decodeEstablish(c.body)
	if resp.rv != 0 {
		return Error(resp.rv)
	}
	c.context = resp.context
	return nil
}

// exchange sends one framed request and reads back the response.
// The daemon answers with the raw message struct only, no message
// header: libpcsclite itself reads the expected struct size
// directly, so responses are read the same way here.
func (c *ipcClient) exchange(command uint32, body []byte, expectResp int) error {
	if err := c.setDeadline(commandTimeout); err != nil {
		return err
	}
	if err := writeMessage(c.conn, command, body); err != nil {
		return fmt.Errorf("pcsc: send 0x%02X: %w", command, err)
	}
	rspBody, err := readRaw(c.conn, expectResp)
	if err != nil {
		return fmt.Errorf("pcsc: receive 0x%02X: %w", command, err)
	}
	c.body = rspBody
	return nil
}

func (c *ipcClient) setDeadline(d time.Duration) error {
	return c.conn.SetDeadline(time.Now().Add(d))
}

func (c *ipcClient) states() ([]ReaderState, error) {
	if err := c.setDeadline(commandTimeout); err != nil {
		return nil, err
	}
	// CMD_GET_READERS_STATE has no request body and the daemon answers
	// with a raw array of exactly maxReaders READER_STATE entries,
	// zero padded, without a message header.
	if err := writeMessage(c.conn, cmdGetReadersState, nil); err != nil {
		return nil, fmt.Errorf("pcsc: send get readers state: %w", err)
	}
	raw, err := readRaw(c.conn, maxReaders*readerStateWireSz)
	if err != nil {
		return nil, fmt.Errorf("pcsc: receive readers state: %w", err)
	}
	states := make([]ReaderState, 0, maxReaders)
	for i := range maxReaders {
		entry := decodeReaderState(raw[i*readerStateWireSz:])
		if entry.Reader == "" {
			continue
		}
		states = append(states, entry)
	}
	return states, nil
}

// waitChange blocks until any reader state change occurs on the
// daemon. The wire format changed with protocol 4.4: pcsc-lite 1.8.24
// and 2.x daemons take no request body, answer the wait registration
// immediately with the complete reader state array and deliver a later
// change as a separate 8 byte struct, the timeout is client side,
// implemented through cmdStopWaitingReaderStateChange. Daemons of
// protocol 4.3 and older take an 8 byte timeout struct in the request
// and stay silent until a change happens or the client gives up.
func (c *ipcClient) waitChange(timeout time.Duration) error {
	if c.minor >= 4 {
		return c.waitChangeNew(timeout)
	}
	return c.waitChangeOld(timeout)
}

// waitChangeNew implements the protocol 4.4+ reader state wait. The
// daemon answers the registration itself with the full reader state
// array: that dump only confirms the registration, it is not the
// change signal. The signal is a separate 8 byte struct, delivered
// once a change actually happens. A client side timeout withdraws
// the registration with a stop request; exactly one 8 byte answer
// follows, either the stop response or a signal that raced it, so
// the stream stays in sync either way.
func (c *ipcClient) waitChangeNew(timeout time.Duration) error {
	if err := c.setDeadline(commandTimeout); err != nil {
		return err
	}
	// The request carries no body, the timeout is client side.
	if err := writeMessage(c.conn, cmdWaitReaderStateChange, nil); err != nil {
		return fmt.Errorf("pcsc: send wait: %w", err)
	}
	// Consume the registration dump, the states are fetched again
	// once a change is signaled.
	if _, err := readRaw(c.conn, maxReaders*readerStateWireSz); err != nil {
		return fmt.Errorf("pcsc: receive wait registration: %w", err)
	}
	if err := c.setDeadline(timeout + waitMargin); err != nil {
		return err
	}
	signal, err := readRaw(c.conn, 8)
	if err == nil {
		if rv := decodeWait(signal).rv; rv != 0 {
			return Error(rv)
		}
		return nil
	}
	if !isNetTimeout(err) {
		return fmt.Errorf("pcsc: receive wait signal: %w", err)
	}
	// The deadline fired: withdraw the registration. The one 8 byte
	// answer is the stop response or a racing signal; a swallowed
	// race is picked up by the states fetch of the next loop turn.
	if err := c.setDeadline(waitSlack); err != nil {
		return err
	}
	if err := writeMessage(c.conn, cmdStopWaitingReaderStateChange, nil); err != nil {
		return fmt.Errorf("pcsc: send stop wait: %w", err)
	}
	if signal, err := readRaw(c.conn, 8); err == nil {
		if rv := decodeWait(signal).rv; rv != 0 {
			return Error(rv)
		}
	}
	return ErrTimeout
}

// waitChangeOld implements the reader state wait of protocol 4.3 and
// older daemons: the request carries the 8 byte wait struct, the
// daemon stays silent until a change occurs and the timeout is
// enforced client side. A timed out registration is withdrawn with a
// stop request carrying the same struct, a leftover registration
// would duplicate the signal of the next one.
func (c *ipcClient) waitChangeOld(timeout time.Duration) error {
	ms := uint32(timeout.Milliseconds())
	if ms == 0 {
		ms = 1
	}
	req := encodeWait(waitMsg{timeoutMS: ms})
	if err := c.setDeadline(timeout + waitMargin); err != nil {
		return err
	}
	if err := writeMessage(c.conn, cmdWaitReaderStateChange, req); err != nil {
		return fmt.Errorf("pcsc: send wait: %w", err)
	}
	signal, err := readRaw(c.conn, 8)
	if err == nil {
		if rv := decodeWait(signal).rv; rv != 0 {
			return Error(rv)
		}
		return nil
	}
	if !isNetTimeout(err) {
		return fmt.Errorf("pcsc: receive wait: %w", err)
	}
	if err := c.setDeadline(waitSlack); err != nil {
		return err
	}
	if err := writeMessage(c.conn, cmdStopWaitingReaderStateChange, req); err != nil {
		return fmt.Errorf("pcsc: send stop wait: %w", err)
	}
	if signal, err := readRaw(c.conn, 8); err == nil {
		if rv := decodeWait(signal).rv; rv != 0 {
			return Error(rv)
		}
	}
	return ErrTimeout
}

func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (c *ipcClient) connect(reader string, preferred uint32) (*Card, error) {
	if len(reader) >= maxReaderName {
		return nil, fmt.Errorf("pcsc: reader name too long: %q", reader)
	}
	req := connectMsg{
		context:            c.context,
		reader:             reader,
		shareMode:          ShareShared,
		preferredProtocols: preferred,
	}
	if err := c.exchange(cmdConnect, encodeConnect(req), 152); err != nil {
		return nil, err
	}
	resp := decodeConnect(c.body)
	if resp.rv != 0 {
		return nil, Error(resp.rv)
	}
	return &Card{ipc: &ipcCard{client: c, handle: resp.card, protocol: resp.activeProtocol}}, nil
}

func (c *ipcClient) close() error {
	// Send the context release best effort: a daemon blocked in a
	// reader state wait for this connection will not read it until
	// the wait ends, so never wait for a response. For protocol 4.4+
	// a pending wait registration is withdrawn first, the daemon
	// only serves the next request once its wait returned. Closing
	// the socket is the real teardown and the cancellation path of a
	// blocked WaitChange.
	if c.minor >= 4 {
		_ = c.setDeadline(2 * time.Second)
		_ = writeMessage(c.conn, cmdStopWaitingReaderStateChange, nil)
	}
	_ = c.setDeadline(2 * time.Second)
	_ = writeMessage(c.conn, cmdReleaseContext, encodeRelease(releaseMsg{context: c.context}))
	return c.conn.Close()
}

// ipcCard is a SCardConnect handle inside an ipcClient connection.
type ipcCard struct {
	client   *ipcClient
	handle   uint32
	protocol uint32
}

func (c *ipcCard) transmit(apdu []byte, maxResp int) ([]byte, error) {
	if len(apdu) == 0 {
		return nil, fmt.Errorf("pcsc: empty apdu")
	}
	if maxResp <= 0 || maxResp > maxBufferSize {
		maxResp = maxBufferSize
	}
	req := transmitMsg{
		card:         c.handle,
		sendPciProto: c.protocol,
		sendPciLen:   8, // sizeof(SCARD_IO_REQUEST)
		sendLength:   uint32(len(apdu)),
		recvPciProto: c.protocol,
		recvPciLen:   8,
		recvLength:   uint32(maxResp),
	}
	if err := c.client.setDeadline(commandTimeout); err != nil {
		return nil, err
	}
	if err := writeMessage(c.client.conn, cmdTransmit, encodeTransmit(req)); err != nil {
		return nil, fmt.Errorf("pcsc: send transmit: %w", err)
	}
	if _, err := c.client.conn.Write(apdu); err != nil {
		return nil, fmt.Errorf("pcsc: send transmit buffer: %w", err)
	}
	// Responses carry no message header, the struct is followed by
	// the response buffer.
	rspBody, err := readRaw(c.client.conn, 32)
	if err != nil {
		return nil, fmt.Errorf("pcsc: receive transmit: %w", err)
	}
	resp := decodeTransmit(rspBody)
	if resp.rv != 0 {
		return nil, Error(resp.rv)
	}
	// A daemon must never answer with more than the short APDU
	// buffer, a larger length would be a protocol violation and must
	// not turn into a giant allocation.
	if resp.recvLength > maxBufferSize {
		return nil, fmt.Errorf("pcsc: transmit response length %d exceeds the %d byte short APDU buffer", resp.recvLength, maxBufferSize)
	}
	data, err := readRaw(c.client.conn, int(resp.recvLength))
	if err != nil {
		return nil, fmt.Errorf("pcsc: receive transmit buffer: %w", err)
	}
	return data, nil
}

func (c *ipcCard) disconnect(disposition uint32) error {
	req := disconnectMsg{card: c.handle, disposition: disposition}
	if err := c.client.exchange(cmdDisconnect, encodeDisconnect(req), 12); err != nil {
		return err
	}
	if resp := decodeDisconnect(c.client.body); resp.rv != 0 {
		return Error(resp.rv)
	}
	return nil
}
