// Package pcsc implements a pure Go client for the pcscd IPC
// protocol on Linux.
//
// It speaks the same wire protocol as libpcsclite over the pcscd
// daemon Unix domain socket, without cgo and without linking
// libpcsclite.
package pcsc

import (
	"log/slog"
	"time"
)

// ReaderState is one entry of the reader state array of the resource
// manager.
type ReaderState struct {
	Reader       string
	EventCounter uint32
	State        uint32 // SCARD_* reader state bit field
	ATR          []byte
	Protocol     uint32
}

// Client is a connection to the local smart card resource manager
// pcscd.
//
// A Client is not safe for concurrent use: drive it from a single
// goroutine. Close is the exception, it may be called from another
// goroutine to unblock a pending WaitChange.
type Client struct {
	backend backend
}

// Card is an open connection to a card in a reader.
type Card struct {
	backend  cardBackend
	protocol uint32
}

// Protocol returns the active protocol of the card
// (ProtocolT0, ProtocolT1 or ProtocolRaw).
func (c *Card) Protocol() uint32 {
	return c.protocol
}

type backend interface {
	version() (major, minor uint32)
	states() ([]ReaderState, error)
	waitChange(timeout time.Duration) error
	connect(reader string, preferred uint32) (*Card, error)
	close() error
}

type cardBackend interface {
	transmit(apdu []byte, maxResp int) ([]byte, error)
	disconnect(disposition uint32) error
}

// New connects to the local smart card resource manager. An empty
// socketPath selects the default, the PCSCLITE_CSOCK_NAME
// environment variable overrides it. A nil logger disables
// protocol debug logging.
func New(socketPath string, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	be, err := newBackend(socketPath, logger)
	if err != nil {
		return nil, err
	}
	return &Client{backend: be}, nil
}

// ServerVersion reports the protocol version of the daemon in use.
func (c *Client) ServerVersion() (major, minor uint32) {
	return c.backend.version()
}

// States returns the current state of all registered readers, including
// the ATR of a present card. It never blocks.
func (c *Client) States() ([]ReaderState, error) {
	return c.backend.states()
}

// WaitChange blocks until any reader state change occurs on the daemon
// or the timeout elapses, in which case ErrTimeout is returned. A
// return without ErrTimeout is only a hint: callers are expected to
// call States afterwards.
func (c *Client) WaitChange(timeout time.Duration) error {
	return c.backend.waitChange(timeout)
}

// Connect opens a connection to the card currently present in reader.
// The share mode is shared and preferred selects the protocols to
// negotiate, usually ProtocolAny. On success the card must be
// disconnected when done.
func (c *Client) Connect(reader string, preferred uint32) (*Card, error) {
	return c.backend.connect(reader, preferred)
}

// Close releases the context and the underlying transport.
func (c *Client) Close() error {
	return c.backend.close()
}

// Transmit sends one APDU to the card and returns the raw response
// including the status words. maxResp caps the expected response size,
// 0 selects the default short APDU buffer.
func (c *Card) Transmit(apdu []byte, maxResp int) ([]byte, error) {
	return c.backend.transmit(apdu, maxResp)
}

// Disconnect closes the card connection using the given disposition
// (LeaveCard or ResetCard).
func (c *Card) Disconnect(disposition uint32) error {
	return c.backend.disconnect(disposition)
}
