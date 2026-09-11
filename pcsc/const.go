package pcsc

import "fmt"

// SCARD_* constants from pcsc-lite src/pcsclite.h.
const (
	ScopeUser uint32 = 0x0000

	ShareExclusive uint32 = 0x0001
	ShareShared    uint32 = 0x0002
	ShareDirect    uint32 = 0x0003

	ProtocolUndefined uint32 = 0x0000
	ProtocolT0        uint32 = 0x0001
	ProtocolT1        uint32 = 0x0002
	ProtocolRaw       uint32 = 0x0004
	// ProtocolAny is SCARD_PROTOCOL_ANY: let the reader driver pick
	// T=0 or T=1.
	ProtocolAny uint32 = ProtocolT0 | ProtocolT1

	LeaveCard uint32 = 0x0000
	ResetCard uint32 = 0x0001

	// Reader state bits as filled by the daemon in the reader state.
	ReaderAbsent    uint32 = 0x0002
	ReaderPresent   uint32 = 0x0004
	ReaderSwallowed uint32 = 0x0008
	ReaderPowered   uint32 = 0x0010
	ReaderSpecific  uint32 = 0x0040
)

// SCARD error codes from pcsc-lite src/pcsclite.h.
const (
	errCancelled         uint32 = 0x80100002
	errInvalidHandle     uint32 = 0x80100003
	errUnknownReader     uint32 = 0x80100009
	errTimeout           uint32 = 0x8010000A
	errSharingViolation  uint32 = 0x8010000B
	errNoSmartcard       uint32 = 0x8010000C
	errProtoMismatch     uint32 = 0x8010000F
	errReaderUnavailable uint32 = 0x80100017
	errNoService         uint32 = 0x8010001D
	errServiceStopped    uint32 = 0x8010001E
	errNoReaders         uint32 = 0x8010002E
	errCommDataLost      uint32 = 0x8010002F
)

// Limits from pcsc-lite src/pcsclite.h.
const (
	maxATRSize    = 33
	maxBufferSize = 264 // short APDU Tx/Rx buffer
)

var errorNames = map[uint32]string{
	errCancelled:         "SCARD_E_CANCELLED",
	errInvalidHandle:     "SCARD_E_INVALID_HANDLE",
	errUnknownReader:     "SCARD_E_UNKNOWN_READER",
	errTimeout:           "SCARD_E_TIMEOUT",
	errSharingViolation:  "SCARD_E_SHARING_VIOLATION",
	errNoSmartcard:       "SCARD_E_NO_SMARTCARD",
	errProtoMismatch:     "SCARD_E_PROTO_MISMATCH",
	errReaderUnavailable: "SCARD_E_READER_UNAVAILABLE",
	errNoService:         "SCARD_E_NO_SERVICE",
	errServiceStopped:    "SCARD_E_SERVICE_STOPPED",
	errNoReaders:         "SCARD_E_NO_READERS_AVAILABLE",
	errCommDataLost:      "SCARD_E_COMM_DATA_LOST",
}

// Error is a PC/SC error code as returned by pcscd or winscard.dll.
type Error uint32

// Error implements error.
func (e Error) Error() string {
	if name, ok := errorNames[uint32(e)]; ok {
		return "pcsc: " + name
	}
	return fmt.Sprintf("pcsc: error 0x%08X", uint32(e))
}

// ErrTimeout is returned by WaitChange when the timeout elapsed
// without any reader state change.
var ErrTimeout = Error(errTimeout)

// ErrProtoMismatch is returned by Connect when none of the requested
// protocols is supported by the card in use.
var ErrProtoMismatch = Error(errProtoMismatch)
