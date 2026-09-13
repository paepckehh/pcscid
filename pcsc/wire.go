//go:build linux

// Wire encoding of the pcscd daemon IPC protocol, as defined by
// pcsc-lite src/winscard_msg.h and src/readers.h.
package pcsc

import (
	"bytes"
	"encoding/binary"
	"io"
)

// PC/SC protocol version understood by this client. Modern daemons
// (protocol 4.4+) accept it, older 1.8.x daemons accept the
// negotiated downgrade performed by the handshake in ipc.go.
const (
	protocolVersionMajor         uint32 = 4
	protocolVersionMinor         uint32 = 4
	protocolVersionMinorBackward uint32 = 2 // oldest minor we can still talk to
)

// pcsc_msg_commands from pcsc-lite src/winscard_msg.h.
const (
	cmdEstablishContext      uint32 = 0x01
	cmdReleaseContext        uint32 = 0x02
	cmdConnect               uint32 = 0x04
	cmdDisconnect            uint32 = 0x06
	cmdTransmit              uint32 = 0x09
	cmdVersion               uint32 = 0x11
	cmdGetReadersState       uint32 = 0x12
	cmdWaitReaderStateChange uint32 = 0x13
	// cmdStopWaitingReaderStateChange unblocks a pending
	// cmdWaitReaderStateChange, it is the timeout and cancel path of
	// the protocol 4.4+ reader state wait.
	cmdStopWaitingReaderStateChange uint32 = 0x14
)

// IPC limits from pcsc-lite src/pcsclite.h.
const (
	maxReaderName     = 128
	maxReaders        = 16  // PCSCLITE_MAX_READERS_CONTEXTS
	readerStateWireSz = 184 // sizeof(READER_STATE) on little endian hosts
)

// writeMessage writes a [size][command][body] framed message.
func writeMessage(w io.Writer, command uint32, body []byte) error {
	buf := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint32(buf[0:], uint32(len(body)))
	binary.LittleEndian.PutUint32(buf[4:], command)
	copy(buf[8:], body)
	_, err := w.Write(buf)
	return err
}

// readRaw reads a fixed size, header-less response body. The daemon
// answers every command with the raw message struct, without the
// [size][command] frame of a request.
func readRaw(r io.Reader, size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// versionMsg is struct version_struct: 12 bytes on the wire.
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

// establishMsg is struct establish_struct: 12 bytes.
type establishMsg struct {
	scope   uint32
	context uint32
	rv      uint32
}

func encodeEstablish(e establishMsg) []byte {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[0:], e.scope)
	binary.LittleEndian.PutUint32(buf[4:], e.context)
	binary.LittleEndian.PutUint32(buf[8:], e.rv)
	return buf
}

func decodeEstablish(b []byte) establishMsg {
	return establishMsg{
		scope:   binary.LittleEndian.Uint32(b[0:4]),
		context: binary.LittleEndian.Uint32(b[4:8]),
		rv:      binary.LittleEndian.Uint32(b[8:12]),
	}
}

// releaseMsg is struct release_struct: 8 bytes.
type releaseMsg struct {
	context uint32
	rv      uint32
}

func encodeRelease(r releaseMsg) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:], r.context)
	binary.LittleEndian.PutUint32(buf[4:], r.rv)
	return buf
}

func decodeRelease(b []byte) releaseMsg {
	return releaseMsg{
		context: binary.LittleEndian.Uint32(b[0:4]),
		rv:      binary.LittleEndian.Uint32(b[4:8]),
	}
}

// connectMsg is struct connect_struct: 152 bytes.
//
//	uint32 hContext; char szReader[128]; uint32 dwShareMode;
//	uint32 dwPreferredProtocols; int32 hCard; uint32 dwActiveProtocol;
//	uint32 rv;
type connectMsg struct {
	context            uint32
	reader             string
	shareMode          uint32
	preferredProtocols uint32
	card               uint32
	activeProtocol     uint32
	rv                 uint32
}

func encodeConnect(c connectMsg) []byte {
	buf := make([]byte, 152)
	binary.LittleEndian.PutUint32(buf[0:], c.context)
	copy(buf[4:], c.reader)
	binary.LittleEndian.PutUint32(buf[132:], c.shareMode)
	binary.LittleEndian.PutUint32(buf[136:], c.preferredProtocols)
	binary.LittleEndian.PutUint32(buf[140:], c.card)
	binary.LittleEndian.PutUint32(buf[144:], c.activeProtocol)
	binary.LittleEndian.PutUint32(buf[148:], c.rv)
	return buf
}

func decodeConnect(b []byte) connectMsg {
	return connectMsg{
		context:            binary.LittleEndian.Uint32(b[0:4]),
		reader:             cString(b[4:132]),
		shareMode:          binary.LittleEndian.Uint32(b[132:136]),
		preferredProtocols: binary.LittleEndian.Uint32(b[136:140]),
		card:               binary.LittleEndian.Uint32(b[140:144]),
		activeProtocol:     binary.LittleEndian.Uint32(b[144:148]),
		rv:                 binary.LittleEndian.Uint32(b[148:152]),
	}
}

// disconnectMsg is struct disconnect_struct: 12 bytes.
type disconnectMsg struct {
	card        uint32
	disposition uint32
	rv          uint32
}

func encodeDisconnect(d disconnectMsg) []byte {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[0:], d.card)
	binary.LittleEndian.PutUint32(buf[4:], d.disposition)
	binary.LittleEndian.PutUint32(buf[8:], d.rv)
	return buf
}

func decodeDisconnect(b []byte) disconnectMsg {
	return disconnectMsg{
		card:        binary.LittleEndian.Uint32(b[0:4]),
		disposition: binary.LittleEndian.Uint32(b[4:8]),
		rv:          binary.LittleEndian.Uint32(b[8:12]),
	}
}

// transmitMsg is struct transmit_struct: 32 bytes.
type transmitMsg struct {
	card         uint32
	sendPciProto uint32
	sendPciLen   uint32
	sendLength   uint32
	recvPciProto uint32
	recvPciLen   uint32
	recvLength   uint32
	rv           uint32
}

func encodeTransmit(t transmitMsg) []byte {
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint32(buf[0:], t.card)
	binary.LittleEndian.PutUint32(buf[4:], t.sendPciProto)
	binary.LittleEndian.PutUint32(buf[8:], t.sendPciLen)
	binary.LittleEndian.PutUint32(buf[12:], t.sendLength)
	binary.LittleEndian.PutUint32(buf[16:], t.recvPciProto)
	binary.LittleEndian.PutUint32(buf[20:], t.recvPciLen)
	binary.LittleEndian.PutUint32(buf[24:], t.recvLength)
	binary.LittleEndian.PutUint32(buf[28:], t.rv)
	return buf
}

func decodeTransmit(b []byte) transmitMsg {
	return transmitMsg{
		card:         binary.LittleEndian.Uint32(b[0:4]),
		sendPciProto: binary.LittleEndian.Uint32(b[4:8]),
		sendPciLen:   binary.LittleEndian.Uint32(b[8:12]),
		sendLength:   binary.LittleEndian.Uint32(b[12:16]),
		recvPciProto: binary.LittleEndian.Uint32(b[16:20]),
		recvPciLen:   binary.LittleEndian.Uint32(b[20:24]),
		recvLength:   binary.LittleEndian.Uint32(b[24:28]),
		rv:           binary.LittleEndian.Uint32(b[28:32]),
	}
}

// waitMsg is struct wait_reader_state_change: 8 bytes.
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

func decodeWait(b []byte) waitMsg {
	return waitMsg{
		timeoutMS: binary.LittleEndian.Uint32(b[0:4]),
		rv:        binary.LittleEndian.Uint32(b[4:8]),
	}
}

// decodeReaderState unpacks the on-wire READER_STATE layout from
// pcsc-lite src/readers.h, 184 bytes little endian:
//
//	char readerName[128]; uint32 eventCounter; uint32 readerState;
//	uint32 readerSharing; unsigned char cardAtr[33]; (pad 3)
//	uint32 cardAtrLength; uint32 cardProtocol;
func decodeReaderState(buf []byte) ReaderState {
	atrLen := int(binary.LittleEndian.Uint32(buf[176:180]))
	if atrLen > maxATRSize {
		atrLen = 0
	}
	atr := make([]byte, atrLen)
	copy(atr, buf[140:140+atrLen])
	return ReaderState{
		Reader:       cString(buf[0:128]),
		EventCounter: binary.LittleEndian.Uint32(buf[128:132]),
		State:        binary.LittleEndian.Uint32(buf[132:136]),
		ATR:          atr,
		Protocol:     binary.LittleEndian.Uint32(buf[180:184]),
	}
}

func cString(b []byte) string {
	if before, _, ok := bytes.Cut(b, []byte{0}); ok {
		return string(before)
	}
	return string(b)
}
