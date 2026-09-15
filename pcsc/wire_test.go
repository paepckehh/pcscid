//go:build linux

package pcsc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestWriteMessageFraming(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := writeMessage(&buf, cmdVersion, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	want := []byte{3, 0, 0, 0, 0x11, 0, 0, 0, 1, 2, 3}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("writeMessage = % X, want % X", buf.Bytes(), want)
	}
}

func TestWriteMessageEmptyBody(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := writeMessage(&buf, cmdGetReadersState, nil); err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 0, 0x12, 0, 0, 0}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("writeMessage = % X, want % X", buf.Bytes(), want)
	}
}

func TestVersionCodecGolden(t *testing.T) {
	t.Parallel()
	got := encodeVersion(versionMsg{major: 4, minor: 4})
	want := []byte{4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(got, want) {
		t.Errorf("encodeVersion = % X, want % X", got, want)
	}
	decoded := decodeVersion([]byte{4, 0, 0, 0, 2, 0, 0, 0, 0x1E, 0x00, 0x10, 0x80})
	if decoded.major != 4 || decoded.minor != 2 || decoded.rv != 0x8010001E {
		t.Errorf("decodeVersion = %+v", decoded)
	}
}

func TestConnectCodecOffsets(t *testing.T) {
	t.Parallel()
	msg := connectMsg{
		context:            0x01020304,
		reader:             "ACS ACR122U 00 00",
		shareMode:          ShareShared,
		preferredProtocols: ProtocolAny,
		card:               7,
		activeProtocol:     ProtocolT1,
		rv:                 0,
	}
	encoded := encodeConnect(msg)
	if len(encoded) != 152 {
		t.Fatalf("encoded size = %d, want 152", len(encoded))
	}
	if got := binary.LittleEndian.Uint32(encoded[0:4]); got != msg.context {
		t.Errorf("context = 0x%08X, want 0x%08X", got, msg.context)
	}
	if got := cString(encoded[4:132]); got != msg.reader {
		t.Errorf("reader = %q, want %q", got, msg.reader)
	}
	if got := binary.LittleEndian.Uint32(encoded[132:136]); got != ShareShared {
		t.Errorf("shareMode = %d, want %d", got, ShareShared)
	}
	if got := binary.LittleEndian.Uint32(encoded[136:140]); got != ProtocolAny {
		t.Errorf("preferredProtocols = %d, want %d", got, ProtocolAny)
	}
	if got := binary.LittleEndian.Uint32(encoded[140:144]); got != 7 {
		t.Errorf("card = %d, want 7", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[144:148]); got != ProtocolT1 {
		t.Errorf("activeProtocol = %d, want %d", got, ProtocolT1)
	}
	if got := binary.LittleEndian.Uint32(encoded[148:152]); got != 0 {
		t.Errorf("rv = %d, want 0", got)
	}
	decoded := decodeConnect(encoded)
	if decoded.reader != msg.reader || decoded.card != 7 {
		t.Errorf("decodeConnect = %+v", decoded)
	}
}

func TestTransmitCodecOffsets(t *testing.T) {
	t.Parallel()
	msg := transmitMsg{
		card:         9,
		sendPciProto: ProtocolT1,
		sendPciLen:   8,
		sendLength:   5,
		recvPciProto: ProtocolT1,
		recvPciLen:   8,
		recvLength:   64,
	}
	encoded := encodeTransmit(msg)
	if len(encoded) != 32 {
		t.Fatalf("encoded size = %d, want 32", len(encoded))
	}
	if got := binary.LittleEndian.Uint32(encoded[12:16]); got != 5 {
		t.Errorf("sendLength = %d, want 5", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[24:28]); got != 64 {
		t.Errorf("recvLength = %d, want 64", got)
	}
	decoded := decodeTransmit(encoded)
	if decoded != msg {
		t.Errorf("decodeTransmit = %+v, want %+v", decoded, msg)
	}
}

func TestGetsetCodecOffsets(t *testing.T) {
	t.Parallel()
	msg := getsetMsg{
		card:    9,
		attrID:  AttrVendorIFDSerialNo,
		attr:    []byte("A123456789"),
		attrLen: 10,
	}
	encoded := encodeGetset(msg)
	if len(encoded) != 280 {
		t.Fatalf("encoded size = %d, want 280", len(encoded))
	}
	if got := binary.LittleEndian.Uint32(encoded[0:4]); got != 9 {
		t.Errorf("card = %d, want 9", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[4:8]); got != AttrVendorIFDSerialNo {
		t.Errorf("attrID = 0x%08X, want 0x%08X", got, AttrVendorIFDSerialNo)
	}
	if got := encoded[8:18]; !bytes.Equal(got, []byte("A123456789")) {
		t.Errorf("attr = %q, want the serial", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[272:276]); got != 10 {
		t.Errorf("attrLen = %d, want 10", got)
	}
	decoded := decodeGetset(encoded)
	if decoded.card != 9 || decoded.attrID != AttrVendorIFDSerialNo || decoded.attrLen != 10 {
		t.Errorf("decodeGetset = %+v", decoded)
	}
	if !bytes.Equal(decoded.attr, []byte("A123456789")) {
		t.Errorf("decoded attr = %q, want the serial", decoded.attr)
	}
}

// A daemon claiming more than the fixed attribute buffer must not leak
// into a slice bound, the length is clamped to empty.
func TestDecodeGetsetClampsOversizedLength(t *testing.T) {
	t.Parallel()
	encoded := encodeGetset(getsetMsg{card: 1, attrID: 2})
	binary.LittleEndian.PutUint32(encoded[272:276], 999)
	if got := decodeGetset(encoded); len(got.attr) != 0 {
		t.Errorf("attr = % X, want empty for a clamped length", got.attr)
	}
}

func TestSmallCodecRoundtrips(t *testing.T) {
	t.Parallel()
	if got := decodeEstablish(encodeEstablish(establishMsg{scope: ScopeUser, context: 3})); got.context != 3 {
		t.Errorf("establish roundtrip = %+v", got)
	}
	if got := decodeRelease(encodeRelease(releaseMsg{context: 3})); got.context != 3 {
		t.Errorf("release roundtrip = %+v", got)
	}
	if got := decodeDisconnect(encodeDisconnect(disconnectMsg{card: 4, disposition: ResetCard})); got.disposition != ResetCard {
		t.Errorf("disconnect roundtrip = %+v", got)
	}
	if got := decodeWait(encodeWait(waitMsg{timeoutMS: 1000})); got.timeoutMS != 1000 {
		t.Errorf("wait roundtrip = %+v", got)
	}
}

func TestDecodeReaderState(t *testing.T) {
	t.Parallel()
	buf := make([]byte, readerStateWireSz)
	copy(buf[0:], "ACS ACR122U 00 00")
	binary.LittleEndian.PutUint32(buf[128:], 7)
	binary.LittleEndian.PutUint32(buf[132:], 0x74)
	atr := []byte{0x3B, 0x84, 0x80, 0x01}
	copy(buf[140:], atr)
	binary.LittleEndian.PutUint32(buf[176:], uint32(len(atr)))
	binary.LittleEndian.PutUint32(buf[180:], ProtocolT1)

	got := decodeReaderState(buf)
	if got.Reader != "ACS ACR122U 00 00" {
		t.Errorf("reader = %q", got.Reader)
	}
	if got.EventCounter != 7 {
		t.Errorf("eventCounter = %d, want 7", got.EventCounter)
	}
	if got.State != 0x74 {
		t.Errorf("state = 0x%02X, want 0x74", got.State)
	}
	if !bytes.Equal(got.ATR, atr) {
		t.Errorf("atr = % X, want % X", got.ATR, atr)
	}
	if got.Protocol != ProtocolT1 {
		t.Errorf("protocol = %d, want %d", got.Protocol, ProtocolT1)
	}
}

func TestDecodeReaderStateBadATRLength(t *testing.T) {
	t.Parallel()
	buf := make([]byte, readerStateWireSz)
	copy(buf[0:], "R")
	binary.LittleEndian.PutUint32(buf[176:], 999) // clamped to empty
	if got := decodeReaderState(buf); len(got.ATR) != 0 {
		t.Errorf("atr = % X, want empty", got.ATR)
	}
}

func TestErrorMessage(t *testing.T) {
	t.Parallel()
	if got := Error(errTimeout).Error(); got != "pcsc: SCARD_E_TIMEOUT" {
		t.Errorf("Error(errTimeout) = %q", got)
	}
	if got := Error(0x12345678).Error(); got != "pcsc: error 0x12345678" {
		t.Errorf("Error(0x12345678) = %q", got)
	}
	if !errors.Is(ErrTimeout, Error(errTimeout)) {
		t.Error("ErrTimeout does not match itself")
	}
	if !errors.Is(ErrProtoMismatch, Error(errProtoMismatch)) {
		t.Error("ErrProtoMismatch does not match itself")
	}
}

func TestCString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"terminated", []byte{'A', 'B', 0, 'C'}, "AB"},
		{"unterminated", []byte{'A', 'B'}, "AB"},
		{"empty", []byte{0}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := cString(tt.in); got != tt.want {
				t.Errorf("cString(% X) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
