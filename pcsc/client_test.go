//go:build linux

package pcsc

import (
	"errors"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"paepcke.de/pcscid/internal/pcscfake"
)

func newTestClient(t *testing.T) (*Client, *pcscfake.Server) {
	t.Helper()
	fake, err := pcscfake.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	cl, err := New(fake.Addr(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	return cl, fake
}

func TestClientVersion(t *testing.T) {
	t.Parallel()
	cl, _ := newTestClient(t)
	major, minor := cl.ServerVersion()
	if major != 4 || minor != 4 {
		t.Errorf("server version = %d.%d, want 4.4", major, minor)
	}
}

func TestClientVersionDowngrade(t *testing.T) {
	t.Parallel()
	fake, err := pcscfake.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	fake.OfferedMinor = 2 // old daemon, proposes 4.2
	cl, err := New(fake.Addr(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	major, minor := cl.ServerVersion()
	if major != 4 || minor != 2 {
		t.Errorf("server version = %d.%d, want 4.2 after downgrade", major, minor)
	}
}

func TestClientStatesEmpty(t *testing.T) {
	t.Parallel()
	cl, _ := newTestClient(t)
	states, err := cl.States()
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Errorf("states = %v, want empty", states)
	}
}

// TestClientNilLogger pins the documented nil logger: New must accept it
// (it disables the protocol debug trace) instead of panicking on the
// first debug line of a successful connection.
func TestClientNilLogger(t *testing.T) {
	t.Parallel()
	fake, err := pcscfake.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	cl, err := New(fake.Addr(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	if _, err := cl.States(); err != nil {
		t.Fatalf("states: %v", err)
	}
}

func TestClientStatesWithCard(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClient(t)
	atr := []byte{0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x01, 0x94, 0x37, 0x26, 0xCB, 0x24}
	fake.InsertCard("ACS ACR122U 00 00", atr, []byte{0x04, 0x11, 0x22, 0x33})

	states, err := cl.States()
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 {
		t.Fatalf("states = %v, want one reader", states)
	}
	state := states[0]
	if state.Reader != "ACS ACR122U 00 00" {
		t.Errorf("reader = %q", state.Reader)
	}
	if state.State&ReaderPresent == 0 {
		t.Errorf("state = 0x%02X, want present bit", state.State)
	}
	if !slices.Equal(state.ATR, atr) {
		t.Errorf("atr = % X, want % X", state.ATR, atr)
	}
	if state.EventCounter != 1 {
		t.Errorf("eventCounter = %d, want 1", state.EventCounter)
	}
}

func TestClientWaitChangeWakesOnInsert(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClient(t)
	var wg sync.WaitGroup
	wg.Add(1)
	var waitErr error
	go func() {
		defer wg.Done()
		waitErr = cl.WaitChange(5 * time.Second)
	}()
	time.Sleep(50 * time.Millisecond)
	fake.InsertCard("Reader 0", []byte{0x3B, 0x00}, []byte{0x04})
	wg.Wait()
	if waitErr != nil {
		t.Errorf("WaitChange = %v, want nil on state change", waitErr)
	}
}

func TestClientWaitChangeTimeout(t *testing.T) {
	t.Parallel()
	cl, _ := newTestClient(t)
	start := time.Now()
	err := cl.WaitChange(50 * time.Millisecond)
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("WaitChange = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("WaitChange returned too early after %v", elapsed)
	}
}

// The protocol 4.3 and older wait carries an 8 byte request struct
// and stays silent until a change, mirroring pcsc-lite 1.8.20.
func newTestClientOldProtocol(t *testing.T) (*Client, *pcscfake.Server) {
	t.Helper()
	fake, err := pcscfake.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	fake.OfferedMinor = 2 // negotiated downgrade, old wait protocol
	cl, err := New(fake.Addr(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	return cl, fake
}

func TestClientWaitChangeWakesOnInsertOldProtocol(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClientOldProtocol(t)
	var wg sync.WaitGroup
	wg.Add(1)
	var waitErr error
	go func() {
		defer wg.Done()
		waitErr = cl.WaitChange(5 * time.Second)
	}()
	time.Sleep(50 * time.Millisecond)
	fake.InsertCard("Reader 0", []byte{0x3B, 0x00}, []byte{0x04})
	wg.Wait()
	if waitErr != nil {
		t.Errorf("WaitChange = %v, want nil on state change", waitErr)
	}
}

func TestClientWaitChangeTimeoutStaysInSyncOldProtocol(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClientOldProtocol(t)
	fake.InsertCard("R", []byte{0x3B, 0x00}, []byte{0x04})
	if _, err := cl.States(); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := cl.WaitChange(50 * time.Millisecond); !errors.Is(err, ErrTimeout) {
			t.Fatalf("wait %d = %v, want ErrTimeout", i, err)
		}
		states, err := cl.States()
		if err != nil {
			t.Fatalf("states after wait timeout %d: %v", i, err)
		}
		if len(states) != 1 {
			t.Fatalf("states after wait timeout %d = %d readers, want 1", i, len(states))
		}
	}
}

func TestClientConnectAndTransmitUID(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClient(t)
	uid := []byte{0x04, 0xA1, 0xB2, 0xC3}
	fake.InsertCard("ACS ACR122U 00 00", []byte{0x3B, 0x00}, uid)

	card, err := cl.Connect("ACS ACR122U 00 00", ProtocolAny)
	if err != nil {
		t.Fatal(err)
	}
	defer card.Disconnect(LeaveCard)
	if card.Protocol() != ProtocolT1 {
		t.Errorf("protocol = %d, want T=1", card.Protocol())
	}
	resp, err := card.Transmit([]byte{0xFF, 0xCA, 0x00, 0x00, 0x00}, 64)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), uid...), 0x90, 0x00)
	if !slices.Equal(resp, want) {
		t.Errorf("transmit = % X, want % X", resp, want)
	}
}

func TestClientTransmitUnsupportedAPDU(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClient(t)
	fake.InsertCard("R", []byte{0x3B, 0x00}, []byte{0x04})
	card, err := cl.Connect("R", ProtocolAny)
	if err != nil {
		t.Fatal(err)
	}
	defer card.Disconnect(LeaveCard)
	resp, err := card.Transmit([]byte{0x00, 0xA4, 0x04, 0x00}, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(resp, []byte{0x6D, 0x00}) {
		t.Errorf("transmit = % X, want 6D 00", resp)
	}
}

func TestClientTransmitAfterDisconnect(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClient(t)
	fake.InsertCard("R", []byte{0x3B, 0x00}, []byte{0x04})
	card, err := cl.Connect("R", ProtocolAny)
	if err != nil {
		t.Fatal(err)
	}
	if err := card.Disconnect(LeaveCard); err != nil {
		t.Fatal(err)
	}
	_, err = card.Transmit([]byte{0xFF, 0xCA, 0x00, 0x00, 0x00}, 64)
	if !errors.Is(err, Error(0x80100003)) { // SCARD_E_INVALID_HANDLE
		t.Errorf("transmit after disconnect = %v, want invalid handle", err)
	}
}

func TestClientConnectUnknownReader(t *testing.T) {
	t.Parallel()
	cl, _ := newTestClient(t)
	_, err := cl.Connect("does not exist", ProtocolAny)
	if !errors.Is(err, Error(0x80100009)) { // SCARD_E_UNKNOWN_READER
		t.Errorf("connect unknown reader = %v, want unknown reader", err)
	}
}

func TestClientConnectEmptyReader(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClient(t)
	fake.InsertCard("R", []byte{0x3B, 0x00}, []byte{0x04})
	fake.RemoveCard("R")
	_, err := cl.Connect("R", ProtocolAny)
	if !errors.Is(err, Error(0x8010000C)) { // SCARD_E_NO_SMARTCARD
		t.Errorf("connect empty reader = %v, want no smartcard", err)
	}
}

func TestClientCloseUnblocksWait(t *testing.T) {
	t.Parallel()
	cl, _ := newTestClient(t)
	result := make(chan error, 1)
	go func() {
		result <- cl.WaitChange(time.Minute)
	}()
	time.Sleep(50 * time.Millisecond)
	if err := cl.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Error("WaitChange = nil after Close, want transport error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitChange did not unblock within 5s after Close")
	}
}

func TestClientStatesAfterClose(t *testing.T) {
	t.Parallel()
	cl, _ := newTestClient(t)
	if err := cl.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.States(); err == nil {
		t.Error("States after Close = nil error, want transport error")
	}
}
