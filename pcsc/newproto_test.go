//go:build linux

package pcsc

import (
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"paepcke.de/pcscid/internal/pcscfake"
)

// The protocol 4.4+ wait carries no request body, the daemon answers
// the registration itself with the reader state array and signals a
// later change as a separate 8 byte struct, timeouts are client
// side. These tests drive it against a fake pcscd 2.x daemon, the
// wire behaviour mirrors pcsc-lite 1.8.24 through 2.4.1.

func newTestClientNewProtocol(t *testing.T) (*Client, *pcscfake.Server) {
	t.Helper()
	fake, err := pcscfake.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	fake.OfferedMinor = 5
	cl, err := New(fake.Addr(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	return cl, fake
}

func TestClientVersionNewProtocol(t *testing.T) {
	t.Parallel()
	cl, _ := newTestClientNewProtocol(t)
	major, minor := cl.ServerVersion()
	if major != 4 || minor != 5 {
		t.Errorf("server version = %d.%d, want 4.5", major, minor)
	}
}

func TestClientStatesNewProtocol(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClientNewProtocol(t)
	fake.InsertCard("ACS ACR122U 00 00", []byte{0x3B, 0x00}, []byte{0x04, 0x01, 0x02, 0x03})
	states, err := cl.States()
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].State&ReaderPresent == 0 {
		t.Errorf("states = %+v, want one present reader", states)
	}
}

func TestClientWaitChangeNewProtocolWakesOnInsert(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClientNewProtocol(t)
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

// The daemon answers the wait registration immediately with the
// reader state array. WaitChange must still block for the timeout
// instead of mistaking that dump for a change: that bug returned
// instantly and spun the watch loop at full speed.
func TestClientWaitChangeNewProtocolBlocksForTimeout(t *testing.T) {
	t.Parallel()
	cl, _ := newTestClientNewProtocol(t)
	start := time.Now()
	if err := cl.WaitChange(150 * time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Errorf("WaitChange = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("WaitChange returned after %v, want it to block", elapsed)
	}
}

func TestClientWaitChangeNewProtocolTimeoutStaysInSync(t *testing.T) {
	t.Parallel()
	cl, fake := newTestClientNewProtocol(t)
	fake.InsertCard("R", []byte{0x3B, 0x00}, []byte{0x04})
	if _, err := cl.States(); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := cl.WaitChange(50 * time.Millisecond); !errors.Is(err, ErrTimeout) {
			t.Fatalf("wait %d = %v, want ErrTimeout", i, err)
		}
		// The timeout path must leave the connection in sync: a
		// follow up states call still answers correctly.
		states, err := cl.States()
		if err != nil {
			t.Fatalf("states after wait timeout %d: %v", i, err)
		}
		if len(states) != 1 {
			t.Fatalf("states after wait timeout %d = %d readers, want 1", i, len(states))
		}
	}
}

func TestClientCloseUnblocksWaitNewProtocol(t *testing.T) {
	t.Parallel()
	cl, _ := newTestClientNewProtocol(t)
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
