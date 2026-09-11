package pcscid

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"

	"paepcke.de/pcscid/internal/pcscfake"
)

var mifareATR = []byte{
	0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C,
	0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x6A,
}

func newFake(t *testing.T) *pcscfake.Server {
	t.Helper()
	fake, err := pcscfake.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	return fake
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func receiveEvent(t *testing.T, events <-chan Event, timeout time.Duration) Event {
	t.Helper()
	select {
	case ev, ok := <-events:
		if !ok {
			t.Fatal("event channel closed unexpectedly")
		}
		return ev
	case <-time.After(timeout):
		t.Fatalf("no event within %v", timeout)
		return Event{}
	}
}

func watchFake(t *testing.T, fake *pcscfake.Server) (<-chan Event, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	events, err := Watch(ctx, &Options{SocketPath: fake.Addr(), Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	return events, cancel
}

func TestShortIDProperties(t *testing.T) {
	t.Parallel()
	uidA := []byte{0x04, 0x11, 0x22, 0x33}
	uidB := []byte{0x04, 0x44, 0x55, 0x66}
	first := ShortID("mifare classic 1k", uidA)
	if first != ShortID("mifare classic 1k", uidA) {
		t.Error("ShortID is not deterministic")
	}
	if ShortID("mifare classic 1k", uidA) == ShortID("mifare classic 1k", uidB) {
		t.Error("same type with different uids must produce different ids")
	}
	if ShortID("type a", uidA) == ShortID("type b", uidA) {
		t.Error("different types with the same uid must produce different ids")
	}
	if !regexp.MustCompile(`^[0-9A-Za-z]{4}-[0-9A-Za-z]{3}-[0-9A-Za-z]{4}$`).MatchString(ShortID("t", uidA)) {
		t.Errorf("ShortID = %q, want xxxx-xxx-xxxx alphanumeric", ShortID("t", uidA))
	}
}

func TestWatchReportsPresentCardAtStart(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	uid := []byte{0x04, 0x11, 0x22, 0x33}
	fake.InsertCard("ACS ACR122U 00 00", mifareATR, uid)

	events, _ := watchFake(t, fake)
	ev := receiveEvent(t, events, 3*time.Second)
	if ev.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", ev.Kind)
	}
	card := ev.Card
	if card.ID != ShortID("mifare classic 1k", uid) {
		t.Errorf("id = %q, want %q", card.ID, ShortID("mifare classic 1k", uid))
	}
	if card.Type != "mifare classic 1k" {
		t.Errorf("type = %q", card.Type)
	}
	if !slices.Equal(card.UID, uid) {
		t.Errorf("uid = % X, want % X", card.UID, uid)
	}
	if !slices.Equal(card.ATR, mifareATR) {
		t.Errorf("atr = % X", card.ATR)
	}
	if card.Source != "uid" {
		t.Errorf("source = %q, want uid", card.Source)
	}
	if ev.Reader != "ACS ACR122U 00 00" {
		t.Errorf("reader = %q", ev.Reader)
	}
}

func TestWatchInsertRemoveStableID(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	events, _ := watchFake(t, fake)

	uid := []byte{0x04, 0x11, 0x22, 0x33}
	fake.InsertCard("R", mifareATR, uid)
	insert := receiveEvent(t, events, 3*time.Second)
	if insert.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", insert.Kind)
	}
	fake.RemoveCard("R")
	remove := receiveEvent(t, events, 3*time.Second)
	if remove.Kind != KindRemove {
		t.Fatalf("kind = %v, want remove", remove.Kind)
	}
	fake.InsertCard("R", mifareATR, uid)
	again := receiveEvent(t, events, 3*time.Second)
	if again.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", again.Kind)
	}
	if again.Card.ID != insert.Card.ID {
		t.Errorf("id changed across presentations: %q then %q", insert.Card.ID, again.Card.ID)
	}
}

func TestWatchDistinguishesSameTypeDifferentUID(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	events, _ := watchFake(t, fake)

	uidA := []byte{0x04, 0x11, 0x22, 0x33}
	uidB := []byte{0x04, 0xAA, 0xBB, 0xCC}
	fake.InsertCard("R", mifareATR, uidA)
	first := receiveEvent(t, events, 3*time.Second)
	if first.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", first.Kind)
	}
	fake.RemoveCard("R")
	if ev := receiveEvent(t, events, 3*time.Second); ev.Kind != KindRemove {
		t.Fatalf("kind = %v, want remove", ev.Kind)
	}
	fake.InsertCard("R", mifareATR, uidB)
	second := receiveEvent(t, events, 3*time.Second)
	if second.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", second.Kind)
	}
	if first.Card.Type != second.Card.Type {
		t.Errorf("types differ: %q vs %q", first.Card.Type, second.Card.Type)
	}
	if first.Card.ID == second.Card.ID {
		t.Errorf("two cards of the same type with different uids share id %q", first.Card.ID)
	}
	if !slices.Equal(second.Card.UID, uidB) {
		t.Errorf("uid = % X, want % X", second.Card.UID, uidB)
	}
}

func TestWatchFallsBackToATRWhenNoUID(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	events, _ := watchFake(t, fake)

	fake.InsertCard("R", mifareATR, nil) // card answers 63 00 to the uid probe
	ev := receiveEvent(t, events, 3*time.Second)
	if ev.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", ev.Kind)
	}
	if ev.Card.Source != "atr" {
		t.Errorf("source = %q, want atr", ev.Card.Source)
	}
	if len(ev.Card.UID) != 0 {
		t.Errorf("uid = % X, want empty", ev.Card.UID)
	}
	if ev.Card.ID != ShortID("mifare classic 1k", mifareATR) {
		t.Errorf("id = %q, want atr derived id", ev.Card.ID)
	}
}

func TestWatchNoRepeatWithoutChange(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	events, _ := watchFake(t, fake)

	fake.InsertCard("R", mifareATR, []byte{0x04, 0x01, 0x02, 0x03})
	insert := receiveEvent(t, events, 3*time.Second)
	if insert.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", insert.Kind)
	}
	// The card stays present: no further events may arrive, except
	// the removal when the test cleans up.
	select {
	case ev := <-events:
		t.Fatalf("unexpected event %+v for unchanged card", ev)
	case <-time.After(750 * time.Millisecond):
	}
}

func TestWatchReaderGoneEmitsRemove(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	events, _ := watchFake(t, fake)

	fake.InsertCard("R", mifareATR, []byte{0x04})
	insert := receiveEvent(t, events, 3*time.Second)
	if insert.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", insert.Kind)
	}
	fake.RemoveCard("R")
	remove := receiveEvent(t, events, 3*time.Second)
	if remove.Kind != KindRemove {
		t.Fatalf("kind = %v, want remove", remove.Kind)
	}
}

func TestWatchCancelClosesChannel(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	events, cancel := watchFake(t, fake)
	cancel()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("channel still delivering events after cancel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("channel not closed within 3s after cancel")
	}
}

func TestWatchScanFallback(t *testing.T) {
	t.Parallel()
	script := filepath.Join(t.TempDir(), "fake-pcsc_scan")
	content := "#!/bin/sh\n" +
		"printf ' Reader 0: ACS ACR122U 00 00\\n'\n" +
		"printf '  Card state: Card inserted,\\n'\n" +
		"printf '  ATR: 3B 84 80 01 80 82 90 00 97\\n'\n" +
		"printf 'ATR: 3B 84 80 01 80 82 90 00 97\\n'\n" +
		"sleep 30\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}

	events, err := Watch(t.Context(), &Options{
		SocketPath:  "/nonexistent-pcscd-socket",
		ScanCommand: script,
		Logger:      discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := receiveEvent(t, events, 3*time.Second)
	if ev.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", ev.Kind)
	}
	atr := mustHex(t, "3B8480018082900097")
	if ev.Card.Source != "scan" {
		t.Errorf("source = %q, want scan", ev.Card.Source)
	}
	if ev.Card.Type != "german eid/passport (npa)" {
		t.Errorf("type = %q", ev.Card.Type)
	}
	if ev.Card.ID != ShortID("german eid/passport (npa)", atr) {
		t.Errorf("id = %q", ev.Card.ID)
	}
	if !slices.Equal(ev.Card.ATR, atr) {
		t.Errorf("atr = % X, want % X", ev.Card.ATR, atr)
	}
}

func TestWatchUnavailableWithoutFallback(t *testing.T) {
	t.Parallel()
	_, err := Watch(t.Context(), &Options{
		SocketPath:  "/nonexistent-pcscd-socket",
		ScanCommand: "pcsc-scan-command-that-does-not-exist",
		Logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("Watch = nil error without pcscd and without pcsc_scan")
	}
}

func TestKindString(t *testing.T) {
	t.Parallel()
	if KindInsert.String() != "insert" || KindRemove.String() != "remove" {
		t.Errorf("kinds = %q, %q", KindInsert, KindRemove)
	}
	if Kind(200).String() == "insert" {
		t.Error("unknown kind renders as insert")
	}
}
