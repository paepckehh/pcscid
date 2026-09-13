package pcscid

import (
	"context"
	"log/slog"
	"regexp"
	"slices"
	"testing"
	"time"

	"paepcke.de/pcscid/internal/pcscfake"
	"paepcke.de/pcscid/pcsc"
)

var mifareATR = []byte{
	0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C,
	0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x01,
	0x94, 0x37, 0x26, 0xCB, 0x24,
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

func TestBtagProperties(t *testing.T) {
	t.Parallel()
	uidA := []byte{0x04, 0x11, 0x22, 0x33}
	uidB := []byte{0x04, 0x44, 0x55, 0x66}
	first := Btag("mifare classic 1k", uidA)
	if first != Btag("mifare classic 1k", uidA) {
		t.Error("Btag is not deterministic")
	}
	if Btag("mifare classic 1k", uidA) == Btag("mifare classic 1k", uidB) {
		t.Error("same type with different uids must produce different ids")
	}
	if Btag("type a", uidA) == Btag("type b", uidA) {
		t.Error("different types with the same uid must produce different ids")
	}
	if !regexp.MustCompile(`^[0-9a-z]{3}-[0-9a-z]{3}-[0-9a-z]{4}$`).MatchString(Btag("t", uidA)) {
		t.Errorf("Btag = %q, want xxx-xxx-xxxx lowercase alphanumeric", Btag("t", uidA))
	}
}

// TestBtagGolden pins the exact btag derivation. Btags are long lived
// identifiers stored by consumers, the digest must never change
// silently: any change here is a breaking release.
func TestBtagGolden(t *testing.T) {
	t.Parallel()
	golden := []struct {
		cardType string
		tag      []byte
		want     string
	}{
		{"mifare classic 1k", []byte{0x04, 0x11, 0x22, 0x33}, "r3v-401-5gmr"},
		{"unknown", nil, "szf-6lf-34qs"},
		{"german eid/passport (npa)", []byte{0x3B, 0x84, 0x80, 0x01, 0x80, 0x82, 0x90, 0x00, 0x97}, "wyo-gij-v6er"},
	}
	for _, g := range golden {
		if got := Btag(g.cardType, g.tag); got != g.want {
			t.Errorf("Btag(%q, % X) = %q, want %q", g.cardType, g.tag, got, g.want)
		}
	}
}

// TestReaderTagGolden pins the exact reader tag derivation for the
// same reason as TestBtagGolden.
func TestReaderTagGolden(t *testing.T) {
	t.Parallel()
	golden := []struct {
		reader string
		want   string
	}{
		{"ACS ACR122U 01 00 00", "qrx-lr"},
		{"SCM Microsystems Inc. SCL011", "nt1-ox"},
	}
	for _, g := range golden {
		if got := ReaderTag(g.reader); got != g.want {
			t.Errorf("ReaderTag(%q) = %q, want %q", g.reader, got, g.want)
		}
	}
}

func TestReaderTagProperties(t *testing.T) {
	t.Parallel()
	reader := "ACS ACR122U 00 00"
	first := ReaderTag(reader)
	if first != ReaderTag(reader) {
		t.Error("ReaderTag is not deterministic")
	}
	if ReaderTag("reader a") == ReaderTag("reader b") {
		t.Error("different readers must produce different tags")
	}
	if !regexp.MustCompile(`^[0-9a-z]{3}-[0-9a-z]{2}$`).MatchString(ReaderTag(reader)) {
		t.Errorf("ReaderTag = %q, want xxx-xx lowercase alphanumeric", ReaderTag(reader))
	}
}

func TestReaderTagStableAcrossHostsAndPorts(t *testing.T) {
	t.Parallel()
	same := []string{
		"ACS ACR122U 01 00 00",
		"ACS ACR122U 02 00 00",
		"ACS ACR122U 01 01 00",
		"ACS ACR122U",
	}
	want := ReaderTag(same[0])
	for _, name := range same[1:] {
		if got := ReaderTag(name); got != want {
			t.Errorf("ReaderTag(%q) = %s, want %s: hotplug suffix must not change the tag", name, got, want)
		}
	}
	if ReaderTag("ACS ACR122U") == ReaderTag("SCM Microsystems Inc. SCL011") {
		t.Error("different reader models must produce different tags")
	}
	if ReaderTag("") == "" {
		t.Error("empty reader name must still produce a tag")
	}
}

func TestBtagStableUnderAllConditions(t *testing.T) {
	t.Parallel()
	uid := []byte{0x04, 0xA1, 0xB2, 0xC3}
	// The same card on any reader, machine or daemon speaks the same
	// type (from the reader independent ATR) and the same UID: the btag
	// must be a pure function of those bytes and nothing else.
	if Btag("mifare classic 1k", uid) != Btag("mifare classic 1k", slices.Clone(uid)) {
		t.Error("Btag must not depend on the underlying uid slice")
	}
	if Btag("mifare classic 1k", uid) == Btag("mifare classic 4k", uid) {
		t.Error("card type must take part in the btag")
	}
	if Btag("mifare classic 1k", uid) == Btag("mifare classic 1k", []byte{0x04, 0xA1, 0xB2, 0xC4}) {
		t.Error("uid must take part in the btag")
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
	if card.ID != Btag("mifare classic 1k", uid) {
		t.Errorf("id = %q, want %q", card.ID, Btag("mifare classic 1k", uid))
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
	if ev.Card.ID != Btag("mifare classic 1k", mifareATR) {
		t.Errorf("id = %q, want atr derived id", ev.Card.ID)
	}
}

func TestWatchRandomUIDFallsBackToATR(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	events, _ := watchFake(t, fake)

	// ISO/IEC 14443-3 random uid: first byte 0x08, a new value on
	// every activation. It must not enter the identity, the btag
	// falls back to the ATR and stays stable across touches.
	fake.InsertCard("R", mifareATR, []byte{0x08, 0x11, 0x22, 0x33})
	first := receiveEvent(t, events, 3*time.Second)
	if first.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", first.Kind)
	}
	if first.Card.Source != "atr" {
		t.Errorf("source = %q, want atr", first.Card.Source)
	}
	if len(first.Card.UID) != 0 {
		t.Errorf("uid = % X, want empty for a random uid", first.Card.UID)
	}
	fake.RemoveCard("R")
	if ev := receiveEvent(t, events, 3*time.Second); ev.Kind != KindRemove {
		t.Fatalf("kind = %v, want remove", ev.Kind)
	}
	fake.InsertCard("R", mifareATR, []byte{0x08, 0xAA, 0xBB, 0xCC})
	second := receiveEvent(t, events, 3*time.Second)
	if second.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", second.Kind)
	}
	if second.Card.ID != first.Card.ID {
		t.Errorf("id changed with the random uid: %q then %q", first.Card.ID, second.Card.ID)
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

func TestWatchUnavailableWithoutPcscd(t *testing.T) {
	t.Parallel()
	_, err := Watch(t.Context(), &Options{
		SocketPath: "/nonexistent-pcscd-socket",
		Logger:     discardLogger(),
	})
	if err == nil {
		t.Fatal("Watch = nil error without pcscd")
	}
}

func TestWatchDaemonRestartDoesNotReReport(t *testing.T) {
	t.Parallel()
	first := newFake(t)
	uid := []byte{0x04, 0x11, 0x22, 0x33}
	first.InsertCard("R", mifareATR, uid)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	tracking := newTracking()
	ch := make(chan Event, 8)
	lg := discardLogger()

	clA, err := pcsc.New(first.Addr(), lg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clA.Close() })
	done := make(chan error, 1)
	go func() {
		done <- pollLoop(ctx, clA, tracking, lg, ch)
	}()
	ev := receiveEvent(t, ch, 3*time.Second)
	if ev.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", ev.Kind)
	}
	cancel()
	clA.Close() // unblocks the WaitChange inside pollLoop
	<-done

	// pcscd restarts: a fresh daemon counts events from zero again,
	// the card never moved and must not be reported a second time.
	second := newFake(t)
	second.InsertCard("R", mifareATR, uid)
	ctx2, cancel2 := context.WithCancel(t.Context())
	t.Cleanup(cancel2)
	clB, err := pcsc.New(second.Addr(), lg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clB.Close() })
	ch2 := make(chan Event, 8)
	done2 := make(chan error, 1)
	go func() {
		done2 <- pollLoop(ctx2, clB, tracking, lg, ch2)
	}()
	select {
	case ev := <-ch2:
		t.Fatalf("unexpected event %+v after daemon restart", ev)
	case <-time.After(750 * time.Millisecond):
	}
	cancel2()
	clB.Close() // unblocks the WaitChange inside pollLoop
	<-done2
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
