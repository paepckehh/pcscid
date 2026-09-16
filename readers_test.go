package pcscid

import (
	"slices"
	"testing"
	"time"
)

// TestIdentifyReadersEmptyInventory pins the startup behavior with no
// reader registered: an empty inventory, not an error.
func TestIdentifyReadersEmptyInventory(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	readers, err := IdentifyReaders(&Options{SocketPath: fake.Addr(), Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 0 {
		t.Errorf("readers = %v, want empty", readers)
	}
}

// TestIdentifyReadersCardPresent proves the full evaluation: a reader
// with a presented card reports the probed serial, the serial tier tag
// and the identification of the card itself.
func TestIdentifyReadersCardPresent(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	uid := []byte{0x04, 0x11, 0x22, 0x33}
	fake.InsertCard("ACS ACR122U 01 00 00", mifareATR, uid)
	fake.SetSerial("ACS ACR122U 01 00 00", "A001")

	readers, err := IdentifyReaders(&Options{SocketPath: fake.Addr(), Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 1 {
		t.Fatalf("readers = %d, want 1", len(readers))
	}
	r := readers[0]
	if r.Reader != "ACS ACR122U 01 00 00" {
		t.Errorf("reader = %q", r.Reader)
	}
	if !r.CardPresent || r.Card == nil {
		t.Fatal("present card not evaluated")
	}
	if r.Serial != "A001" {
		t.Errorf("serial = %q, want the probed A001", r.Serial)
	}
	if r.Tier != "serial" {
		t.Errorf("tier = %q, want serial", r.Tier)
	}
	if r.ModelTag != ReaderTag(r.Reader) {
		t.Errorf("model tag = %q, want %q", r.ModelTag, ReaderTag(r.Reader))
	}
	if r.Tag != ReaderTagWithSerial(r.Reader, r.Serial) {
		t.Errorf("tag = %q, want %q", r.Tag, ReaderTagWithSerial(r.Reader, r.Serial))
	}
	if r.Card.ID != Btag("mifare classic 1k", uid) {
		t.Errorf("card id = %q, want the uid derived btag", r.Card.ID)
	}
	if r.Card.Source != "uid" {
		t.Errorf("card source = %q, want uid", r.Card.Source)
	}
}

// TestIdentifyReadersNoCardModelTier documents the limitation: without
// a presented card the unit facts cannot be probed, the reader reports
// the model level tier and tag.
func TestIdentifyReadersNoCardModelTier(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	fake.SetSerial("ACS ACR122U 00 00", "A001")

	readers, err := IdentifyReaders(&Options{SocketPath: fake.Addr(), Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 1 {
		t.Fatalf("readers = %d, want 1", len(readers))
	}
	r := readers[0]
	if r.CardPresent || r.Card != nil {
		t.Fatal("card reported without one")
	}
	if r.Serial != "" || r.Port != "" {
		t.Errorf("unit facts = %q/%q, want empty without a card to probe with", r.Serial, r.Port)
	}
	if r.Tier != "model" {
		t.Errorf("tier = %q, want model", r.Tier)
	}
	if r.Tag != r.ModelTag {
		t.Errorf("tag = %q, want the model tag %q", r.Tag, r.ModelTag)
	}
}

// TestIdentifyReadersMatchesWatchEvents pins the promise of the
// startup inventory: the reported Tag is exactly the tag the
// reader's insertion events carry under the same options.
func TestIdentifyReadersMatchesWatchEvents(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	events, _ := watchFake(t, fake)
	fake.InsertCard("ACS ACR122U 01 00 00", mifareATR, []byte{0x04, 0x11, 0x22, 0x33})
	fake.SetSerial("ACS ACR122U 01 00 00", "A001")
	ev := receiveEvent(t, events, 3*time.Second)

	readers, err := IdentifyReaders(&Options{SocketPath: fake.Addr(), Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 1 {
		t.Fatalf("readers = %d, want 1", len(readers))
	}
	if readers[0].Tag != ev.ReaderTag {
		t.Errorf("inventory tag = %q, event tag = %q, they must match", readers[0].Tag, ev.ReaderTag)
	}
	if readers[0].Card.ID != ev.Card.ID {
		t.Errorf("inventory card = %q, event card = %q, they must match", readers[0].Card.ID, ev.Card.ID)
	}
}

// TestIdentifyReadersMACID proves the machine component is honored:
// with MACID the inventory tag equals the machine scoped tag.
func TestIdentifyReadersMACID(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	fake.InsertCard("ACS ACR122U 01 00 00", mifareATR, []byte{0x04, 0x11, 0x22, 0x33})

	readers, err := IdentifyReaders(&Options{
		SocketPath: fake.Addr(),
		Logger:     discardLogger(),
		MACID:      true,
		MachineID:  "aa:bb:cc:dd:ee:ff",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 1 {
		t.Fatalf("readers = %d, want 1", len(readers))
	}
	want := ReaderTagWithMachine(readers[0].Reader, readers[0].Serial, readers[0].Port, "aa:bb:cc:dd:ee:ff")
	if readers[0].Tag != want {
		t.Errorf("tag = %q, want the machine scoped %q", readers[0].Tag, want)
	}
	if readers[0].Tag == readers[0].ModelTag {
		t.Error("machine component must change the tag")
	}
}

// TestIdentifyReadersUnreachable fails when the pcscd socket cannot be
// reached, pcscd is a hard requirement of the startup evaluation too.
func TestIdentifyReadersUnreachable(t *testing.T) {
	t.Parallel()
	if _, err := IdentifyReaders(&Options{SocketPath: "/nonexistent-pcscd-socket", Logger: discardLogger()}); err == nil {
		t.Error("IdentifyReaders must fail without pcscd")
	}
}

// TestIdentifyReadersSortedLikeStates keeps the inventory order honest:
// entries appear in the daemon's reader state order, one per reader.
func TestIdentifyReadersMultiple(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	fake.InsertCard("ACS ACR122U 01 00 00", mifareATR, []byte{0x04, 0x11, 0x22, 0x33})
	fake.SetSerial("ACS ACR122U 01 00 00", "A001")
	fake.InsertCard("SCM Microsystems Inc. SCL011", mifareATR, []byte{0x04, 0xAA, 0xBB, 0xCC})
	fake.SetSerial("SCM Microsystems Inc. SCL011", "B002")

	readers, err := IdentifyReaders(&Options{SocketPath: fake.Addr(), Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{readers[0].Reader, readers[1].Reader}
	if !slices.Contains(names, "ACS ACR122U 01 00 00") || !slices.Contains(names, "SCM Microsystems Inc. SCL011") {
		t.Errorf("inventory = %v, want both readers", names)
	}
	for _, r := range readers {
		if r.Serial == "" {
			t.Errorf("reader %q carries no serial", r.Reader)
		}
		if r.Tag == r.ModelTag {
			t.Errorf("reader %q keeps the model tag despite a serial", r.Reader)
		}
	}
	if readers[0].Tag == readers[1].Tag {
		t.Error("two distinct readers must not share one tag")
	}
}
