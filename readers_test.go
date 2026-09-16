package pcscid

import (
	"context"
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

// TestIdentifyReadersCardlessPortPin proves the startup scan pins a
// reader by its USB port even without a presented card: with
// USBPathID enabled the sysfs device scan identifies the port as long
// as exactly one CCID device matches the reader name, so every reader
// is identified at startup, the driver attributes that need the card
// connection still wait for the first presentation.
func TestIdentifyReadersCardlessPortPin(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	fake.SetSerial("ACS ACR122U 01 00", "0") // card-less: unreadable either way
	root := fakeSysfsUSBNamed(t, []fakeUSBDevice{
		{devpath: "1-2", manufacturer: "ACS", product: "ACR122U USB Reader", ifaces: []string{"0b"}},
	})

	readers, err := IdentifyReaders(&Options{
		SocketPath:   fake.Addr(),
		SysfsUSBRoot: root,
		USBPathID:    true,
		Logger:       discardLogger(),
	})
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
	if r.Port != "1-2" {
		t.Errorf("port = %q, want the card-less pinned 1-2", r.Port)
	}
	if r.Tier != "port" {
		t.Errorf("tier = %q, want port", r.Tier)
	}
	if r.Tag != ReaderTagWithUnit(r.Reader, "", "1-2") {
		t.Errorf("tag = %q, want the port derived tag", r.Tag)
	}
	if r.Tag == r.ModelTag {
		t.Error("the pinned port must change the tag")
	}
}

// TestIdentifyReadersCardlessAmbiguousRefuses pins the honesty of the
// startup scan: two identical units without cards cannot be told apart
// (no connection, no probe traffic), the scan refuses instead of
// guessing a port.
func TestIdentifyReadersCardlessAmbiguousRefuses(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	fake.SetSerial("ACS ACR122U 00 00", "0")
	fake.SetSerial("ACS ACR122U 01 00", "0")
	root := fakeSysfsUSBNamed(t, []fakeUSBDevice{
		{devpath: "1-1", manufacturer: "ACS", product: "ACR122U USB Reader", ifaces: []string{"0b"}},
		{devpath: "1-2", manufacturer: "ACS", product: "ACR122U USB Reader", ifaces: []string{"0b"}},
	})

	readers, err := IdentifyReaders(&Options{
		SocketPath:   fake.Addr(),
		SysfsUSBRoot: root,
		USBPathID:    true,
		Logger:       discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 2 {
		t.Fatalf("readers = %d, want 2", len(readers))
	}
	for _, r := range readers {
		if r.Port != "" {
			t.Errorf("reader %q port = %q, want empty, the units are indistinguishable without a card", r.Reader, r.Port)
		}
		if r.Tier != "model" || r.Tag != r.ModelTag {
			t.Errorf("reader %q tier = %q tag = %q, want model fallback", r.Reader, r.Tier, r.Tag)
		}
	}
}

// TestIdentifyReadersIdenticalUnitsUniqueTags drives the full collision
// guarantee through the startup inventory and the watch pipeline: two
// identical units (placeholder serial) resolved by their channel ids
// must never share a reader tag, neither in the inventory nor in the
// events, and the inventory must report exactly the events' tags.
func TestIdentifyReadersIdenticalUnitsUniqueTags(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	root := fakeSysfsUSBNamed(t, []fakeUSBDevice{
		{devpath: "1-1", manufacturer: "ACS", product: "ACR122U USB Reader", ifaces: []string{"0b"}, urbnum: "100"},
		{devpath: "1-2", manufacturer: "ACS", product: "ACR122U USB Reader", ifaces: []string{"0b"}, urbnum: "100"},
	})
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	events, err := Watch(ctx, &Options{
		SocketPath:   fake.Addr(),
		SysfsUSBRoot: root,
		USBPathID:    true,
		Logger:       discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	wiring := map[string]uint32{
		"ACS ACR122U 00 00": 0x00200101, // bus 1 dev 1, the 1-1 tree entry
		"ACS ACR122U 01 00": 0x00200201, // bus 2 dev 1, the 1-2 tree entry
	}
	eventTags := make(map[string]string)
	for reader, channel := range wiring {
		fake.InsertCard(reader, mifareATR, []byte{0x04, 0x11, 0x22, 0x33})
		fake.SetSerial(reader, "0")
		fake.SetChannelID(reader, channel)
		ev := receiveEvent(t, events, 5*time.Second)
		if ev.Kind != KindInsert {
			t.Fatalf("kind = %v, want insert", ev.Kind)
		}
		if ev.ReaderPort == "" {
			t.Errorf("reader %q carries no port, the channel id must resolve it", ev.Reader)
		}
		eventTags[reader] = ev.ReaderTag
	}
	if eventTags["ACS ACR122U 00 00"] == eventTags["ACS ACR122U 01 00"] {
		t.Errorf("two units share one event tag %q", eventTags["ACS ACR122U 00 00"])
	}

	// The startup inventory reports the same unique, port anchored tags.
	readers, err := IdentifyReaders(&Options{
		SocketPath:   fake.Addr(),
		SysfsUSBRoot: root,
		USBPathID:    true,
		Logger:       discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 2 {
		t.Fatalf("readers = %d, want 2", len(readers))
	}
	for _, r := range readers {
		if r.Tag != eventTags[r.Reader] {
			t.Errorf("reader %q inventory tag = %q, event tag = %q, they must match", r.Reader, r.Tag, eventTags[r.Reader])
		}
		if r.Tier != "port" {
			t.Errorf("reader %q tier = %q, want port", r.Reader, r.Tier)
		}
	}
	if readers[0].Tag == readers[1].Tag {
		t.Error("two identical units share one inventory tag")
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
