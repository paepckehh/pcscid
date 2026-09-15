package pcscid

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"paepcke.de/pcscid/pcsc"
)

// fakeSysfsUSB writes a minimal sysfs USB device tree: one directory
// per device with busnum, devnum and devpath files.
func fakeSysfsUSB(t *testing.T, devices map[uint64]string) string {
	t.Helper()
	root := t.TempDir()
	for addr, devpath := range devices {
		bus, dev := uint32(addr>>32), uint32(addr&0xFFFFFFFF)
		dir := filepath.Join(root, devpath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string]string{
			"busnum":  itoa(bus),
			"devnum":  itoa(dev),
			"devpath": devpath,
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestUsbPortPath pins the sysfs resolution: a bus/device address maps
// to the kernel physical port path of the device directory, unknown
// addresses and an empty root answer the empty string.
func TestUsbPortPath(t *testing.T) {
	t.Parallel()
	root := fakeSysfsUSB(t, map[uint64]string{
		(uint64(1) << 32) | 0x22: "1-2",
		(uint64(2) << 32) | 0x33: "2-1.4",
	})
	if got := usbPortPath(root, 1, 0x22); got != "1-2" {
		t.Errorf("usbPortPath(bus 1 dev 0x22) = %q, want 1-2", got)
	}
	if got := usbPortPath(root, 2, 0x33); got != "2-1.4" {
		t.Errorf("usbPortPath(bus 2 dev 0x33) = %q, want 2-1.4", got)
	}
	if got := usbPortPath(root, 9, 0x99); got != "" {
		t.Errorf("usbPortPath(unknown) = %q, want empty", got)
	}
	if got := usbPortPath("", 1, 0x22); got != "" {
		t.Errorf("usbPortPath(empty root) = %q, want empty", got)
	}
}

// TestIsPlaceholderSerial pins the placeholder filter: reader families
// exist (ACS ACR122U) whose USB descriptor serves the same all zero
// serial on every unit, which identifies the model, not the unit.
func TestIsPlaceholderSerial(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"0", "00", "0000000", "0000000000"} {
		if !isPlaceholderSerial(s) {
			t.Errorf("isPlaceholderSerial(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "A001", "0A0", "0.1"} {
		if isPlaceholderSerial(s) {
			t.Errorf("isPlaceholderSerial(%q) = true, want false", s)
		}
	}
}

// TestReadChannelID pins the channel id unpacking through the fake
// daemon: the CCID USB packing resolves, other channel types and
// malformed answers do not.
func TestReadChannelID(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	fake.SetChannelID("R", 0x00200122)
	fake.InsertCard("R", mifareATR, []byte{0x04})
	cl, err := pcsc.New(fake.Addr(), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	card, err := cl.Connect("R", pcsc.ProtocolAny)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { card.Disconnect(pcsc.LeaveCard) })
	bus, dev, ok := readChannelID(card, discardLogger(), "R")
	if !ok || bus != 1 || dev != 0x22 {
		t.Errorf("readChannelID = bus %d dev %d ok %v, want bus 1 dev 0x22", bus, dev, ok)
	}
}

// TestReaderTagWithUnit pins the per-unit tag derivation and its
// precedence: a usable serial wins over the port path, the port path
// wins over the model tag, and the domains stay separated.
func TestReaderTagWithUnit(t *testing.T) {
	t.Parallel()
	reader := "ACS ACR122U 01 00 00"
	if ReaderTagWithUnit(reader, "A001", "") != ReaderTagWithSerial(reader, "A001") {
		t.Error("serial alone must reuse the serial domain")
	}
	// The serial takes precedence when both facts are available.
	if ReaderTagWithUnit(reader, "A001", "1-2") != ReaderTagWithSerial(reader, "A001") {
		t.Error("the serial must win over the port path")
	}
	portTag := ReaderTagWithUnit(reader, "", "1-2")
	if portTag == ReaderTag(reader) {
		t.Error("the port path must take part in the tag")
	}
	if portTag == ReaderTagWithUnit(reader, "", "2-1.4") {
		t.Error("two ports must produce different tags")
	}
	// The hotplug indices stay stripped in every domain.
	if ReaderTagWithUnit("ACS ACR122U 02 00 00", "", "1-2") != portTag {
		t.Error("the same port must keep its tag across hotplug indices")
	}
	if ReaderTagWithUnit(reader, "", "") != ReaderTag(reader) {
		t.Error("no unit facts must fall back to the model tag")
	}
}

// TestWatchIdentifiesIdenticalReadersByPort drives the whole watch
// pipeline over two ACR122U style units: no usable serial (the vendor
// placeholder), so the per-unit identity comes from the physical USB
// port path resolved through the channel id.
func TestWatchIdentifiesIdenticalReadersByPort(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	root := fakeSysfsUSB(t, map[uint64]string{
		(uint64(1) << 32) | 0x22: "1-2",
		(uint64(2) << 32) | 0x33: "2-1.4",
	})
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	events, err := Watch(ctx, &Options{
		SocketPath:   fake.Addr(),
		SysfsUSBRoot: root,
		Logger:       discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	uidA := []byte{0x04, 0x11, 0x22, 0x33}
	uidB := []byte{0x04, 0xAA, 0xBB, 0xCC}
	fake.InsertCard("ACS ACR122U 01 00 00", mifareATR, uidA)
	fake.SetSerial("ACS ACR122U 01 00 00", "0") // vendor placeholder
	fake.SetChannelID("ACS ACR122U 01 00 00", 0x00200122)
	fake.InsertCard("ACS ACR122U 02 00 00", mifareATR, uidB)
	fake.SetSerial("ACS ACR122U 02 00 00", "0000000000")
	fake.SetChannelID("ACS ACR122U 02 00 00", 0x00200233)

	first := receiveEvent(t, events, 3*time.Second)
	if first.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", first.Kind)
	}
	second := receiveEvent(t, events, 3*time.Second)
	if second.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", second.Kind)
	}
	for _, ev := range []Event{first, second} {
		if ev.ReaderSerial != "" {
			t.Errorf("reader %q: placeholder serial %q must be filtered", ev.Reader, ev.ReaderSerial)
		}
		if ev.ReaderPort == "" {
			t.Errorf("reader %q carries no port path, the channel id must resolve it", ev.Reader)
		}
	}
	if ReaderTag(first.Reader) != ReaderTag(second.Reader) {
		t.Fatal("test setup: the two readers must collide on the name based tag")
	}
	tagA := ReaderTagWithUnit(first.Reader, first.ReaderSerial, first.ReaderPort)
	tagB := ReaderTagWithUnit(second.Reader, second.ReaderSerial, second.ReaderPort)
	if tagA == tagB {
		t.Errorf("two identical readers on different ports share one tag: %q", tagA)
	}
	if tagA != ReaderTagWithUnit("ACS ACR122U", "", "1-2") {
		t.Errorf("first tag = %q, want the port 1-2 derived tag", tagA)
	}
	// The card identity stays reader independent.
	if first.Card.ID != Btag("mifare classic 1k", uidA) {
		t.Errorf("card id = %q, want the uid derived btag", first.Card.ID)
	}
}

// TestWatchNoUnitFactsFallsBackToModelTag documents the last fallback:
// a reader serving neither a usable serial nor a resolvable channel id
// keeps the model level tag and still reports cards.
func TestWatchNoUnitFactsFallsBackToModelTag(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	events, _ := watchFake(t, fake)

	fake.InsertCard("ACS ACR122U 00 00", mifareATR, []byte{0x04, 0x11, 0x22, 0x33})
	ev := receiveEvent(t, events, 3*time.Second)
	if ev.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", ev.Kind)
	}
	if ev.ReaderSerial != "" || ev.ReaderPort != "" {
		t.Errorf("unit facts = %q, %q, want empty", ev.ReaderSerial, ev.ReaderPort)
	}
	if ReaderTagWithUnit(ev.Reader, ev.ReaderSerial, ev.ReaderPort) != ReaderTag(ev.Reader) {
		t.Error("no unit facts must fall back to the model tag")
	}
}
