package pcscid

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"paepcke.de/pcscid/pcsc"
)

// fakeSysfsUSB writes a minimal sysfs USB device tree shaped like the
// real one: the bus directory holds symlinks, the device directories
// live in a devices subtree with busnum, devnum and devpath files.
func fakeSysfsUSB(t *testing.T, devices map[uint64]string) string {
	t.Helper()
	root := t.TempDir()
	devicesRoot := filepath.Join(root, "devices")
	for addr, devpath := range devices {
		bus, dev := uint32(addr>>32), uint32(addr&0xFFFFFFFF)
		dir := filepath.Join(devicesRoot, devpath)
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
		// The real bus directory classifies by symlink, the resolver
		// must stat through it.
		if err := os.Symlink(filepath.Join(devicesRoot, devpath), filepath.Join(root, devpath)); err != nil {
			t.Fatal(err)
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
// to the kernel physical port path of the device directory, through the
// symlinks a real sysfs bus directory carries, and unknown addresses and
// an empty root answer the empty string.
func TestUsbPortPath(t *testing.T) {
	t.Parallel()
	root := fakeSysfsUSB(t, map[uint64]string{
		(uint64(1) << 32) | 0x22: "1-2",
		(uint64(2) << 32) | 0x33: "2-1.4",
	})
	if got := usbPortPath(discardLogger(), root, 1, 0x22); got != "1-2" {
		t.Errorf("usbPortPath(bus 1 dev 0x22) = %q, want 1-2", got)
	}
	if got := usbPortPath(discardLogger(), root, 2, 0x33); got != "2-1.4" {
		t.Errorf("usbPortPath(bus 2 dev 0x33) = %q, want 2-1.4", got)
	}
	if got := usbPortPath(discardLogger(), root, 9, 0x99); got != "" {
		t.Errorf("usbPortPath(unknown) = %q, want empty", got)
	}
	if got := usbPortPath(discardLogger(), "", 1, 0x22); got != "" {
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
// placeholder), the USBPathID option is on, so the per-unit identity
// comes from the physical USB port path resolved through the channel
// id.
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
		USBPathID:    true,
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
	// Watch carries the composed tag on the event itself.
	if first.ReaderTag != tagA || second.ReaderTag != tagB {
		t.Errorf("event reader tags = %q, %q, want the composed tags", first.ReaderTag, second.ReaderTag)
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

// TestWatchUSBPathIDDisabledByDefault pins the opt-in: without
// USBPathID the channel id is not even probed, a serial-less reader
// keeps the model level tag even when a port path would resolve.
func TestWatchUSBPathIDDisabledByDefault(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	root := fakeSysfsUSB(t, map[uint64]string{
		(uint64(1) << 32) | 0x22: "1-2",
	})
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	events, err := Watch(ctx, &Options{
		SocketPath:   fake.Addr(),
		SysfsUSBRoot: root, // would resolve, but the option is off
		Logger:       discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fake.InsertCard("ACS ACR122U 01 00 00", mifareATR, []byte{0x04, 0x11, 0x22, 0x33})
	fake.SetSerial("ACS ACR122U 01 00 00", "0") // placeholder, no usable serial
	fake.SetChannelID("ACS ACR122U 01 00 00", 0x00200122)
	ev := receiveEvent(t, events, 3*time.Second)
	if ev.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", ev.Kind)
	}
	if ev.ReaderPort != "" {
		t.Errorf("reader port = %q, want empty with the option off", ev.ReaderPort)
	}
	if ev.ReaderTag != ReaderTag(ev.Reader) {
		t.Errorf("reader tag = %q, want the model tag %q", ev.ReaderTag, ReaderTag(ev.Reader))
	}
}

// fakeSysfsNet writes a minimal sysfs class/net tree shaped like the
// real one: symlinked interface entries whose targets carry type,
// address and the optional phy80211 and device markers.
func fakeSysfsNet(t *testing.T, ifaces []fakeNetIface) string {
	t.Helper()
	root := t.TempDir()
	devicesRoot := filepath.Join(root, "devices")
	for _, ifc := range ifaces {
		dir := filepath.Join(devicesRoot, ifc.name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{"type": ifc.kind}
		if ifc.mac != "" {
			files["address"] = ifc.mac
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if ifc.wireless {
			if err := os.MkdirAll(filepath.Join(dir, "phy80211"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if ifc.physical {
			target := filepath.Join(root, "pci-device")
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "device")); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(dir, filepath.Join(root, ifc.name)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

type fakeNetIface struct {
	name     string
	kind     string // sysfs type, "1" is ethernet
	mac      string // empty means no address file
	wireless bool   // phy80211 marker
	physical bool   // device symlink marker
}

// TestMachineID pins the network stack filter: only physical ethernet
// ports with a burned in MAC count, sorted and joined; wireless,
// virtual and unassigned interfaces never do.
func TestMachineID(t *testing.T) {
	t.Parallel()
	root := fakeSysfsNet(t, []fakeNetIface{
		{name: "eno2", kind: "1", mac: "aa:bb:cc:dd:ee:02", physical: true},
		{name: "eno1", kind: "1", mac: "aa:bb:cc:dd:ee:01", physical: true},
		{name: "wlan0", kind: "1", mac: "aa:bb:cc:dd:ee:03", physical: true, wireless: true},
		{name: "lo", kind: "772", mac: "00:00:00:00:00:00"},
		{name: "br0", kind: "1", mac: "d6:fc:3c:b9:ca:fd"},
		{name: "eno1.100", kind: "1", mac: "aa:bb:cc:dd:ee:01"}, // vlan, shares the parent mac
		{name: "eno3", kind: "1", mac: "00:00:00:00:00:00", physical: true},
		{name: "eno4", kind: "1", physical: true}, // no address file
	})
	want := "aa:bb:cc:dd:ee:01|aa:bb:cc:dd:ee:02"
	if got := machineIDFrom(root); got != want {
		t.Errorf("machineIDFrom = %q, want %q", got, want)
	}
	if got := machineIDFrom(filepath.Join(root, "absent")); got != "" {
		t.Errorf("machineIDFrom(absent) = %q, want empty", got)
	}
}

// TestReaderTagWithMachine pins the machine mixed derivation: the
// machine component separates identical readers across machines, the
// unit facts stay prefixed by their kind, and the empty machine falls
// back to the plain unit derivation.
func TestReaderTagWithMachine(t *testing.T) {
	t.Parallel()
	reader := "ACS ACR122U 01 00 00"
	if ReaderTagWithMachine(reader, "A001", "", "") != ReaderTagWithSerial(reader, "A001") {
		t.Error("empty machine must fall back to ReaderTagWithUnit")
	}
	machineA, machineB := "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
	if ReaderTagWithMachine(reader, "", "1-2", machineA) == ReaderTagWithMachine(reader, "", "1-2", machineB) {
		t.Error("the same reader on two machines must serve different tags")
	}
	// A serial and a port path of the same text must never collide.
	if ReaderTagWithMachine(reader, "1-2", "", machineA) == ReaderTagWithMachine(reader, "", "1-2", machineA) {
		t.Error("serial:1-2 and port:1-2 must hash differently")
	}
	// The machine alone still separates the model on two machines.
	if ReaderTagWithMachine(reader, "", "", machineA) == ReaderTagWithMachine(reader, "", "", machineB) {
		t.Error("the machine must take part even without unit facts")
	}
	if ReaderTagWithMachine(reader, "", "", machineA) == ReaderTag(reader) {
		t.Error("machine mixed tag must differ from the model tag")
	}
	// Deterministic, and the hotplug indices stay stripped.
	if ReaderTagWithMachine("ACS ACR122U 02 00 00", "", "1-2", machineA) != ReaderTagWithMachine(reader, "", "1-2", machineA) {
		t.Error("the same facts must keep their tag across hotplug indices")
	}
}

// TestWatchMACIDScopesReadersToTheMachine drives the machine identity
// through the whole watch pipeline: two serial-less units on their
// ports get tags composed of port and machine identity, distinct per
// unit and per machine.
func TestWatchMACIDScopesReadersToTheMachine(t *testing.T) {
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
		USBPathID:    true,
		MACID:        true,
		MachineID:    "aa:bb:cc:dd:ee:01",
		Logger:       discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fake.InsertCard("ACS ACR122U 01 00 00", mifareATR, []byte{0x04, 0x11, 0x22, 0x33})
	fake.SetSerial("ACS ACR122U 01 00 00", "0")
	fake.SetChannelID("ACS ACR122U 01 00 00", 0x00200122)
	fake.InsertCard("ACS ACR122U 02 00 00", mifareATR, []byte{0x04, 0xAA, 0xBB, 0xCC})
	fake.SetSerial("ACS ACR122U 02 00 00", "0")
	fake.SetChannelID("ACS ACR122U 02 00 00", 0x00200233)

	first := receiveEvent(t, events, 3*time.Second)
	if first.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", first.Kind)
	}
	second := receiveEvent(t, events, 3*time.Second)
	if second.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", second.Kind)
	}
	if first.ReaderTag == second.ReaderTag {
		t.Errorf("two units on different ports share one machine scoped tag: %q", first.ReaderTag)
	}
	want := ReaderTagWithMachine(first.Reader, "", "1-2", "aa:bb:cc:dd:ee:01")
	if first.ReaderTag != want {
		t.Errorf("first tag = %q, want the port and machine derived tag %q", first.ReaderTag, want)
	}
	if first.ReaderTag == ReaderTagWithUnit(first.Reader, "", "1-2") {
		t.Error("the machine must take part in the composed tag")
	}
}
