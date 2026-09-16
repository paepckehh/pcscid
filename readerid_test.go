package pcscid

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
// an empty root answer the empty port plus a qualified reason.
func TestUsbPortPath(t *testing.T) {
	t.Parallel()
	root := fakeSysfsUSB(t, map[uint64]string{
		(uint64(1) << 32) | 0x22: "1-2",
		(uint64(2) << 32) | 0x33: "2-1.4",
	})
	if port, reason := usbPortPath(discardLogger(), root, 1, 0x22); port != "1-2" || reason != "" {
		t.Errorf("usbPortPath(bus 1 dev 0x22) = %q, %q, want 1-2 and no reason", port, reason)
	}
	if port, reason := usbPortPath(discardLogger(), root, 2, 0x33); port != "2-1.4" || reason != "" {
		t.Errorf("usbPortPath(bus 2 dev 0x33) = %q, %q, want 2-1.4 and no reason", port, reason)
	}
	if port, reason := usbPortPath(discardLogger(), root, 9, 0x99); port != "" || reason == "" {
		t.Errorf("usbPortPath(unknown) = %q, %q, want empty and a reason", port, reason)
	}
	if port, reason := usbPortPath(discardLogger(), "", 1, 0x22); port != "" || reason == "" {
		t.Errorf("usbPortPath(empty root) = %q, %q, want empty and a reason", port, reason)
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
	bus, dev, reason := readChannelID(card, discardLogger(), "R")
	if reason != "" || bus != 1 || dev != 0x22 {
		t.Errorf("readChannelID = bus %d dev %d reason %q, want bus 1 dev 0x22 and no reason", bus, dev, reason)
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

// fakeUSBDevice describes one device of a fake sysfs USB tree for the
// name based port resolution: the identification strings pcscd's
// reader names are built from, and the USB interface classes of the
// device.
type fakeUSBDevice struct {
	devpath      string
	manufacturer string
	product      string
	ifaces       []string // bInterfaceClass values, "0b" is CCID
}

// fakeSysfsUSBNamed writes a minimal sysfs USB device tree carrying
// the manufacturer and product strings and the interface class files
// the name based port resolution scans.
func fakeSysfsUSBNamed(t *testing.T, devices []fakeUSBDevice) string {
	t.Helper()
	root := t.TempDir()
	devicesRoot := filepath.Join(root, "devices")
	for i, dev := range devices {
		dir := filepath.Join(devicesRoot, dev.devpath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{
			"busnum":       itoa(uint32(i + 1)),
			"devnum":       "1",
			"devpath":      dev.devpath,
			"manufacturer": dev.manufacturer,
			"product":      dev.product,
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for j, class := range dev.ifaces {
			ifDir := filepath.Join(devicesRoot, fmt.Sprintf("%s:1.%d", dev.devpath, j))
			if err := os.MkdirAll(ifDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ifDir, "bInterfaceClass"), []byte(class+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(ifDir, filepath.Join(root, fmt.Sprintf("%s:1.%d", dev.devpath, j))); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(dir, filepath.Join(root, dev.devpath)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestUsbPortPathByReader pins the name based fallback: a CCID device
// whose manufacturer and product strings carry the reader name is the
// reader, its devpath is the port. Non CCID devices and CCID devices of
// another model never match, and two identical CCID devices cannot be
// told apart without the channel id and answer a qualified reason.
func TestUsbPortPathByReader(t *testing.T) {
	t.Parallel()
	root := fakeSysfsUSBNamed(t, []fakeUSBDevice{
		{devpath: "1-2", manufacturer: "ACS", product: "ACR122U USB Reader", ifaces: []string{"0b"}},
		{devpath: "2-1.4", manufacturer: "Yubico", product: "YubiKey CCID", ifaces: []string{"0b"}},
		{devpath: "3-1", manufacturer: "ACS", product: "ACR122U USB Reader", ifaces: []string{"03"}}, // no CCID interface
		{devpath: "4-1", manufacturer: "Generic", product: "Mass Storage", ifaces: []string{"08"}},
	})
	port, reason := usbPortPathByReader(discardLogger(), root, "ACS ACR122U 01 00 00")
	if port != "1-2" || reason != "" {
		t.Errorf("usbPortPathByReader = %q, %q, want 1-2 and no reason", port, reason)
	}
	// The hotplug indices are stripped before matching.
	if port, _ := usbPortPathByReader(discardLogger(), root, "ACS ACR122U 07 00 00"); port != "1-2" {
		t.Errorf("usbPortPathByReader(hotplug variant) = %q, want 1-2", port)
	}
	// A parenthesized placeholder serial never blocks the match.
	if port, _ := usbPortPathByReader(discardLogger(), root, "ACS ACR122U (0) 01 00 00"); port != "1-2" {
		t.Errorf("usbPortPathByReader(placeholder serial) = %q, want 1-2", port)
	}
	if port, reason := usbPortPathByReader(discardLogger(), root, "Cherry GmbH SmartTerminal XX44"); port != "" || reason == "" {
		t.Errorf("usbPortPathByReader(unknown model) = %q, %q, want empty and a reason", port, reason)
	}
	// Two identical CCID devices are indistinguishable without the channel id.
	// A different CCID model resolves to its own port.
	if port, reason := usbPortPathByReader(discardLogger(), root, "Yubico YubiKey CCID 01 00 00"); port != "2-1.4" || reason != "" {
		t.Errorf("usbPortPathByReader(single yubikey) = %q, %q, want 2-1.4 and no reason", port, reason)
	}
	dup := fakeSysfsUSBNamed(t, []fakeUSBDevice{
		{devpath: "1-2", manufacturer: "ACS", product: "ACR122U USB Reader", ifaces: []string{"0b"}},
		{devpath: "2-1.4", manufacturer: "ACS", product: "ACR122U USB Reader", ifaces: []string{"0b"}},
	})
	if port, reason := usbPortPathByReader(discardLogger(), dup, "ACS ACR122U 01 00 00"); port != "" || reason == "" {
		t.Errorf("usbPortPathByReader(two identical units) = %q, %q, want empty and a reason", port, reason)
	}
}

// TestReaderNameTokens pins the token extraction: hotplug indices,
// parenthesized serial suffixes and bare placeholder zeros never
// become match tokens.
func TestReaderNameTokens(t *testing.T) {
	t.Parallel()
	got := strings.Join(readerNameTokens("ACS ACR122U 01 00 00 (0)"), " ")
	if want := "ACS ACR122U"; got != want {
		t.Errorf("readerNameTokens = %q, want %q", got, want)
	}
	if len(readerNameTokens("00 00")) != 0 {
		t.Error("a name of hotplug digits only must yield no tokens")
	}
}

// TestWatchResolvesPortWithoutChannelID drives the fallback through
// the whole watch pipeline: the driver serves neither serial nor
// channel id, the sysfs device scan identifies the reader's port by
// its name, the event carries the port derived reader tag.
func TestWatchResolvesPortWithoutChannelID(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	root := fakeSysfsUSBNamed(t, []fakeUSBDevice{
		{devpath: "1-2", manufacturer: "ACS", product: "ACR122U USB Reader", ifaces: []string{"0b"}},
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
	fake.InsertCard("ACS ACR122U 01 00 00", mifareATR, []byte{0x04, 0x11, 0x22, 0x33})
	fake.SetSerial("ACS ACR122U 01 00 00", "0") // placeholder, no usable serial
	// No SetChannelID: the driver answers unsupported feature.
	ev := receiveEvent(t, events, 3*time.Second)
	if ev.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", ev.Kind)
	}
	if ev.ReaderPort != "1-2" {
		t.Errorf("reader port = %q, want 1-2 resolved by the sysfs device scan", ev.ReaderPort)
	}
	if ev.ReaderTag != ReaderTagWithUnit(ev.Reader, "", "1-2") {
		t.Errorf("reader tag = %q, want the port derived tag", ev.ReaderTag)
	}
}

// TestWatchReportsUnresolvedPort pins the qualified error: with
// USBPathID enabled and neither the channel id nor the sysfs device
// scan resolving a port, the probe logs an error naming the reasons
// instead of swallowing the empty port silently.
func TestWatchReportsUnresolvedPort(t *testing.T) {
	t.Parallel()
	fake := newFake(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	events, err := Watch(ctx, &Options{
		SocketPath:   fake.Addr(),
		SysfsUSBRoot: t.TempDir(), // empty tree, nothing matches
		USBPathID:    true,
		Logger:       logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	fake.InsertCard("ACS ACR122U 01 00 00", mifareATR, []byte{0x04, 0x11, 0x22, 0x33})
	fake.SetSerial("ACS ACR122U 01 00 00", "0")
	ev := receiveEvent(t, events, 3*time.Second)
	if ev.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", ev.Kind)
	}
	if ev.ReaderPort != "" {
		t.Errorf("reader port = %q, want empty", ev.ReaderPort)
	}
	if ev.ReaderTag != ReaderTag(ev.Reader) {
		t.Errorf("reader tag = %q, want the model tag fallback", ev.ReaderTag)
	}
	out := logs.String()
	for _, want := range []string{
		"reader usb port identity unresolved",
		"reason=",
		"the driver serves no channel id",
		"no CCID USB device in sysfs matches the reader name",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("error report misses %q, got:\n%s", want, out)
		}
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
