// Reader unit identity: the per-unit discriminator of a reader.
//
// The reader name alone identifies the model, not the unit, so the
// watch loop probes the driver for two per-unit facts while a card is
// connected, in one connection:
//
//   - SCARD_ATTR_VENDOR_IFD_SERIAL_NO, the USB iSerial string burned
//     into the reader hardware. Portable: the same unit carries it on
//     every machine, port and daemon restart. Some reader families,
//     for example the ACS ACR122U, ship a constant placeholder ("0"
//     on every unit), which is filtered here.
//   - SCARD_ATTR_CHANNEL_ID, the USB bus and device address, resolved
//     through sysfs to the kernel physical port path (devpath, "2-1.3").
//     The port path anchors the unit to the port it sits on: stable
//     across daemon restarts and reboots, but not portable, moving the
//     reader to another port changes it. It is the opt-in fallback
//     (Options.USBPathID, PCSCID_USB_PATH_ID in the sample app) when
//     no usable serial exists.
//
// When the driver serves neither usable serial nor channel id, the
// sysfs USB tree is scanned for the reader's device directly: the USB
// manufacturer and product strings must match the pcscd reader name
// (pcscd derives that name from the same vendor and product strings)
// and the device must carry a CCID interface. Exactly one matching
// device identifies the port, two identical models cannot be told
// apart without the channel id. With USBPathID enabled an unresolved
// port is reported as a qualified error, not swallowed silently: the
// reader then keeps the model level tag, which two identical units
// share.
//
// MachineID (readerid.go bottom) is the machine level identity, the
// stable hardware MAC addresses of the physical ethernet ports, mixed
// into the reader tag when enabled (Options.MACID, PCSCID_MAC_ID in
// the sample app).
package pcscid

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"paepcke.de/pcscid/pcsc"
)

// defaultSysfsUSB is the sysfs root holding one entry per USB device,
// with the busnum, devnum and devpath files used to resolve a
// bus/device address to its physical port path.
const defaultSysfsUSB = "/sys/bus/usb/devices"

// defaultSysfsNet is the sysfs root holding one entry per network
// interface, the source of the machine identity (MACID).
const defaultSysfsNet = "/sys/class/net"

// channelIDUSBType is the channel type the CCID driver packs into
// SCARD_ATTR_CHANNEL_ID for USB readers: 0x0020<<16 | bus<<8 | device.
// Serial readers and other channel types carry other values, they do
// not resolve to a USB port path.
const channelIDUSBType uint32 = 0x0020

// ccidInterfaceClass is the USB interface class of a smart card reader
// (CCID, bInterfaceClass 0x0B), the marker the sysfs device scan uses
// to tell readers from every other USB device.
const ccidInterfaceClass uint32 = 0x0B

// urbWinnerMinDelta is the smallest URB counter delta that counts as
// the unit's probe traffic, and the margin the runner up must stay
// behind: the probe exchange (connect, two GetAttrib, disconnect)
// submits a burst of URBs to exactly the probed device, an idle
// identical unit moves its counter by at most a stray poll URB.
const (
	urbWinnerMinDelta = 2
	urbWinnerMargin   = 2
)

// pinningExchanges is the number of extra card exchanges the unit
// probe submits when it must single the physical device out by its
// USB traffic: together with the UID exchange (one CCID bulk round
// trip each) they guarantee a burst of URBs to exactly the probed
// device, far above the idle noise of the interrupt pipe, while a
// plain card connection alone submits none (the daemon already
// powered the card, and the driver attributes are answered from
// memory).
const pinningExchanges = 2

// readerFacts bundles everything one probe gathers over a single card
// connection: the per-unit identity facts of the reader (serial, port)
// and the identity facts of the presented card (uid, protocol).
type readerFacts struct {
	serial   string
	port     string
	uid      []byte
	protocol uint32
}

// probeReaderCard probes a reader while its card is presented and
// gathers every fact over ONE card connection: the per-unit identity
// (hardware serial and, only when no usable serial exists and
// useUSBPath allows it, the physical USB port path) plus the UID of the
// card. Failures are best effort, an unusable serial and an
// unresolvable channel id map to the empty strings, the caller then
// falls back to the model level tag. With useUSBPath enabled the port
// resolution is two staged: first the channel id through the driver,
// then the sysfs USB tree scanned for the reader's CCID device by name.
// With several identical candidates the unit is singled out by its USB
// traffic: the UID exchange and the pinning exchanges of this very
// probe submit a burst of URBs to exactly the probed physical device,
// a snapshot taken before the connection and one taken after the
// exchanges identify it through the sysfs urbnum counter. That
// correlation is exact and independent of the daemon's reader order,
// so the same physical reader on the same port derives the same tag
// across service restarts, daemon restarts and reboots. claims holds
// the port identities already taken by other readers of the session
// (see unitRegistry), claimed candidates are never guessed: the scan
// either singles a free device out or refuses with a qualified error
// naming every failed step, because the operator asked for a per-unit
// identity and silently losing it makes two identical readers collide
// on one tag.
func probeReaderCard(cl *pcsc.Client, lg *slog.Logger, reader, sysfsRoot string, useUSBPath bool, claims map[string]string) readerFacts {
	// The traffic baseline must precede the first URB of this probe,
	// the card connection itself already talks to the device.
	var before map[string]uint32
	if useUSBPath {
		before = usbUrbSnapshot(sysfsRoot)
	}
	card, err := openCard(cl, reader)
	if err != nil {
		lg.Debug("reader unit probe connect failed",
			"reader", reader, "error", err)
		if useUSBPath {
			lg.Error("reader unit identity unreadable, the card connection failed (PCSCID_USB_PATH_ID=1)",
				"reader", reader, "error", err,
				"consequence", "the reader keeps the model level tag, identical units share one tag")
		}
		return readerFacts{}
	}
	defer func() {
		if err := card.Disconnect(pcsc.LeaveCard); err != nil {
			lg.Debug("reader unit probe disconnect failed", "reader", reader, "error", err)
		}
	}()

	var facts readerFacts
	var reasons []string
	facts.serial = readVendorSerial(card, lg, reader)
	if facts.serial == "" && useUSBPath {
		if bus, dev, reason := readChannelID(card, lg, reader); reason == "" {
			port, portReason := usbPortPath(lg, sysfsRoot, bus, dev)
			if port != "" {
				facts.port = portIdentity(reader, port)
				lg.Debug("reader usb port resolved by channel id",
					"reader", reader, "bus", bus, "device", dev, "port", facts.port)
			} else {
				reasons = append(reasons, portReason)
			}
		} else {
			reasons = append(reasons, reason)
		}
	} else if facts.serial == "" {
		lg.Debug("reader usb port path identity not enabled (PCSCID_USB_PATH_ID)", "reader", reader)
	}
	// The card identity exchange. It doubles as guaranteed USB traffic
	// of the probe window: a plain card connection submits no URB at
	// all (the daemon already powered the card, both attribute answers
	// come from driver memory), so the UID round trip is what moves the
	// sysfs urbnum counter of the probed device.
	facts.uid, facts.protocol = transmitUID(card, lg, reader)
	if useUSBPath && facts.serial == "" && facts.port == "" {
		// Strengthen the traffic signal of the probe window before
		// the correlation reads it: every exchange is another burst
		// of URBs to exactly this unit.
		for range pinningExchanges {
			if _, err := card.Transmit(uidAPDU, 64); err != nil {
				lg.Debug("reader usb traffic pinning exchange failed", "reader", reader, "error", err)
			}
		}
		port, reason := usbPortPathByReader(lg, sysfsRoot, reader, before, usbUrbSnapshot(sysfsRoot), claims)
		if port != "" {
			facts.port = port
			lg.Info("reader usb port resolved",
				"reader", reader, "port", port)
		} else {
			reasons = append(reasons, reason)
			lg.Error("reader usb port identity unresolved (PCSCID_USB_PATH_ID=1)",
				"reader", reader,
				"reason", strings.Join(reasons, "; "),
				"sysfs", sysfsRoot,
				"consequence", "the reader keeps the model level tag, identical units share one tag")
		}
	}
	// The identity outcome is reported at info level, so the USB
	// anchoring is visible even without the debug trace.
	lg.Info("reader unit identity",
		"reader", reader, "serial", facts.serial, "port", facts.port, "tier", unitTier(facts.serial, facts.port))
	return facts
}

// unitTier names the portability tier of the per-unit identity facts:
// "serial" (one tag per unit, portable), "port" (one tag per USB
// port, not portable) or "model" (no per-unit fact, name only).
func unitTier(serial, port string) string {
	switch {
	case serial != "":
		return "serial"
	case port != "":
		return "port"
	default:
		return "model"
	}
}

// portIdentity qualifies the kernel physical USB port path of a reader
// with its pcscd slot number when it is not the first slot. pcscd
// appends two hex groups to every reader name, the enumeration digit
// and the slot number ("... 01 00"), and a multi-slot unit serves one
// reader per slot on ONE USB device: the plain devpath alone would
// collide between the slots. The first slot ("00", also the only one
// single-slot readers ever carry) keeps the plain devpath, so the port
// derived reader tags of existing deployments stay stable. A name
// without the two trailing hex groups is not a pcscd hotplug name and
// keeps the plain devpath too.
func portIdentity(reader, devpath string) string {
	fields := strings.Fields(reader)
	if len(fields) < 2 {
		return devpath
	}
	slot, digit := fields[len(fields)-1], fields[len(fields)-2]
	if len(slot) != 2 || len(digit) != 2 || !isHexGroup(slot) || !isHexGroup(digit) {
		return devpath
	}
	if slot == "00" {
		return devpath
	}
	return devpath + "#" + strings.ToLower(slot)
}

// isHexGroup reports whether s is a two character hexadecimal group,
// the format of pcscd's trailing enumeration digit and slot number.
func isHexGroup(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// unitRegistry keeps the per-unit reader identity of one daemon
// connection session (one Watch loop or one startup inventory)
// persistent and collision free. A USB port hosts exactly one reader
// unit, so with the port identity enabled (Options.USBPathID) two
// readers must never share one port fact: byPort hands out every
// resolved port to exactly one reader name, and a probe that resolves
// a foreign port refuses it instead of producing a colliding tag.
// facts remembers the last adopted identity of every reader, so a
// transient probe failure cannot flip a reader back to the model level
// tag between two presentations of the same card.
//
// The registry is per session and deliberately not persisted beyond
// it: a daemon restart re-enumerates the volatile name suffixes, so
// the mapping is re-derived from the physical probe evidence instead
// of trusting remembered names.
type unitRegistry struct {
	facts  map[string]readerFacts // reader name to last adopted facts
	byPort map[string]string      // port identity to claiming reader name
}

func newUnitRegistry() *unitRegistry {
	return &unitRegistry{
		facts:  make(map[string]readerFacts),
		byPort: make(map[string]string),
	}
}

// adopt merges freshly probed facts of reader into the session state
// and answers the effective identity: a fresh fact wins over the
// remembered one, a fresh failure falls back to the remembered one,
// and a fresh port already owned by another reader is refused (first
// claim wins, reassigning would ping-pong the port between two
// readers claiming the same device). byPort is safe to hand to the
// probe as its claims view, adopt is its only writer.
func (r *unitRegistry) adopt(lg *slog.Logger, reader string, fresh readerFacts) readerFacts {
	cached, known := r.facts[reader]
	adopted := fresh
	if adopted.serial == "" && known && cached.serial != "" {
		adopted.serial = cached.serial
		lg.Debug("reader serial reused from the session identity",
			"reader", reader, "serial", adopted.serial)
	}
	if adopted.port != "" {
		if owner, taken := r.byPort[adopted.port]; taken && owner != reader {
			lg.Error("reader usb port identity collides with another reader (PCSCID_USB_PATH_ID=1)",
				"reader", reader, "port", adopted.port, "claimed_by", owner,
				"consequence", "the reader keeps its previous identity, the model tag if it has none")
			adopted.port = ""
		}
	}
	if adopted.port == "" && known && cached.port != "" {
		// The probe resolved nothing this time: keep the port this
		// reader already owns, so its tag cannot flip.
		if owner, taken := r.byPort[cached.port]; !taken || owner == reader {
			adopted.port = cached.port
			lg.Debug("reader usb port reused from the session identity",
				"reader", reader, "port", adopted.port)
		}
	}
	if known && cached.port != "" && cached.port != adopted.port {
		if owner, taken := r.byPort[cached.port]; taken && owner == reader {
			delete(r.byPort, cached.port)
		}
	}
	if adopted.port != "" {
		r.byPort[adopted.port] = reader
	}
	r.facts[reader] = adopted
	return adopted
}

// forget drops the session identity of a reader that disappeared from
// the daemon, releasing its port claim for other readers to take.
func (r *unitRegistry) forget(reader string) {
	facts, known := r.facts[reader]
	if !known {
		return
	}
	if facts.port != "" {
		if owner, taken := r.byPort[facts.port]; taken && owner == reader {
			delete(r.byPort, facts.port)
		}
	}
	delete(r.facts, reader)
}

// readVendorSerial asks for the reader hardware serial and filters the
// placeholder values some reader families ship instead of a real one.
func readVendorSerial(card *pcsc.Card, lg *slog.Logger, reader string) string {
	attr, err := card.GetAttrib(pcsc.AttrVendorIFDSerialNo)
	if err != nil {
		lg.Debug("reader serial unavailable",
			"reader", reader, "error", err)
		return ""
	}
	serial := strings.TrimSpace(strings.Trim(string(attr), "\x00"))
	if serial == "" {
		lg.Debug("reader serial empty", "reader", reader)
		return ""
	}
	if isPlaceholderSerial(serial) {
		lg.Debug("reader serial is the vendor placeholder, not a unit identity",
			"reader", reader, "serial", serial)
		return ""
	}
	lg.Debug("reader serial read", "reader", reader, "serial", serial)
	return serial
}

// isPlaceholderSerial reports whether the serial is a vendor
// placeholder instead of a per-unit value: readers exist whose USB
// descriptor serves the same all zero serial on every unit of the
// model (for example ACS ACR122U), such a constant identifies the
// model, which the name already does.
func isPlaceholderSerial(serial string) bool {
	return serial != "" && strings.Trim(serial, "0") == ""
}

// readChannelID asks for the USB channel id of the reader and unpacks
// the CCID packing 0x0020<<16 | bus<<8 | device. An empty reason
// reports success, a non empty one names what failed, for the error
// report of an unresolved port identity.
func readChannelID(card *pcsc.Card, lg *slog.Logger, reader string) (bus, dev uint32, reason string) {
	attr, err := card.GetAttrib(pcsc.AttrChannelID)
	if err != nil {
		lg.Debug("reader channel id unavailable",
			"reader", reader, "error", err)
		return 0, 0, fmt.Sprintf("the driver serves no channel id: %v", err)
	}
	if len(attr) != 4 {
		lg.Debug("reader channel id malformed",
			"reader", reader, "attr", fmt.Sprintf("% X", attr))
		return 0, 0, fmt.Sprintf("the channel id answer is malformed: %d bytes", len(attr))
	}
	id := uint32(attr[0]) | uint32(attr[1])<<8 | uint32(attr[2])<<16 | uint32(attr[3])<<24
	if id>>16 != channelIDUSBType {
		lg.Debug("reader channel is not usb, no port path",
			"reader", reader, "channel", fmt.Sprintf("0x%08X", id))
		return 0, 0, fmt.Sprintf("the reader channel is not USB: 0x%08X", id)
	}
	return (id >> 8) & 0xFF, id & 0xFF, ""
}

// usbPortPath resolves the USB bus/device address of a reader to the
// kernel physical port path (sysfs devpath, for example "2-1.3").
// The entries of a sysfs bus directory are symlinks into
// /sys/devices, so every candidate is stat-ed, not classified by its
// directory entry type. Every step of the scan is logged to lg, so
// an unresolved port is diagnosable from the trace. It returns the
// empty port and a reason naming the failure when the device cannot
// be found, sysfs is unreadable or root is empty.
func usbPortPath(lg *slog.Logger, root string, bus, dev uint32) (port, reason string) {
	if root == "" {
		lg.Debug("usb port path scan skipped, no sysfs root",
			"bus", bus, "device", dev)
		return "", "no sysfs root is configured"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		lg.Debug("usb port path scan failed",
			"sysfs", root, "bus", bus, "device", dev, "error", err)
		return "", fmt.Sprintf("the sysfs USB tree %s is unreadable: %v", root, err)
	}
	lg.Debug("usb port path scan",
		"sysfs", root, "entries", len(entries), "bus", bus, "device", dev)
	for _, entry := range entries {
		dir := filepath.Join(root, entry.Name())
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		if readSysNum(filepath.Join(dir, "busnum")) != bus ||
			readSysNum(filepath.Join(dir, "devnum")) != dev {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "devpath"))
		if err != nil {
			lg.Debug("usb port path devpath unreadable",
				"sysfs", dir, "error", err)
			return "", fmt.Sprintf("the USB device for bus %d device %d carries an unreadable devpath: %v", bus, dev, err)
		}
		return strings.TrimSpace(string(raw)), ""
	}
	lg.Debug("usb port path no matching usb device",
		"sysfs", root, "bus", bus, "device", dev)
	return "", fmt.Sprintf("no USB device with bus %d device %d exists in %s", bus, dev, root)
}

// usbPortPathByReader resolves a reader to its kernel physical USB port
// path without the channel id, by scanning the sysfs USB tree for the
// reader's device: pcscd derives the reader name from the driver's
// vendor and product table, which mirrors the USB manufacturer and
// product strings, so the normalized reader name must appear inside
// the device's identification strings and the device must carry a CCID
// interface (bInterfaceClass 0x0B). The returned port is the qualified
// port identity (see portIdentity), it is what the reader tag hashes.
//
// Exactly one matching device identifies the port directly. N matching
// devices are N identical reader units: they are told apart by their
// USB traffic, not by order — before and after hold the sysfs urbnum
// counters of the probe window (see probeReaderCard), and the device
// whose counter moved is the probed unit. The correlation is exact and
// independent of the daemon's reader order, so the same physical
// reader on the same port keeps its tag across service restarts,
// daemon restarts and reboots. claims maps port identities to the
// readers that already own them: a claimed port is never handed to a
// second reader (a USB port hosts exactly one unit, a collision would
// be a wrong guess), and when the traffic does not single a device out
// but every other candidate is already owned, the one free candidate
// identifies the unit by elimination. When neither traffic nor the
// claims single one device out the scan refuses with a qualified
// reason, the reader then keeps the stable model level tag instead of
// a shuffling guess.
func usbPortPathByReader(lg *slog.Logger, root, reader string, before, after map[string]uint32, claims map[string]string) (port, reason string) {
	if root == "" {
		return "", "no sysfs root is configured to scan for the reader's USB device"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Sprintf("the sysfs USB tree %s is unreadable: %v", root, err)
	}
	tokens := readerNameTokens(reader)
	if len(tokens) == 0 {
		return "", "the reader name carries no tokens to match a USB device against"
	}
	ccid := usbCCIDDevices(root, entries)
	lg.Debug("usb port path name scan",
		"sysfs", root, "reader", reader, "ccid_devices", len(ccid))
	var candidates []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, ":") || !ccid[name] {
			continue // interface entry of a device, or not a CCID reader
		}
		dir := filepath.Join(root, name)
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		device := strings.ToUpper(readSysString(filepath.Join(dir, "manufacturer")) + " " + readSysString(filepath.Join(dir, "product")))
		if !tokensIn(device, tokens) {
			continue
		}
		candidates = append(candidates, name)
	}
	resolve := func(name string) (string, string) {
		devpath := readSysString(filepath.Join(root, name, "devpath"))
		if devpath == "" {
			return "", fmt.Sprintf("the USB device %s carries no devpath", name)
		}
		return portIdentity(reader, devpath), ""
	}
	claimed := func(port string) (string, bool) {
		owner, ok := claims[port]
		return owner, ok && owner != reader
	}
	switch len(candidates) {
	case 0:
		return "", "no CCID USB device in sysfs matches the reader name"
	case 1:
		port, reason := resolve(candidates[0])
		if port == "" {
			return "", reason
		}
		if owner, taken := claimed(port); taken {
			return "", fmt.Sprintf("the USB port %s already identifies reader %q, the device cannot belong to two readers", port, owner)
		}
		lg.Debug("usb port path name scan matched",
			"reader", reader, "device", candidates[0], "port", port)
		return port, ""
	}
	// N identical units: single the probed one out by its USB traffic
	// across the probe window.
	winner, ok := usbUrbWinner(before, after, candidates)
	if ok {
		port, reason := resolve(winner)
		if port == "" {
			return "", reason
		}
		if owner, taken := claimed(port); taken {
			return "", fmt.Sprintf("the usb traffic singles out the USB port %s but it already identifies reader %q, the device cannot belong to two readers", port, owner)
		}
		lg.Info("usb port resolved by traffic correlation",
			"reader", reader, "device", winner, "port", port,
			"urb", after[winner]-before[winner])
		return port, ""
	}
	// No decisive traffic: when every other candidate is already
	// owned by another reader, the one free device is this unit's —
	// each daemon reader is one physical unit, and none of the
	// owned candidates can be this one.
	var free []string
	for _, candidate := range candidates {
		port, reason := resolve(candidate)
		if port == "" {
			return "", reason
		}
		if _, taken := claimed(port); !taken {
			free = append(free, port)
		}
	}
	if len(free) == 1 {
		lg.Info("usb port resolved by elimination, every other candidate is owned by another reader",
			"reader", reader, "port", free[0])
		return free[0], ""
	}
	if before == nil || after == nil {
		return "", fmt.Sprintf("%d CCID USB devices match the reader name and no probe traffic is available to single one out, present a card on the reader to pin its unit", len(candidates))
	}
	return "", fmt.Sprintf("%d CCID USB devices match the reader name and the usb traffic did not single one out, the unit mapping is ambiguous without the channel id", len(candidates))
}

// usbUrbSnapshot reads the URB counter (sysfs urbnum) of every CCID USB
// device in the tree. A nil map or unreadable root disables the
// traffic correlation.
func usbUrbSnapshot(root string) map[string]uint32 {
	if root == "" {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	ccid := usbCCIDDevices(root, entries)
	counts := make(map[string]uint32, len(ccid))
	for name := range ccid {
		counts[name] = readSysNum(filepath.Join(root, name, "urbnum"))
	}
	return counts
}

// usbUrbWinner picks the candidate whose URB counter moved the most
// between the two snapshots of the probe window: the probe exchange
// submits a burst of URBs to exactly the probed device, idle identical
// units stay put. The winner must clear a minimum delta and beat the
// runner up by the margin, anything else is ambiguous and refuses. A
// missing snapshot (unreadable sysfs at either end of the window)
// carries no traffic evidence and refuses too.
func usbUrbWinner(before, after map[string]uint32, candidates []string) (name string, ok bool) {
	if before == nil || after == nil {
		return "", false
	}
	winner, winnerDelta, runnerUp := "", 0, 0
	for _, candidate := range candidates {
		delta := int(after[candidate]) - int(before[candidate])
		switch {
		case delta > winnerDelta:
			runnerUp = winnerDelta
			winner, winnerDelta = candidate, delta
		case delta > runnerUp:
			runnerUp = delta
		}
	}
	if winner == "" || winnerDelta < urbWinnerMinDelta || winnerDelta-runnerUp < urbWinnerMargin {
		return "", false
	}
	return winner, true
}

// usbCCIDDevices maps the name of every sysfs USB device that carries
// a CCID interface (bInterfaceClass 0x0B, the smart card reader class)
// to true. The interface entries of a sysfs bus directory are named
// <device>:<config>.<interface>, the device name is the part before
// the first colon.
func usbCCIDDevices(root string, entries []os.DirEntry) map[string]bool {
	ccid := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		if i := strings.IndexByte(name, ':'); i > 0 {
			if readSysHex(filepath.Join(root, name, "bInterfaceClass")) == ccidInterfaceClass {
				ccid[name[:i]] = true
			}
		}
	}
	return ccid
}

// readerNameTokens extracts the matchable tokens of a pcscd reader
// name: the hotplug index groups stripped by normalizeReaderName, the
// parenthesized serial suffix pcscd optionally appends (" (0)" on a
// placeholder unit) and bare placeholder zeros dropped, the remaining
// fields upper cased. Every token must appear in the USB manufacturer
// and product strings of the reader's device.
func readerNameTokens(reader string) []string {
	var tokens []string
	for field := range strings.FieldsSeq(normalizeReaderName(reader)) {
		token := strings.ToUpper(field)
		if isHotplugIndex(field) {
			continue // enumeration group, sometimes trapped before a serial suffix
		}
		if len(token) >= 2 && token[0] == '(' && token[len(token)-1] == ')' {
			continue
		}
		if strings.Trim(token, "0") == "" {
			continue
		}
		tokens = append(tokens, token)
	}
	return tokens
}

// tokensIn reports whether every token appears in the device
// identification string, case folded by the caller.
func tokensIn(device string, tokens []string) bool {
	for _, token := range tokens {
		if !strings.Contains(device, token) {
			return false
		}
	}
	return true
}

// readSysString parses a sysfs text attribute, absent or unreadable
// files answer the empty string.
func readSysString(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// readSysHex parses a hexadecimal sysfs number file, absent or
// malformed files answer 0.
func readSysHex(path string) uint32 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 16, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// readSysNum parses a decimal sysfs number file, absent or malformed
// files answer 0, which never matches a resolved bus or device.
func readSysNum(path string) uint32 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// MachineID returns the stable hardware identity of this machine: the
// MAC addresses of its physical ethernet network interfaces, sorted,
// joined with "|" (for example "aa:bb:cc:dd:ee:01|aa:bb:cc:dd:ee:02"),
// or the empty string when the machine has no such interface. It
// reads the network stack through sysfs, pure Go: an interface counts
// as a stable hardware ethernet port when it is of type ethernet
// (ARPHRD_ETHER), is backed by a physical device (the sysfs device
// symlink, absent on loopback, bridges, bonds, vlans, veth and every
// other virtual interface), carries no wireless phy (the phy80211
// entry, present on every wifi interface) and has a real, non zero
// MAC burned in. MACs of different physical ports never repeat on one
// machine, and the MAC is the most stable identifier commodity
// hardware carries, it survives reboots, OS reinstalls and software
// reconfiguration.
func MachineID() string {
	return machineIDFrom(defaultSysfsNet)
}

// machineIDFrom is MachineID over an explicit sysfs class/net root,
// the test seam for the filter rules.
func machineIDFrom(root string) string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	var macs []string
	for _, entry := range entries {
		dir := filepath.Join(root, entry.Name())
		if !isHardwareEthernet(dir) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "address"))
		if err != nil {
			continue
		}
		mac := strings.TrimSpace(string(raw))
		if mac == "" || strings.Trim(mac, "0:") == "" {
			continue // no burned in address
		}
		macs = append(macs, mac)
	}
	slices.Sort(macs)
	return strings.Join(macs, "|")
}

// isHardwareEthernet reports whether the sysfs net interface directory
// is a physical ethernet port: type 1, a backing device, no wireless
// phy. The interface directories of a sysfs class tree are symlinks,
// every stat follows them.
func isHardwareEthernet(dir string) bool {
	if readSysNum(filepath.Join(dir, "type")) != 1 { // ARPHRD_ETHER, wifi is type 1 too
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "phy80211")); err == nil {
		return false // wireless, excluded by definition
	}
	_, err := os.Stat(filepath.Join(dir, "device"))
	return err == nil // only physical interfaces have a backing device
}
