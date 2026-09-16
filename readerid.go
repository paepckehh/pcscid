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

// probeReaderUnit asks the driver for the per-unit identity of reader:
// its hardware serial and, only when no usable serial exists and
// useUSBPath allows it, its USB port path. Both need an open card
// connection, they are probed only while a card is presented. Failures
// are best effort, an unusable serial and an unresolvable channel id
// map to the empty strings, the caller then falls back to the model
// level tag. With useUSBPath enabled the port resolution is two
// staged: first the channel id through the driver, then the sysfs USB
// tree scanned for the reader's CCID device by name, and with several
// identical candidates the unit is singled out by its USB traffic —
// the probe exchange itself moves the sysfs urbnum counter of exactly
// the probed physical device, a snapshot taken before the connection
// and one taken after the attribute reads identify it. That correlation
// is exact and independent of the daemon's reader order, so the same
// physical reader on the same port derives the same tag across
// service restarts, daemon restarts and reboots. A port that stays
// unresolved is reported as a qualified error naming every failed
// step, because the operator asked for a per-unit identity and
// silently losing it makes two identical readers collide on one tag.
func probeReaderUnit(cl *pcsc.Client, lg *slog.Logger, reader, sysfsRoot string, useUSBPath bool) (serial, port string) {
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
		return "", ""
	}
	defer func() {
		if err := card.Disconnect(pcsc.LeaveCard); err != nil {
			lg.Debug("reader unit probe disconnect failed", "reader", reader, "error", err)
		}
	}()

	serial = readVendorSerial(card, lg, reader)
	if serial == "" && useUSBPath {
		var reasons []string
		if bus, dev, reason := readChannelID(card, lg, reader); reason == "" {
			var portReason string
			port, portReason = usbPortPath(lg, sysfsRoot, bus, dev)
			if port != "" {
				lg.Debug("reader usb port resolved by channel id",
					"reader", reader, "bus", bus, "device", dev, "port", port)
			} else {
				reasons = append(reasons, portReason)
			}
		} else {
			reasons = append(reasons, reason)
		}
		if port == "" {
			var nameReason string
			port, nameReason = usbPortPathByReader(lg, sysfsRoot, reader, before, usbUrbSnapshot(sysfsRoot))
			if port != "" {
				lg.Info("reader usb port resolved",
					"reader", reader, "port", port)
			} else {
				reasons = append(reasons, nameReason)
				lg.Error("reader usb port identity unresolved (PCSCID_USB_PATH_ID=1)",
					"reader", reader,
					"reason", strings.Join(reasons, "; "),
					"sysfs", sysfsRoot,
					"consequence", "the reader keeps the model level tag, identical units share one tag")
			}
		}
	} else if serial == "" {
		lg.Debug("reader usb port path identity not enabled (PCSCID_USB_PATH_ID)", "reader", reader)
	}
	// The identity outcome is reported at info level, so the USB
	// anchoring is visible even without the debug trace.
	lg.Info("reader unit identity",
		"reader", reader, "serial", serial, "port", port, "tier", unitTier(serial, port))
	return serial, port
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
// interface (bInterfaceClass 0x0B).
//
// Exactly one matching device identifies the port directly. N matching
// devices are N identical reader units: they are told apart by their
// USB traffic, not by order — before and after hold the sysfs urbnum
// counters of the probe window (see probeReaderUnit), and the device
// whose counter moved is the probed unit. The correlation is exact and
// independent of the daemon's reader order, so the same physical
// reader on the same port keeps its tag across service restarts,
// daemon restarts and reboots. When the counters do not single one
// device out the scan refuses with a qualified reason, the reader then
// keeps the stable model level tag instead of a shuffling guess.
func usbPortPathByReader(lg *slog.Logger, root, reader string, before, after map[string]uint32) (port, reason string) {
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
	switch len(candidates) {
	case 0:
		return "", "no CCID USB device in sysfs matches the reader name"
	case 1:
		devpath := readSysString(filepath.Join(root, candidates[0], "devpath"))
		if devpath == "" {
			return "", fmt.Sprintf("the USB device %s carries no devpath", candidates[0])
		}
		lg.Debug("usb port path name scan matched",
			"reader", reader, "device", candidates[0], "port", devpath)
		return devpath, ""
	}
	// N identical units without a channel id: single the probed one out
	// by its USB traffic across the probe window.
	winner, ok := usbUrbWinner(before, after, candidates)
	if !ok {
		return "", fmt.Sprintf("%d CCID USB devices match the reader name and the usb traffic did not single one out, the unit mapping is ambiguous without the channel id", len(candidates))
	}
	devpath := readSysString(filepath.Join(root, winner, "devpath"))
	if devpath == "" {
		return "", fmt.Sprintf("the USB device %s carries no devpath", winner)
	}
	lg.Info("usb port resolved by traffic correlation",
		"reader", reader, "device", winner, "port", devpath,
		"urb", after[winner]-before[winner])
	return devpath, ""
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
// runner up by the margin, anything else is ambiguous and refuses.
func usbUrbWinner(before, after map[string]uint32, candidates []string) (name string, ok bool) {
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
	for _, field := range strings.Fields(normalizeReaderName(reader)) {
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
