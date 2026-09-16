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

// probeReaderUnit asks the driver for the per-unit identity of reader:
// its hardware serial and, only when no usable serial exists and
// useUSBPath allows it, its USB port path. Both need an open card
// connection, they are probed only while a card is presented. Failures
// are best effort, an unusable serial and an unresolvable channel id
// map to the empty strings, the caller then falls back to the model
// level tag.
func probeReaderUnit(cl *pcsc.Client, lg *slog.Logger, reader, sysfsRoot string, useUSBPath bool) (serial, port string) {
	card, err := openCard(cl, reader)
	if err != nil {
		lg.Debug("reader unit probe connect failed",
			"reader", reader, "error", err)
		return "", ""
	}
	defer func() {
		if err := card.Disconnect(pcsc.LeaveCard); err != nil {
			lg.Debug("reader unit probe disconnect failed", "reader", reader, "error", err)
		}
	}()

	serial = readVendorSerial(card, lg, reader)
	if serial != "" || !useUSBPath {
		return serial, ""
	}
	// No usable serial: anchor the unit to its physical USB port.
	bus, dev, ok := readChannelID(card, lg, reader)
	if !ok {
		return "", ""
	}
	port = usbPortPath(sysfsRoot, bus, dev)
	if port != "" {
		lg.Debug("reader usb port resolved",
			"reader", reader, "bus", bus, "device", dev, "port", port)
	} else {
		lg.Debug("reader usb port unresolved",
			"reader", reader, "bus", bus, "device", dev)
	}
	return "", port
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
// the CCID packing 0x0020<<16 | bus<<8 | device.
func readChannelID(card *pcsc.Card, lg *slog.Logger, reader string) (bus, dev uint32, ok bool) {
	attr, err := card.GetAttrib(pcsc.AttrChannelID)
	if err != nil {
		lg.Debug("reader channel id unavailable",
			"reader", reader, "error", err)
		return 0, 0, false
	}
	if len(attr) != 4 {
		lg.Debug("reader channel id malformed",
			"reader", reader, "attr", fmt.Sprintf("% X", attr))
		return 0, 0, false
	}
	id := uint32(attr[0]) | uint32(attr[1])<<8 | uint32(attr[2])<<16 | uint32(attr[3])<<24
	if id>>16 != channelIDUSBType {
		lg.Debug("reader channel is not usb, no port path",
			"reader", reader, "channel", fmt.Sprintf("0x%08X", id))
		return 0, 0, false
	}
	return (id >> 8) & 0xFF, id & 0xFF, true
}

// usbPortPath resolves the USB bus/device address of a reader to the
// kernel physical port path (sysfs devpath, for example "2-1.3").
// The entries of a sysfs bus directory are symlinks into
// /sys/devices, so every candidate is stat-ed, not classified by its
// directory entry type. It returns the empty string when the device
// cannot be found, sysfs is unreadable or root is empty.
func usbPortPath(root string, bus, dev uint32) string {
	if root == "" {
		return ""
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
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
			return ""
		}
		return strings.TrimSpace(string(raw))
	}
	return ""
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
