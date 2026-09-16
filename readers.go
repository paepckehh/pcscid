// Reader inventory: the startup evaluation of every reader currently
// registered with the local pcscd.
//
// IdentifyReaders answers the operator question "what exactly is
// attached here and which tags will it serve" before the first card
// is presented: it enumerates the daemon's reader state array and
// derives every identity tier of each reader — the model level tag
// from the reader name, the per-unit facts (hardware serial, physical
// USB port path) when a card is present to probe them with, and the
// effective tag under the configured Options, including the machine
// component of Options.MACID.
//
// The per-unit facts need an open card connection (SCardGetAttrib
// talks to the driver through the card), so a reader reported without
// a card carries the model level tag only; its Tier says "model".
// The same limitation applies to Watch's insert events, the report
// just makes it visible at startup instead of after the first scan.
package pcscid

import (
	"fmt"

	"paepcke.de/pcscid/pcsc"
)

// ReaderInfo is the evaluated identity of one reader registered with
// the local pcscd, one entry of the IdentifyReaders inventory.
type ReaderInfo struct {
	// Reader is the pcscd reader name, for example
	// "ACS ACR122U 00 00".
	Reader string
	// ModelTag is the model level tag (ReaderTag): derived from the
	// normalized reader name alone, identical for two units of the
	// same model.
	ModelTag string
	// Serial is the hardware serial number of the unit
	// (SCARD_ATTR_VENDOR_IFD_SERIAL_NO) when the driver serves a
	// usable one, empty otherwise. It is only probeable while a
	// card is present.
	Serial string
	// Port is the kernel physical USB port path of the unit
	// (sysfs devpath, for example "2-1.3") when Options.USBPathID
	// allows it and the reader serves no usable serial. It is only
	// probeable while a card is present.
	Port string
	// Tier names the portability tier of the per-unit facts that
	// produced Tag: "serial" (one tag per unit, portable), "port"
	// (one tag per USB port, not portable) or "model" (no per-unit
	// fact readable, name only).
	Tier string
	// Tag is the effective reader tag under the configured Options:
	// ReaderTagWithMachine over the probed facts, the tag every
	// insertion event of this reader will carry in Event.ReaderTag.
	Tag string
	// CardPresent reports whether a card sits on the reader.
	CardPresent bool
	// Card is the identification of the presented card, the same
	// derivation an insertion event carries, nil when CardPresent
	// is false.
	Card *Card
}

// IdentifyReaders evaluates every reader currently registered with
// the local pcscd and answers the inventory of their identities: the
// reader name, every derivable tag and the per-unit facts behind it,
// plus the identification of a card that is already present. The
// evaluation uses the same options and derivations as Watch, so the
// reported Tag is exactly the tag the reader's insertion events will
// carry. Readers with a presented card are probed over a full card
// connection (serial, port, card UID). Readers without a card cannot
// open the connection the driver attributes need, but with
// USBPathID enabled their USB port is still pinned from the sysfs
// device scan when it is unambiguous (or every other identical unit is
// already owned by its own probe); they report the model level tier
// otherwise.
//
// When the pcscd socket cannot be reached, IdentifyReaders fails with
// that error, the pcscd service is a hard requirement.
func IdentifyReaders(opts *Options) ([]ReaderInfo, error) {
	lg, env := watchOptions(opts)
	cl, err := pcsc.New(env.socketPath, lg)
	if err != nil {
		return nil, fmt.Errorf("pcscid: pcscd unavailable: %w", err)
	}
	defer cl.Close()
	states, err := cl.States()
	if err != nil {
		return nil, fmt.Errorf("pcscid: reader states unreadable: %w", err)
	}
	reg := newUnitRegistry()
	readers := make([]ReaderInfo, 0, len(states))
	for _, st := range states {
		info := ReaderInfo{
			Reader:      st.Reader,
			ModelTag:    ReaderTag(st.Reader),
			CardPresent: st.State&pcsc.ReaderPresent != 0,
		}
		if info.CardPresent {
			facts := probeReaderCard(cl, lg, st.Reader, env.sysfsRoot, env.useUSBPath, reg.byPort)
			facts = reg.adopt(lg, st.Reader, facts)
			info.Serial = facts.serial
			info.Port = facts.port
			info.Card = identify(lg, st, facts, env.machine)
		} else if env.useUSBPath {
			// Without a card there is no connection and no probe
			// traffic, but the sysfs device scan still pins the
			// port when it is unambiguous: exactly one CCID device
			// matches the reader name, or every other identical
			// unit is already claimed by its own probe.
			port, reason := usbPortPathByReader(lg, env.sysfsRoot, st.Reader, nil, nil, reg.byPort)
			if port != "" {
				info.Port = reg.adopt(lg, st.Reader, readerFacts{port: port}).port
				lg.Info("reader usb port pinned without a card",
					"reader", st.Reader, "port", info.Port)
			} else {
				lg.Debug("reader usb port not pinned card-less",
					"reader", st.Reader, "reason", reason)
			}
		}
		info.Tier = unitTier(info.Serial, info.Port)
		info.Tag = ReaderTagWithMachine(st.Reader, info.Serial, info.Port, env.machine)
		readers = append(readers, info)
	}
	return readers, nil
}
