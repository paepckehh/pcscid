package pcscid

import (
	"fmt"
	"slices"
)

// ATR is a parsed answer to reset as defined by ISO/IEC 7816-3.
type ATR struct {
	// TS is the initial character, 0x3B direct or 0x3F inverse
	// convention.
	TS byte
	// T0 carries the presence mask of the first interface byte group
	// in its high nibble and the number of historical bytes in its
	// low nibble.
	T0 byte
	// InterfaceBytes lists the TA, TB, TC and TD bytes of each
	// interface byte group in order of appearance.
	InterfaceBytes [][]byte
	// Historical is the historical byte sequence.
	Historical []byte
	// Protocols are the offered transmission protocols, starting with
	// the default T=0, deduplicated in order of first appearance.
	Protocols []byte
	// HasTCK reports whether a checksum byte is present, which is the
	// case as soon as any protocol other than T=0 is offered.
	HasTCK bool
	// TCK is the checksum byte, XOR of all bytes after TS.
	TCK byte
}

// ParseATR parses the answer to reset of a card. It tolerates the
// slightly non-conformant pseudo ATRs some contactless readers emit.
func ParseATR(b []byte) (ATR, error) {
	if len(b) < 2 {
		return ATR{}, fmt.Errorf("pcscid: atr too short: %d bytes", len(b))
	}
	ts := b[0]
	if ts != 0x3B && ts != 0x3F {
		return ATR{}, fmt.Errorf("pcscid: invalid atr initial character 0x%02X", ts)
	}
	t0 := b[1]
	historicalCount := int(t0 & 0x0F)
	pos := 2

	var protocols []byte
	addProtocol := func(p byte) {
		if !slices.Contains(protocols, p) {
			protocols = append(protocols, p)
		}
	}
	addProtocol(0) // default T=0

	mask := t0 >> 4 // Y(1) presence bits of interface byte group 1
	var groups [][]byte
	for mask != 0 {
		next := byte(0)
		group := make([]byte, 0, 4)
		for _, bit := range [...]byte{0x1, 0x2, 0x4, 0x8} {
			if mask&bit == 0 {
				continue
			}
			if pos >= len(b) {
				return ATR{}, fmt.Errorf("pcscid: truncated atr: missing interface byte at offset %d", pos)
			}
			value := b[pos]
			pos++
			if bit == 0x8 { // TD announces the next group
				addProtocol(value & 0x0F)
				next = value >> 4
			}
			group = append(group, value)
		}
		groups = append(groups, group)
		mask = next
	}
	if pos+historicalCount > len(b) {
		return ATR{}, fmt.Errorf("pcscid: truncated atr: expected %d historical bytes, %d left", historicalCount, len(b)-pos)
	}
	historical := append([]byte(nil), b[pos:pos+historicalCount]...)
	pos += historicalCount

	var tck byte
	hasTCK := len(protocols) > 1 // any protocol other than T=0
	if hasTCK {
		if pos >= len(b) {
			return ATR{}, fmt.Errorf("pcscid: truncated atr: missing tck")
		}
		tck = b[pos]
		pos++
	}
	if pos != len(b) {
		return ATR{}, fmt.Errorf("pcscid: atr has %d trailing bytes", len(b)-pos)
	}

	return ATR{
		TS:             ts,
		T0:             t0,
		InterfaceBytes: groups,
		Historical:     historical,
		Protocols:      protocols,
		HasTCK:         hasTCK,
		TCK:            tck,
	}, nil
}

// ChecksumOK reports whether the TCK matches the XOR of all bytes
// after TS and before the TCK. It is true when the ATR carries no
// checksum. The atr argument is the raw ATR the receiver was parsed
// from.
func (a ATR) ChecksumOK(atr []byte) bool {
	if !a.HasTCK || len(atr) < 3 {
		return true
	}
	var sum byte
	for _, b := range atr[1 : len(atr)-1] {
		sum ^= b
	}
	return sum == a.TCK
}
