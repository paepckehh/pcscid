package pcscid

import (
	"bytes"
	"encoding/hex"
	"strings"
)

// pcscRID is the PC/SC Workgroup registered application provider
// identifier that contactless readers place in the ATR historical
// bytes of a card, followed by the standard and card type bytes.
var pcscRID = []byte{0xA0, 0x00, 0x00, 0x03, 0x06}

// pcscStandard maps the standard byte after the RID in a contactless
// pseudo ATR to a card family name, PC/SC part 3.
var pcscStandard = map[byte]string{
	0x00: "rfid, no standard given",
	0x01: "rfid, iso 14443 type a part 1",
	0x02: "rfid, iso 14443 type a part 2",
	0x03: "iso 14443 type a, pc/sc part 3",
}

// pcscCardType maps the card type byte two bytes after the RID of a
// contactless pseudo ATR to its name, PC/SC part 3 table E.1, in the
// same spelling as the pcsc-tools smartcard_list.
var pcscCardType = map[byte]string{
	0x00: "contactless, card name not given",
	0x01: "mifare classic 1k",
	0x02: "mifare classic 4k",
	0x03: "mifare ultralight",
	0x04: "sle55r",
	0x06: "sr176",
	0x07: "sri x4k",
	0x08: "at88rf020",
	0x09: "at88sc0204crf",
	0x0A: "at88sc0808crf",
	0x0B: "at88sc1616crf",
	0x0C: "at88sc3216crf",
	0x0D: "at88sc6416crf",
	0x0E: "srf55v10p",
	0x0F: "srf55v02p",
	0x10: "srf55v10s",
	0x11: "srf55v02s",
	0x12: "tag it",
	0x13: "lri512",
	0x14: "icodesli",
	0x15: "tempsens",
	0x16: "i-code1",
	0x17: "picopass 2k",
	0x18: "picopass 2ks",
	0x19: "picopass 16k",
	0x1A: "picopass 16ks",
	0x1B: "picopass 16k(8x2)",
	0x1C: "picopass 16ks(8x2)",
	0x1D: "picopass 32ks(16+16)",
	0x1E: "picopass 32ks(16+8x2)",
	0x1F: "picopass 32ks(8x2+16)",
	0x20: "picopass 32ks(8x2+8x2)",
	0x21: "lri64",
	0x22: "i.code uid",
	0x23: "i.code epc",
	0x24: "lri12",
	0x25: "lri128",
	0x26: "mifare mini",
	0x27: "my-d move (sle 66r01p)",
	0x28: "my-d nfc (sle 66rxxp)",
	0x29: "my-d proximity 2 (sle 66rxxs)",
	0x2A: "my-d proximity enhanced (sle 55rxxe)",
	0x2B: "my-d light (srf 55v01p)",
	0x2C: "pjm stack tag (srf 66v10st)",
	0x2D: "pjm item tag (srf 66v10it)",
	0x2E: "pjm light (srf 66v01st)",
	0x2F: "jewel tag",
	0x30: "topaz nfc tag",
	0x31: "at88sc0104crf",
	0x32: "at88sc0404crf",
	0x33: "at88rf01c",
	0x34: "at88rf04c",
	0x35: "i-code sl2",
	0x36: "mifare plus sl1 2k",
	0x37: "mifare plus sl1 4k",
	0x38: "mifare plus sl2 2k",
	0x39: "mifare plus sl2 4k",
	0x3A: "mifare ultralight c",
	0x3B: "felica",
	0x3C: "melexis sensor tag (mlx90129)",
	0x3D: "mifare ultralight ev1",
}

// knownATR maps complete ATRs of cards that carry no PC/SC contact
// identification to a type name, keyed by uppercase hex.
var knownATR = map[string]string{
	"3B8480018082900097":                   "german eid/passport (npa)",
	"3B8D80018073C021C057597562694B65FF7F": "yubikey 5 nfc",
	"3B8580015A4356445659":                 "deutschlandticket (vdv-ka)",
}

// DetectType returns a card type name for an answer to reset. The
// name distinguishes card families and models, the unique identifier
// of an individual card comes from its UID, see Identify.
func DetectType(atr []byte) string {
	if name, ok := knownATR[hexUpper(atr)]; ok {
		return name
	}
	parsed, err := ParseATR(atr)
	if err != nil {
		return "unknown"
	}
	at := bytes.Index(parsed.Historical, pcscRID)
	if at < 0 || at+7 >= len(parsed.Historical) {
		return "unknown"
	}
	standard := parsed.Historical[at+len(pcscRID)]
	cardType := parsed.Historical[at+len(pcscRID)+2]
	if name, ok := pcscCardType[cardType]; ok && standard == 0x03 {
		return name
	}
	if name, ok := pcscStandard[standard]; ok {
		return name
	}
	return "pc/sc contactless, unspecified"
}

// hexUpper renders b as upper case hex, the key format of knownATR.
func hexUpper(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
