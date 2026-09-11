package pcscid

import (
	"errors"
	"fmt"
	"log/slog"

	"paepcke.de/pcscid/pcsc"
)

// uidAPDU is the PC/SC part 3 GET DATA pseudo APDU: nearly all
// contactless readers answer it with the anti collision UID of the
// presented tag, which is the individual identifier of the card.
var uidAPDU = []byte{0xFF, 0xCA, 0x00, 0x00, 0x00}

// isRandomUID reports whether a UID is the ISO/IEC 14443-3 random
// UID: privacy cards (for example phone NFC emulation, eID, newer
// DESFire) answer the anti collision with a freshly generated 4 byte
// UID whose first byte is 0x08 on every activation. Such a UID
// changes on every touch and identifies nothing, the caller must
// fall back to the ATR, type level identity.
func isRandomUID(uid []byte) bool {
	return len(uid) == 4 && uid[0] == 0x08
}

// probeUID connects to the card in reader and asks for its UID. It
// returns nil when neither the card nor the reader can provide one,
// the caller then falls back to ATR based, type level identification.
func probeUID(cl *pcsc.Client, lg *slog.Logger, reader string) (uid []byte, protocol uint32) {
	card, err := cl.Connect(reader, pcsc.ProtocolAny)
	if errors.Is(err, pcsc.ErrProtoMismatch) {
		// Raw cards, for example some memory tags, negotiate nothing.
		card, err = cl.Connect(reader, pcsc.ProtocolRaw)
	}
	if err != nil {
		lg.Debug("connect failed, falling back to atr identity",
			"reader", reader, "error", err)
		return nil, 0
	}
	defer func() {
		if err := card.Disconnect(pcsc.LeaveCard); err != nil {
			lg.Debug("disconnect failed", "reader", reader, "error", err)
		}
	}()
	resp, err := card.Transmit(uidAPDU, 64)
	if err != nil {
		lg.Debug("uid apdu failed, falling back to atr identity",
			"reader", reader, "error", err)
		return nil, card.Protocol()
	}
	if len(resp) < 2 {
		lg.Debug("uid apdu too short", "reader", reader, "resp", fmt.Sprintf("% X", resp))
		return nil, card.Protocol()
	}
	sw1, sw2 := resp[len(resp)-2], resp[len(resp)-1]
	if sw1 != 0x90 || sw2 != 0x00 {
		lg.Debug("uid apdu rejected, falling back to atr identity",
			"reader", reader, "sw", fmt.Sprintf("%02X %02X", sw1, sw2))
		return nil, card.Protocol()
	}
	uid = resp[:len(resp)-2]
	if len(uid) == 0 {
		lg.Debug("uid apdu returned no uid", "reader", reader)
		return nil, card.Protocol()
	}
	if isRandomUID(uid) {
		lg.Debug("uid is iso 14443-3 random uid, not a card identity, falling back to atr identity",
			"reader", reader, "uid", fmt.Sprintf("% X", uid))
		return nil, card.Protocol()
	}
	lg.Debug("uid read",
		"reader", reader,
		"uid", fmt.Sprintf("% X", uid),
		"protocol", protocolName(card.Protocol()))
	return uid, card.Protocol()
}

func protocolName(p uint32) string {
	switch p {
	case pcsc.ProtocolT0:
		return "T=0"
	case pcsc.ProtocolT1:
		return "T=1"
	case pcsc.ProtocolRaw:
		return "raw"
	default:
		return fmt.Sprintf("0x%02X", p)
	}
}
