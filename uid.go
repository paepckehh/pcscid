package pcscid

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"paepcke.de/pcscid/pcsc"
)

// uidAPDU is the PC/SC part 3 GET DATA pseudo APDU: nearly all
// contactless readers answer it with the anti collision UID of the
// presented tag, which is the individual identifier of the card.
var uidAPDU = []byte{0xFF, 0xCA, 0x00, 0x00, 0x00}

// uidReadAttempts bounds how often the card connection and the UID
// exchange are retried before the identification gives up on the UID
// and falls back to the ATR. A freshly inserted contactless card is
// not yet activated when pcscd first reports it present: the reader
// state bit flips before the card is powered, so the first connect
// and the first exchange can both fail while the activation settles.
// Those failures are transient, a retry milliseconds later succeeds,
// and the identification insists on the UID instead of silently
// degrading to the type level ATR identity.
const uidReadAttempts = 4

// uidReadDelay is the pause between two UID read attempts, a short
// settling window for the card activation.
const uidReadDelay = 60 * time.Millisecond

// isRandomUID reports whether a UID is the ISO/IEC 14443-3 random
// UID: privacy cards (for example phone NFC emulation, eID, newer
// DESFire) answer the anti collision with a freshly generated 4 byte
// UID whose first byte is 0x08 on every activation. Such a UID
// changes on every touch and identifies nothing, the caller must
// fall back to the ATR, type level identity.
func isRandomUID(uid []byte) bool {
	return len(uid) == 4 && uid[0] == 0x08
}

// openCard connects to the card currently in reader, with the raw
// protocol fallback some memory tags need, and insists: the connect is
// retried a few times with a short pause, because pcscd reports a
// freshly inserted card present before it is activated and the very
// first connect can fail while the reader powers the card up. A reader
// without a present card keeps failing, like a raw Connect.
func openCard(cl *pcsc.Client, reader string) (*pcsc.Card, error) {
	var err error
	for attempt := 1; ; attempt++ {
		var card *pcsc.Card
		card, err = connectCard(cl, reader)
		if err == nil {
			return card, nil
		}
		if attempt >= uidReadAttempts {
			return nil, err
		}
		time.Sleep(uidReadDelay)
	}
}

// connectCard performs one connect attempt with the raw protocol
// fallback some memory tags need.
func connectCard(cl *pcsc.Client, reader string) (*pcsc.Card, error) {
	card, err := cl.Connect(reader, pcsc.ProtocolAny)
	if errors.Is(err, pcsc.ErrProtoMismatch) {
		// Raw cards, for example some memory tags, negotiate nothing.
		card, err = cl.Connect(reader, pcsc.ProtocolRaw)
	}
	return card, err
}

// transmitUID asks the presented card for its UID over an already
// open card connection and insists on an answer: the exchange is
// retried a few times with a short pause, because a freshly inserted
// card is still activating when the first exchange reaches it and a
// transient failure of that one attempt must not degrade the card
// identity to the ATR. It returns nil only when no attempt produced
// a UID, the caller then falls back to ATR based, type level
// identification. The exchange is real USB traffic to the reader
// hardware (a CCID XfrBlock bulk round trip), which the unit probe
// relies on to single the physical device out by its sysfs urbnum
// counter.
func transmitUID(card *pcsc.Card, lg *slog.Logger, reader string) (uid []byte, protocol uint32) {
	protocol = card.Protocol()
	for attempt := 1; ; attempt++ {
		uid, done := uidExchange(card, lg, reader, attempt)
		if done {
			return uid, protocol
		}
		if attempt >= uidReadAttempts {
			lg.Debug("uid unreadable after every attempt, falling back to atr identity",
				"reader", reader, "attempts", attempt)
			return nil, protocol
		}
		time.Sleep(uidReadDelay)
	}
}

// uidExchange performs one UID request and classifies its outcome.
// done is true when the answer is final: either a usable UID, or the
// ISO/IEC 14443-3 random UID, which identifies nothing (a new value
// on every activation, retrying cannot help, the caller falls back to
// the ATR). Everything else, a transport error, a truncated answer,
// an empty payload or any non 9000 status word, is transient at the
// activation seam of a freshly inserted card: the exchange is retried
// by transmitUID until it either produces a UID or the attempt budget
// is exhausted.
func uidExchange(card *pcsc.Card, lg *slog.Logger, reader string, attempt int) (uid []byte, done bool) {
	resp, err := card.Transmit(uidAPDU, 64)
	if err != nil {
		lg.Debug("uid apdu failed",
			"reader", reader, "attempt", attempt, "error", err)
		return nil, false
	}
	if len(resp) < 2 {
		lg.Debug("uid apdu too short",
			"reader", reader, "attempt", attempt, "resp", fmt.Sprintf("% X", resp))
		return nil, false
	}
	sw1, sw2 := resp[len(resp)-2], resp[len(resp)-1]
	if sw1 != 0x90 || sw2 != 0x00 {
		lg.Debug("uid apdu rejected",
			"reader", reader, "attempt", attempt, "sw", fmt.Sprintf("%02X %02X", sw1, sw2))
		return nil, false
	}
	uid = resp[:len(resp)-2]
	if len(uid) == 0 {
		lg.Debug("uid apdu returned no uid",
			"reader", reader, "attempt", attempt)
		return nil, false
	}
	if isRandomUID(uid) {
		lg.Debug("uid is iso 14443-3 random uid, not a card identity, falling back to atr identity",
			"reader", reader, "uid", fmt.Sprintf("% X", uid))
		return nil, true
	}
	lg.Debug("uid read",
		"reader", reader,
		"attempt", attempt,
		"uid", fmt.Sprintf("% X", uid),
		"protocol", protocolName(card.Protocol()))
	return uid, true
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
