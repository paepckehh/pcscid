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

// uidReadAttempts bounds how often the UID exchange is retried on
// one open card connection before that connection is given up on. A
// freshly inserted contactless card is not yet activated when pcscd
// first reports it present: the reader state bit flips before the
// card is powered, so the first connect and the first exchanges can
// fail while the activation settles. Those failures are transient, a
// retry milliseconds later succeeds.
const uidReadAttempts = 3

// uidReadRounds bounds how many card connections the UID read insists
// on: a reader can answer the UID pseudo APDU with 63 00 while the
// freshly activated PICC sits in a state its firmware cannot serve,
// and that state sticks for every further exchange on the same
// connection. Only a card reset (a power cycle, the reader reruns the
// anti collision) clears it, so every failed round resets the card
// and reopens the connection before the identification gives up on
// the UID and falls back to the ATR.
const uidReadRounds = 3

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

// transmitUID asks the presented card for its UID over one open card
// connection and reports whether that connection produced a final
// answer: done is true for a usable UID and for the ISO/IEC 14443-3
// random UID, which identifies nothing (a new value on every
// activation, no retry can help). Every other outcome, a transport
// error, a truncated answer, an empty payload or any non 9000 status
// word such as the 63 00 of a PICC the reader firmware cannot serve,
// leaves the connection suspect: transmitUID retries the exchange a
// few times, and when the connection never answers, done stays false
// and the caller (insistUID) resets the card and opens a fresh one.
// The exchange is real USB traffic to the reader hardware (a CCID
// XfrBlock bulk round trip), which the unit probe relies on to single
// the physical device out by its sysfs urbnum counter.
func transmitUID(card *pcsc.Card, lg *slog.Logger, reader string, round int) (uid []byte, protocol uint32, done bool) {
	protocol = card.Protocol()
	for attempt := 1; ; attempt++ {
		uid, final := uidExchange(card, lg, reader, attempt)
		if final {
			return uid, protocol, true
		}
		if attempt >= uidReadAttempts {
			lg.Debug("uid unreadable on this connection",
				"reader", reader, "round", round, "attempts", attempt)
			return nil, protocol, false
		}
		time.Sleep(uidReadDelay)
	}
}

// uidExchange performs one UID request and classifies its outcome.
// done is true when the answer is final: either a usable UID, or the
// ISO/IEC 14443-3 random UID, which identifies nothing (a new value
// on every activation, retrying cannot help, the caller falls back to
// the ATR). Everything else, a transport error, a truncated answer,
// an empty payload or any non 9000 status word, is suspect on a
// freshly activated contactless card: it is retried by transmitUID
// on the same connection and, when that never succeeds, answered
// with a card reset by insistUID.
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

// insistUID reads the UID of the presented card and insists on it
// across card resets. A contactless reader can wedge the freshly
// activated PICC into a state its firmware cannot serve: every UID
// exchange on that connection then answers 63 00, no same connection
// retry can clear it. A disconnect with SCARD_RESET_CARD powers the
// card down and up again, the reader reruns the anti collision, and
// the UID becomes readable. So every round that produced no final
// answer resets the card and opens a fresh connection, up to
// uidReadRounds rounds of uidReadAttempts exchanges each, before the
// identification gives up and the caller falls back to the ATR, the
// type level identity. Only two answers end the insistence early: a
// usable UID (success), and the ISO/IEC 14443-3 random UID, which
// identifies nothing and never improves through a reset.
//
// insistUID owns the card lifecycle: intermediate connections are
// already disconnected here, the returned live connection is the one
// the caller must disconnect (nil when the last reopen failed). The
// protocol is the one of the connection the UID was read on, or of
// the last connection tried.
func insistUID(cl *pcsc.Client, card *pcsc.Card, lg *slog.Logger, reader string) (uid []byte, protocol uint32, live *pcsc.Card) {
	live = card
	for round := 1; ; round++ {
		uid, protocol, done := transmitUID(live, lg, reader, round)
		if done {
			return uid, protocol, live
		}
		if round >= uidReadRounds {
			lg.Error("uid unreadable after every round, the card identity falls back to the atr",
				"reader", reader, "rounds", round,
				"consequence", "the btag identifies the card type, not the individual card")
			return nil, protocol, live
		}
		lg.Debug("uid unreadable on this connection, resetting the card",
			"reader", reader, "round", round)
		if err := live.Disconnect(pcsc.ResetCard); err != nil {
			lg.Debug("card reset disconnect failed",
				"reader", reader, "round", round, "error", err)
		}
		next, err := openCard(cl, reader)
		if err != nil {
			lg.Debug("card reopen after reset failed",
				"reader", reader, "round", round, "error", err)
			return nil, protocol, nil
		}
		live = next
	}
}
