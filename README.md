# pcscid

**One short, stable btag for every smart card you present — any card, any reader, pure Go.**

[![go version](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](#)
[![cgo](https://img.shields.io/badge/cgo-none-success)](#)
[![dependencies](https://img.shields.io/badge/dependencies-0-informational)](#)
[![license](https://img.shields.io/badge/license-MIT-blue)](#license)

`pcscid` watches every reader registered with your local `pcscd` and prints a compact unique identifier the moment a card is presented: NFC, Mifare, RFID, ISO 14443, eID, YubiKey, contact cards — anything the daemon manages.

The same card always yields the same btag, on every reader, on every presentation. Two cards of the same model yield **different** btags, because the btag is derived from the card's own unique tag, not just its type.

## Highlights

- **Pure Go, no cgo, Linux only** — speaks the `pcscd` daemon wire protocol directly over its Unix socket, no `libpcsclite` linked, the binary is a single static build. Speaks both protocol generations: 4.5 of pcsc-lite 2.x and 4.4 with down-negotiation for 1.8.x/1.9.x daemons.
- **Per-card identity, not type detection** — reads the card's anti-collision UID through the PC/SC part 3 `GET DATA` APDU (`FF CA 00 00 00`) and folds it, together with the detected card type, into a short alphanumeric btag (`xxxx-xxx-xxxx`).
- **Zero dependencies** — standard library only.
- **Fails gracefully** — no `pcscd` socket reachable? Falls back to continuously parsing `pcsc_scan` output (type-level identity only, and it tells you so).
- **Hardware-free tests** — an in-process fake `pcscd` daemon exercises the whole protocol stack; `make test` needs no reader and no card, fully parallel.

## The btag

```text
ID = alnum( SHA-256("pcscid/v1|" + card-type + "|" + uid) [:11] )
```

| Ingredient | Meaning |
| --- | --- |
| `card-type` | detected from the ATR: the PC/SC part 3 contactless table (`mifare classic 1k`, `mifare ultralight ev1`, `felica`, `picopass 16k`, ...), known full ATRs (`german eid/passport (npa)`, `yubikey 5 nfc`, `deutschlandticket (vdv-ka)`), or `unknown` |
| `uid` | the card's own unique tag, normally 4/7/10 bytes. When neither card nor reader can provide one, the ATR is used instead and the ID degrades to type level — `Card.Source` (`uid`, `atr`, `scan`) tells you which |

The btag is stable across readers, restarts and re-presentations, contains no date, timestamp or reader name, and is short enough to paste anywhere. Its 11 characters come from the full alphanumeric alphabet — digits, lower and upper case — grouped into three dash separated segments `xxxx-xxx-xxxx`. The library exports the derivation as `Btag(cardType, tag)`, and every `Card.ID` carries the result.

## Quick start

```console
$ make build
$ ./pcscid
rnpe-ubP-qWBj
```

Normal mode prints the bare btag plus a newline, nothing else — one line per card presentation. The sample app is the full API in ~70 lines.

`DEBUG=1` turns on a complete verbose trace on stderr, while stdout stays machine-readable:

```console
$ DEBUG=1 ./pcscid
time=... level=DEBUG msg="pcscid starting" version=v0.0.1
time=... level=DEBUG msg="pcscd connected" socket=/run/pcscd/pcscd.comm version=4.4
time=... level=DEBUG msg="card inserted" reader="ACS ACR122U 00 00" \
    id=rnpe-ubP-qWBj type="mifare classic 1k" source=uid uid="04 11 22 33" \
    atr="3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A" protocol=T=1
rnpe-ubP-qWBj
```

`./pcscid -version` prints the build-time semver, which the Makefile injects via `-ldflags` from the latest git tag.

## Use the library

```go
events, err := pcscid.Watch(ctx, &pcscid.Options{Logger: logger})
if err != nil {
	log.Fatal(err)
}
for ev := range events {
	switch ev.Kind {
	case pcscid.KindInsert:
		fmt.Println(ev.Card.ID, ev.Card.Type, ev.Card.Source)
	case pcscid.KindRemove:
		fmt.Println("removed from", ev.Reader)
	}
}
```

`Watch` reports cards that are already present at startup, follows hot-plugged readers, reconnects when `pcscd` restarts, and closes its channel once the context is cancelled.

```go
// Fine-grained pieces are exported too:
pcscid.DetectType(atr)      // "mifare classic 1k"
pcscid.ParseATR(atr)        // full ISO 7816-3 ATR breakdown
pcscid.Btag(type, uid)       // the xxxx-xxx-xxxx btag
```

## Card types recognized

| Source | Cards |
| --- | --- |
| PC/SC part 3 ATR table | MIFARE Classic 1K/4K, Mini, Ultralight / C / EV1, MIFARE Plus SL1/SL2, FeliCa, PicoPass family, Topaz, Jewel, ICODE family, SLE55R / my-d, TAG IT, LRI family, AT88 family, Melexis sensor tag |
| Known ATRs | German eID / passport (npa), YubiKey 5 NFC, Deutschlandticket (VDV-KA) |
| Everything else | `unknown` type, still identified by UID when the reader provides one — the UID probe works for any ISO 14443 tag and most contactless readers |

## How it works

```text
cmd/pcscid ──▶ pcscid.Watch ──▶ pcsc.Client ──▶ /run/pcscd/pcscd.comm ──▶ pcscd ──▶ reader ──▶ card
                (events, IDs)     (pure Go          (wire protocol 4.5 or 4.4,
                                    client)           negotiated per daemon)
```

1. `pcsc.Client` performs the header-less version handshake (claims 4.4, adopts 4.5 when pcscd 2.x offers it, down-negotiates for old daemons), establishes a context and fetches the 16-entry `READER_STATE` array — reader names, presence bits, event counters, ATRs.
2. Card insertion events (presence bit plus event counter change) trigger identification: connect in shared mode, negotiate T=0/T=1, transmit the UID pseudo-APDU, disconnect.
3. The ATR yields the card type; type plus UID (or ATR) yields the btag.
4. Reader state waits are server-side with a bounded tick; on pcscd 2.x the wait answers with the fresh state array itself and timeouts are client-side, unblocking the daemon through the stop request. Context cancellation closes the socket to unblock instantly. When no reader is registered at all the daemon answers the wait immediately, so the loop polls gently instead of spinning.
5. If the socket is unreachable at startup, `Watch` falls back to running `pcsc_scan` and parsing its ATR lines — carefully ignoring dates, event numbers and spinner noise. The `pcsc-scan-example-*.txt` files in this repo are real captures that the test suite runs through that parser.

## Requirements

- Linux with `pcscd` (pcsc-lite 1.8.26 or newer) running, **or** `pcsc-tools` (`pcsc_scan`) as the text fallback
- Go 1.25+ to build
- Socket `/run/pcscd/pcscd.comm`, `PCSCLITE_CSOCK_NAME` overrides it

## Install

```console
$ go install paepcke.de/pcscid/cmd/pcscid@latest     # from the module host
$ git clone https://paepcke.de/pcscid && make build  # from source, with semver baked in
```

## Project layout

```text
cmd/pcscid/       sample app: bare btags in normal mode, full trace with DEBUG=1
pcsc/             pure Go pcscd wire-protocol client (Linux)
internal/pcscfake in-process fake pcscd daemon driving the hardware-free tests
pcscid.go         Watch loop, event model, identification
atr.go            ISO 7816-3 answer-to-reset parser
cardtype.go       ATR to card type detection (PC/SC part 3 table, known ATRs)
uid.go            UID pseudo-APDU probe
scan.go           pcsc_scan output fallback parser
version.go        semver via go linker -ldflags injection
```

## Testing

```console
$ make test    # go test ./... — fully parallel, no hardware needed
```

The fake daemon speaks the same wire protocol re-implemented a second time, so client and fake agreeing is itself part of the test, and it emulates both daemon generations. Fixture coverage includes every `pcsc-scan-example-*.txt` capture. The client was additionally verified live against a real pcscd 2.4.1.

## License

[MIT](LICENSE)
