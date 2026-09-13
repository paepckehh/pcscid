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
- **Per-card identity, not type detection** — reads the card's anti-collision UID through the PC/SC part 3 `GET DATA` APDU (`FF CA 00 00 00`) and folds it, together with the detected card type, into a short lowercase alphanumeric btag (`xxx-xxx-xxxx`).
- **Zero dependencies** — standard library only.
- **Hardware-free tests** — an in-process fake `pcscd` daemon exercises the whole protocol stack; `make test` needs no reader and no card, fully parallel.

## The btag

```text
ID = alnum( SHA-256("pcscid/v1|" + card-type + "|" + uid) [:10] )   # xxx-xxx-xxxx, digits and lower case
```

| Ingredient | Meaning |
| --- | --- |
| `card-type` | detected from the ATR: the PC/SC part 3 contactless table (`mifare classic 1k`, `mifare ultralight ev1`, `felica`, `picopass 16k`, ...), known full ATRs (`german eid/passport (npa)`, `yubikey 5 nfc`, `deutschlandticket (vdv-ka)`), or `unknown` |
| `uid` | the card's own unique tag, normally 4/7/10 bytes. When neither card nor reader can provide one, the ATR is used instead and the ID degrades to type level — `Card.Source` (`uid`, `atr`) tells you which |

The btag is stable across readers, restarts and re-presentations, contains no date, timestamp or reader name, and is short enough to paste anywhere. Its 10 characters come from the digits and lower case letters only, grouped into three dash separated segments `xxx-xxx-xxxx`. The library exports the derivation as `Btag(cardType, tag)`, and every `Card.ID` carries the result.

## Quick start

```console
$ make build
$ ./pcscid
bbc-7t: r3v-401-5gmr
```

Normal mode prints one line per card presentation: the stable reader tag, a colon and the btag, nothing else.

`DEBUG=1` turns on a complete verbose trace on stderr, while stdout stays machine-readable:

```console
$ DEBUG=1 ./pcscid
time=... level=DEBUG msg="pcscid starting" version=v0.0.1
time=... level=DEBUG msg="pcscd connected" socket=/run/pcscd/pcscd.comm version=4.4
time=... level=DEBUG msg="card inserted" reader="ACS ACR122U 00 00" \
    id=r3v-401-5gmr reader-tag=bbc-7t type="mifare classic 1k" source=uid uid="04 11 22 33" \
    atr="3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 94 37 26 CB 24" protocol=T=1
bbc-7t: r3v-401-5gmr
```

`./pcscid -version` prints the build-time semver, which the Makefile injects via `-ldflags` from the latest git tag.

## Bridge mode: loopback HTTP for browser pages

A browser sandbox cannot reach `/run/pcscd/pcscd.comm` — neither WebAssembly nor page JavaScript may open Unix sockets, and Firefox implements neither WebUSB nor WebHID. Set the environment variable `PCSCID_HTTP_ADDR` and the same binary additionally serves every card presentation's **reader tag** (`xxx-xx`) and **btag** (`xxx-xxx-xxxx`) as loopback HTTP, CORS-permissive so an HTTPS kiosk page may read `http://127.0.0.1:8976`:

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | `{"ok":true,"version":...}` liveness probe |
| `GET /events` | SSE stream (hello event, then one `card` event per scan, 20 s keep-alive) |
| `GET /pending?after=N` | JSON `{events:[...]}` polling fallback, replay by monotonic cursor |

| Variable | Effect |
| --- | --- |
| `PCSCID_HTTP_ADDR` | Listen address of the bridge, e.g. `127.0.0.1:8976`. Empty (the default) disables bridge mode — plain CLI output only |
| `PCSCID_HTTP_ALLOW_REMOTE` | `1` lifts the loopback guard; without it only loopback addresses are accepted, so card identities can never leave the kiosk by accident |

The bridge suppresses the initial "cards already present" report with a 2 s startup grace, so a card left on a reader never serves an event after a service restart, and debounces the same reader+card pair for 3 s. `scripts/pcscid-bridge.service` is the ready-made systemd unit (`After=pcscd`).

```console
$ PCSCID_HTTP_ADDR=127.0.0.1:8976 ./pcscid
bbc-7t: r3v-401-5gmr
```

The feature is a library piece too: feed a `pcscid.Bridge` from any event loop and serve it yourself.

```go
bridge := pcscid.NewBridge(nil)            // ring buffer, dedup and grace defaults
go bridge.Serve(ctx, "127.0.0.1:8976")      // or mount bridge.Handler() anywhere
for ev := range events {
	bridge.Feed(ev)                        // inserts become {reader tag, btag} events
}
```

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
pcscid.ReaderTag(reader)     // the xxx-xx reader tag
pcscid.Btag(type, uid)        // the xxx-xxx-xxxx btag
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

## Requirements

- Linux with `pcscd` running, a hard requirement — pcsc-lite 1.8.24+ speaks protocol 4.4/4.5 natively, older daemons are handled through protocol down-negotiation
- Go 1.25+ to build
- Socket `/run/pcscd/pcscd.comm`, `PCSCLITE_CSOCK_NAME` overrides it

## Install

```console
$ go install paepcke.de/pcscid/cmd/pcscid@latest     # from the module host
$ git clone https://paepcke.de/pcscid && make build  # from source, with semver baked in
```

## Project layout

```text
cmd/pcscid/       sample app: bare btags in normal mode, full trace with DEBUG=1, loopback HTTP bridge with PCSCID_HTTP_ADDR
pcsc/             pure Go pcscd wire-protocol client (Linux)
internal/pcscfake in-process fake pcscd daemon driving the hardware-free tests
pcscid.go         Watch loop, event model, identification
bridge.go         loopback HTTP bridge: SSE + polling of reader tags and btags for browser pages
atr.go            ISO 7816-3 answer-to-reset parser
cardtype.go       ATR to card type detection (PC/SC part 3 table, known ATRs)
uid.go            UID pseudo-APDU probe
version.go        semver via go linker -ldflags injection
scripts/          systemd unit for bridge mode on a kiosk (pcscid-bridge.service)
```

## Testing

```console
$ make test    # go test ./... — fully parallel, no hardware needed
```

The fake daemon speaks the same wire protocol re-implemented a second time, so client and fake agreeing is itself part of the test, and it emulates both daemon generations. The client was additionally verified live against a real pcscd 2.4.1.

## License

[MIT](LICENSE)
