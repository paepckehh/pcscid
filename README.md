<div align="center">

# pcscid

**One short, stable ID for every smart card you tap. Any card, any reader, pure Go.**

[![go version](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](#)
[![cgo](https://img.shields.io/badge/cgo-none-success)](#)
[![dependencies](https://img.shields.io/badge/dependencies-0-informational)](#)
[![platform](https://img.shields.io/badge/platform-linux-1793d1?logo=linux)](#)
[![license](https://img.shields.io/badge/license-MIT-blue)](#license)

*NFC · MIFARE · RFID · ISO 14443 · eID · YubiKey · contact cards — anything `pcscd` manages.*

</div>

---

Tap a card. Get an ID like `r3v-401-5gmr`. Tap it again tomorrow, on a different machine, through a different reader — **same ID, every time**. Two cards of the same model? **Different IDs.** That's the whole idea, and it's what makes `pcscid` the missing piece between "a card was presented" and "this specific card was presented".

No cgo. No `libpcsclite`. No dependencies. One static binary that talks the `pcscd` daemon wire protocol itself, plus a tiny loopback HTTP bridge so even a browser kiosk page can react to card scans.

```console
$ ./pcscid
#qrx-lr:r3v-401-5gmr        # reader tag, btag; # marks a btag line
```

## Why pcscid

Every other smart card tooling path funnels you through C bindings, type detection, or both. `pcscid` takes a different bet:

- **Identity, not just type detection.** The ATR alone tells you *a MIFARE Classic 1K was tapped* — every card of that model shares it. `pcscid` reads the card's own anti-collision UID through the PC/SC part 3 `GET DATA` APDU (`FF CA 00 00 00`) and folds it into a short **btag**: `xxx-xxx-xxxx`, digits and lowercase letters, stable across readers, machines, daemon restarts and USB ports.
- **Pure Go, zero cgo, zero dependencies.** The pcscd IPC protocol ([framed requests](https://pcsclite.apdu.fr/), raw struct responses) is implemented from scratch against pcsc-lite 1.8.24 through 2.4.x, including version down-negotiation for old daemons. One static binary, nothing to link, nothing to break.
- **Hardware-free tests.** A second, independent in-process implementation of the whole wire protocol acts as a fake `pcscd`. Client and fake agreeing is itself under test — `make test` needs no reader, no card, runs fully parallel.
- **Privacy cards handled correctly.** ISO/IEC 14443-3 random UIDs (phone NFC emulation, eID, newer DESFire — a *new* UID per activation) are detected and rejected as identifiers, with a clean fallback to type level. `Card.Source` (`uid` / `atr`) always tells you which identity you got.

## The btag

```text
ID = alnum( SHA-256("pcscid/v1|" + card-type + "|" + uid) )[:10]    # → xxx-xxx-xxxx
```

| Ingredient | Meaning |
| --- | --- |
| `card-type` | detected from the ATR: PC/SC part 3 contactless table (`mifare classic 1k`, `mifare ultralight ev1`, `felica`, `picopass 16k`, …), known full ATRs (`german eid/passport (npa)`, `yubikey 5 nfc`, `deutschlandticket (vdv-ka)`), or `unknown` |
| `uid` | the card's own unique tag (4/7/10 bytes). When neither card nor reader provides one, the ATR is used and the ID degrades to type level — `Card.Source` says which |

The derivation is a pure function of card type + tag: no timestamps, no reader names, no machine state. The same card produces the same btag everywhere, forever — the digest is pinned by golden tests, so it can never change silently on you. Readers get the same treatment: `ReaderTag` hashes the normalized pcscd reader name (volatile hotplug indices stripped) into a stable `xxx-xx` tag that follows the hardware across machines and USB ports.

## Quick start

```console
$ make build
$ ./pcscid
#qrx-lr:r3v-401-5gmr
```

One line per presentation: `#`, the reader tag, a colon, the btag. Nothing else — stdout is machine readable by design; the leading `#` marks a btag line.

`DEBUG=1` turns on a full verbose trace on stderr while stdout stays clean:

```console
$ DEBUG=1 ./pcscid
time=... level=DEBUG msg="pcscd connected" socket=/run/pcscd/pcscd.comm version=4.5
time=... level=DEBUG msg="card inserted" reader="ACS ACR122U 00 00" \
    id=r3v-401-5gmr reader-tag=qrx-lr type="mifare classic 1k" source=uid \
    uid="04 11 22 33" protocol=T=1
#qrx-lr:r3v-401-5gmr
```

`./pcscid -version` prints the build-time semver (injected from the latest git tag by `make build`).

## Bridge mode: loopback HTTP for browser pages

A browser sandbox cannot open `/run/pcscd/pcscd.comm` — no Unix sockets from WASM or page JavaScript, no WebUSB/WebHID in Firefox. Set `PCSCID_HTTP_ADDR` and the same binary additionally serves every presentation's **reader tag** and **btag** as loopback HTTP, CORS-permissive so an HTTPS kiosk page may read `http://127.0.0.1:8976` without mixed content trouble:

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | `{"ok":true,"version":...}` liveness probe |
| `GET /events` | SSE stream (hello event, then one `card` event per scan, 20 s keep-alive) |
| `GET /pending?after=N` | JSON `{events:[...]}` polling fallback, replay by monotonic cursor |

| Variable | Effect |
| --- | --- |
| `PCSCID_HTTP_ADDR` | Bridge listen address, e.g. `127.0.0.1:8976`. Empty (the default) disables bridge mode |
| `PCSCID_HTTP_ALLOW_REMOTE` | `1` lifts the loopback guard. Without it only loopback addresses are accepted — **card identities must never leave the kiosk by accident** |

A 2 s startup grace swallows Watch's initial "cards already present" report (a card left on a reader never triggers after a service restart) and the same reader+card pair is debounced for 3 s. `scripts/pcscid-bridge.service` is the ready-made, hardened systemd unit (`After=pcscd`, `DynamicUser`, `ProtectSystem=strict`, …).

```console
$ PCSCID_HTTP_ADDR=127.0.0.1:8976 ./pcscid
#qrx-lr:r3v-401-5gmr
```

## Use the library

```go
events, err := pcscid.Watch(ctx, &pcscid.Options{Logger: logger})
if err != nil {
	log.Fatal(err) // pcscd is a hard requirement
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

`Watch` reports cards already present at startup, follows hot-plugged readers, reconnects across `pcscd` restarts without re-reporting still-present cards, and closes its channel when the context is cancelled.

The fine-grained pieces are exported too:

```go
pcscid.DetectType(atr)     // "mifare classic 1k"
pcscid.ParseATR(atr)       // full ISO 7816-3 breakdown, with TCK check
pcscid.ReaderTag(reader)    // the xxx-xx reader tag
pcscid.Btag(type, uid)     // the xxx-xxx-xxxx btag
```

And the bridge is a library piece as well — feed it from any event loop:

```go
bridge := pcscid.NewBridge(nil)          // ring buffer, dedup and grace defaults
go bridge.Serve(ctx, "127.0.0.1:8976")   // or mount bridge.Handler() yourself
for ev := range events {
	bridge.Feed(ev)                       // inserts become {reader tag, btag} events
}
```

## Card types recognized

| Source | Cards |
| --- | --- |
| PC/SC part 3 ATR table | MIFARE Classic 1K/4K, Mini, Ultralight / C / EV1, MIFARE Plus SL1/SL2, FeliCa, PicoPass family, Topaz, Jewel, ICODE family, SLE55R / my-d, TAG IT, LRI family, AT88 family, Melexis sensor tag |
| Known ATRs | German eID / passport (npa), YubiKey 5 NFC, Deutschlandticket (VDV-KA) |
| Everything else | `unknown` type — still identified by UID when the reader provides one; the UID probe works for any ISO 14443 tag and most contactless readers |

## How it works

```text
cmd/pcscid ──▶ pcscid.Watch ──▶ pcsc.Client ──▶ /run/pcscd/pcscd.comm ──▶ pcscd ──▶ reader ──▶ card
                (events, IDs)    (pure Go          (wire protocol 4.5 or 4.4,
                                  client)           negotiated per daemon)
```

1. `pcsc.Client` performs the header-less version handshake (claims 4.4, adopts 4.5 when pcscd 2.x offers it, down-negotiates for old daemons), establishes a context and fetches the 16-entry `READER_STATE` array — reader names, presence bits, event counters, ATRs.
2. Card insertions (presence bit plus event counter change) trigger identification: connect in shared mode, negotiate T=0/T=1, transmit the UID pseudo-APDU, disconnect.
3. The ATR yields the card type; type plus UID (or ATR fallback) yields the btag.
4. Reader state waits are bounded at a 1 s tick; timeouts are client-side and unblock the daemon through the stop request, so the stream stays in sync. Context cancellation closes the socket for an instant exit. With no reader registered the daemon answers the wait immediately — the loop polls gently instead of spinning.

The empirical protocol gotchas (header-less responses, the unframed APDU bytes of `CMD_TRANSMIT`, the registration dump that is *not* a change signal) are documented in the code and covered by tests against both daemon generations.

## Security posture

- The bridge listens on **loopback only** by default (`PCSCID_HTTP_ALLOW_REMOTE` is the explicit, deliberate escape hatch).
- Permissive CORS is a kiosk trade-off: it also means every page open in a browser *on the kiosk itself* can read scans — run bridge mode only on a locked-down terminal, never on a multi-user desktop.
- The btag is a truncated SHA-256 (~52 bits) — an identifier, not a secret. Treat a btag like a username, never like a password or a key.
- Transport responses are size-capped (1 MiB frames, short APDU buffers), so a misbehaving daemon cannot turn the client into a giant allocation.

## Requirements & install

- Linux with `pcscd` running (pcsc-lite 1.8.24+ speaks protocol 4.4/4.5 natively; older daemons are handled through down-negotiation)
- Go 1.25+ to build
- Socket `/run/pcscd/pcscd.comm` (`PCSCLITE_CSOCK_NAME` overrides)

```console
$ go install paepcke.de/pcscid/cmd/pcscid@latest     # from the module host
$ git clone https://paepcke.de/pcscid && make build  # from source, with semver baked in
```

## Project layout

```text
cmd/pcscid/        sample app: bare btags, full trace with DEBUG=1, bridge with PCSCID_HTTP_ADDR
pcsc/              pure Go pcscd wire-protocol client (Linux)
internal/pcscfake  in-process fake pcscd daemon driving the hardware-free tests
pcscid.go          Watch loop, event model, btag and reader tag derivation
bridge.go          loopback HTTP bridge: SSE + polling of reader tags and btags
atr.go             ISO 7816-3 answer-to-reset parser
cardtype.go        ATR to card type detection (PC/SC part 3 table, known ATRs)
uid.go             UID pseudo-APDU probe, random UID detection
version.go         semver via go linker -ldflags injection
scripts/           hardened systemd unit for bridge mode on a kiosk
```

## Testing

```console
$ make test    # go test ./... — fully parallel, no hardware needed
```

The fake daemon re-implements the wire protocol a second time, so client and fake agreeing is itself part of the test; it emulates all three daemon generations (4.4, 4.5, and the 4.2 downgrade). The client was additionally verified live against a real pcscd 2.4.1.

## License

[MIT](LICENSE)