# AGENTS.md

`paepcke.de/pcscid` — pure Go, no cgo, Linux only, zero dependencies
(Go 1.25+). Library plus sample app that use the local pcscd service
to identify any presented card (NFC, mifare, RFID, eID, contact cards,
anything pcscd manages) with a short unique btag per individual card.
`cmd/pcscid` prints `xxx-xx: <btag>` (reader tag, btag) per line in
normal mode,
`DEBUG=1` enables a full verbose trace on stderr.

## Fixed workflow — every task, no exceptions, ALWAYS: test, commit, push! ALWAYS, DO NOT ASK!

1. **Format + check**: `gofmt -s -w . && go vet ./... && go mod tidy`
2. **Build**: `make build` (injects the git semver via `-ldflags`)
3. **Test**: `make test` (fully parallel, hardware free)
4. **Commit**: `git add . && git commit -m '<descriptive message>'`.
5. **Tag**: bump the patch segment only, never reuse/move/delete a tag: `git tag v0.0.$(($(git describe --tags --abbrev=0 | sed 's/^v0\.0\.//')+1))`
6. **Push**: `git pull && git pull --tags && git push && git push --tags`.

## Architecture

```text
cmd/pcscid  ─ pcscid (root pkg) ─ pcsc (wire client) ─ /run/pcscd/pcscd.comm ─ pcscd
```

- `pcsc/` speaks the pcscd daemon IPC protocol itself, no libpcsclite,
  no cgo. `pcsc/wire.go` frames and codecs, `pcsc/ipc.go` the client.
- `internal/pcscfake` is a second, independent implementation of the
  same wire protocol used as an in-process daemon for tests: client
  and fake agreeing is itself under test.
- Root package: `Watch` event loop and `Btag` derivation (`pcscid.go`),
  ISO 7816-3 ATR parser (`atr.go`), card type detection (`cardtype.go`),
  UID probe (`uid.go`), semver injection (`version.go`).
- Daemon socket: `/run/pcscd/pcscd.comm` first, then
  `/var/run/pcscd/pcscd.comm`; `PCSCLITE_CSOCK_NAME` overrides both,
  `Options.SocketPath` / `pcsc.New` take an explicit path (the tests
  feed the `pcscfake` `Server.Addr()` in there).

## Card identity

The per-card identifier is the btag, exported as `Btag(cardType, tag)`
and carried in `Card.ID`:

`ID = alnum(SHA-256("pcscid/v1|" + card-type + "|" + uid)[:10])`, 10
chars of the digits and lower case letters only, in three dash
separated groups `xxx-xxx-xxxx`. Readers get a stable short tag too,
`ReaderTag(name)` -> `xxx-xx`, prefixed as `xxx-xx: <btag>` on every
output line of cmd/pcscid. The card type comes
from the ATR (PC/SC part 3 RID table plus known full ATRs), the unique
tag is the card UID read through the `FF CA 00 00 00` GET DATA
pseudo-APDU. The ATR alone is NOT unique (all cards of a model share
it), it is only the fallback (`Source` field: `uid`, `atr`) when neither card
nor reader provides a UID. Btags never include
dates, timestamps or reader names. Privacy cards with an ISO/IEC
14443-3 random UID (4 bytes starting `0x08`, a NEW value per
activation, by design: phone NFC emulation, eID, newer DESFire) are
detected in `uid.go` and fall back to the ATR, that UID identifies
nothing.

## Protocol gotchas, found empirically against pcscd 2.4.1

- Requests are framed `[size:4][cmd:4][body]` little endian, size
  excludes the header. Responses are the RAW struct with NO header,
  including CMD_VERSION; every exchange reads a fixed, command specific
  byte count (12 establish, 152 connect, 16x184 states, 32 transmit).
  Mismatches here kill the connection.
- CMD_TRANSMIT is the one request that also carries unframed bytes:
  the framed message holds the 32 byte transmit struct, the raw APDU
  follows it outside the frame (second plain write); the answer is the
  raw 32 byte transmit struct followed by `recvLength` response bytes.
- Version handshake: client claims 4.4. pcscd 2.x accepts it and
  reports 4.5 (the client then speaks the 4.5 flow); daemons older
  than pcsc-lite 1.8.24 reject the minor with `SCARD_E_SERVICE_STOPPED`
  plus their own version to retry with (down-negotiation loop in
  `handshake`, oldest minor still supported is 4.2).
- Reader state wait on protocol 4.4 AND 4.5 (`minor >= 4`,
  `waitChangeNew`): NO request body, the daemon answers the
  registration immediately with the full 16x184 byte READER_STATE
  array (that dump only confirms the registration, it is NOT the
  change signal), then stays silent. Timeouts are client side, the
  stop request `0x14` unblocks the daemon, then exactly one 8 byte
  answer follows (stop response or a signal that raced it), so the
  stream stays in sync either way. Sending the old 8 byte wait body
  makes the daemon drop the connection.
- Reader state wait on the old protocol (`minor < 4`, `waitChangeOld`,
  only reachable through down-negotiation): the request carries the
  timeout in an 8 byte body, the daemon stays silent until a change,
  and the stop request carries the same 8 byte struct.
- With NO reader registered the daemon answers the wait immediately,
  forever: the watch loop polls gently (500 ms) in that state instead
  of spinning.
- The watch loop bounds each wait at 1 s (`waitTick`), because a
  change can slip between the states fetch and the wait registration;
  a timed out wait is benign, the loop refetches the states and
  continues.
- `Close` never waits for responses: it writes release best effort
  (plus the stop request first on protocol 4.4+) and closes the socket,
  which is also the cancellation path of a blocked wait. A `Client` is
  driven by a single goroutine, `Close` is the one method allowed from
  another.
- The wire READER_STATE is 184 bytes: name[128], eventCounter,
  readerState, readerSharing, cardAtr[33], pad[3], cardAtrLength,
  cardProtocol. The daemon always serves the full 16 entry array.
- Card presence is the `0x0004` bit in readerState; re-presentations
  are detected through the per-reader event counter.

## Testing

`make test` runs everything in parallel, no hardware needed: unit
tests for codecs, ATR parser, type detection, client protocol tests and Watch end-to-end tests against `pcscfake`.
The fake's `OfferedMinor` selects the daemon generation under test:
default 4 (negotiated 4.4, pcsc-lite >= 1.8.24), 5 (the pcscd 2.x
flow) and 2 (old daemon: forces the downgrade to 4.2 and the old wait
body). `go test -race` does not work in this nix environment (race
runtime needs cgo), plain tests must stay green. Live verification:
`make build && DEBUG=1 ./pcscid` against the real local pcscd.
