# AGENTS.md

`paepcke.de/pcscid` — pure Go, no cgo, Linux only. Library plus sample
app that use the local pcscd service to identify any presented card
(NFC, mifare, RFID, eID, contact cards, anything pcscd manages) with a
short unique ID per individual card. `cmd/pcscid` prints only the
card ID and a newline in normal mode, `DEBUG=1` enables a full verbose
trace on stderr.

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
                             └─ scan.go (pcsc_scan fallback, last resort)
```

- `pcsc/` speaks the pcscd daemon IPC protocol itself, no libpcsclite,
  no cgo. `pcsc/wire.go` frames and codecs, `pcsc/ipc.go` the client.
- `internal/pcscfake` is a second, independent implementation of the
  same wire protocol used as an in-process daemon for tests: client
  and fake agreeing is itself under test.
- Root package: `Watch` event loop (`pcscid.go`), ISO 7816-3 ATR
  parser (`atr.go`), card type detection (`cardtype.go`), UID probe
  (`uid.go`), `pcsc_scan` text parser (`scan.go`), semver injection
  (`version.go`).

## Card identity

`ID = hex(SHA-256("pcscid/v1|" + card-type + "|" + uid)[:8])`, 16 hex
chars. The card type comes from the ATR (PC/SC part 3 RID table plus
known full ATRs), the unique tag is the card UID read through the
`FF CA 00 00 00` GET DATA pseudo-APDU. The ATR alone is NOT unique
(all cards of a model share it), it is only the fallback (`Source`
field: `uid`, `atr`, `scan`) when neither card nor reader provides a
UID. IDs never include dates, timestamps or reader names.

## Protocol gotchas, found empirically against pcscd 2.4.1

- Requests are framed `[size:4][cmd:4][body]` little endian, size
  excludes the header. Responses are the RAW struct with NO header,
  including CMD_VERSION. Mismatches here kill the connection.
- Version handshake: client claims 4.4. pcscd 2.x accepts it and
  reports 4.5; 1.8.x/1.9.x daemons reject other minors with
  `SCARD_E_SERVICE_STOPPED` plus their own version to retry with
  (down-negotiation loop in `handshake`).
- Protocol 4.5 wait (`CMD_WAIT_READER_STATE_CHANGE 0x13`) has NO
  request body and answers with the full 16x184 byte READER_STATE
  array; timeouts are client side, the stop request `0x14` unblocks
  the daemon, then its two answers (array, then 8 byte stop response)
  must be drained in that order. Sending the old 8 byte wait body
  makes the daemon drop the connection.
- Protocol 4.4 wait (1.8.x/1.9.x daemons) carries the timeout in an
  8 byte body and answers with an 8 byte struct.
- With NO reader registered the daemon answers the wait immediately,
  forever: the watch loop polls gently (500 ms) in that state instead
  of spinning.
- `Close` never waits for responses: it writes release best effort
  (plus the 4.5 stop request first) and closes the socket, which is
  also the cancellation path of a blocked wait.
- The wire READER_STATE is 184 bytes: name[128], eventCounter,
  readerState, readerSharing, cardAtr[33], pad[3], cardAtrLength,
  cardProtocol. The daemon always serves the full 16 entry array.
- Card presence is the `0x0004` bit in readerState; re-presentations
  are detected through the per-reader event counter.

## pcsc_scan fallback (last resort)

Used only when the pcscd socket is unreachable and the `pcsc_scan`
binary exists (checked via PATH). The parser only accepts lines
matching `^\s*ATR: <hex bytes>$` (never dates, event numbers, spinner
or identification dump lines), deduplicates the event and analysis ATR
blocks of one insertion, tracks readers by the ` Reader N: <name>`
lines and resets on `Card state: Card removed`. It can never see a
UID, identity is type level only, `Source: "scan"` says so.

## Fixtures

`pcsc-scan-example-*.txt` at the repo root are real pcsc_scan
captures (ACS ACR122U, mifare classic 1k, German npa, Deutschlandticket,
YubiKey 5 NFC) and are the scan parser test fixtures. Each file yields
exactly one insert and one remove event.

## Testing

`make test` runs everything in parallel, no hardware needed: unit
tests for codecs, ATR parser, type detection, scan parser (fixtures),
client protocol tests and Watch end-to-end tests against `pcscfake`
in both protocol generations (4.4 and 4.5, see `OfferedMinor`).
`go test -race` does not work in this nix environment (race runtime
needs cgo), plain tests must stay green. Live verification:
`make build && DEBUG=1 ./pcscid` against the real local pcscd.
