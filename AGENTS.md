# AGENTS.md

`paepcke.de/pcscid` — pure Go, no cgo, Linux only, zero dependencies
(Go 1.26+). Library plus sample app: a short stable btag per card,
reader tags per model, unit and machine, for every card the local
pcscd manages (NFC, mifare, RFID, eID, contact cards).

## Fixed workflow — every task, no exceptions, ALWAYS: test, commit, push! ALWAYS, DO NOT ASK!

0. **Semver fallback (hardwired, every code update)**: keep
   `defaultVersion` in `version.go` equal to the tag the update will
   receive (`v0.0.<N+1>`, the next patch bump), so a plain `go build`
   without `-ldflags` reports the release tag.
1. **Format + check**: `gofmt -s -w . && go vet ./... && go mod tidy`
2. **Build**: `make build` (injects the git semver via `-ldflags`)
3. **Test**: `make test`
4. **Commit**: `git add . && git commit -m '<descriptive message>'`
5. **Tag**: patch bump only, never reuse/move/delete a tag:
   `git tag v0.0.$(($(git describe --tags --abbrev=0 | sed 's/^v0\.0\.//')+1))`
6. **Push**: `git pull && git pull --tags && git push && git push --tags`

## Makefile

- `make build` — binary with the git tag as semver (`VERSION ?=`
  overrides). `make check` — read-only gofmt/vet/tidy-diff.
  `make test` — parallel, no test cache, hardware free.
  `make update`/`make push` — pull (+ tags) / pull plus push.
  `make deploy-test-nix` — sudo deploy to the pilot kiosk.
  `make deps` — DESTRUCTIVE module re-init: never run it, the module
  is dependency free by design.

## Architecture

```text
cmd/pcscid ─ pcscid (root pkg) ─ pcsc (wire client) ─ /run/pcscd/pcscd.comm ─ pcscd
```

- `pcsc/` speaks the pcscd IPC protocol itself (no libpcsclite, no
  cgo): `wire.go` frames/codecs, `ipc.go` client, `const.go` PC/SC
  constants, `pcsc.go` public API.
- `internal/pcscfake` — second, independent wire implementation
  serving as the in-process test daemon; client and fake agreeing is
  itself under test.
- Root pkg: `pcscid.go` watch loop + btag/reader tag derivation,
  `readerid.go` reader unit identity (probes, sysfs USB resolution,
  URB correlation, `unitRegistry`, `MachineID`), `readers.go`
  startup inventory (`IdentifyReaders`), `bridge.go` loopback HTTP
  bridge, `atr.go`, `cardtype.go`, `uid.go`, `sign.go` SSHSIG,
  `version.go` semver injection.
- Sockets: `/run/pcscd/pcscd.comm`, then `/var/run/pcscd/pcscd.comm`;
  `PCSCLITE_CSOCK_NAME` overrides; `Options.SocketPath` / `pcsc.New`
  take an explicit path (tests feed the fake's `Server.Addr()`).

## Identity model (short form)

- **Btag** `Btag(cardType, tag)` =
  `alnum(SHA-256("pcscid/v1|"+card-type+"|"+uid)[:10])`,
  `xxx-xxx-xxxx`, digits and lowercase only. Pure function of card
  type + tag: same card, same btag on every machine, socket, reader.
  UID from the `FF CA 00 00 00` GET DATA pseudo-APDU. A btag ALWAYS
  needs a valid UID (`Card.Source`: `uid` / `none`): a failed UID
  read or a random UID (ISO 14443-3: 4 bytes starting `0x08`, new
  per activation, identifies nothing) yields NO insertion event at
  all, never an ATR derived type level btag. The skip is silent in
  normal mode, `DEBUG=1` keeps every detail (per-attempt trace plus
  one summary record with reader, tag facts, type, uid, atr,
  protocol). The UID read insists (`uidReadRounds` rounds over
  `uidReadAttempts` exchanges each, `uidReadDelay` pauses, all in
  `uid.go` `insistUID`): pcscd reports a card present before its
  activation settled, and a contactless reader (ACR122U family,
  observed as `63 00`) can wedge the freshly activated PICC into a
  state its firmware cannot serve, sticking for the whole connection.
  Every failed round resets the card (`SCARD_RESET_CARD`, the power
  cycle rerunning the anti collision) and reopens the connection;
  only a valid UID, a random UID or an exhausted budget ends the
  insistence. Single shot / same-connection-only retries here were
  the root cause of the intermittent atr misidentification of cards
  with a valid UID.
- **Reader tags** `xx-xxxx-xx` hash the normalized reader name
  (`normalizeReaderName` strips volatile hotplug index groups). Tiers,
  best first: hardware serial (`SCARD_ATTR_VENDOR_IFD_SERIAL_NO`,
  `pcscid/reader/v2`, portable), USB port path (sysfs devpath,
  `pcscid/reader/v3`, opt-in `PCSCID_USB_PATH_ID`), model
  (`pcscid/reader/v1`). `PCSCID_MAC_ID` mixes `MachineID()` into
  whichever tier applies (`pcscid/reader/m1`).
- All-zero serial placeholders (the ACR122U serves `0`) are filtered;
  its iSerial is firmware fixed and no host tool can write it.
- **Port resolution** (serial-less readers, opt-in): channel id
  `SCARD_ATTR_CHANNEL_ID` packs `0x0020<<16|bus<<8|dev`, resolved via
  sysfs (`/sys/bus/usb/devices`, busnum/devnum/devpath; entries are
  symlinks, the resolver stats through them). Without a channel id
  the sysfs USB tree is scanned for the reader's CCID device
  (bInterfaceClass 0x0B, manufacturer/product strings matching the
  reader name).
- **N identical units** are told apart by their USB traffic: a plain
  card connection submits NO URBs, so the probe window (UID plus
  pinning exchanges in `probeReaderCard`) is a burst of URBs to
  exactly the probed device; the sysfs `urbnum` counter that moved
  identifies the unit, independent of the daemon's reader order. The
  winner must clear a minimum delta and a margin over the runner up;
  candidates missing from the before snapshot (a mid-window hotplug:
  the probed reader was registered before the wait, so its device
  cannot be new) are ineligible, or their whole urbnum history would
  count as the delta and win spuriously. An ambiguous correlation
  refuses with a qualified error unless every other candidate is
  already claimed (elimination).
- The per-session `unitRegistry` keeps the identity persistent and
  collision free: one port = one reader name, a transient probe
  failure falls back to the remembered identity (a tag cannot flip),
  a disappeared reader releases its claim, a reconnect drops the
  registry (a daemon restart re-enumerates the name suffixes).
  Multi-slot units qualify the port with the slot group
  (`portIdentity`, `2-1.3#01`); slot 00 keeps the plain devpath so
  existing tags stay stable.
- `Event.ReaderTag` carries the composed tag (insertions only),
  `Event.ReaderSerial` / `Event.ReaderPort` the raw facts. An
  unresolved port under `PCSCID_USB_PATH_ID` is reported as a
  qualified error; the reader keeps the model tag.
- `MachineID()` reads `/sys/class/net`: physical ethernet ports only
  (type 1, backing `device` symlink, no `phy80211`, non-zero MAC),
  MACs sorted, joined with `|`.

## Sample app (`cmd/pcscid`)

- stdout: one line `#<reader tag>:<btag>` per presentation, nothing
  else. `DEBUG=1` adds the verbose trace on stderr.
- Startup: every registered reader evaluated once (`IdentifyReaders`)
  and printed on stderr at info level: name, model tag, unit facts
  (the port resolves card-less when unambiguous, the serial needs a
  card), tier, effective tag, plus the identification of a present
  card (a card without a valid UID is reported as `present without a
  valid uid, no btag`, never with an ATR derived btag).
- Env: `PCSCID_HTTP_ADDR`, `PCSCID_HTTP_ALLOW_REMOTE`,
  `PCSCID_USB_PATH_ID`, `PCSCID_MAC_ID`, `PCSCID_SIGN_KEY`
  (passphrase-less ssh-ed25519; appends `$` + base64 SSHSIG to every
  output line, namespace `pcscid`, verifiable with
  `ssh-keygen -Y verify`; an unusable key fails the startup).

## Bridge (loopback HTTP for kiosk browser pages)

- Browser pages cannot open the pcscd socket (no Unix sockets from
  WASM/JS, no WebUSB/WebHID in Firefox), so `bridge.go` feeds Watch
  insertions through tag derivation plus dedup and serves them as SSE
  + polling JSON with permissive CORS (loopback is a potentially
  trustworthy origin: no mixed content for an HTTPS page).
- `GET /health`, `GET /events` (SSE: hello + one `card` event per
  scan, 20 s keep-alive), `GET /pending?after=N` (JSON replay by
  monotonic cursor, ring keeps 64). Dedup: 2 s startup grace swallows
  the initial "already present" report, the same reader+card pair is
  suppressed for 3 s (`bridgeStartupGrace` / `bridgeDedupWindow` /
  `bridgeCapacity`).
- With a signer every event carries the base64 SSHSIG of its exact
  output line `#<reader>:<card>` in `sig`, byte-identical to the
  stdout `$` signature. `scripts/pcscid-bridge.service` is the
  ready-made systemd unit (After=pcscd, `PCSCID_USB_PATH_ID=1`).

## Protocol gotchas (empirical, against pcscd 2.4.1)

- Requests are framed `[size:4][cmd:4][body]` little endian, size
  excludes the header. Responses are the RAW struct with NO header,
  including CMD_VERSION. Every exchange reads a fixed, command
  specific byte count (12 establish, 152 connect, 16x184 states, 32
  transmit); mismatches kill the connection.
- CMD_TRANSMIT is the one request with unframed bytes: the framed
  message holds the 32 byte transmit struct, the raw APDU follows as
  a second plain write; the answer is the raw 32 byte struct followed
  by `recvLength` response bytes.
- Version handshake: the client claims 4.4; pcscd 2.x accepts it and
  reports 4.5 (client speaks the 4.5 flow); older daemons reject with
  `SCARD_E_SERVICE_STOPPED` plus their own minor to retry with
  (down-negotiation loop in `handshake`, oldest supported 4.2).
- Wait on protocol 4.4+ (`waitChangeNew`): NO request body, the
  daemon answers the registration immediately with the full 16x184
  READER_STATE array (that dump only confirms the registration, it is
  NOT the change signal), then stays silent. Timeouts are client
  side; the stop request `0x14` unblocks the daemon, then exactly one
  8 byte answer follows (stop response or a racing signal), so the
  stream stays in sync either way. Sending the old 8 byte wait body
  makes the daemon drop the connection.
- Wait on the old protocol (`minor < 4`, `waitChangeOld`, only via
  down-negotiation): 8 byte timeout body in request and stop, the
  daemon stays silent until a change.
- With NO reader registered the daemon answers the wait immediately,
  forever: the loop polls gently (500 ms) instead of spinning.
- Each wait is bounded at 250 ms (`waitTick`): a change can slip between
  the states fetch and the wait registration; a timed out wait is
  benign, the loop refetches and continues. The tick stays well under
  the human presence window of a card because the reader beeps at the
  field detection and the operator removes the card right after.
- Event counters are only comparable within one daemon session:
  `pollLoop` drops the remembered counters on every (re)connection,
  a card that never moved is not re-reported.
- `Close` never waits for responses: stop request (4.4+) + release
  best effort, then socket close — also the cancellation path of a
  blocked wait. A `Client` is driven by a single goroutine; only
  `Close` may come from another.
- Wire READER_STATE is 184 bytes: name[128], eventCounter,
  readerState, readerSharing, cardAtr[33], pad[3], cardAtrLength,
  cardProtocol. Presence = the `0x0004` bit in readerState;
  re-presentations are detected through the per-reader event counter.

## Testing

`make test` runs everything in parallel, no hardware. The fake's
`OfferedMinor` selects the daemon generation: 4 (default, negotiated
4.4, pcsc-lite >= 1.8.24), 5 (pcscd 2.x flow), 2 (old daemon:
downgrade to 4.2, old wait body). `go test -race` does not work in
this nix environment (race runtime needs cgo), plain tests must stay
green. Live verification: `make build && DEBUG=1 ./pcscid` against
the real local pcscd.
IMPORTANT: in watch-pipeline tests configure the fake's reader facts
(`SetSerial` / `SetChannelID`) BEFORE `InsertCard` — InsertCard wakes
the watch loop, which probes them immediately. `fake.Reader(name)`
returns the live reader state for failure injection
(`FailConnects`, `FailUIDProbes` answer SCARD_E_NO_SMARTCARD /
SCARD_E_COMM_DATA_LOST for the next n attempts, the transient
activation race of a freshly inserted card; `StuckUID` wedges the
PICC with 63 00 for the whole connection, only a SCARD_RESET_CARD
disconnect cures it, exactly the ACR122U failure). `RemoveCard`
publishes a removal event through the same fake.

## Timing budget (short card presentations)

The ACR122U beeps at the field detection, so an intuitive operator
removes the card as soon as the beep is done, roughly one second
after presenting it. The identification has to finish inside that
window, measured from detection to UID: connect ~20 ms, the first
UID exchange ~90 ms; a wedged 63 00 connection is NOT retried (the
wedge sticks, retries and their `uidReadDelay` pauses only burn the
presence window), the read loop resets the card at once (~265 ms
power cycle) and succeeds on the first exchange of the reopened
connection. Transport errors during the activation settle ARE still
retried (uidReadAttempts x uidReadDelay). Empirical log of the 1 s
failure that shaped this: attempts 1 and 2 answered 63 00, attempt 3
answered SCARD_W_REMOVED_CARD, the reset-reopen then hit
SCARD_E_NO_SMARTCARD — the retries before the reset cost more than
the remaining window.
