# AGENTS.md

`paepcke.de/pcscid` — pure Go, no cgo, Linux only, zero dependencies
(Go 1.26+). Library plus sample app that identify every card the local
pcscd manages (NFC, mifare, RFID, eID, contact cards) with a short
stable btag per card, plus reader tags per model, unit and machine.

## Fixed workflow — every task, no exceptions, ALWAYS: test, commit, push! ALWAYS, DO NOT ASK!

0. **Semver fallback (hardwired, every code update, no exceptions)**:
   keep `defaultVersion` in `version.go` equal to the tag the update
   will receive (`v0.0.<N+1>`, the next patch bump), so a plain
   `go build` without `-ldflags` reports the release tag.
1. **Format + check**: `gofmt -s -w . && go vet ./... && go mod tidy`
2. **Build**: `make build` (injects the git semver via `-ldflags`)
3. **Test**: `make test`
4. **Commit**: `git add . && git commit -m '<descriptive message>'`
5. **Tag**: bump the patch segment only, never reuse/move/delete a tag:
   `git tag v0.0.$(($(git describe --tags --abbrev=0 | sed 's/^v0\.0\.//')+1))`
6. **Push**: `git pull && git pull --tags && git push && git push --tags`

## Makefile

- `make build` — removes a stale binary first, builds with the git tag
  as semver (`VERSION ?=` overrides the tag detection).
- `make check` — read-only verify: `gofmt -l .`, `go vet ./...`,
  `go mod tidy -diff`.
- `make test` — `go test -count=1 -parallel $(nproc) -p $(nproc) ./...`:
  no test cache, packages in parallel, hardware free.
- `make update` / `make push` — `git pull` (+ `--tags`) / pull plus
  push of commits and tags.
- `make deploy-test-nix` — sudo deploy of the fresh binary to
  `/nix/persist/root/bin/pcscid` (`.old`/`.old2` rotation) and restart
  of `pcscid.service`; pilot kiosk only.
- `make deps` — DESTRUCTIVE: deletes `go.mod`/`go.sum` and re-inits
  the module. Never run it, the module is dependency free by design.

## Architecture

```text
cmd/pcscid ─ pcscid (root pkg) ─ pcsc (wire client) ─ /run/pcscd/pcscd.comm ─ pcscd
```

- `pcsc/` speaks the pcscd IPC protocol itself, no libpcsclite, no
  cgo: `wire.go` frames and codecs, `ipc.go` the client, `const.go`
  PC/SC constants, `pcsc.go` the public API.
- `internal/pcscfake` is a second, independent implementation of the
  same wire protocol serving as an in-process daemon for tests: client
  and fake agreeing is itself under test.
- Root package: `pcscid.go` Watch event loop plus btag and reader tag
  derivation, `readerid.go` reader unit identity (wire probes, sysfs
  USB port resolution, URB traffic correlation, `unitRegistry`,
  `MachineID`), `readers.go` startup inventory (`IdentifyReaders`),
  `bridge.go` loopback HTTP bridge, `atr.go` ATR parser,
  `cardtype.go` type detection, `uid.go` UID probe, `sign.go` SSHSIG
  line signatures, `version.go` semver injection.
- Daemon sockets: `/run/pcscd/pcscd.comm` first, then
  `/var/run/pcscd/pcscd.comm`; `PCSCLITE_CSOCK_NAME` overrides both,
  `Options.SocketPath` / `pcsc.New` take an explicit path (the tests
  feed the `pcscfake` `Server.Addr()` in there).

## Identity model

- **Btag** `Btag(cardType, tag)` =
  `alnum(SHA-256("pcscid/v1|"+card-type+"|"+uid)[:10])`,
  `xxx-xxx-xxxx`, digits and lowercase only. Pure function of card
  type + tag: the same card yields the same btag on every machine,
  pcscd socket and reader. UID from the `FF CA 00 00 00` GET DATA
  pseudo-APDU; the ATR identifies only the model and is the fallback
  (`Card.Source`: `uid` / `atr`).
- **Random UIDs** (ISO/IEC 14443-3: 4 bytes starting `0x08`, a NEW
  value per activation: phone NFC, eID, newer DESFire) identify
  nothing and fall back to the ATR.
- **Reader tags** `xx-xxxx-xx` hash the normalized pcscd reader name
  (volatile trailing hotplug index groups stripped,
  `normalizeReaderName`). Two units of the same model share the model
  tag. Tiers, best first: hardware serial
  (`SCARD_ATTR_VENDOR_IFD_SERIAL_NO`, domain `pcscid/reader/v2`,
  portable), USB port path (sysfs devpath, `pcscid/reader/v3`, opt-in
  `PCSCID_USB_PATH_ID`, changes when the reader moves), model
  (`pcscid/reader/v1`). `PCSCID_MAC_ID` mixes `MachineID()` (MACs of
  the physical ethernet ports) into whichever tier applies
  (`pcscid/reader/m1`).
- All-zero serial placeholders (the ACR122U serves `0`) identify the
  model and are filtered; its iSerial is firmware fixed, no host tool
  writes it, and its escape command set has no usable NVRAM store.
- **Port resolution** (serial-less readers, opt-in): the channel id
  `SCARD_ATTR_CHANNEL_ID` packs `0x0020<<16|bus<<8|dev`, resolved via
  sysfs (`/sys/bus/usb/devices`, busnum/devnum/devpath; bus entries
  are symlinks, the resolver stats through them). Without a channel
  id the sysfs USB tree is scanned for the reader's CCID device
  (bInterfaceClass 0x0B, USB manufacturer and product strings matching
  the reader name).
- **N identical units** are told apart by their USB traffic: a plain
  card connection submits NO URBs (the daemon already powered the
  card, attribute answers come from driver memory), so the probe
  window (UID exchange plus pinning exchanges in `probeReaderCard`)
  is a burst of URBs to exactly the probed device. The sysfs `urbnum`
  counter that moved identifies the unit, independent of the daemon's
  reader order (an order aligned mapping would shuffle units on every
  restart). An ambiguous correlation refuses with a qualified error
  unless every other candidate is already claimed (elimination, sound
  because one daemon reader is one physical unit).
- The per-session `unitRegistry` keeps the identity persistent and
  collision free: a resolved port is claimed by exactly one reader
  name, a transient probe failure falls back to the remembered
  identity (a tag cannot flip), a disappeared reader releases its
  claim, and a reconnect drops the whole registry (a daemon restart
  re-enumerates the volatile name suffixes). Multi-slot units qualify
  the port with the pcscd slot group (`portIdentity`, `2-1.3#01`);
  the first slot keeps the plain devpath so existing tags stay stable.
- `Event.ReaderTag` carries the composed tag (insertions only),
  `Event.ReaderSerial` and `Event.ReaderPort` the raw facts.
- An unresolved port under `PCSCID_USB_PATH_ID` is reported as a
  qualified error naming every failed step; the reader then keeps the
  model tag, which identical units share.
- `MachineID()` reads `/sys/class/net`: physical ethernet ports only
  (type 1, backing `device` symlink, no `phy80211`, non-zero MAC;
  wifi, lo, bridges, bonds, vlans and veth never qualify), MACs
  sorted and joined with `|`.

## Sample app (`cmd/pcscid`)

- stdout: one line `#<reader tag>:<btag>` per presentation, nothing
  else. `DEBUG=1` adds the full verbose trace on stderr.
- At startup every reader registered with pcscd is evaluated once
  (`IdentifyReaders`) and printed on stderr at info level: name,
  model tag, unit facts (the port resolves card-less when
  unambiguous, the serial needs a presented card), tier, effective
  tag, and the identification of a card already present.
- Env config: `PCSCID_HTTP_ADDR` (bridge listen address),
  `PCSCID_HTTP_ALLOW_REMOTE` (lift the loopback guard),
  `PCSCID_USB_PATH_ID`, `PCSCID_MAC_ID`, `PCSCID_SIGN_KEY` (path to a
  passphrase-less ssh-ed25519 key; appends `$` and a base64 SSHSIG
  signature to every output line, namespace `pcscid`, verifiable with
  `ssh-keygen -Y verify`; an unusable key fails the startup).

## Bridge (loopback HTTP for kiosk browser pages)

- Browser pages cannot open the pcscd socket (no Unix sockets from
  WASM/JS, no WebUSB/WebHID in Firefox, none in WebExtensions), so
  `bridge.go` feeds Watch insertions through the tag derivation plus
  a dedup guard and serves them as SSE + polling JSON with permissive
  CORS (loopback is a potentially trustworthy origin, so loopback
  HTTP is not mixed content for an HTTPS page).
- Endpoints: `GET /health`, `GET /events` (SSE: hello plus one `card`
  event per scan, 20 s keep-alive), `GET /pending?after=N` (JSON
  replay by monotonic cursor, ring keeps 64). Dedup: a 2 s startup
  grace swallows Watch's initial "already present" report, the same
  reader+card pair is suppressed for 3 s (`bridgeStartupGrace` /
  `bridgeDedupWindow` / `bridgeCapacity`).
- With a signer every served event carries the base64 SSHSIG of its
  exact output line `#<reader>:<card>` in its `sig` field,
  byte-identical to the stdout `$` signature; without one the field
  is omitted. `scripts/pcscid-bridge.service` is the ready-made
  systemd unit (After=pcscd, `PCSCID_USB_PATH_ID=1`).

## Protocol gotchas (empirical, against pcscd 2.4.1)

- Requests are framed `[size:4][cmd:4][body]` little endian, size
  excludes the header. Responses are the RAW struct with NO header,
  including CMD_VERSION. Every exchange reads a fixed, command
  specific byte count (12 establish, 152 connect, 16x184 states, 32
  transmit). Mismatches kill the connection.
- CMD_TRANSMIT is the one request with unframed bytes: the framed
  message holds the 32 byte transmit struct, the raw APDU follows as
  a second plain write; the answer is the raw 32 byte struct followed
  by `recvLength` response bytes.
- Version handshake: the client claims 4.4; pcscd 2.x accepts it and
  reports 4.5 (the client then speaks the 4.5 flow); daemons older
  than pcsc-lite 1.8.24 reject the minor with
  `SCARD_E_SERVICE_STOPPED` plus their own version to retry with
  (down-negotiation loop in `handshake`, oldest minor supported is
  4.2).
- Reader state wait on protocol 4.4 AND 4.5 (`minor >= 4`,
  `waitChangeNew`): NO request body, the daemon answers the
  registration immediately with the full 16x184 byte READER_STATE
  array (that dump only confirms the registration, it is NOT the
  change signal), then stays silent. Timeouts are client side; the
  stop request `0x14` unblocks the daemon, then exactly one 8 byte
  answer follows (stop response or a signal that raced it), so the
  stream stays in sync either way. Sending the old 8 byte wait body
  makes the daemon drop the connection.
- Reader state wait on the old protocol (`minor < 4`,
  `waitChangeOld`, only reachable through down-negotiation): the
  request carries the timeout in an 8 byte body, the daemon stays
  silent until a change, the stop request carries the same struct.
- With NO reader registered the daemon answers the wait immediately,
  forever: the watch loop polls gently (500 ms) in that state instead
  of spinning.
- Each wait is bounded at 1 s (`waitTick`), because a change can slip
  between the states fetch and the wait registration; a timed out
  wait is benign, the loop refetches the states and continues.
- Event counters are only comparable within one daemon session: a
  restarted daemon counts from zero, so `pollLoop` drops the
  remembered counters on every (re)connection and a card that never
  moved is not re-reported.
- `Close` never waits for responses: it writes the release best
  effort (plus the stop request first on protocol 4.4+) and closes
  the socket, which is also the cancellation path of a blocked wait.
  A `Client` is driven by a single goroutine, `Close` is the one
  method allowed from another.
- The wire READER_STATE is 184 bytes: name[128], eventCounter,
  readerState, readerSharing, cardAtr[33], pad[3], cardAtrLength,
  cardProtocol. The daemon always serves the full 16 entry array.
  Card presence is the `0x0004` bit in readerState; re-presentations
  are detected through the per-reader event counter.

## Testing

`make test` runs everything in parallel, no hardware needed. The
fake's `OfferedMinor` selects the daemon generation under test:
default 4 (negotiated 4.4, pcsc-lite >= 1.8.24), 5 (the pcscd 2.x
flow) and 2 (old daemon: forces the downgrade to 4.2 and the old wait
body). `go test -race` does not work in this nix environment (race
runtime needs cgo), plain tests must stay green. Live verification:
`make build && DEBUG=1 ./pcscid` against the real local pcscd.
