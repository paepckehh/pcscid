# AGENTS.md

`paepcke.de/pcscid` — pure Go, no cgo, Linux only, zero dependencies
(Go 1.26+). Library plus sample app that use the local pcscd service
to identify any presented card (NFC, mifare, RFID, eID, contact cards,
anything pcscd manages) with a short unique btag per individual card.
`cmd/pcscid` prints `#xx-xxxx-xx:xxx-xxx-xxxx` (`#` prefixes the
whole line, then reader tag, btag) per line
in normal mode, `DEBUG=1` enables a full verbose trace on stderr.
`PCSCID_HTTP_ADDR` (env var config) turns on the loopback HTTP
bridge of the same binary for browser pages that cannot open the
pcscd socket. `PCSCID_USB_PATH_ID=1` opts into the physical USB port
path as the per-unit reader identity for serial-less readers (stable
per port, changes when the reader moves), `PCSCID_MAC_ID=1` mixes
the machine identity (MAC addresses of the physical ethernet ports)
into every reader tag. `PCSCID_SIGN_KEY` (path to a passphrase-less
ssh-ed25519 private key) appends `$` and a base64 SSHSIG signature
(namespace `pcscid`, verifiable with `ssh-keygen -Y verify`) to every
output line; an unusable key fails the startup.

## Fixed workflow — every task, no exceptions, ALWAYS: test, commit, push! ALWAYS, DO NOT ASK!

0. **Semver fallback (hardwired, every code update, no exceptions)**:
   keep `defaultVersion` in `version.go` equal to the tag the update
   will receive (`v0.0.<N+1>`, the next patch bump), so a plain
   `go build` without `-ldflags` still reports the current release
   tag instead of "dev" when no link time semver and no VCS build
   info is present.
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
  loopback HTTP bridge (`bridge.go`), ISO 7816-3 ATR parser (`atr.go`),
  card type detection (`cardtype.go`), UID probe (`uid.go`), SSHSIG
  line signatures (`sign.go`), semver injection (`version.go`).
- Daemon socket: `/run/pcscd/pcscd.comm` first, then
  `/var/run/pcscd/pcscd.comm`; `PCSCLITE_CSOCK_NAME` overrides both,
  `Options.SocketPath` / `pcsc.New` take an explicit path (the tests
  feed the `pcscfake` `Server.Addr()` in there).

## Card identity

The per-card identifier is the btag, exported as `Btag(cardType, tag)`
and carried in `Card.ID`:

`ID = alnum(SHA-256("pcscid/v1|" + card-type + "|" + uid)[:10])`, 10
chars of the digits and lower case letters only, in three dash
separated groups `xxx-xxx-xxxx`. The card type comes from the ATR
(PC/SC part 3 RID table plus known full ATRs), the unique tag is the
card UID read through the `FF CA 00 00 00` GET DATA pseudo-APDU. The
ATR alone is NOT unique (all cards of a model share it), it is only
the fallback (`Source` field: `uid`, `atr`) when neither card nor
reader provides a UID. Privacy cards with an ISO/IEC 14443-3 random
UID (4 bytes starting `0x08`, a NEW value per activation, by
design: phone NFC emulation, eID, newer DESFire) are detected in
`uid.go` and fall back to the ATR, that UID identifies nothing.
Btags never include dates, timestamps or reader names, the btag is
a pure function of card type + tag: the same card produces the same
btag on every machine, every pcscd socket and every reader.
`ReaderTag(name)` derives the reader tag `xx-xxxx-xx` the same way, it
hashes the pcscd reader name with its volatile trailing hotplug
index groups stripped (`normalizeReaderName`), so the same physical
reader keeps its tag across machines, USB ports and daemon
restarts. The reader state array carries no hardware serial, so two
units of the same model share that name based tag. The individual
unit is identified through the same pcscd wire protocol, with two
per-unit facts probed over `SCardGetAttrib` while a card is present
(`cmdGetAttrib 0x0F`, the 280 byte `getset` struct):
`SCARD_ATTR_VENDOR_IFD_SERIAL_NO` (0x0103) answers the USB iSerial
string burned into the reader hardware (`lsusb -v` shows the same
descriptor), `ReaderTagWithSerial` mixes it into the tag (hash
domain `pcscid/reader/v2`), one portable tag per unit. Constant
vendor placeholders are filtered first: reader families whose USB
descriptor serves the same all zero serial on every unit (ACS
ACR122U serves `0`) keep the model level tag from that path, the
ACR122U iSerial is fixed in its controller firmware and no public
tool writes it, the ACR122U escape command set has no NVRAM store
(the only persistent field is the 1 byte PICC operating parameter,
too small and RF-behavior-changing to serve as an ID). Such serial
less readers are anchored by their physical USB port instead, but
only with the opt-in `PCSCID_USB_PATH_ID` / `Options.USBPathID`,
because the port path is not portable. The port resolves in two
stages, both pure Go sysfs reads: `SCARD_ATTR_CHANNEL_ID` (0x0110)
answers the CCID packing `0x0020<<16 | bus<<8 | device`, resolved
through sysfs (`/sys/bus/usb/devices`, busnum/devnum/devpath files —
the bus directory entries are symlinks, the resolver stats through
them) to the kernel port path (devpath, `2-1.3`); when the driver
serves no channel id, the sysfs USB tree is scanned for the reader's
CCID device directly (bInterfaceClass 0x0B, USB manufacturer and
product strings matching the pcscd reader name, which pcscd derives
from the same vendor and product table). Exactly one matching device
identifies the port. N identical units (same model, placeholder
serial, no channel id) resolve positionally: the daemon serves its
readers in its deterministic slot order (udev coldplug enumeration,
stable for one hardware topology), the sysfs candidates sorted by
syspath carry the same order, and aligning both by position maps
every unit to its own port — guarded by a count match, re-derived on
every poll, logged as a `positional usb port assignment` warning.
A count mismatch cannot be aligned truthfully and answers the
qualified error. Either way the port
travels into `ReaderTagWithUnit` as hash domain `pcscid/reader/v3` —
stable per port across daemon restarts and reboots, but it changes
when the reader moves to another port. With the option enabled a
port that stays unresolved is reported as a qualified error naming
every failed step (driver attribute, sysfs resolution), the reader
then keeps the model level tag, which two identical units share.
`MachineID()` reads the network stack through
sysfs (`/sys/class/net`) for the stable hardware MAC addresses of
the physical ethernet ports (type ethernet, backing device symlink,
no phy80211, non zero MAC: wifi, lo, bridges, bonds, vlans and veth
never qualify), and `PCSCID_MAC_ID` / `Options.MACID` mixes that
machine identity into every reader tag through `ReaderTagWithMachine`
(hash domain `pcscid/reader/m1`, the unit fact kind prefixed with
`serial:`/`port:`/`model` so the namespaces cannot collide). Precedence:
serial, opt-in port path, model tag; the machine component is mixed
into whichever tier applies when enabled. The composed tag travels
in `Event.ReaderTag` (insertions only), the raw facts in
`Event.ReaderSerial` and `Event.ReaderPort`; readers whose
driver serves neither keep the model level tag, nothing can
distinguish those by software.

## Bridge mode (loopback HTTP, env var config)

A browser sandbox cannot reach the pcscd socket (no Unix sockets from
WASM/JS, no WebUSB/WebHID in Firefox, no raw sockets in WebExtensions),
so `bridge.go` provides the minimal local footprint for kiosk pages:
`pcscid.Bridge` feeds Watch insertions through the tag derivation
(Event.ReaderTag, falling back to ReaderTagWithUnit + Btag) and a
dedup guard and serves them as SSE + polling
JSON with permissive CORS (loopback is a potentially trustworthy
origin, so the loopback http is not mixed content for an HTTPS page).

- `PCSCID_HTTP_ADDR` in the sample app enables it (e.g.
  `127.0.0.1:8976`); empty (the default) keeps the plain CLI output
  only. `PCSCID_HTTP_ALLOW_REMOTE=1` lifts the loopback guard that
  `RequireLoopback` enforces — card identities must never leave the
  kiosk by accident.
- Endpoints: `GET /health`, `GET /events` (SSE, hello + one `card`
  event per scan, 20 s keep-alive) and `GET /pending?after=N` (JSON
  replay by monotonic cursor; the ring retains 64 presentations).
- Dedup semantics: a 2 s startup grace swallows Watch's initial
  "cards already present" report (a card left on a reader never
  triggers after a service restart) and the same reader+card pair is
  suppressed for 3 s against prell events. Both are `BridgeOptions`,
  defaults via `bridgeCapacity` / `bridgeDedupWindow` /
  `bridgeStartupGrace`.
- Line signatures: with `PCSCID_SIGN_KEY` set the sample app wires the
  signer into the bridge (`BridgeOptions.Signer`), and every served
  event carries the base64 SSHSIG signature of its exact output line
  `#<reader>:<card>` in its `sig` field — byte-identical to the
  signature `SignLine` appends to the stdout line (the `$` separator
  is never signed or delivered), namespace `pcscid`, verifiable with
  `ssh-keygen -Y verify`. Without a signer the `sig` field is omitted,
  so unsigned deployments keep the lean payload shape. Consumers can
  forward the field verbatim (chrony's kiosk punch endpoint strips an
  optional leading `$` and verifies against the configured key).
- `scripts/pcscid-bridge.service` is the ready-made systemd unit
  (After=pcscd) running the sample app with `PCSCID_HTTP_ADDR` set.

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
- Event counters are only comparable within one daemon session: a
  restarted daemon counts from zero again, so `pollLoop` drops the
  remembered counters on every (re)connection and a card that never
  moved is not re-reported.
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
