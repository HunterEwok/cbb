<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The core's entry point

For engineers and anyone binding the Rust core into another program: the one call through
which every program uses the core's rules (`cbb_core::api`, `lite/core/src/api.rs`). Every
program reaches it through the same C functions of `lite/ffi`: the phone kits link them, Go
through cgo or wasm. The rules themselves are in
[records-v2.md](records-v2.md).

## Requests and answers

A request is a JSON object in UTF-8, at most 8 MiB:

```json
{"abi": 1, "op": "evaluate", "args": {...}}
```

| Field | Meaning |
|---|---|
| `abi` | the version of the request and answer shapes the caller speaks; the core answers only its own |
| `op` | the operation, from the table below |
| `args` | the operation's arguments; left out when it takes none |

The answer is canonical JSON, either `{"abi": 1, "ok": ...}` with the operation's result or

```json
{"abi": 1, "error": {"code": 10, "name": "body", "message": "...", "details": "..."}}
```

`message` is a short sentence for the user. `details` holds the causes under it, one per
line, each with its type where known; a program shows them under the message in debug mode
and always logs them ([errors](reference/errors.md)). The call never panics and answers any
bytes, also bytes that are not a request. A change an older caller would misread raises
`abi`.

`lite/ffi` exports `call` as C functions, declared in `lite/ffi/include/cbb_core.h`:
`cbb_call` takes the request's bytes and returns the answer's, which the caller gives back
with `cbb_free`; `cbb_abi` gives the ABI. `lite/ffi/bind.sh` builds the library for the
phones. The Swift kit links it as the module `CCbbCore` (`Core.swift`), the Kotlin kit loads
`libcbb_ffi` through JNA (`Core.kt`); both check the ABI before each call, as Go does.

Built with the feature `join` (only the Aurora app's library, `bind.sh aurora`), the library
also lets a phone join by its QR code with a key the core does not hold, the Aurora app's key
in OP-TEE: `cbb_join_new` takes the phone's name, its system, its public key, the addresses
for the QR code and a callback that signs a SHA-256 digest with the key, and answers the QR
code's text and modules and the code; for each connection a member dials, `cbb_join_accept`
starts an attempt and `cbb_join_feed` takes the bytes that arrive and answers those to send
and whether the member admitted the phone (with its certificate, the group CA, the roots and
the records file); `cbb_join_finish` tells the member whether the app stored it, and
`cbb_join_free` ends the joiner. In the build with the member, `cbb_join_announce` announces the
joiner by mDNS on the port the app listens on until it is freed, so that a computer of the group
admits it by the code typed there. `cbb_join_new_admin` does the same for a phone that asks to be
an admin: the request names `admin_public`, the admin key's public point, and a second callback
signs with that key; the phone's info offers the key with its proof (docs/protocol.md,
section 6, ADa), and the joined answer carries `admin_ca`, the admin CA the group's root
issued for it. The pairing runs inside the core's TLS (`cbb_core::pair_session`); the app only
moves the bytes.

### The member

Built with the feature `member` too (`bind.sh aurora` today; the iPhone and Android apps move
onto it next), the library runs the lite member's own node in the app's process once the phone
is in a group (`lite/ffi/src/member.rs`, over `cbb_lite::phone`): `cbb_member_start` takes the
app's data directory, the phone's name, system and versions, its identity (device,
certificate, issuer, group CA, roots), its public key, its secret for sealed messages and the
same signing callback, and a callback that gets each event as JSON from the node's threads:
`write`, a text for the phone's clipboard, with its kind and, for a secret, how long it may
stay; `copy`, a copy that became the group's current one from another member (below);
`message`, an `admin`, `hubs` or `credentials` message a peer sent, for the app to keep;
`log`, a line for the app's log; `identity`, the certificate, issuer and roots after an admin
renewed the certificate or a takeover made a new root, which the app keeps in its own file, as
the core keeps no identity file for a key it does not hold; `mute`, an admin muted the phone or
ended its mute, with how long it lasts and who. The node signs its TLS handshakes
and its copies through the callback and presents itself as a phone (role `phone`, key store
`hardware`, or `file` when the request's `key_store` says so); it dials the members mDNS finds
(`mdns`, on by default) and those the app hands in. `cbb_member_stop` stops it.

`cbb_member_call` asks it everything else, a request `{"op", "args"}` and its answer `{"ok"}`
or `{"error"}` as `cbb_call`'s. `fetch`, `command` and `wait` wait for the network, so the app
calls them off its main thread. A copy is `{id, origin, age_ms, kind, via, text, media,
unread, key}`: `media` is the manifest of images or files, and `key` what the button compares
it by (a text by itself, an image by `"\u0000image:"` and the hex SHA-256 of its PNG or JPEG
part, files by `"\u0000files:"` and the copy's ID).

| `op` | `args` | `ok` |
|---|---|---|
| `copy` | `text`, `secret` (optional), `board` (optional, `true` by default: it came from the phone's clipboard) | `{}` |
| `copy_media` | `text` (optional), `parts`: `[{type, path, dir, data, file}]`, clipboard data with its bytes in `data` (base64) or a file or folder with the file on the phone in `file`; `board` (optional, `false` by default) | `{"copy"}` |
| `current` | none | `{"copy"}`: the group's current copy, or null |
| `waiting` | none | `{"copy"}`: the copy from another device that waits for the phone (design.md, "The one button"), or null |
| `took` | `id` | `{}`: the app took that copy into the clipboard, or saved its files |
| `sends` | `board`: the clipboard's key | `{"sends"}`: whether the button sends it: it is neither the group's copy nor what this phone itself sent from its clipboard or took into it last |
| `fetch` | `id`, `max` (bytes of the sealed blob), `out` (a new folder) | `{"parts"}`: each part with `file`, where it is, each checked against its hash |
| `found`, `lost` | `key` (the app's name for the member), `addrs` (`host:port`, loopback too for the tunnel), `device` (optional) | `{}`: dial it again and again, or stop |
| `listen`, `unlisten` | `port` (0 for any) | `{"port"}`: the member port for the members that dial this phone as the group's hub, which the app publishes with `r=phone` |
| `pause`, `resume`, `wait` | `wait`: `timeout_ms` | `{}`; `wait` answers `{"connected"}`: the app in the background closes every connection and makes none; one pass of a background refresh is `resume`, `wait`, `waiting`, `pause` |
| `mute` | `until_ms` (null unmutes) | `{}` |
| `sync` | `on`, `for_ms` (only with `on: false`; 0 for until it is turned on) | the state, as `muted` gives it: turns the phone's sync on or off, saved in `sync.json` (design.md, "Sync on and off"); the members see it at the next connection |
| `muted` | none | `{"sync_off", "sync_off_ms", "muted", "muted_ms"}`: how long sync stays off and an admin's mute lasts, 0 for until lifted |
| `peers` | `all` (optional: those that carry records only too) | `{"peers"}`: `[{device, name, role, os, key_store, mode, muted, muted_for_ms, actions, info, admin_key, tunnel_key, tunnel_psk, reach, records_only, features}]`, as their hellos and reach messages present them |
| `records` | none | `{"records"}` |
| `devices` | none | `{"devices"}`: every device of the group as the app shows it, `[{device, name, role, os, admin, root, frozen, online, self, listed}]`: the group's device records, whether it is connected and whether it is this phone, then the connected members no record lists yet (`listed` false) |
| `alerts` | none | `{"alerts"}`: what the group's records stop and what ends it, for the alerts card (`cbb_core::manage::alerts`, as the kits' `GroupAlert`), `[{kind, names, devices, records, left_ms, count}]`, kind `stopped`, `secrets_stopped`, `two_histories`, `admins`, `claims`, `claim_pending`, `claim_stopped` or `newer`; the root ends one with `cbb_member_manage`'s `resolve` of its records, or by removing one of its devices |
| `away`, `away_status` | `on` for `away` | `{"away"}`: sync away from home turned on (new tunnel keys, which the hellos offer the group's hubs) or off (the keys and the hubs' offers forgotten), and where it stands, as `cbb global` shows it on the lite member (`hub_device`, `endpoints`, `through`, `error`, `detail`), or null while it is off; only in a library built with the feature `tunnel`, otherwise `away` with `on` answers an error |
| `add_records` | `records`: those the app's root or admin key signed | `{}`: kept and sent to every peer |
| `command` | `command` (a record envelope), `timeout_ms` (10 s by default) | `{"result"}`: sent to its receiver, or to the group's hubs connected, which pass it on (protocol.md, section 15) |
| `send_cert`, `send_admin_ca`, `send_tunnel` | `to`, and `cert` with `issuer`, `ca`, or `offer` | `{"sent"}` |
| `send_hubs`, `send_credentials` | `share`, `credentials` | `{"to"}` |

A phone's node passes on a command for another device when it is connected to it, as
protocol.md section 15 says. For itself it carries out the `mute` and `unmute` commands an
admin sends, keeps both in `mute.json` as the lite member does, and refuses the other commands,
which a phone has nothing to carry out for. It keeps the sealed blobs
of the copies with images or files it made or fetched in `content/` of its data directory,
the last eight, and serves them (its hello says `media`). `TestFFIJoiner` runs the join, sync
both ways, a pause, an admin's mute and a renewal against a Go member through the example `phone-on-linux`,
`TestFFIPhoneAway` sync away from home through a Go hub's tunnel, the phone's node running the
lite member's (`lite/src/away.rs`: it keeps the hubs' offers and, while no hub is at home,
dials the first that answers through its tunnel's loopback port),
`TestFFIJoinerAdmin` the join as an admin, then that admin phone admitting a Go computer that
listens, `TestFFIPhoneRoot` a phone that makes its own group and admits a Go computer as its
root, and `TestFFIMember` the calls: an address handed in, the button's rule, images both ways,
and pausing.

`cbb_qr_read` (feature `join`, `src/qr.rs`) reads the QR codes in a grey camera frame with the
`rqrr` crate, since Aurora gives an app no reader of its own. An admin phone admits a device by the device's QR code with `cbb_admit_new`, `cbb_admit_dial`,
`cbb_admit_feed` and `cbb_admit_free` (`src/admit.rs` over `cbb_core::admit`): the app dials one
of the code's addresses and passes the connection's bytes; the core checks the joiner against the
code's fingerprint, confirms the code first, issues the member certificate with the phone's admin
CA (`cbb_core::issue`, the key signing through the callback), and an admin CA when the group's
root admits a phone that asks to be an admin, sends the Welcome and adds the device record to the
group (docs/protocol.md, section 6, "The joiner listens"). `cbb_group_new` (feature `join`,
`cbb_core::admit::new_group`) makes a group of the phone's own, as the iPhone's
`PhoneGroup.create` does: a root CA for the app's root key, the phone's member certificate and its
device record holding the root, all signed through the callback; its answer has a join's
fields, so the app keeps it as it keeps a join, and admits with the root key and no admin CA.
`cbb_member_manage` (feature `member`, `cbb_core::manage`) signs an admin's change to a device
through the same callback, as the phone kits' `PhoneGroup` does: a removal (every key of the
device, its admin key among them; not the phone itself, nor the root's phone, which is taken
over instead), a new name (a device record like its newest; an admin renames only a device the
root did not record, since a root's record beats an admin's), a thaw of a frozen admin, which
the member adds to its records and sends to the group, or a mute or an unmute, a command sealed
to the device's key when its record names one, which the member sends and whose result it
answers. As the root it makes a connected computer an admin (`make_admin`: an admin CA for the
admin key its hello offers, its device record again, and the admin message), and as any admin it
renews (`renew`) every member certificate that is due, each connected member's, sent to it, and the
phone's own, as the phone kits do when a peer connects. `TestFFIPhoneRoot` renames and removes a
computer through it.

Built with the feature `tunnel` (the iPhone and Android libraries), the library is also the
phones' tunnel (`lite/ffi/src/tunnel.rs`, whose comment lists the requests): `cbb_tunnel` takes
a JSON request by its `op` for the tunnel to the hub (a loopback port that leads to the hub's
member port, with AmneziaWG and VLESS with XHTTP), for the phone as the group's hub (its
clients, its remote invitations with a guest tunnel to the pairing window), and their status;
`cbb_tunnel_register` registers the phone's hub with the group's forwarder and
`cbb_tunnel_relay` links the phone to the blind relay, both signing their TLS with the member
key through the same callback, the relay's link telling the app through an events' callback
which connections it joined; `cbb_tunnel_relay_credentials` makes the link register with the
group's server credentials (docs/protocol.md, section 18), signed with the period's server key
through another callback. `TestRustPhoneTunnel`, `TestRustPhoneHub`, `TestRustPhoneHubInvite`,
`TestRustPhoneHubForwarder`, `TestRustPhoneRelay` and `TestRustPhoneRelayCredentials` run them
against Go's hub, clients, forwarder and relay through the example `tunnel-on-linux`.

Go reaches them in `internal/core`: through cgo under the build tag `cbbcore`, linking
`libcbb_ffi`, or through the same core built as WebAssembly (`lite/wasm`, `cbb_call` and its
memory functions), run by wazero under the tag `cbbwasm`. Every release build of `cbb`, on
every system and architecture, takes `cbbwasm`, so it stays one static binary without cgo
(the release workflow checks the tag with `go version -m`), and `cbb version` names the
rules it runs; a build without either tag, as `go build` and `go test` are, evaluates with
Go's own `internal/authority`, which only the tests use as a reference.
`lite/wasm/build.sh` builds the module and writes the `go build -overlay` file that lays it
over `internal/core/cbb_core.wasm`, so no build output lands in the source tree.

## Operations

| `op` | `args` | `ok` |
|---|---|---|
| `version` | none | `{"abi", "core", "source"}`: the ABI, the core's version and, when the build passed it in `CBB_SOURCE`, the commit |
| `evaluate` | `group_ca` (base64 DER), `group` (its tag), `now_ms` (the member's clock that counts sleep), `time_unknown` (optional, `true` when the member does not know how long it has held its claims), `first_seen` (`[{record, ms}]`, optional), `records` (`[{body, sig, chain}]`, base64) | the group's state ([protocol.md](protocol.md), section 10, "The state"); records that do not verify are left out, never an error |
| `evaluate_saved` | the arguments of `evaluate`, `secret` (base64, at least 16 bytes) and `saved` (base64, optional) | `{"saved", "state"}`: the new saved state, base64, and the group's state; see "The saved state" |
| `canonical_body` | a record body as an object, in any order, with `v` and `signer` set | `{"body"}`: the canonical bytes to sign, base64, after each field is checked against its row |
| `check_body` | `{"body"}`, base64 | `{"body"}` as it came, once its size, canonical form and fields check |
| `canonicalize` | `{"body"}`, base64 | `{"body"}`: the strict canonical form of a signed body of version 2 |
| `check_member` | `chain` (the peer's certificates as it sent them, leaf first, base64 DER), `trusted` (the roots the member trusts, the current root first), `usage` (`"server"` for a member this one dialed, `"client"` for one that dialed it), `now_ms` | `{"device", "used"}`: the device the leaf names and the certificates the records then judge, base64: the leaf and the admin CA that issued it, if one did, wherever the peer put it; see "Member chains" |
| `read_invite` | `text`: a remote invitation's text ([protocol.md](protocol.md), section 12) | `{"invitation"}` with `group`, `hub`, `hub_key`, `endpoints`, `guest_key`, `guest_psk`, `secret`, `expires` (Unix seconds) and `obfuscation` (or `null`), as the valid cases of `testdata/interop/invites.json` write them; or `{"refused": {"reason", "message"}}`, the reason one of the names of section 12 and the message a sentence for the user. A refused invitation is an answer, not an error. The caller checks `expires` against its clock |
| `recovery_sheet` | `key` (the recovery key's 32 bytes, base64), `cert` (its admin CA, DER, base64), `group` (the group's tag) | `{"qr", "text", "admin"}`: the sheet's QR code and text ([protocol.md](protocol.md), section 10, "The recovery key") and the key hash the `recovery` record names. An admin CA that is not the key's is refused with `cert` |
| `read_recovery_sheet` | `text`: what the user scanned or typed | `{"sheet"}` with `key` (32 bytes), `pkcs8`, `public` (uncompressed), `admin` (its key hash), all base64, and from the QR code `cert` and `group`; or `{"refused": {"reason", "message"}}` as `read_invite`, with the reasons of protocol.md's "The recovery sheet" |
| `group_add` | the set's arguments (see "The record set"), `records` | `{"file", "fresh", "errors"}`: the new file, the records it did not hold before, and why it left others out (optional) |
| `group_view` | the set's arguments | `{"state", "devices", "path", "root_member", "hub_order", "handed_to", "digest", "claim_times", "records"}`: see "The record set" |
| `group_refused` | the set's arguments, `chain` (a chain `check_member` took, leaf first) | `{"verdict", "why", "claimant"}`: `ok`, `not_listed` (the set does not name the device yet), `taken_over` (the root's own device that a claim took the group over from, whose connection carries records only; `claimant` is `{device, admin}`), `stopped` (the state stops the exchange with the device, docs/protocol.md section 10, "Stopping the exchange"; its connection carries records only) or `refused`, with the reason for the log |
| `group_taken_over` | the set's arguments, `chain` (the member's own) | `{"claimant"}`: `{device, admin}` of the admin that took the group over from this root by a claim that took effect; `{}` when none did |
| `group_refused_admin_ca` | the set's arguments, `ca` (base64 DER) | `{"verdict", "why"}` for an admin CA, as for `group_refused` |
| `group_admin_peer` | the set's arguments, `device`, `chain` | `{"admin"}`: whether the device is the group's root or an admin |
| `group_hub_peer` | the set's arguments, `device`, `chain` | `{"hub"}`: whether the device may be a hub of the group, whose offers a member keeps: the root, an admin, or a device that only passes copies on ([protocol.md](protocol.md), section 11, "Two kinds of hub") |
| `group_seal_copy` | the set's arguments, `id`, `origin`, `time`, `cert` and `issuer` (optional; base64 DER), `kind`, `via` (optional), `text`, `media` (a manifest, optional), `blob` (`{size, sha256}`, optional) and `key` (base64, 32 bytes, the key that sealed the blob; optional without a blob) | `{"event", "to_sign", "readers", "key"}`: the copy sealed to the readers the set names ([protocol.md](protocol.md), section 4, "Sealing" and "Readers"), without `sig`; the caller signs `to_sign` (base64) with its member key, ECDSA P-256 with SHA-256 in DER, and puts it in the event's `sig`. `key` comes back when the core made it. A copy that cannot be sealed is code 17 |
| `group_check_copy` | the set's arguments, `event` (a copy as the member protocol carries it) | `{}` when the copy's certificate, its issuer, its origin's key and its signature check against the set, as a member checks a copy before it passes it on; code 17 with the reason otherwise |
| `seal_copy_to` | `id`, `origin`, `time`, `cert` and `issuer` (optional; base64 DER), `readers` (`[{id, seal}]`, `seal` base64: each reader's public key for sealed messages), `kind`, `via` (optional), `text`, `media` (optional), `blob` (optional) and `key` (base64, 32 bytes) | `{"event", "to_sign"}`: the copy sealed to the readers given, as `group_seal_copy` seals it, for a member that keeps its records itself (the Go service); the caller signs `to_sign` |
| `copy_verdict` | `receives`, `kind`, `mark`, `unread`, `has_text`, `has_media`, `takes_media`, `held` (booleans, false when left out but `receives`), `age_ms`, `window_ms`, `secret_ttl_ms` | `{"verdict"}`: whether the group's current copy goes into the member's clipboard (`write`), or why not: `mode`, `unread`, `secret_gone`, `no_text`, `held` or `old` (`cbb_core::rule`; the cases of `testdata/interop/copy-verdicts.json`) |
| `open_copy` | `event`, `me` (the reader's device), `secret` (base64, its secret for sealed messages) | `{"kind", "via", "text", "media", "key"}`: what the copy holds, and the copy's key (base64), which opens its blob; code 17 when it is not sealed to `me`, does not open or breaks a rule of its content. It does not check the origin |
| `seal_segment`, `open_segment` | `key` (base64, the copy's key), `index` (from 0), `last` (the blob's last segment), `data` (base64: at most 64 KiB to seal, 65 552 bytes to open) | `{"data"}`: the segment sealed or opened ([protocol.md](protocol.md), section 4, "The blob"); a segment that does not open is code 17 |
| `group_command` | the set's arguments, `command` (`{body, sig, chain}`), `me` (the member's device), `secret` (optional, base64: the member's secret for sealed messages) | `{"command", "signer", "root", "sender", "verified", "opened"}`: the command's body as an object, with a sealed command's orders opened with `secret` and put in it (`opened`), the device that signed it, whether it signed as the root, and the device the limits count it for, `verified` when that device's own key signed; a command refused is code 15, as is a sealed one without `secret` or one that does not open with it, and a `paste` in the open for a member whose device record has a `seal` key |
| `group_claim_times` | the set's arguments, `claim_times` (`[{record, ms}]`, from a Welcome) | `{"file"}`: the times earlier than the set's own and not in the future taken |
| `parse_body` | `kind` (`command`, `credential`, `keys`, `release`, `channel`, `attest-status`, `entries`, `zxnext` or `manifest`), `body` (base64) | `{"kind", "value"}`: the body's fields as an object, once it checks; see "Signed bodies" |
| `new_device_key` | none | `{"pkcs8", "public"}`: a new P-256 device key (base64 PKCS #8 and SEC1 uncompressed) for a phone that keeps its key in a file (level 3) |
| `sign_digest` | `pkcs8`, `digest` (base64, 32 bytes) | `{"sig"}`: ECDSA P-256 over the SHA-256 digest with that key, DER, base64: what the phone's signing callback gives for a key in a file |
| `seal_public` | `secret` (base64, 32 random bytes the device keeps) | `{"key"}`: its public key for sealed messages (base64, 1216 bytes), the `seal` its pairing and device record carry |
| `seal_command` | `body` (base64, a command in the open), `key` (base64, the receiver's `seal` key) | `{"body"}`: the same command with its orders sealed to the key (`v` `2`, `sealed`), canonical, for the sender to sign; see "Signed bodies" |
| `group_body` | the set's arguments, `body` (a record body as `canonical_body` takes it, with `signer` set) | `{"body"}`: the canonical bytes of the signer's next record, to sign: the group, seq and prev set from the set, and for a removal, a freeze or a claim `seen` from the set, the signer's own previous seq among them |

The arguments of `evaluate` are a case of `testdata/interop/v2-records.json` as it is.

`cbb version` of the lite member names the core it was built with in a second line,
`core 0.6.0, abi 1, source <commit>`; the release builds pass the tag's commit in `CBB_SOURCE`,
and other builds say `source unknown`. The full member and the apps show the same once they
call the core.

## Error codes

The numbers and names never change meaning; new codes are added at the end of their range.

| Code | Name | Meaning |
|---|---|---|
| 1 | `request` | the request is not a JSON object of the right shape, or an argument is missing or of the wrong type |
| 2 | `abi` | the request's `abi` is not the core's |
| 3 | `op` | the core has no such operation |
| 4 | `too_large` | the request is larger than 8 MiB |
| 10 | `body` | a record body is refused: its size, form or a field |
| 11 | `cert` | a certificate is refused |
| 12 | `strict` | a signed body is not in the strict canonical form |
| 13 | `rollback` | the record set is older than the saved one: a signer's whole chain ends below the seq saved |
| 14 | `saved` | the saved state cannot be read, is of another version or group, or its check with the secret does not match |
| 15 | `command` | a command is refused: its signer, its target, its time or its limits |
| 16 | `signed` | a signed body that is not a record (a command, a server credential, a release file or a manifest) is refused: its size, form or a field |
| 17 | `copy` | a copy is refused or cannot be sealed: its origin, its signature or a field, or it does not open with the device's key |

## Member chains

`check_member` is the check of a peer's certificates in member TLS, for a TLS stack's verify
callback (Go's `VerifyConnection`, the phones' trust evaluation): the leaf is no CA, lists the
usage in its extended key usage, names its device as its CN and its one DNS name
(`cb-<device>.local`), and is in its lifetime; a trusted root issued it, or an admin CA (path
length 0, a P-256 key, certificate signing) that a trusted root issued and that is in its own
lifetime. The clock is `now_ms` raised to the current root's start, so a member whose clock is
years behind still connects. A chain it refuses is code 11 (`cert`). Whether the records still
admit the device, and whether it is the device discovery found, are the caller's to check.
`testdata/interop/member-chains.json`, written by Go from crypto/tls's chain building, holds the
cases both give the same answer.

## The record set

The calls whose names start with `group_` work on the set of records a member keeps, which the
phones store as the records file the lite member writes (`cbb_core::group::Records`):
`{"v": 2, "records": [{body, sig, chain}], "first_seen": [{record, ms}]}`. The caller keeps the
file and passes it in each call, base64; a call that changes the set answers the new file,
which the caller saves in place of the old one. So the phones hold no rule of the group in
their own code, and every member gives the same answers for the same records.

The set's arguments, which every such call takes:

| Field | Meaning |
|---|---|
| `group_ca` | the group CA, base64 DER |
| `now_ms` | the member's clock that counts sleep |
| `file` | the records file, base64; left out for an empty set |
| `group` | optional: the group's tag where it is not the CA's own, for the vectors |

The set keeps a record that verifies under one of the group's roots and names the group, and a
record of a later version, which it passes on and never applies (records-v2.md); it keeps at
most the records records-v2.md allows. `group_view` answers:

| Field | Meaning |
|---|---|
| `state` | the group's state, as `evaluate` gives it for the records the set keeps |
| `devices` | `[{device, name, role, os, key, store, kind, proof, seal, admin, admin_key, powers, commands, frozen, freezes, keys}]`: the devices list the apps show; `key`, `keys` and `seal` (the key commands for it are sealed to, when its record has one) base64; `freezes`, for a frozen admin, the IDs of the freezes a thaw names |
| `path` | the roots' certificates on the path, the group CA first, base64 DER |
| `root_member` | `{device, key}`: the device that holds the root key, when the set names one |
| `hub_order` | the devices that may be hubs, in the order members try them |
| `handed_to` | the admin key hash (base64) of the current root's newest `handover` record that the state does not ignore, while that key is neither revoked nor frozen; left out without one. The phone with that admin key offers to take the group, and its claim takes effect at once (docs/protocol.md, section 10, "Handing the group over") |
| `digest` | the set's digest, which a hello carries; left out for an empty set |
| `claim_times` | `[{record, ms}]`: when the set first held each claim, which a Welcome passes on |
| `known` | every device ID a device record names, counted or not: IDs a new device must not take |
| `records` | the number of records the set holds |

## Signed bodies

`parse_body` reads the signed bodies other than records as every program reads them
([protocol.md](protocol.md): commands in section 15, server credentials in section 13, the
release files in section 16, manifests in section 7): the strict form of signed bodies, then
each field against its row. A release file's body is refused above 256 KiB, as its envelope
allows. It checks the body alone; the signature, the signer and the time are the caller's, or
`group_command`'s for a command. Go calls it in a build that links the core, as the release
builds do, and decodes the fields from the bytes it checked; a build without the core reads the
bodies with Go's own code, which the strict vectors keep the same. The phone kits call it for
each command, credential and release file they take. A manifest comes inside a copy's sealed
Content, in the canonical form, and `open_copy` reads it there for the phones; Go reads it with
`clip.ParseManifest`, which asks `parse_body` first in a build that links the core, and the kits'
`Media.Manifest.parse` asks it for a manifest given as bytes.

`seal_command` seals a command's orders to its receiver (protocol.md, section 15, "Sealed
commands"): it checks the command in the open as `parse_body` does, moves `mode`, `hub`,
`enter`, `kind`, `text` and `action` into the sealed part with the header as associated data,
and writes the body with `v` `2` in the canonical form. The phone kits call it for each command
to a device whose record has a `seal` key; Go seals with its own `group.SealCommand`, and both
open each other's. A phone keeps a secret for sealed messages of its own (32 random bytes in
the keychain, or under a key of the Android Keystore), gives its public key from `seal_public`
when it makes a group or joins one, and passes the secret to `group_command`, which opens the
commands sealed to it.

## Signatures already checked

The core keeps the signatures it has checked in memory, for every call of the process: an
entry is SHA-256 over `cbb sig cache v1`, the signer's key hash, the body's SHA-256 and the
signature, and only a signature that verified gets one. Evaluating the same records again
checks each signature once. It holds at most 8192 entries and starts again when full.

## The saved state

A member keeps a saved state between evaluations, so that a record set rolled back (an older
copy of the records put back on its disk or sent to it) is noticed, and so that the
signatures it checked are not checked again after a restart. The member makes a random
secret of 32 bytes once and keeps it next to its identity (in the keychain or Keystore on a
phone); it calls `evaluate_saved` with the secret and the saved state of its last call, and
saves the `saved` of the answer.

The saved state is canonical JSON:

| Field | Meaning |
|---|---|
| `v` | 1, the format's version |
| `group` | the group's tag |
| `seqs` | `[{key, seq}]`: for each of the group's signers, the highest seq whose prev chain is held whole down to seq 1 |
| `sigs` | the entries of the signatures already checked, base64 |
| `mac` | HMAC-SHA256 with the secret over `cbb saved state v1` and a newline, then the canonical JSON of the other fields |

The core refuses the call (`saved`) when the check does not match, when `v` is another
version or `group` another group, and (`rollback`) when a signer of `seqs` has no whole chain
up to that seq or above in the set: a record taken from the middle of a chain is a rollback
too. The group's signers are the group CA, the root of a claim one of the group's admins
signed, and the admins under those roots; a root that only a stranger's claim names is not
saved, so its records may come and go. A chain may also end at an anchor of one of the
group's roots' checkpoints, so that a set the checkpoint pruned is no rollback. Its entries of `sigs` are added to the signatures already
checked only after the check matched. The member shows the refusal with its details and does
not use the records; the state of the group is not saved, since it comes from the records
each time.
