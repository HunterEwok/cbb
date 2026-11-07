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
`cbb_join_free` ends the joiner. `cbb_join_new_admin` does the same for a phone that asks to be
an admin: the request names `admin_public`, the admin key's public point, and a second callback
signs with that key; the phone's info offers the key with its proof (docs/protocol.md,
section 6, ADa), and the joined answer carries `admin_ca`, the admin CA the group's root
issued for it. The pairing runs inside the core's TLS (`cbb_core::pair_session`); the app only
moves the bytes.

Built with the feature `member` too (again only `bind.sh aurora`), the library runs the lite
member's own node in the app's process once the phone is in a group (`lite/ffi/src/member.rs`,
over `cbb_lite::phone`): `cbb_member_start` takes the app's data directory, the phone's name,
system and versions, its identity (device, certificate, issuer, group CA, roots), its public
key, its secret for sealed messages and the same signing callback, and a callback that gets
each event as JSON from the node's threads (`write`: a text for the phone's clipboard, with its
kind and, for a secret, how long it may stay; `log`: a line for the app's log; `identity`: the
certificate, issuer and roots after an admin renewed the certificate or a takeover made a new
root, which the app keeps in its own file, as the core keeps no identity file for a key it does
not hold). The node signs
its TLS handshakes and its copies through the callback, presents itself as a phone (role
`phone`, key store `hardware`, or `file` when the request's `key_store` says so), never listens and dials the members mDNS finds;
`cbb_member_copy` sends a text the user handed to the app, `cbb_member_peers` lists the members
connected and `cbb_member_stop` stops it. `TestFFIJoiner` runs the join, sync both ways and a
renewal against a Go member through the example `phone-on-linux`, and `TestFFIJoinerAdmin` the
join as an admin.

Built with the feature `tunnel` (the iPhone and Android libraries), the library is also the
phones' tunnel (`lite/ffi/src/tunnel.rs`, whose comment lists the requests): `cbb_tunnel` takes
a JSON request by its `op` for the tunnel to the hub (a loopback port that leads to the hub's
member port, with AmneziaWG and VLESS with XHTTP), for the phone as the group's hub (its
clients, its remote invitations with a guest tunnel to the pairing window), and their status;
`cbb_tunnel_register` registers the phone's hub with the group's forwarder and
`cbb_tunnel_relay` links the phone to the blind relay, both signing their TLS with the member
key through the same callback, the relay's link telling the app through an events' callback
which connections it joined. `TestRustPhoneTunnel`, `TestRustPhoneHub`,
`TestRustPhoneHubInvite`, `TestRustPhoneHubForwarder` and `TestRustPhoneRelay` run them against
Go's hub, clients, forwarder and relay through the example `tunnel-on-linux`.

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
| `copy_verdict` | `receives`, `paused`, `kind`, `mark`, `unread`, `has_text`, `has_media`, `takes_media`, `held` (booleans, false when left out but `receives`), `age_ms`, `window_ms`, `secret_ttl_ms` | `{"verdict"}`: whether the group's current copy goes into the member's clipboard (`write`), or why not: `mode`, `paused`, `unread`, `secret_gone`, `no_text`, `held` or `old` (`cbb_core::rule`; the cases of `testdata/interop/copy-verdicts.json`) |
| `open_copy` | `event`, `me` (the reader's device), `secret` (base64, its secret for sealed messages) | `{"kind", "via", "text", "media", "key"}`: what the copy holds, and the copy's key (base64), which opens its blob; code 17 when it is not sealed to `me`, does not open or breaks a rule of its content. It does not check the origin |
| `seal_segment`, `open_segment` | `key` (base64, the copy's key), `index` (from 0), `last` (the blob's last segment), `data` (base64: at most 64 KiB to seal, 65 552 bytes to open) | `{"data"}`: the segment sealed or opened ([protocol.md](protocol.md), section 4, "The blob"); a segment that does not open is code 17 |
| `group_command` | the set's arguments, `command` (`{body, sig, chain}`), `me` (the member's device), `secret` (optional, base64: the member's secret for sealed messages) | `{"command", "signer", "root", "sender", "verified", "opened"}`: the command's body as an object, with a sealed command's orders opened with `secret` and put in it (`opened`), the device that signed it, whether it signed as the root, and the device the limits count it for, `verified` when that device's own key signed; a command refused is code 15, as is a sealed one without `secret` or one that does not open with it, and a `paste` in the open for a member whose device record has a `seal` key |
| `group_claim_times` | the set's arguments, `claim_times` (`[{record, ms}]`, from a Welcome) | `{"file"}`: the times earlier than the set's own and not in the future taken |
| `parse_body` | `kind` (`command`, `credential`, `keys`, `release`, `channel`, `attest-status`, `entries` or `manifest`), `body` (base64) | `{"kind", "value"}`: the body's fields as an object, once it checks; see "Signed bodies" |
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
