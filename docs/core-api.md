<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The core's entry point

For engineers and anyone binding the Rust core into another program: the one call through
which every program uses the core's rules (`cbb_core::api`, `core/src/api.rs`). Every
program reaches it through the same C functions of `ffi/`: the phone kits link them, Go
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

`ffi/` exports `call` as C functions, declared in `ffi/include/cbb_core.h`:
`cbb_call` takes the request's bytes and returns the answer's, which the caller gives back
with `cbb_free`; `cbb_abi` gives the ABI. `ffi/bind.sh` builds the library for the
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

Built with the feature `member` too (every library `bind.sh` builds: the iPhone, Android and
Aurora apps run it), the library runs the lite member's own node in the app's process once the phone
is in a group (`ffi/src/member.rs`, over `cbb_lite::phone`): `cbb_member_start` takes the
app's data directory, the phone's name, system and versions, its identity (device,
certificate, issuer, group CA, roots), its public key, its secret for sealed messages and the
same signing callback, and a callback that gets each event as JSON from the node's threads:
`write`, a text for the phone's clipboard, with its kind and, for a secret, how long it may
stay; `copy`, a copy that became the group's current one from another member (below);
`message`, an `admin`, `hubs`, `credentials` or `evidence` message a peer sent, for the app to keep;
`peer`, a peer whose hello the node took, as `peers` shows it, for the app to answer (renew
its certificate, send it its admin CA, answer its tunnel key as the hub); `tunnel`, a tunnel
offer of the group's root or an admin, for the app's tunnel; `command`, a command for the
phone itself with a `token`, which the app checks against the records, carries out and
answers with `answer` within ten seconds, or the phone refuses it; `caller`, a call to the
relay's port with a `token`, its loopback `port` and the `device` its certificate names, which
the app answers with the op `caller` within five seconds, or the call is closed;
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

### The member's operations

A phone's `cbb_member_call` and a computer's control socket (protocol.md, section 8: the
service's, the Mac app's, the tray app's and `cbb`'s) take one list of operations, with the same
names and the same `args` and `ok`; `where` says which members take each: `both`, a `phone`
(the node in the app, which the app drives) or a `computer` (the service, whose control socket
also carries the clipboard's watchers). On the socket a text or other bytes go as the payload
after the header, and an operation that answers more than once marks the last answer with
`done`. `TestFFIJoiner` reads the phone's `devices` answer as the socket's, field for field.

| `op` | where | `args` | `ok` |
|---|---|---|---|
| `copy` | both | `text` (on the socket, the payload), `kind` (`text`, the default, or `secret`), `via` (on a computer: `copy`, the default, `phone` or `universal-clipboard`), `board` (on a phone: optional, `true` by default: it came from the phone's clipboard) | `{}`. A deliberate action: always an event, also written to the member's own clipboard |
| `copy_media` | both | on a phone: `text` (optional), `parts`: `[{type, path, dir, data, file}]`, clipboard data with its bytes in `data` (base64) or a file or folder with the file on the phone in `file`; `board` (optional, `false` by default). On a computer the parts stream instead: the payload is the plain-text alternative, or none; then for each part `{"op":"part", part}` (`part` = `{type?, path?, dir?, size?}`), followed for a file or clipboard data by `{"op":"data"}` messages whose payloads, at most 1 MiB each, are exactly its `size` bytes; last `{"op":"part", done}` | a phone answers `{"copy"}`, a computer `{}`: the parts are in the cache and the copy went to the group as a `media` event (protocol.md, section 4, "Media"), also written to the member's own clipboard. An error when the copy is over this device's limit, its manifest is not valid or the bytes do not come as said. `cbb copy FILE...` reads the files as the user and sends them |
| `sync` | both | `on` (required), `for_ms` (only with `on: false`, from 1 to 2 592 000 000, 30 days; 0 or absent for until it is turned on), `device` (on a computer, an admin, on the admin socket: another device by name or device ID, with no `for_ms`; a phone turns another device's sync with `cbb_member_manage`) | `{"sync_off", "sync_off_ms", "muted", "muted_ms"}`, as `muted` gives it: turns the device's sync on or off, saved in `sync.json` and in effect (design.md, "Sync on and off"); the members see it at the next connection. With `device`: `{}` once that device answered `done` to the `mode` command (protocol.md, section 15), or an error with its reason. Without `device` on either socket, so that the apps switch it without the administrator |
| `muted` | both | none | `{"sync_off", "sync_off_ms", "muted", "muted_ms"}`: `sync_off` and `sync_off_ms`, `muted` and `muted_ms` say whether sync is off and an admin muted the device, and how long each lasts, 0 for until lifted |
| `bug` | computer | none | the bug report of the panic before the last restart as `bug_report` answers it (payload; empty when none waits); see "Bug reports" |
| `bug_allow` | computer | payload `{"always"}` | the user allowed the report, and maybe always: it goes, and the panic no longer waits |
| `bug_cancel` | computer | none | the user cancelled the report: nothing goes |
| `devices` | both | none | `{"devices"}`: every device of the group, `[{id, name, role, caps, os, store, skew_ms, form, os_version, version, mac, mode, muted, muted_until_ms, admin, root, frozen, online, last_seen_ms, self, listed, may_hub, forward_only, hub}]` (`control::Device`; empty fields left out): the group's device records, whether it is connected and whether it is this device, what a connected member's hello says (`form`, `os_version`, `version`, `mac`, `mode` `shared` or `own`, `muted` and `muted_until_ms` in Unix milliseconds, 0 for until lifted), then the connected members no record lists yet (`listed` false). `last_seen_ms` is when this member last saw the device connected. A phone fills in what its node knows: no `store`, `skew_ms`, `last_seen_ms` or hub fields |
| `current` | phone | none | `{"copy"}`: the group's current copy, or null |
| `waiting` | phone | none | `{"copy"}`: the copy from another device that waits for the phone (design.md, "The one button"), or null |
| `took` | phone | `id` | `{}`: the app took that copy into the clipboard, or saved its files |
| `sends` | phone | `board`: the clipboard's key | `{"sends"}`: whether the button sends it: it is neither the group's copy nor what this phone itself sent from its clipboard or took into it last |
| `fetch` | phone | `id`, `max` (bytes of the sealed blob), `out` (a new folder) | `{"parts"}`: each part with `file`, where it is, each checked against its hash |
| `served` | phone | `id` | `{"served", "size"}`: how far the peers read the sealed blob of the group's copy `id` this phone made, and its size; 0 and 0 for a copy that is no longer the group's or holds no bytes, as the iPhone's share waits until a computer fetched what it shared |
| `found`, `lost` | phone | `key` (the app's name for the member), `addrs` (`host:port`, loopback too for the tunnel), `device` (optional) | `{}`: dial it again and again, or stop |
| `listen`, `unlisten` | phone | `port` (0 for any), `kind`: `home` (the default: every address, for the members that dial this phone as the group's hub at home, which the app publishes with `r=phone`), `tunnel` (the loopback address, for the hub's tunnel) or `relay` (the loopback address, for a blind relay's calls: each waits for the app to name its caller, a `caller` event, and is served only when its certificate names that device); `unlisten` without `kind` closes every port | `{"port"}`: the member port, one already open for that kind staying |
| `caller` | phone | `token` (a `caller` event's), `device` (the device the relay announced from the call's loopback port, or null) | `{}` |
| `pause`, `resume`, `wait` | phone | `wait`: `timeout_ms` | `{}`; `wait` answers `{"connected"}`: the app in the background closes every connection and makes none; one pass of a background refresh is `resume`, `wait`, `waiting`, `pause` |
| `set_mute` | phone | `until_ms` (null unmutes) | `{}`: the phone's own mute, as the app keeps it |
| `peers` | phone | `all` (optional: those that carry records only too) | `{"peers"}`: `[{device, name, role, caps, os, key_store, mode, muted, muted_for_ms, actions, info, admin_key, tunnel_key, tunnel_psk, reach, records_only, features, chain}]`, as their hellos and reach messages present them, `chain` the certificates the handshake checked, leaf first |
| `answer` | phone | `token` (a `command` event's), `status` (`done`, `refused` or `failed`), `reason` | `{}`: the result the command's sender gets |
| `check_command` | phone | `command` (a `command` event's record) | what `group_command` answers for it against the node's records, opened with the phone's key for sealed messages, and for a paste `clean`: its text as it may go in (newlines and tabs, no other control characters or terminal escapes); a command refused is an error. The app keeps the replay cache and its own switches |
| `tunnel_key` | phone | `key`, `psk` (32 bytes each, base64), or neither while sync away from home is off | `{}`: what the hellos offer the group's hubs; the phone connects to the members again |
| `evidence` | phone | `evidence`: the attestations of the phone's keys | `{}`: every peer gets them after its hello (protocol.md, section 17) |
| `disconnect` | phone | `device` | `{}`: the connection to it ends with a goodbye; it is dialed again later |
| `records` | phone | none | `{"records"}` |
| `alerts` | phone | none | `{"alerts"}`: what the group's records stop and what ends it, for the alerts card (`cbb_core::manage::alerts`, as the kits' `GroupAlert`), `[{kind, names, devices, records, left_ms, count}]`, kind `stopped`, `secrets_stopped`, `two_histories`, `admins`, `claims`, `claim_pending`, `claim_stopped` or `newer`; the root ends one with `cbb_member_manage`'s `resolve` of its records, or by removing one of its devices |
| `away`, `away_status` | phone | `on` for `away` | `{"away"}`: sync away from home turned on (new tunnel keys, which the hellos offer the group's hubs) or off (the keys and the hubs' offers forgotten), and where it stands, as `cbb global` shows it on the lite member (`hub_device`, `endpoints`, `through`, `error`, `detail`), or null while it is off; only in a library built with the feature `tunnel`, otherwise `away` with `on` answers an error |
| `add_records` | phone | `records`: those the app's root or admin key signed | `{}`: kept and sent to every peer |
| `command` | phone | `command` (a record envelope), `timeout_ms` (10 s by default) | `{"result"}`: sent to its receiver, or to the group's hubs connected, which pass it on (protocol.md, section 15) |
| `send_cert`, `send_admin_ca`, `send_tunnel` | phone | `to`, and `cert` with `issuer`, `ca`, or `offer` | `{"sent"}` |
| `send_hubs`, `send_credentials` | phone | `share`, `credentials`; `to` (optional: that member only, as a peer that just connected); for `send_credentials` `except` (optional: every member but that one, which sent them) | `{"to"}`: those it went to; without `to` the hubs go to the group's hubs connected, the credentials to every member |
| `paste` | computer | none | `{kind}` + payload = the member's own clipboard text; error `the clipboard is empty` when unknown or an expired secret, and one that names `cbb paste -o` for images or files without a text |
| `copied_media` | computer | as `copy_media` | as `copy_media`, but a watcher's report that its clipboard changed: the copy goes to the group as an event when the engine decides so (protocol.md section 5) and is not written back to the member's own clipboard |
| `paste_media` | computer | `{value?}` | with `value`, the event ID of a remote paste's copy (protocol.md section 15), while it is the group's current copy and its parts are here: the same answers for that copy. Without it, once every part of the member's own images or files (with sync off the group's) is in the cache, fetched first if it is not: `{kind: "media"}` + payload = the plain-text alternative; then for each part `{part}` and its bytes in answers of at most 1 MiB; last `{}`. An error when the clipboard holds none, or they did not arrive. `cbb paste -o DIR` writes them |
| `config` | computer | `{name?, value?}`: `max-copy` or `max-copy-away` and a size such as `200MiB` | `{status}`, with the setting saved first when `name` is given; `status.media` = `{max_copy, max_copy_away, fetching?, fetched?, from?, failed?}`, in bytes, also in `status` |
| `status` | computer | none | `{status}`; `status` = `{device, group, role, os, peers: [{id, role, os, skew_ms}], unreached?, port, cert_ends_ms, incoming_ms, away?, version}`; `cert_ends_ms` is when this device's member certificate ends, in Unix milliseconds, `unreached` lists the members at home that could not connect to this one and synced only because it dialed them back, `port` is the member port; `incoming_ms` is the group's live window (protocol.md section 5, "Writing the member's own clipboard"); `away`, present while sync away from home is on: `{hub, port, endpoints, clients, hub_device, through, keys_in_file, error, detail, forwarder?, relay?}` (protocol.md section 11); `forwarder`, on a hub with one: `{endpoint, registered, seen, error, detail}` (protocol.md section 13); `relay`, on a device with one: `{endpoint, connected, online, error, detail}`, where `online` lists the other devices of the group on the relay and `through` tells whether a member connection runs through it (protocol.md section 14) |
| `leave` | computer | none | `{}`: the device leaves its group (D-83): the service deletes the keys and the group's files, turns remote paste and the quick actions off, and restarts in no group. Refused on the group's root while the group has other devices; taken while the group file is damaged |
| `new` | computer | none | `{status}`: the device creates a group and is its root (protocol.md section 10). Only on a device in no group |
| `pair` | computer | none, or `{code, addrs?, fingerprint?, admins?}` (`admins`, on the root: the window may make a phone an admin) | without `code`: first `{code, expires: 300, address}` (the member port at the first private IPv4 address), then `{name: <joined device name>, done}` or an error. With `code`, a device that listens to join (protocol.md section 6, "The joiner listens") is admitted: at `addrs` with `fingerprint`, as its QR code gives them, or, without them, each device that announces that it waits (protocol.md section 3, TXT `j`) found within 10 s, until one joins; then `{name}` or an error. `admins`, on the root, lets the window make a phone an admin. Only on the group's root or an admin; elsewhere the error names them. Hanging up closes the window |
| `join` | computer | `{code, address?}`, `{code, listen, expires}` or `{invite, consent}` | `{}` or an error. Without `address` it browses for `p=1`. With `listen` it first answers `{addrs, fingerprint}` for the QR code, then `{}` or an error when a member admitted it, or after `expires` seconds. With `invite`, the text of a remote invitation (protocol.md section 12), it needs `consent` (sync away from home is turned on, and the device keeps its keys in files), first answers `{fingerprint}` (of this device's key, for the admin to compare), then `{}` or an error. Hanging up cancels |
| `invite` | computer | `{expires?}`: seconds, 3600 if absent, at most 86 400 | Only on the group's hub, when it can admit devices. First `{invite, expires}`: the invitation's text. Then, for each device that used it and proved it knows the secret, `{joining: {id, name, os, fingerprint}}` (`joining`, a device to confirm), which the client answers with `{"op": "answer", consent}` (`true` admits it); last `{name}` or an error. Hanging up cancels the invitation |
| `mute` | computer | `{device, for_ms?}`: `device` a name or device ID; `for_ms` from 1 to 2 592 000 000 (30 days), absent for until `unmute` | `{status}` or an error. On an admin that is not frozen, mutes that device: sends it a `mute` command (protocol.md section 15), or mutes this device at once when it names this one (design.md, "Muting a device"). The mute lasts across restarts, in `mute.json`. Only on the admin socket |
| `unmute` | computer | `{device}` | `{status}` or an error: on an admin that is not frozen, sends that device an `unmute` command, or ends this device's own mute at once. So a muted device that is no admin waits for an admin, and a muted admin or root ends its own mute. Only on the admin socket |
| `paste_on` | computer | `{device, method?, enter?, kind?}` + payload = the text | `{}` once that device answered `done` to the `paste` command this admin signed (protocol.md section 15), or an error with its reason. The text is cleaned first (design.md, "Remote paste"). `kind` `media`, without a payload, pastes the group's current copy, which must be images or files that this device reads (`cbb paste -on DEVICE FILE...` copies the files first). Only on the admin socket |
| `paste_receive` | computer | `{name, enter?, console?, device?, all?}`: `name` `on` or `off`; `no_lock_check` lets a target paste where nothing tells whether the session is locked, which it refuses otherwise | `{status}`: `on` saves the switches of remote paste here, only for this device; `off` turns it off here, or with `device` or `all` on another or every device through `paste-off` commands. Only on the admin socket |
| `keyboard` | computer | `{name?, keyboard?}` (`keyboard` = `{layout?, rate?, pastes?}`) + payload for `type`: `name` `on`, `off`, `pair`, `type` or none | `{status}`: `on` saves the Bluetooth keyboard's settings and registers it with BlueZ (Linux only), `off` takes it off, `pair` makes it discoverable for two minutes, `type` types the payload on the connected device and answers once it is typed, none only answers the status. Only on the admin socket |
| `remote` | computer | `{name?, address?, value?, new_name?, consent?, code?, device?}` + payload for `type`: `new_name` the TV's name here; `name` `add`, `code`, `cancel`, `remove`, `pastes`, `type` or none | `{status}`: `add` pairs with the TV at `address` (an Android TV or a Google TV shows a code; a Roku, `value` `roku`, needs `consent`, as its control is plain HTTP), `code` finishes that pairing within two minutes, `cancel` ends it, `remove` forgets the TV `device`, `pastes` sends the group's remote pastes to it or not, `type` types the payload into the field open on the TV, none only answers the status; `status.tvs` = `[{name?, kind, host, pastes?, pairing?}]`. An address outside the home network fails. Only on the admin socket |
| `rename` | computer | `device` (by name or device ID), `name`: its new name | `{name}`, the old name: an admin signs a `device` record like the device's newest one with the new name (protocol.md section 10). Only on the admin socket |
| `network` | computer | none | `{status}`: the networks this device is on now become known ones, where it publishes itself and takes connections (`cbb network`). Only on the admin socket |
| `answer` | computer | `{consent?}` | none: during a request that asks the user, such as a listening `join` waiting for a phone or an `invite` asking whether to admit a device, the client's answer; `consent` is yes |
| `action_set` | computer | `actions`: exactly one quick action, `{name, on?, by?, any_key?, command?}`: on or off, the admins it lets run it (by key), any admin, and for an action of the user's own its program and arguments | `{status}`: this device's user turns the quick action on or off and says who may run it (protocol.md section 15); an action of the user's own carries its `command`. Only on the admin socket |
| `action_remove` | computer | `{name}` | `{status}`: the user's own action `name` is removed; a preset cannot be, only turned off. Only on the admin socket |
| `action_on` | computer | `{name, device}` | `{}` once the member `device` answered the `action` command this admin signed (protocol.md section 15), or an error with its reason. Only on an admin's admin socket |
| `actions_off` | computer | `{device}` or `{all}` | `{status}`: every quick action is turned off on that device, or on every device of the group, through signed commands; this device's own at once. Only on an admin's admin socket |
| `release` | computer | payload = the release in JSON, `{keys, channel, release}`, the three files of protocol.md section 16 that `cbb update` fetched | `{}`: the service checks the release as a `release` message (protocol.md section 16, "In the group"), keeps it when it is newer than the one it holds, and passes it on to its peers |
| `release_file` | computer | `{value, part}`: the archive's SHA-256 and its `size`, then its bytes in `data` messages | `{}`: `cbb update` hands the service an archive of the release it holds (protocol.md section 16), which keeps it only whole and matching its hash, to pass on to its peers. Only on the admin socket |
| `keys` | computer | `{name, value, keys}`: `paste` or `enter`, a user ID, and the grant of an `inject` | `{}` when the service handed that inject to a `desktop` watcher of that user and it is not answered yet, and `name` is its paste keys the first time or, after them, its Enter the first time when the command set `enter`; otherwise an error. Only from root (the uinput helper), on the control socket |
| `release_held` | computer | none | payload = the release this device holds in JSON, `{keys, channel, release}`, or an error when it holds none: `cbb update` takes it when no update server answers, and checks it as it checks what it downloads (protocol.md section 16) |
| `entries` | computer | payload = the signed entry points in JSON, `{keys, entries}` (protocol.md section 16, "Entry points"), from `cbb update` or `cbb global entries import` | `{}`: the service checks them, keeps them when they are newer than those it holds, and passes them on to its peers; an error when they do not check out |
| `entries_get` | computer | none | payload = the signed entry points this device holds, in the same JSON, or an error when it holds none or they have expired: `cbb global entries` shows them and `export` gives them as a string |
| `release_want` | computer | none | payload = the names of the held release's archives that the members' hellos name and this device does not hold whole, a JSON array, at most 16; `null` on a device that is no hub: its `cbb update` downloads them for the group (protocol.md section 16). Only on the admin socket |
| `update_way` | computer | none | payload = the VLESS settings (protocol.md section 11) of the hub this device reaches away from home, with the group's VLESS user ID, or none without VLESS: `cbb update` reaches the mirror through them (protocol.md section 16). Only on the admin socket |
| `release_get` | computer | `{value}`: an archive's SHA-256 | `{part}`, its bytes in `data` answers, then `{}`: the archive of the held release, from this device or fetched from its peers |
| `watch` | computer | `kind`, `via`, `inject` (the remote paste target the watcher offers: `desktop`, `tmux` or `console`), `paste_only` (it holds no clipboard and only pastes, like the Mac app), `act` (it runs the quick actions in its session), `images`, `files`, `html` (it writes copies with images, files, formatted text) + payload = what the clipboard holds now (may be empty) | an answer `{"ok":{}}` without `done`; then the watcher protocol (protocol.md, section 8) |
| `away` | computer | `{name: "on", consent}`, `{name: "off"}`, `{name: "off", device}`, `{name: "hub", addrs, port, forwarder, forwarder_key, obfuscate?, vless?, keep?, consent?}`, `{name: "hub", device, forwarder?, forwarder_key?, addrs?, forward_only?}`, `{name: "hub-off", device?, force?}`, `{name: "move", device, forwarder?, forwarder_key?, addrs?}` or `{name: "relay", relay, relay_key, consent}` | `{status}` or an error. `on` makes the tunnel key and needs `consent` on a device whose keys sit in files (every computer whose keys are not in a TPM); `off` deletes `tunnel.json`, and with `device`, on an admin, sends that device an `away-off` command (protocol.md section 15); `hub` makes this device the group's hub, reached at `addrs` (`ip:port`) on UDP `port`, and through the forwarder at `forwarder` (`ip:port`) whose key `forwarder_key` pins (protocol.md section 13); at most 8 addresses with the forwarder's, and at least one of them; with `device`, on an admin, `hub` sends that member, an admin computer, a signed `hub` command that makes it a hub of the group as well (protocol.md section 11, "Several hubs"); with `forward_only` `true` the member may be any computer that is not an admin, and an admin with `hub` first signs it a device record with `forward_only` (protocol.md section 11, "Two kinds of hub"); reached at `addrs` and through `forwarder`, one of them at least; `relay` makes this device meet the others at the blind relay at `relay` (`ip:port`) whose key `relay_key` pins (`default` for the project's relay, protocol.md section 14), in place of a hub or its offer (protocol.md section 14), and needs `consent`, since the relay learns which devices talk; `move`, on the hub, an admin, makes the member `device` the hub in its place with a signed `hub` command (protocol.md section 15), reached at `addrs` and through `forwarder`, or through this hub's forwarder when none are given; `obfuscate` and `vless` with `hub` are the settings of protocol.md section 11, and `keep` on a hub keeps its addresses, port and forwarder where the message gives none; `consent` with `hub` turns sync away from home on first where it is off; `hub-off` makes this device, a hub, stop being one, or with `device`, on an admin, sends that hub a `hub` command with a stop order, and refuses while the group has no other hub unless `force` (protocol.md section 11, "Stopping a hub"). Members connect again afterwards, so their hellos carry the change (protocol.md section 11) |
| `remove` | computer | `device`: a device ID, or a name (case-insensitive) | `{name}`, the device's name, or an error. Only on the root or an admin whose powers allow it (`remove`, and `remove-admins` for an admin; protocol.md section 10, "Who signs what"); a device cannot remove itself; the root is never removed, only replaced by a claim (`take_over`) |
| `make_admin` | computer | `device`: a device ID, or a name (case-insensitive); `allow_file_key`: the user agreed to the warning about an admin key in a file | `{name}`, the device's name, or an error. Only on the root computer: makes the connected member with `admin` an admin (protocol.md section 10, "Admins") |
| `take_over` | computer | `device`: the lost root, a device ID or a name (case-insensitive) | `{name}`, the device's name, or an error. Only on an admin computer of a group whose root is a computer: signs a `claim` against the root that name names, which takes effect when the root's takeover delay has passed on each member, unless the root cancels it (protocol.md section 10, "Handing the group over") |
| `takeover_delay` | computer | `{value}`: a duration from `0s` to `168h` | `{}` or an error. Only on the group's root: signs a `settings` record with `takeover_delay_ms`, how long a claim waits on each member, and the `key_level` its newest one had |
| `key_level` | computer | `{value}`: `proven`, `hardware` or `files` | `{below}` or an error. Only on the group's root, and never a level its own key does not pass: signs a `settings` record with `key_level` and the `takeover_delay_ms` its newest one had; `below` names the admins and hubs whose keys the new level would not let in, which stay until removed. `cbb new` signs `files` itself when the root's keys are in a file, as a computer's CA keys are (protocol.md section 17) |
| `incoming` | computer | `{value}`: a duration from `5s` to `1h` | `{}` or an error. On the group's root or any admin: signs a `copies` record with `incoming_ms`, how long a copy from another device stays live on each member (protocol.md section 10, "The copies setting") |
| `hubs` | computer | `{hubs}`: 1 to 16 names or device IDs of computers and phones, in the order they serve | `{}` or an error. On the group's root or an admin with `hub`: signs a `hubs` record, the group's main hubs |
| `freeze` | computer | `device`: a device ID, or a name (case-insensitive) | `{name}`, the device's name, or an error. Only on an admin that is not frozen: freezes another admin without `remove-admins`, never the root or an admin phone (protocol.md section 10, "Removals and freezes keep what the author saw") |
| `thaw` | computer | `device` | `{name}`, the device's name, or an error. Only on the root computer (a computer's admin has no `thaw`): ends every freeze of that admin (protocol.md section 10, "Removals and freezes keep what the author saw") |
| `resolve` | computer | none | `{name}`: on the root, voids both histories of every key that signed two; `name` lists whose. Only on the admin socket |
| `recover` | computer | payload = the recovery sheet's text or QR code, or `name` `yubikey` and the YubiKey's PIN as the payload | `{}`: claims the group with its recovery key (protocol.md, section 10, "The recovery key"). Only on the admin socket |
| `hand_over` | computer | `device`: the admin, a device ID or a name (case-insensitive) | `{name}`: on the root, a `handover` record naming that admin's key, whose claim then takes effect at once (protocol.md section 10, "Handing the group over"). Only on the admin socket |

A phone's node passes on a command for another device when it is connected to it, as
protocol.md section 15 says: once until it expires, never one that has expired or claims to live
longer than a command may. For itself it carries out the `mute` and `unmute` commands an
admin sends, keeps both in `mute.json` as the lite member does, and tells the app (the `mute`
event); every other command for the phone goes to the app as a `command` event, as the lite
member refuses it. A phone takes tunnel offers and hub shares only from a device the records
let be a hub, by the chain it proved. It keeps the sealed blobsof the copies with images or files it made or fetched in `content/` of its data directory,
the last eight, and serves them (its hello says `media`). `TestFFIJoiner` runs the join, sync
both ways, a pause, an admin's mute and a renewal against a Go member through the example `phone-on-linux`,
`TestFFIPhoneAway` sync away from home through a Go hub's tunnel, the phone's node running the
lite member's (`member/src/away.rs`: it keeps the hubs' offers and, while no hub is at home,
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
the member adds to its records and sends to the group, or a mute, an unmute or a turn of the
device's sync (`sync_on`, `sync_off`: a `mode` command, shared or own), a command sealed
to the device's key when its record names one, which the member sends and whose result it
answers. As the root it makes a connected computer an admin (`make_admin`: an admin CA for the
admin key its hello offers, its device record again, and the admin message), and as any admin it
renews (`renew`) every member certificate that is due, each connected member's, sent to it, and the
phone's own, as the phone kits do when a peer connects; as the current root, also each connected
admin's CA from an earlier root, as after a takeover. It takes the group over as the computers'
service does (`cbb_core::takeover`): `root_ca` makes a root CA for a new key of the phone (on
Aurora its admin key), which the app keeps before the claim; `take_over` (from the lost root
`device`), `take_handed_over` (the root handed the group to this admin) or `recover` (signed with
the recovery key under its admin CA) signs the claim to it, which the member adds and sends; and
`finish_takeover`, called again while the claim waits, answers `{"state","left_ms"}` (`none`,
`pending`, `cancelled`, `void`, `competing` or `disputed`) and signs nothing until the claim took
effect, then signs with the new root the phone's member certificate from it and the records a new
root starts with (its own device holding the root, the admins it keeps, a removal of a lost root's
device, the old root's settings), answers `{"state":"effective","cert"}`, and the identity event
gives the app the new certificate. `TestFFIPhoneRoot` renames and removes a computer through it,
and `TestFFIPhoneTakeover` takes a computer's group over.

Built with the feature `tunnel` (the iPhone and Android libraries), the library is also the
phones' tunnel (`ffi/src/tunnel.rs`, whose comment lists the requests): `cbb_tunnel` takes
a JSON request by its `op` for the tunnel to the hub (a loopback port that leads to the hub's
member port, with AmneziaWG and VLESS with XHTTP), for the phone as the group's hub (its
clients, its remote invitations with a guest tunnel to the pairing window), and their status;
`cbb_tunnel_register` registers the phone's hub with the group's forwarder (inside VLESS with
XHTTP when the forwarder's TCP port does not answer, as the Go hub does) and
`cbb_tunnel_relay` links the phone to the blind relay, both signing their TLS with the member
key through the same callback, the relay's link telling the app through an events' callback
which connections it joined; `cbb_tunnel_relay_credentials` makes the link register with the
group's server credentials (docs/protocol.md, section 18), signed with the period's server key
through another callback. `TestRustPhoneTunnel`, `TestRustPhoneHub`, `TestRustPhoneHubInvite`,
`TestRustPhoneHubForwarder`, `TestRustPhoneHubOverXHTTP`, `TestRustPhoneRelay` and
`TestRustPhoneRelayCredentials` run them
against Go's hub, clients, forwarder and relay through the example `tunnel-on-linux`.

Go reaches them in `internal/core`: through cgo under the build tag `cbbcore`, linking
`libcbb_ffi`, or through the same core built as WebAssembly (`wasm/`, `cbb_call` and its
memory functions), run by wazero under the tag `cbbwasm`. Every release build of `cbb`, on
every system and architecture, takes `cbbwasm`, so it stays one static binary without cgo
(the release workflow checks the tag with `go version -m`), and `cbb version` names the
rules it runs; a build without either tag, as `go build` and `go test` are, evaluates with
Go's own `internal/authority`, which only the tests use as a reference.
`wasm/build.sh` builds the module and writes the `go build -overlay` file that lays it
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
| `arrange` | `group`, `self`, `devices` (the app's order), `stored` (as kept, or null), `prune`, `op` (optional: `{"op":"move","item","before"}`, `into`, `out`, `new`, `rename`, `ungroup` or `reset`, as `testdata/arrangement/vectors.json` names them) | `{"stored","view"}`: the arrangement of the device tiles (`cbb_core::arrange`, docs/apps.md "Collections and the order of the tiles") to keep in the app's settings, and the items to show after this device; a change that does not fit is refused whole |
| `keyboard` | `layout` (`us` or `ru`, the host's), `text` | `{"reports", "untypeable", "map"}`: the HID boot keyboard's reports that type `text` (each 8 bytes, base64; a key down, then all keys up), the characters the layout has no key for (no reports then), and the report map (base64), for a phone that is a Bluetooth LE keyboard (`cbb_core::keyboard`); an unknown layout is code 1 |
| `seal_public` | `secret` (base64, 32 random bytes the device keeps) | `{"key"}`: its public key for sealed messages (base64, 1216 bytes), the `seal` its pairing and device record carry |
| `seal_command` | `body` (base64, a command in the open), `key` (base64, the receiver's `seal` key) | `{"body"}`: the same command with its orders sealed to the key (`v` `2`, `sealed`), canonical, for the sender to sign; see "Signed bodies" |
| `group_body` | the set's arguments, `body` (a record body as `canonical_body` takes it, with `signer` set) | `{"body"}`: the canonical bytes of the signer's next record, to sign: the group, seq and prev set from the set, and for a removal, a freeze or a claim `seen` from the set, the signer's own previous seq among them |
| `bug_report` | `input` (`{kind, code, name, message, details, app, version, build, os, os_version, model, arch, log, names, now_ms}`: `kind` `panic` or `error`, `app` `ios`, `android`, `aurora`, `mac`, `tray` or `cbb`, `log` CBB's own log, oldest first, `names` the words that must not leave the device), `state` (as the last bug call gave it, optional) | `{"report", "fingerprint", "post", "url", "action", "offer_always", "fixed_in"}`: the report, filtered, as "Technical details" shows it, the break's fingerprint, the body to post to `url` (empty when this build has no key to seal to), what the app does (`ask`, `send` or `skip`), whether the dialog offers "Always allow", and the version the server said fixes this break; see "Bug reports" |
| `bug_allow` | `state`, `always` | `{"state"}`: the user allowed a report, and maybe always |
| `bug_sent` | `state`, `fingerprint`, `version`, `post`, `ok`, `fixed_in` (what the server answered, optional), `now_ms` | `{"state"}`: the report went (`ok`), or it waits to be sent again |
| `bug_pending` | `state`, `now_ms` | `{"queue", "state"}`: the reports waiting (`[{fingerprint, version, post, at_ms}]`), without those older than seven days |

The arguments of `evaluate` are a case of `testdata/interop/v2-records.json` as it is.

`cbb version` names the core it was built with in a second line,
`rules: the Rust core 0.6.0, abi 1, source <commit> (built in)`; the release builds pass the
tag's commit in `CBB_SOURCE`, and other builds say `source unknown`.

## Error codes

The numbers and names never change meaning; new codes are added at the end of their range.

| Code | Name | Meaning |
|---|---|---|
| 1 | `request` | the request is not a JSON object of the right shape, or an argument is missing or of the wrong type |
| 2 | `abi` | the request's `abi` is not the core's |
| 3 | `op` | the core has no such operation |
| 4 | `too_large` | the request is larger than 8 MiB |
| 5 | `panic` | something in CBB broke while it answered, and the request did nothing; `details` says what broke and where (see "Panics") |
| 10 | `body` | a record body is refused: its size, form or a field |
| 11 | `cert` | a certificate is refused |
| 12 | `strict` | a signed body is not in the strict canonical form |
| 13 | `rollback` | the record set is older than the saved one: a signer's whole chain ends below the seq saved |
| 14 | `saved` | the saved state cannot be read, is of another version or group, or its check with the secret does not match |
| 15 | `command` | a command is refused: its signer, its target, its time or its limits |
| 16 | `signed` | a signed body that is not a record (a command, a server credential, a release file or a manifest) is refused: its size, form or a field |
| 17 | `copy` | a copy is refused or cannot be sealed: its origin, its signature or a field, or it does not open with the device's key |

## Panics

The core does not panic on any input, and its tests and fuzzers keep it so; but a bug in CBB
may still break a call. `ffi/` stops every panic at its C functions: the apps' library is
built with unwinding (`ffi/bind.sh` and the Android kit set `CARGO_PROFILE_RELEASE_PANIC=unwind`),
so a call that panics answers code 5 `panic`, whose `details` read `panic: <message> at
<file>:<line>:<column> in thread <name>`, and a function that can only answer null leaves the
same answer for `cbb_last_panic`. A panic in one of the member's own threads becomes the event
`{"type": "panic", "details"}`: the app shows it as an error and starts the member again.
`cbb_test_panic` panics inside the guard, for each wrapper's test that the answer is code 5 and
that the app goes on. The computers' `cbb` is built with `panic = "abort"`: the process ends,
and the system's service manager starts it again.

## Bug reports

When something breaks (code 5, or an error the app did not expect), the app may send a short
report to `https://bug.cbb.tools/` (`cbb_core::bug`). In debug mode the app shows the whole
error and logs it, and asks nothing. In release mode it asks: "Oops, something broke. Sorry!
Allow us to send a short report", with Allow and Cancel and a small link, "Technical details",
which shows the report as it would go. After the user allowed twice, the dialog also offers
"Always allow" (off until ticked); then reports go without asking.

`bug_report` builds the report from what the app gives: what broke, the versions of CBB and the
system, the device's model and architecture, the day, and CBB's own log, at most 300 lines of
400 bytes, the oldest going first until the report fits in 160 KiB. Every field and line is
filtered: addresses (IPv4, IPv6, MAC), e-mail addresses, long numbers (codes), long hex
(device ids, fingerprints), base64 that looks random (keys, secrets, invitations), the user's
name in home folders and every word of `names` are replaced. Clipboard texts never reach the
log. The report is sealed to the robot's public key (`crate::seal`, HPKE with X-Wing,
HKDF-SHA256 and ChaCha20-Poly1305, associated data `cbb bug report v1`), so the server stores
what it cannot read; the robot opens it elsewhere. Until the robot's key is in the build,
nothing is posted and `action` is `skip`.

The body posted is `{"v": 1, "fingerprint", "version", "sealed"}`, at most `MAX_POST` bytes; the
server takes up to twice that. It answers `{"fixed_in"}` when a version fixes the break. The
fingerprint hashes the kind, the error's name, where it broke and the first line of its details
without numbers, so the same break counts once in every version and on every device: the app
sends one report for each fingerprint and version, and `fixed_in` lets the dialog say that an
update fixes it. A report that could not be sent waits, at most five for seven days
(`bug_pending`). The app keeps the `state` the calls give back in its own settings.

On a computer the service is built with `panic = "abort"`. Its panic hook writes what broke and
the service's recent log lines to `panic.json` in the state folder, the system starts the
service again, and its status then says `bug`: the Mac and tray apps ask the user with `bug`,
`bug_allow` and `bug_cancel`, and the service posts the report with curl. With "Always allow"
it goes at the start without asking.

On cbb.tools, nginx (`packaging/linux/nginx-bug.conf`, a server block of its own that logs no
client address) passes each POST to `cbb-bug` (`member/src/bugd.rs`, `cbb-bug.service`) on a
loopback port. It checks that the body is a sealed report, keeps it in a folder of the day and
the break, and answers `fixed_in` from the robot's `fixed.json`. At most 20 reports of one break
and version and 5000 in all are kept each day; the rest are answered as taken and dropped, so
that no app sends them again. The robot opens the reports elsewhere with its secret.

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
| `devices` | `[{device, name, role, caps, os, key, store, kind, proof, seal, admin, admin_key, powers, commands, frozen, freezes, keys}]`: the devices list the apps show; `key`, `keys` and `seal` (the key commands for it are sealed to, when its record has one) base64; `freezes`, for a frozen admin, the IDs of the freezes a thaw names |
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
