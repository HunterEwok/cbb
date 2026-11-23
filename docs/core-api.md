<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The core's entry point

For engineers and anyone binding the Rust core into another program: the one call through
which every program uses the core's rules (`cbb_core::api`, `core/src/api.rs`). Every
program reaches it through the same C functions of `ffi/`, which the phone kits link; the Go
programs do not link it. The rules themselves are in [protocol.md](protocol.md) and the bytes in
[format.md](format.md).

## Requests and answers

A request is a JSON object in UTF-8, at most 8 MiB:

```json
{"abi": 1, "op": "version"}
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
`libcbb_ffi` through JNA (`Core.kt`); both check the ABI before each call.

### The member

Built with the feature `member` too (every library `bind.sh` builds: the iPhone, Android,
HarmonyOS and Aurora apps run it), the library runs `cbb`'s own member in the app's process
once the phone is in a group (`ffi/src/member.rs` and `ffi/src/member/live.rs`, over
`cbb_member::live`). Groups are 0.6 only (D-126): `cbb_member_start` runs the member when the
app's data directory holds the group's `group.cbor`, and answers an error with the message
`this group was made before 0.6, which this version no longer runs: make a new group` for a
folder without one, a group made before 0.6, which the apps show as such, offering to leave it
or make a new group; the folder stays as it is until the person leaves.

`cbb_member_call` asks it everything else, a request `{"op", "args"}` and its answer `{"ok"}`
or `{"error"}` as `cbb_call`'s. `fetch` and `wait` wait for the network, so the app
calls them off its main thread. A copy is `{id, origin, age_ms, kind, text, media, key}`:
`media` is the manifest of images or files, and `key` the copy's ID, which the button compares
it by.

`cbb_member_start` takes the member key's signing callback, as the join does, and a callback
that gets each event as JSON from the member's threads, and its request needs `dir`, `name`,
`os`, `os_version`, `version`, `device`, `public`, `peers` and `mdns`, the records naming the
group's devices and keys; `device` must be the one the member key makes. `cbb_member_stop`
stops it. Its events are `write`, `copy` (`{id, origin,
age_ms, kind, text, media, key}`, the key the copy's ID), `mute` and `sync` (`{off, by}`: an admin
turned the phone's sync off or on), `state` (`{state}`, the group as `group` answers it, at
each change of the records), `notice` (`{notice}`, one that was not there before, as `notices`
lists it), `root_changed` (`{from, to, seq}`: the group's root changed by its recovery key,
from the old root's device to the new one's, `seq` the number of roots the group has had;
sent again each time the member starts until the app answers `root_change_seen`, kept in
`root_seen.json`; a phone that joins sees no change), `log` and `panic`. It carries out by itself the commands
an admin sends the phone that the records let through (`cbb_member::orders`, as the service's
`live_command`): `mute`, `unmute` and the sync mode, kept in `mute.json` and `sync.json` and
sent out in its next hello; it answers the paste, action and away switches with nothing to
do, and refuses an action, a hub change, a device change and, until the apps take it, a paste.
Its operations are `copy`, `copy_media` (images or files, sealed and kept to serve, as the
service's), `fetch` (a copy's images or files, fetched from the member it came from and opened
into `out`), `current`, `swap`, `opened` and `took` (the button's rule, `cbb_member::button`, D-128), `found`, `lost`, `listen` and `unlisten` for the home port, `pause`,
`resume`, `wait`, `set_mute`, `sync`, `muted`, `peers`, `devices`, `why` and `group`, the state the apps show
(`{group, root, root_device, me{device, role, admin, frozen, leaf}, stop, halted,
update_needed, too_old, change_arriving, key_level, ttl_ms, secret_ttl_ms, devices[{device, name,
os, role, admin, frozen, hub, offers_admin}]}`: `key_level` is `proven`, `hardware` or `files`, `ttl_ms` and
`secret_ttl_ms` how long a copy and a secret live in the group as the `copies` record that counts
sets them (null for the defaults, 300 000 and 60 000; D-129), `admin` is whether the admin key the records name for the device is one of the
group's admins, `offers_admin` whether the device offered this phone an admin key when it paired
and is no admin yet, so that the root's "Make it an admin" shows, and removed devices are not listed); `cbb_member_manage` takes `remove`,
`rename`, `freeze`, `thaw` and `ttl` (`ttl_ms` and `secret_ttl_ms`, either left out to keep the
group's, a `copies` record), written with the
key `public` names, which the records judge,
`mute` (`for_ms`), `unmute`, `sync_off`, `sync_on`, `paste` (`text`, `method`, `enter`,
`kind`), `paste_off`, `actions_off` and `away_off`, commands for another device signed with that
key and sent over the phone's connection to it, as the service sends them (the answer is that
device's: `{status, reason}`), and on the root `key_level` (`level`; `{below}`) and
`make_admin` (`device`, `allow_file_key`, with the admin key the device offered when it joined
by this phone's window), both by the core's key level rule (`cbb_core::keylevel`).
For push (protocol.md, section 20.4) the member keeps the signed release and entry points in
the app's folder and passes them on, as a computer does, and takes `push_face` (`{face}`: the
group's face toward the push service that the newest `keys.json` names, base64, 16 bytes, null
until one does), `push` (`frame`: message `push` as `push_registration` made it, checked and
sent to every member connected now and to each one that connects later; no `frame` stops
sending one) and `push_renewals` (`{renewals: [{slot, ahead}]}`: the `push-renew` messages
members sent since the last call, one per slot, which the app answers with a new registration).
The root also names its `hubs` (1 to 16 devices, by name or device ID), which the records
judge: a phone is a hub only with an admin key; and the group's `relay` (`relays`, each
`address pin`, or `default` alone for the project's relay; none meets at no relay; `{relays}`:
their addresses), written in the group's settings, where every device of the group meets the
others while sync away from home is on (protocol.md section 14). The root names the
`forwarder` of a device that may be a hub (`device`, `forwarder` `host:port` or `default`,
`key` its pin; the device's `{status, reason}`) with a `hub` command whose field 11 lists it,
and makes the group's credentials for that forwarder, as `cbb global hub -on` does; a phone
takes the root's `hub` command only as that setting: it keeps the forwarder in
`root_forwarder.json` and serves through it again while it is a hub, never turns its hub on
or off by the command, and refuses one from another key or one to stop. A root phone keeps the
period keys of the group's server credentials, which sign the hubs' and the members'
credentials, but its root key stays with the app: `period` hands it over to sign the periods
that are due (protocol.md section 18; `{period_due, period_overdue}` after), and `relay`,
`forwarder` and `hubs` signed with the root key renew a due period with it too; the away ops
answer `period_due` and `period_overdue` (expired, so the group's relay and its hubs'
forwarders take nobody), both false on a phone that is not the root. A root phone checks its
peers' Android attestations in the core (`attest_status` takes the revocation list the app
fetched, `attest` answers how many wait, and manage's `attest` records them with the root key;
protocol.md section 17). Every phone hands its member the attestation of its own member key
that its app made (`evidence`, `{evidence}` as the helper's JSON gives a computer's TPM
evidence; an empty list sends none), which the member sends in `evidence` messages (t 19) to
each peer connected now and to each one that connects later. A root phone adds a watch with manage's `add_watch` (`key`, the watch's admin
key as a SubjectPublicKeyInfo; `name`, `os`), whose member key nobody keeps (D-124),
answered `{device, name}`; a watch signs nothing in 0.6, so `watch_actions` answers none and
`cbb_member_manage_watch` refuses, saying its actions come with 0.7. A phone in the group
changes the group's root to itself with the recovery key (D-117, D-125): `recovery` is the
sheet's `{qr}` or `{text}`, or `{secret}`, the 32 bytes in base64 that `cbb_piv`'s `open` gave
from a YubiKey, checked against the group's recovery key; `change_preview` (`recovery`,
`leave_out`: names or device IDs) answers `{rows: [{device, name, os, outcome}], waiting}`
without signing, each other device's outcome `stays`, `out`, `admin_kept`, `admin_lost`,
`frozen` or `removed_earlier`, and `change_root` (the same, and `drop_hubs`, `over_waiting`)
signs the new start with the app's new root key and answers `{seq}`, as `cbb recovery` does on
a computer (`writers::recover`); `take_over`, `take_handed_over`, `recover`, `hand_over`,
`takeover_delay` and `finish_takeover` answer that the root changes only with the recovery key.
`TestFFIPhoneChangeRoot` changes a computer's group's root from a phone. Everything else answers that it does not work in this build yet, with the cause
`not on the records of 0.6 yet` in its details, until its part moves over. A copy with
images or files comes as a `write` of kind `media` and a `copy` event with its manifest
(`media`), which the app fetches.

A phone of 0.6 lets a device join at home through a home window, `cbb_window_new`
(`ffi/src/window.rs`), while its member port listens: the request names the admitting key (the
phone's admin key or the root's, signing through the callback until `cbb_window_free`), the
phone's home addresses, how long the window stays open (five minutes by default, an hour at
most) and whether the core announces it by mDNS (`mdns`, on Aurora; the iPhone and Android
announce it with the system's DNS-SD, `p=1`, `f` and `i` from the answer). It answers the QR
code `cbb://pair?addr=…&fp=…&i=…&c=…` (the addresses with the member port, the hash of the
phone's member key, the window's ID and its six digits) and its modules, the six `digits` to
show beside it for a device that types them, the window's `id` and the key's `fingerprint`.
The new device dials; its TLS session of `cbb-pair/3` reaches the window through the member
port and proves the digits (protocol.md, "Pairing in 0.6"): nobody is asked whether anything
matches. `cbb_window_next` waits for the next state: `open`, `joining` while a device pairs,
`done` with the device that joined (the window is then closed), `failed` with the error of that
attempt (the window stays open for another), `closed` when its time is up or after three wrong
codes (with the error). The phone writes the device's record by the core's admission rules
(`join::decide::joiner_record`: at home a member or a phone reads, sends and takes secrets, a
member that can be a hub may be one when the root admits it, a watch only reads) and sends the
Welcome (`ffi/src/pair06.rs`). A phone that holds the group's root key keeps the admin key a
device offered with its proof over the session (`cbb_member::offered`), as a computer's root
does. One attempt at a time; another
gets `busy`.

The new phone joins with `cbb_joiner_new` (`ffi/src/joiner.rs`): the request names the app's
folder, the scanned QR code, or the six digits the person typed (`digits`, with an empty `qr`:
on a phone without a camera, or when the scan failed; the core then finds the one window
announced by mDNS, and refuses when there is more than one), what the phone says of itself and
its member key. It dials the window's addresses in turn over TLS of `cbb-pair/3`, takes only
the member whose key the window names, proves the digits, and `cbb_joiner_next` gives its
state: `dialing`, `done` with the group, the phone's device ID and the name of the member that
let it in once the checked set is kept in the folder (the app then starts its member there), or
`failed` (a wrong code says so). A phone that holds a group already is refused.
`cbb_joiner_new_admin` also offers the phone's admin key (`admin_public`, its own signing
callback) with its signature over the session's exporter (`join::sign_admin_pop`), as a
computer that may be an admin does: the group's root keeps it, and makes the phone an admin with
it later (`cbb admin`, "Make it an admin").
With `invite`, a remote invitation's text of 0.6 (`cbb://join#`, in the build with the
tunnel), the phone joins from afar instead (docs/protocol.md, section 12): a text that is no
invitation is refused at once; the joiner starts the invitation's guest tunnel to the hub
(`cbb_member::live::invite::guest_link`), its first state carries the `fingerprint` the phone
shows for the inviting admin to compare, and it dials the hub's guest address through the
tunnel, the pairing's steps waiting as long as the admin may take to confirm. Its states also
say `answered` once the hub answered through the tunnel, for the app to tell a hub that never
answered from an attempt that failed. The invitation and the group's tunnel state are kept with
the set (`invite-guest`), so that the member, once started, reaches the hub through the guest
tunnel until the hub's offer comes.

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
| `copy_media` | both | on a phone: `text` (optional), `parts`: `[{type, path, dir, data, file}]`, clipboard data with its bytes in `data` (base64) or a file or folder with the file on the phone in `file`; `board` (optional, `false` by default). On a computer the parts stream instead: the payload is the plain-text alternative, or none; then for each part `{"op":"part", part}` (`part` = `{type?, path?, dir?, size?}`), followed for a file or clipboard data by `{"op":"data"}` messages whose payloads, at most 1 MiB each, are exactly its `size` bytes; last `{"op":"part", done}` | a phone answers `{"copy"}`, a computer `{}`: the parts are in the cache and the copy went to the group as a `media` event ([format](format.md), section 10.3), also written to the member's own clipboard. An error when the copy is over this device's limit, its manifest is not valid or the bytes do not come as said. `cbb copy FILE...` reads the files as the user and sends them |
| `sync` | both | `on` (required), `for_ms` (only with `on: false`, from 1 to 2 592 000 000, 30 days; 0 or absent for until it is turned on), `device` (on a computer, an admin, on the admin socket: another device by name or device ID, with no `for_ms`; a phone turns another device's sync with `cbb_member_manage`) | `{"sync_off", "sync_off_ms", "muted", "muted_ms"}`, as `muted` gives it: turns the device's sync on or off, saved in `sync.json` and in effect (design.md, "Sync on and off"); the members see it at the next connection. With `device`: `{}` once that device answered `done` to the `mode` command (protocol.md, section 15), or an error with its reason. Without `device` on either socket, so that the apps switch it without the administrator |
| `muted` | both | none | `{"sync_off", "sync_off_ms", "muted", "muted_ms"}`: `sync_off` and `sync_off_ms`, `muted` and `muted_ms` say whether sync is off and an admin muted the device, and how long each lasts, 0 for until lifted |
| `bug` | computer | none | the bug report of the panic before the last restart as `bug_report` answers it (payload; empty when none waits); see "Bug reports" |
| `bug_allow` | computer | payload `{"always"}` | the user allowed the report, and maybe always: it goes, and the panic no longer waits |
| `bug_cancel` | computer | none | the user cancelled the report: nothing goes |
| `devices` | both | none | `{"devices"}`: every device of the group, `[{id, name, role, caps, os, store, skew_ms, form, os_version, version, mac, mode, muted, muted_until_ms, admin, root, frozen, online, last_seen_ms, self, listed, may_hub, forward_only, hub, hub_rank}]` (`control::Device`; empty fields left out): the group's device records, whether it is connected and whether it is this device, what a connected member's hello says (`form`, `os_version`, `version`, `mac`, `mode` `shared` or `own`, `muted` and `muted_until_ms` in Unix milliseconds, 0 for until lifted), then the connected members no record lists yet (`listed` false). `last_seen_ms` is when this member last saw the device connected. A phone fills in what its node knows: no `store`, `skew_ms`, `last_seen_ms` or hub fields. `hub` is whether the device serves as a hub as this member knows it: with sync away from home on, this device while it serves or a hub whose offer it keeps; with it off, a device the root's hubs record names. `hub_rank` is the device's place in the group's order of hubs, from 1 (protocol section 11, "Several hubs"), left out when it may not serve |
| `view` | both | `away` (optional on a phone, as `why` takes it) | `{"view": {"tiles", "online", "others", "custom", "warnings?"}}`: the device tiles to draw in the user's order and collections, each `{"device"}` (as `devices` lists it) or `{"collection": {id, name, devices}}`, this device among them, and how many other devices are online out of how many, whether the user changed the order, and `warnings`, why this device does not sync, the same reasons as `why` and status's `why`, left out when everything syncs (`member/src/view.rs`; docs/apps.md, "What the member shows" and "Why it does not sync") |
| `arrange` | both | `arrange` (`{"op": "move", "item", "before"}`, `into`, `out`, `new`, `rename`, `ungroup` or `reset`, as `testdata/arrangement/vectors.json` names them), `away` as `view` | as `view`, after the change, which the member keeps in `arrangement.json`; a change that does not fit is refused whole |
| `current` | phone | none | `{"copy"}`: the group's current copy, or null: `{id, origin, age_ms, kind, text, media, unread, key, ttl_ms}`, `media` its manifest of images or files (null for a text), which the app fetches with `fetch` whether or not the copy was written, and `ttl_ms` the lifetime its sender stamped (null when it has none) |
| `swap` | phone | `board`: the clipboard's key | `{"sends", "copy"}`: the one button (design.md, "The one button", D-128), a strict swap: `sends`, whether the clipboard goes to the group (it is not empty, not the group's copy, and not what this phone itself sent from its clipboard or took into it last), and `copy`, the group's copy that comes into the clipboard, null when the clipboard is empty of nothing new or already holds it. The app sends first, then takes |
| `opened` | phone | `board`, `changed`: whether the clipboard changed since the app last saw it (iOS's change count, elsewhere a stored hash) | `{"sends", "copy"}`: the app's opening, which swaps nothing: a changed clipboard the button would send goes to the group (`sends`, `copy` null); otherwise `copy` is the group's copy to take, as `swap` gives it |
| `took` | phone | `id` | `{}`: the app took that copy into the clipboard, or saved its files; what it wrote itself is no copy to send back |
| `fetch` | phone | `id`, `max` (bytes of the sealed blob), `out` (a new folder) | `{"parts"}`: each part with `file`, where it is, each checked against its hash |
| `found`, `lost` | phone | `key` (the app's name for the member), `addrs` (`host:port`, loopback too for the tunnel), `device` (optional) | `{}`: dial it again and again, or stop |
| `listen`, `unlisten` | phone | `port` (0 for any), `kind`: `home` (the default and the only kind: every address, for the members that dial this phone, and as the group's hub at home, which the app publishes with `r=phone`) | `{"port"}`: the member port; a port already open is closed first |
| `pause`, `resume`, `wait` | phone | `wait`: `timeout_ms` | `{}`; `wait` answers `{"connected"}`: the app in the background closes every connection and makes none; one pass of a background refresh is `resume`, `wait`, `pause` |
| `set_mute` | phone | `until_ms` (null unmutes) | `{}`: the phone's own mute, as the app keeps it |
| `peers` | phone | `all` (optional: the members offline too) | `{"peers"}`: `[{device, name, role, os, key_store, mode, muted, reach}]`, the connected members as the records and their hellos name them, `reach` the members each says it reaches |
| `evidence` | phone | `evidence`: the attestations of the phone's keys | `{}`: every peer gets them after its hello (protocol.md, section 17) |
| `why` | phone | `away` (optional: where a tunnel the app runs itself stands, `{hub, standby, hub_device, through, hidden, relay, relay_connected, forwarder, forwarder_registered, entries_stale, error}`; without it the member's own) | `{"why"}`: why the phone does not sync (`cbb_core::why`, docs/apps.md "Why it does not sync"), `[{code, level, until_ms?, device?, devices?, value?, detail?}]`, the reason that stops the most first; empty when everything syncs |
| `notices` | phone | none | `{"notices"}`: what the person should know about the group's records (docs/apps.md, "Notices"), `[{id, kind, args, dismissable}]`, `kind` one of `change_arriving`, `removals_waiting`, `root_room_waiting` (on the root phone, `args.percent` of its room taken by removals that wait, from half of it), `ack_owed` (`args.removals`, `args.days_left`), `frozen_holding` (`args.device`), `checkpoint_stuck` and `returned_after_removal` (`args.device`, the first device that counts again, and `args.devices`, how many), from the set's own notices (`RecordSet::change_arriving`, `removals_waiting`, `root_room_waiting`, `ack_owed`, `frozen_holding`, `stuck_checkpoints` and `notices`). Only `returned_after_removal`, by its record ID in base64, may be hidden |
| `root_change_seen` | phone | none | `{}`: the person saw the change of root the event `root_changed` told of; it is not told again |
| `dismiss` | phone | `id`: a notice's record ID, base64 | `{}`: the set keeps the notice dismissed (`RecordSet::dismiss`), saved with the group's records |
| `away`, `away_status` | phone | `on` for `away` | `{"away"}`: sync away from home turned on (new tunnel keys, which the hellos offer the group's hubs) or off (the keys and the hubs' offers forgotten), and where it stands, as `cbb global` shows it (`hub_device`, `endpoints`, `through`, `error`, `detail`), or null while it is off; only in a library built with the feature `tunnel`, otherwise `away` with `on` answers an error |
| `hub`, `hub_off` | phone | `forwarder` (`host:port`), `key` (its pin, `default` for the project's), `obfuscate_off`, `vless_off`, `port` (the UDP port) and `addrs` (`ip:port`, reached from afar without the forwarder) for `hub` | `{"away"}`, as `away_status` gives it, with `hub` and `forwarder` `{endpoint, registered, error, detail}`: this phone, which the records must give an admin key, is one of the group's hubs, the Live hub the computers run (`member/src/live/away.rs`), which also serves the guests of invitations, or stops being one, handing its clients to the next hub in the order (protocol.md, section 11, "Stopping a hub"); only with the feature `tunnel`. With no `forwarder` the hub serves through the one the root set, and every away op answers it beside `away` as `root_forwarder` `{endpoint, key}`, null while the root set none |
| `attest_status`, `attest` | phone | `keys` and `status` for `attest_status`: the mirror's `keys.json` and `attest-status.json` as the app fetched them | `{"pending", "revoked"?}`: `attest_status` takes the revocation list of Android attestations when it checks out against the release keys and is not older than the one kept (`attest-status.json`, protocol.md section 17, "Revoked attestations"), and answers how many certificates it revokes; `pending` is how many Android peers' evidence waits for the root key, which `cbb_member_manage`'s `attest` records (`member/src/phone_attest.rs`, the core's `cbb_core::attest`); only with the feature `tunnel` |
| `paste` | computer | none | `{kind}` + payload = the member's own clipboard text; error `the clipboard is empty` when unknown or an expired secret, and one that names `cbb paste -o` for images or files without a text |
| `copied_media` | computer | as `copy_media` | as `copy_media`, but a watcher's report that its clipboard changed: the copy goes to the group as an event when the engine decides so (protocol.md section 5) and is not written back to the member's own clipboard |
| `paste_media` | computer | `{value?}` | with `value`, the event ID of a remote paste's copy (protocol.md section 15), while it is the group's current copy and its parts are here: the same answers for that copy. Without it, once every part of the member's own images or files (with sync off the group's) is in the cache, fetched first if it is not: `{kind: "media"}` + payload = the plain-text alternative; then for each part `{part}` and its bytes in answers of at most 1 MiB; last `{}`. An error when the clipboard holds none, or they did not arrive. `cbb paste -o DIR` writes them |
| `config` | computer | `{name?, value?}`: `max-copy` or `max-copy-away` and a size such as `200MiB` | `{status}`, with the setting saved first when `name` is given; `status.media` = `{max_copy, max_copy_away, fetching?, fetched?, from?, failed?}`, in bytes, also in `status` |
| `status` | computer | none | `{status}`; `status` = `{device, group, role, os, peers: [{id, role, os, skew_ms}], unreached?, port, cert_ends_ms, ttl_ms, secret_ttl_ms, away?, version, why?}`; `why` is why this device does not sync, as the phone's `why` answers it; `cert_ends_ms` is when this device's member certificate ends, in Unix milliseconds, `unreached` lists the members at home that could not connect to this one and synced only because it dialed them back, `port` is the member port; `ttl_ms` and `secret_ttl_ms` are how long a copy and a secret live in the group (protocol.md section 10, "The copies setting"); `away`, present while sync away from home is on: `{hub, port, endpoints, clients, hub_device, through, keys_in_file, error, detail, forwarder?, relay?}` (protocol.md section 11); `forwarder`, on a hub with one: `{endpoint, registered, seen, error, detail}` (protocol.md section 13); `relay`, on a device with one: `{endpoint, connected, online, error, detail}`, where `online` lists the other devices of the group on the relay and `through` tells whether a member connection runs through it (protocol.md section 14) |
| `leave` | computer | none | `{}`: the device leaves its group (D-83): the service deletes the keys and the group's files, turns remote paste and the quick actions off, and restarts in no group. Refused on the group's root while the group has other devices; taken while the group file is damaged |
| `new` | computer | none | `{status}`: the device creates a group and is its root (protocol.md section 10). Only on a device in no group |
| `pair` | computer | none (`admins`, which `cbb pair -admin` sends, changes nothing: the root makes a phone an admin with `cbb admin`) | a home window on the member port for one device, for five minutes (protocol.md section 6, "Pairing in 0.6"): first `{code, invite, address, expires}` (the six digits, the QR code's text, the member port at the first private IPv4 address and `expires`, the seconds the window stays open), then a partial `{refused}` with why for each device that failed (a wrong code spends one of three tries; the third closes the window), then `{name: <joined device name>, done}` or an error. Only on the group's root or an admin; elsewhere the error names them. Hanging up closes the window |
| `join` | computer | `{code, address?}` or `{invite, consent}` | `{}` or an error. With `code`, the six digits of a home window: without `address` it browses for `p=1`. With `invite`, the text of a remote invitation (protocol.md section 12), it needs `consent` (sync away from home is turned on, and the device keeps its keys in files), first answers with `fingerprint` (of this device's key, for the admin to compare), then `{}` or an error. `listen`, and a `pair` with `code`, `addrs` or `fingerprint`, are refused: no device listens to join. Hanging up cancels |
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
| `confirm` | computer | `value`: the operation to confirm | `{name, value}`: on Windows, `kept` while this user's last confirmation lasts (five minutes, not for what is confirmed each time), `register` when the user has no Windows Hello key registered, else `sign` with a 32-byte challenge in base64 in `value`, good for 120 seconds, for this user and this operation; elsewhere an error (protocol.md section 8) |
| `confirm_key` | computer | `name`, `value`: a user's SID and the public key (PKCS #1 RSAPublicKey, base64) of the user's Windows Hello key | `{}`: the key that confirms this user's admin actions on Windows. Only on the admin socket |
| `release_get` | computer | `{value}`: an archive's SHA-256 | `{part}`, its bytes in `data` answers, then `{}`: the archive of the held release, from this device or fetched from its peers |
| `watch` | computer | `kind`, `via`, `inject` (the remote paste target the watcher offers: `desktop`, `tmux` or `console`), `paste_only` (it holds no clipboard and only pastes, like the Mac app), `act` (it runs the quick actions in its session), `images`, `files`, `html` (it writes copies with images, files, formatted text) + payload = what the clipboard holds now (may be empty) | an answer `{"ok":{}}` without `done`; then the watcher protocol (protocol.md, section 8) |
| `away` | computer | `{name: "on", consent}`, `{name: "off"}`, `{name: "off", device}`, `{name: "hub", addrs, port, forwarder, forwarder_key, obfuscate_off?, vless_off?, keep?, consent?}`, `{name: "hub", device, forwarder?, forwarder_key?, addrs?, forward_only?}`, `{name: "hub-off", device?, force?}`, `{name: "move", device, forwarder?, forwarder_key?, addrs?}` or `{name: "relay", relay, relay_key, relays?, consent}` | `{status}`, `{relays}` from the root of a group of 0.6, or an error. `on` makes the tunnel key and needs `consent` on a device whose keys sit in files (every computer whose keys are not in a TPM); `off` deletes `tunnel.json`, and with `device`, on an admin, sends that device an `away-off` command (protocol.md section 15); `hub` makes this device the group's hub, reached at `addrs` (`ip:port`) on UDP `port`, and through the forwarder at `forwarder` (`ip:port`) whose key `forwarder_key` pins (protocol.md section 13); at most 8 addresses with the forwarder's, and at least one of them; with `device`, on an admin, `hub` sends that member, an admin computer, a signed `hub` command that makes it a hub of the group as well (protocol.md section 11, "Several hubs"); with `forward_only` `true` the member may be any computer that is not an admin, and an admin with `hub` first signs it a device record with `forward_only` (protocol.md section 11, "Two kinds of hub"); reached at `addrs` and through `forwarder`, one of them at least; `relay` makes this device meet the others at the blind relay at `relay` (`ip:port`) whose key `relay_key` pins (`default` for the project's relay, protocol.md section 14), in place of a hub or its offer (protocol.md section 14), and needs `consent`, since the relay learns which devices talk; in a group of 0.6 the root signs the relay, with the ones `relays` adds (each `address pin`, up to 16 in all), in the group's settings and answers their addresses in `relays` (protocol.md section 14, "The project's relay"); `move`, on the hub, an admin, makes the member `device` the hub in its place with a signed `hub` command (protocol.md section 15), reached at `addrs` and through `forwarder`, or through this hub's forwarder when none are given; with `hub`, `obfuscate_off` turns off the AmneziaWG a hub speaks by default and `vless_off` the VLESS it asks a forwarder for (protocol.md section 11; `obfuscate_off` goes with `vless_off` where there is a forwarder), and `keep` on a hub keeps its addresses, port and forwarder where the message gives none; `consent` with `hub` turns sync away from home on first where it is off; `hub-off` makes this device, a hub, stop being one, or with `device`, on an admin, sends that hub a `hub` command with a stop order, and refuses while the group has no other hub unless `force` (protocol.md section 11, "Stopping a hub"). The members connected learn the change from a new hello, without connecting again (protocol.md section 4, "Hello") |
| `remove` | computer | `device`: a device ID, or a name (case-insensitive) | `{name}`, the device's name, or an error. Only on the root or an admin whose powers allow it (`remove`, and `remove-admins` for an admin; protocol.md section 10, "Who signs what"); a device cannot remove itself; the root is never removed, only replaced by the recovery key (`recover`) |
| `make_admin` | computer | `device`: a device ID, or a name (case-insensitive); `allow_file_key`: the user agreed to the warning about an admin key in a file | `{name}`, the device's name, or an error. Only on the root computer: makes the connected phone, or member with `admin`, an admin (protocol.md section 10, "Admins"). On a group of 0.6 the device need not be connected: the root writes its record with the admin key the device offered, with its proof, when it paired with the root (kept in `offered.json`); for a device another admin admitted it answers that the device pairs with the root to be made an admin (D-118) |
| `take_over` | computer | `device`: the lost root, a device ID or a name (case-insensitive) | an error that points to `recover`: the root changes only with the recovery key (protocol.md section 10, "A change of root"; rule 33, D-117) |
| `takeover_delay` | computer | `{value}`: a duration | an error that points to `recover`: no claim waits (D-117) |
| `key_level` | computer | `{value}`: `proven`, `hardware` or `files` | `{below}` or an error. Only on the group's root, and never a level its own key does not pass: signs a `settings` record with `key_level` and the rest of its newest one; `below` names the admins and hubs whose keys the new level would not let in, which stay until removed. `cbb new` signs `files` itself when the root's keys are in a file, as a computer's CA keys are (protocol.md section 17) |
| `ttl` | computer | `{value}`: `COPY [SECRET]`, durations, a copy from `1m` to `1h` and a secret from `5s` to `1m`, `-` keeping one | `{}` or an error. On the group's root or any admin: signs a `copies` record with `ttl_ms` and `secret_ttl_ms`, how long a copy and a secret live in the group, which every member stamps on the copies it makes (protocol.md section 10, "The copies setting") |
| `hubs` | computer | `{hubs}`: 1 to 16 names or device IDs of computers and phones, in the order they serve | `{}` or an error. On the group's root or an admin with `hub`: signs a `hubs` record, the group's main hubs |
| `freeze` | computer | `device`: a device ID, or a name (case-insensitive) | `{name}`, the device's name, or an error. Only on an admin that is not frozen: freezes another admin without `remove-admins`, never the root or an admin phone (protocol.md section 10, "Removals and freezes keep what the author saw") |
| `thaw` | computer | `device` | `{name}`, the device's name, or an error. Only on the root computer (a computer's admin has no `thaw`): ends every freeze of that admin (protocol.md section 10, "Removals and freezes keep what the author saw") |
| `resolve` | computer | none | `{name}`: on the root, voids both histories of every key that signed two; `name` lists whose. Only on the admin socket |
| `recover` | computer | payload = the recovery sheet's text or QR code, or `name` `yubikey` and the YubiKey's PIN as the payload | `{done}`: this device becomes the group's root by its recovery key (protocol.md, section 10, "The recovery key"). Only on the admin socket. It becomes the root at once by a change of root (rule 33) with a new root key, every device staying but those `leave` names (names or device IDs; never this device), and the service restarts to sign with that key; "the group's root already" on the root; with `yubikey` it opens the recovery key sealed on the one YubiKey with a key in slot 95 (protocol.md, "The recovery key on a YubiKey (0.6)") |
| `hand_over` | computer | `device`: the admin, a device ID or a name (case-insensitive) | an error that points to `recover` (protocol.md section 10, "A change of root"; D-117). Only on the admin socket |

A phone's node passes on a command for another device when it is connected to it, as
protocol.md section 15 says: once until it expires, never one that has expired or claims to live
longer than a command may. For itself it carries out the `mute` and `unmute` commands an
admin sends, keeps both in `mute.json` as `cbb` does, and tells the app (the `mute`
event); every other command for the phone goes to the app as a `command` event, as `cbb`
refuses it. A phone takes tunnel offers and hub shares only from a device the records
let be a hub, by the chain it proved. It keeps the sealed blobsof the copies with images or files it made or fetched in `content/` of its data directory,
the last eight, and serves them (its hello says `media`). `TestFFIJoiner` runs the join by the
home window, sync both ways, a pause and an admin's mute against a Go member through the example `phone-on-linux`,
`TestFFIPhoneAway` sync away from home through a Go hub's tunnel, the phone's node running the
`cbb`'s (`member/src/away.rs`: it keeps the hubs' offers and, while no hub is at home,
dials the first that answers through its tunnel's loopback port),
`TestFFIJoinerMadeAdmin` a phone that joins by the root's window offering its admin key and
that the root makes an admin with it later, `TestFFIJoinerAdmin` that admin phone opening its
own window, by which a Go computer joins, `TestFFIPhoneRoot` a phone that makes its own group of 0.6, lets a Go computer join by its
window and renames, mutes, turns the sync off and on and removes it as its root, and `TestFFIMember` the calls: an address handed in, the button's rule, images both ways,
and pausing.

`cbb_qr_read` (feature `join`, `src/qr.rs`) reads the QR codes in a grey camera frame with the
`rqrr` crate, since Aurora gives an app no reader of its own. `cbb_group_new` (feature `member`,
`src/found.rs`) makes a group of the phone's own: the request names the app's `dir`, and the
core makes the recovery secret (`cbb_member::founding::new_recovery`), writes the phone's record
under the root through the app's root key's callback, keeps the set in `dir`, where
`cbb_member_start` then reads it, and answers `{"group","device","recovery":{"qr","text","modules"}}`,
the recovery sheet the app shows once and keeps nowhere. A request without `dir` is refused:
groups are 0.6 only (D-126). `cbb_member_manage` (feature `member`) signs an admin's change to a
device or command for it through the same callback, as the member's paragraph above lists, and
as the root `key_level`, and the recovery key's change of root (below).
`TestFFIPhoneRoot` renames and removes a computer through it.

A phone in no group restores nothing: a phone in the group changes the root with the recovery key
(`change_root`, above), and restoring on a new phone comes with 0.7 (D-125).

Every phone app keeps the recovery secret on a YubiKey through the core (`ffi/src/piv.rs`,
`cbb_member::piv::recovery`): `cbb_piv` runs one step of PIV and the app's `cbb_transmit_fn`
reaches the card. With `transport` `apdu` (the default: NFC, or a card the system already
speaks to) it carries each APDU and answers with the status word last. With `ccid_bulk` (a
YubiKey on USB-C, whose CCID interface the app claimed) it only moves bytes: a call with data
writes them to the bulk-out endpoint, a call without reads one bulk-in transfer (empty when
nothing came within about a second), and the core frames each APDU as CCID's
`PC_to_RDR_XfrBlock` and waits through the card's time extensions while it waits for its
touch (`cbb_member::piv::ccid`). With `pcsc` (a phone whose system runs pcscd, as Aurora OS
does, which takes a YubiKey plugged into USB-C itself) the core is pcscd's client, as `cbb` is
on a Linux computer, and never calls the function, which must still be one: `open` takes the
one card with the group's recovery key, so that no other card is asked for the PIN, and `seal`
the one card that answers PIV's SELECT; two such cards are refused. The card holds the recovery
secret itself (protocol.md, "The recovery key on a YubiKey (0.6)"; `cbb_member::piv::recovery`),
in the first empty retired slot from 95 down, its certificate naming the group, so both steps
take `group`, the group's ID in hex or its first 16 hex digits: `seal` (`pin`; `recovery`, the
sheet's `{qr}` or `{text}`; `management`, a changed management key in base64, used only when
the card's key is neither the factory one nor PIN-protected) makes the card's key and writes the
container, answering `{"slot", "default_key"}` (the slot, and whether the card keeps its
factory management key, which cbb never changes); `open` (`pin`, then a touch) answers
`{"secret"}`, base64, which the app hands to manage's `change_root` as `recovery` and drops.
`TestFFIPhoneYubiKey` seals a group's sheet on a fake YubiKey in `phone-on-linux`, opens it
after the root is lost, over NFC and through a fake CCID reader, and changes the root with it.

A root phone makes its watch an admin with manage's `add_watch` (`key`, the watch's admin key
as a SubjectPublicKeyInfo; `name`, `os`), whose member key nobody keeps (D-124); a watch signs
nothing in 0.6, so `watch_actions` answers none and `cbb_member_manage_watch` refuses, saying
its actions come with 0.7, where the app's `cbb_sign_body_fn` carries each record or command
whole to the watch (`ffi/src/watch.rs`). `TestFFIPhoneWatch` adds a watch in `phone-on-linux`,
which is listed as a watch, may do nothing to a device and is refused an action from the wrist.

An admin phone makes a remote invitation with `cbb_invite_new` (`ffi/src/invite.rs`): the
request names the public point of the key it admits with (the root's or an admin's), how long
the invitation is valid, optionally the hub, and the `kind` of device invited (`computer` or
empty, or `phone`); the member opens the invitation with `Live::open_invitation`, and each
pairing the hub passes is admitted by the core's admission rules once the user said yes
(`ffi/src/window.rs`, `admit_on`), signing through the callback. It answers the invitation's
text and the QR code's modules; it waits for the hub, so the app calls it off its main thread.
`cbb_invite_next` waits for the invitation's next state (`open`, `joining` with the device's
name, system and fingerprint, `done` with the device that joined, `failed` with the error),
`cbb_invite_answer` answers whether to admit the joining device, and `cbb_invite_free` ends it
and waits until its window closed. `TestFFIInviteThroughHub` and `TestFFIJoinInvite` run both
sides through the example `phone-on-linux`.

The phones run no tunnel of their own beside the member: the Live member runs sync away from
home, the hub and the relay link (decisions.md, D-123). The feature `tunnel` builds the member's own tunnel
into the library (`cbb-member/tunnel`).

The Go programs (`cbb-helper`, `cbb-forward` and the tests) do not link the core and keep
no group state of their own: Go's `internal/clip`, which the interop vectors keep byte for
byte the same as the core's, reads the copies, and `internal/group` holds only the keys and
names they share.

## Operations

| `op` | `args` | `ok` |
|---|---|---|
| `version` | none | `{"abi", "core", "source"}`: the ABI, the core's version and, when the build passed it in `CBB_SOURCE`, the commit |
| `read_invite` | `text`: a remote invitation's text, `cbb://join#...` ([protocol.md](protocol.md), section 12) | `{"invitation": {"phone"}}`, `phone` true when it is a phone's, for an invitation with a guest path; or `{"refused": {"reason", "message"}}`, the reason the format's rule (`invite/shape`, `invite/path`, ...) or `invite/guest` for one with no guest path, and the message a sentence for the user. A refused invitation is an answer, not an error. The invitation carries no expiry: the hub refuses it once its time is over |
| `copy_verdict` | `receives`, `kind`, `mark`, `unread`, `has_text`, `has_media`, `takes_media`, `held` (booleans, false when left out but `receives`), `age_ms`, `window_ms`, `secret_ttl_ms` | `{"verdict"}`: whether the group's current copy goes into the member's clipboard (`write`), or why not: `mode`, `unread`, `secret_gone`, `no_text`, `held` or `old` (`cbb_core::rule`; the cases of `testdata/interop/copy-verdicts.json`) |
| `open_copy` | `event`, `me` (the reader's device), `secret` (base64, its secret for sealed messages) | `{"kind", "via", "text", "media", "key"}`: what the copy holds, and the copy's key (base64), which opens its blob; code 17 when it is not sealed to `me`, does not open or breaks a rule of its content. It does not check the origin |
| `seal_segment`, `open_segment` | `key` (base64, the copy's key), `index` (from 0), `last` (the blob's last segment), `data` (base64: at most 64 KiB to seal, 65 552 bytes to open) | `{"data"}`: the segment sealed or opened ([protocol.md](protocol.md), section 4, "The blob"); a segment that does not open is code 17 |
| `parse_body` | `kind` (`command`, `credential`, `keys`, `release`, `channel`, `attest-status`, `entries`, `zxnext` or `manifest`), `body` (base64) | `{"kind", "value"}`: the body's fields as an object, once it checks; see "Signed bodies" |
| `release_check` | `keys`, `channel`, `release` (each a release file's bytes as fetched, base64), `name` (the channel), `now_ms`, `seen` (what the device kept, optional), `roots` (optional, `[{alg, key, name, use}]`: other roots, for tests; the pinned ones when left out) | `{"value", "seen"}`: release.json's fields and the Seen to keep; a file refused, or one that does not read, is code 16. See "Release files" |
| `release_check_status` | `keys`, `status` (attest-status.json), each its bytes in base64, `now_ms`, `seen`, `roots` as `release_check` | `{"value", "seen"}`: the revocation list's fields and the Seen to keep |
| `release_check_entries` | `keys` and `entries` (entries.json), each its bytes in base64, or in their place `set`: the signed entry points as members pass them (`{"keys", "entries"}`), its bytes in base64; `now_ms`, `seen`, `roots` as `release_check` | `{"value", "seen"}`: the entry points' fields and the Seen to keep |
| `release_named` | `channel` (a channel file's bytes, base64) | `{"release"}`: the version it names, read but not yet checked, so that a device knows which release.json to fetch; `release_check` then checks both |
| `new_device_key` | none | `{"pkcs8", "public"}`: a new P-256 device key (base64 PKCS #8 and SEC1 uncompressed) for a phone that keeps its key in a file (level 3) |
| `sign_digest` | `pkcs8`, `digest` (base64, 32 bytes) | `{"sig"}`: ECDSA P-256 over the SHA-256 digest with that key, DER, base64: what the phone's signing callback gives for a key in a file |
| `why` | `facts` (what a member knows: `in_group`, `removed`, `frozen`, `stop`, `admins_conflict`, `root_two_histories`, `recovery_fork`, `change_arriving`, `checkpoint_stuck`, `owner_disagrees`, `no_secrets_here`, `nothing_here`, `copy_waits`, `update_needed`, `sync_off`, `sync_until_ms`, `muted`, `muted_until_ms`, `newer`, `update`, `connected`, `devices: [{name, online, sync_off, muted}]`, `quiet`, `unreached`, `away`, each optional), `now_ms` | `{"why"}`: the reasons, as the member's `why` gives them (`cbb_core::why`, checked against `testdata/why/vectors.json`); on the group of 0.6 a driver fills the group's part with `why::group_facts` from the state (removed, frozen, the stop, `admins_conflict` from a conflict of admins, `root_two_histories` from `root_pair`, `recovery_fork` from `fork`, `change_arriving` from `first_missing` or `list_missing`, `no_secrets_here` and `nothing_here` from `no_secrets_to` and `nothing_to`, `update_needed` from `update_needed` or `too_old`, `newer`) and adds `owner_disagrees` (peers whose chain parts from its own, `State::disagrees`), `copy_waits` (senders whose copies wait for their records) and `checkpoint_stuck` (`RecordSet::stuck_checkpoints`) |
| `keyboard` | `layout` (`us` or `ru`, the host's), `text` | `{"reports", "untypeable", "map"}`: the HID boot keyboard's reports that type `text` (each 8 bytes, base64; a key down, then all keys up), the characters the layout has no key for (no reports then), and the report map (base64), for a phone that is a Bluetooth LE keyboard (`cbb_core::keyboard`); an unknown layout is code 1 |
| `seal_public` | `secret` (base64, 32 random bytes the device keeps) | `{"key"}`: its public key for sealed messages (base64, 1216 bytes), the `seal` its pairing and device record carry |
| `seal_command` | `body` (base64, a command in the open), `key` (base64, the receiver's `seal` key) | `{"body"}`: the same command with its orders sealed to the key (`v` `2`, `sealed`), canonical, for the sender to sign; see "Signed bodies" |
| `bug_report` | `input` (`{kind, code, name, message, details, app, version, build, os, os_version, model, arch, log, names, now_ms}`: `kind` `panic` or `error`, `app` `ios`, `android`, `aurora`, `mac`, `tray` or `cbb`, `log` CBB's own log, oldest first, `names` the words that must not leave the device), `state` (as the last bug call gave it, optional) | `{"report", "fingerprint", "post", "url", "action", "offer_always", "fixed_in"}`: the report, filtered, as "Technical details" shows it, the break's fingerprint, the body to post to `url` (empty when this build has no key to seal to), what the app does (`ask`, `send` or `skip`), whether the dialog offers "Always allow", and the version the server said fixes this break; see "Bug reports" |
| `bug_allow` | `state`, `always` | `{"state"}`: the user allowed a report, and maybe always |
| `bug_sent` | `state`, `fingerprint`, `version`, `post`, `ok`, `fixed_in` (what the server answered, optional), `now_ms` | `{"state"}`: the report went (`ok`), or it waits to be sent again |
| `bug_pending` | `state`, `now_ms` | `{"queue", "state"}`: the reports waiting (`[{fingerprint, version, post, at_ms}]`), without those older than seven days |
| `push_key` | none | `{"key", "send_key", "slot"}`, base64: a new push key (32 random bytes), send key (P-256, PKCS #8) and slot (16 random bytes). The push key and the slot are one per group, the push key drawn again after a membership change and the slot kept; the send key is one per token for every group, drawn again with each new token (see "Push") |
| `push_limits` | `env` (the platform, as the env registry numbers it) | `{"known", "body", "token", "kinds"}`: whether this core knows the platform, the size of its sealed bodies, the longest token, the bits of `kinds` it defines; the apps hold no number of the format |
| `push_registration` | `now_ms` (the phone's clock), `highest_seq` (the highest seq the app ever gave this group's registrations, left out when none), `restart` (true once after a member's `push-renew` said `ahead`), `kinds` (0 turns push off), and with `kinds` ≠ 0 `env`, `key` (the push key, base64), `send_key` (the token's send key from `push_key`, base64), `slot` (the group's, base64), `face` (the group's face for the push service: the `group` of its hubs credential, base64, 16 bytes), `challenge` (the last one the push service sent for this send key, base64, left out when none) and either `token` (base64, as the platform gave it) or `unifiedpush` (`{url, p256dh, auth}`, the last two base64) | `{"frame", "seq", "highest", "key_hint"}`: message `push` (t 28) as a frame, base64, for every member connection of the group, signed with the send key over [env, token, slot, face, seq] and the challenge when there is one; its seq, max(`highest_seq` + 1, `now_ms`), so that a phone restored from a backup still moves forward, or `now_ms` with `restart` (the service found the number more than a day ahead of its clock, and the member that said so takes this one registration whatever its number); `highest`, the larger of `highest_seq` and seq, or seq with `restart` when the phone's own clock also finds `highest_seq` more than a day ahead, which the app saves before it sends the frame (the cost: a member that says `ahead` falsely while the phone's clock is over a day behind lowers the highest, and members keep refusing the phone's own registrations until its clock is right); and with push on the send key's hint (the first 8 bytes of its hash, base64), which the push service puts beside each challenge. Code 18 when a field breaks its row (a UnifiedPush endpoint that is not `https` on port 443 with a DNS name, a key not 32 bytes, a slot, face or challenge not 16, push on without `face`) |
| `push_open` | `keys` (`[{key, seq}]`: the group's push keys the phone holds, the current one first), `body` (base64, the sealed body as the notification carries it), `me` (the phone's device ID), `origins` (`[{key, rights, frozen}]`: the devices the app last saved, each member key as the records encode it, base64), `sealing` (`[{epoch, secret}]`: the phone's sealing secrets of the epochs in the group's window), `too_old`, `halted`, `hints_only` (booleans; one left out gives the neutral `hint`: `halted` opens nothing, `hints_only` after an event of removal, a new root or a stop until the app has applied it and drawn a new push key), `now_ms` and `window_ms` (the extension's clock and how old a copy may be) | `{"kind", "key_index", ...}`: `copy` with `id`, `origin`, `type` (`text`, `media`, `files` or `other`), `secret`, `ttl_ms` and `text` once the origin, its signature and `commit` hold and the copy is within the window; `waits` with `id` and `origin` when the copy did not fit, does not open here or is older; `event` with `id`, `event`, `device`, `time_ms` for an event less than a day old; `hint` for anything else. Only `copy` states a fact; the rest the app shows as "open the app". The extension keeps the IDs it showed and shows none twice. Code 18 when no key opens the body |

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
| 14 | `saved` | the group's saved set file cannot be read, is of another version, or its pin does not hold under the local key |
| 15 | `command` | a command is refused: its signer, its target, its time or its limits |
| 16 | `signed` | a signed body that is not a record (a command, a server credential, a release file or a manifest) is refused: its size, form or a field |
| 17 | `copy` | a copy is refused or cannot be sealed: its origin, its signature or a field, or it does not open with the device's key |
| 18 | `push` | a push registration cannot be made from its fields, or a push body does not open with any of the phone's push keys |

## Push

A phone whose app is closed hears of a copy or an event through its platform's push service
([format](format.md), section 9.6, `cbb_core::push`). The phone draws a push key per group (`push_key`),
sends the group its token, platform and key in message `push` (`push_registration`), and opens
each body that arrives with `push_open`. Its notification extension calls only `push_open`. It
holds, in a keychain group of its own (this device only, after the first unlock), what opens a
body and a copy in it, and nothing that signs a record: the push keys, the send key (which signs
only registrations to the push service), the phone's sealing secrets of the epochs still in the
group's window, the origins and the window. Never the member key, an admin's or the root's key,
the recovery secret or anything else that signs records: a copy in a body is sealed to the
phone's own sealing key, so the extension needs that secret to show it, and nothing more (the
store `push_open` builds refuses to sign or keep a key). The app writes the epoch secrets and the
window on every rotation of its sealing key and removes the ones that left the window. The text
of a notification comes from the app's translations, never from a string in the body; only a
`copy` answer carries text, and the apps never show a secret's text on a notification.

On the iPhone and iPad, `PushVault` (CBBKit) keeps this in the keychain access group
`tools.cbb.push`, which the app and its notification extension (`apps/ios/NotificationService`)
share; the member key and the app's other secrets go to the app's first group, which the
extension does not have and which every keychain query of the app's names
(`KeychainIdentity.accessGroup`). The extension's one app group is `group.tools.cbb.push`, for
the IDs it showed and the hints-only marks; the app's own group, with the group's file and the
servers' credentials, is not the extension's.
`App/PushSetup.swift` asks iOS for the token and makes the registrations: one sender (token,
platform, send key, its hint, the last challenge) for every group, and per group the push keys,
the slot and the last registration. A registration is made again only when what it says changed
(the token, the switch, a challenge, a membership change) or a member sent `push-renew`, never
because the app ran. A device gone or a new root draws a new push key, and the previous one is
not kept, so a removed member's bodies open nothing; until then an event of a removal, a new root
or a stop marks the group hints-only (`PushMarks`), and the mark is spent once the app has
applied that change and drawn the new key, or has synced the group's records after the mark with
a member other than the device it names (one stayed connected 30 s), took in records newer
than the mark, and those records say the change did not happen (the device still listed,
another root, no stop). Any mark ends a week after the app first synced, after it, with a member
other than the device it names; a phone that met no member keeps it. The apps keep one time for
the records they took in from any peer, so newer records from one peer let a sync with another
that has not heard of the change spend a mark. When the list of marks
is full a mark no longer in force goes first, and one not in force when it arrives never pushes
one out. Every registration names the group's face for the push service; until the group gives
one nothing is registered. Leaving the group first saves a registration with `kinds` 0 for its
members, then forgets its push keys, secrets and marks and the send key, so that what the left
group's members hold stops being good once the phone's other groups confirm the new key; the
token stays. On UnifiedPush, whose endpoint takes a message from whoever knows it, at most one
new challenge an hour is kept, a challenge alone makes a new registration once in a challenge
period (under the same send key), and applying a removal takes a new endpoint. A current
member knows the endpoint and its keys, so it can plant a challenge part of its own each hour
just before the service's and keep the phone's key unconfirmed for as long as it does so; the
phone's groups then send at the unconfirmed rate, which costs function only, no more than
membership already gives. Leaving the last group gives the token up; on FCM a deletion that
fails is tried again at the app's next start. The Android app does the same
(`PushVault.kt`, `PushSetup.kt`). On a group of 0.6 both apps take the group's face from the
member's `push_face`, hands the member each registration it saves (`push`, which the member
sends to every member it connects to) and makes a new one for each `push-renew` the member
hands it (`push_renewals`, read a few seconds after each connection and with the records). A copy's text gets the notification's Copy button;
the test tool's row in Settings is in debug builds only.

On the members the sender is `member/src/pusher.rs`, and the project's push service is
`cbb-push` (`member/src/pushd`). The member's sync calls only the sender's seam, written at the
head of `pusher.rs`: `registration` (message `push` arrived from the device itself),
`connected` and `left` (a peer's member connection opened or closed), `renewals` (the
`push-renew` messages, t 29, to send a peer whose connection opened: one per group where the
service found its registration stale, with `ahead` when it found its number more than a day past
its clock), `forget` (a device removed or frozen), `copy` (with the copy's readers and `cbb_core::push::copy_body` for each),
`event`, and the traits `Faces` (the push service's address, pin, server key and credentials
of the group's face) and `Saved` (where the registrations are kept).

On the records of 0.6 the mesh calls the seam (`member/src/mesh/push.rs`). Events (rule 33's,
`pushbody/event`) come from the records a member applies: a device record that adds a device
(`joined`, naming it), a `revoke` (`removed`, naming the device when it removes one) and a
recovery record that changed the root (`root`), a device record that changes a device
already in the group (`own_record`, to that device's phone alone) and the records that stop
the group (`stopped`, once, when the state comes to stop the exchange with every device or
halts, named by the lowest of the records its conflicts name), each with the record's own
time. The event's `id` is the first 16 bytes of the record's ID, so every member that applies
the record gives the same ID and a phone woken by a hub and by the root shows the event once
(a copy's notification keeps the copy's random ID). A hub sends them, else the root's device
or an admin's when the group has no hub. `waiting` is not sent yet: on 0.6 a device waits to
join only while the inviting admin's window is open, so no member holds a waiting device to
tell of. The previous period's face is kept in `push-previous.cbor` in the group's directory
(the group, the service's pin and address, the credentials, the tag and their expiry; the
server key comes again from the server secret and the tag), so a restart does not lose it.

Every honest sender of one body makes the same bytes (the nonce is derived from the plaintext, a
copy is reduced with age 0, an event carries its record's time), so the service drops a repeat by
the bytes and a phone gets one notification; a repeat with a longer life than the first passes
once. What a send leaves (a repeat, a binding) is written only after the platform took the body,
and a second send of a body still on its way is answered `failed` with a short wait, so a slow
platform never loses a body. A repeat does not outlive a restart of the service.

The phone keeps one send key per token, for all its groups, and draws a slot (16 random bytes,
never the group's ID) per group; the send key signs [env, token, slot, face, seq], and the last
challenge the service sent to the token when the phone has one. The service keeps, per token, a
binding (`member/src/pushd/binding.rs`), across restarts (the state file and its journal, written
before a send that changed a binding is answered `sent`, a send whose change could not be written
answered `failed` with a wait; a missing state file stops a start that is not the first,
`-new-state`):

- While no key is confirmed, a send under any key passes with the challenge for its key, which
  travels to the token with the body (the phone's alert pushes carry it).
- A challenge is not kept: the service computes it from its own secret, the token, the key, the
  binding's generation and the 14-day period, and checks an answer by computing it again for this
  period and the one before; so no number of other keys can push the phone's challenge out. A
  send whose signature covers it, under that key, confirms that key: only the token's holder saw
  it. A confirmation raises the generation, so every challenge made before it confirms nothing
  more. A replayed challenge, one made for another key or token, or an older one confirms
  nothing. The app keeps a challenge only for its own token and its own key (the challenge
  carries the first 8 bytes of the hash of the key it is for, which `push_registration` answers
  as `key_hint`), and the extension keeps one only on the same terms.
- Once a key is confirmed, only that key sends; another key is answered `stale` (7) and gets a
  challenge alone (a push with no body, within its group's budget for them), and takes the
  binding only by confirming it, never by time. A member that binds first so causes no refusal
  of the phone's own sends, only the wait until the phone confirms.
- The highest seq is kept per key and slot, so one group's registration never silences
  another's; a seq more than a day ahead of the service's clock is refused with `ahead` (8). A
  member keeps the highest seq a device registered with (`Registration::replaced_by`), and after
  an `ahead` it sends that device `push-renew` with `ahead` and takes the device's next
  registration whatever its number, once. A reader that does not know a status maps it to
  `failed`, retried after 30 s, at most five tries per body.
- The service holds a registration to the face of the connection it came on: the signature
  covers the face, and a registration signed for another face is refused. A member keeps the
  previous face's key and credentials for push only, and only for registrations that name it,
  until they expire or the phone registers under the new face.

A send key of an algorithm the service does not take is answered `key` (6), and the sender drops
it; one answered `stale` is dropped too, and the phone is sent `push-renew` with the
registration's slot at its next connection, so its app registers again. Until the first send
under a new seq, the old seq passes, and its bodies open nothing. Every send costs its tag's
budget, a refused one too, and the service closes a connection after eight refusals. What goes
to one token is budgeted per group: under the confirmed key, with one ceiling for every group
together; while no key is confirmed, a small
rate per group and one ceiling for every group together, past which a group that sent nothing
to the token lately still sends one body (these passes counted per payer and token, so groups
of one address share them; the ceiling does not bound senders from many addresses: 20 addresses
of 4 groups each bring 80 bodies at once, the price of never holding the phone's own group behind
them) and any other send carries only its challenge, alone; and
challenges alone. The tables
everyone shares give each payer (an address, an IPv6 /64, an IPv4 client on an IPv6 socket read
as its IPv4 address) a share, and when one is full the payer with the most entries loses its
oldest entry, never everyone.

How the challenge reaches the app: APNs, the payload key `k` (24 bytes in base64: the challenge,
then the key's 8 bytes), or alone in a background push (`content-available`, priority 5), which
iOS may hold back, so a confirmation can wait for the next alert push; FCM and Push Kit, a data
key `k`; UnifiedPush, the decrypted message is parts, each a kind (1 byte), a length (2 bytes)
and its bytes (kind 1 the body, kind 2 the challenge, kind 3 padding for a part that is not there,
so every message is one size), the app skipping kinds it does not know.

How the service sends: APNs over HTTP/2 with the team's ES256 key; FCM through the HTTP v1 API,
the service account's RS256 assertion traded for an access token (kept until five minutes before
it ends), each push a data-only message, priority `HIGH` with a body and `NORMAL` for a challenge
alone, its `ttl` the push's own and no collapse key; a token FCM calls `UNREGISTERED` or
`SENDER_ID_MISMATCH` is dropped, a quota answer waits a minute. On Android the push vault is
sealed under an Android Keystore key of its own (AES-256-GCM, kept out of backups); the full
build takes FCM, whose Firebase identifiers come from the build's properties (`cbb.firebase.*`
or `CBB_FIREBASE_*`) and never from a committed `google-services.json`, and without them it
offers no push; the F-Droid build takes UnifiedPush through the distributor the user installed.

New events keep the shapes of the body's fields 3 to 7 (an ID of 16 bytes, an event number, a
device ID of 16 bytes, a time in milliseconds), so that a phone of an older version reads a later
event as the neutral hint and never refuses it.

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

## Secrets

The secrets the core holds itself are wiped when it lets them go (`zeroize`, or the
libraries' own wiping types: p256's keys, x25519-dalek's secrets, HPKE's and ML-KEM's
private keys, the ciphers' key schedules): the CPace password, its scalar, its shared point
and the keys made from them, the TLS exporter's master secret and what it derives, a copy's
derived keys, the recovery key and its text while they are read, an invitation's secrets, the
clipboard engine's local key, the secrets in the arguments of a call (`secret`, `key`,
`pkcs8`) and their base64 text. No `Debug` of the core prints a secret: such fields show as
`<N secret bytes>` or `<hidden>`, and no error text carries one. `ffi/` wipes each answer in
`cbb_free`, and copies an answer to its exact length rather than leave a shorter copy behind.

A secret the core *returns* (a new key's PKCS #8, a seal secret, a WireGuard key, an
answer's bytes once the app has read them) is the caller's to keep and wipe: in the apps the
keys live in the keychain, the Secure Enclave, the Android Keystore, the TPM or a file, and
the kits' copies of an answer are theirs.

Every comparison one of whose sides is a secret or an authenticator is constant time
(`cbb_core::secret::ct_eq`, on `subtle`) or is the library's own verify: the records' marks
and the pinned keys' mark (rule 29), CPace's confirmation tag, the tunnel's confirmation tags,
the short code's commitment, AmneziaWG's mac1 in `member/`. Public values (key hashes,
device IDs, period tags a server sees) are compared with `==`. The timing tests in
`core/src/secret.rs` measure the marks and the pairing confirmation in the manner of dudect;
they are ignored by default: `cargo test -p cbb-core --release -- --ignored timing
--test-threads=1`.

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
filtered: addresses (IPv4, IPv6, MAC, also inside a word such as `peer=...` or a URL), host
names of the home network (`.local`, `.lan`, `.box` and the like), e-mail addresses, long numbers
(codes), long hex (device ids, fingerprints), base64 that looks random (keys, secrets,
invitations), the value of a name's field in `key=value`, `key:value` or `key: value` (`ssid`,
`host`, `peer`, `server`, `device`, `user` and the like), to the field's end (a comma,
semicolon, bracket or quote, or the line's end), an address after any key
(`addr:...`), every word in a script other than Latin (the programs log in English, so such a word is
the user's), the user's name in home folders and every word of `names`, in any case and as a
host name (`Office PC` also as `office-pc`), are replaced. A panic's details keep only the kind
of its message as the standard library words it (`index out of bounds`, `called
Result::unwrap() on an Err value`), never the values after it, and "a panic" for a message the
program wrote itself; its file, line and thread stay. Clipboard texts never reach the log.
The filter works on free text by patterns, not on fields the log names: a name logged without
one of those keys and in none of those forms (`ssid HomeNet`, a bare host name) still passes.
What keeps it out is that the programs log names only in such fields and pass every device
name they know in `names`; logging by field is left for a later version. The report is sealed to the robot's public key (`crate::seal`, HPKE with X-Wing,
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
and version are kept each day; the rest are answered as taken and dropped, so that no app sends
them again. Past 5000 reports in a day, or 2 GiB kept in all, it answers 503, and the apps keep
their reports and send them later. One IPv4 address or IPv6 /64 has at most 100 reports kept a
day and one IPv6 /48 at most 500, past which it answers 503 too, so no one source fills the day;
nginx hands cbb-bug the prefix in a header, which it counts in memory for the day and never
writes. A day's reports are removed after 30 days. nginx allows each IPv4 address and each
IPv6 /64 six reports a minute. The robot opens the reports elsewhere with its secret:
`cbb-bug keygen SECRET` makes the key once (the secret stays on the robot's computer, the public
key goes into `cbb_core::bug::ROBOT_KEY_B64`), and `cbb-bug read SECRET FOLDER...` opens the
reports copied from the server.

## The group (records v3)

The calls whose names start with `set_` are the group of 0.6: its records v3 (`cbb_core::records`)
kept in a set file (`cbb_core::setfile`), which the computers' member writes in its state folder and
Go and the tests pass in each call. Keys, key hashes, record IDs, device IDs and digests are base64;
a key is the point (SEC1, 65 bytes) except the recovery key's second half, the SLH-DSA public key.

Every call takes `set`, the set file, and `local`, the device's 32-byte local key, when the file is
pinned to it. A call that changes the set answers the new `set`, and every call that reads it the
group's view.

**The set file** is one CBOR map in the format's profile, written whole: 1 its version (1), 2 the
group's first root key, 3 and 4 the two halves of the recovery key, 5 the pin (the HMAC under the
local key over the three keys, `records::pin_mark`), 6 the records in dependency order, each
`[envelope]` or `[envelope, mark]`, 7 the lists, 8 the removal records the notices keep, 9 the
notices dismissed, 10 the devices that came in through each change of root `[change, seq, [key
hash]]`, 11 the newest change applied with the devices before it `[change, seq, [device ID]]`. A
record whose mark holds under the local key is taken without its signature checked again; every
other is checked as if a peer sent it. With `local`, a file without a pin, or whose pin does not
hold, is refused (code `saved`): its keys were changed. A file of a later version says to update.

**Signing in rounds.** The root's, an admin's and a new root's keys stay where the device keeps
them. A call that writes answers `{"sign": [{key, digest}]}` while it needs signatures: the caller
signs each digest with that key (ECDSA P-256 over the SHA-256 digest as given) and calls again
with the same arguments and `sigs`, `[{digest, sig}]`, every signature so far (`sig` DER or the 64
bytes r ‖ s). A record's ID covers its body only, so the digests are the same in every round; an
admin key's first record after its grant goes with its acknowledgement, whose digest comes first.

| `op` | `args` | `ok` |
|---|---|---|
| `set_new` | `root`, `recovery`, `recovery2`, `local` (optional) | the empty set of a group, as its creator or a joiner starts it, and its view |
| `set_add` | `records` (envelopes), `lists` | the records and lists a peer sent, each checked before it is kept, round after round as one may wait for another: `stored` (IDs), `refused` `[{id, why}]` (`why` `group`, `unknown_signer` or the rule broken; `id` null for bytes that are no record), `changed`, the view |
| `set_view` | none | the view |
| `set_records` | `peer` (optional, a member key's hash) | `{records, lists, digest}` to send, in dependency order; with `peer`, what the set gives that peer |
| `set_write` | `signer`, `record`, `time_ms`, `sigs` | a record of the root or an admin: `records` (envelopes, to send), the view. `record` is `{"type": ...}`: `device` (`key`, `name`, `role` `member`, `phone`, `watch` or `leaf`, `rights` of `read`, `send`, `hub`, `secrets`, `caps` of `admin`, `dials`, `hub`, `os`, `store` `file`, `hardware`, `rootless` or `proven`, `admin` and `admin_kind` `watch`, `computer` or `phone`, which fixes the powers and commands, `holds_root`, `guarded`, `replaces`), `freeze` (`keys`), `thaw` (`ids`), `resolve` (`ids`), `settings` (`key_level`, `min_rules`, `shared`), `copies` (`ttl_ms`, `secret_ttl_ms`), `hubs` (device IDs), `ack` (`spare`, a spare admin key), `checkpoint` |
| `set_remove` | `signer`, `keys` (member key hashes), `time_ms`, `sigs` | the removal of devices by the root (with what a key in two histories needs) or an admin that may remove |
| `set_dismiss` | `id` | the notice is not shown again |
| `set_change_preview` | `leave_out` (member key hashes) | `{"preview": [{device, outcome, frozen}]}`, what a change of root does to each device: `outcome` `stays`, `out`, `admin_kept_with_spare`, `admin_rights_lost` or `frozen` |
| `set_change` | `recovery_secret` (32 bytes, from the recovery sheet; used for the call and forgotten), `new_root`, `device` (the new root's own device record, as `set_write`'s), `leave_out`, `drop_hubs`, `over_waiting` (write past a change the set holds and has not applied), `time_ms`, `sigs` | a change of root by the recovery key: `records` (the recovery record first, then the new root's first records), `list`, `again` (the change the set held, given back), `blind` (written without records from a member since the set was read: warn before sending), the view |
| `set_standing` | `own`, `peer` (member keys) | where the peer's key stands in the records, as TLS by key asks: `standing` `member` (with `device`), `unknown` (it must send its intro), `refused` (with `reason`), `halted` or `fork_proof` |

The view: `group`, `digest`, `record_count`, `bytes`, `first_root`, `recovery` (K1's hash), `roots`
(the path, the current one last), `root_device`, `devices` `[{id, key, key_hash, name, role, rights,
caps, os, store, admin, powers, commands, root, frozen, guarded, by_root, no_secrets, nothing}]`,
`revoked`, `hubs`, `stop` (`""`, `secrets` or `full`), `stopped`, `halted`, `too_old`,
`update_needed`, `ttl_ms`, `secret_ttl_ms`, `conflicts` `[{kind, records, signers}]` (`admins`, `fork`,
`two_histories`, `admits`, `ids`), `changes` `[{record, seq, root, state}]` (`effective`, `void`,
`competing`), `list_missing`, `change_arriving`, `newer`, `notices` `[{id, keys}]` (removals by an
earlier root the person has not dismissed) and `came_in` `[{change, seq, keys}]` (devices that came
in through a change of root).

## Signed bodies

`parse_body` reads the signed bodies other than records as every program reads them
([protocol.md](protocol.md): commands in section 15, server credentials in section 13, the
release files in section 16, manifests in section 7): the strict form of signed bodies, then
each field against its row. A release file's body is refused above 256 KiB, as its envelope
allows. It checks the body alone; the signature, the signer and the time are the caller's, or
the member's for a command. Go reads the bodies with its own code, which the strict vectors
keep the same. The phone kits call it for
each command, credential and release file they take. A manifest comes inside a copy's sealed
Content, in the canonical form, and `open_copy` reads it there for the phones; Go reads it with
`clip.ParseManifest`, and the kits'
`Media.Manifest.parse` asks it for a manifest given as bytes.

`seal_command` seals a command's orders to its receiver (protocol.md, section 15, "Sealed
commands"): it checks the command in the open as `parse_body` does, moves `mode`, `hub`,
`enter`, `kind`, `text` and `action` into the sealed part with the header as associated data,
and writes the body with `v` `2` in the canonical form. The phone kits call it for each command
to a device whose record has a `seal` key; Go seals with its own `group.SealCommand`, and both
open each other's. A phone keeps a secret for sealed messages of its own (32 random bytes in
the keychain, or under a key of the Android Keystore), gives its public key from `seal_public`
when it makes a group or joins one, and its member in the core opens the commands sealed to it
with that secret.

## Release files

`release_check`, `release_check_status` and `release_check_entries` check the signed files of
the releases as the Rust `cbb` does ([protocol.md](protocol.md), section 16): keys.json under
the root keys, the file under the keys of its use that keys.json certifies, the two signatures
of each (ES256 and SLH-DSA-SHA2-128s, "Two signatures"), the expiries, the clock and that no
sequence number or version is older than `seen`. Each file goes in as the bytes the device
fetched and the core reads it as every reader does (protocol.md, section 16, "Two signatures":
the envelope in the strict form of signed bodies, then its members), so a kit decodes nothing
of a release file and every program takes the same files. The pinned roots are the core's own copy of
`internal/release/roots/roots.pem`, so the phone kits carry none; `roots` replaces them only in
tests and drills. The kits keep the answer's `seen` and pass it to the next check. The
interop vectors `testdata/interop/go-release.json`, `go-release-envelopes.json` (envelopes as
they come, in base64) and `go-entries.json` are the cases every reader agrees on.

## Entries of 0.6 that a driver calls

Beside the JSON operations above, the core has Rust entries that the programs call directly:
`member/`, the Rust service and command line, which every phone also runs inside the core,
and `ffi/`'s own calls for the phones. The ESP32's firmware joins a group in 0.7.

| Entry | What it does | Called by |
|---|---|---|
| `sheet::text`, `sheet::qr` | the recovery sheet's text and QR code from the recovery key's secret and the group ID ([protocol.md](protocol.md), section 9) | `member/src/founding.rs`; `ffi/src/found.rs` for a phone that makes a group |
| `sheet::read` | reads what the person typed or scanned (at most `sheet::MAX_INPUT` (512) bytes) into a `sheet::Read`, or a `sheet::Reason` with its `message()` | the recovery in `member/` (`founding.rs`, `service/on_live.rs`) and `ffi/` (`found.rs`, `member/live.rs`) |
| `sheet::check` | checks a read sheet against the group ID and the group's recovery key, before any signing | the same |
| `sheet::yubikey::seal`, `open`, `read`, `is_ours`, `ecdh`, `check` | the bytes of the YubiKey's recovery object: the object's layout, the seal and opening by ECDH with the card's key, and the check that the opened secret is the group's recovery key. The card itself is the caller's | `member/src/piv/recovery.rs`; `ffi/src/piv.rs` for the phones |
| `tls::bykey::pairing_exporter` | the session's `join::PairExporter`, only from a finished handshake on `cbb-pair/3` | `member/` (`joining.rs`, `mesh.rs`) and `ffi/src/joiner.rs`: the core's TLS stays inside the core |
| `join::PairExporter::exported_by_platform_tls` | the same from 32 bytes a platform's TLS exported with `EXPERIMENTAL-cbb-pair-v3` and an empty context; the caller states where they came from | `ffi/src/pair06.rs`, for a pairing over the platform's TLS |
| `join::invitation::Invitation::home`, `typed`, `home_secret` | a home window: its ID and six digits, and the joiner's same invitation from the ID and the digits it scanned or its person typed | `member/` (`admitting.rs`, `join.rs`, `joining.rs`, `admit_cli.rs`) and `ffi/` (`joiner.rs`, `pair06.rs`) |
| `join::welcome::Welcome::build`, `part_message` | the Welcome and the parts that follow it when the set does not fit one frame | `member/` (`admitting.rs`, `link.rs`) and `ffi/src/pair06.rs` |
| `join::session::JoinerSession`, `MemberSession` | one whole pairing session at each end, without I/O: the frames of messages 64 to 69 in order, the member's counting the attempts on its `invitation::Open`; the joiner ends with `Joined::Done`, a checked Welcome's set and state to store and message 68 to send. Inside, they run the member's CPace exchange (`join::approve::MemberExchange`), the joiner's proof at a home window (`join::invitation::Proven`), message 67 (`join::welcome::message`) and the joiner's taking of the parts (`join::welcome::Assembly`), so a program that runs them needs none of those itself | `member/` (`join.rs`, `admitting.rs`) and `ffi/` (`joiner.rs`, `pair06.rs`, `window.rs`) |
| `bounds::BOUNDS` | every number of the format with its rule, refusal and the vector that reaches it ([protocol.md](protocol.md), section 19) | no driver; the tests and the docs check against it |
| `records::RecordSet::for_peer`, `lists_for_peer`, `parts_for_peer` | what a peer gets in sync, and the same as parts that each fit one frame, every change of root's list beside its head | sync in `member/src/link.rs`; the parts, the Welcome |
| `records::RecordSet::digest` | the set's digest, which a hello and each sync round carry | `member/src/link.rs` |
| `records::RecordSet::missing` | the record IDs to ask the peers for in this round; each ID is given up after `records::set::MISSING_ROUNDS` (16) rounds | `member/src/link.rs` |
| `records::RecordSet::change_arriving` (from `State::first_missing`, `list_missing`) | a change of root waits for the new root's first records or its list | the view's `change_arriving`, which the apps show as "a change of root is arriving" |
| `records::RecordSet::room_of`, `root_room` | a key's room: its tier, its fixed cap, the units its records take and `left()`; `full_for(units)` when the key's next record would not fit (a per-key "this key's room is full", never a flag for the whole group) | no program yet: for the apps, beside each admin key and the root |
| `records::RecordSet::would_take` | what the rooms would do with a record now, on a copy: kept, kept and pushing out some of the same key's newest records, or turned away with the room and the record's units. Nothing changes | no program yet: for the writer before it signs, and the apps, to say why a record of theirs did not stay |
| `records::RecordSet::removal_warning` | before an admin removal is signed: the devices that would leave the group and those that would no longer hold an admin key. Being settled: it judges the removal alone, without the checkpoint the root's writer writes first, so it can name devices that checkpoint keeps | no program yet: for the admin's app, in the confirmation |

### Sync of records: what a driver must do

The record set decides what is held; the driver decides when records travel. A driver that
gets this wrong leaves two members connected with different sets. So:

- **Send while the digests differ.** A member sends what `for_peer` gives whenever its digest and
  the peer's differ: when the connection opens, and after every insert that leaves them
  different, not only at the hello. A receiver takes each part as records, lists, records.
- **Stop only on equal digests.** Equal digests end a round, never "nothing was asked". The
  rounds on one connection are bounded; a connection that passes the bound is a fault of the
  core, which the driver reports (in debug mode with both digests) instead of looping.
- **`missing` is a hint.** Asking by ID speeds sync up; giving an ID up after
  `MISSING_ROUNDS` never stops the sending above. What was asked is not saved, so a restarted
  member asks again.
- **A waiting change is shown.** While `State::first_missing` or `list_missing` is set, the
  app shows "a change of root is arriving" and the driver sends again on every connection.
  `RecordSet::stuck_checkpoints` covers only the current root's checkpoints, not a waiting
  change.
- **Nothing is silent.** A record the rooms turned away is reported with `would_take`'s
  reason, and a full room with `room_of`, never as a generic failure; in debug mode the
  numbers (cap, units held, the record's units) are shown under the message.
- **Offering again changes nothing.** An insert or `insert_all` answers as the rooms'
  judgment of what is held with what came, and what is held is that judgment of itself, so
  `insert_all` of records the set already holds leaves it as it was. One member's end may
  depend on the order it got records in, for a key past its cap; members agree at the end of
  their exchange, which is why the driver sends while the digests differ.
