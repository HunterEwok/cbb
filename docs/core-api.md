<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The core's entry point

For engineers and anyone binding the Rust core into another program. This page specifies the
byte-in/byte-out JSON API (`cbb_core::api`, `core/src/api.rs`), the C bindings exported by `ffi/`
(`ffi/include/cbb_core.h`), the member operations shared between phone apps and the computer
control socket, and the Rust entry points that drivers call directly.

For protocol rules, see [Protocol](protocol.md). For binary wire encodings, see
[Wire format](format.md). For system architecture, see [Design](design.md). For planned work, see
[Roadmap](roadmap.md).

## Requests and answers

`cbb_core::api::call` takes a UTF-8 JSON object of at most 8 MiB (`MAX_REQUEST`):

```json
{"abi": 1, "op": "version"}
```

| Field | Type | Meaning |
|---|---|---|
| `abi` | integer | Version of the request and answer schemas (`1`). The core rejects any other version. |
| `op` | string | Operation name from [Operations](#operations) or [The group (records v3)](#the-group-records-v3). |
| `args` | object | Arguments for the operation. Omit when the operation takes no arguments. |

Every call returns canonical JSON in one of two shapes:

- Success: `{"abi": 1, "ok": ...}` containing the operation's result.
- Error:

```json
{"abi": 1, "error": {"code": 10, "name": "body", "message": "...", "details": "..."}}
```

`message` is a short sentence for the user. `details` lists the underlying causes, one per line,
with each cause's type when known. Programs display `details` under `message` in debug mode and
always write both to the log (see [Error messages and details](reference/errors.md)).

`call` never panics and returns a valid JSON answer for any input bytes, including malformed data.
Any breaking change to request or answer shapes increments `abi`.

### Base C functions

The `ffi/` crate builds `libcbb_ffi` and declares its C interface in `ffi/include/cbb_core.h`.
`ffi/bind.sh` builds the libraries for phone apps and host tests. The Swift kit (`apps/ios/CBBKit`)
links the header as the module `CCbbCore` (`Core.swift`), the Kotlin kit (`apps/android/kit`)
loads `libcbb_ffi` through JNA (`Core.kt`), the HarmonyOS app wraps each function in a Node-API
module (`apps/harmony/entry/src/main/cpp/napi_init.cpp`), and the Aurora OS / Sailfish OS app
calls the header directly from C++ (`apps/silica/src/core.h`). Both phone kits check `cbb_abi()`
before calling `cbb_call`.

| Function | Signature / contract |
|---|---|
| `cbb_abi` | `uint32_t cbb_abi(void)` — Returns the ABI version (`1`). |
| `cbb_call` | `uint8_t *cbb_call(const uint8_t *request, size_t len, size_t *answer_len)` — Processes `len` bytes at `request` (`NULL` with `len == 0` is an empty request) and writes the answer length to `*answer_len`. Returns `NULL` only when `answer_len` is `NULL`, or when `request` is `NULL` with `len > 0`. |
| `cbb_free` | `void cbb_free(uint8_t *answer, size_t len)` — Wipes and frees an answer buffer returned by any `cbb_*` function using its reported length. `NULL` does nothing. |
| `cbb_last_panic` | `uint8_t *cbb_last_panic(size_t *answer_len)` — Returns the error JSON (code `5`, `panic`) of the last caught panic, or `NULL` if none occurred or `answer_len` is `NULL`. Free with `cbb_free`. |
| `cbb_test_panic` | `uint8_t *cbb_test_panic(size_t *answer_len)` — Triggers an intentional panic inside the panic guard and returns code `5` (`panic`) for wrapper tests. Free with `cbb_free`. |

All C functions beside `cbb_call` return JSON answers in the form `{"ok": ...}` or
`{"error": {"message": "...", "details": "..."}}` (without an `abi` field), except caught panics
which return the standard code `5` panic envelope.

### Feature flags in `ffi/`

`ffi/Cargo.toml` defines four Cargo features:

- `join`: Enables `cbb_qr_read` and `cbb_group_new` (plus shared signing and QR helpers).
- `member` (implies `join`): Embeds `cbb_member` into `libcbb_ffi` and exports `cbb_member_*`,
  `cbb_piv`, `cbb_invite_*`, `cbb_window_*`, `cbb_joiner_*`, and full `cbb_group_new` support.
- `tunnel` (implies `join` and `cbb-member/tunnel`): Builds the member's away-from-home WireGuard,
  AmneziaWG, and VLESS over XHTTP tunnel into the library. Every phone build produced by
  `ffi/bind.sh` enables `member` and `tunnel`.
- `testhooks`: Enables test environment hooks for the `phone-on-linux` integration example. Release
  app builds never enable this feature.

The Go programs (`cbb-helper`, `cbb-forward`, and the end-to-end tests) do not link the Rust core
and keep no group state of their own. `internal/clip` defines the clipboard kinds and manifests
shared between the helper and the desktop tray app, and `internal/group` holds only shared key and
name helpers.

### The member

When built with the `member` feature, `libcbb_ffi` runs `cbb_member::live::Live` in the phone
app's process (`ffi/src/member.rs` and `ffi/src/member/live.rs`). The phone's member key stays in
platform key storage and signs through a callback:

```c
typedef int32_t (*cbb_sign_fn)(void *ctx, const uint8_t *digest, uint8_t *sig, size_t *sig_len);
```

The callback signs the 32-byte SHA-256 `digest` with ECDSA P-256, writes the DER signature into
`sig` (72 bytes capacity) and its byte length into `*sig_len`, and returns `0` on success.

#### Lifecycle and calls

- **`cbb_member_start(request, len, sign, event, ctx, answer, answer_len) -> cbb_member *`**
  Starts the member for a group directory containing `group.cbor`. If `dir` has no `group.cbor`,
  `cbb_member_start` leaves the directory untouched and returns an error whose message is
  `this group was made before 0.6, which this version no longer runs: make a new group`.
  - `request`: `{"dir", "name", "os", "os_version"?, "version"?, "device", "public", "peers"?, "mdns"?}`.
    `public` is the member key's 65-byte uncompressed SEC1 point (base64). `device` must match the
    device ID derived from `public`. `peers` is a list of `host:port` addresses. `mdns` defaults to
    `true`.
  - `sign` and `event` share `ctx`, which must remain valid and thread-safe for the lifetime of the
    process because background threads may still invoke callbacks briefly after `cbb_member_stop`.
  - Answer: `{"ok": {}}` on success (returns a non-null `cbb_member *`), or `{"error": ...}`
    (returns `NULL`).
- **`cbb_member_call(m, request, len, answer_len) -> uint8_t *`**
  Sends `{"op": "...", "args": {...}}` to the running member and returns `{"ok": ...}` or
  `{"error": ...}`. Operations that wait on the network (`fetch` and `wait`) block and must run off
  the UI main thread. Unsupported operations return an error whose `details` contain
  `not in this version`.
- **`cbb_member_stop(m)`**
  Stops the member. The pointer remains valid for the rest of the process so concurrent callers
  safely receive `"the member stopped"` instead of dereferencing freed memory. Calling it again
  does nothing.

#### Member events

The member delivers JSON events from its background threads to `cbb_event_fn(ctx, event, len)`:

| `type` | Fields | Meaning |
|---|---|---|
| `write` | `text`, `kind` (`text`, `secret`, `media`), `ttl_ms` (nullable integer) | A copy arrived for the phone's clipboard. `ttl_ms` bounds secret lifetime when present. For `media`, fetch the parts with `fetch`. |
| `copy` | `copy`: `{id, origin, age_ms, kind, text, media, key, ttl_ms}` | A copy from another member became the group's current copy. `media` is the manifest (or `null`), and `key` is the copy ID used by the sync button. |
| `mute` | `muted` (boolean), `for_ms` (integer, `0` until lifted), `by` (device ID) | An admin muted or unmuted this phone. |
| `sync` | `off` (boolean), `by` (device ID) | An admin turned this phone's sync off or on. |
| `state` | `state`: same object as the `group` operation | Emitted whenever the group's records change. |
| `notice` | `notice`: same object as an item of `notices` | A group notice appeared that was not present before. |
| `root_changed` | `from` (device ID), `to` (device ID), `seq` (total root count) | The group's root changed via the recovery key. Re-emitted on every start until the app calls `root_change_seen` (tracked in `root_seen.json`). A newly joined phone receives no `root_changed` event for existing roots. |
| `log` | `line` | A log line from the member. |
| `panic` | `details` | A member background thread panicked (see [Panics](#panics)). The app reports the error and restarts the member. |

The phone member executes incoming admin commands (`cbb_member::orders`) automatically:

- `mute`, `unmute`, and `mode` (sync off/on): persisted in `mute.json` and `sync.json`, broadcast
  in the next hello, and reported through `mute` and `sync` events.
- `paste-off`, `actions-off`, and `away-off`: acknowledged as done with no local action.
- `action`, `hub`, `device`, and `paste`: refused (phones do not run quick actions, serve as hubs,
  handle leaf-device commands, or accept incoming remote paste).

The phone member caches up to eight sealed media blobs (sent or fetched) in `content/` inside its
data directory and advertises `media` in its hello so peers can fetch them.

#### Admin and root actions (`cbb_member_manage`)

`cbb_member_manage(m, request, len, sign, ctx, answer_len)` signs a group record change or an
admin command for another device using the key identified by `public` (base64 65-byte uncompressed
SEC1 point; omitted for read-only actions such as `change_preview` and `watch_actions`). `sign` is
called only during the call. Actions that send commands to another device block on the network and
must run off the main thread.

| `action` | Additional request fields | `ok` result |
|---|---|---|
| `remove` | `device` (name or device ID) | `{"device", "name"}`. Refuses removing this device or the root. |
| `rename` | `device`, `name` | `{"device", "name"}` (`name` is the device's previous name). |
| `freeze`, `thaw` | `device` | `{"device", "name"}`. Refuses freezing or thawing this device. |
| `mute` | `device`, `for_ms` (`0` for until lifted) | `{"device", "name", "status", "reason"}` (`status`: `done`, `refused`, or `failed`). |
| `unmute`, `sync_off`, `sync_on`, `paste_off`, `actions_off`, `away_off` | `device` | `{"device", "name", "status", "reason"}`. Refuses targeting this phone. |
| `paste` | `device`, `text`?, `method`? (`paste` default, or `type`), `enter`? (bool), `kind`? (`text` default, `secret`, or `media`) | `{"device", "name", "status", "reason"}`. Cleans text before signing; `media` pastes the group's current media copy and refuses `method: "type"`. |
| `ttl` | `ttl_ms`? (nullable integer), `secret_ttl_ms`? (nullable integer) | `{"ttl_ms", "secret_ttl_ms"}`. Writes a `copies` record; omitted fields keep the group's current values. |
| `hubs` | `hubs` (1 to 16 names or device IDs) | `{"hubs"}`. Root or admin with hub power; records reject phones, watches, and leaves. Renews due server credential periods when signed by the root. |
| `relay` | `relays` (list of `"address pin"` strings, `"default"` for the project's relay, or empty list for none) | `{"relays"}` (endpoint list). Root only; writes group settings and renews due periods. |
| `forwarder` | `device`, `forwarder` (`host:port` or `default`), `key` (base64 pin or `default`) | `{"device", "name", "status", "reason"}`. Root only; sends a `hub` command (field 11) to a computer allowed to be a hub, stores credentials for that forwarder, and renews due periods. |
| `hub` | `device`, `forwarder`?, `key`? (omit both for the project's forwarder) | `{"device", "name", "status", "reason"}`. Root or admin; sends a `hub` command to make a computer serve as a hub. Renews due periods when signed by the root. |
| `period` | none (requires root `public`) | `{"period_due", "period_overdue"}`. Root only; signs server credential periods that are due ([Protocol](protocol.md), section 18). |
| `make_admin` | `device`, `allow_file_key`? (bool) | `{"device", "name"}`. Root only; promotes a device using the admin key it offered when pairing with this phone (`cbb_member::offered`), checked against `cbb_core::keylevel`. |
| `key_level` | `level` (`proven`, `hardware`, or `files`) | `{"below"}` (names of admins and hubs below the new level, which stay until removed). Root only; refuses a level the root's own key store does not satisfy. |
| `attest` | none (requires root `public`) | `{"recorded", "pending"}`. Root only; verifies pending Android peer attestations and records proven keys ([Protocol](protocol.md), section 17). |
| `add_watch` | `key` (watch admin key as base64 SubjectPublicKeyInfo), `name`? (default `"Watch"`), `os`? (`watchos`, `wearos`, or `harmonyos`; default `"harmonyos"`) | `{"device", "name"}`. Root only; writes a watch record with a throwaway member key nobody stores. |
| `watch_actions` | none | `{"actions": []}`. |
| `change_preview` | `recovery` (`{"qr"}`, `{"text"}`, or `{"secret"}` base64 32 bytes), `leave_out`? (names or device IDs); no `public` needed | `{"rows": [{"device", "name", "os", "outcome", "frozen"}], "waiting"}`. Previews root replacement without signing. `outcome` is `stays`, `out`, `admin_kept`, `admin_lost`, or `frozen`. |
| `change_root` | `recovery`, `leave_out`?, `drop_hubs`? (bool), `over_waiting`? (bool), `public` (new root key) | `{"seq"}`. Makes this phone the group's root using the recovery key and signs the new root's initial records. Refuses if this phone is already the root. |
| `take_over`, `take_handed_over`, `recover`, `hand_over`, `takeover_delay`, `finish_takeover` | any | Always returns an error stating that the group's root changes only with the recovery key. |

`cbb_member_manage_watch(m, request, len, sign_body, ctx, answer_len)` takes a `cbb_sign_body_fn`
callback that sends a full record or command body to a paired watch for signing. In the current
implementation, watches display the group and sign no records or commands, so
`cbb_member_manage_watch` always returns an error without reading `request` or invoking `sign_body`
(see [Roadmap](roadmap.md)).

#### Creating a group (`cbb_group_new`)

`cbb_group_new(request, len, sign, ctx, answer_len)` (`ffi/src/found.rs`, feature `join` +
`member`) creates a group held by this phone as its root. A request without a non-empty `dir` (or
a build without `member`) is refused.

- Request: `{"dir", "name", "os", "store" ("hardware" or "file"), "root_public", "public"}`
  (`root_public` and `public` are base64 65-byte uncompressed SEC1 points; `sign` signs with the
  root key during this call only).
- Writes `group.cbor` into `dir` (refusing if `group.cbor` already exists).
- Answer: `{"group", "device", "recovery": {"qr", "text": [4 lines], "modules"}}`. The core never
  stores the recovery sheet.

#### Home pairing window (`cbb_window_*`)

An admin phone or root phone admits a device on the home network through `cbb_window_new`,
`cbb_window_next`, and `cbb_window_free` (`ffi/src/window.rs`). The member port must already be
open via `listen`.

- **`cbb_window_new(m, request, len, sign, ctx, answer, answer_len) -> cbb_window *`**
  - Request: `{"public", "addrs"?, "expires"?, "mdns"?}`. `public` is the admitting admin or root
    key (base64 SEC1), signed via `sign` until `cbb_window_free`. `addrs` lists up to four local
    IP addresses without ports. `expires` is in seconds (default `300`, maximum `3600`). When `mdns`
    is `true`, the core announces the window via mDNS (`p=1`, `f`, `i`); iOS and Android announce
    with platform DNS-SD using the answer fields instead.
  - Answer: `{"qr", "digits", "id", "fingerprint", "expires", "modules"}`. `qr` is a
    `cbb://pair?addr=...&fp=...&i=...&c=...` URI, `digits` are the six digits for manual entry,
    `id` is the 16-byte window ID in hex, `fingerprint` is the 32-byte member key hash in hex, and
    `modules` are QR rows of `'1'` and `'0'`.
- **`cbb_window_next(w, version, timeout_ms, answer_len) -> uint8_t *`**
  Blocks until the window's `version` exceeds `version` or `timeout_ms` elapses.
  - Answer: `{"version", "state", "name"?, "device"?, "error"?}`. `state` is `open`, `joining`
    (one attempt at a time; concurrent dialers receive `busy`), `done` (a device joined and the
    window closed), `failed` (an attempt failed and the window stays open), or `closed` (timeout
    or three wrong codes).
  - Admission follows `join::decide::joiner_record` (`ffi/src/pair06.rs`). When the root admits a
    device that proves an offered admin key over the session, the root saves that key via
    `cbb_member::offered`.
- **`cbb_window_free(w)`**
  Closes the window, stops its mDNS announcement, and frees it.

#### Joining a group (`cbb_joiner_*`)

A phone joins a group at home (by QR code or six digits) or remotely (by invitation) through
`cbb_joiner_new`, `cbb_joiner_new_admin`, `cbb_joiner_next`, and `cbb_joiner_free`
(`ffi/src/joiner.rs`). A phone whose `dir` already holds a group is refused.

- **`cbb_joiner_new(request, len, sign, ctx, answer, answer_len) -> cbb_joiner *`**
  - Request: `{"dir", "qr"?, "digits"?, "invite"?, "name", "os", "public"}`.
    - Home window via QR: pass `qr` (`cbb://pair?...`).
    - Home window via six digits: leave `qr` empty and pass `digits`; the core browses mDNS for 10
      seconds and requires a single advertised window.
    - Remote invitation (requires feature `tunnel`): pass `invite` (`cbb://join#...`). Invalid
      invitations fail immediately. The joiner opens the invitation's guest tunnel
      (`cbb_member::live::invite::guest_link`), dials the hub's guest address, and stores the
      invitation in `invite-guest` alongside `group.cbor` so the member reaches the hub until it
      receives a hub offer.
  - Returns the initial state in `answer`.
- **`cbb_joiner_new_admin(request, len, sign, ctx, admin_sign, admin_ctx, answer, answer_len) -> cbb_joiner *`**
  Same as `cbb_joiner_new`, except `request` also carries `admin_public` (base64 SEC1) and
  `admin_sign` signs its proof of possession over the pairing exporter (`join::sign_admin_pop`) so
  the root can later promote the phone with `make_admin`.
- **`cbb_joiner_next(j, version, timeout_ms, answer_len) -> uint8_t *`**
  Blocks until `version` advances or `timeout_ms` elapses.
  - Answer: `{"version", "state", "group"?, "device"?, "name"?, "fingerprint"?, "answered"?, "error"?}`.
    `state` is `dialing`, `done` (the verified record set is saved in `dir`; `name` is the
    admitting member), or `failed`. For remote invitations, the first state carries `fingerprint`
    (base64 key hash for the admin to verify), and `answered` becomes `true` once the hub replies
    through the guest tunnel.
- **`cbb_joiner_free(j)`**
  Cancels remaining dial attempts and frees the joiner.

#### Remote invitations (`cbb_invite_*`)

An admin phone or root phone creates a remote invitation through a connected hub using
`cbb_invite_new`, `cbb_invite_next`, `cbb_invite_answer`, and `cbb_invite_free`
(`ffi/src/invite.rs`).

- **`cbb_invite_new(m, request, len, sign, ctx, answer, answer_len) -> cbb_invite *`**
  Blocks while negotiating with the hub (call off the main thread).
  - Request: `{"public", "expires"?, "hub"?, "kind"?}`. `public` is the admitting key (base64
    SEC1), signed via `sign` until `cbb_invite_free`. `expires` is in seconds (default `3600`,
    maximum `86400`). `hub` is a hub name or device ID (empty for any connected hub). `kind` is
    `computer` (default when empty) or `phone`.
  - Answer: `{"invite", "expires", "modules"}`.
- **`cbb_invite_next(i, version, timeout_ms, answer_len) -> uint8_t *`**
  - Answer: `{"version", "state", "joining"?, "name"?, "device"?, "error"?}`. `state` is `open`,
    `joining` (`joining` is `{"device", "name", "os", "fingerprint"}`; prompt the user and call
    `cbb_invite_answer`), `done`, or `failed`.
- **`cbb_invite_answer(i, yes)`**
  Admits the joining device when `yes` is non-zero, or declines it when `0`.
- **`cbb_invite_free(i)`**
  Closes the invitation and blocks until its worker thread exits so `sign` is never invoked after
  return.

#### YubiKey recovery (`cbb_piv`)

`cbb_piv(request, len, transmit, ctx, answer_len)` (`ffi/src/piv.rs`, `cbb_member::piv::recovery`)
seals or opens a group's recovery secret on a YubiKey PIV applet ([Protocol](protocol.md), section
9). The card callback has signature:

```c
typedef int32_t (*cbb_transmit_fn)(void *ctx, const uint8_t *apdu, size_t len,
                                   uint8_t *out, size_t out_cap, size_t *out_len);
```

- Request: `{"op", "group", "pin"?, "recovery"?, "management"?, "transport"?}`.
  - `group`: the group ID in hex or its first 16 hex digits.
  - `transport`:
    - `apdu` (default): NFC or system smart-card APDU exchange; `transmit` sends `apdu` and writes
      the response with trailing status word into `out`.
    - `ccid_bulk`: raw USB-C CCID bulk transfers; `len > 0` writes to bulk-out (`*out_len = 0`),
      `len == 0` reads one bulk-in transfer (`*out_len = 0` on ~1 s timeout), while
      `cbb_member::piv::ccid` handles CCID framing and card time extensions.
    - `pcsc`: PC/SC client over `pcscd` (used on Aurora OS); the core talks to `pcscd` directly and
      never calls `transmit` (pass a valid function pointer). `open` selects the single card
      holding the group's key; `seal` selects the single PIV card (refuses two matching cards).
- Operations:
  - `seal`: requires `pin` and `recovery` (same `{qr}` or `{text}` object as `change_root`), plus
    optional `management` (base64 management key when neither factory nor PIN-protected). Writes
    to the first empty retired slot from `95` down to `82` without changing the card's management
    key. Answers `{"slot", "default_key"}`.
  - `open`: requires `pin` (and card touch). Answers `{"secret"}` (base64 32-byte recovery secret)
    for passing to `cbb_member_manage`'s `change_root`.

#### QR scanning (`cbb_qr_read`)

`cbb_qr_read(gray, width, height, stride, answer_len)` (`ffi/src/qr.rs`, feature `join`) decodes
QR codes from an 8-bit grayscale camera frame using `rqrr` (for platforms without a built-in QR
scanner, such as Aurora OS). `width` and `height` must be between `1` and `4096`, with
`stride >= width` and at least `stride * (height - 1) + width` readable bytes. Returns
`{"ok": {"texts": [...]}}` or `{"error": ...}`.

### The member's operations

A phone's `cbb_member_call` and a computer's control socket ([Protocol](protocol.md), section 8)
share one operation table. The `where` column indicates which runtime handles each row: `both`,
`phone` (the embedded member in phone apps), or `computer` (the `cbb` service on computers and
small devices). On the computer control socket, text and binary payloads follow the JSON header
according to `len`, and multi-message responses mark the final message with `done`.

| `op` | where | `args` | `ok` |
|---|---|---|---|
| `copy` | both | `text` (on a computer, the payload), `kind` (`text`, the default, or `secret`), `via` (on a computer: `copy`, the default, `phone`, or `universal-clipboard`) | `{}`. Always creates a clipboard event and writes to the member's own clipboard. |
| `copy_media` | both | On a phone: `text` (optional), `parts`: `[{type?, path?, dir?, data?, file?}]` (clipboard data in base64 `data`, or a file path on the phone in `file`, or a directory with `dir: true`). On a computer: the payload is the optional plain-text alternative, followed by `{"op":"part", part}` (`part` = `{type?, path?, dir?, size?}`), `{"op":"data"}` chunks (at most 1 MiB each, totaling `size` bytes), and a closing `{"op":"part", done: true}`. | Phone: `{"copy": {id, origin, age_ms, kind, text, media, key}}`. Computer: `{}`. Seals and caches the parts, broadcasts a `media` copy ([Wire format](format.md), section 10.3), and writes to the member's own clipboard. Fails if the copy exceeds this device's size limit, the manifest is invalid, or the byte stream does not match. |
| `sync` | both | `on` (required boolean), `for_ms` (only with `on: false`, `1` to `2 592 000 000` ms / 30 days; `0` or omitted for indefinite), `device` (computer admin socket only: target device by name or ID, without `for_ms`; phones use `cbb_member_manage`) | `{"sync_off", "sync_off_ms", "muted", "muted_ms"}` (same as `muted`). Persists the sync state in `sync.json` and announces it in the next hello. With `device`: `{}` once the target answers `done` to the `mode` command ([Protocol](protocol.md), section 15), or an error. Without `device`, allowed on the control socket without admin confirmation. |
| `muted` | both | none | `{"sync_off", "sync_off_ms", "muted", "muted_ms"}`: `sync_off` and `sync_off_ms` report whether sync is off and for how long; `muted` and `muted_ms` report whether an admin mute is active and for how long (`0` for until lifted). |
| `bug` | computer | none | Payload containing the filtered bug report JSON from a panic before the last restart (empty if none waits); see [Bug reports](#bug-reports). |
| `bug_allow` | computer | payload `{"always"}` (boolean) | `{}`. Sends the pending bug report and optionally enables automatic sending. |
| `bug_cancel` | computer | none | `{}`. Discards the pending bug report without sending. |
| `dismiss` | computer | `value`: notice `id` (base64 record ID) | `{}`. Hides a dismissable notice from `status.notices` on this device; allowed on the control socket without admin confirmation. |
| `devices` | both | none | `{"devices"}`: list of group devices `[{id, name, role, caps, os, store, skew_ms, form, os_version, version, mac, mode, muted, muted_until_ms, admin, root, frozen, online, last_seen_ms, self, listed, may_hub, forward_only, hub, hub_rank}]` (`control::Device`; empty or zero fields omitted). Combines group records with connected peers' hellos (`mode` is `shared` or `own`; `muted_until_ms` and `last_seen_ms` are Unix milliseconds, `0` for indefinite mute), followed by connected unlisted peers (`listed: false`). `hub` indicates whether the device serves as a hub as known locally (on a phone, whether the `hubs` record lists it); `hub_rank` is the 1-based hub priority order ([Protocol](protocol.md), section 11). On a phone, `skew_ms`, local `form`, and local `mac` are omitted. |
| `view` | both | `away` (optional on a phone, same object as `why`) | `{"view": {"tiles", "online", "others", "custom", "warnings?"}}`: ordered tiles and collections (`{"device"}` or `{"collection": {id, name, devices}}`), online and total peer counts, whether a custom order exists, and `warnings` matching `why` when syncing is impaired (`member/src/view.rs`; [App specification](apps.md)). |
| `arrange` | both | `arrange` (`{"op": "move"|"into"|"out"|"new"|"rename"|"ungroup"|"reset", ...}`, as in `testdata/arrangement/vectors.json`), `away` (optional on a phone) | Same as `view`, after saving the updated arrangement in `arrangement.json`. Rejects invalid edits atomically. |
| `group` | phone | none | `{group, root, root_device, me: {device, role, admin, frozen, leaf}, stop, halted, update_needed, too_old, change_arriving, key_level, ttl_ms, secret_ttl_ms, devices: [{device, name, os, role, admin, frozen, hub, offers_admin}]}`. `group` and `root` are base64; `root_device` and `device` are hex; `role` is `computer`, `phone`, `watch`, `leaf`, or `unknown`; `stop` is `none`, `secrets`, or `full`; `key_level` is `proven`, `hardware`, or `files`; `ttl_ms` and `secret_ttl_ms` are `null` when using defaults (`300 000` and `60 000` ms); `offers_admin` is `true` when the device offered an admin key during pairing with this phone and is not yet an admin. Removed devices are omitted. |
| `current` | phone | none | `{"copy"}`: the group's current copy or `null` (`{id, origin, age_ms, kind, text, media, unread, key, ttl_ms}`). `media` is the manifest (or `null`), and `ttl_ms` is the sender's stamped lifetime (or `null`). |
| `swap` | phone | `board`: current clipboard key | `{"sends", "copy"}`. Applies the phone sync button rule (`cbb_member::button`): `sends` is `true` when the phone clipboard should be sent to the group, and `copy` is the group copy to write to the phone clipboard (or `null`). The app sends first, then writes `copy`. |
| `opened` | phone | `board`, `changed` (boolean: whether the clipboard changed since the app last checked) | `{"sends", "copy"}`. Applies the foreground-open rule without swapping: if the clipboard changed and qualifies to send, `sends` is `true` and `copy` is `null`; otherwise `copy` holds the group's copy to take. |
| `took` | phone | `id`: copy ID | `{}`. Marks the copy as written to the phone clipboard or saved, preventing the button from echoing it back. |
| `fetch` | phone | `id`, `max` (maximum sealed blob bytes), `out` (path to a new directory) | `{"parts": [{type, path, dir, size, file}]}`. Fetches the sealed media blob from its origin or a peer, verifies every part hash, and extracts files into `out`. Blocks on the network. |
| `found` | phone | `key` (app identifier for the peer), `addrs` (`host:port` list, including loopback for tunnels), `device` (optional device ID) | `{}`. Starts dialing the discovered peer. |
| `lost` | phone | `key` | `{}`. Stops dialing the peer identified by `key`. |
| `listen` | phone | `port` (`0` for any available port), `kind` (`home`, default and only supported kind) | `{"port"}`. Opens the member listening port for incoming home pairing connections, closing any previous listener first. |
| `unlisten` | phone | `kind` (`home`, default) | `{}`. Closes the member listening port. |
| `pause` | phone | none | `{}`. Closes all active connections and suspends dialing while the app is in the background. |
| `resume` | phone | none | `{}`. Resumes dialing and listening. |
| `wait` | phone | `timeout_ms` (optional, default `5000`, capped at `60 000`) | `{"connected"}` (boolean). Blocks until at least one peer connects or the timeout expires. A background refresh runs `resume`, `wait`, `pause`. |
| `set_mute` | phone | `until_ms` (Unix milliseconds, or `null` to unmute) | `{}`. Sets or clears this phone's local mute state, saves `mute.json`, and sends an updated hello. |
| `peers` | phone | `all` (optional boolean to include offline peers) | `{"peers": [{device, name, role, os, key_store, mode, muted, reach}]}`. Lists peers (excluding this phone), with `reach` listing device IDs reachable through each connected peer. |
| `evidence` | phone | `evidence`: array of attestation objects for this phone's member key | `{}`. Sends `evidence` messages (t 19) to all current and future peers ([Protocol](protocol.md), section 17). Pass an empty array to clear. |
| `push_face` | phone | none | `{"face"}`: 16-byte group face tag for the push service from the newest `keys.json` (base64), or `null` until available. |
| `push` | phone | `frame` (optional base64 `push` message from `push_registration`; omit or `null` to clear) | `{}`. Verifies the registration frame and sends it to all current and future connected peers. |
| `push_renewals` | phone | none | `{"renewals": [{slot, ahead}]}`: drains `push-renew` messages received from peers since the last call (one per `slot`, base64). |
| `why` | phone | `away` (optional `AwayFacts` object overriding the member's own tunnel state: `{hub, standby, hub_device, through, hidden, relay, relay_connected, forwarder, forwarder_registered, entries_stale, error}`) | `{"why": [{code, level, until_ms?, device?, devices?, value?, detail?}]}`. Blocking reasons ordered from highest severity (`stop`, `warn`, `info`); empty when syncing works normally (`cbb_core::why`). |
| `notices` | phone | none | `{"notices": [{id, kind, args, dismissable}]}`. Active notices derived from the record set (`cbb_member::notices`): `change_arriving`, `removals_waiting`, `root_room_waiting` (`args.percent` on the root from 50% upward), `ack_owed` (`args.removals`, `args.days_left`), `frozen_holding` (`args.device`), `checkpoint_stuck`, and `returned_after_removal` (`args.device`, `args.devices`; the only dismissable notice, keyed by base64 record ID). |
| `root_change_seen` | phone | none | `{}`. Marks the pending `root_changed` event as acknowledged in `root_seen.json`. |
| `dismiss` | phone | `id`: notice record ID (base64) | `{}`. Persists the dismissal in the record set (`RecordSet::dismiss`). |
| `away` | phone | `on` (boolean) | `{"away", "period_due", "period_overdue"}`. Turns away-from-home sync on (generating tunnel keys and offering them to hubs) or off (clearing tunnel keys and offers). `away` has the `control::Away` shape (or `null` when off). Requires feature `tunnel` when `on` is `true`. `period_due` and `period_overdue` are always `false` on non-root phones. |
| `away_status` | phone | none | `{"away", "period_due", "period_overdue"}`. Returns current away-from-home status and root server-credential renewal flags. |
| `attest_status` | phone | `keys`, `status` (decoded `release::File` JSON objects for `keys.json` and `attest-status.json`) | `{"revoked", "pending"}`. Verifies and stores the Android attestation revocation list ([Protocol](protocol.md), section 17) and returns the revoked count and pending peer attestation count. Requires feature `tunnel`. |
| `attest` | phone | none | `{"pending"}`. Returns how many Android peer attestations wait for root verification (`cbb_member_manage`'s `attest`). Requires feature `tunnel`. |
| `version` | computer | none | `{status}` with `role`, `os`, and `version` set. Works whether or not the computer is in a group. |
| `paste` | computer | none | `{kind}` plus UTF-8 payload of the member's own clipboard text (or the group's current text while sync is off). Errors with `the clipboard is empty` if none is available, or points to `cbb paste -o DIR` for media without text. |
| `copied_media` | computer | Same stream as `copy_media` | `{}`. Watcher report of a clipboard image or file change: sends to the group according to sync rules ([Protocol](protocol.md), section 5) without writing back to the local clipboard. |
| `paste_media` | computer | `value` (optional event ID for a remote paste copy) | Streams `{kind: "media"}` plus plain-text alternative payload, then `{part}` and data chunks (up to 1 MiB each), ending with `{}`. Fetches missing parts first when reading the clipboard. |
| `config` | computer | `name`? (`max-copy` or `max-copy-away`), `value`? (size string such as `200MiB`) | `{status}` with `status.media` (`{max_copy, max_copy_away, fetching?, fetched?, from?, failed?}` in bytes). Saves the setting first when `name` is given. |
| `status` | computer | none | `{status}` (`member/src/control.rs`): `{device, quiet?, group?, relay_group?, role, os?, peers?, version, left_old_group?, mode?, sync_until_ms?, bug?, muted?, muted_until_ms?, away?, paste?, keyboard?, release?, update?, tvs?, actions?, stop?, removed?, frozen?, media?, key_level?, key_problem?, ttl_ms?, secret_ttl_ms?, conflicts?, newer?, cert_ends_ms?, unreached?, port?, why?, notices?}`. When away-from-home sync is on, `away` carries `{hub?, standby?, port?, clients?, obfuscated?, vless?, endpoints?, hub_device?, through?, keys_in_file?, forwarder?, relay?, error?, detail?, allow?}`, where `forwarder` is `{endpoint, registered?, seen?, entries_stale?, error?, detail?}` and `relay` is `{endpoint, connected?, online?, error?, detail?}`. |
| `leave` | computer | none | `{}`. Deletes keys and group files, disables remote paste and quick actions, and restarts in no group. Refused on the root while other devices remain; accepted when the group file is damaged. |
| `new` | computer | none | `{status}`. Creates a new group with this computer as its root. Only valid when in no group. |
| `pair` | computer | none (`admins` is accepted for compatibility and has no effect; the root promotes devices with `make_admin`) | Opens a 5-minute home pairing window on the member port ([Protocol](protocol.md), section 6): streams `{code, invite, address, expires}`, optional `{refused}` entries on failed attempts (three wrong codes close the window), and `{name, done: true}` on success. Root or admin only; closing the connection closes the window. |
| `join` | computer | `{code, address?}` or `{invite, consent}` | Joins by home window six-digit `code` (browsing mDNS for `p=1` if `address` is empty) or by remote `invite` (`cbb://join#...`, requiring `consent`, streaming `{fingerprint}` before `{}`). Requests with `listen` or a `pair` carrying `code`, `addrs`, or `fingerprint` are refused. Closing the connection cancels. |
| `invite` | computer | `expires`? (seconds, default `3600`, maximum `86 400`) | Hub with admission authority only. Streams `{invite, expires}`, then `joining` (`{id, name, os, fingerprint}`) for each candidate (client replies with `{"op": "answer", consent}`), and finishes with `{name}`. Closing the connection cancels. |
| `mute` | computer | `device` (name or device ID), `for_ms`? (`1` to `2 592 000 000` ms; `0` or absent for indefinite) | `{}` or error. On an unfrozen admin, sends a signed `mute` command to `device`, or mutes this computer directly (saved in `mute.json`). Admin socket (or control socket for this device itself). |
| `unmute` | computer | `device` | `{}` or error. Sends a signed `unmute` command to `device`, or clears this computer's own mute (only an admin can clear a mute placed by another admin). |
| `paste_on` | computer | `device`, `method`?, `enter`?, `kind`? + UTF-8 payload (omitted when `kind` is `media`) | `{}` once `device` answers `done` to the signed `paste` command ([Protocol](protocol.md), section 15). Text is sanitized before signing. Admin socket only. |
| `paste_receive` | computer | `name` (`on` or `off`), `enter`?, `console`?, `no_lock_check`?, `device`?, `all`? | `{status}`. `on` saves local remote-paste settings (`no_lock_check` permits pasting when session lock status cannot be queried); `off` disables locally or sends `paste-off` to `device` or `all`. Admin socket only. |
| `keyboard` | computer | `name`? (`on`, `off`, `pair`, `type`, or empty for status), `keyboard`? (`{layout?, rate?, pastes?}`) + payload for `type` | `{status}`. Manages the Linux BlueZ Bluetooth HID keyboard (`pair` stays discoverable for 2 minutes). Admin socket only. |
| `remote` | computer | `name`? (`add`, `code`, `cancel`, `remove`, `pastes`, `type`, or empty), `address`?, `value`?, `new_name`?, `consent`?, `code`?, `device`? + payload for `type` | `{status}` with `status.tvs` (`[{name?, kind, host, pastes?, pairing?}]`). Pairs and drives Android TV / Google TV and Roku (`value: "roku"`, requires `consent`) devices on the home network. Admin socket only. |
| `rename` | computer | `device` (name or ID), `name` (new name) | `{name}` (previous name). Signs a new `device` record with the updated name. Admin socket only. |
| `network` | computer | none | `{status}`. Marks currently connected interfaces as known home networks so the service advertises and accepts connections on them. Admin socket only. |
| `answer` | computer | `consent`? (boolean) | None. Responds to an interactive prompt on an open `invite` connection. |
| `action_set` | computer | `actions`: single-element array `[{name, on?, by?, any_key?, command?}]` | `{status}`. Configures a preset or custom quick action locally ([Protocol](protocol.md), section 15). Admin socket only. |
| `action_remove` | computer | `name` | `{status}`. Removes a custom quick action (presets can only be turned off). Admin socket only. |
| `action_on` | computer | `name`, `device` | `{}` once `device` completes the signed `action` command. Admin socket only. |
| `actions_off` | computer | `device` or `all` | `{status}`. Disables all quick actions locally or via signed commands to `device` or `all`. Admin socket only. |
| `release` | computer | payload: JSON `{keys, channel, release}` ([Protocol](protocol.md), section 16) | `{}`. Verifies the signed release, keeps it if newer, and relays it to peers. |
| `release_file` | computer | `value` (archive SHA-256), `part` (with `size`), followed by `data` chunks | `{}`. Stores a verified release archive to serve peers. Admin socket only. |
| `keys` | computer | `name` (`paste` or `enter`), `value` (user ID), `keys` (inject grant token) | `{}` when the grant matches an active `desktop` inject for that user on its first paste or permitted Enter press. Accepted only from root on the control socket (used by the uinput helper). |
| `release_held` | computer | none | Payload: held release JSON `{keys, channel, release}`, or error if none is held. |
| `entries` | computer | payload: signed entry points JSON `{keys, entries}` ([Protocol](protocol.md), section 16) | `{}`. Verifies, stores if newer, and relays to peers. |
| `entries_get` | computer | none | Payload: held signed entry points JSON `{keys, entries}`, or error if none or expired. |
| `release_want` | computer | none | Payload: JSON array of up to 16 archive names requested by peers' hellos that this hub lacks, or `null` on non-hubs. Admin socket only. |
| `update_way` | computer | none | Payload: JSON VLESS settings with the group's VLESS user ID for `cbb update`, or empty if VLESS is unavailable. Admin socket only. |
| `confirm` | computer | `value` (operation name), `name`?, `device`? | `{name, value}`. On Windows, returns `kept` (within 5-minute window), `register` (no Windows Hello key registered), or `sign` with a 32-byte base64 challenge valid for 120 seconds. Returns an error on other platforms ([Protocol](protocol.md), section 8). |
| `confirm_key` | computer | `name` (user SID), `value` (base64 PKCS #1 `RSAPublicKey`) | `{}`. Registers a Windows Hello public key for confirming admin actions. Admin socket only. |
| `release_get` | computer | `value` (archive SHA-256) | Streams `{part}`, raw archive chunks, and closing `{}` from local cache or peers. |
| `watch` | computer | `kind`, `via`, `inject` (`desktop`, `tmux`, or `console`), `paste_only`, `act`, `images`, `files`, `html` + initial clipboard payload | `{}` (without `done`), then enters the watcher stream protocol ([Protocol](protocol.md), section 8). |
| `away` | computer | `name`: `on` (`consent`), `off` (`device`?), `hub` (`addrs`, `port`, `forwarder`, `forwarder_key`, `obfuscate_off`?, `vless_off`?, `keep`?, `consent`?; or with `device`, `forward_only`?), `hub-off` (`device`?, `force`?), `move` (`device`, `forwarder`?, `forwarder_key`?, `addrs`?), or `relay` (`relay`, `relay_key`, `relays`?, `consent`) | `{status}` (or `{relays}` when the root configures relays). Manages away-from-home tunnels, hubs, forwarders, and relays ([Protocol](protocol.md), sections 11, 13, 14, and 15). Admin socket only. |
| `remove` | computer | `device` (name or device ID, case-insensitive) | `{name}` (removed device's name). Root or admin with required removal powers; refuses removing this device or the root. Admin socket only. |
| `make_admin` | computer | `device`, `allow_file_key`? (bool) | `{name}`. Root only; promotes a device using the admin key it offered when pairing with this root (`offered.json`). Admin socket only. |
| `take_over` | computer | `device` | Always returns an error directing the user to `recover` (the root changes only with the recovery key). |
| `takeover_delay` | computer | `value` | Always returns an error directing the user to `recover`. |
| `key_level` | computer | `value` (`proven`, `hardware`, or `files`) | `{below}` (`below` lists names of admins and hubs below the new level). Root only; signs a `settings` record. Admin socket only. |
| `ttl` | computer | `value`: `"COPY [SECRET]"` durations (`1m`–`1h` for copies, `5s`–`1m` for secrets, `-` to keep a value) | `{}`. Root or admin; signs a `copies` record ([Protocol](protocol.md), section 10). Admin socket only. |
| `hubs` | computer | `hubs`: 1 to 16 names or device IDs in priority order | `{}`. Root or admin with hub power; signs a `hubs` record. Admin socket only. |
| `freeze` | computer | `device` | `{name}`. Unfrozen admin; freezes another admin computer (never the root or an admin phone). Admin socket only. |
| `thaw` | computer | `device` | `{name}`. Root only; ends all freezes on `device`. Admin socket only. |
| `resolve` | computer | none | `{name}` (comma-separated device names). Root only; voids both forked histories of every key that signed two. Admin socket only. |
| `recover` | computer | payload: recovery sheet text or QR code (or `name: "yubikey"` with YubiKey PIN as payload), optional `leave` (names or device IDs to exclude) | `{done: true}`. Promotes this computer to the group's root via the recovery key, excluding devices in `leave`, and restarts. Refuses if already the root. Admin socket only. |
| `hand_over` | computer | `device` | Always returns an error directing the user to `recover`. |

## Operations

These operations are dispatched by `cbb_core::api::call` (`core/src/api.rs` and `core/src/api/*.rs`).
Group record operations (`set_*`) appear in [The group (records v3)](#the-group-records-v3).

| `op` | `args` | `ok` |
|---|---|---|
| `version` | none | `{"abi", "core", "source"?}`: ABI version (`1`), crate version (`cbb_core::api::VERSION`), and commit hash when `CBB_SOURCE` was set at build time (omitted otherwise). |
| `read_invite` | `text`: remote invitation URI (`cbb://join#...`, [Protocol](protocol.md), section 12) | `{"invitation": {"phone"}}` (`phone` is `true` for a phone invitation) when a guest path is present; otherwise `{"refused": {"reason", "message"}}` (`invite/guest`, `invite/shape`, `invite/path`, or CBOR rule). A refused invitation returns `ok`, not `error`. |
| `parse_body` | `kind` (`credential`, `keys`, `release`, `channel`, `attest-status`, `entries`, `zxnext`, or `manifest`), `body` (base64) | `{"kind", "value"}`: decoded body fields after strict validation (see [Signed bodies](#signed-bodies)). Unknown `kind` returns code `1` (`request`); invalid body (and `credential`, which has no decoder arm) returns code `16` (`signed`). |
| `release_check` | `keys`, `channel`, `release` (raw fetched file bytes, base64), `name` (channel name, default `""`), `now_ms`, `seen`? (previous state), `roots`? (`[{alg, key, name, use}]`, overrides pinned roots for tests) | `{"value", "seen"}`: verified `release.json` body and updated `Seen` state. Missing file arguments return code `1`; malformed or unverified files return code `16` (`signed`). See [Release files](#release-files). |
| `release_check_status` | `keys`, `status` (`attest-status.json`), `now_ms`, `seen`?, `roots`? | `{"value", "seen"}`: verified revocation list body and updated `Seen`. |
| `release_check_entries` | Either (`keys` and `entries`) or `set` (base64 JSON `{"keys", "entries"}` as relayed by members, mutually exclusive with `keys`/`entries`), plus `now_ms`, `seen`?, `roots`? | `{"value", "seen"}`: verified entry points body and updated `Seen`. |
| `release_named` | `channel` (raw channel file bytes, base64) | `{"release"}`: version string read from the channel file without verifying signatures, so a client knows which `release.json` to fetch before calling `release_check`. Malformed input returns code `16`. |
| `new_device_key` | none | `{"pkcs8", "public"}`: new P-256 device key (base64 PKCS #8 DER and 65-byte uncompressed SEC1 point) for devices that store keys in a file. |
| `sign_digest` | `pkcs8` (base64 PKCS #8), `digest` (base64, 32 bytes) | `{"sig"}`: base64 DER ECDSA P-256 signature over `digest`. Code `1` if the key or digest length is invalid. |
| `why` | `facts` (all fields optional: `in_group`, `removed`, `frozen`, `stop`, `admins_conflict`, `root_two_histories`, `recovery_fork`, `change_arriving`, `checkpoint_stuck`, `owner_disagrees`, `no_secrets_here`, `nothing_here`, `copy_waits`, `update_needed`, `sync_off`, `sync_until_ms`, `muted`, `muted_until_ms`, `newer`, `update`, `connected`, `devices: [{name, online, sync_off, muted}]`, `quiet`, `unreached`, `away`), `now_ms` | `{"why": [{code, level, until_ms?, device?, devices?, value?, detail?}]}`: blocking reasons ordered from highest severity (`stop`, `warn`, `info`), verified against `testdata/why/vectors.json`. Drivers fill record-derived facts with `cbb_core::why::group_facts` and add `owner_disagrees` (`State::disagrees`), `copy_waits`, and `checkpoint_stuck` (`RecordSet::stuck_checkpoints`). |
| `keyboard` | `layout` (`us` or `ru`), `text`? (default `""`) | `{"reports", "untypeable", "map"}`: base64 8-byte HID boot-keyboard reports (key down, then all keys up), any characters absent from `layout` (in which case `reports` is empty), and the base64 HID report descriptor (`cbb_core::keyboard`). Unknown `layout` returns code `1`. |
| `bug_report` | `input` (`{kind ("panic"|"error"), code?, name?, message?, details?, app ("ios"|"android"|"aurora"|"harmonyos"|"mac"|"tray"|"cbb"), version, build?, os?, os_version?, model?, arch?, log?, names?, now_ms?}`), `state`? | `{"report", "fingerprint", "post", "url", "action" ("ask"|"send"|"skip"), "offer_always", "fixed_in"}`: filtered report, break fingerprint, sealed POST body (empty if the build has no robot public key), recommended UI action, whether to offer "Always allow", and any known fixing version (see [Bug reports](#bug-reports)). |
| `bug_allow` | `state`?, `always`? (default `false`) | `{"state"}`: records user consent to send a report and optionally sets automatic sending. |
| `bug_sent` | `state`?, `fingerprint`, `version`, `post`?, `ok` (bool), `fixed_in`?, `now_ms` | `{"state"}`: marks the report sent (`ok: true`) or queues it for retry (`ok: false`). |
| `bug_pending` | `state`?, `now_ms` | `{"queue": [{fingerprint, version, post, at_ms}], "state"}`: queued reports after pruning entries older than seven days. |
| `push_key` | none | `{"key", "send_key", "slot"}` (all base64): new 32-byte push key, P-256 PKCS #8 send key, and 16-byte slot (see [Push](#push)). |
| `push_limits` | `env` (integer from the push environment registry) | `{"known", "body", "token", "kinds"}`: whether the core supports `env`, maximum sealed body bytes, maximum token bytes, and defined `kinds` bitmask. |
| `push_registration` | `now_ms`, `highest_seq`?, `restart`? (bool; `true` once after a `push-renew` with `ahead`), `kinds` (`0` turns push off); when `kinds != 0`, also `env`, `key` (32 bytes, base64), `send_key` (PKCS #8, base64), `slot` (16 bytes, base64), `face` (16 bytes, base64), `challenge`? (16 bytes, base64), and either `token` (base64) or `unifiedpush` (`{url, p256dh (65 bytes), auth (16 bytes)}`) | `{"frame", "seq", "highest", "key_hint"?}`: base64 `push` message frame (t 28), assigned `seq`, updated `highest` sequence number to persist before sending, and (when `kinds != 0`) the 8-byte base64 send-key hash prefix `key_hint`. Code `18` (`push`) if any field violates format rules. |
| `push_open` | `keys` (`[{key, seq}]`, current key first), `body` (base64), `me` (16-byte device ID, base64), `origins`? (`[{key, rights, frozen?}]`), `sealing`? (`[{epoch, secret}]`), `too_old`?, `halted`?, `hints_only`?, `now_ms`?, `window_ms`? | `{"kind", "key_index", ...}`: `copy` (`id`, `origin`, `type` (`text`, `media`, `files`, `other`), `secret`, `ttl_ms`?, `text`?), `waits` (`id`, `origin`), `event` (`id`, `event`, `device`?, `time_ms`?), or `hint`. Omitting `halted`, `hints_only`, `now_ms`, or `window_ms` (or setting `halted: true`, or receiving an event older than 24 h or more than 5 min ahead) yields `hint`. Code `18` if `me` is invalid or no push key opens `body`. |

`cbb version` prints the embedded core version on a second line:
`rules: the Rust core <version>, abi 1, source <commit> (built in)`. Release and CI builds pass the
commit in `CBB_SOURCE`; other builds print `source unknown`.

## Error codes

Error codes and names are stable; new codes are appended to their range (`core/src/api.rs`).

| Code | Name | Meaning |
|---|---|---|
| `1` | `request` | The request is not a valid JSON object of the expected shape, or an argument is missing or invalid. |
| `2` | `abi` | The request's `abi` does not match the core's ABI (`1`). |
| `3` | `op` | The core has no operation with that name. |
| `4` | `too_large` | The request exceeds 8 MiB (`MAX_REQUEST`). |
| `5` | `panic` | A panic occurred while handling the request, and the request had no effect; `details` identifies the panic and location (see [Panics](#panics)). |
| `10` | `body` | A record body or write operation failed validation. |
| `11` | `cert` | A certificate failed validation. |
| `14` | `saved` | The group's saved set file cannot be read, has an unsupported version, or fails its local-key pin check. |
| `16` | `signed` | A non-record signed body (release file, channel, entries, revocation list, or manifest) failed validation or verification. |
| `18` | `push` | A push registration could not be constructed from its fields, or a push body could not be opened with any supplied push key. |

## Push

When a phone app is closed, peers wake it through its platform push service
([Wire format](format.md), section 9.6; `cbb_core::push`). The phone generates a per-group push key
and slot plus a per-token send key (`push_key`), builds a signed `push` message frame
(`push_registration`), distributes that frame through the member's `push` operation, and opens
incoming payloads with `push_open`.

### Notification extension isolation

A notification extension calls only `push_open`. It holds only what is required to decrypt a push
body and an inline copy:

- The group's push keys and the token's send key (which signs only push registrations).
- The phone's sealing secrets for epochs still inside the group's active window.
- The saved peer origins and copy window parameters.

The extension never receives the member key, any admin or root key, or the recovery secret. The
internal `KeyStore` inside `push_open` rejects signing and key storage. The app updates the epoch
secrets whenever its sealing key rotates and deletes expired epochs. Notification text always comes
from the app's translations, except for `copy` text; apps never display a secret's text in a
notification, and the extension deduplicates notifications by ID.

### Platform vaults and hints-only marks

- **iOS / iPadOS**: `PushVault` (`apps/ios/CBBKit`) stores push material in keychain access group
  `tools.cbb.push`, shared between the app and `apps/ios/NotificationService`. Member, admin, and
  root keys stay in the app's primary keychain group (`KeychainIdentity.accessGroup`), which the
  extension cannot access. The extension uses app group `group.tools.cbb.push` for shown IDs and
  hints-only marks; the main app's group directory (`group.tools.cbb`) is inaccessible to it.
  `App/PushSetup.swift` manages one sender identity (token, platform, send key, `key_hint`, last
  challenge) across all groups and per-group push keys, slots, and registrations.
- **Android**: `PushVault.kt` seals the push vault under a dedicated Android Keystore AES-256-GCM
  key excluded from backups, and `PushSetup.kt` mirrors iOS behavior. Full builds use FCM with
  Firebase identifiers from build properties (`cbb.firebase.*` or `CBB_FIREBASE_*`, never a
  committed `google-services.json`, disabling push if absent). F-Droid builds use UnifiedPush via
  the user's installed distributor.

Both apps fetch the group's push face via `push_face`, pass each saved registration to the member
via `push`, and respond to `push-renew` notices drained from `push_renewals`. Apps regenerate a
registration only when its inputs change (token, push switch, challenge, or membership change) or
upon `push-renew`.

On any device removal or root change, the app draws a new push key and drops the previous one so
removed members cannot open or forge notifications. Between receiving a push event for a removal,
root change, or group stop and syncing the records, the extension marks the group `hints_only`
(`PushMarks`). A mark clears once the app applies the change and rotates the push key, or syncs
newer records with a peer other than the named device (staying connected for at least 30 s) that
contradict the event, or one week after the first sync with another peer following the mark.
Leaving a group saves a `kinds: 0` deregistration frame, then erases the group's push keys,
secrets, marks, and send key (retaining the platform token until leaving the last group).

On UnifiedPush (where anyone knowing the endpoint URL can deliver messages), the app accepts at
most one new challenge per hour, triggers at most one challenge-only re-registration per challenge
period under a given send key, and requests a new endpoint after applying a device removal.

### Member sender and push service

Computers and hubs send pushes through `member/src/pusher.rs` (`member/src/mesh/push.rs` wires the
record set to it) to the `cbb-push` service (`member/src/pushd`).

The sync layer interacts with `pusher.rs` solely through its seam:

- `registration`: records a `push` message (t 28) received on a device's own connection.
- `connected` / `left`: tracks connected peers so connected phones receive no pushes.
- `renewals`: returns `push-renew` messages (t 29) to send when a peer reconnects after `stale` or
  `ahead` responses.
- `forget`: drops registrations for removed or frozen devices.
- `copy`: sends a sealed copy body (`cbb_core::push::copy_body`) to eligible offline readers after
  a 2-second grace delay.
- `event`: sends record-change events (`joined`, `removed`, `root`, `own_record`, `stopped`) keyed
  by the first 16 bytes of the record ID and stamped with the record's own timestamp. Hubs send
  events; when a group has no hub, the root or an admin sends them.

Every honest sender derives identical ciphertext bytes for a given copy or event (deterministic
nonce from plaintext, copy reduced with age 0, record timestamp for events), allowing `cbb-push` to
deduplicate repeats in memory (repeats with a longer TTL pass once; an in-flight duplicate returns
`failed` with retry wait). Members retain the previous period's face in `push-previous.cbor` for
outstanding registrations until they expire or the phone re-registers.

`cbb-push` persists per-token key bindings (`member/src/pushd/binding.rs`, requiring `-new-state`
on first start):

- Before any send key is confirmed, any key may send and receives a stateless HMAC challenge bound
  to `(service secret, token, send key, binding generation, 14-day period)` (verified across the
  current and previous period).
- A registration signature covering that challenge confirms the send key and increments the
  generation, invalidating earlier challenges.
- After confirmation, only the confirmed send key can send bodies; other keys receive `stale` (`7`)
  and trigger a challenge-only push within budget.
- Sequence numbers (`seq`) are tracked per `(send key, slot)`. A `seq` more than 24 hours ahead of
  the service clock returns `ahead` (`8`), causing the member to send `push-renew` with `ahead` and
  accept one clock-based `restart` registration. Unsupported send-key algorithms return `key` (`6`).
- Every registration signature covers the connection's `face`; mismatches are refused, and eight
  refusals close the connection.
- Rate limits apply per tag, per `(group, token)` under confirmed and unconfirmed keys, and per
  payer (IPv4 address or IPv6 `/64`), evicting the heaviest payer's oldest entry when shared tables
  fill.

Challenge delivery by platform:

- **APNs**: payload key `k` (24 bytes base64: 16-byte challenge + 8-byte `key_hint`), or a
  background push (`content-available`, priority 5); sent over HTTP/2 with the team ES256 key.
- **FCM / Push Kit**: data key `k`; FCM uses the HTTP v1 API with RS256 service-account OAuth
  tokens (cached until 5 minutes before expiry), data-only messages (`HIGH` priority for bodies,
  `NORMAL` for challenge-only), no collapse key, dropping `UNREGISTERED` or `SENDER_ID_MISMATCH`
  tokens.
- **UnifiedPush**: decrypted payload consists of typed chunks `(1-byte kind, 2-byte length, bytes)`:
  kind `1` = body, kind `2` = challenge, kind `3` = padding (unknown kinds are skipped).

New event types keep fields 3–7 (`16-byte id`, `event` number, `16-byte device`, `time_ms`) so
older clients treat unrecognized events as neutral `hint` notifications.

## Panics

`core/` and `ffi/` forbid panic-inducing operations outside tests. As a defense against bugs, `ffi/`
wraps every C entry point in a panic guard (`ffi/src/guard.rs`):

- Phone libraries build with `CARGO_PROFILE_RELEASE_PANIC=unwind` (`ffi/bind.sh` and Android Gradle
  config). A panic inside any C call becomes an error JSON answer with code `5` (`panic`) and
  `details` formatted as `panic: <message> at <file>:<line>:<column> in thread <name>`.
- Functions that can only return `NULL` on failure record the same answer for `cbb_last_panic`.
- A panic on a member background thread emits a `{"type": "panic", "details": "..."}` event so the
  app can display the error and restart the member.
- `cbb_test_panic` triggers a controlled panic inside the guard so language wrappers can test error
  handling and recovery.
- On computers, `cbb` builds with `panic = "abort"`. Its panic hook writes `panic.json` before the
  process exits, and the system service manager restarts `cbb`.

## Secrets

The core wipes secrets on drop using `zeroize` (`core/src/secret.rs`) or the cryptographic crates'
own zeroizing types (`p256`, `x25519-dalek`, `hpke`, `ml-kem`, and cipher key schedules):

- CPace passwords, scalars, shared points, and derived keys.
- TLS exporter master secrets and derived keys.
- Per-copy derived keys, recovery keys and sheet input buffers, and invitation secrets.
- Secret JSON request fields (`secret`, `key`, `pkcs8`) and their base64 buffers.

No `Debug` implementation prints secret bytes (they render as `<N secret bytes>` or `<hidden>`),
and no error message includes secret material. `ffi/` copies every outgoing answer to its exact
length (zeroing any oversized `Vec` buffer) and wipes the answer buffer inside `cbb_free`.

Secrets *returned* by the core (such as generated PKCS #8 keys, sealing secrets, or opened recovery
secrets) are owned by the caller, which is responsible for storing and wiping them.

All comparisons involving secrets or authenticators run in constant time via
`cbb_core::secret::ct_eq` (backed by `subtle`) or library verification primitives: record and pin
marks, CPace and tunnel confirmation tags, and AmneziaWG `mac1` in `member/`. Public values (key
hashes, device IDs, and server period tags) use ordinary equality (`==`). Timing tests in
`core/src/secret.rs` use Welch's t-test (dudect methodology) and run on demand:

```sh
cargo test -p cbb-core --release -- --ignored timing --test-threads=1
```

## Bug reports

When a panic (code `5`) or unexpected error occurs, release builds can send an encrypted,
anonymous bug report to `https://bug.cbb.tools/` (`cbb_core::bug`, `core/src/bug.rs`). Debug builds
display and log full error details without prompting to send reports.

In release mode, the app prompts: *"Oops, something broke. Sorry! Allow us to send a short report"*
with **Allow**, **Cancel**, and **Technical details** (showing the filtered report as it will be
sent). After two allowed reports, the dialog offers **Always allow** (off by default).

### Filtering and sealing

`bug_report` builds a JSON report capped at 160 KiB (`MAX_REPORT`), keeping up to 300 log lines
(`MAX_LINES`) of at most 400 bytes (`MAX_LINE`), dropping the oldest lines first to fit. Before
sealing, the filter scrubs every field and log line:

- IPv4, IPv6, and MAC addresses (including inside `key=value` tokens and URLs).
- Local network hostnames (`.local`, `.lan`, `.home`, `.box`, and similar suffixes).
- Email addresses, long numeric codes, long hex strings (device IDs and fingerprints), and
  high-entropy base64 strings (keys, secrets, and invitations).
- Values of named keys (`ssid`, `host`, `peer`, `server`, `device`, `user`, and related keys) in
  `key=value`, `key:value`, or `key: value` forms, plus addresses following any `key:` prefix.
- Non-Latin words (logs are English, so non-Latin tokens are treated as user text), usernames in
  home directory paths, and every string passed in `input.names` (case-insensitive and hyphenated
  hostname form, e.g. `Office PC` and `office-pc`).
- Panic messages retain only standard-library panic kinds (such as `index out of bounds` or
  `called Result::unwrap() on an Err value`) and replace custom panic messages with `"a panic"`,
  while preserving file, line, column, and thread name.

Because filtering matches text patterns, programs log user-supplied names only under named fields
and pass all known device names in `input.names`. Clipboard text never enters logs.

The filtered report is sealed to `cbb_core::bug::ROBOT_KEY_B64` using `crate::seal` (HPKE with
X-Wing, HKDF-SHA256, and ChaCha20-Poly1305; associated data `cbb bug report v1`). When
`ROBOT_KEY_B64` is empty in a build, `post` is empty and `action` is `skip`.

### Posting, state, and receiver

The HTTP POST body is `{"v": 1, "fingerprint", "version", "sealed"}`, at most `MAX_POST` bytes.
The 16-hex-character `fingerprint` hashes the kind, error name, location, and first detail line
with numbers stripped so each `(fingerprint, version)` sends at most once. The receiver answers
`{"fixed_in": "..."}` from `fixed.json` when a fixing release exists. Undelivered reports stay in
`state` for up to 5 reports and 7 days (`bug_pending`).

On computers, the `panic = "abort"` hook writes `panic.json` into the state directory. After
restart, `status.bug` is `true`; the Mac and tray apps query `bug`, prompt the user, and call
`bug_allow` or `bug_cancel` (or send immediately if **Always allow** is set).

On `cbb.tools`, nginx (`packaging/linux/nginx-bug.conf`, logging no client IP addresses, rate
limiting each IPv4 address or IPv6 `/64` to 6 requests/minute) forwards POSTs to `cbb-bug`
(`member/src/bugd.rs`, `packaging/linux/cbb-bug.service`):

- Rejects bodies larger than `2 * MAX_POST` (`413`).
- Stores at most 20 reports per `(fingerprint, version)` per day (`PER_BREAK`); extras return `200`
  and are discarded so clients do not retry.
- Returns `503` (so clients retry later) once daily storage reaches 5000 reports (`PER_DAY`), total
  disk usage reaches 2 GiB (`MAX_TOTAL`), an IPv4 address or IPv6 `/64` reaches 100 reports/day
  (`PER_SOURCE`), or an IPv6 `/48` reaches 500 reports/day (`PER_WIDE`), tracked in memory per day
  via nginx prefix headers.
- Deletes day directories older than 30 days (`KEEP_DAYS`).
- Offline key generation and decryption: `cbb-bug keygen SECRET` creates the robot keypair;
  `cbb-bug read SECRET FOLDER...` decrypts copied reports.

## The group (records v3)

The `set_*` operations expose group record evaluation and writing (`cbb_core::records`,
`core/src/api/set.rs`) over a serialized set file (`cbb_core::setfile`). Keys, key hashes, record
IDs, device IDs, and digests are base64; P-256 keys use 65-byte uncompressed SEC1 points, and the
second half of the recovery key (`recovery2`) is an SLH-DSA public key.

Every call except `set_new` takes `set` (base64 set file) and optional `local` (base64 32-byte
local key). Mutating calls return the updated `set` together with the group view.

### Set file format

A set file (`core/src/setfile.rs`) is a single canonical CBOR map:

| Key | Value |
|---|---|
| `1` | Format version (`1`). Newer versions fail with an update error. |
| `2` | Group's first root key. |
| `3`, `4` | Recovery key halves (`K1` P-256, `K2` SLH-DSA). |
| `5` | Optional local-key pin (`records::pin_mark` HMAC over keys 2–4). If `local` is supplied and the pin is missing or invalid, loading fails with code `14` (`saved`). |
| `6` | Records in dependency order: `[envelope]` or `[envelope, mark]`. Records with a valid local mark skip signature re-verification; all others verify as from a peer. |
| `7` | Root-change device lists referenced by records. |
| `8` | Removal records retained for notices. |
| `9` | Dismissed notice record IDs. |
| `10` | Devices admitted via each root change: `[change_id, seq, [key_hash...]]`. |
| `11` | Newest applied root change and prior devices: `[change_id, seq, [device_id...]]`. |

### Signing in rounds

Root, admin, and new-root private keys stay outside the core. Write calls (`set_write`,
`set_remove`, `set_change`) return `{"sign": [{"key", "digest"}]}` whenever signatures are needed.
The caller signs each 32-byte `digest` with the indicated P-256 `key` and retries with the same
arguments plus `sigs`: `[{"digest", "sig"}]` (`sig` as base64 DER or 64-byte raw `r ‖ s`). Because
record IDs cover only record bodies, digests remain identical across rounds; an admin's first
record after its grant requests its acknowledgement signature first, then the record's signature in
the next round.

### Set operations

| `op` | `args` (besides `set` and optional `local`) | `ok` |
|---|---|---|
| `set_new` | `root`, `recovery`, `recovery2`, `local`? (no `set`) | View fields + `set`. |
| `set_add` | `records`? (base64 envelopes), `lists`? (base64) | View fields + `set`, `changed` (bool), `stored` (record IDs), `refused` (`[{id (nullable), why ("group"|"unknown_signer"|rule)}]`). Runs multiple passes until no more records apply. |
| `set_view` | none | View fields. |
| `set_records` | `peer`? (base64 member key hash) | `{"records", "lists", "digest"}` in dependency order (filtered for `peer` when given). |
| `set_write` | `signer`, `record`, `time_ms`, `sigs`? | `{"sign": [...]}` or view fields + `set`, `records`. `record` is tagged by `type`: `device` (`key`, `name`, `role` (`member`, `phone`, `watch`, `leaf`), `rights`? (`read`, `send`, `hub`, `secrets`), `caps`? (`admin`, `dials`, `hub`), `os`?, `store`? (`file`, `hardware`, `rootless`, `proven`), `admin`?, `admin_kind`? (`watch`, `computer`, `phone`; required with `admin`), `holds_root`?, `guarded`?, `replaces`?), `freeze` (`keys`), `thaw` (`ids`), `resolve` (`ids`), `settings` (`key_level`?, `min_rules`?, `shared`?; preserves existing `servers`), `copies` (`ttl_ms`, `secret_ttl_ms`?), `hubs` (`hubs`: base64 device IDs), `ack` (`spare`?), or `checkpoint`. |
| `set_remove` | `signer`, `keys` (base64 member key hashes), `time_ms`, `sigs`? | `{"sign": [...]}` or view fields + `set`, `records`. |
| `set_dismiss` | `id` (base64 record ID) | View fields + `set`. |
| `set_change_preview` | `leave_out`? (base64 member key hashes) | `{"preview": [{"device", "outcome", "frozen"}]}`. `outcome` is `stays`, `out`, `admin_kept_with_spare`, `admin_rights_lost`, or `frozen`. |
| `set_change` | `recovery_secret` (base64 32 bytes), `new_root`, `device` (`device` record object), `leave_out`?, `drop_hubs`?, `over_waiting`?, `time_ms`, `sigs`? | `{"sign": [...]}` or view fields + `set`, `records` (recovery record followed by initial records), `list` (base64), `again` (bool), `blind` (bool: warn before sending if no peer records were received since loading). |
| `set_standing` | `own`, `peer` (base64 65-byte SEC1 member keys) | `{"standing", "device"?, "reason"?}`. `standing` is `member` (with `device`), `unknown`, `refused` (with `reason`), `halted`, or `fork_proof`. |

### Group view fields

Every call that returns the group view includes these top-level fields:

- `group`, `digest`, `record_count`, `bytes`, `first_root`, `recovery` (K1 hash), `roots` (ordered
  path ending with current root), `root_device` (optional).
- `devices`: `[{id, key, key_hash, name, role, rights, caps, os, store, admin?, powers?, commands?, root, frozen, guarded, by_root, no_secrets, nothing}]`.
- `revoked`, `hubs`, `stop` (`""`, `secrets`, or `full`), `stopped`, `halted`, `too_old`,
  `update_needed`, `ttl_ms` (optional), `secret_ttl_ms` (optional).
- `conflicts`: `[{kind ("admins"|"fork"|"two_histories"|"admits"|"ids"), records, signers}]`.
- `changes`: `[{record, seq, root, state ("effective"|"void"|"competing")}]`.
- `list_missing` (optional), `change_arriving` (optional), `newer`.
- `notices`: `[{id, keys}]` (undismissed removals by an earlier root).
- `came_in`: `[{change, seq, keys}]` (devices admitted via each root change).

## Signed bodies

`parse_body` (`core/src/api/signed.rs`) validates non-record JSON bodies against strict signed-body
syntax and per-field schema rules ([Protocol](protocol.md), sections 7 and 16): `keys`, `release`,
`channel`, `attest-status`, `entries`, `zxnext`, and `manifest`. Release file bodies larger than
256 KiB (`release::MAX_BODY`) are refused. `parse_body` checks body structure only; callers verify
signatures, signers, and timestamps separately (or use `release_check*` below).

Note: `KINDS` includes `"credential"`, so passing `kind: "credential"` returns code `16` (`signed`)
rather than code `1` (`request`), because `read()` in `core/src/api/signed.rs` has no decoder for
`"credential"`.

Go validates the same bodies with its own parser (`clip.ParseManifest` and `internal/release`),
kept identical via `testdata/interop/strict.json` and `strict-files.json`.

## Release files

`release_check`, `release_check_status`, `release_check_entries`, and `release_named`
(`core/src/api/signed.rs`) verify signed release artifacts identically to `cbb`
([Protocol](protocol.md), section 16):

- `keys.json` under the pinned root keys (embedded from `internal/release/roots/roots.pem`, or
  overridden by `roots` in tests and drills).
- Target files (`channel`, `release`, `attest-status`, or `entries`) under the keys certified by
  `keys.json` for that use.
- Dual signatures (ES256 and SLH-DSA-SHA2-128s), expiration timestamps, clock bounds, and
  monotonicity against `seen`.

Callers pass raw fetched file bytes (base64) so kits never decode release envelopes themselves, and
persist the returned `seen` object for subsequent checks. Interoperability vectors in
`testdata/interop/go-release.json`, `go-release-envelopes.json`, and `go-entries.json` test all
implementations against the same cases.

## Rust entries for drivers

In addition to the JSON API, Rust drivers (`member/` and `ffi/`) call these `cbb_core` items
directly:

| Entry | Purpose | Callers |
|---|---|---|
| `sheet::text`, `sheet::qr` | Formats a recovery sheet's 4-line text and QR URI from the 32-byte recovery secret and group ID ([Protocol](protocol.md), section 9). | `member/src/founding.rs`, `ffi/src/found.rs` |
| `sheet::read` | Parses typed or scanned recovery input (at most `sheet::MAX_INPUT`, 512 bytes) into `sheet::Read` or a `sheet::Reason` with `.message()`. | `member/src/founding.rs`, `member/src/service/on_live.rs`, `ffi/src/found.rs`, `ffi/src/member/live.rs` |
| `sheet::check` | Verifies a parsed recovery sheet against the group ID and recovery key before signing. | Same as `sheet::read` |
| `sheet::yubikey::seal`, `open`, `read`, `is_ours`, `ecdh`, `check`, `container`, `read_container`, `is_tag` | Encodes, seals, opens, and verifies YubiKey recovery objects via ECDH with the card's key (card I/O stays in the caller). | `member/src/piv/recovery.rs`, `ffi/src/piv.rs` |
| `tls::bykey::pairing_exporter` | Extracts a `join::PairExporter` from a completed `cbb-pair/3` TLS handshake. | `member/src/joining.rs`, `member/src/mesh.rs`, `ffi/src/joiner.rs` |
| `join::PairExporter::exported_by_platform_tls` | Constructs a `PairExporter` from 32 bytes exported by platform TLS with label `EXPERIMENTAL-cbb-pair-v3` and empty context. | `ffi/src/pair06.rs` (unit tests) |
| `join::invitation::Invitation::home`, `typed`, `home_secret` | Creates a home window's ID and six-digit code, and reconstructs the same invitation from scanned or typed digits. | `member/src/admitting.rs`, `member/src/join.rs`, `member/src/joining.rs`, `ffi/src/joiner.rs`, `ffi/src/pair06.rs` |
| `join::welcome::Welcome::build`, `part_message` | Builds a Welcome message and any continuation parts needed when the record set exceeds one frame. | `member/src/admitting.rs`, `member/src/link.rs`, `ffi/src/pair06.rs` |
| `join::session::JoinerSession`, `MemberSession` | Runs the complete pairing state machine (messages 64–69) without I/O, encapsulating CPace, attempt counting on `invitation::Open`, Welcome assembly, and final verification (`Joined::Done`). | `member/src/join.rs`, `member/src/admitting.rs`, `ffi/src/joiner.rs`, `ffi/src/pair06.rs`, `ffi/src/window.rs` |
| `bounds::BOUNDS` | Central registry of every format limit, its rule, refusal reason, and test vector ([Protocol](protocol.md), section 19). | Tests and documentation checks |
| `records::RecordSet::for_peer`, `lists_for_peer`, `parts_for_peer` | Selects records and root-change lists to send to a peer, and splits them into single-frame parts for sync and Welcome messages. | `member/src/link.rs` |
| `records::RecordSet::digest` | Computes the set digest carried in hellos and sync rounds. | `member/src/link.rs` |
| `records::RecordSet::missing` | Returns missing record IDs to request in the current round; gives up on an ID after `records::set::MISSING_ROUNDS` (`16`) rounds. | `member/src/link.rs` |
| `records::RecordSet::change_arriving` | Reports when a root change waits for initial records (`State::first_missing`) or its device list (`State::list_missing`). | `member/src/notices.rs` |
| `records::RecordSet::room_of`, `root_room`, `root_room_waiting` | Reports a signer key's room tier, fixed cap, used units, and remaining space (`full_for(units)`), plus root room consumption by waiting removals. | `member/src/notices.rs` (`root_room_waiting`), `core/` tests (`room_of`, `root_room`) |
| `records::RecordSet::would_take` | Simulates inserting a record on a copy to report whether room limits accept, evict newer records from the same key, or reject it without mutating the set. | `core/` tests (available for writers and UI error reporting) |
| `records::RecordSet::removal_warning` | Computes which devices would leave the group or lose admin keys if a removal is signed (evaluates the removal alone, without any preceding root checkpoint). | `core/` tests (available for admin confirmation prompts) |

### Sync of records: what a driver must do

`RecordSet` decides which records are retained; the driver decides when records travel. Drivers
must follow these rules so connected peers converge on the same set:

- **Send while digests differ.** Send `for_peer` output whenever the local digest differs from the
  peer's digest—on connection open and after every insert that leaves digests unequal, not only on
  the initial hello. Process each incoming part in order: records, lists, records.
- **Stop only on equal digests.** End sync only when both digests match, never because `missing` is
  empty. Bound the number of sync rounds per connection; exceeding the bound indicates a core bug
  that the driver must report (including both digests in debug mode) instead of looping.
- **Treat `missing` as a hint.** Requesting specific IDs accelerates sync, but giving up on an ID
  after `MISSING_ROUNDS` (`16`) never stops sending when digests differ. Request counters are not
  persisted, so a restarted member asks again.
- **Surface waiting root changes.** While `State::first_missing` or `State::list_missing` is set,
  show the `change_arriving` notice and re-send records on every connection.
  `RecordSet::stuck_checkpoints` tracks only the current root's checkpoints, not waiting root
  changes.
- **Report room rejections explicitly.** Report rejected records using `would_take` and full rooms
  using `room_of` rather than a generic failure; include cap, used units, and record units in debug
  details.
- **Re-offering existing records is idempotent.** Calling `insert` or `insert_all` with records the
  set already holds leaves the set unchanged. Intermediate state for a key at its room cap may
  depend on arrival order, but peers converge once they exchange records until digests match.
