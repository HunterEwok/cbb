<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Copy Beyond Borders protocol

The text of this document is under the
[Creative Commons Attribution 4.0 license](https://creativecommons.org/licenses/by/4.0/).
You may implement the protocol in your own code under any license. The code of this
repository stays under the GNU AGPL v3.0 only ([LICENSE](../LICENSE)).

This document specifies protocol version 1 of Copy Beyond Borders as the code in this
repository implements it, so that another implementation can interoperate with it. Four
implementations follow it today: Go (`cbb-helper`, the forwarder, and the references the tests check against), Rust
(`cbb` on the computers and small devices, `core/`, whose member the phones' apps run too,
through `ffi/`), Swift
(`CBBKit`) and Kotlin (`apps/android/kit`), with shared test vectors in `testdata/interop`.
The phones' kits keep pairing, restoring, the records they sign and the credentials; the
member protocol of section 4 runs in the Rust core's member on every phone (docs/core-api.md,
"The member"). [design.md](design.md) explains why the protocol
is the way it is; this document only says what it is, and the threats it answers are in the
[threat model](threat-model.md).

**Status.** This is the edition for release 0.6, and it is preliminary: devices work
together within one release, and 0.7, whose format and protocol are final, may change any
part of it (D-131). A change gets a new ALPN protocol, record type or message field, never a
new meaning for an old one; the registries (section 19) list every name in use. Where the
Rust core and this document differ, the difference is a bug in one of them; a "Note:" line
marks a known difference.

### Contents

- [1. Identifiers, names and ports](#1-identifiers-names-and-ports)
- [2. Keys](#2-keys)
- [3. Discovery (mDNS)](#3-discovery-mdns)
- [4. Member protocol](#4-member-protocol)
- [5. Sync semantics](#5-sync-semantics)
- [6. Pairing a computer](#6-pairing-a-computer)
- [7. The join QR code](#7-the-join-qr-code)
- [8. Local control socket](#8-local-control-socket)
- [9. The phone as the root](#9-the-phone-as-the-root)
- [10. Admin CAs, device records and revocation](#10-admin-cas-device-records-and-revocation)
- [11. Tunnel keys](#11-tunnel-keys)
- [12. Remote invitations](#12-remote-invitations)
- [13. The forwarder](#13-the-forwarder)
- [14. The blind relay](#14-the-blind-relay)
- [15. Commands](#15-commands)
- [16. Signed releases](#16-signed-releases)
- [17. Key stores](#17-key-stores)
- [18. Server credentials](#18-server-credentials)
- [19. Registries](#19-registries)
- [20. Security considerations](#20-security-considerations)

### Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119),
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all
capitals, as shown here. They mark what an implementation has to do to interoperate and to
keep the group safe. Sentences in the plain present tense describe what the code in this
repository does; another implementation may do it differently where nothing marked with
these words depends on it.

- **Peer, member.** A member is a device of the group: a device whose key the records name
  (section 10). That is a member with the role
  `member` (a computer, board or router with the service or the firmware, section 4,
  "Capabilities"), or a phone with the app. A peer is the other end of a connection.
- **CBOR.** Every message, record, statement, command, grant, credential and copy header
  is one CBOR data item ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)) in one
  profile, which one reader in the core implements for every platform (`format::cbor`;
  `cbb inspect` prints any item with its field names). Each rule has a name, which the vectors
  cite:
  - `cbor/negative`, `cbor/tag`, `cbor/simple`: major types 0 (unsigned integer), 2 (bytes), 3
    (text), 4 (array) and 5 (map) only. There are no negative integers, no tags, no floats, and
    no `false`, `true`, `null`, `undefined` or other simple values. A flag is the integer `1`,
    present only when set.
  - `cbor/indefinite`, `cbor/reserved`: definite lengths only; additional information 28 to 31
    is refused.
  - `cbor/shortest`: every integer, length and count in its shortest form (RFC 8949, section
    4.2.1).
  - `cbor/int-range`: integers from 0 to `format::cbor::MAX_INT` (9223372036854775807), so that
    Go, Kotlin and Swift hold them in a signed 64-bit integer.
  - `cbor/map-key`: map keys are unsigned integers from 0 to 65535, nothing else.
  - `cbor/map-order`: map keys strictly increasing, so no key twice. For integers in shortest
    form this is the bytewise order of RFC 8949's deterministic encoding.
  - `cbor/utf8`: text is UTF-8 as RFC 3629 has it: no overlong forms, no surrogates, nothing
    above U+10FFFF. Control characters are each field's matter.
  - `cbor/depth`: arrays and maps nest at most `format::cbor::MAX_DEPTH` (8) deep: an item
    inside 8 containers is the deepest.
  - `cbor/count`: an array or map holds at most `format::cbor::MAX_COUNT` (65535) elements; a
    field's row is usually stricter.
  - `cbor/trailing`, `cbor/truncated`: the bytes are exactly one item, with nothing after it and
    nothing cut. Every kind refuses trailing bytes this way.

  With these rules every value has exactly one encoding, so a reader that checks them knows
  that encoding what it read gives the bytes it got, without encoding again to compare. Writers
  sort map keys by number.
- **Fields.** Every object is a map whose keys are field numbers. Each row of a kind's
  table gives a field's number, its CBOR type, whether it is needed, its values and its default.
  Two rules hold for every object:
  - `form/default`: a field whose value is its row's default is left out, and an object with it
    is refused. An optional array or map with no elements, and an optional text or bytes that
    are empty, are left out the same way. A needed field is always written, 0 included where its
    row allows 0. So one value has one object.
  - `form/type`: a field of another CBOR type than its row's, or out of its row's range, refuses
    the object. The vectors cite the row as `records/<type>/<field>` and so on.

  An array that a row calls *sorted* is sorted bytewise by each element's encoding (bytes of one
  length by their bytewise order, an array element by its first element), each value once.
- **Common values.**
  - A **Key** is the array `[alg, pub]`: `alg` 1 ES256 (an uncompressed P-256 point of 65
    bytes, signatures of 64 bytes `r ‖ s` with a low `s`), 2 X-Wing (1216
    bytes, [format](format.md), section 10.2), 3 X25519 (32 bytes, WireGuard), 4 SLH-DSA-SHA2-128s
    (32 bytes, the recovery key's second half). A key of the
    wrong size or off its curve is `keys/es256`, `keys/xwing`, `keys/x25519` or
    `keys/slh-dsa`; one that is not `[alg, pub]` is `keys/shape`.
  - A **key hash** is the SHA-256 of a Key's encoding, 32 bytes. A **device ID** is the first 16
    bytes of the key hash of the device's member key, so nobody can take another device's ID
    without its key. A **group ID** is the first 16 bytes of SHA-256(`cbb group v3` ‖ 0x00 ‖ the
    encodings of the group's first root key and of the recovery key's two halves)
    ([format](format.md), section 2).
  - A **record ID** (and a statement's or credential's ID) is the SHA-256 of the body's bytes;
    the signatures are not in it. A copy's, command's or invitation's ID is 16 random bytes.
  - A **time** is Unix milliseconds, for display and for devices with clocks only: no rule of the
    records reads it. A **duration** is milliseconds. A **hybrid time** is `[wall_ms, logical]`,
    `logical` at most 2^32 − 1, and `[0, 0]` is refused.
- **Signed objects.** A signed object travels as an envelope `[body, sig]`, or
  `[body, sig, sig2]` exactly when the body names a second signer `signer2` (field 8)
  (`format::envelope`). The body is the encoding of the object's map, as bytes, so that it is
  signed and passed on unchanged; it is an item of the profile itself. `sig` is the ES256
  signature of the body's `signer` (field 3) over the label of the object's kind, a zero byte and
  the body, and beside a second signature over the body and that signature's SHA-256 too; the
  label keeps a signature of one kind from being taken as another. The second signer signs
  first, over the body alone, and its signature is at most `format::envelope::MAX_SIG2` (8192)
  bytes, or `format::envelope::MAX_SIG2_HEAD` (32768) for a recovery head; it is not in the ID.
  Rules: `env/shape` (another number of elements, a body or signature that is not bytes, `sig2`
  without `signer2` or the reverse), `env/size` (a body over its kind's ceiling), `env/sig2` (a
  second signature over its ceiling), `sig/size`, `sig/range`, `sig/low-s`, `sig/verify`.
  An envelope whose first signature does not cover its second is `env/damaged`: dropped, neither
  stored nor passed on. A receiver checks in this order: the envelope's size, the profile on the
  envelope and the body, the body's fields against their rows, the signature, then the rules of
  evaluation. A body that fails a step never reaches the next, so nobody verifies a signature
  over a body that others read otherwise, and records are stored by ID only after their
  signature checked.

  Fields 0 to 9 of a signed body are common: 1 `type`, 2 `group`, 3 `signer` (a key hash, or a
  Key in a server credential), 4 the signer's increasing number for the kind, 5 `prev` (records
  only), 6 `time_ms`, 7 `expires_ms` (commands and credentials), 8 `signer2`; 0 and 9 are
  reserved. Keys 10 to 255 are the **critical zone**: a reader that meets a key there that its
  version does not define for the kind and type (or a `type` it does not know, or a Key of an
  unknown `alg` where a key is wanted) holds a record or statement: it verifies and stores it,
  passes it on unchanged and never applies it, the state lists it among the newer ones (at most
  `records::MAX_NEWER` (16)) and the apps say to update. A command, grant or credential with one
  is refused (`form/critical`). Keys 256 to 65535 are the **optional zone**: a reader skips a
  key it does not know there, whatever its value, and the signature covers it. The records that
  remove, freeze, claim, resolve or hand over are written with the fields of 0.6 alone, so that
  every version from 0.6 on applies them.
- **Frames.** Every channel between devices, and between a device and a server, carries the
  frames of section 4, "Frames" ([format](format.md), section 9.1): a 4-byte length on a grid,
  one CBOR map with its type in field 0 and its padding in field 1, each channel with its own
  limit. Only the local control socket (section 8), which never leaves the machine, has framing
  of its own.
- **Time.** Times on the wire are Unix milliseconds (`_ms`), and durations integer
  milliseconds, unless a field says otherwise. Local durations (ages, windows, timeouts) are
  measured on a clock that counts the time the machine sleeps and does not jump when the
  wall clock is set (`CLOCK_BOOTTIME` on Linux, `CLOCK_MONOTONIC` on macOS; package
  `uptime`); an implementation SHOULD do the same.
- **Source.** Each section names the code that implements it, so that a reader can check a
  detail there.

#### JSON and text

The signed release files and entry points (section 16), the local control socket (section 8)
and the manifest of images or files a watcher hands the service are JSON, read by these rules;
so are the texts a person or a server reads (a link, a pin).

- **JSON.** [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) objects. A receiver MUST
  ignore fields it does not know, unless a section says otherwise.
- **Bytes.** Byte strings, in JSON and in the texts of this document (an invitation, a QR
  code, a pin), are standard base64 with padding in its one form
  ([RFC 4648](https://www.rfc-editor.org/rfc/rfc4648), section 4; Go's encoding of
  `[]byte`): no line breaks, no base64url, the padding there, zero bits after the last
  byte. In a URL's query each `+`, `/` and `=` is percent-encoded, and a reader decodes only
  percent escapes, never a `+` as a space. Two kinds of value are in lowercase hex: the
  identifiers in text (device IDs, copy and command IDs, group tags), which compare as
  strings; and the SHA-256 of a file (release files, Docker digests), which `sha256sum`
  prints.
- **Fingerprints.** A TLS key outside the records (a forwarder's or a relay's, whose
  fingerprint is its pin, or the key of the ESP32 firmware's certificate, section 7) has one
  fingerprint: SHA-256 over its SubjectPublicKeyInfo (DER), in standard base64. A device's key
  in the records is named by its key hash (above).
- **Signed bodies.** The body of a release file (section 16) is signed as bytes and passed on
  unchanged, so every member MUST read it alike; a manifest in JSON is read by the same rules,
  although nobody signs it. A receiver MUST refuse a body that breaks any of these rules,
  before it reads a field, and so MUST a signer's own code before it signs. Each rule has a
  name, which the vectors cite:
  - `form/object`: the body is one JSON object in UTF-8, with nothing but whitespace (space,
    tab, CR, LF; not a form feed) around it; no byte order mark, no comma after the last
    member, nothing after the object.
  - `form/utf8`: the bytes are UTF-8 as RFC 3629 has it: no overlong forms, no surrogates,
    nothing above U+10FFFF, no cut or stray continuation bytes.
  - `form/names`: every member name, at every depth, is 1 to 64 of `a`-`z`, `0`-`9` and
    `_`, written without escapes, and no object has the same name twice, even with the same
    value. Names match exactly: `Type` is not `type`.
  - `form/null`: no value is `null`, at any depth; a field that is not there is left out.
  - `form/numbers`: every number, at any depth, is an integer written as `0` or
    `-?[1-9][0-9]*`, without a fraction, an exponent or a plus sign, from -2^63 to 2^63-1;
    `-0` is not one, since some JSON readers take it for 0 and others for a float.
  - `form/strings`: a string holds no raw control character (below U+0020); its escapes are
    `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t` and `\u` with four hex digits of either case;
    a `\u` escape names a UTF-16 code unit, and a surrogate MUST be one half of a pair, the
    high half followed at once by the low half. Escaped control characters are taken here;
    a field's own row may refuse them.
  - `form/depth`: arrays and objects nest at most 16 deep below the body's object.
  - `form/unknown`: a member the body's kind does not know is ignored, whatever its value, but
    it still follows every rule above.
  - The fields every release file has are there: `v`, `type` and every field its table does not
    call optional.
  - Bytes are standard base64 with padding in its one form: decoding and encoding again
    gives the same string (no line breaks, no missing padding, no base64url, zero bits
    after the last byte).

  A receiver checks a body's size first (`size/releases`, 256 KiB, section 16), then these
  rules, then each field against its row, then the signature. `cbb_core::strict` implements
  them, and `testdata/interop/strict-files.json` holds a valid release file of every kind and,
  for every field, the body without it, with a value of each other JSON type, `null`, written
  twice, and its numbers or strings in each form these rules refuse, each vector with its rule
  and whether a member takes the body.

## 1. Identifiers, names and ports

| Item | Value | Source |
|------|-------|--------|
| Device ID | 128 random bits as exactly 32 lowercase hex characters (`[0-9a-f]{32}`) | `core/src/certs.rs` |
| Event ID | same format as a device ID, random per event | `internal/clip/clip.go` |
| Group tag | on the records of 0.6, the first 8 bytes of the group ID (section 1), as 16 lowercase hex characters; in a group of 0.5, the first 8 bytes of SHA-256 over the group CA certificate (DER) | `member::live::tag` |
| Member host name | `cb-<device ID>.local` (mDNS host name and the only DNS name in the member certificate) | `DeviceID.HostName` |
| Service instance | `<device ID>._cbb._tcp.local` | `internal/mdns/zone.go` |
| Member port | TCP 8764, or `CBB_PORT` (the Linux installer's `--port`), when free, otherwise one the OS chooses, all addresses; published in the SRV record. Members listen on it; phones only while they are the hub. CBB's only port: it also serves the pairing windows | `member/src/lib.rs`, `member/src/discovery.rs` |
| mDNS | UDP 5353, groups 224.0.0.251 and ff02::fb | `internal/mdns/mdns.go` |
| Member ALPN | `cbb/4` | `cbb_core::alpn`, `group.MemberProtocol` |
| Pairing ALPN | `cbb-pair/3` | `cbb_core::alpn` |
| Forwarder | UDP and TCP 8764 on the forwarder's own server (`cbb forward -listen`); ALPN `cbb-forward/3` (section 13) | `internal/forward` |
| Blind relay | UDP and TCP 8764 on the user's own server (`cbb relay -listen`); ALPN `cbb-relay/3`; tunnel address `fd00:cbb::1` (section 14) | `member/src/relayd` (`cbb-relay`) |
| Pairing code | six ASCII digits; users may type spaces and dashes, which are removed | `pair.NormalizeCode` |
| Join QR text | `cbb://join?code=` followed by the six-digit code (section 7) | `phone.JoinQR`, `phone.ParseJoinQR` |

Device IDs, event IDs and group tags compare as byte strings. Accepting peers: the member
port MUST accept TCP connections only from addresses that mDNS would publish (private IPv4,
unique-local IPv6, link-local IPv6) or loopback, and close others; a member with an interface list (`CBB_INTERFACES`) MUST also
close a connection that did not arrive on such an interface from its own networks. At most
32 connections to the member port may be in their TLS handshake or in a pairing attempt at
once; more are closed at accept. An implementation SHOULD bound them likewise.

## 2. Keys

Source: `core/src/records/key.rs`, `core/src/format/container.rs`, `core/src/keystore`,
`core/src/seal.rs`. A group has no certificates: its records name keys (section 10), and every
key is a Key of the Conventions.

| Key | Algorithm | Held by | What it does |
|---|---|---|---|
| Member key | ES256 (P-256) | every device | its device ID is the first 16 bytes of its key hash; it proves the device in TLS (section 4) and signs its copies, its keys statements and its intro; in hardware where the device has it (section 17) |
| Seal keys | X-Wing | every device that reads copies | one an epoch, named in the device's keys statement ([format](format.md), section 5); a copy's key and a sealed command are sealed to it |
| Admin key | ES256 | the root and the admins, on a device with the capability `admin` | signs records and commands as far as the records let that key (section 10) |
| Recovery key | ES256 and SLH-DSA-SHA2-128s | the person, on paper or a YubiKey | takes the group back (section 9); with the first root key it gives the Group ID |
| Tunnel key | X25519 | a device away from home, and a hub | WireGuard (section 11) |

TLS needs a certificate, so each side presents the key container of its member key
([format](format.md), section 12): a fixed template that holds the key alone, which a reader
checks byte for byte and never as a certificate. Two certificates remain, outside the group:
the one a device registers with on a forwarder or a relay, of its server key, which names
neither a device nor a group (section 18; `internal/group`, `ServerCertificate`), and the
certificates of the ESP32 firmware (section 7).

## 3. Discovery (mDNS)

Members (computers, boards and routers with the service or the firmware) publish and browse;
phones and joining devices only browse, except a phone that is the group's hub, which
publishes `v=1`, `g=<tag>`, `r=phone` while its app is open (design.md, "The phone as the
hub"), and a phone whose pairing window is open (section 6, "The window and who dials"), which
publishes `v=1`, `g=<tag>`, `p=1`, `f=<fingerprint>` while the window is open.
[RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) and
[RFC 6763](https://www.rfc-editor.org/rfc/rfc6763) apply where this section is silent. Source: `internal/mdns` (Go, for the tests); `cbb`
publishes and browses with the `mdns-sd` crate (`member/src/discovery.rs`), which
follows the same RFCs but not every detail below: it publishes the PTR, SRV, TXT and A/AAAA
records of the table (the TXT with `r=listen` when it does not dial), with the addresses of its interfaces except
loopback. A member it resolves without a TXT record (its responder sends a record it multicast
within the last second no more) it neither dials nor drops: it browses again from a second
daemon, whose first query carries no known answers, after 1.5 s and then every 5 s, doubled up
to 60 s, until the TXT comes. The phones browse with the system's DNS-SD (iOS: `BonjourBrowser`, Android: NSD),
resolve the members to their addresses and hand those to the member in the Rust core, which
starts with its own mDNS off; a phone that is the hub publishes its home port the same way
(`BonjourPublisher`, `NsdPublisher`).

A member SHOULD publish, answer queries and take connections on the member port only on
an interface whose network it knows (design.md, "Known networks"); elsewhere it only
browses, and connections to its member port there are closed at once, except while a pairing
window is open. Publishing on every network is a local setting of the device, not a role.

### Records a member publishes

| Name | Type | Data | TTL | Cache-flush |
|------|------|------|-----|-------------|
| `_cbb._tcp.local` | PTR | `<id>._cbb._tcp.local` | 4500 s | no (shared) |
| `<id>._cbb._tcp.local` | SRV | priority 0, weight 0, member port, target `cb-<id>.local` | 120 s | yes |
| `<id>._cbb._tcp.local` | TXT | see below | 4500 s | yes |
| `cb-<id>.local` | A / AAAA | the addresses of the interface | 120 s | yes |
| `cb-<id>.local` | NSEC | see below | 120 s | yes |
| `_services._dns-sd._udp.local` | PTR | `_cbb._tcp.local` | 4500 s | no; only in answers, never announced |

TXT strings (each at most 255 bytes):

| Key | Value | Meaning |
|-----|-------|---------|
| `v` | `1` | protocol version |
| `g` | group tag | members of another group, or of a replaced CA, are ignored |
| `p` | `1` | present only while a pairing window is open (a computer's or, in 0.6, a phone's) |
| `f` | fingerprint | with `p`, on the records of 0.6: the hex of the window's member key hash (Conventions: SHA-256 of the Key's encoding, 64 lowercase hex characters), the key of its TLS by key, as the window's QR code's `fp` (section 7), which the new device checks before it sends anything; with `j`, until the switch: the fingerprint of the key of the joiner's self-signed certificate (Conventions, "Fingerprints"), as its QR code's `fp` |
| `i` | window ID | with `p`, on the records of 0.6: the home window's ID, 32 lowercase hex characters, by which a new device that has only the six digits typed into it finds the window and builds its password (section 6, "Pairing in 0.6"); never the digits |
| `r` | `listen` or `phone` | `listen` on a member without the capability `dials` (section 4, "Capabilities"), which every member dials since it dials none; `phone` on a phone that is the group's hub while its app is open, which the members do not dial, since it dials them; the other phones dial it |

A computer or a phone whose pairing window of 0.6 is open publishes `v=1`, `g=<tag>`, `p=1`,
`f=<key hash>`, `i=<window ID>` (`member/src/discovery.rs`), so that a new device whose person
typed the window's six digits (`cbb pair -code`, the Aurora app, the ZX Spectrum Next's `.cbb
pair`) dials the one window, checks its key and joins with the digits and that ID; a device
that scanned the window's QR code has all three from the code. Nobody compares a code on two
screens. The Go code publishes them in the order `v=1`, `g=<tag>`, `p=1`; a
member without `dials` publishes `v=1`, `g=<tag>`, `r=listen`. A receiver MUST ignore keys it does not
know, MUST match keys without regard to case, and MUST take as the value what follows the first `=`.
A member MUST NOT dial a peer whose `g` is not its group's tag.

Note: browsers check only `g` (when dialing), `r` (when dialing, on members)
and `p` (when joining); nothing checks `v` (`member/src/discovery.rs`).

NSEC (RFC 6762 section 6.1): owner the host name; RDATA is the host name itself in
uncompressed wire format, then window 0 with a bitmap that has bit A (type 1, byte 0 mask
0x40) and/or AAAA (type 28, byte 3 mask 0x08), trimmed of trailing zero bytes.

Addresses: a member MUST publish only private IPv4, unique-local IPv6 and link-local IPv6
addresses, and each answer carries the addresses of the interface the query arrived on. Interfaces that
are down, cannot multicast, are loopback or point-to-point are not used; the list is
rescanned every 10 s.

### Responding

- A responder MUST process only packets whose source is on the link (inside a prefix of the
  receiving interface, or an IPv6 link-local address). Only PTR, SRV, TXT, A and AAAA records are read;
  a record that does not decode, such as an instance name with a dot in a label, is skipped
  alone. At most 32 questions of a query are answered.
- A PTR question for `_cbb._tcp.local` gets the PTR as answer and SRV, TXT, A/AAAA
  and NSEC of the host as additionals. A question for the instance gets SRV (with the host
  addresses as additionals) and/or TXT. A question for the host name gets its A or AAAA records, or the NSEC record when the
  name has no address of the asked type. Type ANY gets everything that matches.
- Known-answer suppression: a record listed in the query with at least half of its TTL is
  left out. A record already multicast on the interface within the last second is left out.
- A multicast answer that contains a shared record (a PTR) is delayed 20 to 119 ms; other
  answers go at once, to the group of the query's address family.
- A legacy unicast query (source port not 5353) gets a unicast answer that repeats the ID and
  the questions, TTLs capped at 10 s, no cache-flush bits, at most 5 answers a second per
  source. An answer over 9000 bytes drops its additionals.
- Names are never probed: device IDs are random.

### Announcements and goodbyes

- All records are announced twice, one second apart, at start, on a new interface or new
  addresses and after a TXT change.
- Addresses that go away get a goodbye (TTL 0) for the host name.
- On stop, every record gets a goodbye. Goodbyes never carry the cache-flush bit, so they end
  only their own record. A service that stops sends its mDNS goodbyes before the member
  goodbyes (section 4).

### Browsing

- Query PTR `_cbb._tcp.local` at start, then after 1 s, doubling up to one hour,
  listing as known answers the PTR records with more than half their TTL left of the members
  found (a PTR record whose SRV or addresses expired is not listed). When a member found is
  lost, start again: query now, then after 1 s, doubling. A member that was off the network
  for a while, as behind a firewall, comes back without announcing itself.
- Each cached record of a found member (its PTR, SRV, TXT and host addresses) is queried
  again at 80, 85, 90 and 95 percent of its lifetime, plus 0 to 2 percent at random.
- Received records are kept only if relevant: PTR of the service, SRV/TXT of an instance
  whose first label is a device ID, A/AAAA of `cb-<device ID>.local`. Their TTL is capped at
  what Copy Beyond Borders itself uses (4500 s for PTR and TXT, 120 s otherwise). A goodbye expires the
  record after 1 s; a cache-flush record expires older records of its name and type after
  1 s.
- A member is found when a live PTR names an instance that has a live SRV; its addresses
  are the live A/AAAA records of the SRV target that would be published. TXT is optional.

## 4. Member protocol

### The member protocol in 0.6

Source: `core/src/alpn.rs`, `core/src/tls/bykey.rs`, `core/src/peer.rs`,
`core/src/format/frame.rs`, `core/src/msg`, and on the members `member/src/mesh.rs` (the
connections), `member/src/hello.rs`, `member/src/mesh/media.rs` (content) and
`member/src/discovery.rs` (who dials). The bytes of every message are in the
[format](format.md), section 9; this section says how the members use them.

**ALPN.** The member protocol is `cbb/4` and pairing is `cbb-pair/3` (section 6), both named
once in the core (`cbb_core::alpn`: `MEMBERS` and `PAIRS`, the highest first). A device offers
every name it speaks, the highest first. The server takes the first name of its own list that
the client offers, which is the highest common one, and ignores names it does not know. When
there is no common name the handshake ends with `no_application_protocol`, which the apps show
as "the other device runs another version of cbb that this one cannot talk to: update the older
one". A new key container, or a change in what the handshake's bytes mean, takes a new name; a
new message inside the protocol does not. Within a version the hello says what the sender
supports by its fields and by `features`, never by its release, so no rule here depends on a
version number.

#### Who dials whom

- Of two members that both have the capability `dials` (below, "Capabilities"), the one with
  the lower device ID MUST dial the other when it finds it with a matching `g`; the other
  side accepts. When no connection to a found member with a lower device ID has been up for
  30 s, the higher one dials it as well, since a firewall may keep the other from reaching
  it. Of two connections between the same two members, the one the lower device ID dialed
  stays: a member MUST refuse a new connection when the one the lower ID dialed is up and the
  new one is not that, and otherwise the new one replaces the old. The side that dialed
  applies the same rule to its new connection, so the two keep the same one. A member does
  not dial a member it is connected to; one given only an address (`-peer`) learns which
  member is there from its first connection.
- A member without `dials` (TXT `r=listen`) dials no one; every member with `dials` that
  finds it dials it, whatever the device IDs. It accepts the members and the phones.
- A phone app MUST dial every found member with a matching `g`. Phones accept nothing and
  never connect to each other; so a phone syncs with any one member with no other on. A
  phone that is the group's hub is the exception: while its app is open it accepts members
  on the home network and through the tunnel, publishes `r=phone`, and the other phones
  dial it; the members do not, since it dials them.
- Members on another network than the home one (another subnet, where mDNS does not reach)
  reach the hub through the group's WireGuard tunnel (section 11; design.md, "Sync away from
  home"); so do the phone apps, as clients. A member can be given a member's address with
  `-peer`; it MUST NOT dial an address outside the home network (private IPv4, unique-local
  and link-local IPv6, loopback), so away from home it reaches the group only through the
  tunnel.
- A computer that joined at an address the user gave (`cbb pair -code ADDRESS`, as through
  an SSH forward or a VPN) also dials the member that admitted it at that address, whatever
  the rules above say, while no connection to the group is up; with mDNS on, first 3 s for
  discovery, and when discovery found a member of the group, as long as the fallback dial above
  (30 s, and 5 s more), so that of two members that find each other the lower device ID still
  dials. It keeps doing so, with the same waits, until it holds the hub's tunnel offer
  (section 11) or the service stops; the address is not stored.
- Addresses come from discovery; a member MUST NOT authenticate a peer by resolving a
  `.local` name, since the key in the handshake, not the name, says who the peer is. They are
  tried IPv4 first, then routable IPv6, then link-local IPv6. After a round of failures the
  dialer waits 1 s, doubling to 30 s; a connection that lasted more than 30 s resets the wait.
- TCP keepalive is off; the protocol has its own heartbeat.

#### TLS

TLS 1.3 only, with the key exchange X25519MLKEM768 (group 0x11EC) and an X25519 share beside
it, so that a server with X25519 alone answers at once. Session tickets are off, so a connection
never resumes without the peer's key. Each side presents the key container of its member key
([format](format.md), section 12): a fixed template that holds the key alone, so nothing in the
handshake names a device or the group, and no server name is sent. The peer's key is its
identity and its hash gives its device ID. CertificateVerify proves that the peer holds the key,
the client checks the key's hash against the device it dialed, and each side asks its records
where the key stands (`peer::Standing`):

- a device of the group talks;
- a key the records do not name yet may connect only to send its intro (section 6, "The intro")
  as its first message, or the connection closes;
- when the group is halted here nobody is a member, and a peer connects only to give and take
  the recovery key's records;
- a key that a held record of a forked root admits gets that fork's proof and gives only what
  completes it, and then the connection ends;
- every other key is refused, and a connection open when the records come to refuse its peer
  is closed.

A connection to one's own device ID is closed. The handshake must finish within 10 s, counted
from its start rather than from each read.

The member port takes TLS only. A ClientHello that offers `cbb-pair/3` gets the pairing
configuration (section 6), whether or not a window is open; any other the member configuration,
and a connection that does not negotiate `cbb/4` is closed. Outside a pairing window it takes
the member protocol only, from home network addresses. It takes at most 16 connections at once
in their handshake or in a pairing attempt, at most 4 of them from one source (an address, or
the /64 of a global IPv6 address; every device of a home network shares its unique-local and
link-local /64s, so those count address by address; loopback connections, which the tunnels'
and relays' ports share, count only in all). A connection from another device that sends
nothing for 3 s is closed. With no window open, a pairing connection gets its refusal after a
first frame of at most 64 KiB, within 10 s in all.

#### Frames

A frame is a 4-byte big-endian length, then one message: a CBOR map in the profile
([format](format.md), section 1), its type `t` in field 0, padded with `pad` (field 1) to a
size of the grid, so that a frame's size tells only its step ([format](format.md), section
9.1). The limit is `format::frame::LIMIT_MEMBER` (7 MiB) on a member connection,
`format::frame::LIMIT_PAIRING` (1 MiB) while pairing (section 6), and
`format::frame::LIMIT_LEAF` (16 KiB) toward a leaf, which a peer learns from the leaf's record
and never exceeds. A length of 0, off the grid or over the limit closes the connection
(`frame/grid`, `frame/pad`). The binary `chunk` frames ("Content", below), whose length has its
top bit set, are not messages and are read before these rules.

The receiver ignores a `t` it does not know. Within a message it knows, it skips a field the
message's table does not list. A transport's message is the exception: there an unknown field
makes the way unusable. A value of a known field that lies outside what this version knows
refuses the message, except where reading it as absent is neutral or stricter (`msg::later`,
one row a field, and `testdata/format/future.json`). The value never reads as absent where that
would grant more, change the mode, or change what the person compares or approves.

| `t` | Name | What it carries | Section |
|---|---|---|---|
| 1 | `hello` | what the sender says of itself (below) | 4 |
| 2 | `copy` | a copy ([format](format.md), section 10) | 4, 5 |
| 3 | `ping` | nothing | 4 |
| 4 | `bye` | nothing | 4 |
| 5 | `records` | record envelopes and recovery lists | 10 |
| 6 | `have` | record IDs: "I hold these" | 10 |
| 7 | `keys` | keys statements | 4 |
| 8 | `intro` | a new device's records | 6 |
| 9 | `command` | a command envelope | 15 |
| 10 | `result` | the answer to a command | 15 |
| 11 | `credentials` | the server credentials for one server | 18 |
| 12 | `release` | the signed release files as published | 16 |
| 13 | `get` | a range of a blob: its SHA-256, offset and length (0 cancels) | 4 |
| 14 | `missing` | as `get`: "I do not hold it" | 4 |
| 15 | `tunnel` | to a hub only: the device's tunnel key | 11 |
| 16 | `hubs` | hub to hub | 11 |
| 17 | `guest` | an admin and a hub, about an invitation's guest | 12 |
| 18 | `reach` | the device IDs a member is connected to | 4 |
| 19 | `evidence` | an attestation of a key | 17 |
| 20 | `grant` | the leaf's grant | 10 |
| 21 | `nonce` | a leaf's one-use nonce, or a request for one | 15 |
| 22 | `beacon` | the beacon envelope | 10 |
| 23 | `reseal` | "seal this copy to me again" | 4 |
| 24 | `roots` | the claims and handovers a leaf needs | 10 |
| 25 | `entries` | as `release`, for `entries.json` | 16 |
| 26 | `waiting` | the holder (a hub) to a device that may admit | 12 |
| 27 | `dismiss` | that admin to the holder | 12 |
| 28, 29 | `push`, `push-renew` | member to phone, about push ([format](format.md), section 9.6) | 4 |
| 30 | `want` | record IDs or a list's hash: "give me these" | 10 |
| 64–69 | pairing | `cbb-pair/3` only | 6 |
| 80–84 | forwarder | device and forwarder | 13 |
| 90–99 | relay | device and relay, and inside the relay's tunnel | 14 |

Each message's fields and their bounds are in the [format](format.md) (section 9.2), in the
core's tables (`msg::tables`, `msg::wave4`, `msg::member`) and in the vectors of
`testdata/format`.

#### Message order

1. After the TLS handshake each side sends its intro when the records make it a member (the
   other side may not know its key yet), then its hello, without waiting for the other's;
   then every keys statement it holds, its current copy as message `copy` (one it made sealed
   again to that peer alone, one it took as its maker sealed it), and its server credentials.
2. Then any other messages follow, interleaved with pings and the `chunk` frames of content.
3. A side that has written nothing for 5 s MUST send `ping`. Every frame written resets that
   timer.
4. A side that stops (service stop, Rejoin) SHOULD send what is queued and then `bye`, within
   one second, and close the socket. Receiving `bye` ends the connection without an error.

Rules for the receiver:

- A key the records do not name must send its intro first (section 6, "The intro"); otherwise
  the connection closes.
- A message that breaks its table is dropped and logged; a copy that fails its checks is
  dropped ([format](format.md), section 10.4); the connection stays. A frame that breaks the
  frame rules closes it.
- A receiver MUST close a connection silent for 15 s; writes have the same allowance, so a
  peer that stops reading ends the connection.
- A new connection from a device replaces its old one, which is closed without a goodbye,
  unless the old one was dialed by the member with the lower device ID and the new one was
  not ("Who dials whom").
- Each connection's outgoing queue holds 256 frames, `chunk` frames included; a message that
  finds it full is dropped, and the member sends its current copy again on the next
  connection. A chunk waits for room instead, which holds back that connection's reader.
- A member passes each new copy on once to every other connection; it remembers the last 4096
  copies' IDs for that.

Roles: a phone dials every member, publishes nothing and is never dialed, except while it is
the group's hub: it then publishes `r=phone` (section 3) and other phones dial it. A member is
any device with the service or the firmware: a computer (a Mac included), a Raspberry Pi, a
router or a board. What it can do beyond syncing its capabilities say (below); any member with
`admin` can create a group and be its root, or be made an admin. Only the root and the admins
admit devices.

#### Capabilities

A member's capabilities are bits ([format](format.md), section 4.1, `caps`):

| Bit | Capability | Meaning |
|---|---|---|
| 1 | `admin` | it can hold an admin key. The capability gives no rights: only the root's records do (section 10) |
| 2 | `dials` | it dials other members ("Who dials whom") |
| 4 | `hub` | it may be chosen as the group's hub (section 11). It says only that it may: the hubs record and the admins choose |

A member says them in its hello (`caps`) and its joiner Info when it pairs (section 6), and its
device record names them (section 10), which is what counts. Only the role member has them; a
phone and a watch have none, and the phone's hub needs no capability. Computers, Raspberry Pis
and routers have all three. A board such as the ESP32 has none. A Raspberry Pi inside a ZX
Spectrum Next, which reaches the network only through the Next's UART and is on only while the
Next is, has `admin` and `dials` but not `hub`. A hello's bits this version does not know are
read as absent; in a record or an Info they grant nothing.

#### Hello

The hello (`t` 1, [format](format.md), section 9.3) is the first message of each side after its
intro. Everything in it is shown or asks for something; what a device may do comes from its
records. It carries the sender's capabilities, operating system and name (1 to 128 bytes), its
wall clock (for skew reports only: `cbb status` shows `skew_ms`), the set digest and how many
records it holds (section 10, "Sync"), its sync (`mode`: shared or own; design.md, "Sync on and
off") and its mute with how long it still lasts (design.md, "Muting a device"), Device (below),
where its keys live (section 17), its quick actions that are on (section 15), the sequence
numbers of the newest signed release and entry points it holds and of their keys (section 16,
"In the group"), `features` (bit 1: it serves blobs, "Content" below), and the epoch of its own
keys statement, so that a peer holding an older one asks for it.

When what its hello says changes (its sync, its mute, its quick actions, Device), a member sends
a new hello on every connection at once, and the receiver replaces what it knew of the sender,
so the change shows without the connection ending. A receiver keeps a mute's end on its own
clock, so the clocks need not agree. On a peer's hello a member sends the signed release and
entry points it holds when the peer's are older (section 16).

The admin key travels in the joiner's Info and the root's record, the seal key in the keys
statement, and the tunnel's keys in message `tunnel`, to hubs only, so none of them is in the
hello.

#### Device

The hello's `device`, for the apps' device pages and icons, sent on every connection, so it
follows updates of the system and of the program. Every field is optional and shown, never
trusted:

| Field | Meaning |
|---|---|
| `form` | laptop, desktop, phone, tablet, tv, board, server, router, console, watch, retro or other |
| `os_version` | the system's version as the user knows it (`15.1`, `11 (build 26100)`, `Debian GNU/Linux 13 (trixie)`), 1 to 32 bytes |
| `version` | the sender's own version (`0.6.0`), the same limits |
| `mac` | the MAC address of the network card on the home network; phones send none, as their systems hide it |
| `archive` | the release archive this device installs with `cbb update` (`cbb-linux-arm64.tar.gz`, section 16), so that its group's hub fetches it: `cbb-` and two or three parts of 1 to 16 lowercase letters and digits joined by `-`, then `.tar.gz` or `.zip`; absent on a copy that another tool updates (Homebrew, winget, a package) and on phones. A hub ignores a name of another form |

#### Keys statements

Message `keys` (`t` 7) carries keys statements ([format](format.md), section 5): each device's
signed list of the keys a copy is sealed to, by epoch. A member sends every statement it holds
when a connection opens, and passes a new one on to its other connections. A copy is sealed only
to the devices whose statement it holds; a member that copied while it held no other reader's
statement (alone, or just joined) sends the copy with the time it was copied once one arrives.
When a new statement makes a device a reader that the current copy was not sealed to, the member
that made that copy seals it again to that device alone.

#### Copies

Message `copy` (`t` 2) carries one copy, sealed end to end (D-84; [format](format.md), section
10): the origin encrypts the content once and seals its key to each reader, so the members that
pass it on, a hub among them, and the forwarder and relay outside the group carry it without
reading or changing it. Every member checks the origin and the signature before it passes a copy
on, a reader opens its wrap, and the rules of ordering are in section 5. A reader that has no
wrap for a copy it should read (its statement moved on, or it joined after the copy) asks the
origin with `reseal` (`t` 23), and the origin seals the copy again to it alone
([format](format.md), section 10.4).

#### What the members in between see

They see that a device of the group sent a copy, when (`time`, and when it arrived), to which of
the group's devices (the readers), its size within a step, and whether it has images or files,
with their total size rounded up to 64 KiB. They do not see what the copy is (a text, a secret,
an image or files), its text, its file names or their number, or its exact size. The first two
cannot be hidden: the connection a copy comes on names its sender, and every member, one that
only passes copies on too, orders the copies by `time` to give the newest to a peer that
connects. The network outside the group sees less still: TLS, and away from home the group's
WireGuard tunnel around it, hide even this.

#### Content

A copy with images or files carries their manifest inside its sealed content and the size and
SHA-256 of its sealed blob in its header ([format](format.md), sections 10.2 and 10.3). A member
that wants the bytes asks a connected member for the sealed blob, by its SHA-256, and gets them
in binary frames: first the member it got the copy from, then the others. Members fetch, keep
and serve only sealed blobs, so a member that serves one, a hub that only passes copies on among
them, never needs to read it. The same messages fetch the archives of the signed release a
member holds (section 16, "In the group"), by their SHA-256, from a member whose hello has
`features` bit 1.

- `get` (`t` 13) asks for `length` bytes of the blob from `offset`; a server sends at most 1 MiB
  for one get. A member serves only blobs it holds whole and has checked against their SHA-256,
  and through the group's tunnel only those within its limit away from home. `length` 0 cancels.
- `missing` (`t` 14) answers a get for a blob the member does not hold whole, or could not read,
  and ends that fetch.
- A `chunk` frame ([format](format.md), section 9.1) carries at most 256 KiB of the blob at an
  offset. Chunks come in order; one at an offset the fetch does not wait for is left from a fetch
  that was cancelled and is dropped.
- A fetch asks for 1 MiB at a time and continues from what it holds after a reconnect. When 15 s
  pass without a chunk it sends the cancel and asks another member.
- The receiver checks the whole blob against its SHA-256 before it keeps or serves it, and a
  reader opens every segment and checks every part against its SHA-256 in the manifest before it
  writes the copy to its clipboard.
- The receiver's limit decides, against the blob's size: by default 100 MiB a copy at home and
  25 MiB from a member reached through the group's tunnel (`cbb config max-copy` and
  `max-copy-away`, 1 MiB to 1 GiB). A copy over it is not fetched, and `cbb status` says so. A
  hub, and a device that only passes copies on, fetches the blob of each new copy it does not
  write itself within its limit away from home, so that its clients away from home can get it;
  since it serves through its tunnel only blobs within that limit, its limit caps its whole star.
- A member that does not take images or files takes the copy like any other, so the group
  converges, passes it on, and writes only its text, as a text, to its clipboard; with no text
  it keeps its clipboard.

#### Reach

A computer tells each phone connected to it which other members it is connected to now, their
hellos received: message `reach` (`t` 18) holds their device IDs, sorted, at most 256, without
the phone's own, and is absent when there are none. It sends one after the phone's hello and
another whenever that set changes. Away from home a phone connects only to a hub, which passes
the phone's commands on to the members behind it (section 15), so the phone shows a member that
a connected member reaches as online through it. Each message replaces the last from that
connection, and the connection's end drops it. The list is shown, never trusted: a member may
leave a device out or name one it does not reach, as it could drop the commands it should pass
on. A receiver ignores an ID that is not valid or that no device record of the group names.
`cbb` sends it (`member/src/mesh/reach.rs`), the phones send none.

## 5. Sync semantics

The parts marked "wire" are needed for convergence, and an implementation MUST follow them;
the rest is the members' local policy, which another member SHOULD follow so that users see
the same behaviour. Source: `core/src/hlc.rs`, `core/src/copies` (`fresh.rs`),
`core/src/rule.rs`, `member/src/mesh.rs`, `member/src/board.rs`.

### The time of a copy (wire)

A copy's header carries its time, signed: a hybrid timestamp `[wall, logical]`, `wall` in
milliseconds since the Unix epoch, 0 to 253402300799999 (the last millisecond of 9999), and
`logical` a uint32 ([format](format.md), section 2). Order: by `wall`, then by `logical`. The
origin takes it from its hybrid clock (`cbb_core::hlc::Clock`): the wall clock, or, when the
wall clock has not moved past the last time it gave, that time with `logical` one higher. The
copy's age, `age_ms`, travels outside the signature, since it grows on the way.

### The current copy (wire)

The group's current copy, on a member, is the copy with the latest signed time among those it
took that are not secrets. A member sends it when a connection opens (section 4, "Message
order"), so a pair that meets after a copy converges at once: the receiver judges it as any
other copy and drops one older than what it holds or one it has seen.

### Passing copies on (wire)

A member remembers the last 4096 copies' IDs. A copy whose ID it has not seen, once it passes
the checks of every member (the origin is a device of the records that may send, and the
signature holds; [format](format.md), section 10.4), it passes on once to every other
connection: also when it is older than the current copy, also when it cannot read it, and with
sync on or off, since sync decides only what it does with its own clipboard. A copy that fails
the checks it drops and logs; the connection stays.

### Freshness (wire)

A reader decides whether a copy that opened is new from its signed fields
(`cbb_core::copies::fresh`), since `age_ms` alone could be set back by a member in between:

- With a clock, it refuses a copy signed more than the allowance ahead of it: neither written
  nor taken as the newest. The allowance is 5 minutes, and at most a quarter of the copy's
  lifetime.
- The age it uses is the larger of `age_ms` and the time since the signed wall time less the
  allowance, so a copy held back and sent again later is as old as it really is.
- It writes no copy whose signed time is not after the newest copy it wrote. An origin the
  records still name and have not frozen counts with its own time; a removed or frozen one only
  up to the newest time judged from the origins that still stand, so its copy dated ahead stops
  no one.
- A secret it has seen once, written or not, it never writes again.

It keeps what it saw (`marks.cbor` in the state directory) and saves it before it writes, so a
restart forgets nothing of it. A device without a clock decides by the signed times alone.

### Local copies

- A watcher's report of a change (`copied`) makes a copy unless the member's own clipboard
  already holds that text, or the member wrote that text itself within the last 10 s (its own
  write coming back; the last 16 writes are remembered), or its sync is off, or an admin muted
  it.
- Deliberate actions (`copy` on the control socket, sending from a phone) always make a copy,
  unless the member is muted, which they refuse with that reason. The text is also written to
  the member's own clipboard unless it already holds it.
- A copy's content carries the lifetime the group's root set for its kind (section 10, "The
  copies setting"), so every member sends the same (D-129). A member that copied while no other
  reader's keys statement was there sends the copy once one arrives (section 4, "Keys
  statements").

### Writing the member's own clipboard

When a copy that opened is new (above), it becomes the group's current copy here, and it is
written to the local clipboard when all of these hold (`cbb_core::rule`): the member's sync is
on (mode `shared`); the content is of a type this member writes (a text, or images or files on
a member that takes them; one that does not writes a copy's text alone, and keeps its clipboard
when there is none); a secret is within its own lifetime; and the local clipboard does not
already hold the content. A device that always listens keeps its own clipboard equal to the
group's buffer (D-128): the only age limit is the copy's own lifetime (D-129), so a member that
comes back with a live copy made after the group's current one makes it current and every
member writes it, while a copy made before the current one never becomes current and changes
nothing (`cbb_core::copies::fresh`, `Behind`). A write increments the write sequence number
(section 8). A phone, which listens only sometimes, swaps its own clipboard and the group's
buffer on a gesture and listens so only while its app is on screen (design.md, "The one
button").

When the records no longer name the current copy's origin (its device was removed), the member
drops that copy and never writes it later.

### Secrets

- A secret is usable for its own lifetime after the copy (the group's `secret_ttl_ms`, 60 s by
  default, section 10, "The copies setting"), judged by its age. After that it is neither the
  member's usable current text nor returned to the phone.
- A secret never becomes the current copy that a member sends when a connection opens, and a
  reader writes it at most once.
- A member that reads no copies (`forward_only`, or one without a wrap in it) cannot tell a
  secret from a text and passes it on as it holds it.
- A reader MUST NOT write a secret's text to disk.

## 6. Pairing a computer

Source: `core/src/join` (`mod.rs`, `info.rs`, `invitation.rs`, `welcome.rs`, `intro.rs`),
`core/src/msg/tables.rs` (the messages' tables), `core/src/third_party/cpace`,
`member/src/inviter.rs`, `member/src/pair.rs`.

### Pairing in 0.6

Pairing runs over TLS 1.3 with ALPN `cbb-pair/3` (section 19), each side presenting its key
container ([format](format.md), section 12) for the key it keeps. Its messages are CBOR maps in frames
(section 4, "The member protocol in 0.6"), the type in field 0 (section 19, "Member protocol messages"). Before
CPace is confirmed every frame takes the pairing limit, `format::frame::LIMIT_PAIRING` (1048576);
after it, message 67 alone may take the member limit, `format::frame::LIMIT_MEMBER` (7340032),
and every other message still the pairing limit. A message 67 before the confirm is refused
whatever its size (`pair/early-welcome`).

| `t` | Direction | Fields |
|---|---|---|
| 64 `pair/start` | joiner to member | 2 `Ya` bytes, at most 256; 3 `ADa` bytes, at most 16 KiB: the encoding of the joiner's Info |
| 65 `pair/reply` | member to joiner | 2 `Yb` bytes, at most 256; 3 `ADb` bytes, at most 1 KiB: `{1 group ID (16), 2 the member's device ID (16), 3 its name}` |
| 66 `pair/confirm` | joiner to member | 2 `Ta` bytes, at most 64 |
| 67 `pair/welcome` | member to joiner | 2 `Tb` bytes, at most 64; 3 the Welcome; 4 `Tw` bytes 64 |
| 68 `pair/done` | joiner to member | none: the joiner kept its identity |
| 69 `pair/error` | either | 2 `code`: 1 wrong-code, 2 closed, 3 busy, 4 expired, 5 too-many, 6 refused, 7 declined, 8 taken |

Every field is needed. An error code this version does not know is taken as `refused`. The short
code's commitment and nonces of earlier drafts are retired and never given again: message 64
with field 4, 65 with field 4 or 66 with field 3 is refused (`pair/start/retired`,
`pair/reply/retired`, `pair/confirm/retired`). Code 7, `declined`, stays for an app's own
refusal.

**CPace.** Suite CPACE-X25519-SHA512 of draft-irtf-cfrg-cpace-21 with explicit key
confirmation (Ta, Tb), the joiner the initiator. Its channel identifier is `cbb pair channel v3`
0x00 ‖ the key hash of the member's TLS key ‖ that of the joiner's ‖ the ID of the invitation
each side believes it is using, 16 bytes, never all zero (an ID no invitation has). The keys
are those of the key containers the handshake saw, so a party in the middle with keys of its own
gets another identifier and the exchange fails, and two ends in the flows of two invitations get
two identifiers. Its session identifier is the session's TLS exporter: 32 bytes of the label
`EXPERIMENTAL-cbb-pair-v3` with an empty context, exported only from a session that took
`cbb-pair/3`. The session mark takes the same 32 bytes, kept apart by its own label inside the
hash. The password is always an invitation's secret: a QR code's 32 random bytes (section 12),
or a home window's, from its six digits (below). Neither the ID nor the secret is ever all zero;
an end given one refuses (`refused`). The member sends message 67 only with an approval of this
session for this joiner: the joiner's `Ta` verified under the invitation's secret, which shows
that the joiner holds it. The joiner takes message 67 only once the member's `Tb` verified, which
shows the member holds it too. One approval makes one message 67. The vectors are
`testdata/format/messages3.json`, `codes`.

**A home window** (owner, 11-20) is how a computer, a phone or a watch at home joins without a
camera between them: an invitation that lives only at the member that opened it, never written
as text. Its ID is 16 random bytes, never all zero; its code is six random digits, each code as
likely; its secret is SHA-256(`cbb pair home code v1` 0x00 ‖ the six ASCII digits); its profile
is home only, any role but a leaf's, with at most read, send, secrets, and hub for a member
with the hub's capability. The member shows the six digits and a QR code
`cbb://pair?addr=…&fp=…&i=<ID hex>&c=<digits>`; its mDNS announcement adds `i=<ID hex>`, never
the digits. The joiner scans the QR code, or finds the window by mDNS and takes the digits its
person types, and derives the same invitation. A wrong digit fails at `Ta` (`wrong-code`), with
nothing written. At a home window the member's verified `Tb` is also the joiner's proof of that
member in that session (`join::invitation::Proven`), made only there: it is a guarded leaf's
only way to be bound to a new root after a change of root (`format::grant::read_bound`).

**Attempts.** An invitation takes one attempt at a time (another gets `busy`). The machine's
steps, from message 64 to message 68, have `join::invitation::ATTEMPT_MS` (30000) at the
member. An attempt counts as failed from its start, unless it ends in a Welcome; after
`join::invitation::MAX_FAILURES` (3) failures the invitation answers `too-many`, and one
Welcome closes it (`closed`). Six digits and three tries give three chances in a million. The
joiner counts too: at most three sessions per invitation, each started only by the person; the
app never retries by itself. Each attempt at the member has a number from its start, which the
later steps name, so a late message of an earlier attempt changes nothing.

#### Info

The joiner's Info is the map `ADa` carries:

| # | Field | Type | Needed | Meaning |
|---|---|---|---|---|
| 1 | `name` | text, 1 to 128 bytes | yes | the device's name |
| 2 | `os` | uint | no | its system |
| 3 | `caps` | uint, bits 1 to 7 | no | its capabilities (section 4) |
| 4 | `role` | uint 1 to 4 | yes | as the device record's |
| 5 | `admin` | key, ES256 | no | a joiner with `admin` in `caps`, or a phone: its admin key |
| 6 | `admin_pop` | bytes | with 5 | the admin key's signature over `cbb admin pop v1` 0x00 ‖ the session's TLS exporter |
| 7 | `keys` | envelope | no | the joiner's keys statement, epoch 1 |
| 8 | `device` | map | no | as the hello's `device` |
| 9 | `invite` | bytes 16 | no | the invitation's one-time ID, when it joins by one; never the zero ID |

#### The Welcome

Field 3 of message 67:

| # | Field | Type | Present | Meaning |
|---|---|---|---|---|
| 1 | `root` | key, ES256 | always | the group's first root key; its Group ID must be `ADb` field 1 |
| 2 | `records` | array of envelopes, at most 8192 | without parts | the whole set, in the order a receiver takes it: the root changes, the admitter's record with its rights, the joiner's own record, then the others |
| 4 | `keys` | array of envelopes, at most 256 | no | statements of the group's devices, the two devices' own first; with field 7 within `join::welcome::STATEMENTS_BUDGET` (2097152), the rest coming with the first sync |
| 5 | `time_ms` | time | always | the admitter's clock, for a joiner without one |
| 6 | `grant` | map | to a leaf | its first grant: fields 2 to 5 of message `grant` |
| 7 | `credentials` | array of envelopes, at most 259 | no | the current period's server credentials (section 18) |
| 9 | `recovery` | key, ES256 | always | the recovery key's first half |
| 10 | `list` | bytes | without parts | the newest recovery record's list: its count and at most `records::LIST_MAX` (1536) IDs of 34 bytes |
| 11 | `recovery2` | key, SLH-DSA | always | the recovery key's second half |
| 12 | `digest` | bytes 32 | every Welcome but a leaf's | SHA-256(`cbb welcome digest v1` 0x00 ‖ the set digest (32) ‖ the count of lists, 4 bytes big-endian ‖ each list's hash under `cbb recovery list v3`, sorted) |
| 13 | `parts` | uint 1 to `join::welcome::MAX_PARTS` (64) | when the set does not fit | how many `records` messages follow |

Rules between fields: with 13, neither 2 nor 10 (`welcome/parts`); without 13, field 2
(`welcome/shape`); a leaf's Welcome (with 6) has neither 12 nor 13 (`welcome/parts`,
`welcome/digest`); every other has 12 (`welcome/digest`).

**The Welcome's tag.** Every Welcome, a leaf's too, carries `Tw` in field 4 of message 67:
K_w = HMAC-SHA-512(ISK, `cbb welcome key v1` 0x00), and `Tw` = HMAC-SHA-512(K_w, `cbb welcome
v1` 0x00 ‖ the bytes of field 3 exactly as they stand in message 67). ISK is CPace's
intermediate session key; K_w is its only use besides Ta and Tb, under a label nothing else
uses. The joiner checks `Tw` in constant time over the bytes as received, before it reads
anything of field 3 beyond where it starts and ends; a message 67 without `Tw`, or with another,
is a failed pairing (`pair/welcome/tw`), with nothing read and nothing kept. `Tb` alone does not
cover the Welcome. `Tw` covers every field, so it binds field 12, and through it every part.

**The Welcome in parts.** A set that fits the Welcome (within
`join::welcome::RECORDS_BUDGET` (5177344), with at most one list) rides in field 2. A wider one
rides whole in `records` messages (t 5: field 2 record envelopes, at most
`records::sync::PART_RECORDS` (4096); field 3 lists, at most 64; at least one of the two) right
after message 67, as many as field 13 says, at most `join::welcome::MAX_PARTS_BYTES`
(101039910) together. Each part comes within `join::welcome::PART_MS` (120000) of the one
before, and all within `join::welcome::PARTS_MS` (1500000) of message 67 (`welcome/late`);
these are the core's ceilings, and a service may be stricter. A message other than `records`
before the last part, or a part after it, is refused (`welcome/parts`).

The joiner holds each part as it comes, reading each record's envelope and refusing at once on
one that does not read; it evaluates nothing. After the last part it takes every part into a
new set, where each signature is verified, and refuses unless the set's digest with its lists
is field 12 (`welcome/digest`); it refuses a stopped group; and it refuses unless every record
and list it was sent is held (`welcome/digest`): a record whose first signature does not cover
its second is not held. On any failure the joiner drops the parts, the set and the Welcome, and
keeps nothing.

**The joiner's checks.** With the whole set, the joiner checks that the two keys' Group ID is
`ADb` field 1; that the admitter's key, from the TLS handshake, is a device of the group; that
the records hold its own record with its own key, signed by the root or by the admitter's admin
key with the power to admit; and the path of roots the records lead to. What binds the member:
the invitation's secret, CPace's password, whose `Tb` verified. A guarded leaf takes only a
record the root signed itself. Only then does the joiner store the
set and its identity, and send message 68.

#### The intro

The first message to a peer that does not know the sender's key yet is the intro (t 8): field
2, record envelopes in the order a receiver takes them (the root changes, the records that
prove the admitter's rights, the sender's own record); field 3, the sender's keys statement.
A device cannot tell whether its peer knows its key, so it sends its intro as the first message
to every peer that stands as a member in its own records; a peer that knows the sender already
ignores it. A peer whose key it does not know yet gets nothing until that peer's intro makes it
a member, not even this device's intro; then this device sends its own. Two devices that each
know the other's key send theirs both ways. This is how a device admitted after another one
reaches it when the device that admitted it never meets that one: a computer added through a
phone root, for a phone that joined earlier (phones do not dial phones, and computers do not
dial phones). The intros a member takes from connections other devices made count against
`join::intro::MAX_PER_WINDOW` (4) per address and `join::intro::MAX_PER_NETWORK` (256) per
network in `join::intro::WINDOW_MS`; an intro must come within the handshake's 10 seconds.
The recovery heads count apart, at most `join::intro::MAX_HEADS` (65); the other records at
most `join::intro::MAX_RECORDS` (32) and `join::intro::MAX_BYTES` (16384) by their envelopes'
bytes (`intro/size`; vectors: `messages3.json`, `intros`). The receiver checks every signature
up to the root it holds before it keeps any, then goes on; anything that does not check closes
the connection and keeps nothing.

#### The window and who dials

In 0.6 the joiner always dials, and the device it joins through always waits: a member opens a
pairing window and the new device connects to it. No device listens to join. A computer opens
its window with `cbb pair` (`member/src/joining.rs` is the joiner, `member/src/admitting.rs`
the member); a phone that may admit (the root phone, or a phone with an admin key that has
`admit`) opens one with "Add a device" (`cbb_window_new`, `ffi/src/window.rs`), and a new phone
joins with one Join button (`cbb_joiner_new`, `ffi/src/joiner.rs`).

- While the window is open the member takes pairing sessions (`cbb-pair/3`) on its member port,
  one at a time; a session that comes while another runs gets message 69 `busy`. A phone's
  window needs its member port open, and closes after five minutes unless the person gives it
  another time (an hour at most), when the person closes it, or when the app frees it.
- The member shows the window's QR code (section 7): its addresses with the member port and the
  fingerprint of its TLS key, nothing secret. A phone scans it and dials the addresses in turn,
  and goes on only with the member whose key in the handshake has that fingerprint; any other
  key is refused before message 64.
- While the window is open the member announces it by mDNS (section 3): `v=1`, `g=<tag>`, `p=1`
  and `f=<fingerprint>`. A device without a camera (Aurora) browses for such a window for up to
  10 s and MUST refuse when more than one announces itself; it dials the one, its addresses and
  `f` in place of the QR code's. The announcement is not authenticated, and needs not be: both
  persons compare the code, and the fingerprint only keeps the session to the device announced.
- Both ends then show the code the session commits to ("The short code" above), each person
  answers, and the session goes on only after both said "they match". The member writes the
  joiner's record by the admission rules (`join::decide::joiner_record`): at home a member or a
  phone reads, sends and takes secrets, a watch only reads, and a small device without a screen
  joins only by its own invitation. A phone joins as a member of the group with role `phone`;
  the root makes it an admin later, from the admin key its hellos offer.

## 7. The join QR code

### The window's QR code (0.6)

Source: `ffi/src/window.rs` (`qr_text`), `ffi/src/joiner.rs` (`read_code`).

The QR code a member shows while its pairing window is open (section 6, "The window and who
dials"), which the new phone scans:

```
cbb://pair?addr=192.168.1.20%3A8764&addr=%5Bfd00%3A%3A20%5D%3A8764&fp=<64 hex digits>
```

| Field | Count | Meaning |
|-------|-------|---------|
| `addr` | one to four | the member's addresses with its member port, `host:port`, best first; an IPv6 host in brackets |
| `fp` | one | the key hash of the member's TLS key ([format](format.md), section 12), 64 lowercase hex digits |

The values are percent-encoded (Conventions, "Bytes"). A reader matches the scheme and the host
`pair` without regard to case, decodes only percent escapes, ignores fields it does not know,
keeps at most the first four addresses and drops one it cannot read; a text without `fp` or
without an address is not a window's QR code. Nothing in it is secret: the code both persons
compare binds the session.

### The join QR code of the ESP32 firmware

Source: `core/src/pair.rs` (`join_qr`, `parse_join_qr`).

The QR code that the ESP32 firmware shows while it waits to join carries a URL. No device
of 0.6 dials it, so the board joins no group of 0.6; it joins by a pairing window from 0.7.

```
cbb://join?code=123456&addr=192.168.1.20:8764&addr=[fd00::20]:8764&fp=<fingerprint>
```

| Field | Count | Meaning |
|-------|-------|---------|
| `code` | one, first | the six-digit pairing code |
| `addr` | zero to four | where the joiner listens, `host:port`, best first; an IPv6 host in brackets |
| `fp` | one | the fingerprint of the key of the joiner's self-signed certificate (Conventions, "Fingerprints") |

The values are percent-encoded (Conventions, "Bytes"). A reader matches the scheme and the
host `join` without regard to case, decodes only percent escapes, never a `+` as a space,
ignores fields it does not know, keeps at most the first four addresses and drops an address
without a port; a text without `code` is not a join QR code.

## 8. Local control socket

Source: `internal/control`, `internal/service/socket.go`, `internal/connector/connector.go`.

### Socket and permissions

| Platform | Path | Group |
|----------|------|-------|
| Linux | `/run/cbb/control.sock` | `cbb` |
| OpenWrt, FreeBSD | `/var/run/cbb/control.sock` | `cbb` |
| macOS | `/Library/Application Support/cbb/control.sock` | `_cbb` |

`CBB_SOCKET` overrides the path for clients. The socket is a Unix stream socket with
mode 0660, made in a private temporary directory and renamed into place, so only root, the
service's user and members of the group can connect; secrets travel only to them. An
implementation MUST NOT let any other local user connect, and MUST NOT listen for these
operations on a network socket. On Windows
it is `%ProgramData%\cbb\run\control.sock`, in a directory whose protected access
list lets in the system, administrators, the service's account and the group.

Next to it the service listens on the **admin socket** `admin.sock` (on Windows
`run\admin\admin.sock`, in a directory of its own, which the service makes before the control
socket's and makes again at each start unless the system, the administrators or the service owns
it), with mode 0600: only root and the
service's user (on Windows the system, administrators and the service's account) can
connect. `CBB_ADMIN_SOCKET` overrides its path for clients. The control socket takes only
`copy`, `paste`, `copy_media`, `copied_media`, `paste_media`, `config`, `status`, `devices`, `muted`, `sync` without `device`, `release`, `release_get`, `release_held`, `entries`, `entries_get`, `keys` (from root only), `confirm` and `watch` (with
the watcher's `copied`, `clipboard`, `injected` and `acted`), and every other operation only once the user at the screen
confirmed it with the system's prompt, which the service checks itself (below); the admin socket takes them
all without one, and MUST be the only other way to them. So a program of a user in the group can use the clipboard but cannot admit, remove,
rename, freeze or make admin a device, take over, or change sync away from home. `cbb` dials the socket each operation needs.

An admin operation on the control socket carries `auth` in its `args` where the system needs
it, and the service takes it only when the confirmation holds (docs/design.md, "Confirming admin
actions"): on macOS `auth` is the base64 external form (32 bytes) of the caller's authorization,
which must hold the right `tools.cbb.admin` for five minutes, or for an operation confirmed
each time `tools.cbb.admin.each.` and the operation (`tools.cbb.admin.each` for one not
listed). One
confirmation covers the group's everyday changes for five minutes (`sync` of another device,
`mute`, `unmute`, `rename`, `remove`, `freeze`, `thaw`, `resolve`, `ttl`, `network`,
`paste_on`, the quick actions' operations, `release_file`, `release_want` and `update_way`);
every other operation, such as `new`, `leave`, `take_over`, `recover`, `hand_over`,
`key_level`, `takeover_delay`, `make_admin`, `pair`, `join`, `invite`, `away`, `hubs`,
`paste_receive`, `keyboard` and `remote`, is confirmed each time, and `confirm_key` only on
the admin socket. On Linux polkit
must authorize the calling process for the action of the same name, and `auth` is empty; on
Windows `auth` is `CHALLENGE.SIGNATURE`, both base64, the challenge from a `confirm` request
whose `value` is the operation and whose `name` and `device` are the request's (the service
shows that action in the user's session first): the RSASSA-PKCS1-v1_5 SHA-256 signature,
by the user's registered Windows Hello key, of `cbb confirm v2\n`, the action as the prompt
names it (`cbb`, the operation with `-` for `_`, then `name` and `device` when set, each after a
space, without control characters and cut to 80 characters), `\n` and the challenge's 32 bytes.
`mute` and `unmute` of the device itself, by the user at the screen, need no `auth` unless
another admin muted it. A refusal says
`the confirmation was cancelled` when the user cancelled the prompt, and `this computer cannot
confirm the admin action for this user, so only the administrator may run it` when nothing
confirms it.

### Framing

Each message is a JSON header on one line ending in `\n`, at most 64 KiB, followed by exactly
`len` bytes of raw payload (at most 1 MiB + 64 bytes), usually a clipboard text in UTF-8.
The header is the envelope of the core's requests (docs/core-api.md, "Requests and answers"): a
request or a watcher's message is `{"op", "args", "len", "seq"}`, an answer `{"ok", "len",
"seq", "done"}` or, failed, `{"error", "detail", "seq", "done"}`; `len` and `seq` are omitted
when 0. The operations, what goes in `args` and what comes back in `ok`, are in
[core-api.md](core-api.md), "The member's operations": one list for this socket and the phones'
`cbb_member_call`, with the same names and bodies. On the socket a text or other bytes travel as
the payload after the header, `len` bytes, and `done` marks the last answer to a request. A client
reads an answer as op `reply`; `copy_media`, `copied_media` and `release_file` send their
parts as `part` messages and their bytes as `data` messages, and `paste_media` and
`release_get` answer the same way.

A connection carries one request: the service reads the first message and dispatches on
`op`; an unknown `op` fails. An answer has no `op`. A failure is
`{"error":"...","done":true}`.

### Watcher protocol

A desktop connector or the Mac's pasteboard agent keeps a `watch` connection open.

- The watch request's payload is recorded as the member's own clipboard text without making
  an event. If a write was pending (decided while no watcher was connected) and is still the
  member's own text, the watcher gets that write instead.
- Watcher to service, any number, no answers:
  - `copied` (payload, `kind`, `via`): the clipboard changed; the engine decides whether it is
    an event (section 5). A watcher reports `via` `universal-clipboard` for items that came
    through Universal Clipboard.
  - `clipboard` (payload, `kind`): what the clipboard holds, without a change; used for items
    that a password manager marked (`kind` `secret`), which the engine remembers as secrets.
    The Go connector sends marked items only this way, never as `copied`.
- Service to watcher: `write` (payload, `kind`, `via`, `seq`, and for a secret `ttl_ms`).
  `seq` grows with every write the engine decides on (starting at 1 per service run); the
  service sends each write to every connected watcher, dropping the oldest queued write for
  one that falls 16 behind. A watcher MUST ignore a write whose `seq` is not greater than the
  last one it applied. `ttl_ms` is the secret's remaining lifetime (its own `ttl`, 60 s by default, minus its
  age, at least 1 ms); the Go connector uses 60 s when it is missing and gives up the clipboard when
  it expires. A watcher writes a secret with the platform's password-manager marks.
- A copy of images or files: a watcher whose watch request set `images` (for a copy with an
  image) or `files` (for a copy of files and folders) gets, once every part is in the cache,
  a `write` with `kind` `media` whose payload is the plain-text alternative. It fetches the
  parts with `paste_media` on a connection of its own and writes the image (with the text
  next to it) into the clipboard, or saves the files in a new folder of its own and puts
  their paths there, or writes the text alone when the fetch fails. Other watchers get the
  plain-text alternative as a `text` write when there is one, and nothing otherwise. A
  watcher reports a copied image or copied files with `copied_media` on a connection of its
  own (one `png` or `jpeg` part with the text as the payload, or the files and folders as
  `cbb copy` sends them, without a text), never as `copied`; a clipboard that holds a text
  and an image is reported as text, and one that holds files as the files. A newer copy
  stops a report or a fetch still running.
- Service to watcher, for a quick action (section 15), only to a watcher whose watch request
  set `act`: `act` (`seq`, `name`, the action, and for an action of the user's own
  `command`, its program by full path and its arguments, as the device's user set them).
  The watcher runs it in its session, a `command` without a shell and for at most 15 s, and
  answers `acted` with the same `seq`, as `injected` below: no `error` when it did, or
  `error` (and `detail`), with `refused` when it would not. On a Mac and on Windows the
  service's own user has no right to lock, sleep or shut down, so the service hands the
  presets to the agent of the user signed in, waiting up to 20 s; on Linux it asks logind
  itself.
- Service to watcher, for remote paste, only to a watcher whose watch request named an
  `inject` target: `inject` (payload, `seq`, `method`, `enter`, `kind`, `name`, the
  sender's device name, and for a `desktop` watcher `keys`, the grant for the uinput
  helper; `cbb` without its helper gives no grant, so a desktop connector that types through the
  uinput helper refuses its pastes). The watcher checks
  that its session is active and not locked, puts the text in, presses Enter when `enter`
  is set, clears the clipboard after a `secret`, shows a notification with the sender, and
  answers `injected` with the same `seq`: no `error` when it did, or `error` (and `detail`),
  with `refused` when it would not (a locked session, an administrator's window, a missing
  permission) rather than could not. An `inject` of `kind` `media` goes only to a `desktop`
  watcher whose watch request set `images`, `files` (or `html`) for what the copy holds; its
  payload is the copy's event ID, which the watcher fetches with `paste_media` and `value`
  on a connection of its own, writes into its clipboard as it writes a copy, and pastes with
  the paste keys alone; the service waits 8 s for it, after the copy arrived. The service waits 5 s for it, and 5 ms more for each
  byte it types. A watcher whose target is `tmux` or `console`, or whose watch request
  set `paste_only`, holds no clipboard: the service sends it no `write` and takes no report
  from it. On a Mac only the app pastes (a `desktop` watcher with `paste_only`): macOS lets
  an app press keys once its user allowed it in Accessibility, and the service and its
  pasteboard agent are not apps; without it the member refuses with a reason that says so. `status` shows the
  switches and the targets of the connected watchers as `paste: {on, enter, console,
  no_lock_check, targets}`.
- Reports with an unknown `kind` or `via`, and other `op`s, are logged and ignored.
- The socket's group is for the clipboard, while a remote paste and an action go to one
  user's screen or console. So the service MUST read the user at the other end of a watcher
  that offers an `inject` target or `act` from the system (`SO_PEERCRED` on Linux,
  `LOCAL_PEERCRED` on a Mac and FreeBSD, on Windows the process at the other end, from
  `SIO_AF_UNIX_GETPEERPID`, with its user and session) and hand it a paste or an action only
  when that user may take it: root and the service's own user (on Windows the system and
  the service's account) take every target, and `console` only they; `desktop` and `act` go
  to the user of an active session (on Linux and FreeBSD an active graphical logind session
  of the user's own, X11 or Wayland, on a seat or not remote, so that a user signed in over
  SSH alone takes none, even with a session type set by hand; the
  owner of `/dev/console` on a Mac; an active Windows session), and `tmux` to a user with a
  session (logind's, active or online, which counts one over SSH; never the user's service
  manager or a greeter). A watcher whose user the system does not name gets
  none. Where the system does not tell who is at the screen (Linux or FreeBSD without
  logind), a paste goes to any target, but a `secret` to none, and the member refuses it
  with a reason that says so. `cbb` checks its `tmux`, `console` and `desktop`
  watchers the same way.
- A watcher MUST check right before it injects keys that its session is active and not
  locked, and refuse otherwise; a watcher MUST NOT run an action's `command` through a
  shell.

## 9. The phone as the root

In a group that a phone app creates, the phone is the root of trust ("The phone apps" in
[design.md](design.md)). Sections 1-8 hold for it too. A group a computer creates (`cbb new`)
has a root of the same form, which the computer holds in a file (section 10, "Admins").

- **Group CA.** The app creates the group root CA: a P-256 key in the Secure Enclave or
  StrongBox that cannot be exported, with the certificate profile of section 2 except
  path length 1 (MaxPathLen 1), CN `cbb group root YYYY-MM-DD`. Below it every admin
  phone has an admin CA (section 10). Computers get member certificates; a computer holds a
  CA key only when the root phone makes it an admin (section 10, "Admins").
  A phone MUST ask for the user's presence (Face ID, the fingerprint or the passcode) before
  it signs with the root or an admin key. Aurora OS lets no regular app ask the system for it,
  so the Aurora app keeps its root or admin key in a token of its own in the TEE behind a PIN
  the user chooses (at least four digits, apart from the phone's), which the TEE checks
  before the key signs and which locks the key for good after seven wrong ones (D-94). A group CA has path length 1 (`checkCA`). A Welcome without CA keys makes a computer without them (section
  6).
- **The app is a member.** It holds a member certificate of its own group with role
  `phone` and speaks the member protocol of section 4. It dials and never listens for
  members (a phone cannot accept connections in the background), so members MUST NOT dial a
  `phone` member; it publishes no mDNS records, except while its pairing window is open
  and while it is the group's hub, when other phones dial it (section 3, `p=1` and
  `r=phone`).
- **Pairing direction.** The joiner always dials: the root phone, or a phone that may admit,
  opens a pairing window and shows its QR code, and the new device dials it (section 6,
  "The window and who dials").
- **Finding the members.** The app trusts its own CA and finds members through mDNS browsing.
  It keeps the home network addresses (private IPv4, unique local IPv6) of the QR code of
  each computer it admitted, the one that answered first, and dials a computer of the
  group's list at them while browsing does not find it, as one in another subnet that
  mDNS does not reach. TLS checks the peer as for a found member.
- **Renewal and revocation.** The admin phones renew certificates with `cert` messages, as
  an admin computer does (CBBKit's
  `GroupCertificates.renewal`, from the chain of the phone's member's `peer` event, sent
  with its `send_cert`; the app also renews its own certificate at start). The Android
  app's root and admin keys sign only right after the user's authentication, one signature
  each, so it notes a peer that is due and sends its `cert` message on the peer's connection
  once the user confirms it, the next time the app is open. Revocation and the devices list are section 10, and a second admin
  phone is the way back when a phone is lost.

### The recovery sheet (0.6)

Source: `core/src/sheet.rs`, `core/src/records/pq.rs`. The recovery sheet holds a 0.6 group's
recovery secret on paper, as text a person types and as a QR code, each with its version. The
secret is 32 random bytes. The recovery key's two halves come from it as `records::pq`
derives them: K1, an ES256 key, under the label `cbb recovery key es256 v1`, and K2, an
SLH-DSA-SHA2-128s key, under `cbb recovery key slh-dsa-sha2-128s v1`. The sheet adds no
derivation of its own.

**The text, version 1.** The text is Crockford's base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`). It
is read in its canonical form: upper case, `I` and `L` read as `1`, `O` as `0`, and spaces,
line ends and hyphens dropped. Every check is over that form, and an input longer than
`sheet::MAX_INPUT` (512) characters is no sheet. A sheet has 56 data characters:

- the version, `1`;
- the secret, 52 characters, the last 4 bits zero;
- a whole-sheet check, 3 characters: the first 15 bits of SHA-256(`cbb recovery sheet v1 whole`
  ‖ 0x00 ‖ the version character ‖ the secret).

It is written as 4 lines of 4 groups of 4, 64 characters. Each line of 16
characters is 14 data characters and 2 check characters: the first 10
bits of SHA-256(`cbb recovery sheet v1` ‖ 0x00 ‖ the line number, 1 byte from 1 to 4 ‖ the
line's 14 data characters). So a reader says which line holds a mistake, and when every line
check holds but the whole check does not, that the typing has a mistake rather than that the
sheet is another group's.

A reader gives its verdicts in this order:

1. no sheet: not base32, or characters outside the alphabet at another length;
2. a sheet of an earlier cbb: 56 characters, or 0.5's QR prefix (0.6 groups are made anew);
3. needs a newer cbb: a first character other than `1`, and nothing else of the sheet is read;
4. a character outside the alphabet in a text of 64 characters;
5. not 4 lines of 16 characters;
6. which lines fail their check;
7. padding bits that are not zero;
8. a mistake in the typing: the whole check fails.

**The QR code, version 1.** The QR code is text in QR's alphanumeric mode: `CBBR`, the version
character, then the base32 of the secret and the Group ID (77 characters with one zero spare
bit), 82 characters in all, read in canonical form. Another version character
means it needs a newer cbb.

**Against the group.** K1 and K2 from the secret must be the group's recovery keys. A QR code
that names another Group ID is another group's sheet. One that names this group but gives other
keys is damaged. A text that gives other keys is another group's, since its checks held.

The vectors are in `testdata/format/sheet.json`: sheets with their K1, K2, text and QR code,
reads, refusals, and checks against a group.

### The recovery key on a YubiKey (0.6)

Source: `core/src/sheet/yubikey.rs`; the card's commands are in `member/src/piv/recovery.rs`,
which the phones reach through the core (`cbb_piv`, [core-api.md](core-api.md)). A YubiKey 5
holds what the sheet holds: the version and the 32-byte secret. They are sealed to a P-256 key
that the card made in one of PIV's retired slots (0x82 to 0x95), which never leaves the card
and does ECDH only after the PIN and a touch.

The sealed value is `CBBR` ‖ the version (1 byte, 1) ‖ E (65 bytes, an uncompressed P-256
point) ‖ the ciphertext (49 bytes), 119 bytes in all.

- **Sealing**, on the phone, from the sheet or when the group is made. The phone draws a fresh
  key e with its point E. Z is the x coordinate of e times the card's point. K =
  HKDF-SHA256(salt E ‖ the card's point, Z, info `cbb recovery yubikey v1`, 32 bytes). The
  ciphertext is ChaCha20-Poly1305 under K, with a nonce of 12 zero bytes (K seals once), and
  associated data `cbb recovery yubikey v1` ‖ 0x00 ‖ the version byte ‖ the card's point. It seals
  the sheet's version character `1` and the secret.
- **The container.** The sealed value travels in the slot's own certificate object (`5FC10D`
  for slot 0x82 up to `5FC120` for slot 0x95; tag 70 the certificate, 71 0x00, FE empty), as
  a certificate that other PIV tools read and show: version 3, the card's point as its
  P-256 key, subject and issuer the CN `cbb recovery ` followed by the group's tag (the first
  8 bytes of the group's ID in 16 lowercase hex digits), valid from 1970 to 9999, key usage
  digital signature, and the non-critical extension
  `1.2.840.113556.1.8000.2554.16084.34999.32171.17779.49103.9600978.4690077` (cbb's own,
  made from a UUID under Microsoft's arc for such identifiers), whose value is an OCTET STRING
  of the sealed value. A throwaway key signs it and is dropped; nobody checks the signature,
  since the certificate only carries the bytes and names the group. The certificate objects
  read without the PIN, so a device finds the group's slot before asking for the PIN, and a
  card can hold the recovery keys of several groups, each in its own slot.
- **Choosing the slot.** The first slot from 0x95 down to 0x82 that holds neither a
  certificate nor a key (GET METADATA answers 6A88 for an empty slot; 6A82 is taken the same
  way). A slot that holds either is never touched, whoever put it there; a slot with a key but
  no cbb certificate (another tool's, or a seal that stopped before its last write) stays
  taken for good. When every slot is taken the card is refused ("every retired PIV slot of
  this YubiKey is in use"); a card that holds this group's recovery key already is opened,
  never sealed again. Before anything is written the firmware must be 5.3 or later (GET
  VERSION). The writes go in this order: GENERATE in the slot (PIN policy always, touch
  policy always, checked by GET METADATA), then the container, read back. Nothing is
  overwritten, reset or deleted.
- **Opening.** The device reads the 14 certificate objects without the PIN and keeps the
  ones whose CN carries the group's tag: none is "this YubiKey holds no recovery key of
  cbb", two are refused ("two recovery keys for this group"). The slot's key must be one cbb
  asked for (P-256, made on the card, PIN and touch always) with the point the container
  names; then the PIN, and the card gives Z for E after a touch, and the device does the rest.
  The secret is checked against the group's recovery keys and serves one signing. A computer
  that opens a card without naming the group (`cbb recovery -yubikey`) takes the one cbb
  container on the one such card and refuses a card with several.
- **Reading.** A value that does not start with `CBBR` is not cbb's, whatever follows. A later
  version is "this YubiKey needs a newer cbb", and nothing else of it is read. cbb's prefix and
  version with bytes that do not read, or a point off the curve, is damaged. A value that does
  not open with the card's key, or opens to a secret whose K1 and K2 are not the group's
  recovery keys, is another recovery key. A card key that is not a P-256 point is not one cbb
  uses.
- **The management key.** GENERATE and PUT DATA need the card's management key. A device uses
  it as the card keeps it and never changes it (D-127): one that the PIN protects (Yubico's
  PIN-protected mode, the key in `PRINTED` 5FC109 and the flag in `ADMIN DATA` 5FFF00) after
  the PIN, quietly; the factory key, of either kind (Triple DES or AES-192), as it is; any
  other key typed by the person, three tries at most. A key derived from the PIN is refused.
  Nothing resets PIV. The YubiKey and the sheet hold the same secret: one lost or spoiled does
  no harm while the other is whole.

The vectors are in `testdata/format/sheet.json`, `yubikey`.

## 10. Admin CAs, device records and revocation

0.6's records are described in "Records in 0.6" below. The rest of this introduction, and
the subsections under "Until the switch to the core (wave 5)", describe 0.5's version 2.

The wire side of "Admin phones, the devices list and revocation" in
[design.md](design.md). The group's authority records are of version 2: one rule evaluates
a set of them into the group's state ("The state"), and it is written in Rust
(`cbb_core::authority` and `cbb_core::group`, `core/`) for
`cbb` and, through the core's entry point ([core-api.md](core-api.md)), for both
phone apps, which sign records with the Secure Enclave or the Keystore (`Records.swift`;
the Android kit through the core's member, `CoreMember.act`) but evaluate none themselves. Go's release builds evaluate
through the core as well. The vectors (`testdata/interop/v2-records.json`) and the
differential run compare the whole state; why the records changed from version 1 and how
they are tested is in [records-v2.md](records-v2.md).

There is no migration from version 1: a member that holds records of version 1, or a group
made before them, refuses them, and the group is set up again.
A computer or a small device that finds a group of version 1 at start (its `records.json` is a
JSON array, or, on a computer, its group CA has path length 0, section 2) leaves it: it moves the group's files into `before-0.6` in its state directory,
keeps its settings, and says so in its log and, on a computer, in `cbb status`; CI's upgrade
job checks it from 0.5.0.

### Records in 0.6

Source: `core/src/records` (`eval.rs` the evaluation, `keep.rs` the rooms, `set.rs` the set and
its writers, `sync.rs` sync by parts, `pq.rs` the recovery key), and their tests. A record is a
signed object of the conventions (section "Conventions", "Signed objects (0.6)") under the
label `cbb record v3`. The kept set and the state depend on the set of records alone, never on
the order in which they came, and no rule reads a clock.

#### Types

| `type` | Record | Signed by |
|---|---|---|
| 1 | `device`: a device's key, name, role, rights and powers | a root, or an admin with the power to admit (its first record only, base rights) or manage |
| 2 | `revoke`: a removal of keys, with what its author saw of them | a root or an admin |
| 3 | `freeze`, 4 `thaw` | a root or an admin |
| 6 | `resolve`: a root voids an admin's record in a conflict | a root |
| 7 | `settings`, 8 `copies`, 10 `hubs` | a root |
| 9 | `checkpoint`: the heads it settles and the records it keeps | the current root |
| 13 | `recovery`: a change of root | the group's recovery key |
| 14 | `ack`: the heads an admin holds (`seen`, field 10, not empty), so that a removal may be settled ("Checkpoints"), and optionally a spare admin key (`spare`, field 11, ES256) its device made and signs nothing with, which a change of root names ("Re-issue") | an admin |

Types 5, 11 and 12 of earlier drafts are refused (`records/retired`): the root changes only by
the recovery key.

A `settings` record's field 15, `servers`, is the group's own servers, which the root signs so
that every device takes them from the records (D-61, D-121): at most
`records::body::MAX_SERVERS` (16) entries `[kind, endpoint, pin]`, `kind` 1 forwarder, 2 relay,
3 push (reserved), `endpoint` text `host:port` of 1 to 255 bytes, `pin` the 32-byte SHA-256 of
the server's TLS key (Conventions, "Fingerprints"), each `kind` and `endpoint` once
(`records/settings/servers`). 0.6 writes relays alone, set by `cbb global relay` on the root
(an admin asks the root); the forwarders come signed in the hub order. A reader keeps an entry
of a kind it does not know and passes over it.

#### Rooms and units

A set's room is `records::MAX_RECORDS` (7168) units of 512 bytes, and
its records take at most `records::MAX_SET_BYTES` (3670016) bytes. A record takes one unit for
each 512 bytes its body and `records::ENVELOPE_ALLOWANCE` (83) start, at least one. A second
signature takes no units, so every room holds as many twice-signed records as plain ones. The
second signatures of a set take at most `records::MAX_SET_SIG2_BYTES` (134217728) bytes beside
the rooms, and a recovery head's second signature is counted as
`records::HEAD_SIG2_ALLOWANCE` (33280) bytes. The first signature covers the body and the
SHA-256 of the second, so a second signature cannot be swapped on the way.

Each key has a ceiling: the current root `records::MAX_ROOT_RECORDS` (1536) units and each
admin key it names `records::MAX_ADMIN_RECORDS` (256), for at most `records::ADMIN_KEYS_MAX` (16)
admin keys. The roots before the current one, and the admin keys they named, have no room (cap
0): after a change of root only the last root counts. The room keeps
`records::CUT_ROOTS_RESERVE` (1536) units of headroom beside these ceilings, so no key pushes out
another key's records by making many of its own. Any other key has no room and keeps nothing. A record body is at most
`records::MAX_BODY` (16384) bytes, a checkpoint's at most `records::MAX_CHECKPOINT_BODY`
(262144), and a change's list names at most `records::LIST_MAX` (1536) IDs. A set has at most
`records::MAX_DEVICES` (256) devices.

A key keeps the longest start of its own order (below), in whole records, within its cap less
what the checkpoints that may count keep first of it ("Tiers inside the rooms" gives the caps).
Nothing is remembered between two judgments. With f the caps' judgment of a set of records:
what a set holds is f of it; an insert answers as f of what is held and the new record; a live
set and the same set restarted are equal and answer every record alike; two members that give
each other what they hold end equal; and a key whose records never pass its cap loses none, in
any order. What one member ends with may depend on the order it got records in, but only for a
key past its cap: a record that does not fit stops its key's run, and once dropped it stops
nothing (`core/tests/rooms.rs` pins such a case). That pairwise exchange among more members
ends is checked by search, not proved.

#### The order inside a room

Each key's records are taken in an order that depends on each record alone and on which
checkpoint is its key's newest, never on anything else the set holds (`keep::Item::pos`):

1. a root's removals, freezes and resolves, by seq, so that nothing else of the root's drops
   them;
2. the key's newest checkpoint (the highest seq; of two at one seq, the smaller ID);
3. the rest, by seq and then ID (records of one seq with other IDs count against the same
   ceiling);
4. the key's older checkpoints, the newest first.

Of a root that a change cut nothing is kept, listed or not, and such a record is turned away
before its signature is verified. The recovery chain is kept outside the rooms.

#### Tiers inside the rooms

There is no level. Each key has a fixed cap, read from the roster in the root's kept records
alone: the current root `records::MAX_ROOT_RECORDS` (1536) units, the roots a change cut 0,
and each live admin key `records::MAX_ADMIN_RECORDS` (256). A key that is no longer an admin has cap 0: what it signed stays only as far as a root's
checkpoint keeps it, and what a checkpoint keeps comes first in the rooms.

Who is no longer an admin is read from the root records of the path that the roots' rooms keep
(`eval::rooms`, `eval::not_live`; of a root that a change cut, nothing): the
roots' caps hang on nothing else, so their rooms are judged first. An admin key that a
root's record names is no longer an admin when a root's removal names it, when the newest root
record of the device that named it names another key or none, or when it comes after the first
`records::ADMIN_KEYS_MAX` (16) keys. The 16 are taken by the newest root record that names
each key: its root's place on the path, then its seq, then the smaller ID. A root's removals
come first in its room, and so does a root record that takes an admin key back, so the caps
never drop a record that decides who is an admin.

**The seen line.** A record of an admin key counts only on its key's grant line: it, or a
record below it on the key's chain, either has a `seen` entry that names a root record naming
the key as an admin, or a later record of that root (the entry's `seq` at that record's `seq`
or above, and its ID a record of that root the member holds on the root's counting line), or
is a record the counting checkpoint names (a head or a kept record), or sits right above one.
Any naming record will do, so a root's later update of the device never moves the line; the
writer names an admin key's head only at its newest record that counts, so a checkpoint
carries the line and never widens it. After a change of root, a checkpoint's head or kept
record, and a record right above one, carry the line only for a record whose `seen` names the
current root at or above a record of it that names the key (held or pruned): what the key
signed under an earlier root, or before it saw its new grant, stays void even when a root's
checkpoint points at it, so a member that held that record all along and a fresh one given
every record count the same. A seen entry for a root record the member does not hold
yet waits for it; one for a root record at or above a fork of the root stands on no counting
line. What a key signed before it saw its own grant is void: a void record is held, links
`prev`, does not count, and is charged to its signer like any held record; a key whose room
fills with its own void records has locked itself out and is taken back like any laggard. The
honest writer signs as an admin only once its state counts the grant, and its first record
then is an `ack` (`RecordSet::write_record`). So a root's removal signed below the root's
oldest record that names a key needs no `ack` of that key (GRANT_ABOVE): a member that counts
the grant holds the removal below it.

Before a root record that makes an admin key no longer an admin (a removal that names the key
or the key of a device that holds it, or a device record that takes the key back), the root's
writer writes a checkpoint of the root first, then the record (`RecordSet::write_record`). That
checkpoint keeps every record of a key that is no root that counts and is a head, and every
record of the keys going that counts, so what counted of them keeps counting on every member
that holds the checkpoint; a change's first checkpoint likewise keeps what counts of the admin
keys the change removes. When no such checkpoint can be written (the root has two histories),
the record goes alone, and what the root's newest checkpoint does not keep of those keys is
lost. A record of a key the root took back counts no more in the state whether it is held or
not (the writer refuses a take-back that would put a device out), so a removal among them that
is lost changes nothing: the device it names stays until someone removes it again.

The 16 live admin keys can include keys an admin removed: those count among the 16 until the
root removes them too. Before the root names a 17th admin key while 16 are live, its writer
writes the root's removal of every live key an admin removed, then the new record, both or
neither, so that the new key is among the 16 on every member.

#### What a writer refuses

A writer refuses a record past its key's own ceiling, and a record that its own set would not
keep or would not count: a record that its writer drops reaches nobody for sure, and one that
passes the key's ceiling pushes the key's own older records out (`RecordSet::write_record`).
Such a refusal leaves the set as it was and uses no seq. A writer never makes a 257th device
and never puts a device out.

#### Two histories

A key with two records at one seq has two histories. For an admin key, no secrets are sealed
while it lasts.

Two records of a root at one seq halt the group, whether or not their chains are whole, on
every member that holds both. A member whose counting checkpoint names the root's head at or
above that seq and does not keep the record has settled the seq: it refuses one record of the
pair alone, as settled, and stays as it is. When a peer hands it both, it holds the pair and
halts too. A member that holds the pair keeps it outside the rooms, never prunes it, and hands
it to every device of the group in sync, and to any other peer that is not a removed key (one
admitted on the other history, one the records do not name): the pair proves itself, and such a
peer gets it and nothing else. A member takes from a peer it does not know only a valid pair of
the root it counts, one pair, never other records of that root. So members that meet end alike, and a pair that no
member holds any more halts no one. The group stays halted until the recovery key changes the
root. A removed peer is handed only the removals that name it, and of a pair of removals only
the one with the smaller ID, with what proves each to a device that missed records while away:
for an admin's removal its chain, the root's record that names the key, the changes of root,
and the root's line the admin's records saw in their `seen`, from that entry down to seq 1 (or
to the counting checkpoints where the line was pruned). It was a member when those were signed;
it gets no copies and no other member's records.

A removal on a whole chain counts at or above the fork too, on either history, whoever signed
it, so a key in two histories brings nothing back that it removed. Removals have no limit.

#### A change of root

The root changes only by a `recovery` record that the group's recovery key signs, at once: no
delay, no cancel, no objection, and no admin takes the group over. The recovery key is K1 (ES256)
and K2 (SLH-DSA-SHA2-128s): K2 signs every head first, and K1 signs the body and the SHA-256 of
K2's signature. A group has at most `records::body::MAX_RECOVERY` (64) changes, and their heads
are kept outside the rooms. The recovery chain, walked from the recovery key the device was
given with the group, gives the path of roots before anything else; no root's or admin's record
changes it. Each change hands the chain to the next recovery key, whose records start again at
seq 1. Two recovery records at one step stop the group for good.

After a change only three kinds of record count: the last root's on the path, those of the
admin keys that root names, and the recovery chain ("the last root only"). Nothing signed by an
earlier root, by its admins, or by the new root below the head's `from` counts, whatever the
change's list names; the writer names an empty list, and every new root is a fresh key (the
writer refuses a key that was an admin key: "the new root key was an admin key: a new root is
always a new key"). A device that has not applied the change yet still counts the old root and
its admins; once it applies, their records turn void.

A change applies whole or not at all: the new root's first checkpoint keeps every re-issued
record (below), and the change waits until the device holds all of them (`eval::first_gap`), so
a member never counts an empty group. A record of the change's group that the device lacks is
settled by a later checkpoint (of the new root above the first, or of a root after it on the
chain) that names a head at or above it and does not keep it; what that checkpoint keeps must
be held too. Until the group is whole the change waits, and the apps say that a change of root
is arriving. While it waits, the new root's records wait aside, outside the count, and so do the
records of an admin key that only those records name (such a checkpoint may keep one), verified
by that key; within one root's room in all, the new root's own records first, so an admin never
pushes them out. They are taken when the change applies and dropped with the new root when its
change is no longer on the way (a fork at its step).

The writer of a change refuses a set that holds a recovery record it has not applied, whether it
waits for its list or for the new root's records ("a change of root is waiting here: sync with
the group, then try again"), a group stopped for good, a 65th change, a key that is not the
group's recovery key, a new root key the state already knows, and a re-issue that does not fit
the new root's room with room for its next checkpoint ("the change does not fit the new root's
room: leave out some devices").

When the person chooses not to sync first, the writer writes past a waiting change
(`RecordSet::write_change_over_waiting`): the record follows the newest valid recovery record
the set holds (N), as N+1, and re-issues what counts at the writer, the state before N, naming
no spare (an admin's spare may be N's grant). Members apply N+1 over N without N's group: the
newest record whose list and group are held applies, and its cut takes every root before it, so
N's root and all it signs never count, even when they come later. N travels with N+1, as every
recovery record the set holds does. Past a waiting change the writer still refuses a record it
cannot read, one off the chain, and N's root as the new root.

A group halted by two recovery records at one step counts the recovery chain below the fork and
nothing else: it names the roots and no device; the app keeps what it last showed for the screen
that makes the next group.

#### Re-issue

The new root carries the state over as its own first records: its device record (holds_root),
the newest settings, the counting hubs record narrowed to the devices it carries, the copies
record, a plain device record for every device the writer counts (an admin's device without its
admin key or powers), and one freeze of the member key of each frozen device, which only the new
root thaws. It removes no device: a device removed before, or one the person leaves out, is
simply not re-issued. It writes one removal of keys, with an empty `seen`: every admin key that
loses its rights in the change (every admin key of the path the writer knows, and those the
current root's own change removed, but a spare the change names); the new root's own device record
carries none of these keys, so an admin's device that takes the group over stays a plain device of
the new root. So after a change an admin key
is always a new key: the writer refuses to name a removed key as an admin ("this admin key was
used before the change of root"), and a removed key's records never count. Before signing, the app shows the person every device with what the change
does to it (`RecordSet::change_preview`: stays, out, admin rights lost, admin kept with a spare
key, frozen; a frozen admin's line says what happens to its rights and that it stays frozen), and the person may leave devices out; the writer's own device cannot be left out.
A device every admission of which sits below a head of a root's checkpoint that does not keep it
is not carried. An admin keeps its rights across a change asleep, once: the new root names it,
with the powers it had, on the `spare` of the admin key's newest `ack` that counts under the root
being replaced (a newest `ack` without one withdraws it), when that spare is a key the group never used (`RecordSet::spare_of`); any other
admin's device is carried as a plain device. The device switches to the spare once the change
applies, acknowledges its grant first, and publishes its next spare in an `ack`
(`RecordSet::write_ack_spare`, which refuses a used key: "the spare key is not a new key"); it
keeps the secret of every spare it published until a newer `ack` of its own counts. An admin
asleep through two changes has no `ack` under the second's old root, and loses its rights. The
new root's view at the change is the truth: an old root's removal the
writer never received does not bind after the change, and the preview is the person's check.

A peer whose key the set does not know (`peer::Standing::Unknown`), such as a replaced root's
new phone meeting a sleeper, may give it the change: the sleeper takes from it only the
recovery key's records (at most `records::set::UNKNOWN_PER_SEQ` (2) of a seq, none past
`records::body::MAX_RECOVERY`), the lists they name, and the records of a root a held recovery
record names, within that root's room (`RecordSet::insert_from_unknown`); it gives such a peer
only the changes of root it holds (`RecordSet::for_peer`). Copies and commands are never taken
from such a peer.

#### Checkpoints

Only the current root writes a checkpoint. A checkpoint names the heads it settles and the
records it keeps. An honest checkpoint keeps the root's own records under its head, so that it
mends the root's chain where the rooms turned a record away; an older checkpoint of the root
it keeps none (the new one carries their heads); a removal, the root's or an admin's, counts
for good while it is kept, and the writer leaves one out, with the records of the keys it names,
only when every key it names is a plain device key whose admissions it holds below their
signer's head (a removal of a key never admitted stays: it bars the key), and every live admin
key but the removal's signer has an `ack` that counts whose `seen` holds that signer at or
above the removal's seq: an `ack` sits on its signer's whole chain, so the root then holds every
admission that admin signed. An admin's device writes one `ack` after a sync brings a removal it
has not acknowledged; the checkpoint keeps only each key's newest. The root's writer takes back
by itself only an admin key its device received nothing of for `records::set::ADMIN_SILENCE_MS`
(35 days, on the root device's clock; only a key's records that count are heard). A full room, or a frozen admin key (which cannot
acknowledge while frozen) that holds removals back, takes nobody back by itself: the app shows
what each admin key holds back, in removals and in the root's units, and which keys are frozen,
and the person thaws the key or chooses whom to take back; a frozen key whose device is gone
falls to the silence. The root's own key is never taken back as an admin key. A take-back is one record of the root, its checkpoint
first, and passes the floor as a removal does; what that key signed and the root never got
counts for nothing, and the writer never grants that key again: the device makes a new admin
key. With nobody acting, a root whose admins hold removals back passes three quarters of its room
only after more than 440 removals inside the 35 days (16 admins, 256 devices); there its ordinary records are
refused, and every record of the root, its removals included, still goes in only while the person
keeps a way out: after the record the root's room still holds a take-back of every admin key that
holds removals back, each at its widest, and twice the checkpoint the root would write then, with
a head and a kept ID more per take-back (each take-back writes its checkpoint first, and a
checkpoint keeps the record before it, perhaps the last checkpoint, as its anchor), in place of the
root's checkpoints it holds. Twice, since a checkpoint written right after another keeps that one
as its anchor (its own head is the record before it), so two of the root's checkpoints can be held
at once. The writer reads this from the state, without trying it, and `checkpoint_due` says so too. A record that
would close that way is refused ("take back the admin keys that hold removals back first"), except
a take-back and a removal of only such keys or their devices, which are that way; the app names
those keys, and the take-backs and the silence free the room. Of the root's own
settings, hubs and copies records it keeps only the newest of each type, and of its records of
one device the oldest and the newest, where the newest counts and names no admin key and those
left out name the same key and no admin key; a resolve whose every target it leaves out goes
too. The state is the same before and after, and what it leaves out sits below a head and is
refused when offered again. These are the writer's choices: a member counts any checkpoint that
keeps more. The root's writer stops its ordinary records where they would leave no room for
its next checkpoint (a margin of a twenty-fourth of its ceiling below that is for removals,
freezes, resolves and take-backs), and writes that checkpoint first before a removal, freeze or resolve
where one more would leave none. An admin key whose admission the rooms
keep out is no key of the set. A waiting root's records, and records that a checkpoint of the
current root above the counting one keeps, sit aside, outside the count, in any order, within
one root's room; a member asks its peers for a missing record for
`records::set::MISSING_ROUNDS` (16) rounds before it shows a notice.

#### Devices

The device cap comes last and decides nothing before it: every signer's power, every removal
and every admission is judged without it. Then the cap is taken among the devices that count (a
removed device holds no place): the root's own device and the admins' devices first, then the
rest by their earliest record that counts, by seq, then the signer's place (the roots by the
path, then each admin by its admission), then ID. So a key that floods takes only its own first
places. A device past the cap is not a device of the group until one before it is removed, and
its records say why.

#### Sync

Members sync by parts (`records::sync`): message `records` (section 4) carries at most
`records::sync::PART_RECORDS` (4096) records and `records::sync::PART_BYTES` (7323648) bytes,
each change of root's list beside the head that names it, in the order a peer is given its
records, so a receiver that takes the parts one by one ends with what one message of everything
would give. Message `have` carries at most `records::sync::HAVE_IDS` (4096) IDs and is split
alike. A full set with the records outside the rooms and up to 64 lists does not fit one frame,
so nothing assumes it does. A Welcome carries the set whole, in parts when it does not fit, with
its digest (section 6, "The Welcome").

On a connection (`member/src/link.rs`), a member whose digest differs from the one in the
peer's `hello` sends `have` with the IDs of the records it holds for that peer, and asks with
`want` for what the other side's `have` lists and it lacks, with what its own records name and
it lacks and the list a change of root waits for, as on a `hello`. A member that takes a peer's `have`
while the peer's last `hello` still showed a digest other than its own sends its own `have`
too, once for each `hello` of the peer's and each state of its own set: a record written while
two members are connected thus reaches the other side although only the writer sent a new
`hello`, even when the writer had sent its `have` since the peer's last `hello`. A member sends its `have` at
most 64 times on one connection (its own budget in `member/src/link.rs`, not a bound of the
format) and then logs that the exchange is stuck. When two
members dial each other at once, both keep the connection the one with the lower device ID
dialed.

#### What is offered again after a restart

Being settled.

### Until the switch to the core (wave 5)

The subsections that follow, from "Admin CA and chains" to "Exchange in the member protocol",
describe 0.5's records (`v:2`, JSON) and certificates, which `cbb_core::authority` reads.

### Admin CA and chains

| Certificate | Subject CN | Validity | Extensions |
|-------------|-----------|----------|------------|
| Group root CA (phone groups) | `cbb group root YYYY-MM-DD` | as the group CA | CA, path length 1; key usage certSign, cRLSign |
| Admin CA | `cbb admin <device ID>`, the admin phone's device ID | NotBefore = the root's NotBefore; NotAfter = the root's NotAfter | CA, path length 0; key usage certSign, cRLSign; issued by the root |

- An admin phone has two keys: its admin key (certified by the admin CA, used only to sign
  certificates and records, behind a user-presence check) and its member key (certified by
  its own admin CA, role `phone`). The root phone signs with the root key itself and has no
  admin CA. A second phone gets its first member certificate from the phone that admitted it
  and issues the next from its own admin CA when it is due.
- Renewal (section 2): the root renews any member certificate, from the current root; an
  admin phone renews any member certificate too, from its admin CA, and its `cert` message
  carries that admin CA in `issuer`. The member then keeps the new issuer with its
  certificate (Go's `Identity.WithCertFrom`). So the devices a removed admin admitted get
  their next certificates from another admin. A member that receives no `issuer` takes a
  certificate from the issuer of its current one or from a root.
- A member certificate issued by an admin CA has the profile of section 2, issuer the admin
  CA, NotBefore = the admin CA's NotBefore.

### Admins

Any phone, and any member with the capability `admin`, can be an admin, in a group a phone
created and in one a computer created. A member's admin key is in its TPM or a Mac's Secure
Enclave (section 17) and otherwise a file next to its identity, so a thief with such a
computer can act as an admin until another admin removes it. A phone's is in its hardware
behind the owner's face, fingerprint or passcode (section 3).

- A phone joins as a member (section 6) and offers no admin key while it joins. Once it is in
  the group, a phone that is neither the root nor an admin makes its admin key (making it
  asks the owner nothing; each signature does) and its hellos carry `admin_key`, its
  SubjectPublicKeyInfo, as a member's do below. The root makes it an admin the same way, and
  its `device` record keeps the role `phone` and the store its record named, with every power
  (`powers` as an admin phone admitted as one). A phone without such a key, as a TV, offers
  none and stays a member.

- Every member with `admin` that is not the root makes a P-256 admin key when it starts in a group
  and keeps it in the identity file (`admin_key`,
  PKCS #8, or `admin_key_tpm`, section 17). Until it holds an admin CA, and while the admin CA
  it holds is from a root before the current one, its hello carries `admin_key`: the key's
  SubjectPublicKeyInfo.
- The root makes it an admin, the root phone with "Make it an admin" and the root computer
  with `cbb admin NAME`, after the user allows a computer whose keys sit in a file (section
  17); it refuses a key the records already name for another device or a root, which would
  give its holder a second device's admin CA. It issues the member's admin CA for that key (the profile above, CN
  `cbb admin <device ID>`), signs a `device` record for the member that names
  that admin CA in `admin`, and sends `{"t":"admin","admin_ca":...}` on its connection to
  the member. The member must be connected.
- The member MUST check that the admin CA is for its admin key, names its device ID and stands
  under one of the group's roots, and that the records do not refuse it; it keeps it in the
  identity file (`admin_ca`) and issues itself a new member certificate from it, so the
  `issuer` of its Welcome also issued its own certificate. Its hello no longer carries
  `admin_key`. An admin CA that replaces the one it holds MUST be from the current root.
  The `device` record names the admin key in `admin` and what it may do in `powers` and
  `commands` ("Who signs what").
- From then on it acts as an admin phone does, with its admin CA: it opens pairing windows
  (`cbb pair`) and admits members, never phones, with a Welcome that
  carries `issuer` and `roots` and no CA keys; it signs the `device` record of each device it
  admits and `revoke` records (`cbb remove`) of devices; it renews its own certificate and
  those of the computers it is connected to. It never removes the root or another admin and
  makes no admins; when the root computer is lost, it claims the group (below, "Handing the
  group over").
- It is removed as an admin phone is: a revocation of its member key and its admin key,
  which keeps what it signed before the remover saw it ("Removals and freezes keep what the
  author saw").
- In the member handshake (section 4) a member MUST send its certificate followed by its
  issuer when the issuer is not the group CA. Checking a peer: the chain MUST verify to the
  group CA through at most one intermediate that is a CA with path length 0, with the time
  rule of section 2; then the rules of "Certificates" below apply. The issuer those rules check, and the admin CA that makes a
  peer count as an admin, is the certificate that signed the leaf, found wherever it is in
  the chain; other certificates the peer sends are ignored, and a leaf whose issuer is in
  neither the chain nor the roots is refused.

### Records

The envelope is unchanged: `{"body": bytes, "sig": bytes, "chain": [bytes]}`, with `sig` an
ECDSA P-256 signature with SHA-256 over the exact bytes of `body`, DER, and `chain` empty
when a root's own key signed, else the signer's admin CA certificate. The **record ID** is
SHA-256 over `body`.

#### Fields every record has

| Field | JSON type | Values |
|-------|-----------|--------|
| `v` | integer | exactly `2`; a body of a later version is kept, never applied ("Records of a later version") |
| `alg` | string | exactly `es256`: the envelope's `sig` is ECDSA P-256 with SHA-256, DER |
| `type` | string | one of the types below |
| `group` | string | the group tag (section 1) |
| `signer` | string | SHA-256 of the signing key's SubjectPublicKeyInfo, base64: a root's key, or the admin key that the admin CA in `chain` certifies |
| `seq` | integer | from 1 to 2^31-1: the signer's number for this record |
| `prev` | string | the record ID of the signer's record with `seq` - 1; absent when `seq` is 1 |
| `time_ms` | integer | the signer's wall clock, for display only; never used for ordering or for any rule |

A receiver MUST refuse an envelope whose `signer` is not the hash of the key that `sig`
verifies with: the key of the admin CA in `chain`, or, with an empty `chain`, the key of a
root the group may have (the group CA, or the new root of a claim). So one body has one
signer, and the same body under another signer is not a valid record.

`alg` names the signature algorithm inside the signed bytes, so a later algorithm (a
post-quantum one, say) comes with a new `v` and can never be mistaken for, or downgraded
to, this one. A key hash covers the key's SubjectPublicKeyInfo, which names its algorithm.
A signer's own code refuses to sign with any key that is not P-256.

#### Records of a later version

New record types and new fields come only with a new `v`, so a member that meets a body of a
later version needs an update to read it. A record is **kept** when its body is at most the
body's size and in the strict and canonical form, its `v` is an integer from 3 to 2^31-1,
its `group` is the group's tag, and the envelope verifies as this version's does (`sig`
ECDSA P-256 with SHA-256 over the body) with the key its `signer` names, which must be a root
on the current path (`chain` empty) or an admin key of a device in the state (`chain` its
admin CA). So only the group's current roots and admins can raise the signal, and nobody
else can fill it with junk; a later version keeps signing with this algorithm whatever it
adds. The member stores a kept record, passes it on in sync as it is and never applies it.
The state lists the IDs of the kept records in `newer`, sorted, at most 16, and the member's
status and the apps tell the user to update. Nothing else changes: the group goes on under
the records the member can read. Any other body that does not read is left out, as before.

A **key hash** is 32 bytes of SHA-256 in base64 (44 characters); a device ID 32 of `0`-`9`
and `a`-`f`.

#### Types

| `type` | Fields | Meaning |
|--------|--------|---------|
| `device` | `device`, `name`, `role`, `caps`, `os`, `key`, `admin`, `powers`, `commands`, `store`, `kind`, `proof`, `holds_root`, `seal`, `forward_only` | a device in the group, or a change of its name or powers |
| `revoke` | `keys`, `seen` | removes keys from the group |
| `freeze` | `keys`, `seen` | stops admins until the root or an admin with `thaw` ends it |
| `thaw` | `records` | ends the `freeze` records it names |
| `claim` | `root`, `seen` | an admin's claim to take the group over with a new root |
| `resolve` | `records` | the current root voids the records it names: a cancelled claim, one side of a conflict, one of two records with one number |
| `settings` | `takeover_delay_ms`, `key_level` | the root's settings for the group |
| `copies` | `ttl_ms`, `secret_ttl_ms` | how long a copy and a secret live in the group ("The copies setting") |
| `checkpoint` | `heads`, `keep` | a root's checkpoint: the records it covers and does not keep may be dropped |
| `hubs` | `hubs` | the user's main hubs for sync away from home, in the order they serve |
| `recovery` | `admin`, `cert` | names the group's recovery key, an offline admin key that may only claim the group ("The recovery key") |
| `handover` | `admin` | the current root hands the group to an admin, whose claim then takes effect without the delay ("Handing the group over") |

#### Field rows

| Field | JSON type | Needed in | Values |
|-------|-----------|-----------|--------|
| `device` | string | `device` | a device ID |
| `name` | string | `device` | 1 to 64 bytes of UTF-8, no control character (U+0000 to U+001F, U+007F to U+009F) |
| `role` | string | `device` | `member`, `phone` or `watch` |
| `caps` | array of strings | none | sorted, each once; from `admin`, `dials`, `hub` (section 4, "Capabilities"); only with role `member`. A `member` record that names `admin` MUST have `admin` in `caps` |
| `os` | string | none | `linux`, `windows`, `macos`, `ios`, `android`, `aurora`, `sailfish`, `harmonyos`, `watchos`, `wearos` or `none` |
| `key` | string | `device` | a key hash: the member key (for a watch, its admin key) |
| `admin` | string | `recovery`, `handover` | a key hash: the admin key its admin CA certifies; only in a record a root's own key signed |
| `powers` | array of strings | none | sorted; from `admit`, `renew`, `remove`, `remove-admins`, `freeze`, `thaw`, `takeover`, `hub`; only with `admin` |
| `commands` | array of strings | none | sorted; the command types (section 15) the admin may sign: `action`, `actions-off`, `away-off`, `hub`, `mode`, `mute`, `paste`, `paste-off`, `unmute`; only with `admin`. A record signed before `mute` and `unmute` came lets its admin sign neither until the root signs it again |
| `store`, `kind`, `proof` | string | none | as in section 17 |
| `holds_root` | bool | none | `true`: this device holds the signer's root key; only in a record a root's own key signed |
| `seal` | string | none | the device's public key for sealed messages, base64: 1216 bytes, an X-Wing key (HPKE KEM `0x647a`). The rules check only its size; a member checks the whole key before it seals a message to it |
| `forward_only` | bool | none | `true`: the device passes the group's copies on as a hub but reads none, so no copy is sealed to it ([format](format.md), section 10.4); only with role `member` that has `hub` in `caps`, never with `admin` or `holds_root`; absent means `false`, and `false` is written by leaving it out |
| `keys` | array of strings | `revoke`, `freeze`, one at least | sorted key hashes |
| `seen` | array of objects | `revoke`, `freeze`, `claim`, one at least | sorted by `key`, each key once: `{"key": key hash of a signer, "seq": the highest seq of that signer the author held, 0 or more}`; `seq` here is never left out, 0 included |
| `records` | array of strings | `thaw`, `resolve`, one at least | sorted record IDs |
| `root` | string | `claim` | the new root CA certificate, DER, base64: self-signed, a CA with path length 1, a P-256 key |
| `cert` | string | `recovery` | the recovery key's admin CA certificate, DER, base64, whose key hash is `admin` |
| `takeover_delay_ms` | integer | none | from 0 to 604 800 000 (7 days); absent means 259 200 000 (72 hours) |
| `key_level` | string | none | `proven`, `hardware` or `files`: which devices may be the group's root, an admin or a trusted hub, which is an admin ([roadmap](roadmap.md), "Key levels"); absent means `hardware`. The state carries it; the rules do not check it yet, the apps and `cbb` do when they make an admin or a hub |
| `ttl_ms` | integer | `copies` | field 10, from 60 000 (1 minute) to 3 600 000 (1 hour): the lifetime every member stamps on an ordinary copy it makes (D-129); without a `copies` record that counts, 300 000 (5 minutes) |
| `secret_ttl_ms` | integer | none | field 12, from 5 000 to 60 000 (1 minute): the lifetime every member stamps on a secret it makes; absent (0 is never written) or without a `copies` record that counts, 60 000 |
| `heads` | array of objects | `checkpoint`, one at least | sorted by `key`, each key once: `{"key": key hash of a signer, "seq": 1 or more, "id": the ID of that signer's record with that seq}`; above seq 1 its own key's head is its `prev`, at seq 1 it names no head of its own key |
| `keep` | array of strings | none | sorted record IDs: the records below the heads that still count |
| `hubs` | array of strings | `hubs`, one at least | 1 to 16 device IDs, each once, in the user's order (not sorted) |

A field that a type does not list is refused in it (`form/unknown`), and so is a field
with an empty value (`form/empty`). An envelope's body is at most 8 KiB, a checkpoint's
64 KiB.

`seen` names every signer whose records the author held, its own included: the root's key,
every admin key, and a removed admin's key too. A record that removes or freezes an admin
MUST name that admin's key in `seen`, with `seq` 0 when it held none of its records (then
all of them stop). The apps and `cbb` fill `seen` from the records they hold right before
they sign; a signer MUST sync with a member first when it can, and MUST NOT write a `seq`
higher than it held for anyone.

#### Who signs what

A **root key** is the key of the group CA or of the new root of a claim that took effect
(below). The **current root** is the last root on the path. An **admin key** is the `admin`
of a `device` record that the current root's own key signed (or an earlier root on the path,
for a record within that root's cut, below). An admin's **powers** and **commands** are
those of the newest such record (the highest `seq` of that root) that names it.

| Record | Signed by |
|--------|-----------|
| `device` naming `admin`, or with role `watch` | a root's own key |
| `device` with `forward_only` | a root's own key, or an admin with `admit` and `hub` |
| other `device`, a phone's without `admin` among them | a root's own key, or an admin with `admit` |
| `revoke` of member keys | a root's own key, or an admin with `remove` |
| `revoke` of an admin key, or of the member key of a device whose newest root record names an admin key | a root's own key, or an admin with `remove-admins` |
| `revoke` of a root key, or of the root's own device | nobody: a root is replaced only by a claim |
| `freeze` | a root's own key, or an admin with `freeze`; each key it names is an admin key without `remove-admins` |
| `thaw` | a root's own key, or an admin with `thaw` and `remove-admins` |
| `claim` | an admin with `takeover`, under the current root |
| `resolve`, `settings`, `handover` | the current root's own key |
| `checkpoint` | a root's own key |
| `hubs` | a root's own key, or an admin with `hub` |
| `copies` | a root's own key, or any admin, whatever its powers |
| `recovery` | a root's own key |

A record whose signer may not sign it counts for nothing; so does a `revoke` or `freeze` that
names any key its signer may not remove or freeze. The powers the apps and `cbb`
write:

| Admin | `powers` | `commands` |
|-------|----------|-----------|
| a phone, admitted by a phone | all eight | all |
| a phone, admitted by a root computer (`cbb pair -admin`) | `admit`, `renew`, `remove`, `freeze`, `hub`, `takeover` | all |
| a computer | `admit`, `renew`, `remove`, `freeze`, `hub`, and `takeover` when the root is a computer | all |
| a watch | `remove`, `freeze` | `paste-off`, `actions-off`, `away-off`, `action` |

So whether an admin computer may take the group over is decided once, by the root, when it
makes the admin, not by each member from other records.

#### Watches

A watch's admin key sits in its Secure Enclave, Keystore or HUKS, but a watch on the wrist signs
without Face ID or a fingerprint, so its powers are few: the root's `device` record for it
has role `watch`, `powers` `freeze` and `remove`, and `commands` `paste-off`, `actions-off`,
`away-off` and `action` (the table above). So it removes devices but no admin, freezes
admins without `remove-admins`, and admits, renews and hands over nothing: a `device` or
`claim` record it signs counts for nothing, and a certificate it issues is refused
("Certificates"). It is never a hub (section 11), and no server credential names it (section
18): it reaches the group only through its phone, which carries what it signs. The phone
builds the body (a `freeze` or `revoke` record, or a command with `by` the watch's device
ID), the watch checks its type, group, signer and, for a command, `to` and `action`, then
signs it; the phone adds the record to its records and sends it, or passes the command on as
it passes its own (section 15). A watch is listed as an admin while its admin key is neither
revoked nor frozen.

On the records of 0.6 the root writes a watch's `device` record with role `watch`, `rights`
`read`, its admin key the one the watch made, and the powers and commands of
`AdminKind::Watch`; its member key, from which its device ID comes, is made for the record
and dropped at once, so nothing signs a keys statement or a copy as the watch, and no copy is
sealed to it (D-124). In 0.6 a watch signs nothing from the wrist: records sign a digest
(`records::key::sign_es256`), which a watch that must see what it signs refuses, and the
watch apps read the bodies of 0.5; signing on the watch comes with 0.7.

#### Chains and numbers

A signer's records form a chain: the record with `seq` n names in `prev` the ID of the one
with `seq` n - 1. A record **counts** only when the member holds the whole chain below it.
A record whose chain is not complete waits (a member keeps at most 1024 records of one
signer, waiting ones included) and counts once the missing ones arrive.

**Two numbers.** Two different records of one signer with the same `seq`, or a record whose
`prev` is not the ID of the signer's record with `seq` - 1, prove that the signer's key
signed two histories: a stolen key, or a device brought back from a backup that signed again.
From the lowest such `seq` k, no record of that signer counts, on either branch, until the
current root voids one branch with `resolve` (naming the first record of that branch; the
records after it on that branch go with it). Meanwhile (see "Stopping the exchange") the
devices whose counting `device` records that signer alone signed get nothing, and the whole
group stops sending secrets. A root that signed two histories stops the group fully, and only
its own `resolve` ends it.

**Voiding.** A record that a counting `resolve` names counts for nothing. When it has a
sibling (another record of its signer with the same `seq`), the records whose `prev` chain
passes through it count for nothing too, so `resolve` ends two histories by naming the first
record of the branch that goes. Without a sibling only the named record goes, and the
signer's chain goes on through it.

**Going on after two histories.** The root may void both branches, naming both records of
seq k. The signer's next record then has seq k and `prev` the record of seq k - 1, a third
record of that seq and the only one that counts, so the signer goes on below the fork.
A member gives a key's next record the seq one above its highest record that is on no
voided branch (of two records with one seq, the one with the lower ID in base64), and signs nothing
but a root's `resolve` with a key the state names in a conflict of two histories.

A device keeps a log of the records it signed. When the root's `resolve` voids both
histories of its key, it signs again, in their order, the voided records of that log that
admit, remove, freeze, thaw or set (`device`, `revoke`, `freeze`, `thaw`, `hubs`,
`settings`); the voided records it did not sign, as a thief's or its own from before a backup
was restored, stay void, and its user does again what was theirs. Before a record its user
asks for, a computer waits up to 10 seconds until it holds another member's records (a
hello with its digest, or the records a member sent), so that a device brought back from
a backup rarely signs a seq again; when no member answers, it signs anyway and logs it.
On the records of 0.6 the member keeps the log in `signed-records.json`
(`member/src/mesh/signed.rs`), the root's `cbb resolve` names both records of each key in
two histories (`writers::resolve`), the writer follows no voided branch
(`RecordSet::voided_of`), and `cbb status` lists the conflicts with the devices whose keys
they are; it does not wait for another member's records first yet.

#### Checkpoints

A group's records only grow, and a member keeps at most 1 MiB of them (1024 records). A root's
own key signs a `checkpoint` so that members may drop what no longer matters: `heads` names,
for each signer, its newest record the checkpoint covers, and `keep` the records below the
heads that still count: the newest `device` record of each device, the `revoke`, `freeze` and
`thaw` records that count, the newest `settings`, the `hubs` and `copies` records that count, the `recovery` record that counts, every claim not yet decided and the records
its `seen` and its disputes need, and the `resolve` records that end them. The apps sign one
by themselves when the records pass three quarters of either limit.

A checkpoint above seq 1 names its own key's head, and that head is its `prev`: the record one
seq below it, by its ID; a checkpoint at seq 1 names no head of its own key. A body that does
otherwise is refused (`records/checkpoint/own-prev`), so a checkpoint always settles its own
key's records below it, and a newer one never takes back what an older one settled of its key.

A checkpoint leaves out of a set each record of the group whose body reads, of a signer in
`heads`, with a `seq` at or below that head's, other than the heads and the records in `keep`,
whether its signature checks or not. In the set it prunes, a prev chain is whole when it
reaches seq 1 or a record the checkpoint names, so the records after the heads and the records
in `keep` count without the ones dropped below them.

The state is evaluated on the set as the checkpoint that counts prunes it, so it is the same
whether a member still holds what the checkpoint leaves out or not. To find that checkpoint,
the evaluation takes the root's own records of type `checkpoint` of a root of the group (the
group CA, or the root of a claim that an admin under such a root signed), at most 8 of them:
the highest `seq` first, then the smallest ID. It evaluates the set each one prunes, and the
checkpoint counts there when it is a root's record that counts in that evaluation: its root
on the path, within its cut, its chain whole and not voided. Of those that count, the newest
counts: a later root on the path, then a higher `seq`, then the smaller ID. A checkpoint that
does not keep what the path to its own root needs (a claim, the admin record that made the
claimant an admin) does not count and drops nothing, nor does one a `resolve` voided, nor two
of one `seq` (two histories of the root). Without one, the set is evaluated whole. The state
names the checkpoint that counts in `checkpoint`.

A member may delete the records the checkpoint that counts leaves out. A checkpoint that
leaves out a record that mattered changes the state for every member alike; only a root signs
one, and the root always wins.

#### Limits

A set is never refused for its size: whatever an admin signs, the group goes on. Records past
a limit count for nothing, with the reason `limit`, and the rest is evaluated as if they were
not there. The limits are taken after a checkpoint's pruning, in the set each candidate
checkpoint prunes; the candidates themselves come from the whole set, so that the root's
checkpoint brings a set past the limits back under them though it is past them itself.

| Limit | Value | Past it |
|-------|-------|---------|
| records in the set | 1024 | the records after the 1024th, in the order below |
| bytes in the set: each record's body, signature and chain | 1 MiB | the record that would pass it and every record after it |
| devices with a `device` record | 256 | every `device` record of a device past the 256th |
| admin keys a root's own `device` records name | 64 | every root's `device` record naming an admin key past the 64th |
| roots on the path: the group CA and 15 handovers | 16 | a claim that would add the 17th is `void` |

The order: a record's rank (0 for the group CA's own records, 1 for those of the other roots
of the group, 2 for those under an admin CA of one of its roots, 3 for the rest; a signer's
lowest rank counts for all its records), then its depth (how many of its signer's records
have a lower `seq`), then the signer's key hash and the record's ID, in byte order. The
evaluation stops at the first record that does not fit, so each signer keeps the start of
its chain, never a record past a gap, and the root's records go before any admin's. Devices
and admin keys are taken in the order of their first `device` record; a device or an admin
key past its limit drops every `device` record naming it, the first ones too, so that no
chain is left with a hole. A `revoke` naming one still counts.

The apps keep well under these: at the most, 256 devices of about 1.6 KB each (a record with
its sealing key) are about 0.4 MiB, and a checkpoint drops the old records of each.

#### The hubs table

The group's hubs serve in an order every member derives from the records (section 11, "Several
hubs"). A `hubs` record lets the user put main hubs first: its `hubs`
come first, in their order, and the other hubs follow in the derived order.

Of the `hubs` records that count, one counts for the table: a root's beats an admin's, of two
roots' the later root on the path, then the higher `seq`; of two admins' the later `time_ms`,
then the smaller signer, then the higher `seq`. Between admins this trusts each signer's
clock: an admin whose clock runs ahead keeps its table until the root signs one, which beats
any admin's. The state lists in `hubs` the devices of that table that are devices of the state
and may be hubs: a phone, or a member with `hub` in `caps`, in its order; a member puts first those of them that may be
hubs by the records (the root's own device, an admin with `hub`, or a device with
`forward_only`), so a table naming a removed device or one that lost `hub` does not stop the
others. A device the table does not
name still serves after the main hubs.

#### The copies setting

A `copies` record sets the group's two lifetimes (D-129): `ttl_ms`, how long an ordinary copy
lives, and `secret_ttl_ms`, how long a secret lives. Every member stamps the one for its kind
on each copy it makes, as the copy's own `ttl` in milliseconds (Content field 3, from
`content::MIN_TTL_MS` (5000) to `content::MAX_TTL_MS` (3600000)), so the whole group sends the
same; a reader judges a copy by its own `ttl` (`cbb_core::copies::fresh`): past it the copy is
gone, a phone's "Last received" line hides and a secret is no longer written. The root and
every admin may sign one, since it changes only how the
members treat the group's own copies. Of the `copies` records that count, one counts for the
setting by the rule of the hubs table: a root's beats an admin's, of two roots' the later
root on the path, then the higher `seq`; of two admins' the later `time_ms`, then the smaller
signer, then the higher `seq`. The state carries its `ttl_ms` and `secret_ttl_ms`.

#### Removals and freezes keep what the author saw

A `revoke` record that a root's own key signed, or that counts, removes its `keys`. For each
removed admin key A, the records of A with `seq` up to the record's `seen` entry for A keep
counting, and none after: what the admin did before the remover saw it stays, the devices it
admitted among it, and nothing it signs later counts.

A `freeze` that counts stops the admin keys it names in the same way while no counting
`thaw` names it: the records of a frozen admin up to the freeze's `seen` entry count, the
later ones do not, and they count again once the freeze ends. A member certificate of a
device whose newest root record names a frozen admin key is refused.

#### Which admin records count

An admin's record may be cut by a removal or a freeze of that admin. Which records count is
decided the same way on every member, in any order, as follows.

A record a **attacks** a record b when b's signer is an admin key, a is a `revoke` or a
`freeze` whose `keys` name that admin key, a's signer may sign a (the table above), and a's
`seen` entry for b's signer is below b's `seq`: a cuts b off. A `claim` is the exception: an
admin's removal does not attack it but disputes it ("Handing the group over"); only a root's
removal or freeze cuts a claim off. A `thaw` attacks each `freeze` it names. Records of a root's own key are never attacked; records of a root on the path
count up to that root's cut, and the current root's all count.

Every admin record is then **in** (it counts), **out** (it counts for nothing) or
**undecided**, the grounded labelling of these attacks:

1. a record whose attackers are all out is in, and so is one nobody attacks;
2. a record attacked by a record that is in, or by a root's record, is out;
3. repeat 1 and 2 until nothing changes; what is left is undecided.

A record r **happened before** a record s of another signer when s's `seen` names r's signer
with a `seq` of r's `seq` or more: s's author held r when it signed. So for two admins S and T
whose records r (S removes T) and q (T removes S) attack each
other only when neither author held the other's record:

- q happened before r (S held q when it signed r): r does not attack q, q attacks r; q is in,
  r is out. S was removed before it signed r.
- r happened before q: the same with the sides swapped.
- each held the other's (one of them lies): neither attacks; both are in, both are removed.
- they **cross** (neither held the other's): each attacks the other; both are undecided, and
  that is a **conflict**: the group stops (below) until the current root voids one of them, or
  both, with `resolve`, or removes S or T itself. Longer circles (S removes T, T removes U, U
  removes S) end the same way.

An undecided record counts for nothing, and neither do the records it would cut. To keep
the attacks free of circles that do not involve a thief, the powers are in two tiers: an admin
with `remove-admins` is never frozen, and `thaw` counts only from an admin that also has
`remove-admins` (or from a root's own key). So freezes and thaws never chase each other, and a
conflict always means two admins acted against each other without seeing it.

A thief with an admin key can always write a `seen` that pretends it did not see a removal,
and so stop the group; it cannot make its record win. A removal of an admin by another admin
is settled for good when the current root signs it again (a root's record is never
attacked), and the apps ask the root's user to confirm each such removal.

#### Handing the group over

When the root is lost, an admin with `takeover` signs a `claim`: a new root CA certificate,
and `seen` with what it held, the current root's records among them. A claim:

- is **pending** from the moment a member first holds it (by its own clock, which counts
  sleep and does not jump: Conventions, "Time"; never the signer's clock) until
  the root's `takeover_delay_ms` (the newest counting `settings` record of the current root;
  72 hours without one) has passed on that member. A member that does not know how long it
  has held the claim (its clock started again and it kept no time) keeps it pending, without
  a time left, until it knows; only a delay of 0 needs no time. Every device tells its user
  when a claim arrives, and `cbb status` and the apps show it with the time left. Sync and
  the admins' other powers go on; only the new root waits, and the claimant gets no secrets
  meanwhile ("Stopping the exchange");
- is **cancelled** for good when the current root's own key signs a `resolve` that names it,
  or a `revoke` of the claimant's admin key, at any time, before or after the delay: the
  root always wins. When that happens after the claim took effect, the new root and every
  record under it stop counting, and the group is the old root's again;
- is **void** when its new root is not a valid root CA or is already on the path, when it
  does not count (its author lacks `takeover`, a root's removal or freeze cuts it off, it is
  on a dead branch), when its author had seen a counting admin `revoke` or `freeze` of its
  own admin key or member key (the claimant was removed first), or when its author had seen
  another claim under the same root that is not void or cancelled (one claim at a time: a
  claim made while another waits, or after it took effect, counts for nothing);
- is **disputed** when a counting admin `revoke` or `freeze` names the claimant's admin key
  or member key and the claimant had not seen it, whatever else its author had seen. An
  admin who objects to a claim removes the claimant, and the group stops fully until the
  current root decides: a `resolve` of the claim cancels it and the removal stands, a
  `resolve` of the removal lets the claim go on. Nothing in `seen` tells a removal written
  after the handover, since a claimed root can sign before its claim takes effect. After the
  handover an admin removes under an admin CA of the new root, which counts only under that
  root, and the apps always sign with the admin CA of the newest root on the path; a removal
  of the claimant under the old root's admin CA disputes the claim even then;
- **takes effect** when the delay has passed on that member and it is none of the above,
  it is the only such claim under the current root, and no root's freeze holds its
  claimant. Its new root becomes the current root and starts its own `seq` at 1; the old
  root's records up to the claim's `seen` entry for the old root keep counting, and its
  later ones count only to cancel the claim, as above.

A new member takes, for each claim the Welcome's records hold, the time the admitting member
first held it when that is earlier than its own and not in the future (section 6, the
Welcome's `claim_times`): it trusts that member with its certificate already, and a claim
that took effect there takes effect on it too; the rest of the group keeps its own times.

**Two claims** under one root that are neither void nor cancelled stop the group fully on
every member that holds both, at once and whatever their order or delay: no sync, no
messages, no admissions. Only the current root ends it, by cancelling one or both; a group
whose root is lost is set up again. A disputed claim stops the group the same way.

After a claim takes effect the new root signs `device` records for the admins it keeps
(their admin keys stay, so their `seq` goes on) and issues them admin CAs under itself; an admin CA from the old root still signs while the old root is on the path.

**Handing the group over on purpose.** The current root's own key signs a `handover` that names
an admin key, as when the user moves the root to a new phone, or a computer that took the group
back with the recovery key hands it to a phone. A claim by that admin under this root whose
`seen` holds the handover (its entry for the current root is at least the handover's `seq`)
takes effect without the delay: it is a claim as above in every other way, so the root still
cancels it, and a second claim or a removal of the claimant still stops the group. Of the
current root's `handover` records that count, the one with the highest `seq` counts; a claim by
any other admin, or one made before the handover, waits as before.

So a removed or stolen admin phone cannot take the group: its claim waits, the root cancels
it, a second claim or a removal of the claimant stops the group instead of choosing, and
once a new root removes it, nothing it signs counts under that root. What it can do without
the root, by pretending it had not seen a record or by removing the claimant under its old
admin CA, is stop the group: never take it.

**Known limits in 0.6.** Two cases are accepted for 0.6; the apps and `cbb status` show a
stop:

- A removed admin that signs a claim pretending not to have seen another claim, or a removal
  the old root signs late, after a new root that had not seen the removed admin's claim took
  over, leaves the group with one root and a full stop. Nobody is removed by it, but the
  taker's takeover is undone, and the new root's `resolve` does not end the stop: only the
  old root's does. When the old root is lost too, the group is set up again.
- A removal that the old root signs after a handover took effect is cut: it does not count,
  and the removed admin stays until the new root removes it: after a handover, remove on the
  new root.

#### The recovery key

A recovery key lets the user take the group back when every phone with the root or
`takeover` is lost: an offline key, printed or on a hardware key, kept away from the devices.
The root's own key issues it an admin CA, as for an admin, and signs a `recovery` record whose
`cert` is that admin CA and `admin` its key hash; so a computer of the group holds the admin CA
too, and the key alone is enough to claim from it. A `recovery` record whose `cert` is not an
admin CA that the record's signer issued names no key. The recovery key has no device and no
`device` record.

Of the `recovery` records that count (a root's own key on the path signed them, within its
cut), the newest counts. The key it names is an admin key with only `takeover` and no
commands, unless a `device` record of a root names the same key as an admin, whose powers
then hold. So the recovery key signs one thing that counts, a `claim`, with its admin CA as
the chain; every other record it signs is `ignored` with `power`. Its claim is a claim as
above: it waits the root's `takeover_delay_ms`, the root cancels it with a `resolve` or a
`revoke` of the key, a counting admin removal or freeze of the key disputes it, and one claim
at a time holds.

Its claim counts only under the root that issued its admin CA, as any admin's: after a
handover the new root makes a new recovery key.

A device that holds the recovery key and no member certificate of the group, as a new phone
after every phone was lost, issues itself a member certificate under the recovery key's admin
CA. Its device has no `device` record, so its connections carry records only ("Certificates"):
it fetches the records, signs its claim with what it holds as `seen`, and leaves it there. Once
the claim takes effect, its new root certifies the device as a member.

Such a phone holds no root of the group before it connects: the recovery sheet's QR code carries
the group's tag and the key's admin CA only. It dials a member that browsing finds with that
tag, presenting its member certificate and the admin CA as the chain, and takes the server's
certificate unchecked during the handshake. The member's hello carries `group_ca` (section 4,
"Hello"), and the phone MUST check, before it signs anything: the tag of `group_ca` is the
sheet's; the records the member sent lead from `group_ca` to a path whose current root issued
the admin CA (an admin CA under it); the state names the key in `recovery`; and the member's TLS
certificate verifies to a root on that path and names a device the records list. A phone that
finds any of these false closes the connection and tries another member. The claim it signs,
with the admin CA as its chain, waits the root's delay as any recovery claim; the phone keeps
fetching the records over the same kind of connection until the claim takes effect, is
cancelled or becomes void.

**On a hardware key.** A recovery key on a YubiKey, or another card with the PIV application
(NIST SP 800-73-4), is a P-256 key the card made in a free retired key slot (82 to 95, the
first with neither key nor certificate), which never leaves it; the card asks for its PIN, and
for a touch where it can, before each signature. The slot's certificate object holds the key's
admin CA, uncompressed, so that the card alone leads to the key: a computer or a new phone
reads the retired slots' certificates and takes the one whose key hash the state names in
`recovery`, then signs with that slot's key (GENERAL AUTHENTICATE over a SHA-256 digest).
Nothing else on the card is changed, since it may be in use for other things. Making the key
needs the card's management key: the phones use the factory one with AES only (a YubiKey
from firmware 5.7), and refuse a card whose management key is 3DES or that does not say;
signing needs only the PIN. 0.6's recovery key on a YubiKey takes every kind of management key
but one derived from the PIN, changes none, and goes in the first empty retired slot from 0x95
down (section 9, "The recovery key on a YubiKey (0.6)").

A newer `recovery` record replaces the older one: the key the older one named is no admin
any more, and its claims do not count. A `revoke` of the key removes it (a root's own key, or
an admin with `remove-admins`, as for any admin key). The state names the key in `recovery`
while it is neither removed nor frozen.

**The recovery sheet.** A recovery key on paper is a sheet with a QR code and a text, which
the Rust core makes and reads (`recovery_sheet` and `read_recovery_sheet`, docs/core-api.md;
`testdata/interop/recovery-sheet.json`):

- The QR code is `cbb://recover?g=<group>&k=<key>&c=<admin CA>`: the group's tag
  (16 lower-case hex digits), the private key's 32 bytes and its admin CA's DER, both in
  base64url without padding. Each field once, no other field. It is enough on a new phone.
- The text is the key's 32 bytes in Crockford's base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`,
  52 characters, the last 4 bits zero), then 4 check characters, the first 20 bits of
  SHA-256 over `cbb recovery` and the 32 bytes, in groups of four joined by
  hyphens. A reader takes lower case, spaces or no separators, `I` and `L` for `1` and `O` for
  `0`. The text names no admin CA, so it needs a computer of the group, whose `recovery`
  record has it.

A reader refuses with `not_sheet` (neither form), `damaged`, `check` (a mistyped character),
`key` (not a P-256 private key), `cert` (the admin CA cannot be read or is no CA), `mismatch`
(the admin CA is not the key's) or `group`.

The apps make the key and `cbb` claims with it in later changes; this section has the record
and its rules.

#### Certificates

A member certificate is taken when its chain verifies to a root on the path (section 2 and "Admin CA and chains"), its key is the `key` of a counting `device`
record that is not revoked, its issuer is a root on the path or the admin CA of an admin
whose newest root record gives `admit` or `renew` (also when that admin was removed later,
for the devices whose records stay), and neither its key nor its issuer is frozen. An admin CA
is taken when it is under a root on the path and its key is an admin key that is not
revoked. A certificate that passes everything but the rule on its `device` record, as a
device whose record has not reached this member yet or a new member that holds no records
yet, gets a connection that carries records only, so the records reach whichever side lacks
them; it connects as a member once they name it. So does a certificate the recovery key's
admin CA issued ("The recovery key"), which no `device` record names. A certificate no
`device` record names whose issuer is an admin key that was removed (`revoke`) gets nothing. The **root's own device** is the device of the newest `device` record with `holds_root` that
the current root's own key signed (the apps and `cbb` sign it right after making the group
or taking it over); a peer is the root only when its member key is that record's `key`.

### Stopping the exchange

When the records show a likely thief, the exchange stops until the root decides. The state
says how far:

| Cause | `stop` | Effect |
|-------|--------|--------|
| two claims under one root; a disputed claim; a conflict between admins; a root that signed two histories | `full` | every member stops sync, events, media, commands and admissions with every peer; its connections carry records only ("Records only" in the exchange), so the root's decision reaches it |
| an admin that signed two histories | `secrets` | no reader sends a secret event's `payload` (it sends the event's mark), no origin seals a secret to a device that admin alone admitted, and no member takes a `secret` paste; the devices that admin alone admitted get nothing: their connections carry records only |
| a pending claim | none | no origin seals a secret to the claimant's devices, no reader sends them a secret's `payload`, and they take no `secret` paste |

A member applies it as soon as it holds the records, and lifts it as soon as it holds the
root's records that end it: the check of a peer's certificate ("Certificates") lets a
connection carry records only while the stop holds, and the member connects again as a member
once it ends. `cbb status` and the apps show the cause, the devices involved and what ends it
(in Go `control.Status`'s `stop`, `claims`, `conflicts` and `newer`). A user who has lost the
root sets the group up again.

### The state

The function takes the group CA certificate, the record set, the current time on the
member's clock or that the member does not know the time, and, for each claim's record ID,
the time the member first held it (a time after the current one counts as the current one;
the time since and the time left are held at the ends of a 64-bit integer, never wrapped),
and returns the state as one canonical JSON object:

| Field | Type | Meaning |
|-------|------|---------|
| `roots` | array of strings | the path: the root certificates' key hashes from the group CA to the current root |
| `root_device` | string | the root's own device ID; absent when there is none |
| `devices` | array of objects | sorted by `device`: `device`, `name`, `role`, `caps` (a member's, when it has any), `os`, `keys` (sorted member key hashes that stand), the newest record's `store`, `kind`, `proof`, `seal` and `forward_only` when it has them, and, for an admin, `admin`, `powers`, `commands`, `frozen` (true when frozen) |
| `revoked` | array of strings | sorted key hashes the records remove |
| `claims` | array of objects | sorted by `record`: `record`, `claimant` (admin key hash), `root` (new root key hash), `state` (`pending`, `effective`, `cancelled`, `void`, `competing` or `disputed`), `left_ms` while pending |
| `conflicts` | array of objects | sorted by the first record ID: `kind` (`admins`, `claims`, `two_histories`), `records` (sorted record IDs), `signers` (sorted key hashes) |
| `stop` | string | `none`, `secrets` or `full` |
| `no_secrets_to` | array of strings | sorted device IDs that get no secrets |
| `nothing_to` | array of strings | sorted device IDs that get nothing |
| `newer` | array of strings | sorted IDs of the records of a later version the member keeps, at most 16 |
| `ignored` | array of objects | `{record, why}`: the records of the set that do not count and why, sorted by ID, at most 64; records listed in `newer` are not, nor a claim that took effect on the path, nor what the checkpoint that counts leaves out |
| `checkpoint` | string | the ID of the root's checkpoint that counts ("Checkpoints"): a member may delete the records it leaves out |
| `hubs` | array of strings | the main hubs of the `hubs` record that counts ("The hubs table"): its devices that are in `devices` and may be hubs (a phone, or a member with `hub`), in its order |
| `recovery` | string | the key hash of the recovery key ("The recovery key"), while it is neither removed nor frozen |
| `key_level` | string | the `key_level` of the current root's newest counting `settings` record; absent when it has none (then `hardware`), so a claim's new root starts without one and signs the old root's settings again |
| `ttl_ms` | integer | the `ttl_ms` of the `copies` record that counts ("The copies setting"); absent when none counts (then 300 000) |
| `secret_ttl_ms` | integer | the `secret_ttl_ms` of the `copies` record that counts; absent when it has none or none counts (then 60 000) |

The reasons in `ignored`, in the order they are decided:

| `why` | The record |
|-------|------------|
| `unreadable` | its body is not a record of version 2 |
| `signature` | its signature or chain does not check |
| `group` | is of another group |
| `issuer` | its admin CA is from no root of the group |
| `limit` | past a limit on the set (see "Limits") |
| `history` | its prev chain is broken, on a branch a `resolve` voided, or at or after a second history |
| `not_root` | a root's own record whose signer is no root on the path |
| `cut` | a root's record past its root's cut, or an admin record a root's removal, freeze or thaw cut off |
| `undecided` | an admin record in a conflict between admins |
| `power` | an admin record its signer had no admin power for, or with an admin CA of a root off the path |
| `removed` | an admin record a counting admin removal or freeze cut off |

Of two copies of one body left out before the evaluation (the first five reasons) for
different reasons, the reason first in byte order is kept.

Empty fields are left out, as in signed bodies, so two implementations agree when their
states are the same bytes. The state of a given set of records does not depend on the order
in which they arrived; the vectors give each set in every order of its records (up to 8
records; in random orders beyond) and check the same bytes.

### Exchange in the member protocol

- A member keeps every record it can read (and those of a later version, "Records of a
  later version") in a file next to its identity: at most 4096, plus up to 1024 more signed
  by the own key of a root on the path, so a full set still takes the record in which the
  root removes an admin that filled it, and at most 1024 of one signer. It MUST check a
  record's signature before it counts it against these limits. The limits of "Limits" then
  decide which of them count. An envelope with the body and the signature of one it holds
  is a copy, and it keeps the first. Go keeps the records in `records.json` (mode 0600) with
  the time it first held each claim, and the path in the identity file's `roots`.
- The hello object (section 4) carries `records`, the digest of the records the sender
  holds: SHA-256 over, for each record, its record ID and then the SHA-256 of its `sig`, each
  the raw 32 bytes, the 64-byte pairs sorted bytewise and concatenated; standard base64;
  absent when it holds none.
- A side that holds records and whose digest differs from the peer's sends, after the peer's
  hello, `{"t":"records","records":[envelope, ...]}` with every record it holds, split into
  messages of about 1 MiB each. A receiver adds the valid ones, saves them, and sends the
  records that were new to it to its other peers, which have sent their hello, the same way.
  Invalid records are logged and dropped; the connection stays.
- **Records only.** A peer whose certificate passes every rule of "Certificates" but the one
  on its `device` record (a device whose record has not reached this member yet, a new member
  that holds no records yet, or a root's own device during a claim), and any peer while the
  state stops the exchange with it ("Stopping the exchange"), gets a connection that
  carries records only: each side sends its hello with no current event and nothing but its
  records digest, sends its records when the digests differ, takes `records` from the peer,
  and sends and takes nothing else (no events, credentials, commands, tunnel keys or
  hubs). It closes the connection once the records let the peer in, and the side that
  dialed connects again at once as a member, or when no records came for 5 seconds. Every
  member keeps such a connection while the state stops the exchange with the peer, so that
  the root's decision reaches it; in the other cases `cbb` and the phones refuse the peer
  and take the records from the others.
- After adding records that refuse a peer's key (removed, frozen, or an ID that is not its
  own: `standing` in `core/src/peer.rs`), a member first closes every connection with a peer
  the records now refuse, and only then sends the new records and its hello to the others;
  the TLS check refuses the key from then on. A refused peer gets no records: not the record
  that refuses it, and not the device list. A removed device need not learn that it was
  removed, and the group refuses it wherever it connects. A frozen device learns nothing
  while it is frozen: once a `thaw` lifts the freeze, the TLS check lets it in again, and it
  takes the records, the thaw among them, when it connects again. A member MUST close a
  connection, and refuse new ones, whose peer key the records refuse, as soon as it holds the
  record. When the state stops the exchange ("Stopping the exchange"), a member applies it to
  every connection at once.
- A member that holds the root's key records every device it admits (its name and `os` from
  the pairing Info, role `member` and its `caps`), and itself and every connected peer that has no
  record yet, with the name and `os` from the peer's hello (or the role and the first 8
  characters of its ID). When a computer's hello states an `os` that its record does not, it
  signs a new record for it with that `os` and the rest of the record unchanged.

## 11. Tunnel keys

The keys of the group's WireGuard tunnel for sync away from home ([design.md](design.md),
"Sync away from home"), on the records of 0.6. Implemented in the Rust `cbb`: the device's
side in `member/src/live/away.rs` and `member/src/away/toward.rs`, the offer in
`member/src/away/offer.rs`, the hub's side in `member/src/away/held.rs`,
`member/src/away/serve.rs` and the tunnel's hub in `member/src/hub.rs`, the keys and tags in
`core/src/hubkey.rs`; the tunnel carries the member protocol between members ("Through the
tunnel" below). `cbb` runs GotaTun's WireGuard and smoltcp's TCP in its process
(`member/src/tunnel.rs`), with AmneziaWG (`member/src/awg.rs`) and VLESS over XHTTP
(`member/src/vless.rs`). The phones' member keeps the messages of 0.5 until the phones move
to the records of 0.6 (D-122; "Until the phones move to the records of 0.6" below).

- Sync away from home is off by default; nothing in this section happens on a device until
  the user turns it on there (`cbb global on`, the control operation `away`). A device whose
  tunnel secret sits in a file (every one but a Linux computer with a TPM, which seals it,
  section 17) MUST ask for the user's consent first (`consent` in the request). The device
  keeps this section's state in `tunnel.json` next to the group's records (mode 0600); a
  device that moves to another group turns sync away from home off and deletes it.
- A device sends no key in its hello. On each member connection with a device that may be its
  hub (the records give it an admin key or the root's hubs record names it), while sync away
  from home is on, it sends `tunnel` (t 15): field 2 its WireGuard key toward that hub,
  derived from its tunnel secret and the hub's ID, field 3 the confirmation tag of the
  pre-shared key both ends export from that connection's TLS (`hubkey`). It keeps, per hub,
  the last 8 keys it sent, the one the hub confirmed and the one of its last handshake
  (`toward` in `tunnel.json`). The relay's member connections (section 14) count as any
  other: a device meets its hubs there too.
- A member takes `tunnel` from any current member of the group (in the records, not frozen),
  and `hubs` (t 16) only from a device that may be a hub. The hub answers `tunnel` with a
  `result` (t 10) whose field 2 is the first 16 bytes of SHA-256(`cbb offer id v1` ‖ 0x00 ‖
  the tag) (`hubkey::offer_id`), field 3 the hub, and field 6 its offer (table `offer`, below),
  which the device keeps as that hub's, the tag in the offer's field 8 confirming the key.
  An offer comes only from the hub itself: no hub passes on another's offer or clients (A-22).
- All of this happens inside member TLS, so a device gets into the tunnel only after it met
  the hub as a member, and only with the key it sent on such a connection. A device that is
  not yet a member reaches a hub from the internet only with a remote invitation's guest key
  (section 12). No signed record binds the key: the connection's exported key does.
- When the records remove or freeze a device, the hub MUST forget its keys at once.

The offer (table `offer`, `core/src/msg/tables.rs`):

| Field | Name | Meaning |
|-------|------|---------|
| 1 | `hub-key` | the key the hub serves WireGuard under, 32 bytes, not all zeros |
| 2 | `endpoints` | the hub's addresses away from home, at most 8, each once; its forwarder's last (section 13) |
| 3 | `obfuscation` | the group's AmneziaWG settings ("Obfuscation" below); absent for plain WireGuard |
| 4 | `vless` | the way to the hub's forwarder over VLESS ("VLESS" below) |
| 6 | `moved` | the hub is no hub any more: the device forgets its offer and takes the next hub in the order ("Moving the hub", "Stopping a hub") |
| 7 | `next-key` | the key the hub serves with in the next period ("The hub's key" below) |
| 8 | `confirm` | the confirmation tag of the pre-shared key the hub holds newest for this device |
| 9 | `endpoint-keys` | per endpoint, the key the hub serves under there (its key for that forwarder's face, section 18); an endpoint without one uses field 1 |
| 10 | `next-obfuscation` | the AmneziaWG settings the hub takes with `next-key` (table `obfuscation`); only with fields 7 and 3 (`offer/next-obfuscation`), absent when they stay the same |
| 11 | `next-vless` | the way over VLESS the hub takes with `next-key`, at the same forwarder (table `vless`); only with fields 7 and 4 (`offer/next-vless`), absent when it stays the same |

Field 5 is not used. The device reads it so:

- the way over VLESS goes to the offer's forwarder endpoint, the first in field 2 that field 9
  gives a key of its own (else the first): on `vless/port` when present, with `vless/host` as
  the TLS server name and HTTP Host (the endpoint's host when absent), always over XHTTP in
  0.6; a later transport comes in a new field that 0.6 skips. An offer whose way over VLESS
  has no `vless/host` is refused: the forwarder's XHTTP front is checked by the system's
  certificate authorities under a site's name, which an address is not. One without
  `vless/path` is refused too: the path comes from the forwarder's answer to the hub's
  registration;
- `obfuscation` without `obfuscation/key` protects no headers (plain AmneziaWG junk and
  headers).

Away from home, when no hub is connected at home, the device dials a hub it holds an offer of
through the tunnel (`member/src/live/away.rs`): under its key toward that hub, with one
pre-shared key at a time in the order above, over every way of the hub at once (one per key
the hub serves under: its own on the endpoints no face names, each face's on its endpoint, the
way over VLESS with its forwarder's face, and the same with `next-key`). The key whose
handshake the hub answers is noted, and the member connection runs through that link.

The hub keeps, per client, its key toward the hub and the hub's `HubSide` (`held` in
`tunnel.json`). On a `tunnel` whose tag is the one of the connection's exported key it keeps
the key (a key another client or the hub itself holds is refused, and a new key toward the hub
starts afresh), answers with its offer, and gives its tunnel the client's keys; a client whose
keys alone changed keeps the tunnels of the keys that stay, so a connection through the tunnel
survives its own `tunnel`. The tunnel holds, per client, every pre-shared key the hub accepts
(at most 6: the last 4 received and the last 2 handshakes', `hubkey::HubSide::accepts`) as
one WireGuard tunnel each. An initiation is answered under each of them; the client takes the
answer under its own key, and its first data names the hub's session of that key, which
carries what goes to the client from then on. The key a handshake took is kept among the last
2. Its offer names its endpoints, the forwarder's last with the key the hub serves there
(field 9), and VLESS with the forwarder's site's name, port and path.

### Moving the hub

The hub, a computer or a phone, hands its role to another of the group's hubs ([design.md](design.md),
"The phone as the hub"): `cbb global move DEVICE [-forwarder ADDR -forwarder-key KEY]
[address:port...]` on a computer, "Move the hub to a computer" in the apps. On the records
of 0.6 no hub passes on another's offer or clients, and no wire is added for a move (D-122);
`TestMoveHub` moves a hub with a client away from home that has the group's relay.

1. The old hub sends the new one a `hub` command (section 15) with the new hub's forwarder
   and addresses, by default its own forwarder. The new hub must be one the records make a
   hub (the root's hubs record, or an admin); it becomes the hub with that forwarder and
   those addresses, listening on the port of the first address unless it was a hub already,
   and answers `done`.
2. The old hub sends the other hubs `hubs` with `stopped`, so that the new hub serves even
   below it in the order, at once (the grace a hub keeps when the hub above it goes is for a
   hub that went without saying so), and keeps serving the clients that came through its
   tunnel; while it hands over it does not stand by for a hub above it, and a tunnel it
   starts meanwhile (moved before it served) sends no `serving`.
3. A client away meets the new hub at home or at the group's relay, sends it `tunnel` there
   (t 15) as on any connection (the start of this section) and takes its offer from the
   answer.
4. Once the new hub said it serves (`hubs` with `serving`), the old hub sends each client
   connected to it an offer that says it `moved`, and stops being a hub when no client comes
   through its tunnel any more, or 5 minutes after the new hub serves; it stops after 5
   minutes too when the new hub never says it serves. A client that gets `moved` ends the
   connection through the old hub and takes the next hub in the order whose offer it holds.

A client away with neither home nor a relay holds no offer of the new hub at the move: it
loses the hub until it meets the new hub, at home or at a relay, and takes its offer there.

### Several hubs

The hubs of 0.6 serve in the order `State::hub_order` derives from the records alone
(`core/src/records/eval.rs`): the devices of the root's hubs record first, in the record's
order (the user's, not sorted; `cbb global hubs`, the control operation `hubs`), then the root's
own device and the other devices with an admin key, the computers before the phones, in each
part the root's own device first, then by device ID; frozen devices are left out. A phone that
made the group is its root and holds no admin key; it may be a hub all the same
(`State::may_be_hub`). The root is a hub only when its hubs record names it or the user makes
it one there.

- A device tries the hubs whose offers it keeps in that order, and none outside it. It learns
  a hub's offer only from its own `tunnel` to that hub.
- A hub that serves sends `hubs` (t 16) with field 3 (serving, 1) to each connected device
  that may be a hub, after the hello and when it starts serving, and field 2 (stopped, 1)
  when it stops being a hub; exactly one of the two, else the message is refused
  (`hubkey::read_hubs`, `hubs/shape`). Fields 4 and 5 are not used: hubs pass neither offers
  nor clients.
- A hub stands by, with no tunnel, while a hub above it in the order is connected and said
  it serves, and serves again a minute after it lost the last such hub
  (`member/src/live/away.rs`), or at once when that hub said `stopped`; a hub that moves
  does not stand by ("Moving the hub" above).
- An admin, or the root, makes a device the records allow a hub with a `hub` command (section
  15): field 10 names the hub by its address away from home and the hash of its member key,
  and a receiver whose key it does not name refuses; field 11 lists the forwarders with the
  pin the root signs for each (D-121). `cbb global hub -on DEVICE`, "Make it a hub" in the
  apps. The receiver refuses while sync away from home is off there, which only its own user
  turns on (D-45).

### Two kinds of hub

Copies are sealed end to end (section 4), so a hub needs no more trust than the members it
passes them between. A group has two kinds of hub, chosen when a device is made one (D-84):

- A **trusted hub** is the root or an admin, as in the rest of this section. It reads the
  copies as every reader does, and as an admin it admits devices; the group's key level
  (section 17) applies to it as to every admin.
- A hub that **only passes copies on** is a computer whose device record has `forward_only`
  (section 10), which on 0.6 the group's root alone signs, naming it in the hubs record too;
  an admin's order for one is refused as not done yet (D-122). No copy is sealed to it, so it
  reads none; it makes no copies (every member refuses one whose origin has `forward_only`,
  [format](format.md), section 10.4), writes none to a clipboard and takes no `paste` or `action` command.
  It holds no admin key, so it makes no remote invitation (section 12): a device far away
  joins through a trusted hub, or at home. No key level applies to it, since whoever takes
  its keys can hold copies back and learn what any member in between learns (section 4,
  "What the members in between see"), and nothing more: an always-on board whose keys sit in
  files serves as well as any.

The root makes a computer such a hub with `cbb global hub -on DEVICE -forward-only` (the apps'
"Make it a hub", "Only passes copies on"): it signs the record and then sends the `hub`
command.

### Stopping a hub

A hub stops being one by its own user's word (`cbb global hub off`, "Stop being the hub" on
the device's own page in the Mac app and the tray app) or by an admin's: a `hub` command whose
order is `stop` and nothing else (section 15; `cbb global hub off -on DEVICE`, "Stop being the
hub" on another device's page).

1. Without another hub in the group's order the sender refuses, unless the user agreed that
   the devices away from home stop syncing until a device is a hub again (`-yes`; the apps
   ask first); a receiver of the command never refuses for that reason, since its sender
   asked.
2. The hub sends each client connected to it an offer that says it `moved`, so that the
   client takes the next hub in the order whose offer it holds, and drops its hub settings;
   its tunnel stops.
3. It sends `hubs` with `stopped` to its connected peers that may be hubs, so that a hub
   below it that stood by serves.

The receiver of the command answers `done` first and then stops. A device that was away and
not connected keeps the stopped hub's offer until it meets a hub again; it tries the hubs in
order, so the stopped one costs it a try.

### The hub's key

A hub serves its clients with a WireGuard key of its own for each period of its forwarder's
face (section 18), apart from its key at home, so that a server on the way, such as the
forwarder, cannot link the group's traffic from one period to the next by the hub's key.
Implemented in the Rust `cbb` (`State::rotate` in `member/src/tunnel.rs`, `Away::rotate_live`
in `member/src/away/serve.rs`, called from `serve_hub` in `member/src/live/away.rs`).

- The period is the tag of its forwarder's face, else of the project's forwarder's; without
  either, the hub keeps its key.
- A hub that sees a period always holds the next key, made at random, and with it new
  AmneziaWG settings when it hides its tunnel and a new VLESS user ID when it has VLESS, which
  its offers give as `next-key`, `next-obfuscation` and `next-vless` from then on, to every
  connected client at once (they connect again and take the offer with their next `tunnel`)
  and to the others when they meet it.
- When a period comes that it serves with no key for, and at least three days after it made
  the next key, it serves with the next key in place of the old one, with the settings and
  the VLESS user ID that go with it: it starts its tunnel again, registers again with its
  forwarder (section 13) under the new period and the new user ID, and makes the key after it
  at once.
- `tunnel.json` keeps the key the hub serves with, the next one and the period each is for.
- A client tries a hub with its key and, when the offer has one, with `next-key` and the
  settings and way that go with it (`Hub::with_next`), both at once, and keeps the one that
  answers, so a client that was away while the hub moved on still reaches it; the offer it
  gets then replaces the one it kept. A client that was away for the whole period before and
  never got `next-key` reaches the hub again at home or at the group's relay.
- A hub refuses a client key that is one of its own keys.

### Obfuscation

A hub speaks AmneziaWG instead of plain WireGuard unless the user turned it off (`cbb global
hub -no-obfuscate -no-vless`). Its offer carries the settings in field 3 (table
`obfuscation`); every client sets them on its end before the hub as its peer:

| Field | Name | Meaning |
|-------|------|---------|
| 1, 2, 3 | `jc`, `jmin`, `jmax` | junk packets of random bytes before each handshake: `jc` (1 to 128) of them, `jmin` to `jmax` bytes (at most 1280) |
| 4 | `s` | up to 4 paddings, 0 to 1280 bytes each: random bytes in front of the handshake initiation, the response, the cookie reply and each data message, at least 16 with header protection |
| 5 | `h` | up to 4 ranges, each a pair of 32-bit numbers: the range each of those messages' type field is drawn from, in the same order; above 4, not overlapping |
| 6 | `key` | 32 bytes, optional: the key of the header protection, which encrypts the rest of each message's header with the first 12 bytes of its padding as the ChaCha20 nonce; absent, no header is protected |

- A receiver MUST refuse settings outside these bounds and not start the tunnel, and also
  when `key` is all zero, or when two of the padded handshake messages would have the same
  size: the initiation is 148 + its padding, the response 92 + its padding and the cookie
  reply 64 + its padding, and the three MUST differ.
- The header protection, the padding and the type ranges are AmneziaWG's, as the
  amneziawg-go version in `go.mod` implements them (`device/send.go`, `device/receive.go`;
  a copy with three changes unrelated to the wire is in `internal/third_party/amneziawg-go`).
  An implementation MUST follow that version byte for byte.
- The hub makes the settings at random (docs/design.md, "Blocked networks"); its next key
  keeps them. Switching obfuscation on or off changes them; each client gets the new ones the
  next time it meets the hub at home or at the group's relay.
- An obfuscated hub with a forwarder gives it the settings when it registers (section 13),
  since the forwarder's routing needs WireGuard's own headers.

### VLESS

A hub with a forwarder has its clients reach the forwarder inside VLESS where UDP does not
pass, which to the network is HTTPS to a website (docs/design.md, "Blocked networks"): XHTTP
behind the web server of the forwarder's own site. The hub makes a VLESS user ID for the group
and keeps it with its key; it learns the rest from the forwarder's answer when it registers
(section 13) and keeps that too. Its offer then carries, in field 4 (table `vless`):

| Field | Name | Meaning |
|-------|------|---------|
| 1 | `user` | the group's VLESS user ID, 16 random bytes (a UUID of version 4) |
| 2 | `port` | the web server's TCP port at the forwarder's address; absent, the endpoint's |
| 3 | `host` | the site whose name the TLS handshake carries and its certificate must carry; required in 0.6 |
| 4 | `path` | the path the web server passes, a slash and 8 to 64 of `A-Z a-z 0-9 - _`, then the group's own part, made from the user ID (section 13, "VLESS"); required in 0.6 |

- A hub at a forwarder asks for VLESS unless the user turned it off (`cbb global hub
  -no-vless`). A hub that sets VLESS speaks AmneziaWG as well ("Obfuscation" above): its offer
  carries `obfuscation` beside `vless`. Inside VLESS it hides WireGuard's fixed sizes from
  what the TLS records show, and over UDP it lets a client try the faster way first.
- Until the hub has the forwarder's answer it MUST NOT send an offer with `vless`. When the
  answer comes, or changes, the clients connected connect again and take the new offer with
  their next `tunnel`.
- The client runs VLESS without encryption (Xray-core) from a local UDP port to that
  endpoint, and points its WireGuard at the local port. It is XHTTP's `packet-up` mode (plain
  HTTP requests, which any web server and proxy passes) on `path`, with `host` as the host,
  over TLS with the fingerprint of Chrome, ALPN `h2` and `http/1.1`, and the site's
  certificate checked against the public CAs for `host`. Its HTTP connections are reused as
  Xray's own client configuration does by default (three at once, each dropped after 600 to
  900 requests or 1800 to 3000 seconds, at random), and the gap between two uploads is 10 to
  50 ms at random; each request carries Xray's padding of random length. Each upload carries
  at most 32 KiB, and the forwarder refuses a larger one and keeps at most 8 uploads of a
  session that no client has opened ([relay-budget.md](relay-budget.md#xhttp)). The forwarder
  passes every UDP packet that comes over VLESS to its own UDP port, so the packets are
  forwarded as in section 13; VLESS carries nothing else.
- A receiver MUST refuse settings that do not have this form and not start the tunnel; it
  never falls back to plain WireGuard.

### Through the tunnel

- The hub runs WireGuard in user space on its UDP port (8764 when none is given), with one
  tunnel per pre-shared key it accepts of each client (above), the client's tunnel address
  the only allowed address. Inside the tunnel the hub MUST listen only on TCP 8764 at its own tunnel
  address, for the member protocol (section 4) and nothing else: no pairing and no forwarding of packets between peers.
- After the member TLS handshake the hub MUST check that the device ID of the client
  certificate gives the tunnel address the connection came from, and close it otherwise,
  so a device cannot use another device's tunnel key.
  Note: a phone that is a hub does not check this yet. Its tunnel (`ffi/src/tunnel.rs`) hands
  each connection to the app through a loopback port, which does not say from which tunnel
  peer it came, so such a hub knows the client by its member certificate alone. This is
  planned for 0.7, with a call in the phones' tunnel that names the peer of a loopback connection.
- A member that keeps hubs' offers runs the other end, with the hub it tries as its only
  peer and a keepalive every 25 s. It dials the hub's tunnel address, TCP 8764, with member
  TLS whenever no hub is connected on the home network, trying the hubs in order, each over
  all its ways at once (above), with the dialers' backoff (1 s, doubling to 30 s). A hub that discovery finds holds
  this off for 30 s only: anyone on a network can announce the hub's name and the group's
  tag, so after that only a connection to the hub counts. The relay path (section 14) and
  the dialers through the hub follow the same rule.
- A member MUST fail closed: when the hub or the link cannot start, or the hub does not answer, the
  member syncs at home only, and `status` says why (`error`, with `detail` for debugging).
- `cbb` starts its end only while it dials the hub through it, so at home it sends
  nothing to the hub's addresses away from home. It accepts an offer only from a
  member that may be a hub, starts the handshake at once over every way of the hub,
  and runs TCP inside the tunnel with an MTU of 1280, so no packet is fragmented on the way.

### Until the phones move to the records of 0.6

The phones' member of 0.5 (`member/src/phone.rs`, through ffi; the kits' `TunnelOffer`)
still reads and writes the tunnel's messages of 0.5 until the old code goes (D-122); the
apps act on none of them, since a phone in a group of 0.5 syncs at home only (D-123), and a
service of 0.6 starts no tunnel in a group of 0.5 and never sends them.

- Each member's hello carries `tunnel_key`, its WireGuard public key, and `tunnel_psk`, a
  preshared key of 32 random bytes it made with the key pair. A member where sync away from
  home is off sends neither, and tells its peers of a change in a `presence` message.
- A hub admits a peer whose hello carries `tunnel_key` and answers with
  `{"t":"tunnel","tunnel":{...}}`: `hub_key` (32 bytes), `psk` (the one the hello offered),
  `endpoints` (at most 8), `obfuscation` (AmneziaWG's names: `jc` 0 to 16, `jmin` and `jmax`
  at most 1000, `s1` to `s4` 16 to 64, `h1` to `h4` as `"min-max"`,
  `header_protection_key`), `vless` (`transport` `xhttp`, `endpoint`, `server_name`, `path`,
  `id`), `hub` (in an offer passed on for another hub), `moved`, and `next_key`,
  `next_obfuscation` and `next_vless` for the next period.
- A hub sends each peer that may be a hub `{"t":"hubs","hubs":{...}}` with `stopped`,
  `serving`, its `offer` without `psk` and its `clients` (`device`, `key`, `psk`, at most
  256), and passes the other hubs' offers on to its clients.
- A member keeps an offer only from a device that may be a hub by its records (the root, an
  admin, or a device with `forward_only`), one per hub by device ID; `moved` makes it forget
  the sender's. A phone that is the hub ignores offers, and shares its clients but does not
  stand by for a hub above it.

## 12. Remote invitations

A device that shares no network with the group joins through the hub's tunnel with a remote
invitation ([design.md](design.md), "Joining from another network"). Implemented in the Rust
`cbb` (`member/src/inviter.rs`, `member/src/away/invite.rs`, `cbb invite`, `cbb pair -invite`)
on the computers and small devices, in the phones' member through ffi (`cbb_invite_*`,
`cbb_joiner_*` with `invite`), and on an admin phone that is the group's hub (the member's
Live hub, ffi's `hub` operation). The text is read by the Rust
core (`cbb_core::invite`) and Go's `internal/invite`.

### The invitation

Made by the root or any admin that admits devices: on the hub, by the control operation
`invite` (`cbb invite`) or in the app of a phone that is the hub, whose endpoints are its
forwarder's; on another admin, through a hub ("Through the hub"). A hub that only passes
copies on (section 11, "Two kinds of hub") holds no CA key and makes none itself, though it
opens the guest tunnel of another admin's invitation. Its text is
`cbb://invite#` followed by standard base64 of this JSON (byte strings
in it as in the rest of this document):

| Field | Type | Meaning |
|-------|------|---------|
| `v` | number | 1 |
| `g` | string | the group's tag |
| `h` | string | the hub's device ID |
| `hk` | bytes | the hub's WireGuard public key, 32 bytes |
| `ep` | array of strings | the hub's addresses away from home, `ip:port`, 1 to 8 |
| `k` | bytes | the guest's one-time WireGuard private key, 32 bytes |
| `psk` | bytes | the guest's preshared key, 32 bytes |
| `s` | bytes | the pairing secret, at least 16 random bytes (128 bits) |
| `exp` | number | when it expires, Unix seconds |
| `o` | object or absent | the hub's obfuscation settings, as in its offer (section 11, "Obfuscation") |
| `x` | object or absent | the way to the hub's forwarder over VLESS with XHTTP, as in its offer (section 11, "VLESS"): `transport` (`xhttp`), `endpoint`, `server_name`, `path` and `id`, all strings |

The JSON is in the strict form of signed bodies (Conventions), with exactly these fields and
no other, so that every implementation reads one text alike (Go's `internal/invite`, the
Rust core's `cbb_core::invite`, both checked on `testdata/interop/invites.json`):

- The text is the prefix, in these lowercase letters, and standard base64 in its one form
  (Conventions, "Bytes"); spaces, tabs and line breaks around it are ignored, and nothing else
  is.
- `g` is a group tag and `h` a device ID (section 1). `hk`, `k`, `psk`, `s` and the
  obfuscation's `header_protection_key` are standard base64 in its one form (padded).
- `hk`, `k` and `psk` are 32 bytes and not all zeros. `s` holds 16 to 64 bytes. `exp` is
  greater than 0.
- Each `ep` is an address in its canonical form: an IPv4 address without leading zeros, or
  an IPv6 address in brackets, compressed, in lowercase and without a zone, then `:` and a
  port from 1 to 65535 without a leading zero.
- `o`, when present, has every field of the offer's settings, each within the offer's
  bounds. Each `h1` to `h4` is `min-max`: two decimal numbers of 32 bits, without a sign or
  a leading zero, `min` not above `max`.
- `x`, when present, has exactly its five fields, each a string: `transport` is `xhttp`,
  `endpoint` an address as in `ep`, `server_name` a host name, `path` an absolute path and
  `id` a UUID in lowercase, as the offer's VLESS settings. A hub whose offer has none, or
  REALITY, which the phones and `cbb` do not speak, writes none. A device that
  cannot reach the hub over UDP dials the guest tunnel through it.

A text refused names one reason, the same in every implementation:

- `not_invitation`: not the prefix.
- `damaged`: not standard base64, not strict JSON, a field missing, unknown or of another type.
- `version`: a `v` other than 1.
- `group`, `hub`, `key`, `endpoints`, `secret`, `expiry`, `obfuscation` or `vless`: that
  field's value is refused.

A device joins only while `exp` is later than its clock. A device that does not know the
time yet does not join.

It travels as a QR code of its text, the usual way, which a phone scans in Join with an
invitation, or as its text or a file of one line (`.cbbinvite`, mode 0600, which `cbb invite`
deletes when the invitation ends and `cbb pair -invite` deletes once it joined), for a
computer and for whoever got the QR code another way; it is never typed. It is a secret
until it is used. It serves one device once, for 1 hour unless the admin asks for up to 24
hours, and closes after three failed attempts or when the admin cancels it. A device asks
its user before it joins: it shows the group's tag, the hub and when the invitation expires,
and joins only once the user accepts; declining sends nothing.

### The guest tunnel

- The hub adds the guest key as a WireGuard peer, with the preshared key, whose only
  allowed address is the guest address: fd00:cbc::/32 followed by the first 96 bits of
  SHA-256 of the guest's public key. That prefix is apart from the members' (section 11),
  so a guest address never names a member. Peers that stay when the hub's peers change
  keep their sessions.
- Inside the tunnel, a connection from a guest address to TCP 8764 gets the pairing
  (ALPN `cbb-pair/3`, section 6) of that invitation's window and nothing else,
  except, once the window admitted a device, member TLS from that device alone, for its
  first hello (below). Any other connection MUST be closed.
- The hub drops the guest peer when the invitation ends without a device, and once the
  admitted device reached it with its own tunnel key (Joining, step 4), or 24 hours after it
  admitted the device, whichever comes first: a device that starts late, or loses its
  network after the join, still offers its key through the guest tunnel.

### Joining

1. The new device starts a tunnel client with the guest key, its guest address and the
   hub's key, tries the hub's endpoints in turn (20 s each), and dials the hub's tunnel
   address, TCP 8764.
2. It pairs as in section 6 with the secret as the password. The window MUST take no other
   password, MUST give no CA keys, and before it makes the certificate MUST ask the hub's
   admin to confirm the device, with its name, system, device ID and key fingerprint; the device
   shows the same fingerprint. The admin has 5 minutes; a no sends `declined`. The device
   MUST check that ADb's `group` is the invitation's `g` before it sends its tag, and so that
   the Welcome's group CA is that group's: whoever else holds the secret cannot bring the
   device into another group.
3. Once it has its certificate, the device turns sync away from home on (the user
   consented before the join) and makes a member connection to the hub through the guest
   tunnel. Its hello carries its own tunnel key, which the hub admits (section 11) and
   answers with its offer.
4. With the offer, the device closes the guest tunnel and from then on reaches the hub
   through the tunnel with its own key, as any member. Until it has the offer, it keeps the
   invitation (`cbb` in `invite-guest`, mode 0600, the phones in
   their key store) and tries again through the guest tunnel, after a restart too, for up to
   24 hours.

### On the records of 0.6

A group of 0.6 makes the invitation of the [format](format.md), section 11.3 (`cbb://join#...`),
on a hub that serves (`member/src/live/invite.rs`, the control operation
`invite` in `member/src/service/on_live.rs`), or through a hub (below). It
carries no group and no hub, only one-time values and one guest path: the hub's addresses
away from home (its forwarder's after its own, at most eight), the key it serves under, the
guest's one-time WireGuard key and pre-shared key, and the group's obfuscation settings.

- Its profile is a computer's (role member) or, with `cbb invite -phone`, a phone's, with
  the rights a home window gives (read, send, secrets, and hub for a member with the cap
  that the root admits); never home only.
- Inside a guest tunnel the hub also answers at its guest address, `fd00:cbc::1`: the
  invitation names no hub, so the guest dials TCP 8764 there. It is the first address of
  the guests' prefix and no guest's (a guest whose address it would be is refused); only a
  guest's packets may reach it. There a connection gets only the pairing (`cbb-pair/3`) of
  its invitation, one attempt at a time, and once the admin admitted a device, member TLS
  from that device alone.
- The pairing is section 8's, by the invitation, from network `guest`. Once the device
  proved the secret, the member writes nothing yet: the operation `invite` answers a partial
  `joining` with the device's name, system, device ID and key fingerprint (standard base64 of
  its key hash, which the device shows too), and the admin answers once (`answer` with
  `consent`), within 5 minutes. A no, or no answer, ends the attempt as failed: the device
  gets pair error 7 (`declined`), nothing is written, and the invitation takes the next
  attempt at once; three failed attempts close it. A yes writes the device's record and
  sends the Welcome. The device waits for each answer that long.
- The device that joined keeps the invitation in `invite-guest` (mode 0600) and turns sync
  away from home on before it keeps the set. Until it holds a hub's offer, its member dials
  the hub through the guest tunnel; its `tunnel` (t 15) there gets the hub's offer, and the
  hub drops the guest once that connection ends, or a day after the admission. The device
  then forgets the invitation and reaches the hub with its own key.
- An admin that is not the hub makes it through a hub (`member/src/live/through.rs`, the
  hub's side in `member/src/live/invite.rs`): the one `cbb invite -hub` names, or the first of
  the group's hub order connected now that takes it (one that answers that it serves as none
  is skipped). The two talk in their member connection with message `guest` (t 17, table
  `guest`): field 2 the op, 3 the guest's WireGuard key (which names the invitation), and by
  op 1 `open` 4 the pre-shared key, 5 the expiry (Unix ms, at most 24 hours and a minute
  away) and 11 the invitation's ID; 2 `opened` 6 the hub's offer (table `offer`: 1 its key,
  2 its addresses, 3 the obfuscation settings), from which the admin makes the guest path;
  3 `refused` 7 a sentence for the user; 4 `data` 8 the connection (numbered by the hub from
  1) and 9 at most 16 KiB of its bytes; 5 `end` 8; 6 `admitted` 10 the device ID; 7 `close`.
  The hub takes `open` only from a member its records let admit devices, and every later
  message about the guest only from that admin. It keeps at most 4 such invitations of one
  admin and 16 in all, passes at most two pairing connections of a guest at once, each at
  most 1 MiB and silent at most 6 minutes, and closes one that comes while the admin is not
  connected. The admin's window takes each passed connection as its own; once it admitted a
  device, the device's member connection through the guest tunnel reaches the hub's member
  listener, as on the hub's own invitation.

### Through the hub

An admin that is not the hub makes the invitation through a hub it is connected to: the
first of the group's hubs (section 11) that takes it, or the one the admin names (`cbb invite
-hub`). The admin keeps the window and the CA key; the hub only lets the guest in and passes
the bytes. They talk in the member connection with `guest` messages (section 4): `{"t":
"guest", "guest": {...}}`, the object's `op` naming what it does and `key` the guest's
WireGuard public key, standard base64, which names the invitation:

| `op` | From | Fields | Meaning |
|------|------|--------|---------|
| `open` | admin | `psk`, `expires_ms` | let this guest in until `expires_ms` (Unix milliseconds, at most 24 hours and a minute away) |
| `opened` | hub | `hub_key`, `endpoints`, `obfuscation`, `vless` | the guest is in: the invitation's `hk`, `ep`, `o` and `x` |
| `refused` | hub | `reason` | a sentence for the user: not a hub, not an admin that admits devices, a lifetime too long, or the key in use |
| `data` | both | `conn`, `data` | bytes of the guest's connection `conn` (numbered by the hub from 1), at most 16 KiB a message |
| `end` | both | `conn` | that side closed the connection for writing |
| `admitted` | admin | `device` | the window admitted this device: the hub keeps the guest for its first hello (Joining, step 3) |
| `close` | admin | | the invitation ended without a device |

The hub takes `open` only from a peer whose chain and records make it the root or an admin
that admits devices, and every later message about a guest only from the admin that opened
it. The guest's connections to TCP 8764 inside the tunnel reach the admin's window through
`data` messages; once the window admitted a device, its member connection through the guest
tunnel reaches the hub's member listener, as on the hub's own invitation. A guest
connection that comes while the admin is not connected is closed, and the device tries
again; the guest stays until the invitation's expiry. A hub keeps a few such guests at once,
and fewer for one admin.

### On a phone that joins

The phone joins in its app: Start's Join with an invitation reads the QR code, the text or
the file, and the invitation waits to be accepted or declined. Accepted, the core starts the
guest tunnel in the app's process and dials the hub's guest address through it
(`cbb_joiner_new` with `invite`); the phone is the TLS client of the pairing and shows the
fingerprint the admin compares. Once admitted it keeps the set with the invitation, and its
member, once started, reaches the hub through the guest tunnel and offers its own tunnel key
until the hub's offer comes, as a computer that joined by an invitation does.

### On a phone that is the hub

A phone that is a hub of a group of 0.6 is the Live member's hub, which serves the guests of
invitations as the computers' does. An admin phone makes its invitation through a hub of the
group, as "Through the hub" says, with the window in its member (`cbb_invite_*`), and so does
an admin phone of a group of 0.5, which is no hub (D-123); the invitation shows as a QR code,
and its file goes through the phone's share sheet. `TestFFIInviteThroughHub` and the Kotlin
kit's `InviteKitTest` run it.


## 13. The forwarder

A server that holds no keys and passes the encrypted WireGuard packets of a group's clients
to that group's hub, for hubs that clients cannot reach directly ([design.md](design.md),
"The forwarder"). Implemented in Go (`internal/forward`, `cbb forward`, which reads the
format with `internal/blind`, D-106), and on the hub in Rust (`member/src/forward`). Routing is by `mac1`; the fallback by a computed port is
not built.

- The forwarder listens on one port number, UDP for packets and TCP for registrations.
  Its key is an ECDSA P-256 key with a self-signed certificate; hubs pin it by its
  fingerprint (Conventions, "Fingerprints").
- The hub keeps `forwarder: {endpoint, key}` in its `tunnel.json` and gives its clients the
  forwarder's endpoint after its own (section 11). Clients need nothing else: to them the
  forwarder is one more address of the hub.

### What the forwarder learns

Accepted by design ([design.md](design.md), "The forwarder"): the hub's WireGuard public
key, the group's obfuscation settings and VLESS user ID when set, the addresses of the hub
and its clients, and the timing and sizes of their packets. Besides, a hub shows only the
tag of its group's period for the forwarder's face (section 18, faces per server), a
certificate of its server key for that face that names neither a device nor a group, and the
face's hubs' credential: hashes of server keys, padded, a version, an expiry and the period
key. It never shows the period credential, so the forwarder never sees the Group ID or the
root's key. All of it is new each period, as are the hub's WireGuard key, its obfuscation
settings and its VLESS user ID (section 11, "The hub's key"). The hub moves to its key,
settings and user ID at once, as it registers under the new period, so none of these three
links two periods; the hub's source address and port, which the forwarder sees as it sees
every packet's, stay the same across the change unless its network changes them, and so may
link two periods. The first period a hub serves still has the key its hello offers for three
days. It never sees a member key, a record, a device ID, a text, or which client address is
which device. On disk it keeps only a keyed hash of each period's tag with the version of its
newest credential and a hash of its period key ("What it keeps").

### The project's forwarder

The project runs a forwarder at `cbb.tools:8764`, which every program knows: `cbb global hub`
without addresses, or with `-forwarder default`, and a phone that is the hub without a
forwarder of the user's own take its address, looked up when the hub is set, and its pin,
so that nobody types either. The control request carries the address the command line
looked up and `forwarder_key` `default`; the service fills in the pin. The pins a hub
accepts from it are those of the newest `keys.json` the group passed around, with a release
or with the entry points, when that lists any for `cbb.tools:8764` (section 16, "Keys"), else those built in
(`internal/forward/project.go`, `HubState.Forwarder.projectPin` in the kits); while its key
changes both pins are listed and either is taken. A hub command carries the pin the old hub
accepts, and a hub that knows it as the project's follows its key from then on, as the hub
state's `project` says. The clients get the forwarder from the hub's offer, as for any
other.

A hub of the project's forwarder registers over VLESS when direct TCP to it does not answer
("Registration", below): through the ways in that the newest signed entry points it holds
name for `cbb.tools:8764` (section 16, "Entry points"), each `server_name` looked up when it
is not the forwarder's host, else through the one built in (`forward.ProjectVLESS`: XHTTP
on `cbb.tools:443`). A hub of another forwarder uses the VLESS settings it learned from that
forwarder's registration answer.

### Registration

A hub of 0.6 registers by `cbb-forward/3`, the one protocol the forwarder speaks. Each message
is one frame of the format (section 4, "Frames"), a map with its type `t` in field 0, its
length on the format's grid; the forwarder reads at most 1 MiB from the hub in all and closes
the connection beyond that:

| t | Message | From | Fields |
|---|---|---|---|
| 80 | `forward/challenge` | forwarder | 2 `e`, the forwarder's ephemeral X25519 key (32 bytes) |
| 81 | `forward/register` | hub | 2 `key`, its WireGuard key (an X25519 key); 3 `proof` (32 bytes); 4 `obfuscation`, the group's settings (table `obfuscation`); 5 `vless`, the group's VLESS user ID (16 bytes); 6 `credentials`, at most 3 envelopes |
| 82 | `forward/registered` | forwarder | 2 `id`, the registration's ID (1 to 2^63 - 1); 3 `mask`, the key of the hellos' mask (32 bytes); 4 `vless`, a map: 1 `user` (16 bytes), 2 `port`, 3 `host`, 4 `path` |
| 83 | `forward/error` | forwarder | 2 `reason`, text of at most 256 bytes |
| 84 | `forward/seen` | forwarder | 2 `addr`, where the forwarder sees the hub's WireGuard port (`ip:port`) |

1. The hub connects over TCP and runs TLS 1.3 with ALPN `cbb-forward/3` and no server name.
   It MUST accept only the pinned key. It presents only a certificate of its server key for
   the forwarder's face (section 18), self-signed, with the subject `cbb server`, no names,
   key usage digitalSignature and client use. The forwarder refuses any other ALPN and any
   other chain. A hub whose group's hubs' credential for the face does not list its server
   key yet does not connect, and its status says it waits for it.
2. The forwarder sends `forward/challenge`.
3. The hub answers `forward/register`:
   - `key` is its WireGuard public key, and `proof` is HMAC-SHA256 under X25519(the hub's
     WireGuard private key, `e`) of 32 bytes exported from the TLS session with the label
     `cbb forwarder key` and no context. So the hub proves it holds the key, on this
     connection only.
   - `credentials` is the face's hubs' credential alone. The forwarder checks it (section 18,
     "What a server checks"): it has not expired, lists the hash of the certificate's key
     among the hubs, and the period key that signed it is the one the forwarder first saw for
     its tag, at a version no older than the one it keeps ("What it keeps"). It then keeps
     the version for the period, whose tag names the group there (`period <tag in hex>`).
   - An obfuscated hub adds its group's `obfuscation` settings (section 11, "Obfuscation");
     a plain hub leaves them out. Settings of the table that the forwarder cannot route by
     (with no header protection key, for one) make its way unusable, not the message: it
     refuses them as "the obfuscation settings are not usable". A hub whose clients come over VLESS adds the group's VLESS
     user ID as `vless` (section 11, "VLESS").
4. The forwarder answers `forward/registered`, a random registration ID and the key of the
   hellos' mask, the same for every hub, or `forward/error` and closes: the frame or a
   message breaks the format, the proof is wrong, the credential does not verify, has
   expired, does not list the hub, is older than the forwarder saw or comes from another
   period key than the one it saw first for the tag, another group registered that key or
   that VLESS user ID, or the forwarder is full. A forwarder without VLESS registers a hub
   that asked for it for UDP alone and leaves `vless` out of its answer; the hub then
   forgets its VLESS user ID and sends its offer without `vless`. A hub told that another
   group registered its VLESS user ID takes a new one, with the path made for it, sends its
   offers again and registers again. To a hub that asked for VLESS a forwarder with it adds
   `vless`: the user ID, the web server's port (443 when left out), its site and the
   group's path ("VLESS", below), which the hub's offers give as XHTTP; the forwarder lets
   that user ID in while the registration lasts. A group has one registration: a new one
   replaces the old, whose connection closes.
5. The registration lasts while the connection does; the hub sends nothing more on it. The
   forwarder sends `forward/seen` whenever it learns a new address of the hub's WireGuard
   port, in the address's one written form (no zone, no IPv4-mapped IPv6 address, a port
   that is not 0); a hub refuses another form (`forward/seen/addr`). The hub registers again whenever the connection breaks, with a backoff of 1 s
   doubling to 60 s, and at once when the face's hubs' credential changes, so that the
   forwarder learns the new version, and under a new period's tag when it serves with its
   key for that period (section 11, "The hub's key").

### Hellos

From its WireGuard UDP port, the hub sends the forwarder's UDP port a hello every second
until it hears `seen`, then every 15 s, which also keeps its NAT mapping open. A hello's
content is 36 bytes: `0x80 0x00 0x00 0x00`, the registration ID (8 bytes, big-endian), a
counter (8 bytes, big-endian, growing; the hub uses Unix nanoseconds), and the first 16
bytes of HMAC-SHA256, under 32 bytes exported from the TLS session with the label
`cbb forwarder hello`, of the first 20 bytes. On the wire it is masked: a random
12-byte nonce, then the content XORed with the ChaCha20 key stream under the `mask` key and
that nonce, then 0 to 31 random bytes, so a hello is 48 to 79 bytes of random-looking data.
The forwarder MUST take a hello only with a valid MAC and a counter above the last one, and the
hub's port is where the last hello came from.

### Forwarding

The forwarder looks at WireGuard's message type (the first byte, then three zero bytes) and
at the indices; it MUST NOT change anything in a packet, and MUST pass a packet only to the
hub or client of its own group. In an obfuscated group it reads them as the
hub does: it skips the padding of the message's size (`s1` to `s4`), takes the header
protection off a copy, and checks that the type field is in the message's range (`h1` to
`h4`); `mac1` is then computed over the message with that type field.

- A handshake initiation (type 1, 148 bytes) from a client goes to the hub whose `mac1` key,
  BLAKE2s-256(`mac1----` || the hub's public key), gives the packet's `mac1` field. The
  forwarder remembers the client's address under the initiation's sender index for 10 s.
- A handshake response (type 2, 92 bytes) from a hub goes to the client whose sender index
  is its receiver index. The forwarder then keeps the session for 200 s: the client's
  address and index, and the hub's index (the response's sender index).
- A cookie reply (type 3) from a hub goes like a response; data (type 4) from a hub goes to
  the client of the session with that receiver index, and data from anyone goes to the hub
  of the session whose hub index is its receiver index. When two sessions get the same hub
  index, the newer wins.
- Everything else is dropped: packets of other types or sizes, a handshake whose `mac1`
  matches no hub, a hub's own handshake initiation (its `mac1` is keyed with a client's key,
  which the forwarder does not know; clients keep their sessions fresh), and responses
  from clients.
- A client's new address is taken with its next handshake (within 15 s of WireGuard
  hearing nothing), not with data, which anyone could send.
- An obfuscated group's packets are read with its settings only where they can be the
  group's: a handshake initiation of the size of that group's, and anything from an address
  that has a handshake or session with that group. The data of an obfuscated session then
  passes only from the client's address, and goes to the hub whose index it names only if
  the session is that group's.

### VLESS

A forwarder takes VLESS over XHTTP (`cbb forward -vless-xhttp cbb.tools`): it listens on the loopback address
(`-vless-listen`, `127.0.0.1:3276` by default) for XHTTP as plain HTTP, behind the web
server of its site, which ends the TLS on TCP 443 with the site's certificate and passes
the path to it:

- The path is `-vless-path`, or one made at random the first time and kept in its key file
  as a PEM block `CBB XHTTP PATH` (the path's bytes). It keeps scanners off the listener;
  nothing relies on it being secret.
- Under the path itself the forwarder takes only registrations (the registrations' user ID,
  below). Each group's packets come under a path of its own below it, `<path>/<group>`:
  `<group>` is the first 16 bytes of SHA-256 over `cbb group path`, a zero byte and the
  group's VLESS user ID, in unpadded base64url (Go's `tunnel.GroupPath`, the Rust core's
  `vless::group_path`), so it is the same at each registration with that ID and after a
  restart, unknown to anyone who does not know the ID, and known to the hub before it
  registers its next ID (section 11, "The hub's key"). The registration's answer gives it in
  `path`, and the hub hands it to its clients in the offer. A group's user ID is let in only
  under the path of a registered group; the path every build may carry thus reaches nothing
  but the registrations.
- Every other request gets the site. The web server sees the VLESS user ID and the
  encrypted WireGuard packets and SHOULD keep no log of that path.

Beyond the paths:

- Only the VLESS user IDs of registered hubs that asked for VLESS are let in. A client's
  UDP packets, whatever address the client names, go to the forwarder's own UDP port, from
  a port of the forwarder's own address for each of the client's flows, and are routed
  there as any client's; the answers go back the same way. A TCP stream goes nowhere, but
  to the forwarder's mirror of the releases when it runs with one (`cbb forward
  -vless-mirror 127.0.0.1:443`, the web server that serves `dl.cbb.tools` on the same
  server): whatever address the client names, the stream goes to that one address, so a
  device on a network that blocks the mirror still updates (section 16), and the forwarder
  gives no way to anywhere else. Its TLS runs inside, between the device and the mirror,
  with the mirror's certificate. One VLESS user ID has at most 4 such streams at a time,
  and one is closed after 2 minutes with nothing sent either way.
- A hub that cannot reach the forwarder's TCP port registers over VLESS: a TCP stream to
  port 8764, whatever the address, goes to the forwarder's registrations, which take it
  as one on the TCP port. The hub opens it with the registrations' user ID
  `0cbb0000-7e91-4000-8000-000000008764`, which is no secret and reaches nothing else (no
  mirror, no UDP), and no group may take as its own. The TLS of the registration goes
  inside, with the forwarder's key pinned. Once registered, the hub sends its own packets,
  its hellos and its answers to its clients, over VLESS with the group's user ID: the
  forwarder learns from the hellos that the hub is reached at the port its side of VLESS
  sends them from, and passes the clients' packets to the hub through it. The settings
  for the first time are those an earlier registration gave the hub, or, for the project's
  forwarder, those the signed entry points name (section 16, "Entry points"), else the
  built-in ones: XHTTP on port 443 of `cbb.tools`, the path `/banMEJvnYJJap8S`.
  A registration over VLESS is charged to the client's own address as a direct one is:
  the one the web server in front names (`X-Real-IP`); when that is not known, those registrations share an eighth of
  the setup slots. All the registrations over VLESS, held or being set up, are bounded
  together at 1024 (relay-budget.md, "XHTTP").
  The forwarder knows which group's ID each of those ports serves, and the per-source
  handshake limit and the per-network budget of "Limits" count what comes over VLESS by
  that ID, as one source and one network for each group; a client's own group's limits
  apply as to any client.
- The forwarder keeps no log of VLESS either.

### Limits

Per group: 16 client addresses, 64 handshakes waiting for the hub, 1000 packets and 2 MiB a
second (twice that in a burst); per source address, 10 handshakes a second; 100 000 groups
and 256 registrations being set up at a time. A group that reaches a limit loses only its
own packets. Another forwarder SHOULD bound each group and each source likewise, so that no
group or network can starve the others.

Registrations, held or being set up, are bounded at 16 from one address, 64 from one
network, an IPv4 /24 or an IPv6 /64, 256 from one wide network, an IPv4 /16 or an IPv6
/48, and 1024 from one IPv6 provider, a /32; the forwarder closes a connection past any of them at once. A handshake to a new group
is checked against each registered group, so it costs one check per group. These checks are
bounded at 500 000 a second for all sources together, and one network gets a sixteenth of
that. A single handshake costs a network at most its whole budget, so one still passes now
and then on a forwarder with more groups than that. A handshake from an address that has a
handshake or a session with a group is checked against those groups first, without that
budget. A client over VLESS reaches only the hub of the group that registered its VLESS
user ID: its handshakes are checked against that group alone, also without the budget, and
the forwarder passes its packets to no other group.
The tables of sources and networks hold at most four entries per group; when full, a new
entry replaces the one used least recently (its owner starts again with a full budget), so
forged addresses cannot keep a real client out.

### What it keeps

Its own key file, and a state file (`cbb forward -state`, `forward-state.json` next to the
key by default, `none` for memory only): for each period that registered with a credential,
under HMAC-SHA256 of the period's tag, the version of its newest hubs' credential and
HMAC-SHA256 of the tag and the SHA-256 of the period key, with a counter and the expiry of
the last credential it saw (`expires`, Unix milliseconds; a file without it is read as 35
days from the start, and never more than 35 days from when it was kept). An entry is kept until that expiry, since forgetting it sooner would
let an older credential of the period pass. The table holds at most 100,000 periods, one
network (an IPv4 /24 or an IPv6 /64) at most 256 of those it added, one wide network (an
IPv4 /16 or an IPv6 /48) at most 1024 and one IPv6 provider (a /32) at most 4096; a tag new to the table is refused while any of these
is full and nothing has expired, and no entry is ever dropped to make room. The file is written at most 2 s after a change, and when the forwarder stops,
outside the lock the lookups use. The HMAC key is
HMAC-SHA256 under the forwarder's private key (PKCS #8) of `cbb forwarder
state`, so the file names no group by itself, and a period lasts about a month, so the file
cannot link one month of a group to the next. A registration with a credential is refused
when another period key signed it or its version is below the one kept. At start it deletes the files earlier versions kept, one per group with its roots
and removals (`-records`, `groups` next to the key by default). Groups, addresses and sessions
live in memory while the connections last, and nothing else of a group: whatever a hub
sends in fields the forwarder passes over is not kept; and the forwarder logs none of them; a forwarder SHOULD NOT write any of them to disk
or to a log. With `CBB_DEBUG=1` it logs counts each minute.

## 14. The blind relay

The meeting point, on the user's own server or the project's open relay, for a group that has
no computer to be its hub ([design.md](design.md), "Blind relay"). Implemented in Rust (`member/src/relayd`,
`cbb-relay`, which `cbb relay` starts, and on the devices `member/src/relay.rs`), and on the
phones through the Live member in a group of 0.6. It holds none of the group's keys: it ends each device's WireGuard
tunnel and joins two devices' connections inside the tunnels, and member TLS (section 4)
runs end to end between the two devices.

- The relay listens on one port number, UDP for WireGuard and TCP for registrations. Its
  key file holds an ECDSA P-256 key with a self-signed certificate, which devices pin as a
  forwarder's (section 13), and its WireGuard key.
- It serves only the groups it is started for (`cbb relay -group`, each by its root key and
  the two halves of its recovery key, from which it computes the Group ID), and refuses
  every other; an open relay (`cbb relay -open`) serves every group whose device registers,
  within the limits below.
- A device's service takes a relay only with the user's consent (`consent` on the control
  socket's `away` request, section 8), after `cbb global relay` showed what the relay learns;
  where sync away from home is off, the same request turns it on with new keys.
- A device keeps `relay: {endpoint, key, project}` in its `tunnel.json` (section 11), and
  then is neither a hub nor a hub's client: it ignores a hub's offer.

### The project's relay

The project runs an open relay at `cbb.tools:8765`. `cbb global relay default` sends the
address it looked up and `relay_key` `default`; the service keeps the relay with `project`
`true` and follows its key and address from the signed lists (section 16), so that the relay
can change its key or move without a release and without the user:

- At each start of the link, the device accepts the pins of the keys that the newest
  `keys.json` it holds (with a release or with the entry points) lists with `use` `relay` and
  `name` `cbb.tools:8765`, else the pins built in (`member/src/away/meet.rs`). While the
  key changes both are listed, and either is taken.
- When a registration fails, the device fetches `keys.json` and `entries.json` from the
  mirror `dl.cbb.tools` (HTTPS, its certificate checked by name) at the relay's address on
  TCP 443, the one server its network limit lets it reach, at most every 10 minutes, and
  takes them with the checks of section 16; the group and `cbb update` bring them as well.
  It then tries again at once with the pins of the newest lists, without asking the user.
- When the relay did not answer, the device looks up where it is reached now: the
  `endpoints` that the newest `entries.json` gives the relay named `cbb.tools:8765`, else that
  name, and tries the next address, which it keeps in `tunnel.json` as the relay's
  `endpoint`. Where the system limits the service's network (the systemd unit, the Windows
  Firewall rule), `cbb global allow` lets it reach the new address.
- Status shows a short reason while it fails, the whole error as its detail.

A relay of the user's own is kept as it was given: a new key means `cbb global relay` with the
new key on every device. In a group of 0.6 it is the group's setting instead (the `settings`
record's `servers`, section 10): the root's service, on the `away` request with `name` `relay`
and `consent`, signs a new `settings` record whose relays (kind 2) are the ones given, `relay`
with `relay_key` and then each of `relays` (`address pin`, as `cbb global relay` with several
`address -key KEY` sends them), each address once, keeping the entries of other kinds; for
`relay_key` `default`, which goes alone, one entry for the project's relay, its name
(`cbb.tools:8765`) with the pin of its key the newest keys.json gives (else the one built in),
so that the root's consent is in the group's settings. With `relay` `off` (`cbb global relay
off`, no consent asked) it removes every relay. Its answer names their addresses in `relays`.
A group meets at a relay only when its settings name one: no relay entries mean no relay,
never the project's by default. A member of 0.6 with sync away from home on meets the group at
the first relay the settings name (`member/src/live/relay.rs`), and at the next when one keeps
failing for a minute: it registers under the period's server credentials of that relay's face
(`faces::Faces::for_relay`), waiting until they list its server key, and the relay joins it to
each device of the group it neither reaches at home nor is connected to (through a hub, say),
the device with the lower pseudonym dialing. A call the relay brings comes to a loopback port of
its own, served as a member connection only when the caller's certificate names the device the
relay said calls (`Mesh::accept_checked`). Hubs and a relay serve side by side on 0.6. A device
not on the records of 0.6 refuses `relays`: it meets at one relay. A device that is not the root is refused; an admin's
request to the root has not moved yet (`NotYet`). Every device makes a face for each relay
the settings name (`faces::group_servers`), after the project's servers.

### Registration

A device of 0.6 registers by `cbb-relay/3`, the one protocol the relay speaks. Each message is
one frame of the format (section 4, "Frames"), a map with its type `t` in field 0, its
length on the format's grid; the relay takes at most 64 KiB from the device:

| t | Message | From | Fields |
|---|---|---|---|
| 90 | `relay/challenge` | relay | 2 `e`, the relay's ephemeral X25519 key (32 bytes); 3 `root`, 1 when the device must show its period credential and its root |
| 91 | `relay/register` | device | 2 `key`, its WireGuard key (an X25519 key); 3 `proof` (32 bytes); 4 `credentials`, at most 3 envelopes; 5 `root`, the group's root key (ES256), when asked |
| 92 | `relay/registered` | relay | 2 `key`, the relay's WireGuard key (X25519); 3 `psk`, a new preshared key (32 bytes); 4 `addr`, the device's tunnel address (text) |
| 93 | `relay/error` | relay | 2 `reason`, text of at most 256 bytes |

1. The device connects over TCP and runs TLS 1.3 with ALPN `cbb-relay/3` and no server
   name. It MUST accept only the pinned key. It presents only the certificate of its server
   key for the period (section 18), as a hub to its forwarder (section 13, step 1); the
   certificate names neither a device nor a group. The relay refuses any other ALPN and any
   other chain.
2. The relay sends `relay/challenge`. A relay that serves a fixed list of groups sets `root`;
   an open relay does not, and never sees the period credential or the root.
3. The device answers `relay/register` with a fresh WireGuard key, so the key links no two
   of its registrations, and the proof that it holds it: HMAC-SHA256 keyed with X25519 of
   that key and `e`, over 32 bytes the TLS session exports with the label `cbb relay key`
   (RFC 8446, section 7.5). `credentials` are the period's hubs' and members' credentials,
   and, when `root` was asked, the period credential too, with the root key in field 5.
4. The relay checks them (section 18, "What a server checks"): they hold together, have not
   expired, the members' credential lists the hash of the certificate's key, and on a relay
   with a list the period credential is signed by the root of a listed group. The period's
   tag names the group there (as `period <tag in hex>`, also in the list of refused groups).
5. The relay answers `relay/registered`: its own WireGuard public key, a new preshared key
   for this registration, and the device's tunnel address, which the relay chooses at random
   in fd00:cbb::/32, so no group can take another's address. Or it answers `relay/error`
   and closes: the frame or a message breaks the format, the proof is wrong, the credentials
   do not verify, have expired, do not list the device, are older than the relay saw or come
   from another period key than the one it saw first for the tag, another device registered
   that WireGuard key, the group is refused, or a limit is reached. The whole setup, from
   the TCP connection to the answer, has one deadline of 15 s.
   A device has one registration: a new one replaces the old, whose connection closes.
6. The registration lasts while the connection does; neither side sends anything more on
   it. The relay keeps the device as a WireGuard peer, with its key, the preshared key and
   the tunnel address as its only allowed address, until the connection closes, and then
   drops it at once with all its connections. The device registers again whenever the
   connection breaks, with a backoff of 1 s doubling to 60 s, and at once with the newer
   credentials of a new period.

### Inside the tunnel

The device runs a WireGuard client with the relay as its only peer, at the relay's
tunnel address `fd00:cbb::1`, with a keepalive every 25 s. The relay listens only on TCP
8764 at that address, and knows each connection's device by its tunnel address. Each
connection starts with one frame from the device, a request; the relay answers with
frames of its own, notes, each of at most 64 KiB. A device's **name** there is its
pseudonym, the hash of its server key (32 bytes), which the other members map to its device
through the members' credential and their own records, and the relay to nothing. So the
relay holds no device ID, and a device's name changes with each period.

| t | Request | Fields | Meaning |
|---|---|---|---|
| 94 | `relay/watch` | | keep this connection for the notes; a new watch replaces the old |
| 95 | `relay/dial` | 2 `name` (32 bytes) | join this connection to that device's |
| 96 | `relay/answer` | 2 `ticket` (16 bytes) | answer the call with that ticket |

| t | Note | Fields | Meaning |
|---|---|---|---|
| 97 | `relay/online` | 2 names, sorted, at most 64; absent when there are none | on the watch: the group's other devices on the relay, sent at once and whenever they change |
| 98 | `relay/call` | 2 `name`; 3 `ticket`, 16 random bytes | on the watch: that device dials this one |
| 99 | `relay/ok` | | on a dial and on its answer: the two connections are joined; the member protocol follows on both at once |
| 93 | `relay/error` | 2 `reason` | the request failed; the relay closes the connection |

1. Each device keeps one watch. For each device on the relay with a higher name than
   its own (as byte strings), the device dials it whenever it has no member connection
   to it another way (at home, for example, it has one), with a backoff of 1 s doubling to
   60 s.
2. The relay MUST call the other device only within the dialer's group, and only one that has a
   watch. It waits 10 s for the answer, then sends both connections `relay/ok` and copies the
   bytes between them, unchanged, until either closes, and then closes both. A dial names a
   pseudonym, never an address: the relay dials nowhere.
3. The dialing device runs member TLS as the client for the device that name stands for
   (section 4); the answering one as the server, and it MUST close the connection unless the
   client certificate names the device the call came from. So the relay can join two devices,
   but cannot pose as either.
   On a phone, the relay link joins the answered connection to the app's member listener on the
   loopback address and first tells the app the call's device and the connection's source
   port; the listener serves a connection only when the client certificate names the
   device told for its port, and closes any other.
4. Limits per group: 64 devices, 16 calls waiting for one device, 256 joined connections.
   Limits of the setups, on every relay: 256 registrations being set up at a time, at most 16
   of them from one IP address, 64 from one network (an IPv4 /24 or an IPv6 /64), 128
   from one wide network (an IPv4 /16 or an IPv6 /48) and 128 from one IPv6 provider (a
   /32), each setup also paid for by the second: an address may start 16 a second, a network
   64, a wide network 256 and an IPv6 provider 512, with a burst; and, counted apart, 256
   requests inside the tunnels being read at a time, at most 16 of them from one device, 32
   from one group, 32 from the devices that registered from one IP address, 64 from one
   network, 64 from one wide network and 128 from one IPv6 provider. A connection in a tunnel sends
   its request within 5 s. The relay closes a connection over a limit at once.
   A device, in turn, ends its watch on a note longer than 16 KiB or one that breaks the
   format, and leaves unanswered a call past 16 it is answering at once.
5. An open relay also limits: 4096 groups at a time; 16 registrations from one IP address,
   64 from one network (an IPv4 /24 or an IPv6 /64), 256 from one wide network (an IPv4
   /16 or an IPv6 /48) and 1024 from one IPv6 provider (a /32); and 1 MiB a second of copying for each group, both ways together,
   after a burst of two seconds' worth. A registration over a limit gets `relay/error`. It
   forgets a group's period (its key, versions and members' list) once the group's last
   device leaves. A registration it refuses leaves it as it was: the devices registered
   before stay, and it keeps nothing of the refused device's group or period. A newer members'
   credential counts the devices it leaves out as gone when the relay checks its limits.

### What it keeps

Only its key file. Registrations and connections live in memory while they last; the relay
logs none of them (a relay SHOULD NOT), and with `CBB_DEBUG=1` it logs counts each minute. It learns which
devices of a group are on it, which of them connect to each other, when and how much,
which a hub would not let out; what the devices send each other it cannot read. It learns
them only by pseudonym, under the period's tag, both new each period; a relay with a list
also sees the group's root key and period credential. It never sees a device ID, a record
or a member certificate.

## 15. Commands

An admin orders one member to do something with a **command**: signed like a record (section
10) and never stored. `mode` turns the receiver's sync on (`shared`) or off (`own`; design.md, "Sync on and off"); `hub`
makes the receiver the group's hub, or a hub of the group as well, or with a stop order makes
the receiver stop being one (section 11, "Moving the hub", "Several hubs", "Stopping a hub"); `paste` puts a text where
the receiver's focus is, and `paste-off` turns remote paste off on the receiver (design.md,
"Remote paste"); `action` runs one of the receiver's quick actions, and `actions-off` turns
them all off there (design.md, "Quick actions"); `away-off` turns sync away from home off on
the receiver (section 11), which only its own user turns on again (D-45); `mute` keeps the
receiver's copies from the group for a while or until `unmute` ends it (design.md, "Muting a
device").

On the records of 0.6 a computer sends and carries out `mode`, `paste`, `paste-off`, `action`,
`actions-off`, `away-off`, `mute` and `unmute` as commands of [format](format.md) section 6
(`member/src/service/on_live/orders.rs`), signed by its root or admin key; the receiver's
checks of its user's switches are the same as above. Its `result` says `refused` (2) when the
receiver's user or settings say no, such as remote paste being off, and `failed` (3) when
carrying the command out went wrong. A small device's own command (`device`, type 10: a
name and its arguments) is refused with "this device has no command NAME", since no computer
or Pi defines commands of its own; the leaves that do, and a way to send one, come with 0.7; `away-off` turns sync away from home off on the receiver, which only
its own user turns on again; `hub` makes the receiver a hub or stops it being one (below).

A `hub` command of 0.6 orders field 10 (the hub: its address away from home and the hash of
its member key, the format's 32-byte reference to a signer, so that every reader knows which
device the hub is), 11 (the
forwarders, 1 to 8, each `[address, pin]`, an address once: the pin of the forwarder's key, 32
bytes, comes signed by the root with its address, so the hub takes no forwarder's key on first
use) or 13 (stop being a hub, alone). Field 12, the clients with their keys and
pre-shared keys, is retired and refused (`orders/hub`), and its number is not used again: a
client gives each hub its key in message `tunnel` (t 15), and the pre-shared key is never sent,
since both ends export it from their own connection (`core/src/hubkey.rs`).
The receiver, a computer the records make a hub with sync away from home on, refuses a command
whose field 10 names another device's key, and otherwise becomes a hub at that address with
the first forwarder of field 11, as `cbb global hub` makes it one (`cbb global hub -on DEVICE`
sends it, with one address on 0.6); with field 13 it stops being a hub (`cbb global hub off -on
DEVICE`). `cbb global move DEVICE` sends the new hub its command, by default with this hub's
forwarder, and once it is done stops this hub. A hub that stops sends each client connected an
offer with `moved` and the tag of that connection's key; the client forgets the hub, ends a
connection through its tunnel and takes the next hub in the order.

### The command

It has the form of a record, `{body, sig, chain?}`. Its body is JSON, in the strict form of
signed bodies (Conventions):

| Field | Type | Meaning |
|-------|------|---------|
| `v` | integer | `1`, or `2` for a sealed command (below) |
| `type` | string | `mode`, `hub`, `paste`, `paste-off`, `action`, `actions-off`, `away-off`, `mute` or `unmute` |
| `group` | string | the group tag |
| `by` | string | the signer's device ID (32 of `0`-`9` and `a`-`f`): a receiver refuses a command whose `by` is no device ID, or, when its records show which device holds the signing key (the root's own device for the root's key, the device whose record names the admin CA), names another device, or, when they show none, names a device they show |
| `to` | string | the receiver's device ID (32 of `0`-`9` and `a`-`f`) |
| `id` | string | 128 random bits as 32 lowercase hex characters; IDs compare as byte strings |
| `time_ms` | integer | when it was signed, milliseconds since the Unix epoch, not negative |
| `expires_ms` | integer | after `time_ms`, at most 30 000 ms later: from `time_ms` + 1 to `time_ms` + 30 000 |
| `mode` | string | in a `mode` command: `shared` (sync on) or `own` (sync off); in a `paste` command: `paste` (the clipboard and the paste keys) or `type` (key by key) |
| `enter` | bool | in a `paste` command: press Enter after the text |
| `kind` | string | in a `paste` command: `text`, `secret` or `media` (the group's copy of images or files that `text` names, below) |
| `text` | string | in a `paste` command: the text, not empty, at most 1 MiB of UTF-8 for `paste` and 4 KiB for `type`; in one of kind `media`, the event ID of the copy (32 of `0`-`9` and `a`-`f`), with `mode` `paste` |
| `action` | string | in an `action` command: the action's name, 1 to 32 of `a`-`z`, `0`-`9` and `-`, starting with a letter; in no other command |
| `hub` | object | in a `hub` command: `forwarder` (`endpoint`, `key`) or absent, `endpoints` (at most 8 with the forwarder's) or absent, at least one of the two, and `clients`, at most 256 of `{device, key, psk}` (base64, 32 bytes each, no device twice); or `{"stop":true}` with none of the others, which makes the receiver stop being a hub |
| `for_ms` | integer | in a `mute` command: how long the mute lasts, from 1 to 2 592 000 000 (30 days) on the receiver's clock from when it takes the command; absent or 0 for until an `unmute` command or the receiver's user ends it |
| `sealed` | string | in a command of `v` `2` only: the orders, sealed to the receiver (below), base64 |

The exact rule, after the strict form: each field of this table has its JSON type in every
command. A command is refused without `mode` in `mode` and `paste`, `hub` in `hub`, `kind`
and `text` in `paste`, and `action` in `action`. In a command of another type these fields
are absent or empty: `mode`, `kind`, `text` and `action` `""`, `enter` `false`, `for_ms` `0`,
and `hub` absent, since even `{}` is an order. `mode` in a `mode` command is any string that is not
empty here; the receiver answers a mode it does not know with an error. `paste`'s `mode`
and `kind` are exactly the values above, and one of kind `media` has `mode` `paste` and an event ID as its `text`. The 1 MiB and 4 KiB of `text` count the bytes of
UTF-8 once its escapes are read. In `hub`, `forwarder` has `endpoint` and `key`, strings
that are not empty; `endpoints` holds at most 8 strings (the forwarder does not count among
them) and, without a forwarder, one at least; each of `clients` has `device`, a device ID,
and `key` and `psk`, 32 bytes each in base64. A body is at most 64 KiB, or 2 MiB for
`paste` (`size/commands`), checked before anything else. The vectors cite a row as
`commands/<type>/<field>`.

`sig` is ECDSA P-256 with SHA-256 over the body's exact bytes, by a root's own key (no `chain`)
or by an admin CA's key (`chain` holds that admin CA, DER), as for records.

A receiver's limits per sender (remote paste, quick actions) and its logs count a command for
its `by` when the records show that this device holds the signing key, and otherwise for the
signing key itself, with the log entry marked `unverified`: `by` is then only the signer's word.

### In the member protocol

```
{"t":"command","command":{"body":"...","sig":"...","chain":["..."]}}
{"t":"result","result":{"id":"...","by":"...","status":"done"}}
```

The sender sends the command on its own connection to the receiver, which answers with a
`result`: its `id` is the command's, its `status` `done`, `refused` (the receiver does not take
it) or `failed` (it took it and could not carry it out), and `reason` says why for the last
two. The reason is a peer's text: a member that shows it, or passes it to a program, first
turns each control character (C0, DEL, C1) into a space and cuts it to 256 bytes at a
character boundary. A `hub` command's `done` carries `tunnel`, the new hub's offer. A member without
commands ignores the message, so the sender gives up after 10 s (20 s for `hub`). A member
carries out at most 4 commands of one connection at once and takes at most 32 from it in
10 s; it answers the others `refused` at once, without reading them.

Each computer and small device keeps a secret for sealed messages in `seal.json` next to its
identity (sealed by the TPM where a computer has one, as the WireGuard key) and offers its public key in its hello
(`seal`, section 4) and in its pairing info (ADa, section 5); a root computer records it in
the device's record, as it records a changed system, a member that admits it records it at
once, and the phones keep it when they sign the record again. A command for it is sealed
(below, "Sealed commands").

A sender that has no connection to the receiver sends a `mode`, `paste`, `paste-off`,
`action`, `actions-off`, `away-off`, `mute` or `unmute` command to the group's hubs it is connected to (the
root and the admins, "Several hubs" in section 11), and to no other member: a command's body,
a paste's text among it, is signed but encrypted only when sealed (below), and the hubs are
the devices the user gave admin powers. A `hub` command only goes directly. A member
that gets a command whose `to` is another device passes it on, unchanged, only when it is
connected to that device and has not passed that `id` before (it keeps the IDs until the
command expires, at most 4096), and passes the receiver's `result` back to the member it
came from, once; a member not connected to `to` drops it. The receiver names itself in the
result's `by`, so that a sender takes a result from a member in between only when `by` is
the receiver: `cbb` refuses a command for another device
for itself instead of passing it on. The signature, not the
connection, says who sent a command, so the member in between can neither forge nor change
it; it could withhold a command or forge a `result`, as any member could drop messages.

The receiver MUST take a command only when:

- its body decodes, with a known `type` and a lifetime of at most 30 s;
- `group` is its group and `to` its own device ID;
- the signature verifies under a root on the path of the group's records, and the signer is
  that root or an admin CA under it that is neither revoked nor frozen; a watch's admin CA
  (section 10, "Watches") signs only `paste-off`, `actions-off`, `away-off` and `action`;
- `expires_ms` is after its clock and `time_ms` at most 60 s ahead of it;
- its `id` is not in its replay cache, which keeps the IDs of the commands it carried out
  until they expire (at most 4096 at a time);
- `time_ms` is not before the time the receiver started. The replay cache lives in memory
  and starts empty, so a command carried out before a restart would otherwise be taken
  again; a refused one is sent again with a new `id`.

A body is at most 64 KiB, a `paste` command's 2 MiB (the sender writes the text without
JSON's escapes of `<`, `>` and `&`). A `mode` command with an unknown mode is refused. One that is taken sets the mode, saves it
and logs who sent it. Every member takes `mode` commands; only a computer takes `hub`, and the
phones and `cbb` refuse it.

A `paste` command MUST be refused unless the receiver's user turned remote paste on there,
and, with `enter`, allowed Enter; and beyond one a second and 30 a minute from one sender
(the limits per sender, above). The switches MUST be set only on the device itself, never by a command. The receiver MUST
clean the text (newlines and tabs stay; other control characters, terminal escape
sequences and bytes that are not UTF-8 go; CR LF and CR become LF), hands it to a target
(the watcher protocol's `inject`, section 8: a desktop session first, then tmux, then a text
console only where the user allowed consoles). A line break may run what comes before it
wherever the focused program does not take a paste bracketed, which no target can tell (a
shell or console window on a desktop may not ask for it), so unless the user allowed Enter,
the receiver MUST refuse a text with a line break on each of these targets, and when it
types the text on a Bluetooth keyboard or a TV. An Android phone that puts it into the
focused text field through its accessibility service takes it: a line break there is a
character of the field. The receiver answers `done` when the target put it
in, `refused` with its reason (for example a locked session) or `failed`. It keeps the last
100 pastes in a log (sender, time, length, way, result, never the text), but no `secret`
one.

A `paste` command of kind `media` pastes images or files: its sender first makes a copy of
them in the group as any copy ([format](format.md), section 10.3), then signs the command with that copy's
event ID as its `text`. The receiver waits up to 20 s for that copy to be its group's current
copy, and refuses it unless it reads the copy, the copy is a `media` copy, and the copy has a
wrap for the signer's device (`by`), so that a paste never puts in a copy its sender could not
read. It fetches the copy's blob within its limits (section 4, "Content"), then hands the
paste to a desktop watcher whose clipboard takes the copy whole (the watcher protocol's
`inject` of kind `media`, section 8), which writes it into the clipboard (an image, formatted
text, or the files as a file manager copies them) and presses the paste keys, and Enter when
`enter` is set. The clipboard keeps the copy, which is the group's anyway. tmux, a text
console, a Bluetooth keyboard and a TV take only text, so a receiver with only those refuses
it. The receiver answers within the command's lifetime, after which the members in between no
longer pass the result back; the sender waits 33 s for it. A `paste-off` command turns remote paste off, Enter and consoles too; only the
device's own user turns it on again.

An `action` command carries only the action's name: what it does is defined on the receiver,
which knows the presets `lock` (lock the screen), `sleep`, `reboot` and `shutdown` (both a
minute after the command, so that `cancel-shutdown` can stop them), `cancel-shutdown` and
`restart` (the service ends and its service manager starts it again, after the result is
sent), `keyboard-layout` (the computer's Bluetooth keyboard types in the next of its layouts,
`us` then `ru`; refused where it is off or there is none), and the actions its user added there, each a program with fixed arguments that the
agent of the user signed in runs; nothing in the command reaches its arguments, and only
the exit status comes back. The receiver MUST refuse it unless its user turned that action
on there, and then:

- unless the signer is of a kind the user allowed for it, when the user named kinds: `root`
  (the root's own key signed it), `phone`, `computer` or `watch` (the role of the signer's
  device, the device record whose `admin` is the signer's admin CA, or the root's own device;
  only a record a known root's own key signed says either: section 10, the devices list);
- for `reboot` and `shutdown`, unless that device's record says its keys are in hardware
  (`store` `hardware` or `proven`), or the user allowed keys in files for that action;
- beyond one a second and 30 a minute from one sender (the limits per sender, above).

It answers `done` when the system took the action (a reboot that is scheduled counts),
`refused` with the reason (the action is off, the signer is not allowed, the system refused
it) or `failed`, and keeps the last 100 actions in a log (sender, time, action, result). An
`actions-off` command turns every action off on the receiver, keeping who may run each; only
the device's own user turns them on again.

An `away-off` command turns sync away from home off on the receiver as its user's own
`off` does (section 11, the control operation `away`): its tunnel keys go, and once the
result is sent it tells the members connected in a new hello (section 4,
"Hello"). It answers `done` also when sync away from home was
off already.

A `mute` command mutes the receiver until `for_ms` from when it takes the command, or until
an admin lifts it; the commands of several admins simply follow each other, the last one
taken counts. It makes no events, not even
from a deliberate copy (which it refuses), and takes the group's copies as before; its sync
mode stays as its user set it. It saves the mute, so that it lasts across restarts, answers
`done`, and tells the members connected in a new hello, so that they show it
(section 4, "Hello") without the connection ending. An `unmute` command ends it the same way; the device's own
user ends it only where the device is itself an admin or the root (section 8, `unmute`), and
a mute that ends by its time ends without a message. Every member takes both: computers,
small devices and the phones. A device that does not take the command (an older one, or one
that is broken) is removed instead; each device's user may also pause receiving there
(section 8, `mute`).

### Sealed commands

A sender seals a command's orders to its receiver when the receiver's device record has a
`seal` key, so that the members in between see only the header:

- The **orders** are the fields `mode`, `hub`, `enter`, `kind`, `text`, `action` and `for_ms`, as a JSON
  object in the strict form of signed bodies, with only those of them the command has.
- The **associated data** is the header: the context `cbb command v2`, then
  `type`, `group`, `by`, `to` and `id`, each of these six strings as its length in 4 bytes and
  its bytes, then `time_ms` and `expires_ms`, 8 bytes each; every number big-endian.
- `sealed` is the orders sealed to the `seal` key with that associated data: X-Wing HPKE,
  the encapsulated key (1120 bytes) and then the ciphertext with its tag (`internal/seal`).
- The body is the header with `v` `2` and `sealed`, and none of the orders; the signature
  covers it as any command's.

A receiver refuses a body of `v` `2` without `sealed`, with any of the orders beside it, or
with an unknown `type`, and one of `v` `1` with `sealed`; `sealed` is base64 in its standard
form. It checks the signature and the header as for any command, then opens `sealed` with
its own secret and the header as associated data, and refuses the command when it does not
open, when the orders are not in the strict form, or when they fail the checks of the table
for the command's `type`. Its orders then count as those of a command in the open. Sealed
orders open only under the header they were sealed with, so no other signer can send them
again under an `id` or a time of its own. The limits of a body (64 KiB, 2 MiB for `paste`)
hold for the body as sent and for the orders once opened. The members in between pass a
sealed command on as any other. Every sender seals to a receiver whose record has a `seal`
key: computers, small devices and both phone apps (the kits through the core's
`seal_command`), and every one of them has a key of its own, which it opens the commands for
it with (the phones through their member in the core). So a receiver whose own record has one refuses a `paste` command in the
open, whose text was read on its way; it takes the other types in the open, as a watch signs
them (a watch checks what it signs and cannot read sealed orders). A receiver without a key
in its record takes commands in the open, and a member without a key of its own refuses a
sealed one. The vectors are `go-sealed-commands.json`.

## 16. Signed releases

Every release is described by signed files, so that a program updates only to a release the
project signed, whichever server it came from (design.md, "Secure updates"; D-69). The Go
package `internal/release` and `core/` (`release.rs`) check them alike, against
`testdata/interop/go-release.json` (whose cases name their files by their index in its
`files`); the phone kits ask the core (`release_check`, core-api.md, "Release files").

### Keys

Every key below has two halves, which sign every file it signs together (see "Two
signatures"): a P-256 key and an SLH-DSA-SHA2-128s key (FIPS 205), whose signatures hold
when a quantum computer breaks P-256. Where the P-256 half lives in hardware (a YubiKey, the
Mac's Secure Enclave), the SLH-DSA half, which no such hardware holds, is a file encrypted to
that same hardware (with `age` and its plugin for the YubiKey or the Secure Enclave) and opened
only to sign; on a server, an encrypted credential of the service that signs
(maintaining.md, "Two signatures").

- Two **root keys**, each on its own hardware key kept offline. Every program pins both,
  each by its two halves' SubjectPublicKeyInfos under its name (`internal/release/roots/roots.pem`,
  a `Name` header on each half); either one signs `keys.json`.
- **Release keys**, P-256, which `keys.json` certifies. A release key signs `release.json`
  and the channel files.
- A **status key**, P-256, which `keys.json` certifies with `use` `status`. It lives on the
  mirror of Google's revocation list and signs only `attest-status.json` (section 17,
  "Revoked attestations"), never a release.
- A **channel key**, P-256, which `keys.json` certifies with `use` `channel`. It lives on
  cbb.tools and signs only channel files, to renew them every week with the release they
  already name; it signs no `release.json`, so whoever takes it can at most hold a channel
  on a release the project signed, which a device that has seen a newer version refuses.
- **The project's forwarder's keys**, P-256, which `keys.json` lists with `use` `forwarder`
  and the forwarder's address as `name` (`cbb.tools:8764`). They sign nothing: a hub takes
  their pins (SHA-256 of each SubjectPublicKeyInfo, as `cbb forward` prints its key) as the
  ones it accepts from that forwarder, in place of the pins built into the program, when the
  newest `keys.json` it holds, with a release or with the entry points, lists any (section
  13, "The project's forwarder"). A new key is listed beside the old one before the
  forwarder changes to it, and the old one is dropped after.
- **The project's relay's keys**, P-256, the same with `use` `relay` and the relay's address
  as `name` (`cbb.tools:8765`); a device on the project's relay takes their pins (section 14,
  "The project's relay").
- **The project's push service's keys**, P-256, the same with `use` `push` and the service's
  address as `name` (`cbb.tools:8767`): no pin is built in, so a group shows the service a
  face, and its members send to it, only once a `keys.json` they hold lists one
  (`release-sign -push`; [design.md](design.md), "Push").

### The envelope

Each file is JSON: `{"body": "...", "sigs": [{"alg": n, "key": "...", "sig": "..."}, ...]}`.
`body` is the body's exact bytes (base64), signed as they are and never re-encoded. Each of
`sigs` (1 to 8) is one signature over them: `alg` names its algorithm, `key` is SHA-256 of the
signing half's SubjectPublicKeyInfo (base64, 32 bytes), which picks the half to verify with,
and `sig` the signature (base64): for `alg` `1`, ES256, ECDSA P-256 with SHA-256, DER; for
`alg` `4`, SLH-DSA-SHA2-128s, pure, with the context `cbb release v1`, 7856 bytes. A body is
at most 256 KiB and a whole file at most 1 MiB. Every body has `v`
(`1`) and `type`, so one kind of file is never taken for another; unknown fields are ignored.
A body follows the strict form of signed bodies (Conventions), checked before its fields, and
has every field of its row: only `min_from`, `docker`, `binaries`, `use` and `source_ms` may
be left out, and `use` is never empty. Every key is a P-256 SubjectPublicKeyInfo with an
uncompressed point, and every name, version, channel, serial number and hash matches its rule
whole (a line break after it is refused). `get.sh` and `get.ps1` refuse a body they cannot
read as the programs do: a member name that is not 1 to 64 of `a`-`z`, `0`-`9` and `_`, a
`null`, a backslash, or a field they read written twice. `seq` is from 1 to 2^63-1. `cbb` reads no `attest-status.json`; the
vectors in `testdata/interop/strict-files.json` (section `releases`) test each row.

| `type` | Signed by | Fields |
|--------|-----------|--------|
| `keys` (`keys.json`) | a root key | `seq` (from 1, raised with each new file), `time_ms`, `expires_ms`, `keys`: 1 to 64 of `{alg` (from 1: `1` a P-256 half, `4` an SLH-DSA-SHA2-128s half), `key` (SubjectPublicKeyInfo, DER, base64), `name` (1-64 bytes), `use` (`release` when absent, `status`, `channel`, `forwarder`, `relay` or `push`)`}`, the two halves of one key under the same `name` and `use` |
| `release` (`release.json`) | a release key | `version`, `channel`, `time_ms`, `min_from` (a version, optional), `files`: 1 to 256 of `{name, size, sha256, binaries?}`, `docker` (optional `{image, digest}`) |
| `channel` (`stable.json`, ...) | a release key or a channel key | `channel`, `seq` (from 1), `time_ms`, `expires_ms`, `release` (the version), `release_sha256` (SHA-256 of that `release.json`'s body, hex) |
| `entries` (`entries.json`) | a release key or a channel key | `seq` (from 1), `time_ms`, `expires_ms`, `forwarders`: at most 16 of `{name` (the forwarder, `host:port`, each once), `vless`: at most 8 of `{transport` (`xhttp`), `server_name` (a site's name), `port` (1 to 65535), `path` (`/` and 8 to 64 of `A-Z a-z 0-9 - _`)`}}`, `relays` (optional): at most 16 of `{name` (the relay, `host:port`, each once), `endpoints` (optional): at most 8 `host:port` where it is reached now`}` |
| `zxnext` (`zxnext.json`) | a release key | `version`, `time_ms`, `files`: the ZX Spectrum Next's four, `CBB`, `CBB.OVL`, `CBB.DRV` and `cbb`, each once as `{name, size` (1 to 64 MiB)`, crc32` (8 lowercase hex digits)`, sha256}` |
| `attest-status` (`attest-status.json`) | a status key | `seq` (from 1), `time_ms`, `expires_ms`, `source_ms` (when Google last changed its list, optional), `android_revoked`: the serial numbers |

- A key of a `use` the reader does not know is in `keys.json` for newer programs and signs
  nothing for it, and so is a half of an `alg` it does not know, whatever its length; a release key signs no `attest-status.json`, a status key no release
  or channel file, a channel key nothing but channel files, and a forwarder or relay key
  nothing.

- A version is `X.Y.Z` or, for a release candidate, `X.Y.Z-rc.N`: decimal numbers of at
  most 6 digits without leading zeros (`N` from 1), compared number by number, a release
  candidate before its release; tags add the `v`.
- A channel name is 1-32 of `a-z`, `0-9` and `-`, starting with a letter.
- A file `name` is 1-128 of `A-Z a-z 0-9 . _ -`, not starting with `.` or `-`, each name
  once. `size` is its length in bytes and `sha256` its hash in lowercase hex. `binaries`, at
  most 64, are the programs inside an archive: `name`, the path inside it (`/` allowed, no
  `..`), and `sha256`.
- `docker.digest` is `sha256:` and 64 hex digits.
- A `keys`, `channel` or `entries` file lives at most 100 days (`expires_ms` after `time_ms`, by at
  most 8 640 000 000 ms), and its `time_ms` is not negative. `keys.json` is signed again every 90 days, and a channel file
  before it expires. `attest-status.json` lives at most 8 days (691 200 000 ms) and is
  signed again at least a day before it expires.
- A serial number is lowercase hex without leading zeros (`0` for zero), at most 64
  digits, as Google's list names them. `android_revoked` lists each once, shorter numbers
  first and numbers of one length in string order, which is numeric order.

### Two signatures

A reader takes a file only when the halves of one key, one `name` and `use` of the keys it
checks the file under (the pinned roots for `keys.json`), signed it with every algorithm the
reader requires: `1` and `4`, fixed in every program from 0.6, with no switch to turn either
off. A signature of an algorithm the reader does not know, or by a half it does not list, is
passed over, whatever its length; a signature of a known algorithm by a listed half that does
not verify refuses the file. So a later version can add an algorithm beside these two, and
MUST keep signing with both while readers of 0.6 are in use. 0.5 reads no release files, so
the envelope of `sig` and `key` that it never took is gone.

Every reader reads a file alike, in one strict form beside the body's own:

- The file is the envelope in the canonical form of signed bodies (Conventions,
  `form/canonical`), with whitespace (space, tab, line feed, carriage return) before and after
  it passed over: one object whose members are exactly `body` and `sigs`, in that order, with
  no whitespace inside, no escape, no `null`; nothing else before or after it, not even a byte
  order mark. `body` is base64 in its one form (standard alphabet, padded, no line break, no
  stray bits).
- `sigs` holds 1 to 8 objects, each with exactly `alg`, `key` and `sig`, in that order: `alg`
  an integer from 1 to 2^31 − 1 without leading zeros, `key` and `sig` base64 in its one form.
  Any other shape refuses the file, whatever its algorithm; a member of another name refuses
  it too, so a later version extends the envelope only by an algorithm, never by a member. An
  entry of that shape and an algorithm the reader does not know is passed over, and so is a
  signature longer than 16 KiB.
- A key in `keys.json` names an `alg` from 1 to 2^31 − 1. A key that signs (every use but
  `forwarder` and `relay`) is its halves under one `name` and `use`, one of each algorithm:
  two halves of one algorithm under one name and use refuse the `keys.json`, so the halves of
  two keys never count as one. A release key's `use` left out and written `"release"` are one
  use. `roots.pem` holds one half of each algorithm under each `Name`.
- An ES256 signature is DER with its S in the lower half of the curve's order; the other S,
  which verifies as well, is refused, so that each signature has one form.

A root is replaced only by a release. The programs pin the roots in their code (`roots.pem`,
read by Go and the Rust core when they are built), so no file can add a root to a device
that is running. The release that ships a new root, beside the root that stays, reaches a
0.6 device like any other release: in a `keys.json` that the remaining pinned root signed
with both of its halves. Only the program installed from that release trusts the new root.
Until then the new root signs nothing that a device takes, and neither does a lost root once
a release has dropped it. The vectors cover both cases: "a release key rotated by the second
root" (the remaining root signs alone) and "keys.json signed by a key that is not a root" (a
root that no release pins yet), with "keys.json signed by two roots, one half each" refused.
A device therefore needs one of its pinned roots, with both halves, through every release
until the new root reaches it. The two roots sit on separate YubiKeys for this reason.

`get.sh` checks the ES256 signatures always and the SLH-DSA ones where its `openssl` does
(OpenSSL 3.5 and later, tried with a key of its own first), and says which it checked;
`get.ps1` checks the ES256 ones and says that PowerShell cannot check SLH-DSA. Both pass over
a signature they do not check, and the program they install checks both from then on. Both
read the envelope by the rules above, as the programs do: they take and refuse the same
shapes of the envelope, including the other S of an ES256 signature, another DER form of
it and a ninth signature, and check every key of `keys.json`, whatever its use; what they
cannot check, they cannot refuse, so a file without its SLH-DSA signature is taken where
that signature is not checked. CI gives both every envelope of the interop vectors.

### Where the files are

A release on GitHub cannot take new files once published, while `keys.json` and the
channel files are signed again during its life. So `release.json` is a file of its release
(`releases/download/vX.Y.Z/release.json`), and the current `keys.json` and `stable.json` are
in the repository's branch `channel`, read at
`https://raw.githubusercontent.com/HunterEwok/cbb/channel/<file>`. A mirror
keeps all three at its top and each release's files under `vX.Y.Z/`. A device fetches
`keys.json` and the channel file, then the `release.json` of the version the channel file
names, and that version's files; `get.sh` and `get.ps1` install the release `stable.json`
names, not GitHub's latest, which differ for a few minutes after a release.

A release with the ZX Spectrum Next's files also carries `zxnext.json`, and a mirror keeps
it under `vX.Y.Z/`; cbb.tools serves it over plain HTTP as `zxnext/SIGNED`, the current
`keys.json` and the newest such release's `zxnext.json`, a line each. `.cbb update` hands
that to the Pi's `cbb` (`cbb next check-list`), which checks both as in steps 1 and 3 below
(the `keys.json` without a stored `seq`, the `zxnext.json` under a release key of it, its
version not below the Pi's own) and writes the four files' names, sizes, CRC-32s and
SHA-256s; the Next takes a newer `CBB` and its files only from those lines.

`cbb update` tries GitHub, then the mirror. When this device syncs away from home through a
hub that uses VLESS (section 11), it reaches the default mirror only inside VLESS, through
the hub's forwarder (section 13), since a network that blocks WireGuard blocks the mirror
as well; a mirror set by hand (`cbb update -mirror`) is reached directly. When neither
answers, it asks its service for the release the group passed to it (control operation
`release_held`, below), and the archive comes from the members as below; the files are
checked the same way, wherever they came from.

### The check

A device that looks for an update fetches `keys.json`, the channel file of its channel and
the `release.json` that names, and MUST take the release only when:

1. `keys.json` verifies under a pinned root key (both of its halves, as "Two signatures"), decodes as a `keys` body, has not expired,
   is not signed more than a day ahead of the device's clock (`time_ms`), and its `seq` is
   not below the highest the device has taken;
2. the channel file verifies under a release or channel key of that `keys.json`, decodes as a `channel`
   body for the device's channel, has not expired, is not signed more than a day ahead of
   the device's clock, and its `seq` is not below the highest taken under the same or an
   older `keys.json`: a `keys.json` with a higher `seq` than the one the device took its
   highest channel file under lets the channel's `seq` start again;
3. `release.json` verifies under a release key of that `keys.json`, the SHA-256 of its body
   is `release_sha256`, its `version` and `channel` are the channel file's, and its version is
   not below the highest the device has taken.

A channel file's `seq` MUST also be at most 65 536 above the highest taken, or at most
65 536 when none counts (a fresh device, or one under a newer `keys.json`), so that one file
signed with a far `seq` cannot hold a device above every file signed after it. A device whose clock reads before 2026 skips the checks of `time_ms`, as its
clock is unset. `attest-status.json` (section 17) is checked the same way as a channel file,
under its `keys.json`.

The device then MUST keep the highest `keys` and channel `seq` and version it has taken, and
the `keys` `seq` under which it took its channel file, so that nobody can give it older files
later. A file it downloads MUST have the size and
SHA-256 that `release.json` lists, and a program inside an archive the SHA-256 that its
`binaries` entry lists, before the device installs it. A device below `min_from` updates to `min_from` first.
A release key that is lost or stolen is dropped from the next `keys.json`; a device that has
taken it no longer accepts anything that key signs.

### In the group

Members pass the newest signed release they hold to each other, so that a device learns of a
release when any device of its group has checked, and one without internet access learns of
it too (D-69). The signatures make the peers untrusted: a member checks what a peer sends as
it checks what it downloads.

- A member's hello carries `release_seq` and `release_keys_seq`, the channel and `keys.json`
  `seq` of the release it holds. After a peer's hello, a member that holds a newer release
  sends it (one whose `keys.json` has a higher `seq`, or the same `keys.json` and a channel
  file with a higher `seq`), when the peer is
  a `member` (phones update from their stores), a `release` message: `{"t":"release","release":{"keys":...,"channel":...,"release":...}}`.
- A member MUST take a `release` only when its three files pass the check above for the `stable`
  channel, with the `keys` and channel `seq` of the release it holds, and it is newer in the
  same order. It keeps the files (`release.json` in the service's state directory) and
  sends them on to its other peers; it drops one that fails, and logs why. A held release
  whose channel file has expired is not sent.
- `cbb update` hands the files it fetched and checked to the service on this computer
  (control operation `release`), which takes them the same way and sends them to its peers.
- `cbb status` and the tray app say when the newest release is above this computer's
  version, and the devices list marks the devices that run an older one. Taking a release
  only informs: a device installs one only through its own update (`cbb update`, its timer,
  the app store), which checks the files again.
- The archives pass through the group as images and files do ("Content", section 4): a
  member serves, by its SHA-256, a file of the release it holds once it holds it whole, and
  `get` asks for it like a part. `cbb update` hands the archive it installed to the service
  (control operation `release_file`), which keeps it (`release-files/` in its state
  directory, named by the SHA-256) only when the held `release.json` lists it with that size
  and hash. Before downloading, `cbb update` asks its service (`release_get`), which fetches
  the archive from its peers that send `media`, and downloads it from the server only when
  no peer has it; it checks the archive against `release.json` either way. A member deletes
  the archives of a release once it holds a newer one, and serves them through the group's
  tunnel too.
- A hub fetches the archives its group's members install, so that a device on a network that
  blocks the update servers, as one that syncs over AmneziaWG may be on, gets them through
  the group and its tunnel. Its `cbb update` (the daily timer, or by hand) asks its service
  (control operation `release_want`) for the archives of the held release that the
  members seen since its service started name in their hellos, `device` `archive` (section 4;
  on the records of 0.6 field 5 of the hello's `device` map, the table `hello/device` in
  `core/src/msg/member.rs`), and it does not hold whole, at most 16, downloads each from the
  server it checked the release from, checks it against `release.json` and hands it over as
  with `release_file`.
- A member that does not know `release` ignores it, as it ignores every message of a type it does not know.

### Entry points

The project's servers can be reached in more ways than the addresses built into the
programs, and those ways change when a network starts to block one. So the project signs
their list, `entries.json`, with a release key or the channel key, beside `keys.json` in the
branch `channel` and at the top of every mirror (`https://cbb.tools/channel/entries.json`,
renewed with the channel file); a device trusts the signature, wherever the list came from.
It lists, for each forwarder of the project, its ways in over VLESS (section 13, "VLESS"),
through which a hub registers (section 13, "The project's forwarder"); and for each relay of
the project, where it is reached now (section 14, "The project's relay").

- A device MUST take a list only when its `keys.json` passes step 1 of the check above, and
  `entries.json` verifies under a release or channel key of that `keys.json`, decodes as an
  `entries` body, has not expired, is not signed more than a day ahead of the device's clock,
  and its `seq` is not below the highest it took under the same or an older `keys.json`, nor
  more than 65 536 above it; the floors are kept apart from the release's. It keeps the
  newest that checks out (`entries.json` in the service's state directory, `{keys,
  entries}`), and stops using it once it expires.
- `cbb update` fetches `entries.json` from the server whose release it checked and hands it,
  with that `keys.json`, to its service (control operation `entries`).
- Members pass it on as they pass the release ("In the group"): a hello carries
  `entries_seq` and `entries_keys_seq`, and after a peer's hello a member that holds a newer
  list (a `keys.json` with a higher `seq`, or the same one and a higher `entries` `seq`)
  sends it to the peer in an `entries` message:
  `{"t":"entries","entries":{"keys":...,"entries":...}}`. A member takes it with the check
  above, keeps it and sends it on to its other peers; it drops one that fails, and logs why.
  Each file in it is read, kept and sent on as the bytes that came, in the one envelope every
  reader takes ("Two signatures"), never decoded and written again; the same holds for the
  `release` message ("In the group") and for the string of `cbb global entries`.
  A phone takes it the same way and keeps it in its own files, but passes none on: its hello
  carries the seqs it holds, so that a computer does not send the same list again, and its
  hub registers through the ways it names (section 13). A member that does not know
  `entries` ignores it.
- A hub of the project's forwarder that does not register, and holds no list that has not
  expired, says so where it shows the forwarder (`cbb global`, the apps; control status
  `away.forwarder.entries_stale`) and where to get a new one: `cbb update` on a computer of
  the group, or `cbb global entries import` there.
- Between devices that share no group, the list goes as a string: `cbb-entries:` and the
  JSON `{keys, entries}` in base64url without padding, which `cbb global entries export`
  gives (`-qr` as a QR code) and `cbb global entries import` takes.

## 17. Key stores

Where a device keeps its keys decides what a thief with the device gets: a key in a file can
be copied and used elsewhere until an admin removes the device, a key in hardware (the
Secure Enclave, the Android Keystore with StrongBox or the TEE, a TPM) signs only on that
device. The roadmap's key levels (item 31) build on this; this section is what 0.6 has so
far.

- A **hello** says where the sender's keys live in `key_store` (section 4); a receiver MUST
  NOT trust it for anything but what the root records, below: the phones send
  `hardware`, a Linux computer whose member key is in its TPM and a Mac whose member key is in
  its Secure Enclave `hardware`, a rootless
  install (below) `rootless`, the other computers and small devices `file`. A device that
  cannot tell sends `file`.
- **Rootless installs** (D-79). A member installed and run without root, as its
  user's own service, keeps its keys in a file that every program of that user may read. Its
  hello says `rootless`; a computer that is the group's root records such a
  member with `store` `rootless`, without `admin`, `kind` or `proof`, also over a record that
  said otherwise, and the phones go by its hello. Such a device MUST NOT be made the group's root, an admin or a trusted hub (it may be a hub
  that only passes copies on, section 11, "Two kinds of hub"), whatever the key level and the user's consent; it makes no group, offers no admin key and takes no
  admin CA itself. A reader that does not know the value takes it as `file` (below), so an
  older member keeps it from being an admin unless its user allowed keys in files.
- **Keys in a TPM.** A computer on Linux makes its member key and its admin key in the
  TPM 2.0 at `/dev/tpmrm0` when it may open it (the installer lets the service do so):
  an ECC P-256 signing key under the TPM's ECC storage root key (the TCG template, made
  again each time the service starts), fixed to that TPM and its parent, used without a
  password. The identity file then keeps the key's TPM blob, its public and private parts,
  in `key_tpm` and `admin_key_tpm` instead of `key` and `admin_key`; the blob loads only in
  that TPM. `CBB_TPM=off` makes new keys in a file; a key already in a file stays there
  until the device joins again. The CA keys of a root computer stay in the file.
- **Keys in the Secure Enclave.** A computer on a Mac with a Secure Enclave (Apple
  silicon, or an Intel Mac with the T2 chip) makes its member key, its admin key and its
  server keys (section 18) there: a P-256 signing key that no keychain keeps, usable after
  the Mac's first unlock since it started and without the user's presence, so the service,
  a LaunchDaemon running as root, signs from boot on. The identity file keeps the enclave's
  encrypted copy of the key (what CryptoKit calls its `dataRepresentation`) in `key_se`
  and `admin_key_se`, `server-keys.json` in `se`; only that Mac's enclave opens it. A build
  without cgo, or `CBB_TPM=off`, makes new keys in a file. The CA keys of a root computer
  stay in the file.
- **The WireGuard key** (section 11) is sealed by the same TPM: a sealed data object under
  the storage root key, its blob in `tunnel.json` as `key_tpm` in place of `key`. The key
  crosses to and from the TPM in a session salted with the storage root key that encrypts
  it, so it never shows on the chip's bus. A key in the file moves into the TPM when the
  service next reads the state; WireGuard itself still uses it in memory. The hub's keys
  for its clients (`serving_tpm`, `next_tpm`) and the secret for sealed commands
  (`seal.json`, `tpm`, section 15) are sealed the same way.
- **Sealed by the Secure Enclave.** On a Mac the same secrets are sealed to a new P-256 key
  in the enclave, which cannot hold an X25519 key itself: an ephemeral P-256 key agrees on
  a secret with the enclave's key (ECDH), and AES-256-GCM, keyed with HKDF-SHA256 of that
  secret (salt the ephemeral and then the enclave's public key, uncompressed; info
  `cbb sekey seal v1`), seals the secret with a random 12-byte nonce and the info as
  associated data. The file keeps `{"v":1,"key":…,"eph":…,"box":…}`: the enclave key's
  encrypted copy, the ephemeral public key and the nonce followed by the sealed secret,
  each in base64, as `key_se`, `serving_se` and `next_se` in `tunnel.json` and `se` in
  `seal.json`.
  `CBB_TPM_SIMULATOR=host:port` points the service at a software TPM (swtpm), for tests.
- A **device record** says it in `store`: `file`, `hardware`, `rootless`, or `proven` once the group's
  root checked a proof of hardware (an attestation, "Evidence" below), with `kind`, the kind
  of hardware (`android-tee`, `android-strongbox`, or `tpm` for a TPM's proof), and `proof`, the hex SHA-256 of the
  attestation's leaf certificate. The signer writes what the device's hello said when it
  made the record, and a record that renames a device, or that makes it an admin, keeps its
  `store`, `kind` and `proof`. A record without `store`, or
  with a value the reader does not know, counts as `hardware` for a `phone` and as `file`
  for every other role. `cbb status` and the
  apps' device pages show it.
- **Admins.** By default a device whose keys sit in a file does not become an admin: the
  root asks the user first, who allows it after a warning that whoever copies the file acts
  as an admin until another admin removes it (`cbb admin -allow-file-key`, and the warning
  in the phones' "Make it an admin" dialog). The root then signs the device record with
  `store` `file`. Moving the hub to such a computer makes it an admin only through that
  dialog; a hub that only passes copies on is no admin, and no key store keeps a computer from
  being one.
- **The root.** `cbb new` on a computer warns that its root key is a file: the group's CA
  keys are not in the TPM or the Secure Enclave yet (roadmap, D-44). A computer that holds
  the current root's CA key in a file therefore says `file` for its keys, in its hello and
  `cbb status`, whatever its member key, and `cbb new` signs the level `files` for its
  group; `key_level` refuses `hardware` and `proven` there. Making a group or an admin with
  keys in a file asks first too.
- **The attestation challenge.** An Android key is made with the attestation challenge
  `SHA-256("cbb attest v1" || field(group tag) || field(member key) || salt)`, where
  `field` is a two-byte big-endian length followed by the bytes, the group tag is its
  16 lowercase hex characters as ASCII, empty while the phone is in no group, the member key is the SubjectPublicKeyInfo of the
  device's member key (empty for the member key itself), and `salt` is 16 random bytes kept
  with the key. The key itself is bound by the attestation's leaf certificate, and whoever
  presents the key proves holding it in member TLS, so the proof needs no live nonce: it is
  made with the key, offline, and shown later with its salt and group tag. A Keystore that
  cannot attest at that moment still makes the key, which then has no proof.

### Evidence

A device whose keys an attestation proves sends an `evidence` message to each peer after the
hellos, once per connection:

| Field | Type | Meaning |
| --- | --- | --- |
| `format` | string | `android-key`: Android's Key Attestation |
| `key` | string | `member`: the attested key is the member key of the sender's TLS certificate |
| `group_tag` | string or absent | the group tag the key was made with; absent for a key made outside a group |
| `salt` | string | the 16 bytes of the challenge, base64 |
| `chain` | array of strings | the Keystore's certificate chain, leaf first, DER in base64 |

Only the group's root acts on it; every other member MUST ignore it, as it ignores a `format`
or `key` it does not know. The root MUST check that `group_tag` is absent or the group's own, that
the chain leads to one of Google's attestation roots without a revoked certificate, that every
certificate but the leaf, each of which signs the one before it, is a CA (BasicConstraints
`cA`), has the `keyCertSign` key usage when it has a key usage, and has a path length (when it
has one) that allows the CAs below it, that the extension of Remote Key Provisioning counts only
on such a certificate (never on the leaf), that the
leaf certifies the key of the sender's TLS certificate and carries the challenge made with
`group_tag`, an empty member key and `salt`, and reads the leaf's key description:

- a key in software: `file`;
- a key in the TEE or StrongBox of a phone with a locked bootloader and a verified boot:
  `proven`, of kind `android-tee` or `android-strongbox` (StrongBox only when both levels of
  the description say it);
- a key in hardware otherwise (an unlocked bootloader, a system signed with its own key as
  GrapheneOS, a boot not verified, no root of trust): `hardware`.

When that differs from the `store` or `kind` of the device's record, the root signs a new
device record that keeps the rest and says what the attestation shows. A chain that proves
nothing is logged and changes nothing.

### TPM evidence

A computer whose member key is in a TPM (above) proves it to the group's root in three
`evidence` messages of key `member`, after the hellos. Every message carries `salt` and
`chain`, empty where the format has none.

1. **`tpm`**, the device to every peer: `chain` holds the endorsement key's certificate,
   which the TPM's maker wrote in its NV (index `0x01c0000a` for the ECC P-256 EK, else
   `0x01c00002` for the RSA 2048 one; a device whose TPM holds neither sends nothing), then
   any certificates the device has between it and the maker; `tpm` holds base64 TPM
   structures: `ek`, the EK's `TPM2B_PUBLIC` made from the TCG's template; `ak`, the
   `TPM2B_PUBLIC` of an attestation key the device made under its storage root key, a
   restricted P-256 ECDSA signing key fixed in the TPM; `key`, the member key's
   `TPM2B_PUBLIC`; `attest`, the `TPMS_ATTEST` of `TPM2_Certify` of the member key by the AK
   with the qualifying data the attestation challenge (above) of `group_tag`, an empty member
   key and `salt`; and `signature`, the AK's `TPMT_SIGNATURE` of it.
2. **`tpm-credential`**, the root to that device: the root checks that the EK certificate
   leads to one of the TPM makers' certificates that releases ship
   (`internal/attest/tpmroots`), that `ek` is a restricted decryption key with the
   certificate's key, that `ak` is a restricted signing key made in the TPM, that `key` was
   made in the TPM, cannot leave it, and is the key of the sender's TLS certificate, and that
   the AK signed with ECDSA and SHA-256 a `TPM2_Certify` of `key` with the challenge. It then
   encrypts 32 random bytes to the EK for the AK's name (`TPM2_MakeCredential`'s format) and
   sends `credential`, the ID object, and `secret`, the encrypted seed.
3. **`tpm-activated`**, the device to the root: `secret` holds what `TPM2_ActivateCredential`
   recovered with the AK and the EK, which the TPM does only when both are its own. The device
   opens a credential only from the group's root (the device and key of the root's own
   device record, not revoked) and one at a time, since the TPM's work holds up the member
   key's signatures.

When it holds the 32 bytes, the root records the device's keys as `proven`, kind `tpm`, and
`proof` the hex SHA-256 of the EK certificate. Anything that fails is logged and changes
nothing: the record keeps the `hardware` of the device's hello. A computer whose record says
`file` while its hello says `hardware` (its keys were in the TPM before the root saw its
hello, as one admitted by pairing) gets a record that says `hardware`; on the records of
0.6 the root signs it when the member's hello comes (`writers::store_from_hello`), and a
member whose hello says `rootless` gets `store` `rootless` without an admin key, powers or
commands. On the records of 0.6 the same evidence goes in the `evidence` message (t 19),
below. Nothing goes to the
TPM's maker: a TPM whose EK certificate is not in its NV, as Intel's and AMD's firmware TPMs
often, stays `hardware` (the strict key level will fetch theirs). The phones do not check
TPM evidence yet; a phone as the group's root ignores it.

### Evidence on the records of 0.6

On the records of 0.6 each evidence above is one `evidence` message (t 19): field 2 `format`
1 `android-key`, 2 `tpm`, 3 `tpm-credential`, 4 `tpm-activated`; field 3 `key`, the hash of
the attested key, which MUST be the sender's member key (a receiver ignores evidence of any
other key, as it ignores a format it does not know); field 4 `data`, one item of the CBOR
profile, a map of its format's table (`msg::member::evidence_data`, the vectors' `data_take`
and `data_refuse` in `testdata/format/messages5.json`):

| Format | Fields of `data` |
| --- | --- |
| 1 `android-key` | 1 `group_tag` (8 bytes, absent for a key made outside a group); 2 `salt` (16 bytes); 3 `chain`, 1 to `msg::member::MAX_EVIDENCE_CHAIN` (10) certificates of at most `msg::member::MAX_EVIDENCE_CERT` (8192) bytes, DER, leaf first |
| 2 `tpm` | 1 `group_tag`, 2 `salt` and 3 `chain` as format 1, the endorsement key's certificate first; 4 `ek`, 5 `ak`, 6 `key`, 7 `attest`, 8 `signature`: the TPM structures above, each at most `msg::member::MAX_TPM_STRUCTURE` (2048) bytes |
| 3 `tpm-credential` | 1 `credential`, the ID object; 2 `secret`, the encrypted seed |
| 4 `tpm-activated` | 1 `secret`, the 32 bytes recovered |

The message's own bound on `data`, `msg::member::MAX_EVIDENCE` (65536), caps the whole encoded
map, so a chain at its widest leaves no room for the TPM's structures at theirs. In formats 3
and 4 `key` is the attested member key's hash too, the key of the device whose TPM the
credential is for: a device drops a credential whose `key` is not its own member key's, and
the root an answer whose `key` is not the one its credential went for.

The group tag is the group ID's first 8 bytes; the challenge takes it as its 16 lowercase hex
characters, as above, and the member key as the SubjectPublicKeyInfo of the sender's member key
(ES256). A `group_tag` of another length refuses the data, never reads as absent, since absent
is a key made outside a group, which the root takes. The root records what the evidence proves
in the device's record, `store` 4 (`proven`) with `proof` 1 `android-tee`, 2
`android-strongbox` or 3 `tpm`, as above.
Only the group's root records it; it records no proof for its own device, and a device whose
hello says `rootless` keeps `store` 3. A computer sends its TPM's evidence on each new
connection, to every peer since any may be the root or become it, and answers the root's credential (format 3) with format 4; the root
takes one exchange at a time per device and keeps the last evidence of each to check again
against a new revocation list. A phone that is the group's root has no helper and its app holds
the root key: it keeps the last Android evidence of each peer, checks it with the core's
checks (`cbb_core::attest`) under the revocation list its app hands it (`attest_status`), and
records what it proves when its app hands it the root key (the manage action `attest`); it
takes no TPM evidence.

### Revoked attestations

Google revokes the attestation keys of phones whose keys leaked (and suspends some for a
while) in a list at `https://android.googleapis.com/attestation/status`, which is not
signed. Devices never fetch it: a mirror on `cbb.tools` fetches it once a day, keeps the
serial numbers that are revoked or suspended, and publishes them at
`https://cbb.tools/attest/` as `attest-status.json` beside `keys.json`, signed with the
status key (section 16; `tools/attest-status`). The mirror refuses a list that drops a
serial number the last one revoked until its maintainer looks.

- The group's root fetches both files when the group starts and once a day (a root phone
  when evidence comes, at most once a day), and takes the
  list when it passes the checks of section 16, its `seq` checked as there under the
  `keys.json` it came with (kept in the state directory). The request is the same for every device and names none.
- The root checks every chain against the list it holds. A chain with a revoked
  certificate proves nothing: the root keeps the last evidence of each peer and, when it
  takes a new list, checks it again; a device recorded as `proven` whose chain is now
  revoked gets a new record with `store` `hardware` (its hello's word), its `kind`, and no
  `proof`, and the log says which certificate was revoked.
- A root without a current list (the mirror unreachable for a week, or no root keys pinned
  yet) checks chains without it. The strict key level (roadmap, item 31) will prove nothing
  without one.


## 18. Server credentials

What a forwarder and a relay check in place of the group's records, so that no device ID,
name, system, root or date leaves the group, and a server cannot follow a group or a device
from one month to the next ([design.md](design.md), D-67 and D-75). Implemented in Go
(`internal/forward`), and in Rust for the relay (`member/src/relayd`); the core reads the
format's profile, frames and credentials in `core/src/blind`. The phones' kits do what Go does
(`Credentials.swift`: `ServerCredentials`, `CredentialStore`, and
`CredentialRefresh`, which signs as Go's refresh does, the period on a root phone), keep them
and pass them on through the phone's member in the Rust core (`send_credentials`, its
`message` events). A phone registers with a relay
by them once the members' credential lists its server key (the Live member, member/src/relay.rs,
with the server certificate of `certs::server_cert_by`); it maps the pseudonyms the relay
names back to device IDs by the server credentials. A phone that is the group's hub
registers with its forwarder the same way once the hubs' credential lists its server key
(the Live member, member/src/forward.rs), and
with its member certificate and the records until then.

The group lives in **periods** of about 30 days. For each, its root signs, inside the group,
a fresh **tag** for the servers and a fresh **period key**; each device signs with its member
key a fresh **server key** that it uses with the servers in that period only. The servers see
only what the period key signs: the period's tag and lists of padded hashes of server keys.
A device that registers this way presents a certificate of its server key alone, which names
neither a device nor a group (`cbb server`, self-signed, no SAN, client
authentication).

### The envelope

A credential is `{"body": bytes, "sig": bytes, "key": bytes}`: the body, JSON, signed as
these exact bytes; an ECDSA P-256 signature with SHA-256 over them, DER; and the signer's
public key as a SubjectPublicKeyInfo, DER. Its ID is SHA-256 over `body`. Every body has
`v` (1), `type`, `group` (16 lower-case hex characters), `version` (a positive integer) and
`expires_ms` (positive), and nothing that names a device or a time of signing. Bodies are at
most 16 KiB. A receiver checks a body's size, then the strict form of signed bodies
(Conventions), then its fields, before it verifies the signature; a signer checks its own
body the same way. A `period` and a `server` credential have `tag` and `key` and no list; a
`hubs` credential no `tag`, `key` or `members`; a `key` is a P-256 SubjectPublicKeyInfo with
an uncompressed point; a `members` credential no `tag`, `key`, `hubs`
or `admins`; a field a type does not have is left out or empty. Bytes and hashes are base64
in its one form (Conventions). The vectors in `testdata/interop/strict-files.json` (section
`credentials`) test each row in all four implementations.

| `type` | `group` | Other fields | Signed by | Seen by |
|--------|---------|--------------|-----------|---------|
| `period` | the group's tag (section 1) | `tag`: the period's tag, 8 random bytes in hex; `key`: the period key, a P-256 SubjectPublicKeyInfo | the group's current root | the members; a relay with a fixed list of groups |
| `server` | the group's tag | `tag`: the period's; `key`: the device's server key | the device's member key | the members |
| `hubs` | the period's tag | `hubs`, `admins`: arrays of 32-byte hashes of server keys | the period key | the members, the forwarder and the relay |
| `members` | the period's tag | `members`: an array of 32-byte hashes of server keys | the period key, or a server key among the `admins` of the period's hubs' credential | the members and the relay |

A key's hash is SHA-256 over its SubjectPublicKeyInfo. Each list is padded with random
32-byte strings to 4, 8, 16, 32, 64, 128 or 256 entries, the smallest that holds it, so a
server learns the number of devices only roughly. `hubs` holds at most 16 entries, `admins`
64, `members` 256. The `server`, `hubs` and `members` credentials expire with their period.

### The period

The current root starts a period when it has none of its own, when the one it keeps is 30
days old (it lasts 35), and when a device that sent a server credential for it is no longer
in the group: a removed device knows the period's tag. It makes the period key (in the TPM
where there is one) and a new tag, and signs the period with its root key; `version` is one
above the period it keeps, or the time in Unix seconds when that is more. After a takeover
(section 10) the new root starts its own period at once. A phone's root asks for Face ID for
it about once a month, and with each removal, which asks anyway.

Every member that sees a period it has no server key for makes one (in the TPM where there is
one) and signs its `server` credential with its member key. It keeps the keys of the current
period only, in `server-keys.json` next to its identity, so the keys of a period are gone
when it ends.

### The lists

The root signs the hubs' and members' credentials with the period key, from the records and
the server credentials it keeps; an admin that the hubs' credential lists signs the members'
credential with its server key. A device that sent no server credential for the period is
left out until it does.

- `hubs`: the server keys of the devices that may be the hub, in the order of section 11,
  "Several hubs", at most 16.
- `admins`: the server keys of the admins that are neither removed nor frozen, the root's own
  device left out.
- `members`: the server keys of the group's devices that are not frozen.

A signer signs a new version when it has none for the period, or when a list does not match:
its real entries are not first (the hubs, in their order) or not all there (the others), its
length is not the padded length, or another entry is a server key it keeps. `version` is one
above the version it keeps of that type, or the time in Unix seconds when that is more. Go
checks all of this when the group starts, every 12 hours, after every new record and after
every new credential.

### Keeping and passing them on

A member keeps, in `credentials.json` next to its identity, the newest period that the
group's current root signed, and for it the newest server credential of each member key of
the group (a device's key that is neither revoked nor frozen), the newest hubs' credential
that the period key signed, and the newest members' credential that the period key or an
admin of that hubs' credential signed. A newer period drops the credentials of the one
before. After the hello, a member that keeps any sends `{"t":"credentials","credentials":
[credential, ...]}` with all of them, at most 259; a receiver keeps the new valid ones,
passes them on to its other peers the same way, and logs and drops the others.

A member that knows a pseudonym at the relay (section 14) finds the device it names through
the server credential whose key has that hash.

### What a server checks

A device presents one hubs' credential, and to a relay also the members' credential, and to
a relay that serves a fixed list of groups also the period credential with the group's root
key (the relay's challenge sets `root`, section 14). The server MUST check that:

1. none has expired;
2. the members' credential is of the same period (`group`) and the hubs' credential's
   signer, or a key among its `admins`, signed it;
3. the period credential, if any, has the hubs' credential's tag as `tag` and its signer's
   key as `key`, and a relay with a fixed list of groups takes it only when the root key shown
   signed the period and, with the recovery key the list gives, makes the Group ID of a group
   it serves;
4. the hash of the device's certificate key is among the `hubs` (the forwarder) or the
   `members` (the relay);
5. the period key is the one it first saw for the period's tag: the forwarder keeps, in
   `forward-state.json`, HMAC-SHA256 under a secret from its own key of the tag, with the
   newest hubs' version and the same HMAC of the tag and the period key's hash; the relay
   keeps the same in memory while any device of the period is on it, with the newest
   members' version and list. Older versions are refused, and a newer members' credential
   drops the devices it no longer lists.

The first period key a server sees for a tag counts: only the group's devices know the tag,
and a removed device's period ends with its removal.

A forwarder keeps a group that registered with credentials apart from the groups that
registered with records, which it names by the group CA's tag (section 13). A relay takes
registrations with credentials alone (section 14).

## 19. Registries

Every name the protocol uses, in one place. A new name gets a row here in the same change
that brings it in; an old name never gets a new meaning, and a receiver ignores a name it
does not know unless its section says it refuses it.

### ALPN protocol IDs and ports

| ID | Port | Section |
|---|---|---|
| `cbb/4` | TCP 8764, the member port; TCP 8764 inside the tunnel | 4 |
| `cbb-pair/3` | the member port; a listening joiner's port; TCP 8764 inside a guest tunnel | 6, 12 |
| `http/1.1` (or none) | the member port, on a member that serves the iPhone | 7 |
| `cbb-forward/3` | TCP on the forwarder's port (8764 by default) | 13 |
| `cbb-relay/3` | TCP on the relay's port (8764 by default) | 14 |
| (WireGuard, AmneziaWG) | UDP on the hub's, forwarder's or relay's port (8764 by default) | 11, 13, 14 |
| (VLESS over XHTTP) | TCP 443 on the web server in front of a forwarder | 11, 13 |
| (mDNS) | UDP 5353, 224.0.0.251 and ff02::fb | 3 |

### Labels and domain separation

| String | Use | Section |
|---|---|---|
| `EXPERIMENTAL-cbb-pair-v3` | TLS exporter label of a 0.6 pairing: CPace's `sid` and the exporter of the session mark | 6 |
| `cbb pair channel v3` + `0x00` | CPace's channel identifier prefix in 0.6 | 6 |
| `EXPERIMENTAL-cbb-pair-v2` | TLS exporter label: CPace's `sid` (0.5's pairing, until wave 5) | 6 |
| `cbb pair v2` + `0x00` | CPace's channel identifier prefix (0.5's pairing, until wave 5) | 6 |
| `cbb forwarder key` | TLS exporter label: a hub's proof of its WireGuard key | 13 |
| `cbb forwarder admin` | TLS exporter label: the root's or an admin's signature of a registration | 13 |
| `cbb forwarder hello` | TLS exporter label: the MAC key of a hub's hellos | 13 |
| `cbb forwarder state` | HMAC input: the key of the forwarder's state file | 13 |
| `cbb relay key` | TLS exporter label: a device's proof of its WireGuard key | 14 |
| `cbb attest v1` | the attestation challenge's prefix | 17 |
| `cbb copy v1` | the start of a copy's header, whose hash binds its payload and wraps | 4 |
| `cbb copy sig v1` | the start of what a copy's origin signs | 4 |
| `cbb copy payload v1` | HKDF info: a copy's payload key | 4 |
| `cbb copy blob v1` | HKDF info: a copy's blob key | 4 |
| `cbb blob` | associated data of a blob's segments | 4 |

Only the pairing label carries the `EXPERIMENTAL-` prefix that RFC 5705, section 4, asks of
labels not registered with IANA; the forwarder's and the relay's labels do not, which is a
known deviation. Since an exporter label is part of the protocol, they stay as they are
within version 1, and a new ALPN version would rename them.

### Certificate names

| Common name | Certificate | Section |
|---|---|---|
| `cbb group root YYYY-MM-DD` | a group root CA | 2, 9 |
| `cbb group CA YYYY-MM-DD` | the group CA of a group made before 0.4, refused | 2 |
| `cbb admin <device ID>` | an admin CA | 10 |
| `<device ID>` | a member certificate, DNS name `cb-<device ID>.local` | 2 |
| `cbb server` | a server key's certificate | 13, 18 |
| `cbb forwarder` | a forwarder's or relay's own certificate | 13, 14 |

### Member protocol messages (`t`)

`hello`, `event`, `ping`, `bye`, `cert` (section 4); `get`, `missing` and binary `chunk`
frames (section 4, "Content"); `records`, `admin` (section 10); `tunnel`, `hubs`
(section 11); `command`, `result` (section 15); `release`, `entries` (section 16); `evidence` (section
17); `credentials` (section 18).

### Values

| Name | Values | Section |
|---|---|---|
| Role (hello) | `member`, `phone` | 4 |
| Role (device record) | `member`, `phone`, `watch` | 10 |
| Capabilities (hello `caps`, record `caps`, ADa `caps`) | `admin`, `dials`, `hub` | 4 |
| System (`os`) | `linux`, `windows`, `macos`, `ios`, `android`, `aurora`, `sailfish`, `harmonyos`, `watchos`, `wearos`, `none` | 4, 10 |
| Device form | `laptop`, `desktop`, `phone`, `tablet`, `tv`, `board`, `server`, `router`, `console`, `watch`, `retro`, `other` | 4 |
| Event `kind` | `text`, `secret`, `media` | 4 |
| Event `via` | `copy`, `phone`, `universal-clipboard` | 4 |
| Media part `type` | `image/png`, `image/jpeg`, `text/html` | 4 |
| Sync mode | `shared` (sync on), `own` (sync off) | 4, 15 |
| Key store | `file`, `hardware`, `rootless`, `proven` (records only); proof kinds `android-tee`, `android-strongbox`, `tpm` | 17 |
| mDNS TXT keys | `v`, `g`, `p`, `j`, `f`, `r` (`listen`, `phone`) | 3 |
| Record `type` | `device`, `revoke`, `root`, `freeze`, `thaw` | 10 |
| Command `type` | `mode`, `hub`, `paste`, `paste-off`, `action`, `actions-off`, `away-off` | 15 |
| Command result `status` | `done`, `refused`, `failed` | 15 |
| Quick action presets | `lock`, `sleep`, `reboot`, `shutdown`, `cancel-shutdown`, `restart`, `keyboard-layout` | 15 |
| Signer kinds of an action | `root`, `phone`, `computer`, `watch` | 15 |
| Pairing errors | `wrong-code`, `closed`, `busy`, `expired`, `too-many`, `refused`, `declined`, `taken` | 6 |
| Evidence `format` | `android-key`, `tpm`, `tpm-credential`, `tpm-activated` | 17 |
| Release file `type` | `keys`, `release`, `channel`, `attest-status` | 16 |
| Release key `use` | `release`, `status`, `channel` | 16 |
| Server credential `type` | `period`, `server`, `hubs`, `members` | 18 |

### Addresses and URIs

| Item | Value | Section |
|---|---|---|
| Members' tunnel addresses | `fd00:cbb::/32` followed by the first 96 bits of the device ID | 11 |
| Guests' tunnel addresses | `fd00:cbc::/32` followed by the first 96 bits of SHA-256 of the guest key | 12 |
| A relay's own tunnel address | `fd00:cbb::1` | 14 |
| The hub's guest address, inside a guest tunnel (0.6) | `fd00:cbc::1` | 12 |
| Join QR code | `cbb://join?code=...&addr=...&fp=...` | 6, 7 |
| Remote invitation | `cbb://invite#...`, file `.cbbinvite`; on 0.6 `cbb://join#...` | 12 |

### Bounds

Every limit of the 0.6 format, from the core's registry (`core/src/bounds.rs`, written out as
`testdata/format/bounds.json`). The class says what a later version may do with it: a
**frozen** number never changes, because readers depend on it; a **stated** limit is the
writer's promise to the person and may be raised only up to what the previous version's
reader takes; a **reader** budget is one device's own and never on the wire. "Refused as"
names the rule a reader gives one past the bound (empty for a budget nothing reads back).
Where the text of this document names a bound, it writes the registry's name with its value,
as `records::MAX_SEEN` (1024); a test of the core checks every such name and value, and this
table, against the registry (`CBB_WRITE_BOUNDS=1` writes the table again).

<!-- bounds:begin -->
| Bound | Value | Class | Widest case | Refused as |
|---|---|---|---|---|
| `format::cbor::MAX_DEPTH` | 8 | frozen | an item inside 8 containers | `cbor/depth` |
| `format::cbor::MAX_COUNT` | 65535 | frozen | 65 535 elements of one array or map | `cbor/count` |
| `format::cbor::MAX_INT` | 9223372036854775807 | frozen | 2^63 − 1 | `cbor/int-range` |
| `format::frame::LIMIT_MEMBER` | 7340032 | frozen | message 67 or one part of a set, 448 · 16 KiB | `frame/grid` |
| `format::frame::LIMIT_PAIRING` | 1048576 | frozen | a pairing message before the code is confirmed | `frame/grid` |
| `format::frame::LIMIT_LEAF` | 16384 | frozen | a leaf's widest message | `frame/grid` |
| `format::container::MAX_SIG` | 72 | frozen | two integers of 33 bytes | `container/template` |
| `format::envelope::MAX_SIG2` | 8192 | frozen | ML-DSA-87 and a later algorithm | `env/sig2` |
| `format::envelope::MAX_SIG2_HEAD` | 32768 | frozen | K2's SLH-DSA-SHA2-128s, 7856 bytes, and a larger set | `env/sig2` |
| `format::copy::WRAP_SIZE` | 1168 | frozen | a wrap to an X-Wing key | `copy/shape` |
| `format::copy::MIN_WRAP` | 49 | frozen | K and its tag after one byte of encapsulation | `copy/shape` |
| `format::copy::MAX_READERS` | 256 | frozen | every device of the widest group | `copy/readers` |
| `copies::MAX_RESEALS` | 2 | reader | two asks of one reader | `reseal/limit` |
| `copies::STATEMENT_MAX_AGE_MS` | 3024000000 | frozen | a device away for 35 days |  |
| `copies::fresh::ALLOWANCE_MS` | 300000 | frozen | an origin's clock 5 minutes ahead; past it a copy is the verdict `ahead` (not written, not the newest), which depends on the reader's clock, so its vectors give the clock | `ahead` |
| `copies::fresh::MAX_SECRETS` | 1024 | reader | secrets listed by ID above the floor |  |
| `copies::fresh::MAX_ORIGINS` | 1024 | reader | origins with a newest time |  |
| `copies::blob::SEGMENT` | 65536 | frozen | a blob's plaintext segment, the last one padded with zeros |  |
| `copies::blob::SEALED_SEGMENT` | 65552 | frozen | a segment and its AES-256-GCM tag, the unit a fetch gets |  |
| `copies::blob::MAX_SEGMENTS` | 16384 | frozen | the largest media copy in segments |  |
| `content::MAX_STATE` | 4096 | frozen | a device's state | `content/data` |
| `media::MAX_NAME` | 765 | stated | a file name of 255 characters of 3 bytes | `content/manifest` |
| `media::MAX_PATH` | 16384 | stated | one path | `content/manifest` |
| `media::MAX_PATHS` | 2097152 | stated | every path of a manifest | `content/manifest` |
| `media::MAX_MEDIA` | 1073741824 | stated | files of 1 GiB | `content/manifest` |
| `media::MAX_PARTS` | 10000 | frozen | parts of a manifest | `content/manifest` |
| `media::MAX_TYPES` | 8 | frozen | types of one media copy | `content/manifest` |
| `media::MAX_ALT_TEXT` | 262144 | stated | an image's text | `content/text` |
| `commands::MAX_LIFETIME_MS` | 600000 | frozen | a later writer's command of 600 s | `commands/expires` |
| `commands::WRITE_LIFETIME_MS` | 30000 | stated | every 0.6 writer's command |  |
| `commands::SKEW_MS` | 60000 | frozen | a commander's clock a minute off | `commands/time` |
| `commands::MAX_BODY` | 65536 | frozen | a command with its widest orders | `env/size` |
| `commands::MAX_PASTE_BODY` | 2097152 | frozen | a paste of 1 MiB of text | `env/size` |
| `commands::DEFAULT_LIFE_MS` | 3024000000 | reader | a guarded leaf's grant that says nothing |  |
| `commands::MAX_NONCES` | 16 | reader | one-time numbers out at once | `commands/nonce` |
| `commands::orders::MAX_PASTE_TEXT` | 1048576 | stated | a paste's text | `orders/paste` |
| `commands::orders::MAX_TYPED_TEXT` | 16384 | stated | text typed out on a member | `orders/paste` |
| `commands::orders::MAX_MUTE_MS` | 2592000000 | stated | a mute of 30 days | `orders/mute` |
| `commands::orders::MAX_ARGS` | 4096 | frozen | a device command's arguments | `orders/device` |
| `format::grant::MAX_GRANT` | 4096 | frozen | 16 commanders, 16 readers and a later key's fields | `env/size` |
| `format::grant::MAX_LIFE_MS` | 3456000000 | stated | a guarded grant of 40 days | `grants/life` |
| `format::grant::MAX_READERS` | 16 | stated | a leaf's readers | `grants/readers` |
| `format::grant::MAX_COMMANDERS` | 16 | stated | a leaf's commanders | `grants/commanders` |
| `format::grant::MAX_NEIGHBORS` | 8 | stated | a leaf's neighbours | `grants/neighbors` |
| `format::grant::MAX_RECOVERY` | 64 | frozen | the group's 64 recovery records | `grants/recovery` |
| `records::statement::MAX_STATEMENT_BODY` | 32768 | frozen | X-Wing and the seal keys of later algorithms | `env/size` |
| `records::statement::KEYS_PER_MESSAGE` | 256 | frozen | a message `keys` of a full group | `keys-message/list` |
| `beacon::MAX_BEACON` | 512 | frozen | a beacon body | `env/size` |
| `beacon::MAX_COUNT` | 7168 | frozen | the records of a full set | `beacons/count` |
| `beacon::ALLOWANCE_MS` | 300000 | frozen | a sender's clock 5 minutes ahead | `beacons/time` |
| `beacon::MAX_AGE_MS` | 3024000000 | frozen | a beacon as old as a statement | `beacons/time` |
| `blind::card::MAX_BODY` | 16384 | frozen | a card | `env/size` |
| `blind::card::MAX_ENDPOINTS` | 8 | frozen | a server's endpoints | `card/endpoints` |
| `blind::card::MAX_KEYS` | 4 | frozen | a server's keys | `card/keys` |
| `blind::credential::MAX_BODY` | 16384 | frozen | a credential | `env/size` |
| `records::MAX_BODY` | 16384 | frozen | a record body | `env/size` |
| `records::MAX_CHECKPOINT_BODY` | 262144 | frozen | a checkpoint naming a full set | `env/size` |
| `records::MAX_SEQ` | 2147483647 | frozen | 2^31 − 1 | `records/seq` |
| `records::MAX_SEEN` | 1024 | reader | a `seen` list; the body's bound comes first: 1024 of the smallest entries pass MAX_BODY, so the count is a reader's guard that already stands if a later version widens the body | `records/revoke/seen` |
| `records::body::MAX_RECOVERY` | 64 | stated | 64 recovery records for the group's life | `records/recovery/seq` |
| `records::body::MAX_KEYS` | 256 | frozen | keys of a settings record | `records/revoke/keys` |
| `records::body::MAX_HUBS` | 16 | stated | hubs of a group | `records/hubs/hubs` |
| `records::body::MAX_SERVERS` | 16 | stated | servers of a group | `records/settings/servers` |
| `records::body::MIN_COPY_TTL_MS` | 60000 | frozen | the owner's shortest lifetime of an ordinary copy, a minute | `records/copies/ttl_ms` |
| `records::body::MAX_COPY_TTL_MS` | 3600000 | frozen | the owner's longest lifetime of an ordinary copy, an hour | `records/copies/ttl_ms` |
| `records::body::MIN_SECRET_TTL_MS` | 5000 | frozen | the owner's shortest lifetime of a secret, 5 seconds | `records/copies/secret_ttl_ms` |
| `records::body::MAX_SECRET_TTL_MS` | 60000 | frozen | the owner's longest lifetime of a secret, a minute | `records/copies/secret_ttl_ms` |
| `content::MIN_TTL_MS` | 5000 | frozen | the shortest lifetime a copy carries, a secret's least | `content/ttl` |
| `content::MAX_TTL_MS` | 3600000 | frozen | the longest lifetime a copy carries, an ordinary copy's most | `content/ttl` |
| `records::ADMIN_KEYS_MAX` | 16 | stated | the owner's cap of 16 admins |  |
| `records::MAX_DEVICES` | 256 | stated | 256 devices with a device record |  |
| `records::MAX_ROOT_RECORDS` | 1536 | frozen | a full checkpoint, a second waiting one and the devices |  |
| `records::MAX_ADMIN_RECORDS` | 256 | frozen | one admin's records |  |
| `records::CUT_ROOTS_RESERVE` | 1536 | frozen | headroom in the room: the roots before the current one keep 0 |  |
| `bounds::LIST_FIELD` | 52228 | frozen | a change's list as a field of `records` | `records/lists` |
| `records::LIST_MAX` | 1536 | frozen | a change's list in the format (the writer names none) | `records/lists` |
| `records::MAX_RECORDS` | 7168 | frozen | the set's room in units of 512 bytes |  |
| `records::MAX_SET_BYTES` | 3670016 | frozen | the room's bytes |  |
| `records::MAX_SET_SIG2_BYTES` | 134217728 | reader | both rooms, a waiting root and the settled records, each twice signed |  |
| `records::HEAD_SIG2_ALLOWANCE` | 33280 | frozen | K2's signature on a head with its head |  |
| `records::ENVELOPE_ALLOWANCE` | 83 | frozen | the envelope beyond a record's body |  |
| `records::MAX_PATH` | 65 | frozen | the first root and one per recovery record |  |
| `records::MAX_NEWER` | 16 | reader | held records a state lists |  |
| `records::MAX_NOTICES` | 256 | reader | notices a set keeps |  |
| `records::eval::MAX_IGNORED` | 64 | reader | records a state lists in ignored |  |
| `records::set::UNKNOWN_PER_SEQ` | 2 | frozen | recovery records of one seq taken from a peer the set does not know |  |
| `records::set::ADMIN_SILENCE_MS` | 3024000000 | stated | an admin's device silent for 35 days before the root takes its key back |  |
| `records::set::MISSING_ROUNDS` | 16 | reader | rounds a member asks for a missing record |  |
| `records::sync::PART_RECORDS` | 4096 | frozen | record envelopes of one part | `records/records` |
| `records::sync::HAVE_IDS` | 4096 | frozen | IDs of one `have` |  |
| `records::sync::PART_BYTES` | 7323648 | frozen | a part's items in one frame |  |
| `join::intro::MAX_RECORDS` | 32 | frozen | an intro's records | `intro/size` |
| `join::intro::MAX_BYTES` | 16384 | frozen | an intro's records' bytes | `intro/size` |
| `join::intro::MAX_HEADS` | 65 | frozen | a head for each recovery seq and the first | `intro/size` |
| `join::intro::MAX_PER_WINDOW` | 4 | reader | intros of one address in a window |  |
| `join::intro::MAX_PER_NETWORK` | 256 | reader | intros of one network in a window |  |
| `join::intro::WINDOW_MS` | 60000 | reader | the window |  |
| `join::intro::MAX_ADDRESSES` | 256 | reader | addresses a limiter tracks |  |
| `join::invitation::MAX_ENDPOINTS` | 8 | frozen | endpoints of one path | `invite/path` |
| `join::invitation::MAX_PATHS` | 4 | frozen | paths of an invitation | `invite/shape` |
| `join::invitation::MAX_FAILURES` | 3 | reader | failed attempts before an open invitation closes |  |
| `join::invitation::HOME_DIGITS` | 6 | frozen | the digits of a home window's code, CPace's password |  |
| `join::invitation::MAX_WINDOW_ADDRS` | 4 | reader | addresses in a home window's QR code |  |
| `join::invitation::MAX_WINDOW_TEXT` | 512 | reader | the text of a home window's QR code |  |
| `join::invitation::ATTEMPT_MS` | 30000 | reader | the machine's steps of one attempt |  |
| `join::waiting::MAX_WAIT_MS` | 86400000 | frozen | a request held a day | `waiting/requests` |
| `join::waiting::MAX_REQUESTS` | 16 | frozen | requests by guest paths | `waiting/requests` |
| `join::waiting::MAX_PER_INVITATION` | 2 | reader | requests of one invitation |  |
| `join::waiting::MAX_HOME` | 32 | frozen | requests from home | `waiting/requests` |
| `join::waiting::MAX_MESSAGE` | 48 | frozen | requests of one `waiting` | `waiting/requests` |
| `join::welcome::STATEMENTS_BUDGET` | 2097152 | frozen | a Welcome's statements and credentials |  |
| `join::welcome::RECORDS_BUDGET` | 5177344 | frozen | a Welcome's records when the set rides in it |  |
| `join::welcome::MAX_PARTS` | 64 | frozen | the widest set in about 14 parts | `welcome/parts` |
| `join::welcome::MAX_PARTS_BYTES` | 101039910 | frozen | what for_peer gives a device at the widest | `welcome/parts` |
| `join::welcome::PART_MS` | 120000 | reader | a 7 MiB part at 0.49 Mbit/s | `welcome/late` |
| `join::welcome::PARTS_MS` | 1500000 | reader | the widest parts at 0.54 Mbit/s | `welcome/late` |
| `keystore::AHEAD_MS` | 86400000 | reader | a newest epoch a day ahead |  |
| `keystore::WEEK_MS` | 604800000 | frozen | a sealing epoch, the newest for a week and kept a week after |  |
| `store::HEADER` | 12 | frozen | a store frame's header |  |
| `msg::member::MAX_ACTIONS` | 64 | frozen | the action names a hello offers | `hello/actions` |
| `msg::member::MAX_ACTION_NAME` | 32 | frozen | an action's name | `hello/actions` |
| `msg::member::MAX_VERSION_TEXT` | 32 | frozen | a system's or cbb's version in a hello | `hello/device` |
| `msg::member::MAX_ARCHIVE` | 64 | frozen | a release archive's name, 61 bytes at the widest | `hello/device` |
| `msg::member::MAX_RELEASE_FILE` | 524288 | frozen | a release file of a 256 KiB body in base64 with its signature | `release/release` |
| `msg::member::MAX_EVIDENCE` | 65536 | frozen | an attestation's chain or a TPM's quote with its certificates | `evidence/data` |
| `msg::member::MAX_EVIDENCE_CERT` | 8192 | frozen | a certificate of an attestation's chain: Android's with Remote Key Provisioning, a TPM maker's | `evidence/android/chain` |
| `msg::member::MAX_EVIDENCE_CHAIN` | 10 | frozen | an attestation's chain, leaf or endorsement key's certificate first | `evidence/android/chain` |
| `msg::member::MAX_TPM_STRUCTURE` | 2048 | frozen | a TPM structure: an RSA endorsement key's TPM2B_PUBLIC, an encrypted seed | `evidence/tpm/ek` |
| `join::guest::MAX_DATA` | 16384 | frozen | bytes of a guest's connection in one guest message | `guest/data` |
| `sheet::MAX_INPUT` | 512 | reader | a sheet typed with spaces and line ends | `not_sheet` |
<!-- bounds:end -->

### Why the time constants have these values

The core's clocks follow a few values, each chosen once (D-116):

| Constant | Value | What follows it |
|---|---|---|
| `keystore::WEEK_MS` | a week | how long a sealing epoch is the newest, and how long the previous one is kept |
| `PERIOD_RENEW_MS` (`member/src/faces.rs`) | 30 days | how old a period gets before the root starts the next |
| `PERIOD_LIFETIME_MS` (`member/src/faces.rs`) | 35 days | how long a period lasts: the renewal plus 5 days |
| `copies::STATEMENT_MAX_AGE_MS` | 35 days | how long a device may be away and still read and write; `beacon::MAX_AGE_MS` and `records::set::ADMIN_SILENCE_MS` follow it |

**A week for the sealing keys.** MLS leaves the time between key updates to the application
and says that "the right frequency is usually on the order of hours or days, not
milliseconds" (RFC 9420, section 3.2). The Matrix specification recommends a week as the
default for rotating a room's session (`rotation_period_ms`, "604800000 (a week) is the
recommended default"; Client-Server API v1.19, `m.room.encryption`). A week is at the long end
of that range, so a device that sleeps over a weekend still finds the key it last saw.

**35 days for a silent device or admin.** The MLS architecture asks every application to
define "a policy on how long to allow a member to stay in a group without updating its leaf
keys before removing them" (RFC 9750, section 7), and recommends that applications "evict
clients that are idle for too long" (section 8.2.2), since a client that stays offline may
still hold old keying material. Ours is one 30-day period plus 5 days; the 5 days of slack are
our own choice, so that a device that renews late in a period is not dropped at its end. As an
example of practice, not a basis: Signal says "After linking a device, your phone has to come
online at least once every 30 days. Otherwise, your linked devices will become unlinked." and
"Linked devices will also become unlinked after 45 days of inactivity." (Signal Support,
"Linked Devices").

**Not 7 days for silence.** Silence equal to the key period would drop every device that
missed one rotation out of the readers, so active devices that sleep for a week would leave
the group weekly.

**No early rotation on a removal or a change of root.** The group has no shared secret: each
copy is sealed for each reader separately, and the readers come from the records that count
(`copies::readers`, which also leaves out a device whose keys statement is older than
`copies::STATEMENT_MAX_AGE_MS`), so a removed device or an old root's admin is no longer a reader of the
next copy. MLS rotates its group secret on a removal because every member holds it; we have
nothing of that kind to rotate.

## 20. Security considerations

The threats, the defences and their code are in the [threat model](threat-model.md); this
section lists what an implementation must not get wrong, by section.

- **Authentication is the certificate, never the address or the name** (sections 3, 4). mDNS
  can be answered by anyone on the network; only the member TLS
  handshake, checked against the group's CAs and the records, says who a peer is.
- **The records decide, the same way everywhere** (section 10). An implementation that
  evaluates the records differently from the others splits the group: a removed device
  stays in on one member, or an admin's powers differ. The interop vectors in
  `testdata/interop` are the test of this; a new implementation MUST pass them.
- **The pairing code is short** (section 6). Its safety rests on CPace with at most three
  online guesses per code, on the code never leaving the joining device after it is spent,
  and on no free text from an unauthenticated peer. A remote invitation's secret is long
  because it crosses the internet.
- **Copies are sealed end to end** (section 4). A member takes no copy in the open, checks
  the origin's certificate and signature before it passes a copy on, and reads only through
  its own wrap; a member that leaves a check out lets a member in between, a hub among them,
  forge copies, and one that took a copy in the open would let it read them. The readers are
  the devices the origin's records list, so the records decide who reads, as they decide who
  connects.
- **Secrets** (section 5) never go to disk, never into a hello, a log, a notification or a
  `message`, and expire 60 s after the copy.
- **Remote paste and quick actions** (section 15) type into and act on a device. Their
  switches are set only on the device itself; commands expire in 30 s, are checked against
  a replay cache and the records, and are limited per signer; control characters are
  removed; nothing is typed on a lock or login screen; an action's program runs without a
  shell and takes no argument from the network.
- **Away from home** (sections 11 to 14) data exists only inside the group's WireGuard
  tunnel, with member TLS inside it. A member fails closed; a hub forwards no packets
  between peers; a client never sends plain WireGuard where VLESS is set. A forwarder or
  relay holds no key that decrypts anything, and a relay sees which devices talk and when
  (section 14, "What it keeps"), which the user is told before it is used.
- **Received content** (section 4) is checked against the blob's SHA-256, each segment's tag
  and each part's SHA-256 before use; names are
  cleaned so that a copy cannot write outside its folder, and no link is followed or made.
- **Updates** (section 16) are taken only under the pinned root keys and never to an older
  version than the device has seen, so neither a server nor the network can hold a device
  back or give it another build.
- **Keys in files** (section 17) can be copied by whoever reads the disk; such a device
  becomes an admin or turns sync away from home on only after the user's consent.
