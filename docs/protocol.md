<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Clipboard Bridge protocol

The text of this document is under the
[Creative Commons Attribution 4.0 license](https://creativecommons.org/licenses/by/4.0/).
You may implement the protocol in your own code under any license. The code of this
repository stays under the GNU AGPL v3.0 only ([LICENSE](../LICENSE)).

This document specifies protocol version 1 of Clipboard Bridge as the code in this
repository implements it, so that another implementation can interoperate with it. Four
implementations follow it today: Go (`cbb`, the computers and the servers), Rust (the lite
member, `lite/core`), Swift (`ClipboardBridgeKit`) and Kotlin (`apps/android/kit`), with
shared test vectors in `testdata/interop`. [design.md](design.md) explains why the protocol
is the way it is; this document only says what it is, and the threats it answers are in the
[threat model](threat-model.md).

**Status.** This is the edition for release 0.6. A change that a peer of the previous
release could not read gets a new ALPN protocol, record type or message field, never a new
meaning for an old one; the registries (section 19) list every name in use. Where the Go
code and this document differ, the Go code is the source of truth and the difference is a
bug in one of them; a "Note:" line marks a known difference.

### Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119),
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all
capitals, as shown here. They mark what an implementation has to do to interoperate and to
keep the group safe. Sentences in the plain present tense describe what the code in this
repository does; another implementation may do it differently where nothing marked with
these words depends on it.

- **Peer, member.** A member is a device of the group with a member certificate: a full
  member (a computer with the service), a lite member, or a phone with the app. A peer is
  the other end of a connection.
- **JSON.** [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) objects. A receiver MUST
  ignore fields it does not know, unless a section says otherwise.
- **Bytes.** Byte strings, in JSON and in the texts of this document (an invitation, a QR
  code, a pin), are standard base64 with padding in its one form
  ([RFC 4648](https://www.rfc-editor.org/rfc/rfc4648), section 4; Go's encoding of
  `[]byte`): no line breaks, no base64url, the padding there, zero bits after the last
  byte. In a URL's query each `+`, `/` and `=` is percent-encoded, and a reader decodes only
  percent escapes, never a `+` as a space. Three kinds of value stay in lowercase hex: the
  identifiers (device IDs, event and command IDs, group and period tags), which compare as
  strings; the SHA-256 of a file (release files, Docker digests), which `sha256sum` prints;
  and the REALITY short ID (section 13), whose form Xray sets. The iPhone shortcut's token
  and the iPhone CA's fingerprint (sections 2 and 7) keep their forms until the shortcut goes
  ([roadmap](roadmap.md), item 17).
- **Fingerprints.** A key has one fingerprint: SHA-256 over its SubjectPublicKeyInfo (DER),
  in standard base64, 44 characters, the same as a record's key hash (section 10). The
  join QR code, the confirmation of a joining device, a forwarder's or a relay's pin and a
  device's pseudonym at a relay all use it.
- **Signed bodies.** The body of a record (section 10), of a command (section 15), of a
  release file (section 16) and of a server credential (section 18) is signed as bytes and
  passed on unchanged, so every member MUST read it alike. A receiver
  MUST refuse a body that breaks any of these rules, before it reads a field, and so MUST
  a signer's own code before it signs. Each rule has a name, which the vectors cite:
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
    it still follows every rule above. A record refuses it instead (below).
  - The fields every body of its kind has are there: `v`, `alg`, `type`, `group`, `signer`,
    `seq` and `time_ms` in a record; `v`, `type`, `group`, `by`, `to`, `id`, `time_ms` and `expires_ms` in a command;
    `v`, `type`, `group`, `version` and `expires_ms` in a server credential; `v`, `type` and
    every field its table does not call optional in a release file.
  - Bytes are standard base64 with padding in its one form: decoding and encoding again
    gives the same string (no line breaks, no missing padding, no base64url, zero bits
    after the last byte).

  A record (section 10) is read more strictly still, in one canonical form, so that encoding
  what a receiver read gives the bytes it received:
  - `form/unknown`: a member the record's type does not name refuses the body. A new field
    needs a new `v`.
  - `form/empty`: an optional field whose value is empty (`""`, `[]`, `{}` or `false`) MUST be
    left out, and a body with such a field is refused. An integer is never empty: where its
    row allows 0, 0 is written.
  - `form/canonical`: the body is exactly the bytes a receiver gets when it encodes what it
    read again: no whitespace anywhere, outside strings; the members of every object sorted
    by name, bytewise; integers as `0` or `-?[1-9][0-9]*`; in a string, `"` and `\` escaped
    as `\"` and `\\`, each character below U+0020 as `\u00` and two lower-case hex digits,
    and nothing else escaped (no `\/`, `\n` or `\t`, no `\u` for any other character),
    every other character as its UTF-8; arrays in the order the field's row gives (a row
    that says "sorted" means sorted bytewise by each value's string, for a key hash or record
    ID its base64, or by the string field the row names, each value once); bytes as above.

  A receiver checks a body in this order: its size (`size/records`, 8 KiB and 64 KiB for a
  checkpoint, section 10; `size/commands`, section 15; `size/releases`, 256 KiB, section 16;
  `size/credentials`, 16 KiB, section 18) before anything else; then these rules, and for a
  record its canonical form (it encodes the value it parsed and compares bytes); then each
  field against its row in the tables of its kind ("Field rows" in section 10, "The command"
  in section 15); then the group, the signature and the rules of evaluation. A body that
  fails a step is refused there, so a member never verifies a signature over a body it
  cannot read alike, and never evaluates a record whose fields another member reads
  otherwise. Go's `checkStrict`, the lite member's `strict`, and `Strict` in both phone kits
  implement these rules. Every one of them gives the same verdict on the vectors in
  `testdata/interop/strict.json`, written by hand, and in
  `testdata/interop/strict-generated.json`, which Go's `TestStrictGenerated` writes from
  these rules and the tables, and in `testdata/interop/strict-files.json`, which
  `TestStrictGeneratedFiles` writes the same way for server credentials and release files: a
  valid body of every kind and, for every field, the body
  without it, with a value of each other JSON type, `null`, written twice, its name in upper
  case or escaped, its numbers or strings in each form these rules refuse (for the fields every
  kind of a section has, on one kind only), and the values at the ends of its row's range. Each vector names its rule (`form/...`, `size/...`, or
  `records/<type>/<field>`, `commands/<type>/<field>`, `manifests/<field>`,
  `credentials/<type>/<field>` and `releases/<type>/<field>` for a row of a table) and whether
  a member takes the body, and in strict-files.json its `kind`; a vector with `pad` has `pad` bytes `a`
  inserted at the offset `pad_at` of its body. The tests fail when the file is not what the
  tables give, and when any implementation reads a vector otherwise. The records in these
  files are still of version 1, which every member now refuses whatever the vector says; the
  record bodies of version 2 are read by `internal/authority` and `cbb_core::authority`
  alone (the phones through the core), and their strict and canonical forms are checked by
  those packages' own tests and the differential run.
- **Frames.** Every channel of this document between devices, and between a device and a
  server, carries the same frames: a 4-byte big-endian length, then that many bytes of one
  JSON object in UTF-8, with no newline after it. A length of 0, or over the channel's limit,
  closes the connection, and so does a frame that is not a JSON object. The member protocol
  (section 4) adds binary chunk frames, marked by the length's top bit; pairing (section 6),
  the forwarder (section 13) and the relay (section 14) use the frames as they are, each with
  its own limit. A receiver reads exactly one frame and nothing after it, so another protocol
  may follow on the connection (the member protocol after the relay's `ok`). Go's
  `internal/frame` implements them. Only the local control socket (section 8), which never
  leaves the machine, has framing of its own.
- **Time.** Times on the wire are Unix milliseconds (`_ms`), and durations integer
  milliseconds, unless a field says otherwise. Local durations (ages, windows, timeouts) are
  measured on a clock that counts the time the machine sleeps and does not jump when the
  wall clock is set (`CLOCK_BOOTTIME` on Linux, `CLOCK_MONOTONIC` on macOS; package
  `uptime`); an implementation SHOULD do the same.
- **Source.** Each section names the code that implements it, so that a reader can check a
  detail there.

## 1. Identifiers, names and ports

| Item | Value | Source |
|------|-------|--------|
| Device ID | 128 random bits as exactly 32 lowercase hex characters (`[0-9a-f]{32}`) | `internal/group/cert.go` |
| Event ID | same format as a device ID, random per event | `internal/clip/clip.go` |
| Phone ID | 16 random bytes, shown as 32 lowercase hex characters; embedded in the token | `internal/phone/token.go` |
| Group tag | first 8 bytes of SHA-256 over the group CA certificate (DER), as 16 lowercase hex characters | `group.Tag` |
| Member host name | `cb-<device ID>.local` (mDNS host name and the only DNS name in the member certificate) | `DeviceID.HostName` |
| Service instance | `<device ID>._clipboardbridge._tcp.local` | `internal/mdns/zone.go` |
| Shared iPhone name | `clipboardbridge.local` | `group.PhoneName` |
| Member port | TCP 8764, or `CBB_PORT` (the Linux installer's `--port`), when free, otherwise one the OS chooses, all addresses; published in the SRV record. Full and lite members listen on it; phones only while they are the hub. Clipboard Bridge's only port: it also serves pairing, the iPhone endpoints and the profile (section 7), and a listening join waits there | `internal/service/service.go`, `internal/service/demux.go` |
| mDNS | UDP 5353, groups 224.0.0.251 and ff02::fb | `internal/mdns/mdns.go` |
| Member ALPN | `clipboardbridge/2` | `group.MemberProtocol` |
| Pairing ALPN | `clipboardbridge-pair/2` | `pair.Protocol` |
| Forwarder | UDP and TCP 8764 on the forwarder's own server (`cbb forward -listen`); ALPN `clipboardbridge-forward/2` (section 13) | `internal/forward` |
| Blind relay | UDP and TCP 8764 on the user's own server (`cbb relay -listen`); ALPN `clipboardbridge-relay/2`; tunnel address `fd00:cbb::1` (section 14) | `internal/relay` |
| Pairing code | six ASCII digits; users may type spaces and dashes, which are removed | `pair.NormalizeCode` |
| Join QR text | `clipboardbridge://join?code=` followed by the six-digit code; unknown query fields are ignored | `phone.JoinQR`, `phone.ParseJoinQR` |

Device IDs, event IDs and group tags compare as byte strings. Accepting peers: the member
port MUST accept TCP connections only from addresses that mDNS would publish (private IPv4,
unique-local IPv6, link-local IPv6) or loopback, and close others (the iPhone endpoints
also answer HTTP 403 to them); a member with an interface list (`CBB_INTERFACES`) MUST also
close a connection that did not arrive on such an interface from its own networks. At most
32 connections to the member port may be in their TLS handshake or in a pairing attempt at
once; more are closed at accept. An implementation SHOULD bound them likewise.

## 2. Certificates

All keys are ECDSA P-256; all signatures are ECDSA with SHA-256 (Go's default for P-256).
Serial numbers are random. Go also adds subject and authority key identifiers; peers do not
rely on them. Source: `internal/group/cert.go`, `internal/group/tls.go`, `internal/pair/join.go`.

| Certificate | Subject CN | SAN | Validity | Extensions |
|-------------|-----------|-----|----------|------------|
| Group root CA | `clipboardbridge group root YYYY-MM-DD` (UTC creation date) | none | NotBefore = creation - 24 h; NotAfter = creation + 20 years | CA, path length 1 (MaxPathLen 1); key usage certSign, cRLSign |
| Group CA of a legacy group | `clipboardbridge group CA YYYY-MM-DD` | none | as the root CA | CA, path length 0 (MaxPathLen 0); key usage certSign, cRLSign |
| iPhone CA | `clipboardbridge iPhone CA YYYY-MM-DD` | none | as the root CA | CA, path length 0; key usage certSign, cRLSign; plus critical name constraints (below) |
| Member certificate (from the group CA) | the device ID | DNS `cb-<device ID>.local`, exactly one | NotBefore = the group CA's NotBefore; NotAfter = min(issue + 2 years, CA NotAfter) | key usage digitalSignature; EKU serverAuth and clientAuth; not a CA |
| `clipboardbridge.local` server certificate (from the iPhone CA) | `clipboardbridge.local` | DNS `clipboardbridge.local` | NotBefore = max(issue - 24 h, CA NotBefore); NotAfter = min(NotBefore + 397 days, CA NotAfter) | key usage digitalSignature; EKU serverAuth; not a CA |
| Joiner's self-signed certificate (pairing only) | the joiner's new device ID | none | 1970-01-01T00:00:00Z to 9999-12-31T23:59:59Z | none set |

iPhone CA name constraints, marked critical: permitted DNS domains `clipboardbridge.local` (the
name and names below it); permitted e-mail and URI domains `clipboardbridge.invalid` (a domain
that never exists, so no such name is valid); excluded IP ranges `0.0.0.0/0` and `::/0`.

A device has one key. The member certificate and, on a member that serves the shortcut, the
`clipboardbridge.local` certificate certify the same key. A CA MUST NOT issue when the local
clock is outside its own validity. The computer that creates a group is its **root**: it
makes the group root CA (the `group_ca` that names the group, as a phone does, section 9) and
the iPhone CA and holds both keys. The admins it makes (section 10, "Admins") hold an admin
CA under the root and the iPhone CA key; every other member holds neither and has no
`clipboardbridge.local` certificate. A **legacy group**, made before admin CAs, has a group CA
with path length 0, and every Linux and Windows member of it holds both CA keys, a Mac
neither (design.md, "Full members, admins and the operating system"). Records of version 2
have no upgrade from it: a legacy group is set up again to get a root.
Implementations other than Go MAY refuse legacy groups. A phone never takes part in one: only
a phone admits a phone (section 6), and a phone's group always has a root, so the phone kits
join only a group whose CA has path length 1. The joiner's certificate carries the key that the member certifies in the welcome
(section 6).

Checking a member certificate (`checkPeer`, `DeviceOf`): the chain MUST verify to the group
CA at the time max(now, group CA NotBefore), so a device whose clock is behind still accepts
it, while an expired certificate is rejected. The subject CN MUST be a device ID, and the
certificate MUST carry exactly one DNS name, `cb-<that ID>.local`.

Renewal rules (`Identity.Renew`): a member certificate SHOULD be renewed when less than 240 days
remain, a `clipboardbridge.local` certificate when less than 60 days remain or when its NotBefore
is in the future; neither is renewed when it already ends with its CA.

When renewal runs: a member that holds a CA key (the root, an admin, a key holder of a legacy
group) checks its own certificates when the group
starts and every 12 hours, saves renewed ones and presents them on new connections at once
(running connections keep theirs). It renews the certificates of other members too: when a
peer's hello arrives, and every 12 hours for the running connections, it checks the
certificate the peer presented in the handshake and, when it is due, sends a `cert` message
(section 4) with a new certificate for the same device ID and key, at most once per
connection. A member without the CA keys MUST keep a certificate from a `cert` message only when
it verifies to the group CA (or to one of the group's roots, through the message's `issuer`
when present, section 10), names its own device ID and key, has client and server use, ends
later than its current one, is not refused by the records and was not issued by a CA whose
key the records revoke (a removed admin's or an old root's certificates stay valid for the
devices its removal keeps, but it renews none); otherwise it MUST ignore it, and SHOULD log
that. A certificate that has
already expired cannot be renewed this way, since the handshake fails; the device pairs again.

Fingerprint (shown to the user): SHA-256 over the certificate DER as upper-case hex bytes
separated by spaces; the short form is the first 8 bytes (23 characters).

## 3. Discovery (mDNS)

Full members (Linux, FreeBSD, Windows and macOS computers) and lite members publish and browse;
phones and joining devices only browse, except a phone that is the group's hub, which
publishes `v=1`, `g=<tag>`, `r=phone` while its app is open (design.md, "The phone as the
hub"). Only a full member that holds the iPhone CA key
publishes a holder priority (`h`) and may hold `clipboardbridge.local`.
[RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) and
[RFC 6763](https://www.rfc-editor.org/rfc/rfc6763) apply where this section is silent. Source: `internal/mdns`; a lite
member publishes and browses with the `mdns-sd` crate (`lite/src/discovery.rs`), which
follows the same RFCs but not every detail below: it publishes the PTR, SRV, TXT and A/AAAA
records of the table (the TXT with `r=lite`), with the addresses of its interfaces except
loopback, and never holds `clipboardbridge.local`.

A full member SHOULD publish, answer queries and take connections on the member port only on
an interface whose network it knows (design.md, "Known networks"); elsewhere it only
browses, and connections to its member port there are closed at once, except while a pairing
window is open. The lite member publishes on every interface.

### Records a full member publishes

| Name | Type | Data | TTL | Cache-flush |
|------|------|------|-----|-------------|
| `_clipboardbridge._tcp.local` | PTR | `<id>._clipboardbridge._tcp.local` | 4500 s | no (shared) |
| `<id>._clipboardbridge._tcp.local` | SRV | priority 0, weight 0, member port, target `cb-<id>.local` | 120 s | yes |
| `<id>._clipboardbridge._tcp.local` | TXT | see below | 4500 s | yes |
| `cb-<id>.local` | A / AAAA | the addresses of the interface | 120 s | yes |
| `cb-<id>.local` | NSEC | see below | 120 s | yes |
| `clipboardbridge.local` (holder only) | A / AAAA | the addresses of the interface | 10 s | yes |
| `clipboardbridge.local` (holder only) | NSEC | see below | 10 s | yes |
| `_services._dns-sd._udp.local` | PTR | `_clipboardbridge._tcp.local` | 4500 s | no; only in answers, never announced |

TXT strings (each at most 255 bytes):

| Key | Value | Meaning |
|-----|-------|---------|
| `v` | `1` | protocol version |
| `g` | group tag | members of another group, or of a replaced CA, are ignored |
| `p` | `1` | present only while a computer pairing window is open |
| `r` | `lite` or `phone` | `lite` on a lite member, which the full members do not dial (section 4); `phone` on a phone that is the group's hub while its app is open, which the full and lite members do not dial, since it dials them; the other phones dial it |
| `h` | `1` or `2` | the holder priority, present only on a full member that may hold `clipboardbridge.local`: `1` first, `2` only as a fallback |

The Go code publishes them in the order `v=1`, `g=<tag>`, `h=<priority>` (if any), `p=1`; a
lite member publishes `v=1`, `g=<tag>`, `r=lite`. A receiver MUST treat an unknown `h` value as absent,
MUST match keys without regard to case, and MUST take as the value what follows the first `=`.
A member MUST NOT dial a peer whose `g` is not its group's tag.

Note: browsers check only `g` (when dialing), `r` (when dialing, on full and lite members),
`h` (in the election, on full members)
and `p` (when joining); nothing checks `v` (`internal/service/members.go`,
`internal/service/socket.go`, `lite/src/discovery.rs`).

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
- A PTR question for `_clipboardbridge._tcp.local` gets the PTR as answer and SRV, TXT, A/AAAA
  and NSEC of the host as additionals. A question for the instance gets SRV (with the host
  addresses as additionals) and/or TXT. A question for the host name, or for
  `clipboardbridge.local` on the holder, gets its A or AAAA records, or the NSEC record when the
  name has no address of the asked type. Type ANY gets everything that matches.
- Known-answer suppression: a record listed in the query with at least half of its TTL is
  left out. A record already multicast on the interface within the last second is left out.
- A multicast answer that contains a shared record (a PTR) is delayed 20 to 119 ms; other
  answers go at once, to the group of the query's address family.
- A legacy unicast query (source port not 5353) gets a unicast answer that repeats the ID and
  the questions, TTLs capped at 10 s, no cache-flush bits, at most 5 answers a second per
  source. An answer over 9000 bytes drops its additionals.
- Names are never probed: device IDs are random, and the election below decides who holds
  `clipboardbridge.local`.

### Announcements and goodbyes

- All records are announced twice, one second apart, at start, on a new interface or new
  addresses, after a TXT change and when the member becomes the holder.
- Addresses that go away get a goodbye (TTL 0) for the host name and, on the holder, for
  `clipboardbridge.local`.
- Giving up `clipboardbridge.local` sends a goodbye for its A/AAAA and NSEC records.
- On stop, every record gets a goodbye. Goodbyes never carry the cache-flush bit, so they end
  only their own record. A service that stops sends its mDNS goodbyes before the member
  goodbyes (section 4).

### Browsing

- Query PTR `_clipboardbridge._tcp.local` at start, then after 1 s, doubling up to one hour,
  listing as known answers the PTR records with more than half their TTL left of the members
  found (a PTR record whose SRV or addresses expired is not listed). When a member found is
  lost, start again: query now, then after 1 s, doubling. A member that was off the network
  for a while, as behind a firewall, comes back without announcing itself.
- Each cached record of a found member (its PTR, SRV, TXT and host addresses) is queried
  again at 80, 85, 90 and 95 percent of its lifetime, plus 0 to 2 percent at random.
- Received records are kept only if relevant: PTR of the service, SRV/TXT of an instance
  whose first label is a device ID, A/AAAA of `cb-<device ID>.local`. Their TTL is capped at
  what Clipboard Bridge itself uses (4500 s for PTR and TXT, 120 s otherwise). A goodbye expires the
  record after 1 s; a cache-flush record expires older records of its name and type after
  1 s.
- A member is found when a live PTR names an instance that has a live SRV; its addresses
  are the live A/AAAA records of the SRV target that would be published. TXT is optional.

### The holder of `clipboardbridge.local`

Election (`electLocked`, `internal/service/members.go`): a full member takes part when it
holds the iPhone CA key and its holder setting is not `never`; its priority is `1` (first)
or `2` (fallback), and it publishes it as `h`. With the setting `auto`, the default, a
machine with a battery of its own (a laptop: on Linux a power supply of type `Battery` whose
scope is not `Device`, on macOS `pmset -g batt` listing `InternalBattery`, on Windows
`GetSystemPowerStatus` with a system battery) gets `2` and any other `1`; `first` and
`fallback` set it, and `cbb holder` changes the setting (state file `holder`). It holds
`clipboardbridge.local` when no connected peer with role `full` whose discovered TXT has an
`h` comes before it: a lower priority number, or the same with a lower device ID. A member
alone holds it at once. Members without the iPhone CA key never hold it: in a group whose
root is the phone none has it. The election runs whenever the set of connected peers or
what discovery finds changes, so a holder that leaves with a goodbye is
replaced at once and one that falls silent after the 15-second timeout. Two holders for a
moment are harmless. Only a member that holds the iPhone CA key MAY publish `h` or answer for
`clipboardbridge.local`.

## 4. Member protocol

Source: `internal/node`, `internal/clip`, `internal/group/tls.go`,
`internal/service/members.go`.

### Who dials whom

- A full member (Linux, FreeBSD, Windows or macOS) MUST dial every found full member whose device ID is
  greater than its own and whose `g` matches its group tag; the other side accepts. When no
  connection to a found full member with a lower device ID has been up for 30 s, it dials
  that one as well, since a firewall may keep the other from reaching it. Of two
  connections between the same two members, the one the lower device ID dialed stays: a
  member MUST refuse a new connection when the one the lower ID dialed is up and the new one
  is not that, and otherwise the new one replaces the old. It MUST NOT dial a lite member
  (TXT `r=lite`): they dial it.
- A lite member MUST dial every found full member with a matching `g`, and every found lite
  member whose device ID is greater than its own; it accepts the others and phones.
- A phone app MUST dial every found member with a matching `g`. Phones accept nothing and
  never connect to each other; so a phone syncs with a lite member or any one computer with
  no other on. A phone that is the group's hub is the exception: while its app is open it
  accepts members on the home network and through the tunnel, publishes `r=phone`, and the
  other phones dial it; the full and lite members do not, since it dials them.
- Members on another network than the home one (another subnet, where mDNS does not reach)
  reach the hub through the group's WireGuard tunnel (section 11; design.md, "Sync away from
  home"); so do the phone apps and the lite member on Linux, as clients. A lite member can
  be given a member's address with `-peer`; it MUST NOT dial an address outside the home network
  (private IPv4, unique-local and link-local IPv6, loopback), so away from home it reaches
  the group only through the tunnel.
- A computer that joined at an address the user gave (`cbb pair -code ADDRESS`, as through
  an SSH forward or a VPN) also dials the member that admitted it at that address, whatever
  the rules above say, while discovery does not find that member and no other connection to
  it is up. It keeps doing so, with the same waits, until it holds the hub's tunnel offer
  (section 11) or the service stops; the address is not stored.
- Addresses come from discovery; a member MUST NOT authenticate a peer by resolving a
  `.local` name, since the certificate, not the name, says who the peer is. They are tried IPv4
  first, then routable IPv6, then link-local IPv6. After a round of failures the dialer waits
  1 s, doubling to 30 s; a connection that lasted more than 30 s resets the wait.
- TCP keepalive is off; the protocol has its own heartbeat.

### TLS

- TLS 1.3 only ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)): an implementation MUST
  NOT negotiate an earlier version. ALPN `clipboardbridge/2` on both sides. Both sides
  present their member certificate (leaf only), with the admin CA's certificate after it
  when an admin issued it (section 10).
- Every implementation MUST support the key exchange group `x25519`, the cipher suite
  `TLS_AES_128_GCM_SHA256` and the signature scheme `ecdsa_secp256r1_sha256`, since the
  certificates' keys are P-256; it MAY offer more. The lite member offers only these, with
  `TLS_CHACHA20_POLY1305_SHA256` beside the suite. The same holds for every TLS connection of
  this document (sections 6, 13 and 14).
- Server: MUST require and verify a client certificate from the group's CAs; session tickets
  off, so a connection never resumes without the peer's certificate.
- Client: verifies the server against the group CA with server name `cb-<peer ID>.local`,
  where the peer ID is the one found in discovery, and MUST check that the certificate names
  exactly that device.
- Both sides MUST check the peer as in section 2 and against the records (section 10), and
  that the negotiated version is TLS 1.3 and the ALPN protocol is `clipboardbridge/2`. A
  connection to one's own device ID is closed.
- The handshake must finish within 10 s, counted from its start rather than from each read;
  an implementation SHOULD close one that does not.
- A lite member listens on the member port for the member protocol only: TLS with ALPN
  `clipboardbridge/2`, from home network addresses, at most 16 handshakes at once. It has
  no pairing window and no iPhone endpoints.
- The member port tells its connections apart by their first bytes. One that does not start
  with a TLS handshake record (0x16) is plain HTTP for the profile (section 7) while an
  iPhone pairing window is open, and is closed otherwise. Over TLS, a ClientHello that
  offers `clipboardbridge-pair/2` gets the pairing configuration (section 6), whether or not a
  window is open; one that offers `clipboardbridge/2` the member configuration; any other, on a
  member that serves the iPhone, the iPhone endpoints' (section 7, ALPN `http/1.1`).
  The connections passed on to the iPhone endpoints and to the profile are bounded while they
  are open: 32 at a time, at most 4 from one IP address; a connection over a limit is closed
  at once, and one idle for 30 s is closed.

### Framing

Each frame is a 4-byte big-endian length followed by that many bytes of a JSON object (UTF-8,
no trailing newline). A frame MUST NOT exceed 7 MiB (7 340 032 bytes); a larger length closes
the connection. The Go code writes JSON without HTML escaping; receivers MUST accept any valid
JSON, and MUST close a connection whose frame is not a JSON object. Every number in a frame,
in members the receiver does not know too, is an integer written as in signed bodies
(Conventions, "Signed bodies"): no `-0`, fraction or exponent, in the range of a 64-bit signed
integer; a frame with another number is not a message. A length with its top bit set (0x80000000) marks a binary `chunk` frame instead, which
carries content of images and files ("Content", below) and comes only to a member that sent
`get`.

Message object:

| Field | Type | In | Meaning |
|-------|------|----|---------|
| `t` | string | all | `hello`, `event`, `ping`, `bye`, `cert`, `records`, `admin`, `phone_ca`, `tunnel` or `hubs` (section 11), `command` or `result` (section 15), `evidence` (section 17), `credentials` (section 18), `release` (section 16), `get` or `missing` ("Content", below) |
| `role` | string | hello | `full` (a computer with the service: Linux, FreeBSD, Windows or macOS), `phone` (a phone app) or `lite` (a lite member) |
| `hello` | object | hello | Hello (below) |
| `event` | object | event | Event (below) |
| `cert` | string | cert | a renewed member certificate for the receiver, DER in base64 (section 2) |
| `issuer` | string | cert | from an admin phone or computer: its admin CA, which issued `cert`, DER in base64; absent when a root did (section 10) |
| `records` | array | records | signed records (section 10) |
| `admin_ca` | string | admin | from the group's root, a phone or a computer: the receiver's admin CA, for the admin key its hello offered, DER in base64 (section 10, "Admins") |
| `phone_ca` | string | phone_ca | from the root or an admin of a group a computer created: the group's iPhone CA, DER in base64 (section 10, "Admins") |
| `phone_ca_key` | string | phone_ca | with `phone_ca`: its key, PKCS #8 DER in base64 |
| `evidence` | object | evidence | an attestation of one of the sender's keys (section 17, "Evidence") |
| `credentials` | array | credentials | the group's server credentials the sender keeps (section 18) |
| `release` | object | release | the newest signed release the sender holds: `keys`, `channel` and `release`, each a file of section 16 as published (section 16, "In the group") |
| `get` | object | get, missing | a range of a part of images or files: Get ("Content", below) |
| `tunnel` | object | tunnel | from the group's hub: its offer for the tunnel key the receiver's hello carried (section 11) |
| `hubs` | object | hubs | what a hub shares with the group's other hubs (section 11, "Several hubs") |
| `command` | object | command | a record envelope: a command an admin signed for the receiver (section 15) |
| `result` | object | result | the answer to a command (section 15) |

```json
{"t":"hello","role":"full","hello":{"os":"linux","wall_ms":1761024000000,"current":{"id":"9f0c...","origin":"3b1e...","time":"1761023990000.0","age_ms":10000,"kind":"text","text":"hello"}}}
{"t":"event","event":{"id":"77aa...","origin":"3b1e...","via":"phone","time":"1761024001234.2","age_ms":15,"kind":"secret","text":"hunter2"}}
{"t":"ping"}
{"t":"bye"}
{"t":"cert","cert":"MIIB..."}
```

### Message order

1. After the TLS handshake each side MUST send its hello first, without waiting for the other's.
2. Then events follow, in any number, interleaved with pings, records messages, `admin`,
   `phone_ca`, `tunnel`, `hubs`, `credentials` (section 18), `command` and `result`
   messages, `evidence` (section 17), `release` (section 16), `get`, `missing` and `chunk`
   frames ("Content", below), and at most one `cert`.
3. A side that has written nothing for 5 s MUST send `ping`. Every frame written resets that
   timer.
4. A side that stops (service stop, Rejoin) SHOULD send what is queued and then `bye`, within
   one second, and close the socket. Receiving `bye` ends the connection without an error.

Rules for the receiver:

- The first frame MUST be a hello with one of the roles; otherwise the receiver MUST close
  the connection. A hello whose `hello` object does not decode closes the connection. A
  `current` that does not decode (for example an unknown `kind` or `via` from a newer
  version) MUST count as no current event. A `current` that decodes but fails validation,
  or that is a secret with its text, closes the connection (`internal/node/node.go`).
- An `event` that does not decode or fails validation MUST be dropped; the connection stays.
- Unknown `t` values and `ping` MUST be ignored, so a newer peer can add messages.
- Timeouts: each frame must start arriving within 15 s of the previous one; once its length
  is known, the frame gets 15 s plus 1 s per full 16 KiB (16 384 bytes). Writes have the same
  allowance. A receiver MUST close a connection silent for 15 s.
- A new connection from a device replaces its old one, which is closed without a goodbye,
  unless the old one was dialed by the member with the lower device ID and the new one was
  not ("Who dials whom").
- A peer whose outgoing queue (256 messages) is full is disconnected; it gets the current
  event again in the next hello. An implementation MUST bound its queues.

Roles: a `phone` member dials every member, publishes nothing and is never dialed, except
while it is the group's hub: it then publishes `r=phone` (section 3) and other phones dial
it. A `lite`
member publishes itself with `r=lite`, dials the full members and accepts phones and lite
members with a lower device ID (above, "Who dials whom"); it never holds
`clipboardbridge.local`. A `full` member is any computer with the service, a Mac included:
any of them can create a group and be its root, or be made an admin. Only the root and the
admins admit devices, and only a member with the iPhone CA key holds the name.

### Hello

A member speaks one version of the member protocol, the one its ALPN names
(`clipboardbridge/2`); a release that changes the protocol so that an older member cannot
read it takes the next ALPN version, which is the oldest peer it takes, and a peer of
another version fails at the handshake. Within a version the hello says what the sender
supports by its fields and by `features`, never by the sender's release, so no rule here
depends on a version number.

| Field | Type | Meaning |
|-------|------|---------|
| `wall_ms` | integer | the sender's wall clock, milliseconds since the Unix epoch; for skew reports only (`cbb status` shows `skew_ms`); 0 or absent means unknown |
| `current` | Event or absent | the sender's current event with its age as of sending; for a secret only its mark (text `""`), whatever its age; absent when there is none |
| `records` | string or absent | the digest of the sender's records (section 10) |
| `name` | string or absent | the sender's device name, 1-64 bytes; a receiver ignores an invalid one |
| `os` | string or absent | the sender's operating system: `linux`, `windows`, `macos`, `ios`, `android` or `none` (firmware without one); shown, never trusted; a receiver ignores an unknown one. A watch's device record says `watchos` or `wearos` (section 10) |
| `admin_key` | string or absent | from a full member that is neither the root nor an admin yet, or an admin whose admin CA is from a root before the current one, outside a legacy group: the SubjectPublicKeyInfo of its admin key, DER in base64 (section 10, "Admins") |
| `phone_ca` | string or absent | from a member that holds the iPhone CA key: SHA-256 of that CA's SubjectPublicKeyInfo, in base64, so another admin knows whether to send it a newer one (section 10, "Admins") |
| `tunnel_key` | string or absent | the sender's WireGuard public key, 32 bytes in base64, for the group's hubs (section 11) |
| `tunnel_psk` | string or absent | always with `tunnel_key`, which a receiver ignores without it: the WireGuard preshared key the sender chose for its tunnels, 32 bytes in base64, which every hub of the group uses for it (section 11, "Several hubs") |
| `mode` | string or absent | the sender's sync mode: `own`, `shared`, `receive` or `send` (design.md, "Sync modes"); shown, never trusted; a receiver ignores an unknown one. It changes only what the sender itself does with its clipboard, so a receiver handles the sender's events the same in every mode |
| `device` | object or absent | what the sender says about its device: Device (below); shown, never trusted |
| `key_store` | string or absent | where the sender's keys live: `file`, `hardware` or `rootless` (section 17); shown, never trusted, except by the root that makes the sender an admin; a receiver ignores another value |
| `actions` | array or absent | the names of the sender's quick actions that are on (section 15), at most 64, for the admins' buttons; a receiver drops a name that is not valid; absent from one with none on. A change shows at the next connection |
| `release_seq` | integer or absent | the `seq` of the channel file of the newest signed release the sender holds (section 16, "In the group"); absent when it holds none |
| `release_keys_seq` | integer or absent | with `release_seq`: the `seq` of that release's `keys.json`; absent when it holds none |
| `features` | array of strings or absent | what the sender supports beyond the protocol of its ALPN version, each name once: `media` from a member that serves the content of media events ("Content", below), so others may send it `get` (the lite member serves none). A receiver reads the first 32 names and ignores those it does not know, so a later release adds a feature without a new ALPN version |
| `seal` | string or absent | the sender's public key for sealed messages, 1216 bytes in base64 (an X-Wing key, `internal/seal`), which the group's root puts in the sender's device record (`seal`, section 10) so that commands for it can be sealed (section 15); a key of another size is ignored; absent from the phones for now |

### Device

The `device` of a hello, for the apps' device pages and icons. Every field is optional; a
receiver drops each one that is invalid and keeps the rest, and a `device` that does not
decode counts as absent. It is sent on every connection, so it follows updates of the system
and of the program.

| Field | Type | Meaning |
|-------|------|---------|
| `form` | string or absent | `laptop`, `desktop`, `phone`, `tablet`, `tv`, `board`, `server`, `router`, `console`, `watch`, `retro` or `other`; an unknown one is dropped |
| `os_version` | string or absent | the system's version as the user knows it (`15.1`, `11 (build 26100)`, `Debian GNU/Linux 13 (trixie)`), 1-32 bytes without control characters |
| `version` | string or absent | the sender's own version (`0.5.0`), the same limits |
| `mac` | string or absent | the MAC address of the network card on the home network, six lowercase hex bytes with colons; phones send none, as their systems hide it |

### Event

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | event ID, 32 lowercase hex characters |
| `origin` | string | device ID of the member that made the event |
| `via` | string | `copy` (copied on that member), `phone` (sent from a phone: the app, iPhone or Android, or the iPhone shortcut's button) or `universal-clipboard` (reached a Mac through Universal Clipboard). Omitted for `copy`; absent means `copy`. Receivers also take `iphone`, the name of `phone` before phones other than the iPhone |
| `time` | string | hybrid timestamp `"<wall>.<logical>"` (section 5) |
| `age_ms` | integer | milliseconds since the copy, as of the moment the frame is written |
| `kind` | string | `text`, `secret` or `media` (images or files, from 0.6); always present |
| `text` | string | the text; `""` only in the mark of a secret, and in media without a plain-text alternative |
| `media` | object | in a `media` event only: its Manifest ("Media", below) |

Validation (`Event.Validate`), which a receiver MUST apply: `id` and `origin` are 32 lowercase hex characters; `time` is
not `0.0` and its wall time is at most 253402300799999; `kind` and `via` are known;
`age_ms` is not negative; a `media` event has a valid manifest and no other has one; and,
unless the event is a mark (kind `secret` with empty text), `text` is non-empty, at most
1 MiB (1 048 576 bytes) and valid UTF-8, except that in a `media` event it may be empty and is
at most 256 KiB (262 144 bytes). Unknown fields are ignored.

### Media

A `media` event (design.md, "Images and files") carries a manifest of its content instead of
the bytes, so it travels in events and hellos like a text and the sync model of section 5
applies unchanged. Its `text` is a plain-text alternative, such as the text a browser copies
next to an image, or `""`.

Manifest:

| Field | Type | Meaning |
|-------|------|---------|
| `size` | integer | the parts' sizes together, at most 1 GiB (1 073 741 824 bytes); it MUST equal the sum of the parts' `size` |
| `parts` | array | 1 to 10 000 Parts |

Part:

| Field | Type | Meaning |
|-------|------|---------|
| `type` | string or absent | clipboard data: `image/png`, `image/jpeg` or `text/html`, each at most once, so three parts at most today; an unknown type is refused, and the limit for types added later is 8 |
| `path` | string or absent | a copy of files: the file's or folder's path, names joined by `/`, each path once, compared byte for byte (case matters) |
| `dir` | bool or absent | with `path`: `true` for a folder, which has no `size` or `sha256`: the field is absent or null, never an empty string |
| `size` | integer or absent | the part's bytes; absent means 0 |
| `sha256` | string | the SHA-256 of the part's bytes, 32 bytes in base64; absent only for a folder |

A manifest holds either clipboard data (every part has `type`) or files (every part has
`path`), never both. A path is at most 4096 bytes, and all paths together at most 512 KiB; a
file's path does not go through another file. Each name in a path is valid UTF-8 of 1 to 255
bytes, not `.` or `..`, without control characters (C0, DEL, C1) or `/ \ : * ? " < > |`, not
ending in a dot or a space, and not a name Windows reserves (`CON`, `PRN`, `AUX`, `NUL`,
`COM1` to `COM9`, `LPT1` to `LPT9`, in any case of ASCII letters, before the first dot), so
that every system can hold a received copy. Windows reserves a few more device names, which
a manifest may hold since earlier members send them: `COM0`, `LPT0`, `COM` or `LPT` followed
by `¹`, `²` or `³`, `CONIN$` and `CONOUT$`, and any of these names with spaces before the
first dot (`CON .txt`). A receiver MUST take such a name and write it with `_` after the part
before the first dot (`COM0_`, `CON _.txt`), and a sender SHOULD give its own names that form
before it sends them; `testdata/interop/media-names.json` holds the cases. The paths are
checked as the receiver writes them too: a receiver MUST refuse a manifest in which a name
grows past 255 bytes or a path past 4096 bytes that way, two paths become one (`COM0.txt`
and `COM0_.txt`), or a file becomes one that another path goes through. Every number in a manifest is an integer written as in signed
bodies (Conventions, "Signed bodies"): no `-0`, fraction or exponent. A receiver MUST refuse a
manifest that breaks any of these rules (the vectors of
`strict-generated.json` cite them as `manifests/size` and `manifests/parts`; a manifest is no
signed body, so only its numbers have the strict form),
and MUST NOT follow or create links when it writes a copy of files. The Go code is
`internal/clip/media.go`.

```json
{"t":"event","event":{"id":"77aa...","origin":"3b1e...","time":"1761024002000.0","age_ms":5,"kind":"media","text":"trip","media":{"size":1234,"parts":[{"path":"trip","dir":true},{"path":"trip/a.jpg","size":1234,"sha256":"AQEB..."}]}}}
```

A member that does not take images or files (the lite member) takes
the event like any other, so the group converges, forwards it, and writes only its `text`, as
a text, to its clipboard; with no text it keeps its clipboard.

### Content

A member that wants the bytes of a part asks a connected member whose hello says `media` for
them, by hash, and gets them in binary frames. The Go code is `internal/node/content.go`.

- `{"t":"get","get":{"sha256":"...","offset":0,"length":1048576}}` asks for `length` bytes
  of the part from `offset`. `length` is 1 to 1 MiB; a receiver drops a get that is not
  valid. A member MUST serve only parts it holds whole and has checked against their
  `sha256`. `length` 0 cancels every get of that part from the sender: what is queued is
  dropped and the range being served ends with its next chunk; a cancel of a part that is
  neither queued nor served changes nothing, and a receiver MUST NOT keep anything of it. A receiver keeps at most 64
  gets per connection and closes a connection that asks for more.
- `{"t":"missing","get":{...}}` answers a get for a part the member does not hold whole, or
  that it could not read, and ends that fetch.
- A `chunk` frame: the 4-byte length with its top bit set (the rest is the length of what
  follows), the part's SHA-256 (32 bytes), the offset (8 bytes, big-endian), the data's
  length (4 bytes, big-endian, at most 256 KiB), the data, and zeros up to a multiple of
  16 KiB, so the network learns less of the parts' sizes. A frame longer than a chunk with
  its padding (278 528 bytes) closes the connection.
- The server answers the gets of a connection in order, a chunk at a time, and writes a chunk
  only while no other message waits; chunks do not count against the 256-message queue, so
  events keep flowing during a large transfer.
- A fetch asks for at most 4 MiB ahead, in gets of 1 MiB, more as chunks arrive. Chunks come
  in order for each part; one at an offset the fetch does not wait for is left from a fetch
  that was cancelled and is dropped. The receiver MUST check the whole part against its
  `sha256` before it uses it, and MUST NOT write a copy to the clipboard until every part
  has arrived and matched, and continues from what it has after a reconnect.
- A fetch that ends before the part is whole, on a `missing`, its own cancel, or 15 seconds
  without a chunk, sends the cancel (`length` 0), so the ranges it asked for after that do not
  cross the next fetch; the member then asks again or asks another member.
- The receiver's limit decides: by default 100 MiB a copy at home and 25 MiB from a member
  reached through the group's tunnel (`cbb config max-copy` and `max-copy-away`, 1 MiB to
  1 GiB). A copy over it is not fetched, and `cbb status` says so.

Ages: a sender MUST add the time an event waited in its outgoing queue to `age_ms` (saturating at
the largest int64). A receiver caps `age_ms` at 365 days and turns it into a local time:
copied at = now - age. The hybrid clock is never used for durations.

## 5. Sync semantics

The parts marked "wire" are needed for convergence, and an implementation MUST follow them;
the rest is the Go engine's local policy, which another member SHOULD follow so that users
see the same behaviour. Source:
`internal/clip/clip.go`, `internal/hlc/hlc.go`, `internal/node/node.go`.

### Hybrid logical clock (wire)

A timestamp is `(wall, logical)`: `wall` is milliseconds since the Unix epoch, 0 to
253402300799999 (the last millisecond of 9999); `logical` is a uint32. Text form: the two
numbers in decimal separated by a dot, with no sign or spaces, for example
`1761024000000.3`. Order: by `wall`, then by `logical`. The zero timestamp sorts first and
MUST be refused in an event.

An event whose `wall` is more than 7 days (MaxAhead) ahead of the receiver's wall clock MUST
be refused, whatever `last.wall` is, so a chain of events, each within MaxAhead of the one
before, cannot carry the clocks further ahead: as a message it changes nothing (Go and
the lite member answer it with an error), and as a hello's current event it is taken as no
current event while the connection stays. Otherwise one device with a wrong date, or a removed
member, could hold every clock of the group at MaxWall for good. A device whose reference is
before 2026-01-01 (1767225600000), such as a board without a real-time clock that has not set
its time yet, refuses nothing.

- `Now()` for a local event: `pt = min(wall clock in ms, MaxWall)`. If `pt > last.wall`, then
  `last = (pt, 0)`; otherwise `logical` is incremented (if it is at its maximum, `last =
  (wall + 1, 0)`, stopping at MaxWall).
- `Observe(r)` for a received event, done only the first time its ID is seen:
  `w = max(last.wall, r.wall, pt)`; if `w` equals both `last.wall` and `r.wall`, `logical =
  max(last.logical, r.logical) + 1`; else if `w == last.wall`, `logical + 1`; else if
  `w == r.wall`, `last = r` then `logical + 1`; else `last = (w, 0)`.
- Persistence: a member MUST NOT issue a timestamp below one it issued before, also after a
  restart or a crash. The Go service does it so: before the clock reaches the last saved
  mark, it saves a new mark 10 000 ms ahead (file `hlc.mark` in the state directory, text
  form) and uses it as the floor after a restart. A saved mark more than MaxAhead ahead of
  a wall clock that reads 2026 or later is dropped at the restart, and the clock starts
  from the wall clock: the device's clock was ahead and has been set right, every member
  with a right clock refused those timestamps, and keeping the mark would leave its copies
  refused until real time caught up (Go and the lite member).

### Ordering and the current event (wire)

Event E is later than F when `E.time > F.time`, or the times are equal and `E.id > F.id`
compared as strings. The group's current event MUST be the latest event a member has seen,
so every member converges on the same one (last writer wins).

### Forwarding and reconciliation (wire)

A member remembers the last 4096 event IDs (at least that many SHOULD be kept). For each received event (from an `event` frame,
or the `current` of a hello), after validation:

1. If its ID was seen before: if it is the current event, the current event is a mark and the
   received one has the text, the text is taken (and forwarded); otherwise nothing happens
   (except the rejoin case below).
2. Otherwise: observe its timestamp, record the ID, and forward it to every other connection
   (also when it is older than the current event, and also a mark). A member MUST forward
   every new event so, whatever its sync mode: the mode decides only what it does with its
   own clipboard. If it is later than the
   current event, it becomes the current event.

A member MUST send its current event in every hello, so a newly connected pair converges at
once. A local event is sent to all connections; a mark (from a hello) travels in `event`
frames like any other event.

### Local events

- A new event gets a random ID, `origin` = own device ID, `time = Now()`, `age_ms` 0 at
  creation, and becomes the current event and the member's own clipboard text.
- Reported copies (a clipboard watcher, `copied`) make no event when: the member's own
  clipboard already holds that text; the text was written to the local clipboard within the
  last 10 s (echo; the last 8 written texts are remembered); `via` is
  `universal-clipboard` and the text equals the live current event (a Mac receiving the
  group's own text back); or the text is a remembered secret reported as `text` (a clipboard
  manager restoring it), which also clears the known local text.
- Deliberate actions (`copy` on the control socket, sending from a phone) always make an event;
  a text remembered as a secret is sent as a secret. The text is also written to the
  member's own clipboard unless it already holds it.

### Writing the member's own clipboard (local policy)

When an event becomes current (or a mark gets its text) it is written to the local clipboard
when all of these hold: the current event is live (it has a text, and a secret is younger
than the secret TTL); the local clipboard does not already hold the text; and either it was
copied at most 60 s ago (live window), or the member is within 30 s of its last Rejoin
(rejoin window) and made no copy of its own before it was back in sync. A write increments
the write sequence number (section 8).

- Rejoin: on service start, and when the machine slept (the clock that counts sleep moved
  more than 3 s further than the one that does not, checked every 2 s), the member closes all
  connections, waits up to 2 s for them to end, and then records the Rejoin; connections that
  start meanwhile wait. "Back in sync" means a hello was reconciled while at least one
  connection is up. A copy made while not in sync, or with no peers, is an offline copy; it
  blocks rejoin-window writes until the member is in sync and the window has closed.
- A current event that a hello brought before the member noticed it had slept is written
  when the same event arrives again inside the rejoin window while not yet in sync.
- Losing all peers without a sleep or restart does not open the rejoin window: such a member
  takes the group's text again only if it is live.

### Secrets (wire and local)

- Secret TTL: a secret event is usable for 60 s after the copy, judged by its age. After that
  it is neither the member's usable current text nor returned to the iPhone, but it stays the
  current event for ordering.
- Marks (wire): a hello MUST carry a secret only as its mark: the event with `text` `""`. A
  hello that carries a secret's text closes the connection. Full secret events travel in
  `event` frames.
- A member MUST NOT write a secret's text to disk, and SHOULD forget it 60 s after the copy.
- Secret memory (local): each member remembers keyed hashes (HMAC-SHA-256 with a random
  per-process key, memory only) of secret texts it sent, received or was told about by a
  watcher, up to 4096 entries for 12 hours. Such a text reported again as `text` makes no
  event; sent deliberately, it becomes a secret again.

## 6. Pairing a computer

Source: `internal/pair`, `internal/third_party/cpace`, `internal/service/socket.go`.

### Window

The root or an admin (section 10, "Admins"), or in a legacy group a Linux or Windows member
that holds the CA keys, opens a window with a six-digit code. The code MUST be drawn
uniformly at random, and MUST NOT be taken from a command line, where other users of the
machine could read it. While it is open
the member publishes `p=1`. The window lives 5 minutes (counting sleep); an attempt that has
started may finish after that. One attempt at a time; another gets `busy`. The window MUST
close after a success or after the third failed attempt (`too-many`), so that a guesser gets
at most three online guesses per code. An attempt fails (counts)
when it fails after the member sent its CPace message; errors before that (bad AD, bad
certificate, a dropped connection) do not count. Each attempt has 30 s on both sides, and
the joiner's first message must arrive within 10 s of the TLS handshake. After 5 attempts
from one IP address that ended before they counted, the window answers that address `busy`,
so that one device on the network cannot hold the window for its whole life.

A window for a remote invitation (design.md, "Joining from another network") differs:

- Its password is the invitation's secret, at least 16 random bytes (128 bits), in place
  of the code. The joiner gets it from the invitation and never types it.
- It lives as long as the invitation, up to a day.
- Its joiner gets no CA keys, whatever its `os`.
- After Ta verifies, and before it makes the certificate, the member asks its admin to
  confirm the device: its name, `os`, device ID and key fingerprint (of the key of the
  joiner's TLS certificate, Conventions, "Fingerprints", as the joiner shows it). It sends frame 4
  only after a yes; a no sends `{"error": "declined"}` and counts as a failed attempt.
- Each attempt then has 30 s plus the time allowed for the admin's answer, on both sides.

### TLS

- Joiner (client): TLS 1.3, ALPN `clipboardbridge-pair/2`, presents its self-signed certificate
  (section 2) for the P-256 key it will keep, with its new device ID as CN; it does not
  verify the server's certificate during the handshake.
- Member (server): TLS 1.3, ALPN `clipboardbridge-pair/2`, presents its member certificate (leaf
  only), requires any client certificate, session tickets off. It MUST reject the connection
  unless the client sent exactly one certificate with a P-256 key and a device ID as CN that
  differs from its own.

### Channel binding and CPace

Suite CPACE-X25519-SHA512 of draft-irtf-cfrg-cpace-21, as implemented in
`internal/third_party/cpace`, with explicit key confirmation.

| Input | Value |
|-------|-------|
| Roles | joiner = initiator, member = responder |
| PRS (password) | the six ASCII digits of the code, or a remote invitation's secret (its raw bytes) |
| CI (channel identifier) | `"clipboardbridge pair v2"` + one zero byte + SHA-256(member certificate DER) + SHA-256(joiner certificate DER); 23 + 1 + 32 + 32 = 88 bytes |
| sid | 32 bytes of TLS exporter output, label `EXPERIMENTAL-clipboardbridge-pair-v2`, empty context |
| ADa (joiner) | JSON `{"name":"<device name>","os":"linux"\|"windows"\|"macos"\|"ios"\|"android"}`; a phone with the app (`ios` for an iPhone, `android` for an Android phone) adds `"admin_key"`, its admin key's SubjectPublicKeyInfo (bytes, DER); a lite member adds `"role":"lite"` and may say `"os":"none"`; every joiner adds `"seal"`, its public key for sealed messages (bytes, 1216, as `seal` of the hello, section 4), which the admitting member puts in its device record (a phone puts its own in the record of itself it signs when it makes the group). A phone admits `ios` and `android` joiners as phones and records a lite member with role `lite`; a computer admits only `linux`, `windows`, `macos` and lite members |
| ADb (member) | JSON `{"device":"<member device ID>","group":"<group tag>"}` |
| Ya, Yb | 32-byte X25519 u-coordinates |
| Tags Ta, Tb | HMAC-SHA-512, 64 bytes |

The AD bytes are used exactly as they travel in the `ad` field. The member MUST check ADa: `os`
is `linux`, `windows` or `macos`, or `none` with `role` `lite` (an admin phone also takes
`ios` and `android`); `name` is 1 to 64 bytes of
printable UTF-8; `admin_key`, when present, comes with `ios` or `android` and is a P-256 key; `role`,
when present, is `lite`; `seal`, when present, comes from no phone and is 1216 bytes. A lite member (a Linux device without CA keys) gets
no CA keys and is recorded with role `lite`. Go members
take no `ios` joiner: only admin phones admit phones.

### Frames

Frames are a 4-byte big-endian length and a JSON object of at most 64 KiB (65 536 bytes).
Fields, all optional, each frame using some: `msg` (bytes), `ad` (bytes), `tag` (bytes),
`welcome` (object), `error` (string), `ok` (bool).

| # | Direction | Frame |
|---|-----------|-------|
| 1 | joiner to member | `{"msg": Ya, "ad": ADa}` |
| 2 | member to joiner | `{"msg": Yb, "ad": ADb}`, or `{"error": code}` |
| 3 | joiner to member | `{"tag": Ta}` |
| 4 | member to joiner | `{"tag": Tb, "welcome": Welcome}`, or `{"error": code}` |
| 5 | joiner to member | `{"ok": true}`, or `{"error": "refused"}` |

- The member always reads frame 1 before it answers, also when it refuses at once (no window:
  `closed`; busy; expired; too many).
- The member sends frame 2 before it processes Ya. If processing Ya fails, or Ta does not
  verify (`wrong-code`), it sends `{"error": code}` instead of frame 4.
- The joiner MUST check Tb and that a welcome is present. Once it has sent frame 3 the code is
  spent: a joiner that fails after that MUST NOT try the same code at another address.
- A member MUST NOT send a certificate before Ta verified. Sending frame 4 is the point of
  no return: the window records the device and closes,
  whether or not frame 5 arrives. Frame 5 only reports whether the joiner stored its
  identity.

Error codes: `wrong-code`, `closed`, `busy`, `expired`, `too-many`, `refused`, `declined`
(the admin did not confirm the device of a remote invitation), `taken` (the joiner's device
ID is in the group already). A joining device picks its own device ID, so the member refuses
one that a `device` record names, with any key, or that a connected member or the member
itself has, after the joiner's first frame and before its own CPace message; this does not
count as a failed attempt, and the joiner joins again with a new ID. An unknown
code MUST be treated as `refused`. Errors carry no free text, and an implementation MUST NOT
show free text from a peer that has not proved it knows the code, so an unauthenticated
peer cannot put words in front of the user.

### Welcome

| Field | Type | Present |
|-------|------|---------|
| `cert` | bytes, DER | always: a member certificate from the group CA, or from `issuer`, for the key of the joiner's TLS certificate and its device ID |
| `issuer` | bytes, DER | only from an admin phone or computer: its admin CA (section 10), which issued `cert` |
| `group_ca` | bytes, DER | always: the group's first root, which names the group |
| `roots` | array of bytes, DER | only in a group that claims handed to new roots (section 10, "Handing the group over"): those roots in order, the current one last |
| `records` | array of record envelopes (section 10) | the group's records (section 10), so the new device takes its peers at once; always with `roots`, which they must lead to; otherwise left out when they do not fit in the frame, and the new device gets them over connections that carry records only |
| `claim_times` | array of `{record, ms}` | with `records` that hold a claim: when the admitting member first held each claim, in Unix milliseconds; the joiner takes a time that is earlier than its own and not in the future, so a claim that took effect there takes effect on the joiner too (section 10, "Handing the group over") |
| `admin_ca` | bytes, DER | only to a phone (`ios` or `android`) that sent `admin_key`, from the root phone: the joiner's admin CA for that key (section 10) |

The joiner MUST check: the tag of `group_ca` equals ADb `group`; `issuer`, when present, is an
admin CA under `group_ca` or one of `roots` (section 10); the member's TLS certificate is
signed by `issuer` or by one of those roots and names ADb `device` (section 2); `cert`
verifies to one of them, through `issuer` when present; `roots` are exactly the path that
`records` lead to from `group_ca` (section 10, "The state"), so an admin cannot make a joiner trust a
root of its own; the joiner keeps `records` in its record set before it keeps the identity, keeps
`roots`, and keeps `issuer` to send in its handshakes.

The Welcome carries no CA key: no device gets the key of the group CA or of the iPhone CA by
joining. A new computer is a member without CA keys: it publishes and listens, but admits
nobody until the root makes it an admin (section 10, "Admins"), and until then serves no
iPhone and never holds `clipboardbridge.local`. A joiner reads a Welcome by the fields of this
table only; the `group_ca_key`, `phone_ca` and `phone_ca_key` of the legacy groups (section 2)
are gone with them.

The Welcome carries no group state and no token hashes: tokens need no hashes (section 7),
and the group state arrives in the first hello.

A phone that joins MUST check the same, and also: `group_ca` is a phone's root (path length 1);
there are no CA keys; `admin_ca`, when present, is an admin CA under `group_ca` for the key
it sent in `admin_key`, its CN naming its own device ID.

### Joining side behaviour

Without an address the joiner browses up to 10 s for a member with `p=1`, refuses when more
than one announces a window, and tries that member's addresses in order, at most three,
stopping after the first attempt whose code was spent. A whole join is bounded by 2 minutes
plus the browse time.

### The joiner listens (for the phone)

`cbb pair` without `-code` turns the direction round, so that the device that scans
the QR code dials the computer, and nothing is announced:

- The joiner listens on its member port, which nothing holds while it is in no group, when
  free, otherwise on a port the OS chooses (all
  addresses; only home network addresses may connect, as on the member port) for up to
  5 minutes, and shows the QR code
  `clipboardbridge://join?code=<code>&addr=<host:port>&fp=<fingerprint>` (section 7): its
  addresses that mDNS would publish, IPv4 first, without link-local ones, at most four; and
  the fingerprint of its self-signed certificate's key (Conventions, "Fingerprints"),
  percent-encoded.
- The member dials and is the TLS client. It presents its member certificate and MUST
  check that the server sent exactly one certificate whose fingerprint is `fp`, with a
  P-256 key and a device ID as CN. The joiner (server) requires any client certificate and
  checks it as in the other direction, through the exchange and the Welcome.
- The CPace inputs, roles and the Welcome are those above. The member, which dialed,
  confirms first:

| # | Direction | Frame |
|---|-----------|-------|
| 1 | joiner to member | `{"msg": Ya, "ad": ADa}` |
| 2 | member to joiner | `{"msg": Yb, "ad": ADb, "tag": Tb}` |
| 3 | joiner to member | `{"tag": Ta}`, or `{"error": "wrong-code"}` when Tb does not verify |
| 4 | member to joiner | `{"welcome": Welcome}`, or `{"error": code}` |
| 5 | joiner to member | `{"ok": true}`, or `{"error": "refused"}` |

- A device that does not know the code gets the joiner's refusal and nothing to test
  guesses with, so a failed attempt never spends the code: the joiner takes further
  attempts, one at a time, and gives up after the third wrong code or the 5 minutes.
- On the member the window counts attempts as above. It is not announced (`p` stays unset)
  and takes no pairing connections on the member port, so the code is good only against the
  computer whose certificate `fp` names.
- A phone joins a phone group the same way (ClipboardBridgeKit's `PairingJoiner`): it listens
  while its "Join a group" screen is open, shows this QR code, and an admin phone scans it
  and dials. The phone makes its admin key before it listens and sends it in ADa; the root
  phone, when the user makes the new phone an admin (the default), answers with `admin_ca`.
  A phone that is not the root makes no admins, so its welcome has no `admin_ca`.

## 7. iPhone endpoints

Source: `internal/phone`, `internal/service/iphone.go`.

These endpoints serve the iPhone shortcut, for an iPhone without the app, so their names keep
the word: the iPhone CA, `to_iphone` and `from_iphone`. A phone
with the app, iPhone or Android, is a member (section 4) and uses none of them.

### iPhone endpoints on the member port

The shortcuts name `https://clipboardbridge.local:8764`, so they work only with the default
member port; up to 0.2.0 these endpoints had their own port, 8765.

HTTPS, TLS 1.3 only, no client certificate; the server presents the `clipboardbridge.local`
certificate followed by the iPhone CA certificate. Server timeouts: 10 s for the request
header, 30 s for reading and writing; headers at most 16 KiB. The client MUST trust only the
iPhone CA for `clipboardbridge.local`. Paths are exact; others get 404.

### Tokens

```
token = "cb1." base64url_nopad( phone_id[16] || HMAC-SHA-256(K, phone_id)[0:16] )
K     = HKDF-SHA-256(IKM = iPhone CA private scalar (32 bytes, big-endian),
                     salt = SHA-256(iPhone CA certificate DER),
                     info = "clipboardbridge iPhone token v1", length 32)
```

The root and every admin of a group a computer created hold the iPhone CA key, so each
checks any token without a stored list: trim spaces, require the prefix `cb1.`, decode to
exactly 32 bytes, and compare the MAC in constant time, which a server MUST do. A new iPhone CA ends every token. The Authorization header carries
`Bearer <token>` (scheme in any case) or the bare token.

### POST /sync

Request body (at most 7 MiB), with `Authorization`:

| Field | Type | Meaning |
|-------|------|---------|
| `v` | number or string | MUST be `1` |
| `text` | string | the iPhone clipboard; may be empty |
| `secret` | bool, optional | make a secret event |

Reply, always HTTP 200, `Content-Type: application/json`, `Cache-Control: no-store`:

| Field | Type | Meaning |
|-------|------|---------|
| `v` | integer | 1 |
| `direction` | string | `to_iphone`, `from_iphone`, `none`, `unpaired` or `error` |
| `copy` | string | the text for the iPhone clipboard; omitted when empty |
| `expires_in` | integer | seconds a secret copy may stay: max(1, floor((60 s - age) / 1 s)); 0 for normal text; always present |
| `message` | string | a human message for a notification; never contains a secret |

```json
{"v":1,"direction":"to_iphone","copy":"some text","expires_in":0,"message":"Copied to the iPhone"}
```

Order of checks: not POST gives `error`; a missing or unknown token gives `unpaired` (the
client MUST delete its token, so the next run pairs again); a body over 7 MiB, invalid JSON
or `v` other than 1 gives `error`. Then the direction, in order (`phone.decide`):

1. The group's current event is live, has `via` `copy`, is younger than 45 s and differs from
   `text`: `to_iphone` with that text (and its kind's expiry).
2. `text` is non-empty and differs from both the current event's text and the member's own
   clipboard text: a deliberate event with `via` `phone` (secret if `secret` is true, or if
   the text is a remembered secret), also written to the member's own clipboard;
   `from_iphone`.
3. The member's own clipboard holds a live text that differs from `text`: `to_iphone` with it.
4. Otherwise `none`.

The client writes `copy` to its clipboard only on `to_iphone`, for this device only (not
through Universal Clipboard). A server MUST NOT put a secret's text in `message`.

### GET and POST /pair

Needs no token. An iPhone pairing window is opened by `pair-phone` on the control socket, on
the holder of `clipboardbridge.local` only; it has the limits of a computer window (5 minutes,
one success, three wrong codes; any code that is not six digits counts as wrong).

- `GET /pair`: an HTML form that posts the field `code`.
- `POST /pair` with a `Content-Type` that does not contain `json`: the form field `code`;
  the answer is an HTML page that shows the token or the error.
- `POST /pair` with a `Content-Type` that contains `json`: body (at most 4096 bytes)
  `{"v": 1, "code": "123456"}`; `v` may be a number or a string; `code` may be a string or a
  number (a number is left-padded with zeros to six digits). Reply, always HTTP 200:

| Field | Type | Meaning |
|-------|------|---------|
| `v` | integer | 1 |
| `ok` | bool | the iPhone is paired |
| `token` | string | the new token; only when `ok` |
| `message` | string | a human message |

The shortcut's token gives only `/sync`. Up to 0.4 a `POST /admit` let a paired shortcut add
a computer; it is gone, and requests to it get HTTP 404. Computers join through the phone
apps or `cbb pair`. `cbb pair -phone -new-token` revokes the token of every shortcut (one
revocation record naming their keys, section 10) before it opens the window, so a copied
token stops working and the iPhone gets a new one.

### Profile on the member port

Plain HTTP on the member port (up to 0.2.0 its own port, 8766), only while an iPhone
pairing window is open, same address restriction:

| Path | Content |
|------|---------|
| `GET /` | an HTML page with the steps; it sends the user to the terminal of `cbb pair -phone` for the iPhone CA fingerprint and does not show it, since it comes over plain HTTP |
| `GET /clipboardbridge.mobileconfig` | the configuration profile, `application/x-apple-aspen-config` |
| `GET /clipboardbridge.shortcut` | the signed sync shortcut, `application/octet-stream` (404 if the build has none) |

The profile has the fixed identifier `io.github.hunterewok.clipboardbridge` with one payload of
type `com.apple.security.root` (identifier `io.github.hunterewok.clipboardbridge.ca`) carrying
the iPhone CA certificate. Its UUIDs are derived from SHA-256 of the CA certificate, so a new
CA's profile replaces the old one.

Requests from outside the home network get HTTP 403 with a text body, not a JSON reply with
status 200 (`internal/service/iphone.go`).

## 8. Local control socket

Source: `internal/control`, `internal/service/socket.go`, `internal/connector/connector.go`.

### Socket and permissions

| Platform | Path | Group |
|----------|------|-------|
| Linux | `/run/clipboardbridge/control.sock` | `clipboardbridge` |
| OpenWrt, FreeBSD | `/var/run/clipboardbridge/control.sock` | `clipboardbridge` |
| macOS | `/Library/Application Support/clipboardbridge/control.sock` | `_clipboardbridge` |

`CBB_SOCKET` overrides the path for clients. The socket is a Unix stream socket with
mode 0660, made in a private temporary directory and renamed into place, so only root, the
service's user and members of the group can connect; secrets travel only to them. An
implementation MUST NOT let any other local user connect, and MUST NOT listen for these
operations on a network socket. On Windows
it is `%ProgramData%\clipboardbridge\run\control.sock`, in a directory whose protected access
list lets in the system, administrators, the service's account and the group.

Next to it the service listens on the **admin socket** `admin.sock` (on Windows
`run\admin\admin.sock`, in a directory of its own, which the service makes before the control
socket's and makes again at each start unless the system, the administrators or the service owns
it), with mode 0600: only root and the
service's user (on Windows the system, administrators and the service's account) can
connect. `CBB_ADMIN_SOCKET` overrides its path for clients. The control socket takes only
`copy`, `paste`, `copy-media`, `copied-media`, `paste-media`, `config`, `status`, `devices`, `release`, `release-get`, `keys` (from root only) and `watch` (with
the watcher's `copied`, `clipboard`, `injected` and `acted`) and refuses every other operation with an error; the admin socket takes them
all, and MUST be the only way to them. So a program of a user in the group can use the clipboard but cannot admit, remove,
rename, freeze or make admin a device, take over, or change sync away from home and
the holder setting. `cbb` dials the socket each operation needs. The lite member does the same
with its own two sockets, but its control socket takes fewer: no `copy-media`, `copied-media`,
`paste-media`, `config`, `release`, `release-get` or `keys`, and of the watcher's reports no
`acted`.

### Framing

Each message is a JSON header on one line ending in `\n`, at most 64 KiB, followed by exactly
`len` bytes of raw payload (at most 1 MiB + 64 bytes), usually a clipboard text in UTF-8.
Header fields (all omitted when empty):

| Field | Type | Meaning |
|-------|------|---------|
| `op` | string | the operation |
| `kind` | string | `text` (default), `secret`, or `media` for the images or files of a copy |
| `via` | string | `copy` (default), `phone` or `universal-clipboard`; `iphone` is taken as `phone` |
| `seq` | integer | order of writes |
| `ttl_ms` | integer | how long a written secret may stay in the clipboard |
| `len` | integer | payload length |
| `error` | string | a failed request, human text |
| `done` | bool | the last answer to a request |
| `code` | string | pairing code |
| `fingerprint` | string | iPhone CA fingerprint |
| `address` | string | `host:port` |
| `name` | string | a device name, or a phone ID |
| `expires` | integer | seconds a window stays open; for a listening `join`, seconds to wait (at most 300) |
| `listen` | bool | `join`: listen for a member instead of dialing one |
| `addrs` | array of strings | the first answer of a listening `join`: where it listens |
| `port` | integer | `away hub`: the UDP port; 0 for 8764 |
| `consent` | bool | `away on`: the user agreed to the warning about keys in files; `join` with an invitation and `admin` of a device with keys in files: the user agreed to the warning; `remote add`: a Roku over plain HTTP; `answer`: yes |
| `device` | string | `mode`, `paste-on`, `paste-receive`: another device, by name or device ID; `remote`: the TV, by its name |
| `new_name` | string | `rename`: the device's new name; `remote add`: the TV's name here |
| `method` | string | `paste-on`, `inject`: `paste` (the clipboard and the paste keys, the default) or `type` |
| `enter` | bool | `paste-on`, `inject`: press Enter after the text; `paste-receive on`: allow that |
| `console` | bool | `paste-receive on`: allow text consoles and root's tmux |
| `no_lock_check` | bool | `paste-receive on`: let a target paste where nothing tells whether the session is locked, which it refuses otherwise; `inject`: that this device allows it |
| `all` | bool | `paste-receive off`, `actions-off`: on every device of the group |
| `actions` | array | `action-set`: one quick action, `{name, on?, by?, any_key?, command?}`: on or off, the admins it lets run it (by key), any admin, and for an action of the user's own its program and arguments; in `status`, this device's actions, the presets first |
| `inject` | string | `watch`: the remote paste target the watcher offers, `desktop`, `tmux` or `console` |
| `paste_only` | bool | `watch`: the watcher holds no clipboard and only pastes, like the Mac app |
| `images` | bool | `watch`: the watcher writes images, so the service sends it copies with images as a `write` of kind `media` |
| `files` | bool | `watch`: the same for copies of files and folders |
| `html` | bool | `watch`: the same for formatted text, a copy with a `text/html` part whose plain-text alternative is its text; such a watcher reports formatted text with `copied-media` and the text as the alternative, and the others get the text |
| `act` | bool | `watch`: the watcher runs the quick actions in its session: the presets on a Mac and on Windows, the user's own actions everywhere |
| `command` | array | `act`, and `action-set`'s action: the program and arguments of the user's own action |
| `hubs` | array | `hubs`: the group's main hubs by name or device ID, in the order they serve |
| `refused` | bool | `injected`, `acted`: the target refused, rather than failed |
| `keys` | string | `inject` to a `desktop` watcher: the grant that its desktop connector hands the uinput helper; `keys`: that grant |
| `keyboard` | object | `keyboard on`: the Bluetooth keyboard's settings, `{layout?, rate?, pastes?}`; in `status`, also `{on?, connected?, visible_until_ms?, problem?}` |
| `status` | object | for `status` |
| `devices` | array | reserved |
| `part` | object | `copy-media`'s `part` messages and `paste-media`'s answers: `{type?, path?, dir?, size?}`, a part of images or files without its hash; `release-file` and `release-get`: the archive's `size` |
| `value` | string | `config`: the setting's new value; `remote add`: the TV's kind, `androidtv` (the default) or `roku`; `remote pastes`: `on` or `off` |
| `detail` | string | with `error`: the underlying error, which the client shows with error details on (`CBB_DEBUG=1`) |
| `new_token` | bool | `pair-phone`: revoke every shortcut's token first |
| `forwarder`, `forwarder_key` | strings | `away hub`: the forwarder's address and its key, 44 characters of base64 |
| `relay`, `relay_key` | strings | `away relay`: the relay's address and its key; needs `consent` |
| `obfuscate` | bool | `away hub`: speak AmneziaWG instead of plain WireGuard (section 11) |
| `vless` | bool | `away hub`: the clients reach the forwarder only over VLESS (section 11) |
| `invite` | string | the text of a remote invitation: made by `invite`, used by `join` (section 12) |
| `joining` | object | `invite`: a device to confirm before it is admitted, `{id, name, os, fingerprint}` |

A connection carries one request: the service reads the first message and dispatches on
`op`; an unknown `op` fails. Every answer has `op` `reply`. A failure is
`{"op":"reply","error":"...","done":true}`.

### Operations

| `op` | Request | Answers |
|------|---------|---------|
| `copy` | payload = text; `kind`, `via` | `{done}`. A deliberate action: always an event, also written to the member's own clipboard |
| `paste` | none | `{kind, done}` + payload = the member's own clipboard text; error `the clipboard is empty` when unknown or an expired secret, and one that names `cbb paste -o` for images or files without a text |
| `copy-media` | payload = the plain-text alternative, or none; then for each part `{"op":"part", part}`, followed for a file or clipboard data by `{"op":"data"}` messages whose payloads, at most 1 MiB each, are exactly its `size` bytes; last `{"op":"part", done}` | `{done}`: the parts are in the cache and the copy went to the group as a `media` event (section 4, "Media"), also written to the member's own clipboard. An error when the copy is over this device's limit, its manifest is not valid or the bytes do not come as said. `cbb copy FILE...` reads the files as the user and sends them |
| `copied-media` | as `copy-media` | as `copy-media`, but a watcher's report that its clipboard changed: the copy goes to the group as an event when the engine decides so (section 5) and is not written back to the member's own clipboard |
| `paste-media` | none | once every part of the member's own images or files (in mode `own` the group's) is in the cache, fetched first if it is not: `{kind: "media"}` + payload = the plain-text alternative; then for each part `{part}` and its bytes in answers of at most 1 MiB; last `{done}`. An error when the clipboard holds none, or they did not arrive. `cbb paste -o DIR` writes them |
| `config` | `{name?, value?}`: `max-copy` or `max-copy-away` and a size such as `200MiB` | `{status, done}`, with the setting saved first when `name` is given; `status.media` = `{max_copy, max_copy_away, fetching?, fetched?, from?, failed?}`, in bytes, also in `status` |
| `status` | none | `{status, done}`; `status` = `{device, group, role, os, holder, peers: [{id, role, os, skew_ms}], unreached?, port, cert_ends_ms, away?, version}`; `cert_ends_ms` is when this device's member certificate ends, in Unix milliseconds, `unreached` lists the members at home that could not connect to this one and synced only because it dialed them back, `port` is the member port; `away`, present while sync away from home is on: `{hub, port, endpoints, clients, hub_device, through, keys_in_file, error, detail, forwarder?, relay?}` (section 11); `forwarder`, on a hub with one: `{endpoint, registered, seen, error, detail}` (section 13); `relay`, on a device with one: `{endpoint, connected, online, error, detail}`, where `online` lists the other devices of the group on the relay and `through` tells whether a member connection runs through it (section 14) |
| `new` | none | `{status, done}`: the device creates a group and is its root (section 10). Only on a device in no group |
| `pair` | none | first `{code, expires: 300, address}` (the member port at the first private IPv4 address), then `{name: <joined device name>, done}` or an error. Only on the group's root or an admin; elsewhere the error names them. Hanging up closes the window |
| `pair-phone` | none | first `{code, expires: 300, fingerprint, address}` (the member port, where the profile is), then `{name: <phone ID>, done}` or an error. Only on a member that holds the iPhone CA (in a group a computer created, the root or an admin) and answers for `clipboardbridge.local`. Hanging up closes the window |
| `join` | `{code, address?}`, `{code, listen, expires}` or `{invite, consent}` | `{done}` or an error. Without `address` it browses for `p=1`. With `listen` it first answers `{addrs, fingerprint}` for the QR code, then `{done}` or an error when a member admitted it, or after `expires` seconds. With `invite`, the text of a remote invitation (section 12), it needs `consent` (sync away from home is turned on, and the device keeps its keys in files), first answers `{fingerprint}` (of this device's key, for the admin to compare), then `{done}` or an error. Hanging up cancels |
| `invite` | `{expires?}`: seconds, 3600 if absent, at most 86 400 | Only on the group's hub, when it can admit devices. First `{invite, expires}`: the invitation's text. Then, for each device that used it and proved it knows the secret, `{joining: {id, name, os, fingerprint}}`, which the client answers with `{"op": "answer", consent}` (`true` admits it); last `{name, done}` or an error. Hanging up cancels the invitation |
| `mode` | `{name, device?}`: `name` the sync mode, `own`, `shared`, `receive` or `send`; `device`, a name or device ID, for another device (on an admin) | without `device`: `{status, done}`, the mode saved and in effect; with it: `{done}` once that device answered `done` to the command (section 15), or an error with its reason. Only on the admin socket |
| `paste-on` | `{device, method?, enter?, kind?}` + payload = the text | `{done}` once that device answered `done` to the `paste` command this admin signed (section 15), or an error with its reason. The text is cleaned first (design.md, "Remote paste"). Only on the admin socket |
| `paste-receive` | `{name, enter?, console?, device?, all?}`: `name` `on` or `off` | `{status, done}`: `on` saves the switches of remote paste here, only for this device; `off` turns it off here, or with `device` or `all` on another or every device through `paste-off` commands. Only on the admin socket |
| `keyboard` | `{name?, keyboard?}` + payload for `type`: `name` `on`, `off`, `pair`, `type` or none | `{status, done}`: `on` saves the Bluetooth keyboard's settings and registers it with BlueZ (Linux only), `off` takes it off, `pair` makes it discoverable for two minutes, `type` types the payload on the connected device and answers once it is typed, none only answers the status. Only on the admin socket |
| `remote` | `{name?, address?, value?, new_name?, consent?, code?, device?}` + payload for `type`: `name` `add`, `code`, `cancel`, `remove`, `pastes`, `type` or none | `{status, done}`: `add` pairs with the TV at `address` (an Android TV or a Google TV shows a code; a Roku, `value` `roku`, needs `consent`, as its control is plain HTTP), `code` finishes that pairing within two minutes, `cancel` ends it, `remove` forgets the TV `device`, `pastes` sends the group's remote pastes to it or not, `type` types the payload into the field open on the TV, none only answers the status; `status.tvs` = `[{name?, kind, host, pastes?, pairing?}]`. An address outside the home network fails. Only on the admin socket |
| `rename` | `{name, new_name}`: `name` the device, by name or device ID | `{name, done}` with the old name: an admin signs a `device` record like the device's newest one with the new name (section 10). Only on the admin socket |
| `holder` | `{name}`: `auto`, `first`, `fallback` or `never` | `{status, done}`: the holder setting of `clipboardbridge.local` saved (state file `holder`), its priority published and the holder elected again (section 3, "The holder of `clipboardbridge.local`"). Only on the admin socket |
| `network` | none | `{status, done}`: the networks this device is on now become known ones, where it publishes itself and takes connections (`cbb network`). Only on the admin socket |
| `answer` | `{consent?}` | none: during a request that asks the user, such as a listening `join` waiting for a phone or an `invite` asking whether to admit a device, the client's answer; `consent` is yes |
| `action-set` | `{actions: [action]}`, exactly one | `{status, done}`: this device's user turns the quick action on or off and says who may run it (section 15); an action of the user's own carries its `command`. Only on the admin socket |
| `action-remove` | `{name}` | `{status, done}`: the user's own action `name` is removed; a preset cannot be, only turned off. Only on the admin socket |
| `action-on` | `{name, device}` | `{done}` once the member `device` answered the `action` command this admin signed (section 15), or an error with its reason. Only on an admin's admin socket |
| `actions-off` | `{device}` or `{all}` | `{status, done}`: every quick action is turned off on that device, or on every device of the group, through signed commands; this device's own at once. Only on an admin's admin socket |
| `release` | payload = the release in JSON, `{keys, channel, release}`, the three files of section 16 that `cbb update` fetched | `{done}`: the service checks the release as a `release` message (section 16, "In the group"), keeps it when it is newer than the one it holds, and passes it on to its peers |
| `release-file` | `{value, part}`: the archive's SHA-256 and its `size`, then its bytes in `data` messages | `{done}`: `cbb update` hands the service an archive of the release it holds (section 16), which keeps it only whole and matching its hash, to pass on to its peers. Only on the admin socket |
| `keys` | `{name, value, keys}`: `paste` or `enter`, a user ID, and the grant of an `inject` | `{done}` when the service handed that inject to a `desktop` watcher of that user and it is not answered yet, and `name` is its paste keys the first time or, after them, its Enter the first time when the command set `enter`; otherwise an error. Only from root (the uinput helper), on the control socket |
| `release-get` | `{value}`: an archive's SHA-256 | `{part}`, its bytes in `data` answers, then `{done}`: the archive of the held release, from this device or fetched from its peers |
| `watch` | `{kind, via, inject?, paste_only?, act?, images?, files?}` + payload = what the clipboard holds now (may be empty) | `{"op":"reply"}` without `done`; then the watcher protocol below |

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
  last one it applied. `ttl_ms` is the secret's remaining lifetime (60 s minus its age, at
  least 1 ms); the Go connector uses 60 s when it is missing and gives up the clipboard when
  it expires. A watcher writes a secret with the platform's password-manager marks.
- A copy of images or files: a watcher whose watch request set `images` (for a copy with an
  image) or `files` (for a copy of files and folders) gets, once every part is in the cache,
  a `write` with `kind` `media` whose payload is the plain-text alternative. It fetches the
  parts with `paste-media` on a connection of its own and writes the image (with the text
  next to it) into the clipboard, or saves the files in a new folder of its own and puts
  their paths there, or writes the text alone when the fetch fails. Other watchers get the
  plain-text alternative as a `text` write when there is one, and nothing otherwise. A
  watcher reports a copied image or copied files with `copied-media` on a connection of its
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
  helper; the lite member gives no grant, so a desktop connector that types through the
  uinput helper refuses its pastes). The watcher checks
  that its session is active and not locked, puts the text in, presses Enter when `enter`
  is set, clears the clipboard after a `secret`, shows a notification with the sender, and
  answers `injected` with the same `seq`: no `error` when it did, or `error` (and `detail`),
  with `refused` when it would not (a locked session, an administrator's window, a missing
  permission) rather than could not. The service waits 5 s for it, and 5 ms more for each
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
  with a reason that says so. The lite member checks its `tmux`, `console` and `desktop`
  watchers the same way.
- A watcher MUST check right before it injects keys that its session is active and not
  locked, and refuse otherwise; a watcher MUST NOT run an action's `command` through a
  shell.

The `devices` and `revoke` operations are in section 10.

## 9. The phone as the root

In a group that a phone app creates, the phone is the root of trust ("The phone apps" in
[design.md](design.md)). Sections 1-8 hold for it too. A group a computer creates (`cbb pair`,
`cbb pair -phone`) has a root of the same form, which the computer holds in a file, and an
iPhone CA as well (section 10, "Admins").

- **Group CA.** The app creates the group root CA: a P-256 key in the Secure Enclave or
  StrongBox that cannot be exported, with the certificate profile of section 2 except
  path length 1 (MaxPathLen 1), CN `clipboardbridge group root YYYY-MM-DD`. Below it every admin
  phone has an admin CA (section 10). Computers get member certificates; a computer holds a
  CA key only when the root phone makes it an admin (section 10, "A computer as admin").
  A phone MUST ask for the user's presence (Face ID, the fingerprint or the passcode) before
  it signs with the root or an admin key. Go accepts a group CA with path length 0 (a legacy
  group) or 1 (`checkCA`). A Welcome without CA keys makes a computer without them (section
  6). There is no iPhone
  CA in such a group, so no member of it holds `clipboardbridge.local`.
- **The app is a member.** It holds a member certificate of its own group with role
  `phone` and speaks the member protocol of section 4. It dials and never listens for
  members (a phone cannot accept connections in the background), so members MUST NOT dial a
  `phone` member; it publishes no mDNS records, except while it is the group's hub, when
  other phones dial it. It listens only for pairing, while another
  phone joins it (section 6, "The joiner listens"), and while it is the group's hub
  (section 3, `r=phone`).
- **Join QR code and pairing direction.** `cbb pair` listens and shows its addresses and
  certificate fingerprint; the app dials it as the admitting side, confirms first (section
  6, "The joiner listens") and sends a Welcome with a member certificate signed by its CA.
- **No profile, no token.** The app trusts its own CA, so it needs no configuration
  profile, no iPhone CA and no token; it finds members through mDNS browsing.
  It keeps the home network addresses (private IPv4, unique local IPv6) of the QR code of
  each computer it admitted, the one that answered first, and dials a computer of the
  group's list at them while browsing does not find it, as one in another subnet that
  mDNS does not reach. TLS checks the peer as for a found member.
  The shortcut endpoints of section 7 stay for phones without the app.
- **Renewal and revocation.** The admin phones renew certificates with `cert` messages, as
  an admin computer does (ClipboardBridgeKit's
  `GroupCertificates.renewal` and `MemberNode`'s `renew`; the app also renews its own
  certificate at start). Revocation and the devices list are section 10, and a second admin
  phone is the way back when a phone is lost.

## 10. Admin CAs, device records and revocation

The wire side of "Admin phones, the devices list and revocation" in
[design.md](design.md). The group's authority records are of version 2: one rule evaluates
a set of them into the group's state ("The state"), and it is written twice, in Go
(`internal/authority`, with the record set in `internal/group/records.go`) for the
computers, and in Rust (`cbb_core::authority` and `cbb_core::group`, `lite/core`) for the
lite member and, through the core's entry point ([core-api.md](core-api.md)), for both
phone apps, which sign records in their kits (`Records.swift`, `Records.kt`, with the
Secure Enclave or the Keystore) but evaluate none themselves. Go's release builds evaluate
through the core as well. The vectors (`testdata/interop/v2-records.json`) and the
differential run compare the whole state; why the records changed from version 1 and how
they are tested is in [records-v2.md](records-v2.md).

There is no migration from version 1: a member that holds records of version 1, or a group
made before them, refuses them, and the group is set up again. `cbb upgrade` of a legacy
group went with version 1.

### Admin CA and chains

| Certificate | Subject CN | Validity | Extensions |
|-------------|-----------|----------|------------|
| Group root CA (phone groups) | `clipboardbridge group root YYYY-MM-DD` | as the group CA | CA, path length 1; key usage certSign, cRLSign |
| Admin CA | `clipboardbridge admin <device ID>`, the admin phone's device ID | NotBefore = the root's NotBefore; NotAfter = the root's NotAfter | CA, path length 0; key usage certSign, cRLSign; issued by the root |

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

Any full member can be an admin, in a group a phone created and in one a computer created.
Its admin key is in its TPM on Linux (section 17) and otherwise a file next to its identity,
not a Secure Enclave key, so a thief with such a computer can act as an admin until another
admin removes it.

- Every full member that is not the root makes a P-256 admin key when it starts in a group
  with a root (not in a legacy group) and keeps it in the identity file (`admin_key`,
  PKCS #8, or `admin_key_tpm`, section 17). Until it holds an admin CA, and while the admin CA
  it holds is from a root before the current one, its hello carries `admin_key`: the key's
  SubjectPublicKeyInfo.
- The root makes it an admin, the root phone with "Make it an admin" and the root computer
  with `cbb admin NAME`, after the user allows a computer whose keys sit in a file (section
  17): it issues the member's admin CA for that key (the profile above, CN
  `clipboardbridge admin <device ID>`), signs a `device` record for the member that names
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
  (`cbb pair`) and admits computers and lite members, never phones, with a Welcome that
  carries `issuer` and `roots` and no CA keys; it signs the `device` record of each device it
  admits and `revoke` records (`cbb revoke`) of devices; it renews its own certificate and
  those of the computers it is connected to. It never removes the root or another admin and
  makes no admins; when the root computer is lost, it claims the group (below, "Handing the
  group over").
- **The iPhone CA.** In a group a computer created, the root holds the iPhone CA, and so does
  every admin, so the shortcut works while any of them is on. A member that holds its key
  says so in its hello (`phone_ca`). When a member that holds a key that is not revoked meets
  the root or an admin whose hello names another key or none, it sends `{"t":"phone_ca",
  "phone_ca":..., "phone_ca_key":...}`; the root sends it right after the `admin` message
  too. A peer counts as the root or an admin when its TLS chain carries its own admin CA, or
  the records list it as the root or as an admin with the key it presented. The receiver
  MUST take it only from the root or an admin, only when it is the root or an admin itself, and
  only when the records do not revoke the new CA's key; it keeps it when it holds none, when
  the records revoke the one it holds, or when both stand and the new one's SHA-256 is the
  smaller (so two replacements at once settle on one); otherwise it keeps it aside, in case
  the records revoke its own later. It then issues itself a `clipboardbridge.local`
  certificate and passes the CA on to the admins it is connected to. A member whose iPhone CA
  key the records revoke deletes it and its `clipboardbridge.local` certificate, and serves
  the shortcut again only once another admin sends the new one. A group a phone created has
  no iPhone CA, and its admins never get one.
- It is removed as an admin phone is: a revocation of its member key and its admin key,
  which keeps what it signed before the remover saw it ("Removals and freezes keep what the
  author saw"). In a group a computer created it held the iPhone CA, so the
  member that removes it, the root or an admin with the iPhone CA, makes a new iPhone CA,
  revokes in the same record the old one's key and the key of every `shortcut` device (their
  tokens stop working), takes the new CA itself and sends it to the admins as above; the
  iPhones that use the shortcut pair again with the new profile. An admin without the iPhone
  CA does not remove another admin of such a group.
- In the member handshake (section 4) a member MUST send its certificate followed by its
  issuer when the issuer is not the group CA. Checking a peer: the chain MUST verify to the
  group CA through at most one intermediate that is a CA with path length 0, with the time
  rule of section 2; then the rules of "Certificates" below apply. A legacy group, whose CA
  has path length 0, has no intermediates. The issuer those rules check, and the admin CA that makes a
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
| `device` | `device`, `name`, `role`, `os`, `key`, `admin`, `powers`, `commands`, `store`, `kind`, `proof`, `holds_root`, `seal` | a device in the group, or a change of its name or powers |
| `revoke` | `keys`, `seen` | removes keys from the group |
| `freeze` | `keys`, `seen` | stops admins until the root or an admin with `thaw` ends it |
| `thaw` | `records` | ends the `freeze` records it names |
| `claim` | `root`, `seen` | an admin's claim to take the group over with a new root |
| `resolve` | `records` | the current root voids the records it names: a cancelled claim, one side of a conflict, one of two records with one number |
| `settings` | `takeover_delay_ms`, `key_level` | the root's settings for the group |
| `checkpoint` | `heads`, `keep` | a root's checkpoint: the records it covers and does not keep may be dropped |
| `hubs` | `hubs` | the user's main hubs for sync away from home, in the order they serve |
| `recovery` | `admin`, `cert` | names the group's recovery key, an offline admin key that may only claim the group ("The recovery key") |
| `handover` | `admin` | the current root hands the group to an admin, whose claim then takes effect without the delay ("Handing the group over") |

#### Field rows

| Field | JSON type | Needed in | Values |
|-------|-----------|-----------|--------|
| `device` | string | `device` | a device ID |
| `name` | string | `device` | 1 to 64 bytes of UTF-8, no control character (U+0000 to U+001F, U+007F to U+009F) |
| `role` | string | `device` | `full`, `phone`, `lite`, `watch` or `shortcut` |
| `os` | string | none | `linux`, `windows`, `macos`, `ios`, `android`, `watchos`, `wearos` or `none` |
| `key` | string | `device` | a key hash: the member key (for a watch, its admin key; for `shortcut`, the phone ID) |
| `admin` | string | `recovery`, `handover` | a key hash: the admin key its admin CA certifies; only in a record a root's own key signed |
| `powers` | array of strings | none | sorted; from `admit`, `renew`, `remove`, `remove-admins`, `freeze`, `thaw`, `takeover`, `hub`; only with `admin` |
| `commands` | array of strings | none | sorted; the command types (section 15) the admin may sign; only with `admin` |
| `store`, `kind`, `proof` | string | none | as in section 17 |
| `holds_root` | bool | none | `true`: this device holds the signer's root key; only in a record a root's own key signed |
| `seal` | string | none | the device's public key for sealed messages, base64: 1216 bytes, an X-Wing key (HPKE KEM `0x647a`). The rules check only its size; a member checks the whole key before it seals a message to it |
| `keys` | array of strings | `revoke`, `freeze`, one at least | sorted key hashes |
| `seen` | array of objects | `revoke`, `freeze`, `claim`, one at least | sorted by `key`, each key once: `{"key": key hash of a signer, "seq": the highest seq of that signer the author held, 0 or more}`; `seq` here is never left out, 0 included |
| `records` | array of strings | `thaw`, `resolve`, one at least | sorted record IDs |
| `root` | string | `claim` | the new root CA certificate, DER, base64: self-signed, a CA with path length 1, a P-256 key |
| `cert` | string | `recovery` | the recovery key's admin CA certificate, DER, base64, whose key hash is `admin` |
| `takeover_delay_ms` | integer | none | from 0 to 604 800 000 (7 days); absent means 259 200 000 (72 hours) |
| `key_level` | string | none | `proven`, `hardware` or `files`: which devices may be the group's root, an admin or a hub ([roadmap](roadmap.md), "Key levels"); absent means `hardware`. The state carries it; the rules do not check it yet, the apps and `cbb` do when they make an admin or a hub |
| `heads` | array of objects | `checkpoint`, one at least | sorted by `key`, each key once: `{"key": key hash of a signer, "seq": 1 or more, "id": the ID of that signer's record with that seq}` |
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
| `device` naming `admin`, or with role `phone` or `watch` | a root's own key |
| other `device` | a root's own key, or an admin with `admit` |
| `revoke` of member keys and phone IDs | a root's own key, or an admin with `remove` |
| `revoke` of an admin key, or of the member key of a device whose newest root record names an admin key | a root's own key, or an admin with `remove-admins` |
| `revoke` of a root key, or of the root's own device | nobody: a root is replaced only by a claim |
| `freeze` | a root's own key, or an admin with `freeze`; each key it names is an admin key without `remove-admins` |
| `thaw` | a root's own key, or an admin with `thaw` and `remove-admins` |
| `claim` | an admin with `takeover`, under the current root |
| `resolve`, `settings`, `handover` | the current root's own key |
| `checkpoint` | a root's own key |
| `hubs` | a root's own key, or an admin with `hub` |
| `recovery` | a root's own key |

A record whose signer may not sign it counts for nothing; so does a `revoke` or `freeze` that
names any key its signer may not remove or freeze. The powers the apps and `cbb`
write:

| Admin | `powers` | `commands` |
|-------|----------|-----------|
| a phone | all eight | all |
| a computer | `admit`, `renew`, `remove`, `freeze`, `hub`, and `takeover` when the root is a computer | all |
| a watch | `remove`, `freeze` | `paste-off`, `actions-off`, `away-off`, `action` |

So whether an admin computer may take the group over is decided once, by the root, when it
makes the admin, not by each member from other records.

#### Watches

A watch's admin key sits in its Secure Enclave or Keystore, but a watch on the wrist signs
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
voided branch (of two records with one seq, the one with the lower ID), and signs nothing
but a root's `resolve` with a key the state names in a conflict of two histories.

A device keeps a log of the records it signed. When the root's `resolve` voids both
histories of its key, it signs again, in their order, the voided records of that log that
admit, remove, freeze, thaw or set (`device`, `revoke`, `freeze`, `thaw`, `hubs`,
`settings`); the voided records it did not sign, as a thief's or its own from before a backup
was restored, stay void, and its user does again what was theirs. Before a record its user
asks for, a computer waits up to 10 seconds until it holds another member's records (a
hello with its digest, or the records a member sent), so that a device brought back from
a backup rarely signs a seq again; when no member answers, it signs anyway and logs it.

#### Checkpoints

A group's records only grow, and a member keeps at most 1 MiB of them (1024 records). A root's
own key signs a `checkpoint` so that members may drop what no longer matters: `heads` names,
for each signer, its newest record the checkpoint covers, and `keep` the records below the
heads that still count: the newest `device` record of each device, the `revoke`, `freeze` and
`thaw` records that count, the newest `settings`, the `hubs` record that counts, the `recovery` record that counts, every claim not yet decided and the records
its `seen` and its disputes need, and the `resolve` records that end them. The apps sign one
by themselves when the records pass three quarters of either limit.

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
with the role `full` or `phone`, in its order; a member puts first those of them that may be
hubs by the records (the root's own device, or an admin with `hub`), so a table naming a
removed device or one that lost `hub` does not stop the others. A device the table does not
name still serves after the main hubs.

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

A newer `recovery` record replaces the older one: the key the older one named is no admin
any more, and its claims do not count. A `revoke` of the key removes it (a root's own key, or
an admin with `remove-admins`, as for any admin key). The state names the key in `recovery`
while it is neither removed nor frozen.

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
| an admin that signed two histories | `secrets` | no member sends a secret event's text (`kind` `secret`; it sends the event's mark) or takes a `secret` paste; the devices that admin alone admitted get nothing: their connections carry records only |
| a pending claim | none | the claimant's devices get no secret's text and take no `secret` paste |

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
| `devices` | array of objects | sorted by `device`: `device`, `name`, `role`, `os`, `keys` (sorted member key hashes that stand), the newest record's `store`, `kind`, `proof` and `seal` when it has them, and, for an admin, `admin`, `powers`, `commands`, `frozen` (true when frozen) |
| `revoked` | array of strings | sorted key hashes the records remove |
| `claims` | array of objects | sorted by `record`: `record`, `claimant` (admin key hash), `root` (new root key hash), `state` (`pending`, `effective`, `cancelled`, `void`, `competing` or `disputed`), `left_ms` while pending |
| `conflicts` | array of objects | sorted by the first record ID: `kind` (`admins`, `claims`, `two_histories`), `records` (sorted record IDs), `signers` (sorted key hashes) |
| `stop` | string | `none`, `secrets` or `full` |
| `no_secrets_to` | array of strings | sorted device IDs that get no secrets |
| `nothing_to` | array of strings | sorted device IDs that get nothing |
| `newer` | array of strings | sorted IDs of the records of a later version the member keeps, at most 16 |
| `ignored` | array of objects | `{record, why}`: the records of the set that do not count and why, sorted by ID, at most 64; records listed in `newer` are not, nor a claim that took effect on the path, nor what the checkpoint that counts leaves out |
| `checkpoint` | string | the ID of the root's checkpoint that counts ("Checkpoints"): a member may delete the records it leaves out |
| `hubs` | array of strings | the main hubs of the `hubs` record that counts ("The hubs table"): its devices that are in `devices` with the role `full` or `phone`, in its order |
| `recovery` | string | the key hash of the recovery key ("The recovery key"), while it is neither removed nor frozen |
| `key_level` | string | the `key_level` of the current root's newest counting `settings` record; absent when it has none (then `hardware`), so a claim's new root starts without one |

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
states are the same bytes. The state does not depend on the order in which records arrived;
the vectors give each set in every order of its records (up to 8 records; in random orders
beyond) and check the same bytes.

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
  and sends and takes nothing else (no events, credentials, commands, tunnel keys, hubs or
  iPhone CA). It closes the connection once the records let the peer in, and the side that
  dialed connects again at once as a member, or when no records came for 5 seconds. Every
  member keeps such a connection while the state stops the exchange with the peer, so that
  the root's decision reaches it; for the other cases only full members keep it, and the
  lite member and the phones refuse the peer and take the records from the others.
- After adding records that refuse a certificate a member first queues the new records for
  its peers, then closes every connection whose peer certificate is now refused
  ("Certificates"), after what is queued for it and a `bye`, and the TLS check refuses it from
  then on. So a revoked member that is connected gets the record that revokes it. A member
  that learns that its own key is revoked logs that it was removed from the group, and its
  status says so (`removed`); an admin computer whose admin key is frozen says that instead
  (`frozen`); the others refuse it. A member MUST close a connection, and refuse new ones,
  whose peer certificate the records refuse, as soon as it holds the record. When the state
  stops the exchange ("Stopping the exchange"), a member applies it to every connection at
  once.
- A member that holds the root's key records every device it admits (its name and `os` from
  the pairing Info, role `full` or `lite`) and every iPhone it pairs (`shortcut`, `os` `ios`,
  name `iPhone`, device = the phone ID), and itself and every connected peer that has no
  record yet, with the name and `os` from the peer's hello (or the role and the first 8
  characters of its ID). When a computer's hello states an `os` that its record does not, it
  signs a new record for it with that `os` and the rest of the record unchanged.
- The iPhone endpoints (section 7) treat the token of a revoked iPhone as unknown.

### Control operations

| `op` | Request | Answers |
|------|---------|---------|
| `devices` | none | `{devices: [{id, name, role, os, form, os_version, version, mac, admin, root, frozen, old_keys, online, last_seen_ms, self, listed}], done}`: the listed devices, then this device and the connected peers that have no record yet (`listed` false). `last_seen_ms` is when this member last saw the device connected; `form`, `os_version`, `version` and `mac` are what its hello says (section 4, "Device"), for this device and the connected ones only |
| `away` | `{name: "on", consent}`, `{name: "off"}`, `{name: "off", device}`, `{name: "hub", addrs, port, forwarder, forwarder_key, obfuscate?, vless?}`, `{name: "move", device, forwarder?, forwarder_key?, addrs?}` or `{name: "relay", relay, relay_key, consent}` | `{status, done}` or an error. `on` makes the tunnel key and needs `consent` on a device whose keys sit in files (every computer whose keys are not in a TPM); `off` deletes `tunnel.json`, and with `device`, on an admin, sends that device an `away-off` command (section 15); `hub` makes this device the group's hub, reached at `addrs` (`ip:port`) on UDP `port`, and through the forwarder at `forwarder` (`ip:port`) whose key `forwarder_key` pins (section 13); at most 8 addresses with the forwarder's, and at least one of them; `relay` makes this device meet the others at the blind relay at `relay` (`ip:port`) whose key `relay_key` pins, in place of a hub or its offer (section 14), and needs `consent`, since the relay learns which devices talk; `move`, on the hub, an admin, makes the member `device` the hub in its place with a signed `hub` command (section 15), reached at `addrs` and through `forwarder`, or through this hub's forwarder when none are given; `obfuscate` and `vless` with `hub` are the settings of section 11. Members connect again afterwards, so their hellos carry the change (section 11) |
| `revoke` | `{name}`: a device ID, or a name (case-insensitive) | `{name, done}` or an error. Only on the root or an admin whose powers allow it (`remove`, and `remove-admins` for an admin; "Who signs what"); a device cannot remove itself; the root is never removed, only replaced by a claim (`takeover`); removing an admin of a group a computer created replaces the iPhone CA ("Admins") and needs the iPhone CA key |
| `admin` | `{name}`: a device ID, or a name (case-insensitive) | `{name, done}` or an error. Only on the root computer: makes the connected full member an admin ("Admins") |
| `takeover` | `{name}`: the lost root, a device ID or a name (case-insensitive) | `{name, done}` or an error. Only on an admin computer of a group whose root is a computer, and holding the iPhone CA: signs a `claim` against the root that name names, which takes effect when the root's takeover delay has passed on each member, unless the root cancels it ("Handing the group over") |
| `takeover-delay` | `{value}`: a duration from `0s` to `168h` | `{done}` or an error. Only on the group's root: signs a `settings` record with `takeover_delay_ms`, how long a claim waits on each member |
| `hubs` | `{hubs}`: 1 to 16 names or device IDs of computers and phones, in the order they serve | `{done}` or an error. On the group's root or an admin with `hub`: signs a `hubs` record, the group's main hubs |
| `freeze` | `{name}`: a device ID, or a name (case-insensitive) | `{name, done}` or an error. Only on an admin that is not frozen: freezes another admin without `remove-admins`, never the root or an admin phone ("Removals and freezes keep what the author saw") |
| `thaw` | `{name}` | `{name, done}` or an error. Only on the root computer (a computer's admin has no `thaw`): ends every freeze of that admin ("Removals and freezes keep what the author saw") |

## 11. Tunnel keys

The keys of the group's WireGuard tunnel for sync away from home ([design.md](design.md),
"Sync away from home"). Implemented in Go (`internal/tunnel`, `internal/node`,
`internal/service/tunnel.go`); the tunnel carries the member protocol between Go members
("Through the tunnel" below). The phone kits speak the hello's `tunnel_key` and the
`tunnel` message (Swift `MemberNode`, Kotlin `MemberNode`) and bind the tunnel itself from
Go (`mobile/cbbtun`), and both apps turn it on in their settings; the kits keep the obfuscation settings with
the offer and hand them to the tunnel. The lite member on Linux takes part as a client, with
plain WireGuard only: GotaTun's WireGuard and smoltcp's TCP in its process
(`lite/src/tunnel.rs`, `lite/src/away.rs`); it refuses an offer with `obfuscation` or `vless`
and then syncs at home only ("Through the tunnel" below).

- Sync away from home is off by default; nothing in this section happens on a device until
  the user turns it on there (`cbb global on`, the control operation `away`). Go turns it on
  by writing `tunnel.json` next to the identity
  (mode 0600), which holds the device's own Curve25519 key pair, made on the device, and the
  rest of this section's state; on a Linux computer with a TPM the private key is sealed by
  it (`key_tpm` in place of `key`, section 17). The lite member keeps its own `tunnel.json` there: `v` (1),
  `group` (the group tag), `key` (its private key, base64), `psk` (the preshared key it chose)
  and `hubs`, each hub's offer (`device`, `key`, `psk`, `endpoints`, `next`); it reads the single
  `to_hub` of earlier versions into `hubs`. A device whose tunnel key sits in a file (every
  one but a Linux computer with a TPM) MUST ask for the user's consent before it turns sync
  away from home on (`consent` in the request).
- Each member's hello carries `tunnel_key`, its public key, and `tunnel_psk`, a preshared
  key of 32 random bytes it made with the key pair: 32 bytes each. A member where sync
  away from home is off, or whose tunnel state cannot be read, sends neither, and syncs at
  home only.
- A hub is a member chosen on that member (`cbb global hub`; `is_hub`,
  `endpoints`, `listen_port` and `forwarder` in its `tunnel.json`); a group can have several
  ("Several hubs" below). When
  a peer's hello carries `tunnel_key`, the hub admits it for the peer's device ID together
  with the certificate chain the peer presented in this connection's TLS handshake, and
  answers with `{"t":"tunnel","tunnel":{"hub_key":...,"psk":...,"endpoints":[...]}}`:

| Field | Type | Meaning |
|-------|------|---------|
| `hub_key` | bytes | the hub's public key, 32 bytes |
| `psk` | bytes | the member's own WireGuard preshared key, 32 bytes: the one its hello offered |
| `endpoints` | array of strings or absent | the hub's addresses away from home, `ip:port` or `[ipv6]:port`, at most 8; its forwarder's last (section 13) |
| `obfuscation` | object or absent | the group's AmneziaWG settings ("Obfuscation" below); absent for plain WireGuard |
| `vless` | object or absent | the way to the hub's forwarder over VLESS ("VLESS" below); with it, the only way to the hub |
| `hub` | string or absent | in an offer one hub passes on for another: that hub's device ID ("Several hubs", "Moving the hub" below) |
| `moved` | bool or absent | `true` when the sender is no hub any more and hands its clients over to `hub` |
| `next_key` | bytes or absent | the key the hub serves with in the next period, 32 bytes ("The hub's key" below) |

- The hub keeps one preshared key per device: the one the device's hello offers, so every
  hub of the group uses the same. From a member without `tunnel_psk` it keeps the one it
  had, and makes a new one for a new key. It MUST refuse a key that another device or the hub
  itself has, and keeps at most 256 devices. It sends the offer on every connection whose
  hello carries a key, so a member learns new endpoints the next time it connects.
- A member MUST keep an offer only from the group's root or an admin (by its records, or an
  admin CA in its verified chain). The record that makes the peer the root or an admin must
  name the key of the certificate it presented, not only its device ID, and never the role
  its hello claims. It keeps one offer per hub, by the hub's device ID: the sender's, or the
  one its `hub` names when the records make that device the root or an admin and it is not
  the member itself, which it ignores. A new offer for a hub replaces that hub's earlier one;
  `moved` also makes the member forget the sender's own. An offer that does not decode is
  ignored and changes nothing. Go, both kits and the lite member all apply these rules.
  `cbb global hub` refuses on a device that is no admin. A phone that is the hub ignores
  offers. The tunnel addresses follow from the device IDs (fd00:cbb::/32 followed by the
  first 96 bits of the ID), so the offer does not carry them.
- A phone can be the hub while its app is open ([design.md](design.md), "The phone as the
  hub", D-64): its kit listens for member connections (`MemberListener`, on the loopback
  address, where `mobile/cbbtun`'s `Hub` leads each connection through the tunnel) and
  admits clients and answers with the offer by the rules above (`PhoneHub`, MemberNode's
  `hub`); `cbbtun`'s `SetClients` takes the clients it keeps.
- When records revoke a device (section 10, "Certificates", on the chain it presented), the hub
  MUST forget its key at once.
- All of this happens inside member TLS, so a device gets into the tunnel only after it met
  the hub as a member, with the key that member sent. A device that is not yet a member
  reaches the hub from the internet only with a remote invitation's guest key (section 12).
  No signed record binds the key: the member certificate already does.
- A member that moves to another group turns sync away from home off: it deletes
  `tunnel.json` (whose `group` names the old group), and the user turns it on again.

### Moving the hub

The hub, a computer or a phone, hands its role to an admin computer ([design.md](design.md),
"The phone as the hub"): `cbb global move DEVICE [-forwarder ADDR -forwarder-key KEY]
[address:port...]` on a computer, "Move the hub to a computer" in both apps. Implemented in
Go (`internal/service/movehub.go`), both kits (`Commands.hub`, `PhoneHub.movedOffer`) and
both apps; `TestMoveHub` moves a hub with a client away from home.

1. The old hub sends the new one a `hub` command (section 15) with the new hub's forwarder
   and addresses, by default its own forwarder, and every client it keeps: device ID, public
   key and preshared key. It includes itself, with its own keys as a client.
2. The new hub must be an admin with sync away from home on and without a relay; it refuses
   otherwise. It becomes the hub with that forwarder and those addresses, takes each client
   whose device its records list, with the keys it was given and no certificate chain yet,
   and answers `done` with its offer (`tunnel` in the result, without `psk`). A client
   without a chain stays while the records list its device; its chain is filled in on its
   first hello.
3. The old hub sends each client connected to it the new hub's offer with that client's own
   preshared key, `hub`, the new hub's device ID, and `moved`. After 2 s it stops being the
   hub and becomes the new hub's client with its own keys.

A client keeps the new hub's offer by the rules above and forgets the old hub's. A client
that was away from home and not connected at the move gets the new hub's offer on its next
connection to it, or to any other hub that passes it on.

When an admin phone takes the group over from a lost root phone that was the hub, it turns
its own hub on; the clients keep its offer as any hub's.

### Several hubs

The group's root and admins with a hub set up are its hubs, in an order every member
derives from the records alone: phones first (a phone is the hub while its app is open,
so it serves whenever it is there), then computers; within each, the root first, then by
device ID. The vectors in `testdata/interop/v2-hubs.json` (Go's `TestGoHubVectors`) give an
order that Go (`Records.HubOrder`), both kits (`RecordSet.hubOrder`) and the lite member
(`hub_order`) must all derive. The root, or an admin with `hub`, may sign a table of main
hubs in the user's order (a `hubs` record, section 10, "The hubs table"; `cbb hubs`):
its hubs come first, in its order, then the others in the derived order (D-65 in
[design.md](design.md)).

- A member keeps every hub's offer and, away from home, uses the first hub in the order that
  answers: it tries them in turn, each at the next of its endpoints. On a hub below the
  first it ends the connection after 5 minutes and tries the hubs above again. A hub found
  on the home network, or connected directly, counts as answering. Hubs outside the order
  are not tried.
- Since every member offers its own preshared key, a hub can serve a member it never met,
  given the member's public key. A hub sends each peer that may be a hub, after the hello,
  `{"t":"hubs","hubs":{...}}`:

| Field | Type | Meaning |
|-------|------|---------|
| `serving` | bool or absent | `true` while the sender serves its clients as the hub |
| `offer` | object or absent | the sender's offer, without `psk` |
| `clients` | array or absent | the sender's clients, each `device`, `key` and `psk`, the sender itself among them, without the receiver; at most 256 |

- The receiver takes the message only from the group's root or an admin, by the same check
  as an offer. On a hub it takes each client its records list, other than itself, as it
  takes the clients a hub command hands over ("Moving the hub"): a client it met keeps its
  own keys. Every receiver keeps the sender's offer with its own preshared key, as that
  hub's. A hub sends the message again to the connected hubs when it starts or stops
  serving, and when it admits a client it did not have, so that the other hubs know every
  client before this hub is off.
- A computer's hub serves only while no hub above it answers, and is otherwise a client of
  the first that does. Starting, it tries the hubs above it once, then serves. It stops
  serving when a hub above it says it serves, or offers its tunnel: first it passes that
  hub's offer on to its connected clients and waits for those through its tunnel to leave, as
  a hub that moves does, since a client far from home may know only this hub. Once it loses
  the hub above, it tries the hubs above for a minute and then serves again. While it serves with
  hubs above it, it tries them as a client every 15 minutes.
- A hub passes the other hubs' offers on to its clients, each with the client's own
  preshared key and `hub`, so a client that met only one hub learns them all.
- A phone that is the hub shares its clients, takes the others' and passes their offers on,
  but does not yet stop serving for a hub above it, nor become another hub's client; as
  phones come first in the order, the computers' hubs give way to it.

### The hub's key

A hub serves its clients with a WireGuard key of its own for each period of the group's
server credentials (section 18), apart from the key its hello offers, so that a server on the
way, such as the forwarder, cannot link the group's traffic from one period to the next by
the hub's key. Implemented in Go (`tunnel.State.Rotate`, `internal/service/tunnel.go`).

- When a hub sees a period it has no key for, it makes the next key and gives its public key
  as `next_key` in its offers from then on, to every connected client at once and to the
  others when they connect. Three days later it serves with that key in place of the old
  one: it starts its tunnel again and registers again with its forwarder (section 13). Until
  the first period, and in a group without server credentials, it serves with the key its
  hello offers.
- `tunnel.json` keeps the key the hub serves with (`serving`, or `serving_tpm` when the TPM
  seals it, and `serving_for`, the period's tag) and the next one (`next`, `next_tpm`,
  `next_for`, and `next_at_ms`, when the hub moves on to it); a client keeps a hub's
  `next_key` as `next` in its offer.
- A client tries a hub with its key and, when the offer has one, with `next`, so a client
  that was away while the hub moved on still reaches it; the offer it gets then replaces the
  one it kept. Go tries both keys at once (`tryHub`, `internal/service/hubs.go`), so the key
  the hub no longer serves with, which gets no answer, costs no time; the lite member
  (`lite/src/tunnel.rs`, `hubs_to_try`) and the phone kits (`TunnelOffer.withNextKey`) try
  them in turn, the old key first. A client that was away for the whole three days and
  never got `next` reaches the hub again at home.
- A hub refuses a client or another hub's offer with any of its own keys.

### Obfuscation

A hub where the user asked for it (`cbb global hub -obfuscate`; `obfuscation` in its
`tunnel.json`) speaks AmneziaWG instead of plain WireGuard. Its offer carries the settings,
with AmneziaWG's own names; every client sets them on its end before the hub as its peer:

| Field | Type | Meaning |
|-------|------|---------|
| `jc`, `jmin`, `jmax` | numbers | junk packets of random bytes before each handshake: `jc` (0 to 16) of them, `jmin` to `jmax` bytes (at most 1000) |
| `s1`, `s2`, `s3`, `s4` | numbers | random bytes in front of the handshake initiation, the response, the cookie reply and each data message: 16 to 64; the three padded handshake messages differ in size |
| `h1`, `h2`, `h3`, `h4` | strings | `"min-max"`: the range each of those messages' type field is drawn from, in the same order; above 4, not overlapping |
| `header_protection_key` | base64 | 32 bytes: the key of the header protection, which encrypts the rest of each message's header with the first 12 bytes of its padding as the ChaCha20 nonce |

- A receiver MUST refuse settings outside these bounds and not start the tunnel, and also
  when `header_protection_key` is all zero, or when two of the padded handshake messages
  would have the same size: the initiation is 148 + `s1` bytes, the response 92 + `s2` and
  the cookie reply 64 + `s3`, and the three MUST differ.
- The header protection, the padding and the type ranges are AmneziaWG's, as the
  amneziawg-go version in `go.mod` implements them (`device/send.go`, `device/receive.go`;
  a copy with three changes unrelated to the wire is in `internal/third_party/amneziawg-go`).
  An implementation MUST follow that version byte for byte.
- The hub makes the settings once, at random (docs/design.md, "Blocked networks"), and
  keeps them while it stays obfuscated. Switching obfuscation on or off changes them; each
  client gets the new ones the next time it meets the hub at home.
- An obfuscated hub with a forwarder gives it the settings when it registers (section 13),
  since the forwarder's routing needs WireGuard's own headers.

### VLESS

A hub with a forwarder where the user asked for it (`cbb global hub -forwarder ... -vless`)
has its clients reach the forwarder only inside VLESS with REALITY, which to the network is
TLS 1.3 to a well-known site (docs/design.md, "Blocked networks"). The hub makes a VLESS user
ID for the group once and keeps it (`forwarder.vless_id` in its `tunnel.json`); it learns the
rest from the forwarder's answer when it registers (section 13) and keeps that too
(`forwarder.vless`). Its offer then carries:

| Field | Type | Meaning |
|-------|------|---------|
| `endpoint` | string | the forwarder's VLESS address, `ip:port` (TCP): the forwarder's address with the port its answer gave |
| `public_key` | base64 | the forwarder's REALITY key, X25519, 32 bytes |
| `short_id` | string | REALITY's short ID, 2 to 16 hex digits |
| `server_name` | string | the site whose name the TLS handshake carries |
| `id` | string | the group's VLESS user ID, a random UUID (version 4) |

- Until the hub has the forwarder's answer it MUST NOT send an offer, so a client never
  learns a way that bypasses VLESS. A client with a `vless` offer MUST NOT send plain
  WireGuard to the hub's endpoints. When the answer comes, or changes, the members connect again
  and get the new offer.
- The client runs VLESS with REALITY (Xray-core: VLESS without encryption inside REALITY,
  the TLS fingerprint of Chrome) from a local UDP port to that endpoint, and points its
  WireGuard at the local port instead of the offer's `endpoints`. The forwarder passes every
  UDP packet that comes over VLESS to its own UDP port, so the packets are forwarded as in
  section 13; VLESS carries nothing else.
- A receiver MUST refuse settings that do not have this form and not start the tunnel.

### Through the tunnel

- The hub runs WireGuard in user space on UDP `listen_port` (8764 when 0), with one peer per
  admitted device: its key, its preshared key, and its tunnel address as the only allowed
  address. Inside the tunnel the hub MUST listen only on TCP 8764 at its own tunnel
  address, for the member protocol (section 4) and nothing else: no pairing, no shortcut,
  and no forwarding of packets between peers.
- After the member TLS handshake the hub MUST check that the device ID of the client
  certificate gives the tunnel address the connection came from, and close it otherwise,
  so a device cannot use another device's tunnel key.
  Note: a phone that is a hub does not check this yet. Its tunnel (`mobile/cbbtun`) hands
  each connection to the app through a loopback port, which does not say from which tunnel
  peer it came, so such a hub knows the client by its member certificate alone. This is
  planned for 0.7, with a call in `cbbtun` that names the peer of a loopback connection.
- A member that keeps hubs' offers runs the other end, with the hub it tries as its only
  peer and a keepalive every 25 s. It dials the hub's tunnel address, TCP 8764, with member
  TLS whenever no hub is connected on the home network, trying the hubs in order and each
  offer's endpoints in turn ("Several hubs" above), with the dialers' backoff (1 s, doubling
  to 30 s). A hub that discovery finds holds
  this off for 30 s only: anyone on a network can announce the hub's name and the group's
  tag, so after that only a connection to the hub counts. The relay path (section 14) and
  the dialers through the hub follow the same rule.
- A member MUST fail closed: when the hub or the link cannot start, or the hub does not answer, the
  member syncs at home only, and `status` says why (`error`, with `detail` for debugging).
- The lite member starts its end only while it dials the hub through it, so at home it sends
  nothing to the hub's addresses away from home. It accepts an offer only from a full
  member, starts the handshake at once, tries the next endpoint after 10 s without an answer,
  and runs TCP inside the tunnel with an MTU of 1280, so no packet is fragmented on the way.

## 12. Remote invitations

A device that shares no network with the group joins through the hub's tunnel with a remote
invitation ([design.md](design.md), "Joining from another network"). Implemented in Go
(`internal/invite`, `internal/service/invite.go`, `cbb invite`, `cbb pair -invite`) for
computers, and made and served on a phone that is the group's hub (mobile/cbbtun's
`Hub.Invite`, the kits' `InvitationWindow`); the phones do not use invitations yet.

### The invitation

Made on the hub, by the control operation `invite` (`cbb invite`), or in the app of a phone
that is the hub, whose endpoints are its forwarder's. Its text is
`clipboardbridge://invite#` followed by standard base64 of this JSON (byte strings
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

A text refused names one reason, the same in every implementation:

- `not_invitation`: not the prefix.
- `damaged`: not standard base64, not strict JSON, a field missing, unknown or of another type.
- `version`: a `v` other than 1.
- `group`, `hub`, `key`, `endpoints`, `secret`, `expiry` or `obfuscation`: that field's
  value is refused.

A device joins only while `exp` is later than its clock. A device that does not know the
time yet does not join.

It travels as a file of one line (`.cbbinvite`, mode 0600, which `cbb invite` deletes when
the invitation ends and `cbb pair -invite` deletes once it joined) or, later, a QR code; it
is never typed. It is a secret until it is used. It serves one device once, for 1 hour
unless the admin asks for up to 24 hours, and closes after three failed attempts or when
the admin cancels it.

### The guest tunnel

- The hub adds the guest key as a WireGuard peer, with the preshared key, whose only
  allowed address is the guest address: fd00:cbc::/32 followed by the first 96 bits of
  SHA-256 of the guest's public key. That prefix is apart from the members' (section 11),
  so a guest address never names a member. Peers that stay when the hub's peers change
  keep their sessions.
- Inside the tunnel, a connection from a guest address to TCP 8764 gets the pairing
  (ALPN `clipboardbridge-pair/2`, section 6) of that invitation's window and nothing else,
  except, once the window admitted a device, member TLS from that device alone, for its
  first hello (below). Any other connection MUST be closed.
- The hub drops the guest peer when the invitation ends without a device, and 2 minutes
  after it admitted one.

### Joining

1. The new device starts a tunnel client with the guest key, its guest address and the
   hub's key, tries the hub's endpoints in turn (20 s each), and dials the hub's tunnel
   address, TCP 8764.
2. It pairs as in section 6 with the secret as the password. The window MUST take no other
   password, MUST give no CA keys, and before it makes the certificate MUST ask the hub's
   admin to confirm the device, with its name, system, device ID and key fingerprint; the device
   shows the same fingerprint. The admin has 5 minutes; a no sends `declined`.
3. Once it has its certificate, the device turns sync away from home on (the user
   consented before the join) and makes a member connection to the hub through the guest
   tunnel. Its hello carries its own tunnel key, which the hub admits (section 11) and
   answers with its offer.
4. With the offer, the device closes the guest tunnel and from then on reaches the hub
   through the tunnel with its own key, as any member.

### On a phone that is the hub

The phone makes the invitation in its app while it is registered with its forwarder; its
`ep` is the forwarder's endpoint. cbbtun's hub adds the guest peer and joins each
connection through the guest tunnel to a loopback port of the kit's pairing window
(`InvitationWindow`), and once the window admitted the device, to the member listener, for
the device's first hello. The window runs the exchange of section 6 as the server, with the
secret as the password: the device confirms first, the phone asks its user to confirm the
device by its name, system and fingerprint, then unlocks its signing key (Face ID or the
screen lock) and sends the welcome with its own tag. It gives no CA keys and makes no admin.
It takes one attempt at a time, ends after three failures, and the guest goes at expiry,
when the user cancels, or 2 minutes after the device was admitted. The invitation's file
goes through the phone's share sheet. Go's `TestSwiftHubAdmitsInvitedGoJoiner` runs `cbb`'s
joiner against the window of both kits.


## 13. The forwarder

A server that holds no keys and passes the encrypted WireGuard packets of a group's clients
to that group's hub, for hubs that clients cannot reach directly ([design.md](design.md),
"The forwarder"). Implemented in Go (`internal/forward`, `cbb forward`, and on the hub
`internal/service/forwarder.go`). Routing is by `mac1`; the fallback by a computed port is
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
and its clients, and the timing and sizes of their packets. A hub that registers with a
credential (section 18) shows besides only the period's tag, a certificate of its server key
that names neither a device nor a group, and the period's hubs' credential: hashes of
server keys, padded, a version, an expiry and the period key; all of it new each period, so
the forwarder cannot tell one month of a group from the next. A hub that registers with
records shows instead the group tag, its member certificate (device ID, validity, admin
CA), the group's root certificates and its authority records, which name the root's and the
admins' devices, with their names and systems, and the removals. It never sees a member key,
a text, the other devices' records or names, or which client address is which device. On
disk it keeps only a keyed hash of each period's tag with the version of its newest
credential and a hash of its period key ("What it keeps").

### Registration

Framing: inside TLS, each message of this section is one frame (Conventions, "Frames").
Go forwarders and hubs read at most 1 MiB in all from the other side, frames and lengths
together, and close the connection beyond that; a sender MUST stay below it.

1. The hub connects over TCP and runs TLS 1.3 with ALPN `clipboardbridge-forward/2` and no
   server name. It MUST accept only the pinned key. A hub whose period's hubs' credential lists
   its server key (section 18) presents only a certificate of that key, self-signed, with
   the subject `clipboardbridge server`, no names, key usage digitalSignature and client
   use. Any other hub presents its member certificate, its admin CA if it has one, and the
   group's roots (the group CA, then the new roots of the claims that took effect).
2. The forwarder takes the hub's certificate as a member certificate when it names a device
   (section 1), and verifies it, for client authentication, to a self-signed CA among the
   presented certificates, whose tag names the group (section 1). Otherwise it must be the
   only certificate, not a CA, and the hub must register with a credential, whose period's
   tag names the group. It knows no group beforehand: any group may register, but only its
   hubs, its root or an admin can (step 3).
3. The forwarder sends `{"e": bytes}`, a fresh X25519 public key. The hub answers
   `{"key": bytes, "proof": bytes, "obfuscation": object, "vless": string, "credentials":
   [credential], "admin": bytes, "admin_sig": bytes, "records": [record]}`, at most 1 MiB
   with at most 1024 records and 3 credentials:
   - `key` is its WireGuard public key, and `proof` is HMAC-SHA256 under X25519(the hub's
     WireGuard private key, `e`) of 32 bytes exported from the TLS session with the label
     `clipboardbridge forwarder key` and no context. So the hub proves it holds the key, on
     this connection only.
   - A hub with a credential sends `credentials`, the period's hubs' credential alone, and
     neither `admin`, `admin_sig` nor `records`. The forwarder checks it (section 18, "What
     a server checks"): it has not expired, lists the key of the hub's certificate among
     the hubs, and the period key that signed it is the one the forwarder first saw for
     its tag, at a version no older than the one it keeps ("What it keeps"). It then keeps
     the version for the period.
   - Any other hub sends `admin`, `admin_sig` and `records`. The forwarder keeps the
     groups that registered with a credential apart from these, so a period's tag never
     stands for a group CA's.
   - `admin_sig` is an ECDSA signature (ASN.1) of SHA-256 over 32 bytes exported with the label
     `clipboardbridge forwarder admin` followed by `key`. The key of the group's root or of
     the hub's admin CA signs it. `admin` is that admin CA (DER), left out for a root. The
     forwarder takes the signature only from a root on the path of the records it knows, or
     from an admin CA that such a root certified, so a member that is no admin cannot
     register its group.
   - A hub whose root or admin key signs only after the user, a phone hub (design.md, "The
     phone as the hub", D-64), leaves `admin` and `admin_sig` out. The forwarder then takes
     the hub when the records make its member certificate's device, with that
     certificate's key, the group's root (the latest `device` record of its own that the
     current root signed) or an admin that is not frozen (the devices list, section 10,
     names it an admin with that key). Go hubs (`internal/forward`) and
     the phones' hub (`mobile/cbbtun`) do this; any other hub is refused as before.
   - `records` are the group's authority records: the path records (section 6, the Welcome; section 10, "The state"), every record
     that is not a `device` record, and of the `device` records a root signed with its own key
     those of a root's own device and every record of each device a root made an admin, so
     that a demotion counts. The records of the other devices, with their names, are not
     sent.
     The forwarder adds them to those it keeps for the group and refuses a hub whose signer
     or member certificate the records revoke or freeze. It keeps the merged authority
     records in memory after the registration ends, so a removed or demoted admin that
     registers later, while the group's own hub is away, cannot leave its revocation out,
     until the forwarder restarts; it writes none of them to disk. It refuses a registration
     whose merged authority records come to more than 256 KiB, so it never keeps part of a
     group's records. The records of a group that is registered now are never forgotten.
     Of the groups that are away it keeps at most 32 MiB of records and 100,000 groups; past
     that it forgets from the provider (an IPv6 /32, an IPv4 /16) that holds the most of them
     (docs/relay-budget.md),
     its group kept least recently first. The group CA for these records is the
     root the hub's member certificate verified to in step 2, whose tag names the group; a
     self-signed certificate the hub presents besides counts for nothing.
   - An obfuscated hub adds its group's `obfuscation` settings (section 11, "Obfuscation");
     a plain hub leaves them out. A hub whose clients come over VLESS adds the group's VLESS
     user ID as `vless` (section 11, "VLESS").
4. The forwarder answers `{"id": number, "mask": bytes}`, a random 64-bit registration ID
   (an unsigned integer up to 2^64 - 1 as a JSON number: a decoder MUST keep all 64 bits,
   which a double does not) and the 32-byte key of the hellos' mask, the same for every hub, or `{"error": string}`
   and closes: the proof is wrong, the credentials do not verify, have expired, do not list
   the hub, are older than the forwarder saw or come from another period key than the one it
   saw first for the tag, no root or admin signed the registration, the records remove or
   freeze the hub, the obfuscation settings are outside their bounds,
   another group registered that key or that VLESS user ID, the forwarder has no VLESS
   and the hub asked for it, or the forwarder is full. To a hub that asked for VLESS the
   answer adds `"vless": {"port": number, "public_key": bytes, "short_id": string,
   "server_name": string}`, and the forwarder lets that user ID in while the registration
   lasts. A group has one registration: a new one replaces the old, whose
   connection closes.
5. The registration lasts while the connection does; the hub sends nothing more on it. The
   forwarder sends `{"seen": "ip:port"}` whenever it learns a new address of the hub's
   WireGuard port. The hub registers again whenever the connection breaks, with a backoff of
   1 s doubling to 60 s, and at once when the period's hubs' credential changes, so that the
   forwarder learns the new version, and with each new period under its new tag.

### Hellos

From its WireGuard UDP port, the hub sends the forwarder's UDP port a hello every second
until it hears `seen`, then every 15 s, which also keeps its NAT mapping open. A hello's
content is 36 bytes: `0x80 0x00 0x00 0x00`, the registration ID (8 bytes, big-endian), a
counter (8 bytes, big-endian, growing; the hub uses Unix nanoseconds), and the first 16
bytes of HMAC-SHA256, under 32 bytes exported from the TLS session with the label
`clipboardbridge forwarder hello`, of the first 20 bytes. On the wire it is masked: a random
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

A forwarder started with a site to borrow (`cbb forward -vless-site www.example.com`) also
listens on TCP (`-vless-listen`, port 443 by default) for VLESS inside REALITY:

- Its REALITY key is X25519, kept in its key file as a PEM block `CLIPBOARDBRIDGE REALITY
  KEY` of 32 bytes, made the first time. The short ID is the first 8 bytes of
  HMAC-SHA256(that key, `clipboardbridge reality short id`), in hex.
- A connection that is not a client's, by REALITY's check, gets the borrowed site's own
  TLS and answers, from port 443 of that site.
- Only the VLESS user IDs of registered hubs that asked for VLESS are let in. A client's
  UDP packets, whatever address the client names, go to the forwarder's own UDP port, from
  a port of the forwarder's own address for each of the client's flows, and are routed
  there as any client's; the answers go back the same way, and a TCP stream goes nowhere.
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
HMAC-SHA256 under the forwarder's private key (PKCS #8) of `clipboardbridge forwarder
state`, so the file names no group by itself, and a period lasts about a month, so the file
cannot link one month of a group to the next. A registration with a credential is refused
when another period key signed it or its version is below the one kept. At start it deletes the files earlier versions kept, one per group with its roots
and removals (`-records`, `groups` next to the key by default). Groups, addresses, sessions
and the records of the hubs that register with them live in memory while the connections
last, and the forwarder logs none of them; a forwarder SHOULD NOT write any of them to disk
or to a log. With `CBB_DEBUG=1` it logs counts each minute.

## 14. The blind relay

The meeting point, on the user's own server or the project's open relay, for a group that has
no computer to be its hub ([design.md](design.md), "Blind relay"). Implemented in Go (`internal/relay`,
`cbb relay`, and on the devices `internal/service/relay.go`), and on the phones through
`mobile/cbbtun` (`StartRelay`) with the kits' `RelayOnPhone`. It holds none of the group's keys: it ends each device's WireGuard
tunnel and joins two devices' connections inside the tunnels, and member TLS (section 4)
runs end to end between the two devices.

- The relay listens on one port number, UDP for WireGuard and TCP for registrations. Its
  key file holds an ECDSA P-256 key with a self-signed certificate, which devices pin as a
  forwarder's (section 13), and its WireGuard key.
- It serves only the groups it is started for (`cbb relay -group`, by tag), and refuses
  every other; an open relay (`cbb relay -open`) serves every group whose device registers,
  within the limits below.
- A device's service takes a relay only with the user's consent (`consent` on the control
  socket's `away` request, section 8), after `cbb global relay` showed what the relay learns;
  where sync away from home is off, the same request turns it on with new keys.
- A device keeps `relay: {endpoint, key}` in its `tunnel.json` (section 11), and then is
  neither a hub nor a hub's client: it ignores a hub's offer.

### Registration

Framing: as for the forwarder (section 13, "Registration"): one frame per message
(Conventions, "Frames"), at most 1 MiB in all from the other side.

1. The device connects over TCP and runs TLS 1.3 with ALPN `clipboardbridge-relay/2` and no
   server name. It MUST accept only the pinned key. A device whose period's members' credential
   lists its server key (section 18) presents only the certificate of that key, as a hub to
   its forwarder (section 13, step 1). Any other presents its member certificate, its admin
   CA if it has one, and the group's roots (the group CA, then the new roots of the claims that took effect).
2. With a member certificate, the relay checks that the leaf names a device (section 1) and
   verifies it, for client authentication, to one of the presented self-signed CAs whose
   tag is among the groups it serves. That tag names the group. A group that took a new root
   (a claim, section 10) is served under each of its tags the relay is given.
3. The key proof is the forwarder's (section 13, step 3) with the label
   `clipboardbridge relay key`: `{"e": bytes, "roots": bool}` from the relay, `{"key":
   bytes, "proof": bytes, "records": [record], "credentials": [credential], "roots":
   [bytes]}` from the device, with the device's WireGuard key.
   - With a member certificate, `records` are the group's authority records, as for the
     forwarder. The relay keeps them for the group in memory while it runs. It refuses a
     device whose member certificate chain they refuse, as a member does (section 10: its
     key revoked or frozen, or its admin CA removed without keeping it), and drops a
     registered device as soon as a later registration's records refuse its chain.
   - With a server certificate, `credentials` are the period's hubs' and members'
     credentials, and the relay checks them (section 18, "What a server checks"); the
     period's tag names the group, kept apart from the tags of group CAs. A relay that
     serves a fixed list of groups sets `roots` in its challenge, and the device adds the
     period credential to `credentials` and the group's roots, DER, the group CA first, as
     `roots`; an open relay sets no `roots` and never sees them. The device uses a fresh
     WireGuard key for each such registration, so the key links no two of them.
4. The relay answers `{"key": bytes, "psk": bytes, "addr": string}`: its own WireGuard
   public key, a new preshared key for this registration, and the device's tunnel address,
   which the relay chooses at random in fd00:cbb::/32 (not from the device ID, so no group
   can take another's address). Or it answers `{"error": string}` and closes: the proof is
   wrong, the records remove the device, the credentials do not verify, have expired, do not
   list the device, are older than the relay saw or come from another period key than the
   one it saw first for the tag, another device registered that WireGuard key, or the group
   has 64 devices there.
   A device has one registration: a new one replaces the old, whose connection closes.
5. The registration lasts while the connection does; neither side sends anything more on
   it. The relay keeps the device as a WireGuard peer, with its key, the preshared key and
   the tunnel address as its only allowed address, until the connection closes, and then
   drops it at once with all its connections. The device registers again whenever the
   connection breaks, with a backoff of 1 s doubling to 60 s.

### Inside the tunnel

The device runs a WireGuard client with the relay as its only peer, at the relay's
tunnel address `fd00:cbb::1`, with a keepalive every 25 s. The relay listens only on TCP
8764 at that address, and knows each connection's device by its tunnel address. Each
connection starts with one frame from the device, a request; the relay answers with
frames of its own, notes, each of at most 64 KiB. A device's **name** there is its device ID when it registered with
its member certificate, and its **pseudonym** when it registered with credentials: the
fingerprint of its server key (Conventions, "Fingerprints"), which the other members map to its device through
its server credential (section 18), and the relay to nothing. So the relay holds no device
ID, and a device's pseudonym changes with each period.

| Request | Meaning |
|---------|---------|
| `{"watch": true}` | keep this connection for the notes; a new watch replaces the old |
| `{"dial": "<name>"}` | join this connection to that device's |
| `{"answer": "<ticket>"}` | answer the call with that ticket |

| Note | Meaning |
|------|---------|
| `{"online": [...]}` | on the watch: the names of the group's other devices on the relay, sorted, sent at once and whenever they change |
| `{"call": "<name>", "ticket": "<base64>"}` | on the watch: that device dials this one; the ticket is 16 random bytes |
| `{"ok": true}` | on a dial and on its answer: the two connections are joined; the member protocol follows on both at once |
| `{"error": string}` | the request failed; the relay closes the connection |

1. Each device keeps one watch. For each device on the relay with a higher name than
   its own (as byte strings), the device dials it whenever it has no member connection
   to it another way (at home, for example, it has one), with a backoff of 1 s doubling to
   60 s.
2. The relay MUST call the other device only within the dialer's group, and only one that has a
   watch. It waits 10 s for the answer, then sends both connections `ok` and copies the
   bytes between them, unchanged, until either closes, and then closes both.
3. The dialing device runs member TLS as the client for the device that name stands for
   (section 4); the answering one as the server, and it MUST close the connection unless the
   client certificate names the device the call came from. So the relay can join two devices,
   but cannot pose as either.
   On a phone, cbbtun joins the answered connection to the app's member listener on the
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
   A device, in turn, ends its watch on a note longer than 64 KiB or an `online` list of
   more than 64 names or with a name that is not a device ID or a pseudonym (32 lowercase
   hex characters, or a fingerprint), and leaves unanswered a call with such a name, a ticket
   that is not 16 bytes in base64, or past 16 calls it is answering at once.
5. An open relay also limits: 4096 groups at a time; 16 registrations from one IP address,
   64 from one network (an IPv4 /24 or an IPv6 /64), 256 from one wide network (an IPv4
   /16 or an IPv6 /48) and 1024 from one IPv6 provider (a /32); and 1 MiB a second of copying for each group, both ways together,
   after a burst of two seconds' worth. It keeps at most 256 KiB of a group's authority
   records, 1 MiB of the records one network brought, 4 MiB of those one wide network
   brought and 16 MiB of those one IPv6 provider brought, and 128 MiB of all groups' records, and refuses a registration that would take
   it past any of them rather than keep part of them. It verifies
   a record once, when it first gets it, and keeps the verified set, so a group's later
   registrations that send the same records cost no checks; each new record is charged to
   what the address and network that sent it may start by the second. A registration over
   a limit gets `{"error": string}`. It forgets a group's records, or its period's key,
   versions and members' list, once the group's last device leaves. A registration it
   refuses leaves it as it was: the devices registered before stay, and it keeps nothing of
   the refused device's group, its period or records, except the records of a group it
   holds devices of that verified, which take effect for those devices. A newer members'
   credential counts the devices it leaves out as gone when the relay checks its limits.

### What it keeps

Only its key file. Registrations and connections live in memory while they last; the relay
logs none of them (a relay SHOULD NOT), and with `CBB_DEBUG=1` it logs counts each minute. It learns which
devices of a group are on it, which of them connect to each other, when and how much,
which a hub would not let out; what the devices send each other it cannot read. From devices
that register with credentials it learns them only by pseudonym, under the period's tag,
both new each period; from the others, their device IDs, the group's tag and roots, and
its authority records.

## 15. Commands

An admin orders one member to do something with a **command**: signed like a record (section
10) and never stored. `mode` sets the receiver's sync mode (design.md, "Sync modes"); `hub`
makes the receiver the group's hub (section 11, "Moving the hub"); `paste` puts a text where
the receiver's focus is, and `paste-off` turns remote paste off on the receiver (design.md,
"Remote paste"); `action` runs one of the receiver's quick actions, and `actions-off` turns
them all off there (design.md, "Quick actions"); `away-off` turns sync away from home off on
the receiver (section 11), which only its own user turns on again (D-45).

### The command

It has the form of a record, `{body, sig, chain?}`. Its body is JSON, in the strict form of
signed bodies (Conventions):

| Field | Type | Meaning |
|-------|------|---------|
| `v` | integer | `1`, or `2` for a sealed command (below) |
| `type` | string | `mode`, `hub`, `paste`, `paste-off`, `action`, `actions-off` or `away-off` |
| `group` | string | the group tag |
| `by` | string | the signer's device ID (32 of `0`-`9` and `a`-`f`): a receiver refuses a command whose `by` is no device ID, or, when its records show which device holds the signing key (the root's own device for the root's key, the device whose record names the admin CA), names another device, or, when they show none, names a device they show (a computer takes a legacy group CA's command that names a `full` member, since each holds that key) |
| `to` | string | the receiver's device ID (32 of `0`-`9` and `a`-`f`) |
| `id` | string | 128 random bits as 32 lowercase hex characters; IDs compare as byte strings |
| `time_ms` | integer | when it was signed, milliseconds since the Unix epoch, not negative |
| `expires_ms` | integer | after `time_ms`, at most 30 000 ms later: from `time_ms` + 1 to `time_ms` + 30 000 |
| `mode` | string | in a `mode` command: `own`, `shared`, `receive` or `send`; in a `paste` command: `paste` (the clipboard and the paste keys) or `type` (key by key) |
| `enter` | bool | in a `paste` command: press Enter after the text |
| `kind` | string | in a `paste` command: `text` or `secret` |
| `text` | string | in a `paste` command: the text, not empty, at most 1 MiB of UTF-8 for `paste` and 4 KiB for `type` |
| `action` | string | in an `action` command: the action's name, 1 to 32 of `a`-`z`, `0`-`9` and `-`, starting with a letter; in no other command |
| `hub` | object | in a `hub` command: `forwarder` (`endpoint`, `key`) or absent, `endpoints` (at most 8 with the forwarder's) or absent, at least one of the two, and `clients`, at most 256 of `{device, key, psk}` (base64, 32 bytes each, no device twice) |
| `sealed` | string | in a command of `v` `2` only: the orders, sealed to the receiver (below), base64 |

The exact rule, after the strict form: each field of this table has its JSON type in every
command. A command is refused without `mode` in `mode` and `paste`, `hub` in `hub`, `kind`
and `text` in `paste`, and `action` in `action`. In a command of another type these fields
are absent or empty: `mode`, `kind`, `text` and `action` `""`, `enter` `false`, and `hub`
absent, since even `{}` is an order. `mode` in a `mode` command is any string that is not
empty here; the receiver answers a mode it does not know with an error. `paste`'s `mode`
and `kind` are exactly the values above. The 1 MiB and 4 KiB of `text` count the bytes of
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
commands ignores the message, so the sender gives up after 10 s (20 s for `hub`).

Each computer and lite member keeps a secret for sealed messages in `seal.json` next to its
identity (sealed by the TPM where a computer has one, as the WireGuard key) and offers its public key in its hello
(`seal`, section 4) and in its pairing info (ADa, section 5); a root computer records it in
the device's record, as it records a changed system, a member that admits it records it at
once, and the phones keep it when they sign the record again. A command for it is sealed
(below, "Sealed commands").

A sender that has no connection to the receiver sends a `mode`, `paste`, `paste-off`,
`action`, `actions-off` or `away-off` command to the group's hubs it is connected to (the
root and the admins, "Several hubs" in section 11), and to no other member: a command's body,
a paste's text among it, is signed but encrypted only when sealed (below), and the hubs are
the devices the user gave admin powers. A `hub` command only goes directly. A member
that gets a command whose `to` is another device passes it on, unchanged, only when it is
connected to that device and has not passed that `id` before (it keeps the IDs until the
command expires, at most 4096), and passes the receiver's `result` back to the member it
came from, once; a member not connected to `to` drops it. The receiver names itself in the
result's `by`, so that a sender takes a result from a member in between only when `by` is
the receiver: the lite member refuses a command for another device
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
phones and the lite member refuse it.

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
one. A `paste-off` command turns remote paste off, Enter and consoles too; only the
device's own user turns it on again.

An `action` command carries only the action's name: what it does is defined on the receiver,
which knows the presets `lock` (lock the screen), `sleep`, `reboot` and `shutdown` (both a
minute after the command, so that `cancel-shutdown` can stop them), `cancel-shutdown` and
`restart` (the service ends and its service manager starts it again, after the result is
sent), and the actions its user added there, each a program with fixed arguments that the
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
`off` does (section 11, the control operation `away`): its tunnel keys go, and the members
connect again once the result is sent. It answers `done` also when sync away from home was
off already. Of the presets, the lite member knows only `reboot`, `cancel-shutdown` and
`restart`.

### Sealed commands

A sender seals a command's orders to its receiver when the receiver's device record has a
`seal` key, so that the members in between see only the header:

- The **orders** are the fields `mode`, `hub`, `enter`, `kind`, `text` and `action`, as a JSON
  object in the strict form of signed bodies, with only those of them the command has.
- The **associated data** is the header: the context `clipboardbridge command v2`, then
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
key: computers, lite members and both phone apps (the kits through the core's
`seal_command`), and every one of them has a key of its own, which it opens the commands for
it with (the phones through the core's `group_command`). So a receiver whose own record has one refuses a `paste` command in the
open, whose text was read on its way; it takes the other types in the open, as a watch signs
them (a watch checks what it signs and cannot read sealed orders). A receiver without a key
in its record takes commands in the open, and a member without a key of its own refuses a
sealed one. The vectors are `go-sealed-commands.json`.

## 16. Signed releases

Every release is described by signed files, so that a program updates only to a release the
project signed, whichever server it came from (design.md, "Secure updates"; D-69). The Go
package `internal/release`, `lite/core` (`release.rs`) and the phone kits (`Releases`) check
them alike, against `testdata/interop/go-release.json`.

### Keys

- Two **root keys**, P-256, each on its own hardware key kept offline. Every program pins
  both (their SubjectPublicKeyInfos); either one signs `keys.json`.
- **Release keys**, P-256, which `keys.json` certifies. A release key signs `release.json`
  and the channel files.
- A **status key**, P-256, which `keys.json` certifies with `use` `status`. It lives on the
  mirror of Google's revocation list and signs only `attest-status.json` (section 17,
  "Revoked attestations"), never a release.
- A **channel key**, P-256, which `keys.json` certifies with `use` `channel`. It lives on
  cbb.tools and signs only channel files, to renew them every week with the release they
  already name; it signs no `release.json`, so whoever takes it can at most hold a channel
  on a release the project signed, which a device that has seen a newer version refuses.

### The envelope

Each file is JSON: `{"body": "...", "sig": "...", "key": "..."}`. `body` is the body's exact
bytes (base64), signed as they are and never re-encoded; `sig` is ECDSA P-256 with SHA-256
over them, DER (base64); `key` is SHA-256 of the signer's SubjectPublicKeyInfo (base64, 32
bytes), which picks the key to verify with. A body is at most 256 KiB. Every body has `v`
(`1`) and `type`, so one kind of file is never taken for another; unknown fields are ignored.
A body follows the strict form of signed bodies (Conventions), checked before its fields, and
has every field of its row: only `min_from`, `docker`, `binaries`, `use` and `source_ms` may
be left out, and `use` is never empty. Every key is a P-256 SubjectPublicKeyInfo with an
uncompressed point, and every name, version, channel, serial number and hash matches its rule
whole (a line break after it is refused). `get.sh` and `get.ps1` refuse a body they cannot
read as the programs do: a member name that is not 1 to 64 of `a`-`z`, `0`-`9` and `_`, a
`null`, a backslash, or a field they read written twice. `seq` is from 1 to 2^63-1. The lite member reads no `attest-status.json`; the
vectors in `testdata/interop/strict-files.json` (section `releases`) test each row.

| `type` | Signed by | Fields |
|--------|-----------|--------|
| `keys` (`keys.json`) | a root key | `seq` (from 1, raised with each new file), `time_ms`, `expires_ms`, `keys`: 1 to 8 of `{key` (SubjectPublicKeyInfo, DER, base64), `name` (1-64 bytes), `use` (`release` when absent, `status` or `channel`)`}` |
| `release` (`release.json`) | a release key | `version`, `channel`, `time_ms`, `min_from` (a version, optional), `files`: 1 to 256 of `{name, size, sha256, binaries?}`, `docker` (optional `{image, digest}`) |
| `channel` (`stable.json`, ...) | a release key or a channel key | `channel`, `seq` (from 1), `time_ms`, `expires_ms`, `release` (the version), `release_sha256` (SHA-256 of that `release.json`'s body, hex) |
| `attest-status` (`attest-status.json`) | a status key | `seq` (from 1), `time_ms`, `expires_ms`, `source_ms` (when Google last changed its list, optional), `android_revoked`: the serial numbers |

- A key of a `use` the reader does not know is in `keys.json` for newer programs and signs
  nothing for it; a release key signs no `attest-status.json`, a status key no release
  or channel file, and a channel key nothing but channel files.

- A version is `X.Y.Z` or, for a release candidate, `X.Y.Z-rc.N`: decimal numbers of at
  most 6 digits without leading zeros (`N` from 1), compared number by number, a release
  candidate before its release; tags add the `v`.
- A channel name is 1-32 of `a-z`, `0-9` and `-`, starting with a letter.
- A file `name` is 1-128 of `A-Z a-z 0-9 . _ -`, not starting with `.` or `-`, each name
  once. `size` is its length in bytes and `sha256` its hash in lowercase hex. `binaries`, at
  most 64, are the programs inside an archive: `name`, the path inside it (`/` allowed, no
  `..`), and `sha256`.
- `docker.digest` is `sha256:` and 64 hex digits.
- A `keys` or `channel` file lives at most 100 days (`expires_ms` after `time_ms`, by at
  most 8 640 000 000 ms), and its `time_ms` is not negative. `keys.json` is signed again every 90 days, and a channel file
  before it expires. `attest-status.json` lives at most 8 days (691 200 000 ms) and is
  signed again at least a day before it expires.
- A serial number is lowercase hex without leading zeros (`0` for zero), at most 64
  digits, as Google's list names them. `android_revoked` lists each once, shorter numbers
  first and numbers of one length in string order, which is numeric order.

### Where the files are

A release on GitHub cannot take new files once published, while `keys.json` and the
channel files are signed again during its life. So `release.json` is a file of its release
(`releases/download/vX.Y.Z/release.json`), and the current `keys.json` and `stable.json` are
in the repository's branch `channel`, read at
`https://raw.githubusercontent.com/HunterEwok/clipboardbridge/channel/<file>`. A mirror
keeps all three at its top and each release's files under `vX.Y.Z/`. A device fetches
`keys.json` and the channel file, then the `release.json` of the version the channel file
names, and that version's files; `get.sh` and `get.ps1` install the release `stable.json`
names, not GitHub's latest, which differ for a few minutes after a release.

### The check

A device that looks for an update fetches `keys.json`, the channel file of its channel and
the `release.json` that names, and MUST take the release only when:

1. `keys.json` verifies under a pinned root key, decodes as a `keys` body, has not expired,
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
later; a version before 0.6 checks no signed files. A file it downloads MUST have the size and
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
  a `full` or `lite` member (phones update from their stores), a `release` message: `{"t":"release","release":{"keys":...,"channel":...,"release":...}}`.
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
  (control operation `release-file`), which keeps it (`release-files/` in its state
  directory, named by the SHA-256) only when the held `release.json` lists it with that size
  and hash. Before downloading, `cbb update` asks its service (`release-get`), which fetches
  the archive from its peers that send `media`, and downloads it from the server only when
  no peer has it; it checks the archive against `release.json` either way. A member deletes
  the archives of a release once it holds a newer one, and serves them through the group's
  tunnel too.
- A member that does not know `release` ignores it, as it ignores every message of a type it does not know.

## 17. Key stores

Where a device keeps its keys decides what a thief with the device gets: a key in a file can
be copied and used elsewhere until an admin removes the device, a key in hardware (the
Secure Enclave, the Android Keystore with StrongBox or the TEE, a TPM) signs only on that
device. The roadmap's key levels (item 31) build on this; this section is what 0.6 has so
far.

- A **hello** says where the sender's keys live in `key_store` (section 4); a receiver MUST
  NOT trust it for anything but what the root records, below: the phones send
  `hardware`, a Linux computer whose member key is in its TPM `hardware`, a rootless
  install (below) `rootless`, the other computers and the lite member `file`. A device that
  cannot tell sends `file`.
- **Rootless installs** (D-79). A full member or a lite member installed and run without root, as its
  user's own service, keeps its keys in a file that every program of that user may read. Its
  hello says `rootless`; a computer that is the group's root records such a
  member with `store` `rootless`, without `admin`, `kind` or `proof`, also over a record that
  said otherwise, and the phones go by its hello. Such a device MUST NOT be made the group's root, an admin or a hub, whatever
  the key level and the user's consent; it makes no group, offers no admin key and takes no
  admin CA itself. A reader that does not know the value takes it as `file` (below), so an
  older member keeps it from being an admin unless its user allowed keys in files.
- **Keys in a TPM.** A full member on Linux makes its member key and its admin key in the
  TPM 2.0 at `/dev/tpmrm0` when it may open it (the installer lets the service do so):
  an ECC P-256 signing key under the TPM's ECC storage root key (the TCG template, made
  again each time the service starts), fixed to that TPM and its parent, used without a
  password. The identity file then keeps the key's TPM blob, its public and private parts,
  in `key_tpm` and `admin_key_tpm` instead of `key` and `admin_key`; the blob loads only in
  that TPM. `CBB_TPM=off` makes new keys in a file; a key already in a file stays there
  until the device joins again. The CA keys of a root computer stay in the file.
- **The WireGuard key** (section 11) is sealed by the same TPM: a sealed data object under
  the storage root key, its blob in `tunnel.json` as `key_tpm` in place of `key`. The key
  crosses to and from the TPM in a session salted with the storage root key that encrypts
  it, so it never shows on the chip's bus. A key in the file moves into the TPM when the
  service next reads the state; WireGuard itself still uses it in memory.
  `CBB_TPM_SIMULATOR=host:port` points the service at a software TPM (swtpm), for tests.
- A **device record** says it in `store`: `file`, `hardware`, `rootless`, or `proven` once the group's
  root checked a proof of hardware (an attestation, "Evidence" below), with `kind`, the kind
  of hardware (`android-tee`, `android-strongbox`, or `tpm` for a TPM's proof), and `proof`, the hex SHA-256 of the
  attestation's leaf certificate. The signer writes what the device's hello said when it
  made the record, and a record that renames a device, or that makes it an admin, keeps its
  `store`, `kind` and `proof`. A record without `store`, made before 0.6, or
  with a value the reader does not know, counts as `hardware` for a `phone` and as `file`
  for every other role, which is where those versions kept the keys. `cbb status` and the
  apps' device pages show it.
- **Admins.** By default a device whose keys sit in a file does not become an admin: the
  root asks the user first, who allows it after a warning that whoever copies the file acts
  as an admin until another admin removes it (`cbb admin -allow-file-key`, and the warning
  in the phones' "Make it an admin" dialog). The root then signs the device record with
  `store` `file`. Moving the hub to such a computer makes it an admin only through that
  dialog.
- **The root.** `cbb new` on a computer warns that its root key is a file: the group's CA
  keys are not in the TPM yet, and Macs and Windows PCs keep all their keys in a file until
  the service uses the Secure Enclave and the Windows TPM (roadmap, D-44). From then on
  making a group or an admin with keys in a file asks first too.
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
hello, as one admitted by pairing) gets a record that says `hardware`. Nothing goes to the
TPM's maker: a TPM whose EK certificate is not in its NV, as Intel's and AMD's firmware TPMs
often, stays `hardware` (the strict key level will fetch theirs). The phones do not check
TPM evidence yet; a phone as the group's root ignores it.

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
(`internal/group/credential.go` and `serverkeys.go`, `internal/forward`, `internal/relay`,
`internal/service/credentials.go`). The vectors in `testdata/interop/v2-credentials.json`
(Go's `TestGoCredentialVectors`) give a group's records, the lists its credentials must hold,
a period with its server credentials, its hubs' and members' credentials, and sets a server
refuses. The lite member's core reads and checks them as Go does (`lite/core/src/credential.rs`:
the lists, the signatures and types, and a server's check), and passes the vectors; it
registers with no server, so it signs none and keeps none. The phones' kits do what Go does
(`Credentials.kt`, `Credentials.swift`: `ServerCredentials`, `CredentialStore`, and
`CredentialRefresh`, which signs as Go's refresh does, the period on a root phone), keep them
and pass them on in `MemberNode`, and pass the same vectors. A phone registers with a relay
by them once the members' credential lists its server key (`CredentialStore.registration`,
cbbtun's `Relay.SetCredentials`); it maps the pseudonyms the relay names back to device IDs
by the server credentials.

The group lives in **periods** of about 30 days. For each, its root signs, inside the group,
a fresh **tag** for the servers and a fresh **period key**; each device signs with its member
key a fresh **server key** that it uses with the servers in that period only. The servers see
only what the period key signs: the period's tag and lists of padded hashes of server keys.
A device that registers this way presents a certificate of its server key alone, which names
neither a device nor a group (`clipboardbridge server`, self-signed, no SAN, client
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
a relay that serves a fixed list of groups also the period credential with the group's roots
(the relay's challenge asks with `"roots": true`). The server MUST check that:

1. none has expired;
2. the members' credential is of the same period (`group`) and the hubs' credential's
   signer, or a key among its `admins`, signed it;
3. the period credential, if any, has the hubs' credential's tag as `tag` and its signer's
   key as `key`, and a relay with a fixed list of groups takes it only when one of the roots
   shown is a self-signed CA of a group it serves whose key signed the period;
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

A forwarder and a relay keep a group that registered with credentials apart from the groups
that registered with records, which they name by the group CA's tag (sections 13 and 14).

## 19. Registries

Every name the protocol uses, in one place. A new name gets a row here in the same change
that brings it in; an old name never gets a new meaning, and a receiver ignores a name it
does not know unless its section says it refuses it.

### ALPN protocol IDs and ports

| ID | Port | Section |
|---|---|---|
| `clipboardbridge/2` | TCP 8764, the member port; TCP 8764 inside the tunnel | 4 |
| `clipboardbridge-pair/2` | the member port; a listening joiner's port; TCP 8764 inside a guest tunnel | 6, 12 |
| `http/1.1` (or none) | the member port, on a member that serves the iPhone | 7 |
| `clipboardbridge-forward/2` | TCP on the forwarder's port (8764 by default) | 13 |
| `clipboardbridge-relay/2` | TCP on the relay's port (8764 by default) | 14 |
| (WireGuard, AmneziaWG) | UDP on the hub's, forwarder's or relay's port (8764 by default) | 11, 13, 14 |
| (VLESS with REALITY) | TCP 443 on a forwarder, by default | 11, 13 |
| (mDNS) | UDP 5353, 224.0.0.251 and ff02::fb | 3 |

### Labels and domain separation

| String | Use | Section |
|---|---|---|
| `EXPERIMENTAL-clipboardbridge-pair-v2` | TLS exporter label: CPace's `sid` | 6 |
| `clipboardbridge pair v2` + `0x00` | CPace's channel identifier prefix | 6 |
| `clipboardbridge iPhone token v1` | HKDF `info` of the token key | 7 |
| `clipboardbridge forwarder key` | TLS exporter label: a hub's proof of its WireGuard key | 13 |
| `clipboardbridge forwarder admin` | TLS exporter label: the root's or an admin's signature of a registration | 13 |
| `clipboardbridge forwarder hello` | TLS exporter label: the MAC key of a hub's hellos | 13 |
| `clipboardbridge forwarder state` | HMAC input: the key of the forwarder's state file | 13 |
| `clipboardbridge reality short id` | HMAC input: the forwarder's REALITY short ID | 13 |
| `clipboardbridge relay key` | TLS exporter label: a device's proof of its WireGuard key | 14 |
| `cbb attest v1` | the attestation challenge's prefix | 17 |

Only the pairing label carries the `EXPERIMENTAL-` prefix that RFC 5705, section 4, asks of
labels not registered with IANA; the forwarder's and the relay's labels do not, which is a
known deviation. Since an exporter label is part of the protocol, they stay as they are
within version 1, and a new ALPN version would rename them.

### Certificate names

| Common name | Certificate | Section |
|---|---|---|
| `clipboardbridge group root YYYY-MM-DD` | a group root CA | 2, 9 |
| `clipboardbridge group CA YYYY-MM-DD` | the group CA of a legacy group | 2 |
| `clipboardbridge iPhone CA YYYY-MM-DD` | the iPhone CA | 2 |
| `clipboardbridge admin <device ID>` | an admin CA | 10 |
| `<device ID>` | a member certificate, DNS name `cb-<device ID>.local` | 2 |
| `clipboardbridge.local` | the shortcut's server certificate | 2, 7 |
| `clipboardbridge server` | a server key's certificate | 13, 18 |
| `clipboardbridge forwarder` | a forwarder's or relay's own certificate | 13, 14 |

### Member protocol messages (`t`)

`hello`, `event`, `ping`, `bye`, `cert` (section 4); `get`, `missing` and binary `chunk`
frames (section 4, "Content"); `records`, `admin`, `phone_ca` (section 10); `tunnel`, `hubs`
(section 11); `command`, `result` (section 15); `release` (section 16); `evidence` (section
17); `credentials` (section 18).

### Values

| Name | Values | Section |
|---|---|---|
| Role (hello) | `full`, `lite`, `phone` | 4 |
| Role (device record) | `full`, `lite`, `phone`, `shortcut`, `watch`; read as legacy: `linux` and `mac` (`full`), `iphone` (`shortcut`) | 10 |
| System (`os`) | `linux`, `windows`, `macos`, `ios`, `android`, `watchos`, `wearos`, `none` | 4, 10 |
| Device form | `laptop`, `desktop`, `phone`, `tablet`, `tv`, `board`, `server`, `router`, `console`, `watch`, `retro`, `other` | 4 |
| Event `kind` | `text`, `secret`, `media` | 4 |
| Event `via` | `copy`, `phone`, `universal-clipboard`; read as legacy: `iphone` (`phone`) | 4 |
| Media part `type` | `image/png`, `image/jpeg`, `text/html` | 4 |
| Sync mode | `own`, `shared`, `receive`, `send` | 4, 15 |
| Key store | `file`, `hardware`, `rootless`, `proven` (records only); proof kinds `android-tee`, `android-strongbox`, `tpm` | 17 |
| mDNS TXT keys | `v`, `g`, `p`, `r` (`lite`, `phone`), `h` (`1`, `2`) | 3 |
| Record `type` | `device`, `revoke`, `root`, `freeze`, `thaw` | 10 |
| Command `type` | `mode`, `hub`, `paste`, `paste-off`, `action`, `actions-off`, `away-off` | 15 |
| Command result `status` | `done`, `refused`, `failed` | 15 |
| Quick action presets | `lock`, `sleep`, `reboot`, `shutdown`, `cancel-shutdown`, `restart` | 15 |
| Signer kinds of an action | `root`, `phone`, `computer`, `watch` | 15 |
| Pairing errors | `wrong-code`, `closed`, `busy`, `expired`, `too-many`, `refused`, `declined`, `taken` | 6 |
| iPhone `direction` | `to_iphone`, `from_iphone`, `none`, `unpaired`, `error` | 7 |
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
| Join QR code | `clipboardbridge://join?code=...&addr=...&fp=...` | 6, 7 |
| Remote invitation | `clipboardbridge://invite#...`, file `.cbbinvite` | 12 |
| Token | `cb1.` followed by base64url | 7 |

## 20. Security considerations

The threats, the defences and their code are in the [threat model](threat-model.md); this
section lists what an implementation must not get wrong, by section.

- **Authentication is the certificate, never the address or the name** (sections 3, 4). mDNS
  and `clipboardbridge.local` can be answered by anyone on the network; only the member TLS
  handshake, checked against the group's CAs and the records, says who a peer is.
- **The records decide, the same way everywhere** (section 10). An implementation that
  evaluates the records differently from the others splits the group: a removed device
  stays in on one member, or an admin's powers differ. The interop vectors in
  `testdata/interop` are the test of this; a new implementation MUST pass them.
- **The pairing code is short** (section 6). Its safety rests on CPace with at most three
  online guesses per code, on the code never leaving the joining device after it is spent,
  and on no free text from an unauthenticated peer. A remote invitation's secret is long
  because it crosses the internet.
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
- **Received content** (section 4) is checked against its SHA-256 before use; names are
  cleaned so that a copy cannot write outside its folder, and no link is followed or made.
- **Updates** (section 16) are taken only under the pinned root keys and never to an older
  version than the device has seen, so neither a server nor the network can hold a device
  back or give it another build.
- **Keys in files** (section 17) can be copied by whoever reads the disk; such a device
  becomes an admin or turns sync away from home on only after the user's consent.
