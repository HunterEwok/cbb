<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# The wire format of 0.6

For anyone writing another implementation, and for security reviewers: every message, record,
statement, command, grant, credential and copy of 0.6, byte by byte. [protocol.md](protocol.md)
says what each of them is for and the rules that apply them (the member protocol in section 4,
pairing in section 6, the records' rules in section 10); this page says how they are written. The
code is in the Rust core (`core/`): `cbb_core::format` reads the profile, envelopes, keys, frames,
grants, copies and the key container, `cbb_core::records` the records and statements,
`cbb_core::commands` the commands, `cbb_core::msg` the messages, `cbb_core::join` pairing, and
`cbb_core::blind` the server credentials. `format::print::describe` prints any item with the field
names of these tables, for logs in debug builds.

The format of 0.6 is preliminary: devices work together within one release, and 0.7, whose
format is final, may change any part of it ([versions and compatibility](reference/compatibility.md),
D-131). This page is under the same license as protocol.md, CC BY 4.0.

**Vectors.** `testdata/format/` holds the vectors that every reader checks: `gen.py` writes them
(`python3 -I testdata/format/gen.py OUTDIR`; deterministic, from fixed test keys and RFC 6979
signatures), the Rust core reads every one, and `testdata/format/check` is a second reader in Go
that shares no code with it. Each vector's verdict is `take`, `hold` (valid in form, kept and not
applied) or `refuse` with the name of the rule it breaks; the rule names in this page are those
names. The message tables below are the ones `msg::tables`, `msg::member`, `msg::wave4` and
`cbb_core::push` hold, which the vectors' `tables` (`messages3.json`, `messages5.json`,
`wave4.json`, `push.json`) repeat and the tests keep equal.

### Contents

- [1. The CBOR profile](#1-the-cbor-profile)
- [2. Common values](#2-common-values)
- [3. Signed objects](#3-signed-objects)
- [4. Records](#4-records)
- [5. The keys statement](#5-the-keys-statement)
- [6. Commands](#6-commands)
- [7. The leaf's grant](#7-the-leafs-grant)
- [8. Server credentials and cards](#8-server-credentials-and-cards)
- [9. Frames and messages](#9-frames-and-messages)
- [10. The copy](#10-the-copy)
- [11. Pairing, the invitation and the intro](#11-pairing-the-invitation-and-the-intro)
- [12. The key container for TLS](#12-the-key-container-for-tls)
- [13. Ceilings](#13-ceilings)
- [14. Registries](#14-registries)

## 1. The CBOR profile

Every message, record, statement, command, grant, credential and copy header is one CBOR data
item ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)) in this profile, which
`cbb_core::format::cbor` implements for every platform.

| Rule | What is allowed |
|---|---|
| `cbor/negative`, `cbor/tag`, `cbor/simple` | Major types 0 (unsigned integer), 2 (bytes), 3 (text), 4 (array) and 5 (map) only. No negative integers, no tags, no floats, no `false`, `true`, `null`, `undefined` or other simple values. A flag is the integer `1`, present only when set. |
| `cbor/indefinite`, `cbor/reserved` | Definite lengths only; additional information 28 to 31 is refused. |
| `cbor/shortest` | Every integer, length and count in its shortest form (RFC 8949, 4.2.1). |
| `cbor/int-range` | Integers from 0 to 2^63 − 1, so that every platform holds them in a signed 64-bit integer. |
| `cbor/map-key` | Map keys are unsigned integers from 0 to 65535, nothing else. |
| `cbor/map-order` | Map keys strictly increasing (so no key twice): for integers in shortest form, the bytewise order of RFC 8949's deterministic encoding. |
| `cbor/utf8` | Text is UTF-8 as RFC 3629 has it: no overlong forms, no surrogates, nothing above U+10FFFF. Control characters are a field's matter (its row). |
| `cbor/depth` | Arrays and maps nest at most 8 deep. |
| `cbor/count` | An array or map holds at most 4096 elements; a field's row is usually stricter. |
| `cbor/trailing`, `cbor/truncated` | The bytes are exactly one item: nothing after it, nothing cut. |

With these rules every value has exactly one encoding, so a reader that checks them knows that
encoding what it read gives the bytes it got. Writers sort map keys by number.

**Fields.** Every object of this page is a map whose keys are field numbers. Each row of the tables
gives a field's number, its CBOR type, whether it is needed, its values and its default. Two rules
hold for every object:

- `form/default`: a field whose value is its row's default is left out, and an object with it is
  refused. An optional array or map with no elements, and an optional text or bytes that are
  empty, are left out the same way. A needed field is always written, 0 included where its row
  allows 0. So one value has one object.
- `form/type`: a field of another CBOR type than its row's, or out of its row's range, refuses the
  object; the vectors cite the row as `records/<type>/<field>`, `commands/<field>` and so on.

**Sets.** An array that a row calls a *set* is sorted bytewise by each element's encoding (for an
array element, by its first element), each value once.

**Hidden characters.** U+0000 to U+001F, U+007F to U+009F, U+2028 to U+202E and U+2066 to U+2069
(`format::is_hidden`). A row that says "no hidden character" refuses text with one, and the printer
writes them as `\uXXXX`.

## 2. Common values

| Value | Form |
|---|---|
| **Key** | array `[alg, pub]`: `alg` an unsigned integer from the algorithm registry (section 14), `pub` bytes of the size that `alg` gives (`keys/shape`, `keys/es256`, `keys/xwing`, `keys/x25519`, `keys/slh-dsa`). |
| **Key hash** | SHA-256 over the Key's encoding (the array's bytes), 32 bytes: how records, commands and statements name a signer. |
| **Device ID** | the first 16 bytes of the key hash of the device's member key, so nobody takes another device's ID without its key. |
| **Group ID** | the first 16 bytes of SHA-256(`cbb group v3` ‖ 0x00 ‖ the encodings of the group's first root key, the recovery key's ES256 half and its SLH-DSA half). A recovery key that is not the group's gives another Group ID. |
| **Record ID**, statement ID, credential ID | SHA-256 over the body's bytes, 32 bytes; the signatures are not in it. |
| **Copy ID**, command ID, invitation ID | 16 random bytes; an invitation ID is never all zero. |
| **Time** | unsigned integer, Unix milliseconds; for display and for devices with clocks only. No rule of the records reads a time. |
| **Duration** | unsigned integer, milliseconds. |
| **Hybrid time** | array `[wall_ms, logical]`, both unsigned integers, `logical` at most 2^32 − 1; `[0, 0]` is refused. |
| **Address** (`addr`) | text `host:port` with an IP address: IPv4, or IPv6 without a zone, flow label or IPv4-mapped form. |

**Algorithms** (registry in section 14):

| `alg` | Name | `pub` | Signature or ciphertext |
|---|---|---|---|
| 1 | ES256: ECDSA P-256 with SHA-256 | 65 bytes, an uncompressed point (`0x04 ‖ X ‖ Y`) on the curve | signature 64 bytes `r ‖ s`, big-endian, 1 ≤ r < n, 1 ≤ s ≤ (n − 1)/2 (low S) |
| 2 | X-Wing KEM | 1216 bytes | encapsulated key 1120 bytes |
| 3 | X25519 (WireGuard) | 32 bytes | none |
| 4 | SLH-DSA-SHA2-128s (FIPS 205) | 32 bytes | signature 7856 bytes; only the recovery key's second half, never a record's signer |

Every signature key that signs a body is ES256: the hardware key stores (the Secure Enclave, a TPM,
the Android Keystore) sign only P-256. A record or statement that names a key of an `alg` the reader
does not know, where a signature key is wanted, is held like an unknown critical field (section
3.3); a signer of an unknown `alg` cannot be verified, and its object is refused.

## 3. Signed objects

### 3.1 The envelope

```
envelope = [ body: bytes, sig: bytes ]                 ; one signer
         / [ body: bytes, sig: bytes, sig2: bytes ]    ; with a second signature
```

- `body` is the encoding of the object's map, as bytes, so that it is signed and passed on
  unchanged. It is itself an item of the profile.
- `sig` is the ES256 signature of the body's `signer` (field 3) over the **signed message**
  `label ‖ 0x00 ‖ data`, with the label of the object's kind (section 14). `data` is the body;
  beside a second signature it is the body followed by the SHA-256 of `sig2`, so the first
  signature covers the second. The label keeps a signature of one kind from being taken as
  another.
- `sig2` is there exactly when the body has `signer2` (field 8), the key hash of a second key. It
  is at most 8192 bytes, and a recovery head's (record type 13) at most 32 KiB (`env/sig2`); its
  length follows its algorithm. A reader of 0.6 applies a statement, command, grant, credential,
  card or beacon on its first signature alone and keeps the second to pass on; a recovery head
  carries both of the recovery key's signatures (section 4.8). A first signature that does not
  verify over the body with the second's hash is `env/damaged`.
- `env/shape`: another number of elements, a body or signature that is not bytes, or `sig2`
  without `signer2` (or the reverse) refuses the envelope. `sig/size`, `sig/range`, `sig/low-s`
  and `sig/verify` name a signature of the wrong length, `r` or `s` out of range, a high `s`, and
  one that does not verify.
- A receiver checks, in this order: the body's size against its kind's ceiling (`env/size`,
  section 13), the profile on the envelope and on the body, the body's fields against their rows,
  then the signature, then the rules that apply the object. A body that fails a step never reaches
  the next, so nobody verifies a signature over a body others read otherwise, and a record is
  stored by its ID only after its signature checked.

### 3.2 Fields every signed body has

| # | Field | Type | Meaning |
|---|---|---|---|
| 0 | | | not used in signed bodies |
| 1 | `type` | uint | the object's type within its kind |
| 2 | `group` | bytes 16 | the Group ID; in a `hubs` or `members` credential the period's tag |
| 3 | `signer` | bytes 32, or Key | the signer's key hash; in a server credential and a card the signer's Key itself, since a server has no records to find it in |
| 4 | number | uint | the signer's increasing number for the kind: a record's `seq`, a statement's `epoch`, a command's `n`, a grant's counter, a credential's or card's `version`, a beacon's `n` |
| 5 | `prev` | bytes 32 | records only: the ID of the signer's record with `seq` − 1; absent when `seq` is 1 |
| 6 | `time_ms` | Time | the signer's clock, for display (a command's and a beacon's are needed) |
| 7 | `expires_ms` | Time | commands, credentials and cards only |
| 8 | `signer2` | bytes 32 | the key hash of the second signer (3.1) |
| 9 | | | reserved for a later common field |
| 10–255 | | | the type's own fields: the critical zone |
| 256–65535 | | | the optional zone |

### 3.3 Two zones

- **Critical zone, keys 0 to 255.** A reader that meets a key there that its version does not
  define for the object's kind and type, a `type` it does not know, or a Key of an unknown `alg`
  where a signature key is wanted, **holds** a record or statement: it verifies the signature as
  for any other, stores it, passes it on in sync unchanged, and never applies it. The state lists
  held records among the newer ones (at most 16), and the apps say to update. A command, grant,
  credential, card or beacon with one is refused (`form/critical`): a command is never stored, and
  a leaf and a server must understand all they take.
- **Optional zone, keys 256 to 65535.** A reader skips a key it does not know there, whatever its
  value, which still follows the profile; the signature covers it.
- `revoke`, `freeze`, `resolve` and recovery head records are written with the fields of 0.6
  alone, never with a critical field of a later version, so that every later version applies
  them. A writer refuses to sign one with more.
- `min_rules` in `settings` (section 4.4) names the oldest rules version that may work with the
  group's secrets. 0.6 is rules version **1** (`records::RULES_VERSION`). A device whose rules
  version is lower opens no secret (a content is opened only to learn that it is one, then
  dropped), keeps syncing everything else, and asks its user to update.

## 4. Records

Label `cbb record v3`. A record is the envelope of 3.1 with the common fields 1 to 6 of 3.2;
`seq` is from 1 to 2^31 − 1 (`records/seq`), and `prev` is there exactly when `seq` is above 1
(`records/prev`). A body is at most 16 KiB, a checkpoint's 256 KiB. Who may sign each type, and
how the set of records gives the group's state, is in [protocol.md](protocol.md), section 10,
"Records in 0.6".

| `type` | Name | Section |
|---|---|---|
| 1 | `device` | 4.1 |
| 2 | `revoke` | 4.2 |
| 3 | `freeze` | 4.2 |
| 4 | `thaw` | 4.3 |
| 6 | `resolve` | 4.3 |
| 7 | `settings` | 4.4 |
| 8 | `copies` | 4.5 |
| 9 | `checkpoint` | 4.6 |
| 10 | `hubs` | 4.7 |
| 13 | recovery head | 4.8 |
| 14 | `ack` | 4.7 |

Types 5, 11 and 12 are retired: a record of one is refused (`records/retired`), and the numbers are
never given again. A type above them that this version does not know holds the record.

**`seen`.** Several types carry a `seen` list: entries `[key hash bytes 32, seq uint ≥ 1, record ID
bytes 32]`, a set by key hash, at most 1024 entries. Each names the head of a signer's chain that
the author held: a record of that signer at or below `seq` was seen only when it is on the chain
ending at that record ID, and a signer that is not listed was seen at 0 (`records/<type>/seen`).

### 4.1 `device` (1)

| # | Field | Type | Needed | Values | Default |
|---|---|---|---|---|---|
| 10 | `key` | Key | yes | the member key, `alg` 1; the device's ID is the first 16 bytes of its hash | |
| 11 | `name` | text | yes | 1 to 64 bytes, no hidden character | |
| 12 | `role` | uint | yes | 1 member, 2 phone, 3 watch, 4 leaf | |
| 13 | `rights` | uint, bits | no | 1 read (copies are sealed to it), 2 send (it may make copies), 4 hub, 8 secrets (secrets are sealed to it). A hub without read only passes copies on. Bits are grants: a bit a version does not know grants nothing | 0 |
| 14 | `skip` | uint, bits | no | the content types not sealed to it: bit (type − 1) for each content type of 10.3 | 0 |
| 16 | `caps` | uint, bits | no | 1 admin, 2 dials, 4 hub; only with role member | 0 |
| 17 | `os` | uint | no | the system registry (section 14); a number this version does not name is kept and shown as unknown | unknown |
| 18 | `store` | uint | no | where its keys live: 1 file, 2 hardware, 3 rootless, 4 proven ([protocol.md](protocol.md), section 17) | 1 |
| 19 | `proof` | uint | no | 1 android-tee, 2 android-strongbox, 3 tpm; only with `store` 4 | |
| 20 | `admin` | Key | no | the device's admin key, `alg` 1 | |
| 21 | `powers` | uint, bits | no | 1 admit, 2 manage, 4 remove, 8 remove-admins, 16 freeze, 32 thaw, 128 hub, 256 periods; bit 64 is retired and refused; only with `admin` | 0 |
| 22 | `commands` | uint, bits | no | the command types the admin may sign: bit (type − 1) for each type of section 6; only with `admin` | 0 |
| 23 | `holds_root` | flag | no | the device holds the signer's root key | |
| 24 | `replaces` | bytes 32 | no | the key hash of the member key of the device this one replaces ("this is the new laptop"); never its own | |
| 25 | `guarded` | flag | no | a guarded leaf (a lock, a door); only with role leaf | |
| 26 | `seen` | `seen` | no | when a root's record takes the device's admin key away or names another: what the old key signed up to these heads still counts | empty |

Field 15 is retired: a `device` record with it is refused (`form/critical`). The apps and `cbb`
write one of three fixed sets of `powers` and `commands` (`records::body::AdminKind`: a watch's, a
computer's, a phone's).

### 4.2 `revoke` (2) and `freeze` (3)

| # | Field | Type | Needed | Values |
|---|---|---|---|---|
| 10 | `keys` | array of bytes 32 | yes | 1 to 256 key hashes, a set |
| 11 | `seen` | `seen` | yes | what the author held of the keys it names and their pairs (a device's admin key, an admin key's member key); may be empty |

### 4.3 `thaw` (4) and `resolve` (6)

| # | Field | Type | Needed | Values |
|---|---|---|---|---|
| 10 | `records` | array of bytes 32 | yes | 1 to 256 record IDs, a set |
| 11 | `seen` | `seen` | thaw only, yes | what the thaw saw of the frozen keys; the rest stays cut; may be empty |

### 4.4 `settings` (7)

| # | Field | Type | Needed | Values | Default |
|---|---|---|---|---|---|
| 11 | `key_level` | uint | no | the key store a device needs for secrets: 1 proven, 2 hardware, 3 files | 2 |
| 12 | `min_rules` | uint | no | 1 or more (3.3) | 1 |
| 14 | `shared` | flag | no | a shared group: nothing is sent to it by itself, only what a person sends on purpose | |
| 15 | `servers` | array | no | at most 16 `[kind uint, endpoint text, pin bytes 32]` in the person's order, each `kind` and `endpoint` once: `kind` 1 forwarder, 2 relay, 3 push (reserved), a kind this version does not know kept and passed over; `endpoint` `host:port`, 1 to 255 bytes, no control character; `pin` the SHA-256 of the server's TLS key (its SubjectPublicKeyInfo). 0.6 writes relays only (D-121) | empty |

Fields 10 and 13 are retired: a `settings` record with one is refused (`form/critical`).

### 4.5 `copies` (8)

| # | Field | Type | Needed | Values | Default |
|---|---|---|---|---|---|
| 10 | `ttl_ms` | Duration | yes | an ordinary copy's lifetime: 60 000 to 3 600 000 (the apps' default 300 000) | |
| 11 | `seen` | `seen` | yes | of two admins' records the one that saw the other wins; may be empty | |
| 12 | `secret_ttl_ms` | Duration | no | a secret's lifetime: 5 000 to 60 000 | 60 000 |

### 4.6 `checkpoint` (9)

| # | Field | Type | Needed | Values |
|---|---|---|---|---|
| 10 | `heads` | array | yes | `[key hash, seq ≥ 1, record ID]`, a set by key hash. Its own key's entry, if any, is the record just below it: `seq` − 1 and `prev` (`records/checkpoint/own-head`, `records/checkpoint/own-prev`) |
| 11 | `keep` | array of bytes 32 | no | record IDs below the heads that still count, a set |

### 4.7 `hubs` (10) and `ack` (14)

| Type | # | Field | Type | Needed | Values |
|---|---|---|---|---|---|
| `hubs` | 10 | `hubs` | array of bytes 16 | yes | 1 to 16 device IDs, each once, in the person's order (not sorted) |
| `hubs` | 11 | `seen` | `seen` | yes | as in `copies`; may be empty |
| `ack` | 10 | `seen` | `seen` | yes | the heads of other keys that the signing admin key holds, at least one: the root lets a removal go only once every live admin key acknowledged it |
| `ack` | 11 | `spare` | Key | no | a spare admin key its device made and signs nothing with; read, checked and kept |

### 4.8 The recovery head (13)

A change of root, signed by the group's recovery key: its ES256 half signs as `signer` and its
SLH-DSA half as `signer2`, so every head carries both signatures.

| # | Field | Type | Needed | Values |
|---|---|---|---|---|
| 8 | `signer2` | bytes 32 | yes | the key hash of the recovery key's SLH-DSA half; differs from `signer` |
| 10 | `root` | Key | yes | the new root key, ES256; neither half of the recovery key (`records/recovery/root`) |
| 11 | `list` | bytes 32 | yes | the hash of the list that rides beside the head |
| 12 | `from` | uint | no | the seq at which the new root's own records start; absent for a fresh key; at most 2^31 − 1 (`records/recovery/from`) |
| 13 | `first` | bytes 32 | yes | the ID of the new root's first checkpoint, which the writer signs before the head |

`seq` is 1 to 64 (`records/recovery/seq`). The **list** is an array of 0 to 1536 record IDs of
earlier roots, a set (`records/list`): the records that stay. It travels beside its head, in field 3
of message `records`, and its hash is SHA-256(`cbb recovery list v3` ‖ 0x00 ‖ its bytes). Bytes with
the right hash that do not read are the empty list. A head's first checkpoint is at most 256 KiB, as
every checkpoint.

### 4.9 The set digest

Sets are compared by IDs: the **set digest** is SHA-256(`cbb set v3` ‖ 0x00 ‖ the IDs of the records
a member holds, sorted, concatenated). A sender sends records in the order of their dependencies, a
root's first; a receiver drops a record whose signer it does not know and keeps nothing of it.

## 5. The keys statement

Label `cbb keys v1`. A device's own statement of the key that copies and commands are sealed to it
with, signed by its member key; nobody else can sign it.

| # | Field | Type | Needed | Values |
|---|---|---|---|---|
| 1 | `type` | uint | yes | 1 |
| 2 | `group` | bytes 16 | yes | the Group ID |
| 3 | `signer` | bytes 32 | yes | the key hash of the device's member key |
| 4 | `epoch` | uint | yes | 1 or more |
| 6 | `time_ms` | Time | no | only from a wall clock; a device without one writes none |
| 10 | `seal` | Key | yes | `alg` 2 (X-Wing), 1216 bytes |
| 256 | `seals` | array of Keys | no | sealing keys of later algorithms; a sender seals to the first key it knows of field 10 and then this list |

- A body is at most 32 KiB. A type other than 1, a critical field other than these, a `seal` of
  an unknown `alg`, or `signer2` holds the statement; a `seal` of a known algorithm that is not
  X-Wing is refused (`keys/xwing`). The other rules: `statements/group`, `statements/signer`,
  `statements/epoch`, `statements/seal`.
- Of a device's statements that verify, the highest `epoch` counts. A statement counts only while
  the device has a counting `device` record.
- A device makes a new epoch when its newest is a week old, on its own clock or running time, and
  keeps the previous secret until the newest is a week old. A sender with a clock does not seal to
  a statement whose `time_ms` is more than 35 days before its clock.
- Message `keys` (t 7) carries statements, at most 256 a message.

## 6. Commands

Label `cbb command v3`. A device is controlled only by commands, each signed by its commander and,
when it carries orders, sealed to the receiver's sealing key, so that only the receiver reads them.

| `type` | Name | Orders (inside `sealed`) |
|---|---|---|
| 1 | `mode` | 10 `mode`: 1 shared, 2 own |
| 2 | `hub` | 13 `stop`: 1, alone; or 10 `[endpoint text, key hash bytes 32]` (the endpoint away from home, 1 to 255 bytes without hidden characters, and the chosen hub's key hash; a receiver whose own key hash differs refuses it), 11 `forwarders`: 1 to 8 `[address text, pin bytes 32]`, each address once; field 12 is retired and refused; not empty |
| 3 | `paste` | 10 `way`: 1 paste, 2 type; 11 `enter`: flag; 12 `kind`: 1 text, 2 secret, 3 media; 13 `text`: text, 1 MiB, 16 KiB for `type`; 14 `copy`: copy ID, with kind 3 and way 1, in place of `text` |
| 4 | `paste-off` | none |
| 5 | `action` | 10 `action`: text, 1 to 32 of `a-z 0-9 -`, starting with a letter |
| 6 | `actions-off` | none |
| 7 | `away-off` | none |
| 8 | `mute` | 10 `for_ms`: 1 to 2 592 000 000; absent for until `unmute` |
| 9 | `unmute` | none |
| 10 | `device` | 10 `name`: text, 1 to 32 bytes without hidden characters (a command the device's firmware declares); 11 `args`: bytes, 1 B to 4 KiB, one item of the profile, the firmware's own |

The orders are a map in the profile; a field below 256 that the type does not define refuses them
(`form/critical`), and the type's other rules are `orders/mode`, `orders/hub`, `orders/paste`,
`orders/action`, `orders/mute` and `orders/device`.

Body:

| # | Field | Type | Needed | Values |
|---|---|---|---|---|
| 1 | `type` | uint | yes | 1 to 10 (`commands/type`) |
| 2 | `group` | bytes 16 | yes | (`commands/group`) |
| 3 | `signer` | bytes 32 | yes | a root key, an admin key, or for a leaf a commander its grant names |
| 4 | `n` | uint | yes | the signer's counter, 1 or more, increasing across all its commands; a receiver keeps the last of each signer and refuses one not above it (`commands/counter`) |
| 6 | `time_ms` | Time | yes | |
| 7 | `expires_ms` | Time | yes | `time_ms` + 1 to `time_ms` + 600 000 (`commands/expires`); every 0.6 writer gives 30 000 |
| 10 | `to` | bytes 16 | yes | the receiver's device ID |
| 11 | `id` | bytes 16 | yes | random |
| 13 | `nonce` | bytes 16 | with a guarded leaf | the one-time number the leaf gave this commander (message `nonce`) |
| 14 | `epoch` | uint | with `sealed` | the epoch of the receiver's statement it is sealed to |
| 15 | `sealed` | bytes | types 1, 2, 3, 5, 8 and 10 | the orders sealed to the receiver's `seal` key: X-Wing HPKE (`cbb_core::seal`), the encapsulated key (1120 bytes), then the ciphertext and its 16-byte tag; associated data `cbb command v3` ‖ 0x00 ‖ the encoding of the body without field 15 |

- Fields 8 (`signer2`) and 12 are critical fields this version does not know: a command with one
  is refused (`form/critical`). A type with orders and no `sealed`, or `sealed` on a type without
  orders, is refused (`commands/sealed`), and so is `epoch` without `sealed` (`commands/epoch`).
- A body is at most 64 KiB, a `paste`'s 2 MiB (`env/size`); the opened orders the same.
- A receiver checks the signature first, by the key the body names; every refusal before it is
  `commands/signer` and gets no answer. After it: group, `to`, whether the signer may command
  (`commands/signer`), an admin's `commands` bit for the type (`commands/right`), with a clock the
  times within 60 s (`commands/late`), the counter, at a guarded leaf the grant not stale
  (`commands/stale`) and the one-time number (`commands/nonce`), then the orders. A refusal after
  the signature is answered by `result` (t 10) with status 2 and the rule's name in `reason`.
- Message `command` (t 9) carries the envelope; message `nonce` (t 21) carries a one-time number
  from a guarded leaf, or, without field 2, asks a leaf for one.

## 7. The leaf's grant

Label `cbb grant v1`. A small device's paper from the group: one signed envelope, whose body lists
whom the leaf obeys and whom it seals to. The root signs any grant; for an ordinary leaf a key among
the commanders of its current grant signs one too, and its first grant comes from the admitter with
the root's record of that admin key. A guarded leaf takes grants from the root only.

| # | Field | Type | Needed | Values | Default |
|---|---|---|---|---|---|
| 1 | `type` | uint | yes | 1 | |
| 2 | `group` | bytes 16 | yes | the Group ID | |
| 3 | `signer` | bytes 32 | yes | the root's key hash, or an admin key's | |
| 4 | `counter` | uint | yes | above the leaf's last of its signer's side (the root's or the admins') | |
| 6 | `time_ms` | Time | no | the signer's clock; a hint for the leaf's clock | |
| 10 | `leaf` | bytes 16 | yes | the leaf's device ID | |
| 11 | `life_ms` | Duration | guarded only | 1 to 3 456 000 000 (40 days), on the leaf's running time from when it took the grant (`grants/life`) | 3 024 000 000 |
| 12 | `commanders` | array of Keys | no | at most 16 ES256 Keys, a set by key hash: the keys the leaf obeys (`grants/commanders`) | empty |
| 13 | `readers` | array | no | at most 16 `[device ID, member Key]`, a set; the ID is the Key's: whom the leaf seals its state and copies to, and takes copies from (`grants/readers`) | empty |
| 14 | `neighbors` | array of bytes 32 | no | at most 8 member key hashes, a set: the only peers the leaf connects with (`grants/neighbors`) | empty |
| 15 | `guarded` | flag | no | a guarded leaf (`grants/guarded`) | |
| 16 | `time_ms` | Time | no | the signer's clock when it signed | |
| 17 | `root_counter` | uint | no | an admin grant's: the root counter it was made under | 0 |
| 18 | `replaces` | bytes 32 | no | an admin grant after its first: the SHA-256 of the body of the grant the leaf keeps (`grants/replaces`) | |
| 19 | `recovery` | uint | no | the recovery seq the grant was made under, 1 to 64 (`grants/recovery`) | 0 |

- A body is at most 4 KiB. A field below 256 other than these, and `signer2`, refuse the grant
  (`form/critical`); a type, group or leaf other than the leaf's is `grants/shape`.
- Message `grant` (t 20), and the Welcome's field 6: field 2 the grant envelope; field 3 the root's
  record of the admin key that signed it, needed when an admin signed the leaf's first grant
  (`grants/admin`): a `device` record signed by the root, with an ES256 admin key and `admit`.
- A leaf that sees a grant of a newer recovery seq asks for message `roots` (t 24): field 2 the
  recovery heads from its kept root to the current one, field 3 two records of its root at one
  seq, when that root forked.

## 8. Server credentials and cards

### 8.1 Credentials

Label `cbb credential v2`. The blind credentials a group gives its forwarder and relay
([protocol.md](protocol.md), section 18). The signer's Key is in the body.

| # | Field | Type | In types | Values |
|---|---|---|---|---|
| 1 | `type` | uint | all | 1 period, 2 server, 3 hubs, 4 members |
| 2 | `group` | bytes 16 | all | period and server: the Group ID; hubs and members: the period's tag |
| 3 | `signer` | Key | all | period: the current root key; server: the device's member key; hubs: the period key; members: the period key or a server key among `admins` |
| 4 | `version` | uint | all | 1 or more |
| 7 | `expires_ms` | Time | all | |
| 10 | `tag` | bytes 16 | period, server | the period's tag, 16 random bytes |
| 11 | `key` | Key | period, server | the period key, or the device's server key for the period; ES256 |
| 12 | `hubs` | array of bytes 32 | hubs | server key hashes, padded with random entries to 4, 8 or 16 |
| 13 | `admins` | array of bytes 32 | hubs | the same, to 4, 8, 16, 32 or 64 |
| 14 | `members` | array of bytes 32 | members | the same, to 4, 8, 16, 32, 64, 128 or 256 |

- A field a type does not list refuses the credential (`credentials/<type>/<field>`), and so does
  a list of a length that is not one of its padded lengths. Lists are not sorted: real entries
  first, hubs in their order. A second signature is taken on the first alone.
- A body is at most 16 KiB. A server key hash is the key hash of section 2.
- Each server gets its own period, with its own tag and key, and each device its own server key
  for it (`blind::alias`), so two servers that compare what they saw find nothing in common.

### 8.2 The server card

Label `cbb server card v1`, signed by the operator's key (`blind::card`): its name, addresses, TLS
keys, what it is and which ways around a block it offers, until when. A group adds a server by its
card; the operator changes keys and addresses with a new version.

| # | Field | Type | Values |
|---|---|---|---|
| 1 | `type` | uint | 1 |
| 3 | `signer` | Key | the operator's key |
| 4 | `version` | uint | 1 or more |
| 7 | `expires_ms` | Time | |
| 10 | `name` | text | 1 to 128 bytes |
| 11 | `endpoints` | array of text | at most 8 |
| 12 | `keys` | array of Keys | at most 4: the server's TLS keys |
| 13 | `kinds` | uint, bits | 1 forwarder, 2 relay; 4 push is reserved |
| 14 | `paths` | uint, bits | 1 WireGuard, 2 AmneziaWG, 4 VLESS |

## 9. Frames and messages

### 9.1 Frames

A frame is a 4-byte big-endian length `L`, then `L` bytes: one message, a map in the profile, its
type `t` in field 0 (`frame/message`).

- **The grid.** `L` is one of 64, 256, 1024, 4096, 16384, or a multiple of 16384 (`frame/grid`). A
  message that is not that long by itself carries `pad` (field 1): zero bytes (`frame/pad`), just
  enough for the smallest grid size it can reach; a message already on the grid has no `pad`. So
  the size of a frame tells only its step: not the number of devices in a records message, not
  whether a small message was a copy.
- **Limits.** A member connection 7 MiB (`frame::LIMIT_MEMBER`, 7 340 032 bytes), pairing 1 MiB
  (`frame::LIMIT_PAIRING`; message 67 alone may reach the member limit), toward a leaf 16 KiB
  (`frame::LIMIT_LEAF`), which a peer learns from the leaf's record and never exceeds. A length of
  0, off the grid or over the limit closes the connection.
- **Chunks.** A length with its top bit set marks a binary `chunk` frame, which carries a copy's
  sealed blob and comes only to a member that sent `get`: the length's other bits give the length
  of what follows, then the blob's SHA-256 (32 bytes), the offset (8 bytes, big-endian), the data's
  length (4 bytes, big-endian, at most 256 KiB), the data, and zeros up to a multiple of 16 KiB. A
  chunk is not a message and is read before these rules; a longer one than 278 528 bytes closes the
  connection.

**Messages.** A receiver ignores a `t` it does not know. Within a message it knows it skips a field
the message's table does not list (messages are not signed and have no zones), so a later version
adds messages and fields freely; a field it lists must have its type and bounds, a needed field must
be there, and a field at its default is left out. A value of a known field that lies outside what
this version knows refuses the message, except where reading it as absent is neutral or stricter
(`msg::later`, one row a field, and the vectors of `testdata/format/future.json`): never where that
would grant more, change the mode, or change what a person compares or approves.

### 9.2 Message types

| `t` | Name | Fields | Where |
|---|---|---|---|
| 1 | `hello` | 9.3 | member |
| 2 | `copy` | 2 the copy (section 10) | member |
| 3 | `ping` | none | member |
| 4 | `bye` | none | member |
| 5 | `records` | below | member |
| 6 | `have` | 2 record IDs, a set, at most 4096: "I hold these" | member |
| 7 | `keys` | 2 statement envelopes, at most 256 (section 5) | member |
| 8 | `intro` | 11.4 | member |
| 9 | `command` | 2 the command envelope (section 6) | member |
| 10 | `result` | below | member |
| 11 | `credentials` | below | member |
| 12 | `release` | 2 `keys`, 3 `channel`, 4 `release`: each the bytes of a release file as published, at most 512 KiB ([protocol.md](protocol.md), section 16) | member |
| 13 | `get` | 2 `sha256` bytes 32, needed; 3 `offset`; 4 `length` (absent: 0, which cancels) | member |
| 14 | `missing` | as `get`: the blob is not held whole | member |
| 15 | `tunnel` | to a hub only: 2 `key` the device's WireGuard key (X25519 Key), 3 `confirm` bytes 32 ([protocol.md](protocol.md), section 11) | member |
| 16 | `hubs` | hub to hub: 2 `stopped` flag, 3 `serving` flag | member |
| 17 | `guest` | an admin and a hub, about an invitation's guest; below | member |
| 18 | `reach` | 2 device IDs, a set, at most 256 | member |
| 19 | `evidence` | below | member |
| 20 | `grant` | section 7 | member |
| 21 | `nonce` | 2 bytes 16 (section 6) | member |
| 22 | `beacon` | 2 the beacon envelope (9.4) | member |
| 23 | `reseal` | 2 the copy's ID bytes 16, 3 the asker's current epoch: "seal this copy to me again" (10.4) | member |
| 24 | `roots` | section 7 | member |
| 25 | `entries` | 2 `keys`, 3 `entries`: as `release`, for `entries.json` | member |
| 26 | `waiting` | the holder (a hub) to a device that may admit; 11.3 | member |
| 27 | `dismiss` | that admin to the holder; 11.3 | member |
| 28 | `push` | member to phone: 9.6 | member |
| 29 | `push-renew` | member to phone: 9.6 | member |
| 30 | `want` | 2 record IDs, a set, at most 4096; 3 the hash of a list (32 bytes); at least one: "give me these" | member |
| 64–69 | pairing | 11.1 | `cbb-pair/3` |
| 80–84 | forwarder | 9.5 | `cbb-forward/3` |
| 90–99 | relay | 9.5 | `cbb-relay/3` |
| 100–104 | push service | 9.6 | `cbb-push/1` |

`records` (t 5):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `records` | array 1..4096 of envelope |  |
| 3 | `lists` | array 1..64 of bytes 1..52228 |  |

Field 2 carries record envelopes in the order of their dependencies; field 3 the lists of recovery
heads (4.8), each with the head that names it. A set wider than 4096 IDs goes over several
messages.

`result` (t 10), the answer to a command; `status` 1 done, 2 refused, 3 failed; `tunnel` is the hub's offer (11.3):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `id` | bytes 16 | yes |
| 3 | `by` | bytes 16 | yes |
| 4 | `status` | uint 1..3 | yes |
| 5 | `reason` | text 1..256 |  |
| 6 | `tunnel` | map offer |  |

`credentials` (t 11), the credentials for one server, always with its pin: a face for each server,
never one for all. Field 3 is room for obfuscation settings that change with the period, which no
server reads:

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `list` | array 1..259 of envelope | yes |
| 3 | `obfuscation` | map obfuscation |  |
| 4 | `server` | bytes 32 | yes |
| 5 | `address` | text 1..261 |  |

`evidence` (t 19), an attestation of one of the sender's keys ([protocol.md](protocol.md), section
17): `format` 1 android-key, 2 tpm, 3 tpm-credential, 4 tpm-activated, and `data` one CBOR item, a
map of that format's table:

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `format` | uint 1..4 | yes |
| 3 | `key` | bytes 32 | yes |
| 4 | `data` | bytes 1..65536 | yes |

| Format | # | Field | Type | Needed |
|---|---|---|---|---|
| android-key, tpm | 1 | `group_tag` | bytes 8 | |
| android-key, tpm | 2 | `salt` | bytes 16 | yes |
| android-key, tpm | 3 | `chain` | array 1..10 of bytes 1..8192 | yes |
| tpm | 4 to 8 | `ek`, `ak`, `key`, `attest`, `signature` | bytes 1..2048 each | yes |
| tpm-credential | 1, 2 | `credential`, `secret` | bytes 1..2048 each | yes |
| tpm-activated | 1 | `secret` | bytes 32 | yes |

`guest` (t 17), between an admin and a hub about the guest of an invitation the admin makes
through that hub, named by the guest's WireGuard key (`key`). `op`: 1 open (admin to hub: let this
guest in until `expires`, for the invitation `invite`, with `psk`), 2 opened (hub to admin: the guest
is in, with the hub's `offer`), 3 refused (hub to admin, with a `reason` for the person), 4 data
(both ways: bytes of the guest's connection `conn`), 5 end (both ways: that side closed `conn` for
writing), 6 admitted (admin to hub: the window admitted `device`), 7 close (admin to hub: the
invitation ended without a device).:

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `op` | uint 1..7 | yes |
| 3 | `key` | X25519 Key | yes |
| 4 | `psk` | bytes 32 |  |
| 5 | `expires` | uint ≥ 1 |  |
| 6 | `offer` | map offer |  |
| 7 | `reason` | text 1..256 |  |
| 8 | `conn` | uint 1..2^32−1 |  |
| 9 | `data` | bytes 1..16384 |  |
| 10 | `device` | bytes 16 |  |
| 11 | `invite` | id 16 |  |

### 9.3 `hello` (t 1)

The first message of each side on a member connection:

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `caps` | uint 1..7 |  |
| 3 | `os` | uint 1..2^32−1 |  |
| 4 | `name` | text 1..128 |  |
| 5 | `wall_ms` | uint ≥ 1 |  |
| 6 | `current` | copy |  |
| 7 | `records` | bytes 32 |  |
| 8 | `count` | uint 1..2^32−1 |  |
| 10 | `mode` | uint 1..2 |  |
| 11 | `muted` | flag |  |
| 12 | `muted_for_ms` | uint 1..2592000000 |  |
| 13 | `device` | map hello/device |  |
| 14 | `key_store` | uint 1..4 |  |
| 15 | `actions` | array 1..64 of text 1..32 |  |
| 16 | `release_seq` | uint ≥ 1 |  |
| 17 | `release_keys_seq` | uint ≥ 1 |  |
| 18 | `entries_seq` | uint ≥ 1 |  |
| 19 | `entries_keys_seq` | uint ≥ 1 |  |
| 20 | `features` | uint 1..1 |  |
| 21 | `keys_epoch` | uint ≥ 1 |  |

- `caps`, `os`, `mode` and `key_store` are numbered as the device record's (4.1); `mode` 1 shared,
  2 own; `muted` and `muted_for_ms` say an admin muted the sender. They are shown, never trusted.
- `records` is the set digest (4.9) and `count` how many records the sender holds.
- `current` is the sender's current copy with its age (for a secret, a copy without its payload).
- `actions` are the names of its quick actions that are on.
- `release_seq` to `entries_keys_seq` are the `seq` of the newest signed release and entry files it
  holds and of their keys ([protocol.md](protocol.md), section 16).
- `features` bit 1 says it serves blobs (`get`).
- `keys_epoch` is the epoch of its own statement, so a peer holding an older one asks for it.

`device`, what the sender says about its device, shown and never trusted:

| # | Field | Type | Needed |
|---|---|---|---|
| 1 | `form` | uint 1..12 |  |
| 2 | `os_version` | text 1..32 |  |
| 3 | `version` | text 1..32 |  |
| 4 | `mac` | bytes 6 |  |
| 5 | `archive` | text 1..64 |  |

`form` 1 laptop, 2 desktop, 3 phone, 4 tablet, 5 tv, 6 board, 7 server, 8 router, 9 console, 10
watch, 11 retro, 12 other. `archive` is the release
archive the device installs with `cbb update`.

### 9.4 The beacon

Label `cbb beacon v1`. Signed by the member key of a device that has an admin key: "I saw this set
at this time". It is not a record, and no group rule reads it; a device uses it to show that its
records are current, or behind.

| # | Field | Type | Needed | Values |
|---|---|---|---|---|
| 1 | `type` | uint | yes | 1 |
| 2 | `group` | bytes 16 | yes | |
| 3 | `signer` | bytes 32 | yes | the member key's hash |
| 4 | `n` | uint | yes | 1 or more, rising |
| 6 | `time_ms` | Time | yes | |
| 10 | `digest` | bytes 32 | yes | the set digest |
| 11 | `count` | uint | yes | 1 to 7168: the records in that set (`beacons/count`) |

A body is at most 512 bytes; another field below 256 refuses it (`form/critical`). A receiver with
a clock takes no beacon dated more than 5 minutes ahead of it.

### 9.5 The forwarder's and the relay's messages

A device registers with the forwarder (ALPN `cbb-forward/3`, [protocol.md](protocol.md), section
13) and the relay (ALPN `cbb-relay/3`, section 14) over TLS, with frames of 9.1.

| `t` | Name | Direction |
|---|---|---|
| 80 | `forward/challenge` | forwarder to device |
| 81 | `forward/register` | device to forwarder |
| 82 | `forward/registered` | forwarder to device |
| 83 | error | forwarder to device |
| 84 | `forward/seen` | forwarder to device: the address it saw |
| 90 | `relay/challenge` | relay to device |
| 91 | `relay/register` | device to relay |
| 92 | `relay/registered` | relay to device |
| 93 | error | relay to device |
| 94 | `relay/watch` | device to relay: tell me who is online |
| 95 | `relay/dial` | device to relay |
| 96 | `relay/answer` | device to relay |
| 97 | `relay/online` | relay to device |
| 98 | `relay/call` | relay to device |
| 99 | `relay/ok` | relay to device: the member protocol follows |

`forward/challenge` (80):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `e` | bytes 32 | yes |

`forward/register` (81):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `key` | X25519 Key | yes |
| 3 | `proof` | bytes 32 | yes |
| 4 | `obfuscation` | map obfuscation |  |
| 5 | `vless` | bytes 16 |  |
| 6 | `credentials` | array 1..3 of envelope | yes |

`forward/registered` (82):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `id` | uint ≥ 1 | yes |
| 3 | `mask` | bytes 32 | yes |
| 4 | `vless` | map vless |  |

An error (83, 93), after which the server closes the connection:

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `reason` | text 1..256 | yes |

`forward/seen` (84):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `addr` | addr | yes |

`relay/challenge` (90):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `e` | bytes 32 | yes |
| 3 | `root` | flag |  |

`relay/register` (91):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `key` | X25519 Key | yes |
| 3 | `proof` | bytes 32 | yes |
| 4 | `credentials` | array 1..3 of envelope | yes |
| 5 | `root` | ES256 Key |  |

`relay/registered` (92):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `key` | X25519 Key | yes |
| 3 | `psk` | bytes 32 | yes |
| 4 | `addr` | text 1..261 | yes |

`relay/watch` (94) and `relay/ok` (99) have no fields. `relay/dial` (95):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `name` | bytes 32 | yes |

`relay/answer` (96):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `ticket` | bytes 16 | yes |

`relay/online` (97):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `names` | set 1..64 of bytes 32 |  |

`relay/call` (98):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `name` | bytes 32 | yes |
| 3 | `ticket` | bytes 16 | yes |

### 9.6 Push

The project's push service wakes a sleeping phone (`cbb-push`, ALPN `cbb-push/1`, labels `cbb push
v1`, `cbb push body v1`, `cbb push nonce v1` and `cbb push send v1`; `cbb_core::push`, vectors
`testdata/format/push.json`). A member tells the phone how it may be woken (t 28) and asks it to
renew (t 29); the member then sends through the service (t 100 to 104).

`push` (t 28):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `token` | bytes 1..4096 |  |
| 3 | `env` | uint 1..255 |  |
| 4 | `key` | bytes 32 |  |
| 5 | `seq` | uint 1..9007199254740992 | yes |
| 6 | `kinds` | uint 0..2^32−1 | yes |
| 7 | `send-key` | signer 1..4096 |  |
| 8 | `send-sig` | bytes 1..4096 |  |
| 9 | `slot` | bytes 16 |  |
| 10 | `challenge` | bytes 16 |  |
| 11 | `face` | bytes 16 |  |

`push-renew` (t 29):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `slot` | bytes 16 | yes |
| 3 | `ahead` | flag |  |

| `t` | Name | Direction |
|---|---|---|
| 100 | `push/hello` | member to service |
| 101 | `push/ready` | service to member |
| 102 | `push/send` | member to service |
| 103 | `push/sent` | service to member |
| 104 | error | service to member |

`push/hello` (100):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `credentials` | array 1..2 of envelope | yes |

`push/ready` (101):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `left` | uint 0..2^32−1 | yes |

`push/send` (102):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `n` | uint 1..2^32−1 | yes |
| 3 | `token` | bytes 1..4096 | yes |
| 4 | `env` | uint 1..255 | yes |
| 6 | `body` | bytes 1..2972 | yes |
| 7 | `ttl` | uint 1..4 |  |
| 8 | `key` | signer 1..4096 | yes |
| 9 | `sig` | bytes 1..4096 | yes |
| 10 | `seq` | uint 1..9007199254740992 | yes |
| 11 | `slot` | bytes 16 | yes |
| 12 | `challenge` | bytes 16 |  |

`push/sent` (103):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `n` | uint 1..2^32−1 | yes |
| 3 | `status` | uint 1..255 | yes |
| 4 | `retry_ms` | uint 1..86400000 |  |

An error (104):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `reason` | text 1..256 | yes |

The body a push carries, sealed to the phone:

| # | Field | Type | Needed |
|---|---|---|---|
| 0 | `kind` | uint ≥ 1 | yes |
| 2 | `copy` | bytes 1..2944 |  |
| 3 | `id` | bytes 16 |  |
| 4 | `origin` | bytes 16 |  |
| 5 | `event` | uint ≥ 1 |  |
| 6 | `device` | bytes 16 |  |
| 7 | `time_ms` | uint 0..2^63−1 |  |

A UnifiedPush endpoint, as an Android phone without Google's services gives it:

| # | Field | Type | Needed |
|---|---|---|---|
| 1 | `url` | text 1..4000 | yes |
| 2 | `p256dh` | bytes 65 | yes |
| 3 | `auth` | bytes 16 | yes |

## 10. The copy

### 10.1 Wire form

A copy is a map:

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | `hdr` | bytes | the header, a map in the profile (10.2), signed through its hash |
| 2 | `age_ms` | Duration | outside the signature: it grows on the way |
| 3 | `wraps` | array of bytes | in the order of the header's readers: each the copy key sealed to that reader (an X-Wing wrap is 1168 bytes), or in a **reduced copy** that wrap's SHA-256 (32 bytes) |
| 4 | `payload` | bytes | the sealed content: a step of 10.3 and its 16-byte tag |
| 5 | `payload_hash` | bytes 32 | in place of `payload`, in a mark (a secret's current copy) or a reduced copy |
| 6 | `sig` | bytes 64 | the origin's ES256 signature (10.2) |

Exactly one of 4 and 5; as many wraps as readers (`copy/shape`). Another field below 256 refuses
the copy (`form/critical`). A reduced copy, for a leaf, holds the leaf's own wrap whole and the
others as hashes, and the payload whole only when message `copy` then fits 16 KiB, else its hash
(`copy/leaf-frame`).

### 10.2 Header and keys

| # | Field | Type | Needed | Meaning |
|---|---|---|---|---|
| 1 | `id` | bytes 16 | yes | the copy's ID |
| 2 | `origin` | bytes 16 | yes | the origin's device ID |
| 3 | `time` | Hybrid time | yes | |
| 4 | `readers` | array | yes | 1 to 256 `[device ID, epoch]`, a set (`copy/readers`) |
| 5 | `blob` | array | no | `[size, sha256 bytes 32]` of the sealed blob |
| 6 | `commit` | bytes 32 | yes | HKDF-SHA256(K, salt empty, info `cbb copy commit v2`): binds the copy key |

Field 7 is reserved and refused (`copy/reuse`); another field below 256 is `form/critical`, and a
bad row is `copy/shape`.

The origin picks K, 32 random bytes, and computes:

- `h` = SHA-256(`cbb copy v2` ‖ 0x00 ‖ `hdr`);
- payload key = HKDF-SHA256(K, salt `h`, info `cbb copy payload v2`);
- blob key = HKDF-SHA256(K, salt empty, info `cbb copy blob v2`): not under `h`, which covers the
  sealed blob's hash, so a copy sealed again with the same K keeps the one sealed blob readable;
- `payload` = ChaCha20-Poly1305(payload key, nonce 12 zero bytes, associated data `h`, content);
- each wrap = X-Wing HPKE of K to the reader's statement key of that epoch, associated data `h`;
- `W` = SHA-256 of the concatenated SHA-256 of each wrap, `P` = SHA-256(`payload`);
- `sig` = ES256 over `cbb copy sig v2` ‖ 0x00 ‖ `h` ‖ `W` ‖ `P`.

A reader opens its wrap (`copy/wrap`), checks `commit` against K before it opens anything else
(`copy/commit`), then opens the payload under `h` (`copy/payload`). A leaf checks the signature
from the reduced copy alone.

**The blob.** The bytes of a copy's parts travel as one blob: the parts that hold bytes one after
another in the manifest's order, then zero bytes up to a whole segment of 64 KiB. Each segment is
sealed with ChaCha20-Poly1305 under the blob key, the nonce 4 zero bytes and the segment's number
from 0 in 8 bytes, big-endian, and as associated data `cbb blob` and one byte, 1 for the last
segment and 0 for the others, so a blob cannot be cut short. The sealed blob is the sealed segments
one after another, each 65 552 bytes; `blob` holds its length and its SHA-256.

### 10.3 Content

Inside `payload`, a map in the profile: field 0 `type`, field 1 `pad` (zeros) so that the whole
encoding is exactly one step, the smallest that holds it: 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB,
1 MiB, 2 MiB, 3 MiB or 4 MiB. A content whose encoding is a step by itself has no `pad`
(`copy/content-pad`).

| # | Field | Type | Meaning | Default |
|---|---|---|---|---|
| 0 | `type` | uint | 1 text, 2 clipboard media (images, formatted text), 3 files, 4 a device's state | |
| 1 | `pad` | bytes | zeros | |
| 2 | `flags` | uint, bits | 1 secret: any type may be secret | 0 |
| 3 | `ttl` | Duration | the copy's own lifetime: 5 000 to 3 600 000 | the group's (4.5) |
| 4 | `via` | uint | 1 phone, 2 universal clipboard | a copy |
| 5 | `text` | text | the text, or a plain-text alternative, at most 1 MiB, 256 KiB beside media | |
| 6 | `manifest` | map | types 2 and 3: 1 `size`, 2 `parts`, 1 to 10 000 maps of 1 `type` (1 png, 2 jpeg, 3 gif, 4 html), 2 `path` text, 3 `dir` flag, 4 `size`, 5 `sha256` bytes 32 | |
| 7 | `data` | bytes | type 4: the device's state, one item of the profile its firmware defines, 1 B to 4 KiB | |

- A type above 4, a flag this version does not know, or a critical field it does not define makes
  the content **unknown**: the copy is kept and passed on, never written to a clipboard.
- Type 1 needs `text`; types 2 and 3 need `manifest` (2 clipboard types, 3 files) and only they
  carry one; type 4 needs `data`, only it carries one, and it has no `text`. The rules are
  `content/type`, `content/flags`, `content/ttl`, `content/via`, `content/text`,
  `content/manifest` and `content/data`.
- A manifest holds either clipboard data (every part has `type`, each type once, at most 8) or
  files (every part has `path`). The parts together are at most 1 GiB; a path is at most 16 KiB,
  a name in it at most 765 bytes, all paths together at most 2 MiB. Each name is valid UTF-8, not
  `.` or `..`, without control characters, bidirectional controls or `/ \ : * ? " < > |`, not
  ending in a dot or a space, not a name Windows reserves before its first dot, and equal to its
  own NFC (Unicode 15.1, `core/src/content/unicode.rs`); two paths that are equal by each
  character's case key are one. A receiver writes no link and follows none.

### 10.4 Readers, checks and sealing again

- **Readers.** The origin seals a copy to every device with `read`, and for a secret also
  `secrets` and rules not too old; not skipping the content's type; not a watch; with a counting
  keys statement; a leaf only when the origin is named in its grant. Root and admin keys open
  nothing.
- **Checks.** Every member, one that only passes copies on included, checks the origin (a device of
  the records with `send`, its admin key not frozen; `copy/origin`, `copy/send`) and the signature
  before it passes a copy on. A copy is known by its origin and ID.
- **Freshness.** A reader with a clock refuses a copy whose signed wall time is ahead of its clock
  by more than the allowance: min(5 minutes, a quarter of the copy's lifetime). The age it uses is
  max(`age_ms`, now − signed wall − allowance). It writes no copy whose signed time is not after
  the newest it wrote from that origin, and never writes a secret twice.
- **Sealing again** (`reseal`, t 23). Only the origin seals again, only for a device that was a
  reader of the copy and still is, at the epoch of its counting statement (`reseal/reader`,
  `reseal/not-current`), never past the copy's lifetime (`reseal/expired`), at most twice for an
  asker and a copy (`reseal/limit`). The new copy keeps the ID, origin and time, has the asker as
  its one reader, and a new header.

## 11. Pairing, the invitation and the intro

### 11.1 Pairing messages

ALPN `cbb-pair/3` ([protocol.md](protocol.md), section 6). Each side presents the key container
(section 12) of its member key; the two run CPace.

| `t` | Direction | Message |
|---|---|---|
| 64 | joiner to member | start |
| 65 | member to joiner | reply |
| 66 | joiner to member | confirm |
| 67 | member to joiner | welcome |
| 68 | joiner to member | done: it kept its identity (no fields) |
| 69 | either | error |

Start (64), `Ya` and `ADa`, the encoding of the joiner's Info (11.2):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `ya` | bytes 1..256 | yes |
| 3 | `ada` | bytes 1..16384 | yes |

Reply (65), `Yb` and `ADb`, the encoding of `{1 Group ID, 2 the member's device ID, 3 its name}`:

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `yb` | bytes 1..256 | yes |
| 3 | `adb` | bytes 1..1024 | yes |

| # | Field | Type | Needed |
|---|---|---|---|
| 1 | `group` | bytes 16 | yes |
| 2 | `device` | bytes 16 | yes |
| 3 | `name` | text 1..128 | yes |

Confirm (66), `Ta`:

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `ta` | bytes 1..64 | yes |

Welcome (67), `Tb`, the Welcome (11.2), and `Tw`, the Welcome's tag: an HMAC from CPace's ISK
(key label `cbb welcome key v1`, tag label `cbb welcome v1`) over field 3's bytes:

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `tb` | bytes 1..64 | yes |
| 3 | `welcome` | map welcome | yes |
| 4 | `tw` | bytes 64 | yes |

Error (69): `code` 1 wrong-code, 2 closed, 3 busy, 4 expired, 5 too-many, 6 refused, 7 declined, 8
taken:

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `code` | uint 1..255 | yes |

CPace's channel identifier is `cbb pair channel v3` ‖ 0x00 ‖ the member's key hash ‖ the joiner's
key hash ‖ the invitation ID (16 bytes, all zero in a home window). A home window's password is
SHA-256(`cbb pair home code v1` ‖ 0x00 ‖ its six digits); an invitation's is its 32-byte secret.

### 11.2 Info and Welcome

The joiner's Info, in `ADa`:

| # | Field | Type | Needed |
|---|---|---|---|
| 1 | `name` | text 1..128 | yes |
| 2 | `os` | uint 1..2^32−1 |  |
| 3 | `caps` | uint 1..7 |  |
| 4 | `role` | uint 1..4 | yes |
| 5 | `admin` | ES256 Key |  |
| 6 | `admin-pop` | bytes 1..8192 |  |
| 7 | `keys` | envelope |  |
| 8 | `device` | map pair/info/device |  |
| 9 | `invite` | id 16 |  |

`role` and `caps` are numbered as the device record's; unknown `caps` bits grant nothing. `admin-pop` is, with `admin`, the admin key's ES256 signature over `cbb admin pop v1` ‖
0x00 ‖ the TLS exporter of the pairing session. `keys` is the joiner's statement, epoch 1; `device`
is as the hello's; `invite` the invitation's ID when it joins by one.

The Welcome:

| # | Field | Type | Needed |
|---|---|---|---|
| 1 | `root` | ES256 Key | yes |
| 2 | `records` | array 1..8192 of envelope |  |
| 4 | `keys` | array 1..256 of envelope |  |
| 5 | `time` | uint ≥ 1 | yes |
| 6 | `grant` | map welcome/grant |  |
| 7 | `credentials` | array 1..259 of envelope |  |
| 9 | `recovery` | ES256 Key | yes |
| 10 | `list` | bytes 1..52228 |  |
| 11 | `recovery2` | key 4 | yes |
| 12 | `digest` | bytes 32 |  |
| 13 | `parts` | uint 1..64 |  |

- `root` is the group's first root key and `recovery`, `recovery2` the recovery key's two halves:
  together they give the Group ID, which must be `ADb`'s.
- `records` holds the group's records in the order of their dependencies, and `list` the newest
  recovery head's list, when the set fits the Welcome. A wider set rides whole in `records`
  messages after it: `parts` says how many, at most 64. Either way `digest` is the digest of the
  set the admitter sends (its IDs and its lists' hashes, label `cbb welcome digest v1`), so the
  parts are bound to the Welcome. A leaf's Welcome has neither.
- `time` is the admitter's clock, for a joiner without one; `keys` statements of the group's
  devices; `grant` a leaf's first grant (section 7); `credentials` the current period's.

### 11.3 The invitation and the request that waits

An invitation is the text `cbb://join#` and the unpadded base64url of a map; a QR code carries the same text
(`cbb_core::join::invitation`):

| # | Field | Type | Needed | Meaning |
|---|---|---|---|---|
| 1 | `id` | bytes 16 | yes | its one-time ID, never all zero |
| 2 | `secret` | bytes 32 | yes | CPace's password |
| 3 | `paths` | array of maps | yes | 1 to 4 ways to reach the group (below) |
| 4 | `profile` | map | yes | what the invited device may be (below) |

A path:

| # | Field | Type | Needed | Meaning |
|---|---|---|---|---|
| 1 | `kind` | uint | yes | 1 the home network, 2 the hub's guest tunnel, 3 the way around a block (VLESS to a forwarder) |
| 2 | `endpoints` | array of addr | no | 1 to 8, each once; none for the home network |
| 3 | `hub` | X25519 Key | no | the hub's WireGuard key, for a guest path |
| 4 | `guest` | bytes 32 | no | the guest's one-time WireGuard private key |
| 5 | `psk` | bytes 32 | no | its one-time pre-shared key |
| 6 | `obfuscation` | map | no | the group's AmneziaWG settings, on a guest or bypass path |

The profile:

| # | Field | Type | Needed | Meaning |
|---|---|---|---|---|
| 1 | `role` | uint | yes | 1 member, 2 phone, 3 watch, 4 leaf |
| 2 | `rights` | uint, bits | no | the most rights it gets: as the device record's |
| 3 | `home_only` | flag | no | it may join only from the home network |
| 4 | `guarded` | flag | no | a guarded leaf: only the root admits it |

The AmneziaWG settings, in a path and in the hub's offer:

| # | Field | Type | Needed |
|---|---|---|---|
| 1 | `jc` | uint 1..128 | yes |
| 2 | `jmin` | uint 0..1280 | yes |
| 3 | `jmax` | uint 1..1280 | yes |
| 4 | `s` | array 1..4 of uint 0..1280 | yes |
| 5 | `h` | array 1..4 of array 1..2 of uint 0..2^32−1 | yes |
| 6 | `key` | bytes 32 |  |

The hub's offer, in `result` and `guest`:

| # | Field | Type | Needed |
|---|---|---|---|
| 1 | `hub-key` | X25519 Key | yes |
| 2 | `endpoints` | once 1..8 of addr |  |
| 3 | `obfuscation` | map obfuscation |  |
| 4 | `vless` | map vless |  |
| 6 | `moved` | flag |  |
| 7 | `next-key` | X25519 Key |  |
| 8 | `confirm` | bytes 32 |  |
| 9 | `endpoint-keys` | array 1..8 of map offer/endpoint-key |  |
| 10 | `next-obfuscation` | map obfuscation |  |
| 11 | `next-vless` | map vless |  |

| # | Field | Type | Needed |
|---|---|---|---|
| 1 | `endpoint` | addr | yes |
| 2 | `key` | X25519 Key | yes |

The way to a hub's forwarder over VLESS with XHTTP:

| # | Field | Type | Needed |
|---|---|---|---|
| 1 | `user` | bytes 16 | yes |
| 2 | `port` | uint 1..65535 |  |
| 3 | `host` | text 1..253 |  |
| 4 | `path` | text 1..128 |  |

A device that joins by an invitation no admin is there to approve waits at the hub: the hub tells
each device that may admit about it (`waiting`, t 26), and that admin answers by dismissing it
(`dismiss`, t 27) or by admitting the device.

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `requests` | once 1..48 of map waiting/request | yes |

A request; `network` says how the device reached the hub:

| # | Field | Type | Needed |
|---|---|---|---|
| 1 | `invite` | id 16 | yes |
| 2 | `key` | ES256 Key | yes |
| 3 | `info` | map pair/info | yes |
| 4 | `network` | uint 1..3 | yes |
| 5 | `held` | uint 1..86400000 |  |
| 6 | `attempts` | uint 1..255 | yes |

`dismiss` (t 27):

| # | Field | Type | Needed |
|---|---|---|---|
| 2 | `invite` | id 16 | yes |
| 3 | `key` | bytes 32 |  |

### 11.4 The intro (t 8)

The first message of a peer whose key the other side does not know yet: its records up to the root
the other side holds.

| # | Field | Type | Meaning |
|---|---|---|---|
| 2 | `records` | array of envelopes | at most 32 and 16 KiB together, in the order of their dependencies: the records that prove the admitter's rights, then the sender's own record; up to 65 recovery heads besides, counted apart (`intro/size`) |
| 3 | `keys` | envelope | the sender's statement |

The receiver checks every signature up to the root it holds and keeps them, then goes on; anything
that does not check closes the connection and keeps nothing (`intro/shape`, `intro/record`).

## 12. The key container for TLS

TLS needs a certificate. Each side presents one fixed template on every system, a function of its
P-256 key alone (`format::container`): 221 bytes, a TBSCertificate of 195 bytes with the key at
offset 130 of it.

```
30 81 da                                   Certificate (218)
  30 81 c0                                 TBSCertificate (192)
    a0 03 02 01 02                         version v3
    02 10 <16 bytes>                       serial = SHA-256(point)[0..16], first byte 0x40 | (b & 0x3f)
    30 0a 06 08 2a8648ce3d040302           ecdsa-with-SHA256
    30 0e 31 0c 30 0a 06 03 550403 0c 03 636262            issuer CN "cbb" (UTF8String)
    30 20 17 0d 3730303130313030303030305a                 notBefore 1970-01-01 00:00:00Z (UTCTime)
          18 0f 39393939313233313233353935395a             notAfter 9999-12-31 23:59:59Z (GeneralizedTime)
    30 0e 31 0c 30 0a 06 03 550403 0c 03 636262            subject = issuer
    30 59 30 13 06 07 2a8648ce3d0201 06 08 2a8648ce3d030107   id-ecPublicKey, P-256
          03 42 00 <65-byte uncompressed point>
  30 0a 06 08 2a8648ce3d040302             ecdsa-with-SHA256
  03 09 00 30 06 02 01 01 02 01 01         signature: ECDSA r = 1, s = 1
```

- The serial comes from the key, since Apple's keychain treats two certificates with one issuer and
  serial as one.
- No extensions, no subject alternative name, no server name: nothing in the handshake names a
  device or the group.
- **A reader** checks the TBSCertificate byte for byte against the template with the key and its
  serial in their slots, checks that the point is on the curve, takes the key, and checks its hash
  against the device it dialed or the records (`container/template`). It reads only the
  signature's form, a BIT STRING with no unused bits holding a SEQUENCE of two INTEGERs, at most 72
  bytes in all, never its value: TLS's CertificateVerify proves the key.
- **Writers** write the constant `r = 1, s = 1`, so the whole container is a function of the key.
- The vectors are `testdata/format/container.json`.

## 13. Ceilings

| What | Ceiling | Past it |
|---|---|---|
| a record body | 16 KiB; a checkpoint's, a first one included, 256 KiB | refused (`env/size`) |
| a second signature | 8192 bytes; a recovery head's 32 KiB | refused (`env/sig2`) |
| a statement body | 32 KiB | refused |
| a command body | 64 KiB; a `paste`'s 2 MiB | refused |
| a grant body | 4 KiB | refused |
| a credential body | 16 KiB | refused |
| a beacon body | 512 bytes | refused |
| records of one root key | 1536 units of 512 bytes | the rest count for nothing |
| the roots before the current one, together | 1536 units | the same |
| admin keys | 16 | the 17th device is a device without an admin key |
| records of one admin key | 256 units | the same |
| records in a set | 7168 units, 3.5 MiB | the same |
| second signatures of a set | 128 MiB | the same |
| a recovery head's list | 1536 record IDs | refused (`records/list`) |
| recovery heads | 64 | refused (`records/recovery/seq`) |
| a `seen` list | 1024 entries | refused |
| devices | 256 | |
| held records in the state | 16 | |
| an intro | 32 records and 16 KiB, and 65 recovery heads | the connection closes |
| a Welcome's parts | 64 | refused |
| a frame | 7 MiB member, 1 MiB pairing, 16 KiB toward a leaf | the connection closes |
| a device's name | 64 bytes in a record; 128 in a message | refused |

How a record is counted in units, and what each room holds, is in [protocol.md](protocol.md),
section 10, "Rooms and units".

## 14. Registries

A number is never given a new meaning; a new one gets a row here in the same change.

**Labels** (signed message prefixes, HKDF infos, hash contexts):

| Label | Use |
|---|---|
| `cbb record v3` | records |
| `cbb keys v1` | keys statements |
| `cbb command v3` | commands, and the associated data of their sealed orders |
| `cbb grant v1` | grants |
| `cbb credential v2` | server credentials |
| `cbb server card v1` | server cards |
| `cbb beacon v1` | beacons |
| `cbb admin pop v1` | the admin key's proof at pairing |
| `cbb copy v2` | the copy's header hash `h` |
| `cbb copy sig v2` | the copy's signature |
| `cbb copy payload v2`, `cbb copy blob v2`, `cbb copy commit v2` | the copy's HKDF infos |
| `cbb blob` | a blob segment's associated data |
| `cbb seal v1` | the HPKE info of sealed orders and wraps |
| `cbb set v3` | the set digest |
| `cbb group v3` | the Group ID |
| `cbb recovery list v3` | a recovery head's list |
| `cbb recovery fetch v3` | the recovery key's fetch proof; a signature under it is no record |
| `cbb pair channel v3` | CPace's channel identifier |
| `cbb pair home code v1` | a home window's password |
| `cbb welcome digest v1`, `cbb welcome key v1`, `cbb welcome v1` | the Welcome's digest and tag |
| `cbb push v1`, `cbb push body v1`, `cbb push nonce v1`, `cbb push send v1` | push |

**ALPN:** `cbb/4` the member protocol, `cbb-pair/3` pairing, `cbb-forward/3` the forwarder,
`cbb-relay/3` the relay, `cbb-push/1` the push service.

**Algorithms:** 1 ES256, 2 X-Wing, 3 X25519, 4 SLH-DSA-SHA2-128s; 5 to 15 reserved. A reader holds or
refuses an unknown one (section 2).

**Systems** (`os`): 1 linux, 2 windows, 3 macos, 4 ios, 5 android, 6 aurora, 7 sailfish, 8 watchos, 9
wearos, 10 none (firmware without one), 11 harmonyos.

**Numbers** (each also in its table): record types 1 to 4, 6 to 10, 13 and 14 (5, 11 and 12
retired); command types 1 to 10; credential types 1 to 4; content types 1 to 4; member messages 1 to
30; pairing 64 to 69; forwarder 80 to 84; relay 90 to 99; push service 100 to 104; roles 1 to 4;
`store` 1 to 4; `proof` 1 to 3; device `form` 1 to 12; pairing errors 1 to 8; result status 1 to 3;
server kinds 1 to 3.
