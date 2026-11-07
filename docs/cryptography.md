<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Cryptography

For engineers and security reviewers: every cryptographic primitive Copy Beyond Borders uses,
with the library that provides it in each implementation, the key sizes, the lifetimes and
where each key is kept. The wire format is normative in the [protocol](protocol.md); this
page only lists. Why each choice was made is in the [design](design.md) and the
[decisions](decisions.md); what each defence protects against is in the
[threat model](threat-model.md).

## Rules

- Only standard, published constructions; nothing of our own. The one construction from an
  Internet-Draft, CPace, is the CFRG's balanced PAKE and is copied as is
  (`internal/third_party/cpace`, `core/src/third_party/cpace`).
- One curve for signatures: NIST P-256 with ECDSA and SHA-256, everywhere, since the
  phones' secure hardware (the Secure Enclave, Android's Keystore and StrongBox) and TPM 2.0
  all offer it.
- Curve25519 only where the protocol requires it: CPace's suite, WireGuard and REALITY.
- TLS 1.3 only (RFC 8446), never an earlier version, on every TCP connection.
- Randomness from the operating system's generator only (`crypto/rand`, `getrandom`,
  `SecRandomCopyBytes`, `SecureRandom`).
- Keys never leave the device that made them, with one exception the protocol names:
  the one-time WireGuard key a hub makes for a guest and puts in its invitation (section 12). A device's key in
  hardware cannot leave it.

## Primitives

| Use | Primitive | Standard | Section of the protocol |
|---|---|---|---|
| Every TCP connection | TLS 1.3, mutual between members | RFC 8446 | 4, 6, 13, 14 |
| Key exchange in TLS | X25519MLKEM768 first on Go members (Go 1.27's default), then X25519; X25519 on the lite member; what the system offers on the phones | RFC 8446, draft-ietf-tls-ecdhe-mlkem | 4 |
| TLS cipher suites | Go: the three of TLS 1.3; the lite member: TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_128_GCM_SHA256 | RFC 8446 | 4 |
| Certificates | X.509 v3, ECDSA P-256 with SHA-256 | RFC 5280 | 2 |
| Device records, revocations, commands, server credentials, release files, evidence | ECDSA P-256 over SHA-256 of the exact signed bytes, ASN.1 DER signatures | FIPS 186-5 | 10, 15, 16, 17, 18 |
| Pairing | CPace, suite CPACE-X25519-SHA512, bound to the TLS exporter | draft-irtf-cfrg-cpace-21, RFC 5705 | 6 |
| Channel binding | TLS exporter (32 bytes) with the labels of section 19 | RFC 8446, section 7.5 | 6, 13, 14 |
| Content addresses, key hashes, group tag, fingerprints | SHA-256 | FIPS 180-4 | 1, 4, 10 |
| Forwarder hellos and state | HMAC-SHA-256 | RFC 2104 | 13 |
| Masking of the forwarder's hellos | ChaCha20 key stream (no authentication; the MAC inside does that) | RFC 8439 | 13 |
| Sync away from home | WireGuard: Noise IK, Curve25519, ChaCha20-Poly1305, BLAKE2s, plus a preshared key per client | WireGuard paper, Noise | 11 |
| AmneziaWG's header protection | ChaCha20 over the message header, nonce from the padding | AmneziaWG | 11 |
| VLESS with REALITY | TLS 1.3 with an X25519 key pair of the forwarder | Xray-core | 11, 13 |
| Hardware key proofs | Android Key Attestation, TPM 2.0 quotes and credential activation | Android, TCG | 17 |

## Libraries

| Implementation | Libraries |
|---|---|
| Go members, the forwarder, the relay | the Go standard library (`crypto/tls`, `crypto/ecdsa`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha256`), `golang.org/x/crypto` (ChaCha20, BLAKE2s), amneziawg-go (copied under `internal/third_party`), gVisor's netstack (a module) with wireguard-go's adapter for it (`internal/third_party/netstack`), go-tpm for the TPM, go-libpcsclite (PC/SC through pcscd) and the platforms' PC/SC for the recovery key on a YubiKey, Xray-core for VLESS |
| The lite member | RustCrypto (`p256`, `sha2`, `hmac`, `x25519-dalek`, `chacha20poly1305`, `aes-gcm`, `x509-cert`), rustls without its default provider, GotaTun for WireGuard with `ring-shim/` over RustCrypto |
| The iPhone kit | swift-crypto (CryptoKit's API, BoringSSL on Linux), the Security framework for the keychain and the Secure Enclave, Network.framework for TLS |
| The Android kit | `java.security` and `javax.crypto`, the Android Keystore, its own X25519 and CPace in Kotlin (`Field25519.kt`, `CPace.kt`), checked against the Go code by the interop vectors |
| The phones' tunnel | the Go tunnel of `mobile/cbbtun`, bound by gomobile |

The interop vectors in `testdata/interop` pin the bytes of each signed object and of a
CPace exchange, so the four implementations cannot drift apart ([testing](testing.md)).

## Keys

| Key | Type | Made by | Kept | Lifetime |
|---|---|---|---|---|
| Group root CA | ECDSA P-256 | the root phone, or `cbb new` on a computer | the phone's Secure Enclave or Keystore, signs only after Face ID, the fingerprint or the passcode; on a computer a file readable only by the service | the certificate 20 years |
| Admin CA | ECDSA P-256 | each admin | a phone's Secure Enclave or Keystore, behind the user's face, fingerprint or passcode; on a computer the TPM on Linux when there is one, else a file | the certificate ends with the root's |
| Member key | ECDSA P-256 | each device | the TPM on Linux when there is one, the Secure Enclave or Keystore on phones, else a file readable only by the service | the certificate 2 years, renewed 240 days before its end |
| Tunnel key | X25519 | each device that syncs away from home | sealed in the TPM on Linux when there is one, else a file of the service; the phone's keychain or app storage | until the device leaves the group |
| Preshared key | 32 random bytes | each tunnel client | as the tunnel key | as the tunnel key |
| Server key | ECDSA P-256 | each hub | the TPM on Linux when there is one, else a file of the service | until the hub leaves; each credential it gets lasts a period of 35 days |
| Forwarder key | ECDSA P-256 and X25519 (WireGuard, REALITY) | the forwarder | its state directory | until its operator changes it |
| Release root keys | ECDSA P-256 | the maintainer | offline hardware keys | until replaced in a release |
| Release and status keys | ECDSA P-256 | the maintainer | the maintainer's Secure Enclave, never CI | named in `keys.json`, at most 100 days per signature |
| Pairing secrets | the six-digit code, CPace's scalars | for one attempt | memory only | the window, 5 minutes |
| Invitation secret | at least 16 random bytes | the hub, for `cbb invite` | the invitation file (`.cbbinvite`, mode 0600) and the hub's memory | the invitation, 1 hour by default, at most 24 hours |

The lifetimes are in [limits](reference/limits.md#certificates-and-keys); where each system keeps the
files is in [devices, ports and files](reference/devices.md). The key levels (which keys
must be in hardware, and how a device proves it) are in [keys](guide/keys.md) and the
protocol, section 17.

## What is not encrypted

- mDNS announcements: the device ID, the group tag and the port are public on the home
  network (protocol, section 3).
- WireGuard and AmneziaWG hide content, not size and timing: only chunk frames are padded,
  to 16 KiB (threat 6 of the [threat model](threat-model.md)).

## Changing an algorithm

A new algorithm comes with a new ALPN ID or a new value in a registry (protocol, section 19),
in all four implementations and the interop vectors at once, and an entry in the
[decisions](decisions.md). Members of the earlier release must keep working with the new
one, so the old algorithm stays accepted until no supported release needs it.
