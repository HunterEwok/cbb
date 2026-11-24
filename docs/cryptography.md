<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Cryptography

For engineers and security reviewers: every cryptographic primitive Connect Beyond Borders uses,
the libraries that provide it in each implementation, and every key type with its size, lifetime,
and storage location. The wire format is normative in [Protocol](protocol.md) and
[Wire format](format.md). Rationale and architecture decisions are in [Design](design.md) and
[Architecture decisions](decisions.md); security properties and threat mapping are in
[Threat model](threat-model.md).

## Rules

- **Standard constructions only**: Connect Beyond Borders uses published, standard algorithms and
  constructions. The sole Internet-Draft construction, CPace (CFRG balanced PAKE), is translated
  line by line from the Go reference (`core/src/third_party/cpace`).
- **One classical signature curve**: NIST P-256 with ECDSA and SHA-256 everywhere, matching what
  phone security hardware (Secure Enclave, Android Keystore and StrongBox, OP-TEE, HUKS) and
  TPM 2.0 provide.
- **Post-quantum protection**: X-Wing (ML-KEM-768 + X25519) for end-to-end sealed messages,
  `X25519MLKEM768` for TLS key exchange and tunnel PSK derivation, and SLH-DSA-SHA2-128s alongside
  ECDSA P-256 for recovery keys and signed releases.
- **Curve25519 where required by the protocol**: CPace, WireGuard, TLS key exchange, and X-Wing.
- **TLS 1.3 only** (RFC 8446): No earlier TLS version is accepted on any TCP connection.
- **Operating system randomness only**: `crypto/rand` (Go), `getrandom` (Rust),
  `SecRandomCopyBytes` (Apple), and `SecureRandom` (Android/JVM).
- **Keys stay on their device**: Private keys never leave the device that generated them, with one
  protocol-defined exception: the single-use WireGuard guest key a hub generates and places in a
  remote invitation ([protocol.md](protocol.md), section 12). Hardware-backed keys cannot be
  exported.

## Primitives

| Use | Primitive | Standard | Protocol section |
|---|---|---|---|
| Member and server TCP connections | TLS 1.3, mutual authentication between members | RFC 8446 | 4, 6, 13, 14 |
| TLS key exchange | `X25519MLKEM768` first, `X25519` fallback in both the Rust core (`cbb` and phone members) and Go (`cbb-helper`, forwarder); platform defaults during phone pairing | RFC 8446, draft-ietf-tls-ecdhe-mlkem | 4 |
| TLS cipher suites | Go: all three TLS 1.3 cipher suites; Rust core: `TLS_CHACHA20_POLY1305_SHA256` (preferred) and `TLS_AES_128_GCM_SHA256` | RFC 8446 | 4 |
| Member key transport in TLS | Fixed X.509 v3 template holding only the member public key, matched byte for byte rather than verified as a CA certificate (D-105) | RFC 5280 | 2 |
| Group records, revocations, commands, grants, keys statements, beacons, server credentials, copies, push sends | ECDSA P-256 over SHA-256 of `label \|\| 0x00 \|\| data`, canonical 64-byte `r \|\| s` with low `s` (RFC 6979) | FIPS 186-5, RFC 6979 | 4, 10, 15, 18 |
| Recovery records (second signature) | SLH-DSA-SHA2-128s (pure, 32-byte public key, 7,856-byte signature) with domain context, paired with ECDSA P-256 | FIPS 205 | 10 |
| Release files (`keys.json`, `release.json`, `stable.json`, `zxnext.json`) | Dual signatures required from both halves of one key: ECDSA P-256 (ASN.1 DER) and SLH-DSA-SHA2-128s (pure, context `cbb release v1`) | FIPS 186-5, FIPS 205, RFC 9909 | 16 |
| Pairing | CPace (`CPACE-X25519-SHA512`), bound to the TLS exporter | draft-irtf-cfrg-cpace-21, RFC 5705 | 6 |
| Channel binding | TLS exporter (32 bytes) with registry labels | RFC 8446, section 7.5 | 6, 13, 14, 19 |
| Content addresses, key hashes, group tags, fingerprints | SHA-256 (SHA-512 for SLH-DSA recovery seed derivation) | FIPS 180-4 | 1, 4, 10 |
| Forwarder hellos and state | HMAC-SHA-256 | RFC 2104 | 13 |
| Forwarder hello masking | ChaCha20 keystream (unauthenticated; inner HMAC authenticates) | RFC 8439 | 13 |
| Sync away from home (tunnel) | WireGuard (Noise IK, Curve25519, ChaCha20-Poly1305, BLAKE2s) plus a per-client 32-byte preshared key derived via HKDF-SHA256 (`cbb tunnel psk v1`) from an `X25519MLKEM768` TLS exporter | WireGuard, Noise, RFC 5869 | 11 |
| AmneziaWG header obfuscation | ChaCha20 over message headers with padding bytes as nonce | AmneziaWG | 11 |
| VLESS over XHTTP | TLS 1.3 to the front-end web server (public CA certificate; RSA, P-256, and P-384 verification in Rust core's `web` feature) | Xray-core, rustls | 11, 13 |
| Hardware key attestation | Android Key Attestation, TPM 2.0 quotes and credential activation, YubiKey PIV attestation | Android, TCG, Yubico | 17 |
| Sealed messages (copy key wraps, commands, bug reports) | HPKE base mode with X-Wing (ML-KEM-768 + X25519, KEM `0x647a`, 32-byte secret, 1,216-byte public key, 1,120-byte encapsulated key), HKDF-SHA256, ChaCha20-Poly1305, info `cbb seal v1`, plus use-specific associated data | RFC 9180, draft-connolly-cfrg-xwing-kem, FIPS 203 | 4, 15 |
| Copies end to end | Random 32-byte copy key; HKDF-SHA256 derives the payload key (`cbb copy payload v2`), blob key (`cbb copy blob v2`), and key commitment (`cbb copy commit v2`); ChaCha20-Poly1305 seals content under the header hash and blobs in 64 KiB padded segments | RFC 5869, RFC 8439 | 4 |
| Sealed push notifications | ChaCha20-Poly1305 under HKDF-SHA256-derived body key (`cbb push body v1`) with deterministic 12-byte nonce from HMAC-SHA256 (`cbb push nonce v1`); ES256 JWT for APNs, RS256 OAuth assertion for FCM, and RFC 8291 P-256 ECDH for UnifiedPush | RFC 8439, RFC 5869, RFC 8291 | 4 |
| Local secret sealing and YubiKey PIV | Mac Secure Enclave: P-256 ECDH + HKDF-SHA256 + AES-256-GCM; YubiKey PIV management auth: AES-128/192/256 (firmware 5.7+) or Triple DES (up to 5.6) plus PIV ECDH | NIST SP 800-56A, SP 800-38D, SP 800-73 | 17 |

## Libraries

| Implementation | Libraries |
|---|---|
| `cbb-helper`, forwarder, and release tools (Go) | Go standard library (`crypto/tls`, `crypto/ecdsa`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha256`, `crypto/hpke`), `github.com/cloudflare/circl` (`sign/slhdsa` for SLH-DSA-SHA2-128s), `golang.org/x/crypto` (ChaCha20, BLAKE2s), `amneziawg-go` (`internal/third_party/amneziawg-go`), gVisor netstack with wireguard-go adapter (`internal/third_party/netstack`), `go-tpm` for TPM 2.0, and `Xray-core` for VLESS |
| `cbb`, `cbb-relay`, `cbb-push`, `cbb-bug`, and the phones' core/member (Rust) | RustCrypto (`p256`, `p384`, `sha2`, `hmac`, `hkdf`, `x25519-dalek`, `chacha20`, `chacha20poly1305`, `aes`, `aes-gcm`, `blake2`, `des`, `rsa`, `crypto-bigint`, `ml-kem`, `slh-dsa`, `x509-cert`, `subtle`, `zeroize`), `hpke` (X-Wing KEM in `core/src/seal.rs`), `rustls` with custom RustCrypto provider (`core/src/tls/provider.rs`), `gotatun` for WireGuard with `ring-shim/` over RustCrypto, and `member/src/third_party/pcsclite` (plus system PC/SC on macOS and Windows) for YubiKey PIV |
| iPhone kit (`apps/ios/CBBKit`) | `swift-crypto` (CryptoKit on Apple platforms, BoringSSL on Linux), Security framework (Keychain and Secure Enclave), Network.framework, and the Rust core/member/tunnel through `ffi/` |
| Android kit (`apps/android/kit`) | `java.security`, `javax.crypto`, Android Keystore (StrongBox/TEE), Conscrypt (`conscrypt-android` / `conscrypt-openjdk-uber`) for TLS 1.3, and the Rust core/member/tunnel through `ffi/` (JNA) |
| Aurora OS and Sailfish OS app (`apps/silica`) | OP-TEE via PKCS#11 (`libckteec`) and QCA (`qca-aurora-pkcs11`) on Aurora OS 5, file keys on Aurora OS 4 and Sailfish OS, and the Rust core/member/tunnel through `ffi/` |
| HarmonyOS app (`apps/harmony`) | HUKS (Hardware Universal KeyStore) via Node-API (`entry/src/main/cpp/keys.cpp`) and the Rust core/member/tunnel through `ffi/` |

Interoperability vectors in `testdata/interop` pin the exact bytes of signed objects, CPace
exchanges, and sealed messages (`seal-go.json`, `seal-rust.json`) across implementations
([Testing](testing.md)). External reference vectors ensure implementations cannot agree on a
shared mistake:

- CPace against `draft-irtf-cfrg-cpace-21` vectors
- X-Wing HPKE (KEM `0x647a`) against `draft-ietf-hpke-pq-05` (`testdata/interop/xwing-hpke-pq.json`)
- SLH-DSA-SHA2-128s against NIST vectors (`testdata/interop/nist-slh-dsa-sha2-128s.json`)

## Keys

| Key | Algorithm and size | Generated by | Storage | Lifetime |
|---|---|---|---|---|
| Root key | ECDSA P-256 | Main phone, or `cbb new` on a computer | Phone Secure Enclave, Android Keystore (StrongBox/TEE), Aurora OS 5 OP-TEE (app PIN), or HarmonyOS HUKS (gated by user auth); on a computer, TPM 2.0 (Linux/Windows) or Secure Enclave (Mac) when available, else service-only file | Until the main device changes ([protocol.md](protocol.md), section 9) |
| Admin key | ECDSA P-256 | Each admin | Phone security hardware behind user auth; on computers, TPM 2.0 (Linux/Windows) or Secure Enclave (Mac) when available, else service-only file | Until removed, root changes, or device is silent for 35 days |
| Recovery key | ECDSA P-256 (`K1`) and SLH-DSA-SHA2-128s (`K2`), derived from one 32-byte secret | Main device at group creation | Printed recovery sheet or sealed in a retired PIV slot on a YubiKey; not stored on devices | Until replaced by the owner |
| Member key | ECDSA P-256 | Each device | Phone security hardware; on computers, TPM 2.0 (Linux/Windows) or Secure Enclave (Mac) when available, else service-only file | Until the device leaves the group |
| Tunnel key | X25519 (32 bytes) | Each device using **Everywhere** | Sealed by TPM 2.0 or Secure Enclave when available, else service-only file; protected app storage/keychain on phones | Until the device leaves the group |
| Tunnel preshared key | 32 bytes (derived from `X25519MLKEM768` TLS exporter) | Each tunnel client and hub | Same as tunnel key | Rotated on rekey; until the device leaves the group |
| Server key | ECDSA P-256 | Each hub | TPM 2.0 or Secure Enclave when available, else service-only file | Until the hub leaves; each server credential lasts 35 days |
| Forwarder / relay identity key | ECDSA P-256 | Server on first start | Server state directory (`forwarder.pem` / `relay.pem`) | Until replaced by the operator |
| Release root keys | Hybrid ECDSA P-256 + SLH-DSA-SHA2-128s (`root-1`, `root-2`) | Maintainer | Two offline YubiKey 5C NFC devices (PIV slot 82, PIN + touch always; SLH-DSA half encrypted to each YubiKey) | Until replaced in a release |
| Release, status, and channel keys | Hybrid ECDSA P-256 + SLH-DSA-SHA2-128s | Maintainer | YubiKey PIV slot 83 or Mac Secure Enclave (never CI); channel key on `cbb.tools` renews `stable.json` only | Listed in `keys.json`; `keys.json` and `release.json` valid at most 100 days, `stable.json` at most 8 days |
| Pairing secrets | 6-digit code and CPace scalars | Pairing window / joiner per attempt | Memory only | 5-minute pairing window (or 3 wrong attempts) |
| Invitation secret | 32 random bytes | Hub (`cbb invite` or admin phone) | `cbb://join#...` QR code or `cbb.cbbinvite` (mode `0600`) and hub memory | 1 hour default, up to 24 hours |
| Sealing keys | X-Wing per epoch (32-byte secret, 1,216-byte public key) | Each reading device | `epochs.json` on computers (each secret sealed under `local.json`, hardware-sealed where available); protected app storage/keychain on phones | Until erased on epoch rotation (`keystore::rotate`) |
| Copy key | 32 random bytes | Copying device per copy | Wrapped in X-Wing HPKE envelopes for each reader only | Single copy |
| Push keys | 32-byte symmetric key per group + ECDSA P-256 send key per token | Phone app | Protected app storage / dedicated iOS push keychain access group | Rotated on membership changes (symmetric key) or token changes (send key) |
| Bug report robot key | X-Wing (32-byte secret, 1,216-byte public key) | Maintainer (`cbb-bug keygen`) | Secret on the maintainer's host (never on `cbb.tools`); public key in `core/src/bug.rs` (`ROBOT_KEY_B64`) | Until replaced in a release |

For exact lifetimes, see [Limits and lifetimes](reference/limits.md#keys-and-signed-files). For
storage paths by operating system, see [Devices, ports and files](reference/devices.md). For key
levels and hardware attestation, see [Keys and attestation](guide/keys.md) and
[protocol.md](protocol.md), section 17.

## What is not encrypted

- **mDNS announcements**: Device ID, group tag, and member port are broadcast on the local home
  network ([protocol.md](protocol.md), section 3).
- **Packet size and timing**: WireGuard and AmneziaWG hide content, not packet timing or exact
  sizes outside padded 64 KiB blob segments and 16 KiB chunk frames (threat 6 in
  [Threat model](threat-model.md)).
- **Opt-in Roku remote**: Roku's External Control Protocol runs over plain HTTP on the home
  network and requires explicit `-consent` ([Privacy: who sees what](guide/privacy.md)).

## Changing an algorithm

Introducing a new algorithm requires a new ALPN identifier or registry value
([protocol.md](protocol.md), section 19), coordinated updates across implementations and
interoperability vectors, and an entry in [Architecture decisions](decisions.md). For cross-version
upgrade guarantees, see [Versions and compatibility](reference/compatibility.md).
