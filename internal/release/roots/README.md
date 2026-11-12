<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Release root keys

`roots.pem` holds the project's two release root keys (docs/protocol.md, section 16): the
public keys of P-256 keys made on two YubiKey 5C NFC (firmware 5.7.4) on 2026-10-28, each in
the PIV slot 82, with the PIN and a touch required for every signature. They sign
`keys.json` and nothing else. `internal/release.Roots` reads this file; `packaging/get.sh`,
`packaging/windows/get.ps1`, the Rust cbb's `update::ROOTS` and the phone kits'
`Releases.roots` carry copies, which `roots_test.go` compares with it.

`release-keys.pem` holds the release keys on the same two YubiKeys, in the PIV slot 83 with
the same policies: they sign `release.json` and `stable.json`, and the roots certify them
in `keys.json`. Programs do not pin them; the file is here for their attestation.

`attestation/` proves that the keys were made on the YubiKeys and cannot leave them:

- `root-1.pem` and `root-2.pem`: each key's attestation certificate, from
  `ykman piv keys attest 82`. Its extensions say the firmware (5.7.4), the YubiKey's
  serial number, and the PIN and touch policies (always and always).
- `release-yubikey-1.pem` and `release-yubikey-2.pem`: the same for the release keys, from
  `ykman piv keys attest 83`.
- `yubikey-f9.pem`: the YubiKeys' attestation certificate in slot `f9`, which signs both.
- `yubico-intermediates.pem` and `yubico-root.pem`: Yubico's "PIV Attestation B 1",
  "Attestation Intermediate B 1" and "Attestation Root 1", from
  `https://developers.yubico.com/PKI/` (`yubico-intermediate.pem` and `yubico-ca-certs.txt`).

`roots_test.go` checks the chain from each attestation to Yubico's root and that it attests
the key in `roots.pem` or `release-keys.pem` with both policies at "always". docs/maintainers/maintaining.md, "Signed releases",
says how a root is made and replaced.
