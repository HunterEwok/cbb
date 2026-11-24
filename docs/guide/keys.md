<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Keys and attestation

For anyone who wants to understand where each device stores its cryptographic keys, how devices
prove that their keys live in security hardware, and which **key level** to choose for their
group. For the full wire specification, see [Protocol](../protocol.md), section 17, and
[Cryptography](../cryptography.md).

Every device in a group holds a **member key** that proves its identity to your other devices. The
**main device** (called *root* in command-line tools) holds the group's main key, and each
**admin** holds an admin key that signs group changes and commands. Where a device keeps those
keys determines what an attacker can extract if the device is stolen.

## Where each device keeps its keys

The device list in the apps and the `KEYS` column of `cbb status` show each device's key storage
tier: **proven** (`proven`), **hardware** (`hardware`), **file** (`file`), or **rootless**
(`rootless`).

| Device | Where member, admin, and main keys live | Confirmation before main/admin signing | Storage tier shown | What a thief can take |
|---|---|---|---|---|
| **iPhone and iPad** | Secure Enclave (hardware) | Face ID, Touch ID, or passcode | `hardware` | Nothing to copy; keys sign only on that device after unlock |
| **Android phone or tablet** (locked bootloader, verified OS) | Android Keystore (StrongBox or TEE, hardware) | Fingerprint, face, or screen lock (enforced by Keystore) | `proven` | Nothing to copy; the group also verifies hardware proof offline |
| **Android phone or tablet** (unlocked bootloader or custom-signed OS such as GrapheneOS) | Android Keystore (StrongBox or TEE, hardware) | Fingerprint, face, or screen lock | `hardware` | Nothing to copy; OS verification cannot be vouched for by Google's roots |
| **Aurora OS 5 phone** | OP-TEE secure element (hardware) | App's own admin PIN (at least 6 digits when created; 7 wrong tries lock the admin key permanently) | `hardware` | Nothing to copy; member key syncs without PIN, admin/main key requires PIN |
| **Aurora OS 4 and Sailfish OS phone** | App file on the phone | None from hardware | `file` | A copy of the key file, usable anywhere until removed |
| **HarmonyOS 5+ phone or tablet** | HUKS (TEE, hardware) | Face, fingerprint, or PIN (User Authentication Kit) | `hardware` | Nothing to copy; keys sign only on that device after authentication |
| **Mac with Apple silicon or T2 chip** | Secure Enclave (hardware); local and tunnel secrets sealed by Secure Enclave | macOS Touch ID or administrator password via system prompt | `hardware` | Nothing to copy; keys sign only on that Mac |
| **Intel Mac without T2 chip** | Service state files (`/Library/Application Support/cbb/state`) | macOS administrator password | `file` | A copy of the key files if disk is readable; encrypt with FileVault |
| **Linux or Windows PC with TPM 2.0 and `cbb-helper`** | TPM 2.0 (hardware); local and tunnel secrets sealed by TPM | Linux polkit or Windows Hello / administrator prompt | `proven` (with on-chip EK certificate) or `hardware` | Nothing to copy; keys sign only on that PC |
| **Linux or Windows PC without TPM, FreeBSD, OpenWrt, OPNsense, small devices without `cbb-helper`, Docker** | Service state files (readable only by the service account) | Administrator privileges (`sudo` or administrator terminal) | `file` | A copy of the key files if disk or volume is readable; encrypt the disk (LUKS, BitLocker) |
| **Linux rootless install (`--rootless`)** | User files in `~/.local/state/cbb` | None (any program of your user can read them) | `rootless` | Any program running under your account can copy the key files; never main device, admin, or hub |

Setting `CBB_TPM=off` on a computer keeps newly generated keys in files instead of hardware. A
Docker container refuses to hold main or admin keys unless you set `CBB_KEYS_IN_FILE=yes` in its
environment.

### The recovery key

When you create a group, Connect Beyond Borders derives the group's **recovery key** (an ECDSA
P-256 key paired with a post-quantum SLH-DSA-SHA2-128s key) from one random 32-byte secret. The
secret is shown once and is never stored on any device in the group. You keep it on paper (the
recovery sheet), sealed in an unused retired PIV slot (slots 95 down to 82) on a YubiKey
(firmware 5.3 or later), or both.

## How a key is proven

Any device can report that its key lives in hardware, and a modified program could report that
falsely. **Hardware attestation** lets a security chip sign cryptographic proof that the key was
generated inside the chip and cannot leave it.

- **Android Key Attestation:** When the Android app creates its key, Android Keystore signs a
  certificate chain describing the key (StrongBox or TEE, locked bootloader, verified boot state)
  rooted at Google's attestation root certificates. The main device verifies this chain offline
  and records the phone as **proven**. Nothing is sent to Google.
- **Unlocked bootloaders and custom systems:** Phones running an unlocked bootloader or a
  self-signed operating system (such as GrapheneOS) still store keys inside StrongBox or TEE, so
  the key cannot be extracted. Because the chain does not vouch for a factory-verified OS, the
  group records the phone as **hardware** rather than **proven**.
- **Revoked Android attestation keys:** Google publishes a list of devices whose hardware
  attestation keys were compromised. The project's server at `cbb.tools` fetches that list once a
  day and serves a signed copy (`https://cbb.tools/attest/`). The main device fetches the signed
  copy from `cbb.tools`, so your devices never contact Google. Any phone whose certificate serial
  appears on the list drops from **proven** to **hardware**.
- **TPM 2.0 attestation on computers:** A Linux or Windows computer with a TPM 2.0 and `cbb-helper`
  stores its keys in the TPM. When the TPM holds an on-chip Endorsement Key (EK) certificate from
  its maker (common on discrete Infineon, ST, and Nuvoton TPM chips, such as Raspberry Pi TPM
  boards), the main device verifies the TPM's credential activation offline without contacting any
  external server and records the computer as **proven**. Firmware TPMs (common on Intel and AMD
  CPUs) often omit an on-chip EK certificate and therefore remain **hardware**.

## The three levels

Your group's **key level** sets the minimum key storage tier required for a device to act as the
**main device**, an **admin**, or a **hub that reads copies**.

A **hub that only passes copies on** needs no key level because every copy is sealed end to end
past it: an attacker who copies its keys can delay traffic and observe metadata (see
[Privacy: what the devices in between see](privacy.md#what-the-devices-in-between-see)), but
cannot read or forge copies. A **rootless member** can never be the main device, an admin, or a
hub at any key level.

1. **Proven hardware only (`proven`):** Only devices whose keys are proven by hardware attestation
   (`proven`) can be the main device, an admin, or a hub that reads copies. On Android, strict
   verification requires chains issued through Google's Remote Key Provisioning (RKP). A main
   device whose own key is not `proven` cannot set the group to this level.
2. **Keys in hardware (`hardware`, default and recommended):** Any device whose keys live in
   security hardware (`hardware` or `proven`) can be the main device, an admin, or a hub that
   reads copies. Offline proofs (Android Key Attestation and TPMs with on-chip EK certificates)
   are still verified and displayed, and no device information leaves your home network beyond
   fetching the shared revocation list from `cbb.tools`.
3. **Keys in files too (`files`):** Also allows devices whose keys live in files (`file`) to be
   the main device, an admin, or a hub that reads copies, after an explicit warning each time
   (`cbb admin -allow-file-key` in a terminal, or the warning dialog in the apps). A group created
   on a computer without a TPM or Secure Enclave starts at `files`.

### View or change the key level

Only the group's **main device** can change the key level:

- **In the phone or desktop app:** Open **Settings**, turn on **Advanced settings**, and go to
  **Group > Admin keys**.
- **In a terminal on a main computer:** Run `cbb keys` to view the current level, or set it with:

  ```sh
  sudo cbb keys proven
  sudo cbb keys hardware
  sudo cbb keys files
  ```

Admins and hubs already in the group with weaker keys stay active until you remove them, and
Connect Beyond Borders warns you which devices fall below the new level.

## If a device is lost

Remove the lost device from your group as soon as possible; see
[If a device is lost or stolen](lost-device.md). A key stored in hardware cannot be extracted or
used off that device; a key stored in a file can be copied and used until you remove the device.
