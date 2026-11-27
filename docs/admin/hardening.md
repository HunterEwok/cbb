<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Hardening

For administrators who want to make a group harder to attack beyond the default settings. Items are
ordered by what they protect most, with trade-offs noted for each. For the security analysis behind
each defence, see [Threat model](../threat-model.md).

The defaults are safe for typical home use: every connection uses mutual TLS 1.3 under your group's
keys, every copy is sealed end to end, the background service runs unprivileged in a sandbox,
remote paste and quick actions stay off until each device's own user enables them, and nothing
leaves your home network until you turn syncing away from home on.

## Protect the group's keys

1. **Keep the main device on a phone with security hardware.** An iPhone (Secure Enclave), Android
   phone (StrongBox or TEE Keystore), Aurora OS 5 phone (OP-TEE with admin PIN), or HarmonyOS phone
   (HUKS) keeps the main key in hardware that requires your face, fingerprint, passcode, or admin
   PIN before each admin signature. A computer acting as the main device (`cbb new`) stores its key
   in a TPM 2.0 or Mac Secure Enclave when available (or in a file otherwise), which still relies on
   operating-system prompts or root privileges rather than biometric approval on a separate device.
2. **Store the recovery key offline and keep a second device in the group.** Only the group's
   **recovery key** (the printed recovery sheet or a YubiKey) can move the group to a new main
   device if your main device is lost, and moving the group requires at least one remaining device
   in the group ([Upgrades and backups](upgrade-and-backup.md)). Keep the recovery key offline and
   away from your devices.
3. **Add only hardware-backed admins and keep the key level at `hardware` or `proven`.** A second
   admin phone lets you admit or remove members and remove a compromised admin computer when the
   main device is unavailable. Avoid lowering the group key level to `files` (`sudo cbb keys files`)
   or promoting a file-key computer with `sudo cbb admin -allow-file-key`: anyone who copies a
   file-backed admin key can admit devices until another admin freezes or removes that computer.
4. **Prefer attested hardware keys (`proven`).** Check the device list in the apps and the `KEYS`
   column of `cbb status`, which prints `proven hardware`, `hardware`, `in a file`, or
   `in a file, rootless` ([Keys and attestation](../guide/keys.md)). Android phones with a locked
   bootloader and verified OS, and Linux or Windows PCs with a discrete TPM 2.0 holding an on-chip
   Endorsement Key certificate, reach `proven hardware`. If your main device and admins all reach
   `proven hardware`, tighten the group key level with `sudo cbb keys proven` on the main computer
   (or **Settings > Advanced settings > Group > Admin keys** in the app).
5. **Use a forwarding-only hub on always-on devices without hardware keys.** If your always-on hub
   is a NAS, router, Raspberry Pi, or Docker container that keeps keys in files, configure it as a
   **hub that only passes copies on** (`sudo cbb global hub -on DEVICE -forward-only` on the main
   device). Copies stay sealed end to end past it, so it reads no clipboard content and needs no
   admin key.
6. **Encrypt every disk.** Enable LUKS (Linux), FileVault (macOS), BitLocker (Windows), or an
   encrypted volume on a NAS. A key stored in a file is safe only as long as the disk stays
   encrypted.

## Lock down individual devices

- **Admit only devices you control.** Every reading device in the group decrypts every copy sealed
  to it. Remove a device before giving it away or retiring it (`sudo cbb remove NAME`, or **Remove**
  in the app), and remove a lost device immediately
  ([If a device is lost or stolen](../guide/lost-device.md)).
- **Limit the `cbb` group.** On Linux, FreeBSD, and Windows, members of the local `cbb` group—and
  on macOS, members of `_cbb`—can read and send clipboard copies through the control socket. Add
  only the accounts that use that computer's desktop.
- **Keep the service sandbox intact.** On Linux, `cbb.service` runs as user `cbb` with
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `MemorySwapMax=0`, no capabilities, and restricted
  address families and system calls. Do not add systemd drop-ins that loosen these settings.
- **Avoid rootless Linux installs where system installs are possible.** A rootless install
  (`install.sh --rootless`) runs under your user account, so any program you run can copy its key
  files. Use the standard system install whenever you have `sudo`.
- **Pause syncing or mute untrusted clipboards.** Turn **Sync** off (`cbb sync off`) on a computer
  whose desktop clipboard should stay local while remaining connected (manual `cbb copy` and
  `cbb paste` still work). To prevent a device from sending copies to the group at all, mute it
  from an admin (`sudo cbb mute -on DEVICE`).
- **Mark secrets and shorten secret lifetimes.** Password manager secrets are skipped
  automatically, and items sent with `cbb copy -secret` stay in memory only and clear when they
  expire (60 seconds by default). To shorten the group's secret lifetime down to 5 seconds, run
  `sudo cbb ttl - 15s` on the main device or an admin ([Command reference](../reference/cli.md)).

## Restrict remote paste and quick actions

Both features remain off on every device until that device's own user turns them on locally.

- Enable only the targets and quick actions you use, on only the devices that need them, and limit
  which admin kinds can run each action with `-by` (for example, `sudo cbb action enable lock -by
  phone` allows only admin phones). Keep the default hardware-key requirement for `reboot` and
  `shutdown` (omit `-any-key`).
- Leave Enter disabled (`cbb paste-receive on` without `-enter`) so text with a line break is never
  pasted into a terminal or text console.
- Audit local logs when needed: every device logs who sent each paste or quick action (never secret
  text). To disable both features across every device in the group immediately from an admin, run
  `sudo cbb paste-receive off -all` and `sudo cbb action off -all`; only each device's own user can
  turn them back on locally.

## Restrict network exposure

- **Keep inbound firewall rules limited to your home network.** The installers allow TCP 8764 (or
  your custom member port) and UDP 5353 from private home address ranges only
  ([Installing: the firewall](../guide/install.md#the-firewall)).
- **Set `CBB_INTERFACES` on computers with multiple networks.** Restrict mDNS and the member port
  to trusted home interfaces in `cbb.env`—or `list zone` on OpenWrt—so guest, IoT, and WAN
  interfaces are excluded ([Routers and FreeBSD](routers.md),
  [Settings and environment variables](../reference/config.md)).
- **Turn syncing away from home off where it is not needed.** Run `sudo cbb global off` on devices
  that never leave home so they keep no tunnel keys and stay confined to your home network. On an
  admin, run `sudo cbb global off -on NAME` to disable it remotely on a lost device.
- **Prefer a direct hub or your own servers.** Port forwarding or IPv6 to your own hub avoids
  internet servers altogether. When you need a server on the internet, running your own forwarder
  or blind relay keeps connection times and IP addresses off `cbb.tools`
  ([Running your own servers](self-hosting.md)). A hub with a forwarder reveals less metadata than
  a blind relay.
- **Disguise tunnels on monitored networks.** Keep AmneziaWG enabled (the default on hubs) and use
  VLESS over XHTTP behind your own forwarder's website when operating on networks that inspect or
  block VPN traffic ([Networks that block VPNs](../guide/blocked-networks.md)).

## Keep software verified and current

- **Turn automatic updates on.** Run `sudo cbb update -auto on` on computers installed with
  `get.sh` or `get.ps1` so security fixes reach each computer within a day. `cbb status` marks any
  device running an older release than the newest known to the group with `(old)`.
- **Require build provenance attestations.** `get.sh`, `get.ps1`, and `cbb update` verify every
  release against the project's built-in release root keys and refuse unsigned releases by default.
  Set `CBB_ATTESTATION=require` before running `get.sh` or `get.ps1` (with an authenticated `gh`
  CLI) to also refuse any archive whose GitHub build provenance attestation does not verify
  ([Checking a download](../guide/install.md#checking-a-download)).
- **Watch security advisories.** Security fixes ship in the latest release and are announced in the
  [changelog](../../CHANGELOG.md) and GitHub Security Advisories. To report a vulnerability, follow
  [SECURITY.md](../../SECURITY.md).
