<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Hardening

For whoever looks after the group: the settings that make a group harder to attack, beyond
the defaults, in order of what they protect most. Each item says what it costs. Why each
defence exists is in the [threat model](../threat-model.md).

The defaults are already safe for a home: every connection is TLS 1.3 under the group's
keys, the service runs unprivileged in a sandbox, remote paste and quick actions are off
until each device's own user turns them on, and nothing leaves the home network unless you
turn sync away from home on.

## The group's keys

1. **Keep the root on a phone.** A phone's root key sits in the Secure Enclave or the
   Keystore and signs only after your face, fingerprint or passcode. A computer's root key
   (`cbb new`) sits in a file.
2. **Have a second admin, and only in hardware.** A second admin phone, or a Linux computer
   with a TPM, lets the group survive a lost root ([upgrades and backups](upgrade-and-backup.md)).
   Do not make a computer whose keys sit in a file an admin (`cbb admin -allow-file-key`)
   unless you must: whoever copies the file can add devices until another admin removes it.
3. **Prefer devices that prove their keys.** The devices list and `cbb status` (the KEYS
   column) show `file`, `hardware` or `proven` for each device ([keys](../guide/keys.md)).
   A Linux computer with a discrete TPM and an Android phone with a locked bootloader can be
   proven.
4. **Encrypt every disk.** LUKS, FileVault, BitLocker, or an encrypted volume on a NAS. A
   key in a file is safe only as long as the disk it is on.

## The devices

- **Only devices you control.** Every device in the group reads every copy that reaches
  it. Remove a device you give away before it leaves (`sudo cbb remove NAME`, or Remove in
  the app), and a lost one at once ([if a device is lost](../guide/lost-device.md)).
- **Limit the `cbb` group.** On Linux, FreeBSD and macOS, members of the
  system group `cbb` read and set the clipboard through the service; add only
  the people who use that computer's desktop.
- **Leave the service's sandbox as it is.** The systemd unit runs the service as its own
  user without capabilities (`NoNewPrivileges`, `ProtectSystem=strict`, restricted address
  families and system calls). A drop-in that loosens it removes a defence.
- **Turn sync off where it is not wanted.** A shared computer whose clipboard should stay
  its own runs `cbb sync off`; its copies then never reach the group, and an admin turns it
  back with `cbb sync -on DEVICE on`.
- **Mark secrets.** A password manager's copies, and `cbb copy -secret`, live only in memory
  and are gone after 60 seconds.

## Remote paste and quick actions

Both are off on every device until its own user turns them on there.

- Turn on only what you use, on only the devices that need it, and only for the signers
  that need it (`-by phone`, for example, lets only phones run an action).
- Leave Enter off (`cbb paste-receive on` without `-enter`): a text with a line break then
  never reaches a terminal or the console.
- Every device logs who pasted or ran what; `cbb paste-receive off -all` and
  `cbb action off -all` on an admin turn them off on every device at once, and only each
  device's own user turns them on again.

## The network

- **Keep the firewall rules to the home network.** The installers' rules open TCP 8764 and
  mDNS from the home network only ([the firewall](../guide/install.md#the-firewall)).
- **Name the interfaces on a computer with several networks.** `CBB_INTERFACES`
  ([settings](../reference/config.md)) limits mDNS and the member port to the networks you
  name, as the `zone` list does on OpenWrt; a computer with a guest or IoT network should
  have it.
- **Sync away from home only where needed.** `cbb global off` on a device that never leaves
  home; each device that is on keeps a tunnel key in its state. Turn it off on a lost device
  from another one (`cbb global off -on NAME`).
- **Your own servers.** A forwarder or a blind relay you run yourself keeps the times and
  addresses of your devices away from anyone else ([running your own servers](self-hosting.md)).
  A relay sees which devices are online and when; a hub at home with a forwarder sees less.
- **Networks that watch traffic.** AmneziaWG's obfuscation, or VLESS with REALITY on your
  forwarder, hides that the tunnel is WireGuard ([networks that block VPNs](../guide/blocked-networks.md)).

## Updates and downloads

- **Automatic updates on** (`sudo cbb update -auto on`): security fixes reach every
  computer within a day. `cbb status` marks a device that runs an older release `(old)`.
- **Check what you install.** `CBB_ATTESTATION=require` makes `get.sh` refuse an archive
  whose build attestation does not check out ([checking a download](../guide/install.md#checking-a-download)).
  Once the project's release keys exist, the installers and `cbb update` refuse an unsigned
  release by themselves.
- **Watch the advisories.** Security fixes are announced in the
  [changelog](../../CHANGELOG.md) and GitHub's security advisories; how to report one is in
  [SECURITY.md](../../SECURITY.md).
