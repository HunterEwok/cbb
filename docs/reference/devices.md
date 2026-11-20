<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Devices, ports and files

What each kind of device can do, which ports Copy Beyond Borders uses, and where it keeps its
files. For developers, the full comparison with its reasons is in
[Platform parity](../parity.md).

## What each device can do

"Computers" are Linux, Windows and FreeBSD, and routers with OpenWrt or OPNsense, which run
the same `cbb` without a desktop. A small device, a Raspberry Pi or a router, runs it too,
usually without `cbb-helper` beside it: it then keeps its keys in files, so it is the root or
an admin only where the group's [level](../guide/keys.md#the-three-levels) allows keys in files
(a hub that only passes copies on needs none), and it has no Bluetooth keyboard or TV remotes; on MIPS routers it has no sync away from home yet
([small devices](../../member/README.md)).

| | Computers | Mac | Android | iPhone |
|---|---|---|---|---|
| Sync the clipboard at home | yes | yes | yes | yes, with one gesture |
| Gets copies without a tap | yes | yes | yes | no: iOS allows it only in front |
| Sends copies without a tap | yes | yes | with the accessibility service | no: one gesture |
| Images and files | yes, on a desktop | yes | yes | yes, while the app runs |
| Hold the group (root) | yes, [without the app](../guide/without-app.md) | yes | yes | yes |
| Be an admin | yes | yes | yes | yes |
| Be the hub | yes | yes | while the app is open, or in the background with "Keep the hub running in the background" | while the app is open |
| Sync away from home | yes | yes | yes, also in the background | while the app is open |
| AmneziaWG and VLESS | yes | yes | yes | yes |
| Join from afar by an invitation | yes | yes | not yet | not yet |
| Use a blind relay | yes | yes | yes | yes |
| Take remote paste | yes: X11, Wayland, GNOME and KDE, Windows, tmux, the text console | through the Mac app | yes, with the accessibility service | no: iOS allows no app to type into another |
| Take quick actions | yes, the presets and your own | yes | no | no |
| Device keys | in the TPM on Linux when there is one, else in files | in files | in the security chip | in the Secure Enclave |
| Update itself ([how](../guide/install.md#updating)) | yes (`cbb update`, once a day if turned on); Homebrew, winget, Docker and packages through their own tools | yes, or Homebrew | the APK from a release, in Settings | through its store, once it is in one |

Items that password managers mark as secret are not synced automatically. Each remote paste
target and each quick action is off until the device's own user turns it on.

## Ports

| Port | Who listens | From where | What for |
|---|---|---|---|
| TCP 8764 | every computer and small device | the home network | the devices' connections |
| UDP 5353 | every device | the home network | mDNS, to find each other |
| UDP 8764 | the hub | the internet | the group's tunnel, with a router port forward |
| UDP and TCP 8764 | a forwarder or a relay | the internet | [your own servers](../admin/self-hosting.md) |
| TCP 443 | the web server in front of a forwarder with VLESS | the internet | VLESS over XHTTP |
| TCP 3276 | a forwarder with VLESS | its own loopback address, from the web server in front | VLESS over XHTTP as plain HTTP (`-vless-listen`) |
| TCP 6466 and 6467 | an Android TV or a Google TV | a computer at home | its remote and its pairing, for [`cbb remote`](cli.md) |
| TCP 49153 | an Apple TV | a computer at home | the Companion protocol, its pairing and its remote, for [`cbb remote`](cli.md) |
| TCP 8060 | a Roku | a computer at home | its External Control Protocol, for [`cbb remote`](cli.md) |
| TCP 8769 | `cbb next link` on a ZX Spectrum Next's Pi | the loopback address only | the connections of `cbb` on that Pi through the Next's ESP8266 |

The member port can be changed when installing (`--port`, [settings](config.md)). The TVs' ports are
on the TV; a computer only connects to them. The installers ask before they open any of the
others ([the firewall](../guide/install.md#the-firewall)).

## Files and logs

| System | Keys and state | Settings | Log |
|---|---|---|---|
| Linux | `/var/lib/cbb` | `/etc/cbb` | `journalctl -u cbb`; the desktop connector in `journalctl --user` |
| FreeBSD, OPNsense | `/var/db/cbb` | `/usr/local/etc/cbb` | syslog, `/var/log/messages` |
| OpenWrt | `/etc/cbb/state`, kept by sysupgrade | `/etc/config/cbb` | `logread -e cbb` |
| Mac | `/Library/Application Support/cbb/state` | `/etc/cbb` | `/Library/Logs/cbb/service.log`, the agent's `~/Library/Logs/cbb/agent.log` |
| Windows | `ProgramData\cbb\state` | the service's registry key ([settings](config.md#settings-files)) | `ProgramData\cbb\logs\service.log`, the agent's `LocalAppData\cbb\agent.log` |

Keep the keys out of unencrypted backups, and encrypt the disk (LUKS, FileVault,
BitLocker): whoever copies them can act as that device until you remove it from the group.
