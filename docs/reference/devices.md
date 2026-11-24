<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Devices, ports and files

For users and administrators checking platform capabilities, network ports, and file and log
locations. For the engineering capability matrix and platform gaps, see
[Platform parity](../parity.md).

## What each device can do

In the table below, **Computers** covers Linux, Windows, FreeBSD, OpenWrt, and OPNsense. Small
devices such as Raspberry Pi boards and routers typically install `cbb` without `cbb-helper`
(`get.sh --no-helper`; see [Small devices](../../member/README.md)): they store keys in files
(requiring key level `files` for main device or admin roles, though a forwarding-only hub needs
none), omit `cbb keyboard` and `cbb remote`, and on MIPS routers do not include the away-from-home
tunnel. Rootless Linux installs (`install.sh --rootless`) sync like any member but cannot be the
main device, an admin, or a hub.

| Capability | Computers | macOS | Android | iPhone | Aurora OS / Sailfish OS | HarmonyOS |
|---|---|---|---|---|---|---|
| Sync clipboard at home | Yes | Yes | Yes | Yes (one gesture or while open) | Yes | Yes |
| Receive copies automatically | Yes | Yes | Yes (foreground service) | While app is open (iOS limit) | Yes | While app is open |
| Send copies automatically | Yes | Yes | With accessibility service | While app is open; one gesture in background (iOS limit) | While app is open (OS limit) | While app is open (OS limit) |
| Images and files | Yes (desktop) | Yes | Yes | Yes (while app runs) | Yes | Yes |
| Main device (*root*) | Yes ([Without the app](../guide/without-app.md)) | Yes | Yes | Yes | Yes | Yes |
| Admin | Yes | Yes | Yes | Yes | Yes | Yes |
| Hub | Yes (except rootless Linux and MIPS routers) | Yes | No | No | No | No |
| Sync away from home (**Everywhere**) | Yes (except MIPS routers) | Yes | Yes (including background) | While app is open | While app runs | While app runs (or continuous task) |
| AmneziaWG and VLESS | Yes (except MIPS routers) | Yes | Yes | Yes | Yes | Yes |
| Join from afar by invitation | Yes | Yes | Yes | Yes | Yes | Yes |
| Use a blind relay | Yes | Yes | Yes | Yes | Yes | Yes |
| Receive remote paste | Yes (X11, Wayland, GNOME/KDE, Windows, tmux, Linux text console) | Yes (through Mac app) | No | No (iOS limit) | No | No |
| Run quick actions | Yes (presets and custom) | Yes | No | No | No | No |
| Act as a Bluetooth keyboard | Linux with `cbb-helper` and BlueZ 5.50+ | No (OS limit) | Yes (where supported) | No (OS limit) | Yes (BlueZ) | Yes (HID over GATT) |
| Control TVs (`cbb remote`) | Yes (with `cbb-helper`) | Yes | No | No | No | No |
| Device key storage | TPM 2.0 on Linux and Windows when present, otherwise files; files on FreeBSD, OpenWrt, rootless Linux, and without `cbb-helper` | Secure Enclave (Apple silicon or T2 Mac), otherwise files | Android Keystore (StrongBox or TEE) | Secure Enclave | OP-TEE (Aurora 5); files (Aurora 4 and Sailfish OS) | HUKS |
| Updates ([Installing](../guide/install.md#updating)) | `cbb update` (manual or daily timer); Homebrew, winget, Docker, or OS packages | `cbb update` or Homebrew | Release APK in Settings or F-Droid | App Store / TestFlight | RPM release | HAP release |

Items marked as secret by password managers are skipped automatically. Remote paste targets and
quick actions remain disabled on every device until that device's own user enables them.

## Ports

| Port | Listener | Allowed source | Purpose |
|---|---|---|---|
| TCP `8764` | Every computer and small device | Home network | Member-to-member TLS connections (`cbb/4`) and home pairing (`cbb-pair/3`). Configurable via `--port` / `CBB_PORT`. |
| UDP `5353` | Every device | Home network | Local network discovery (mDNS). |
| UDP `8764` | Hub | Internet | Away-from-home WireGuard/AmneziaWG tunnel (requires router port forwarding or IPv6 when reached directly). |
| UDP and TCP `8764` | Forwarder (`cbb forward`) or blind relay (`cbb relay`) | Internet | Self-hosted forwarder or blind relay ([Running your own servers](../admin/self-hosting.md)). |
| UDP and TCP `8765` | Project open blind relay (`cbb.tools:8765`) | Internet | Default open blind relay for groups without a hub. |
| TCP `443` | Web server in front of a forwarder with VLESS | Internet | VLESS over XHTTP disguised as HTTPS. |
| TCP `3276` | Forwarder with VLESS (`-vless-listen`) | Loopback only | Plain HTTP handoff from the front-end web server for VLESS over XHTTP. |
| TCP `8767` | Push service (`cbb-push`) | Internet | Sealed wake-up push relay for closed phone apps (`packaging/linux/cbb-push.service`). |
| TCP `8791` | Bug report collector (`cbb-bug`) | Loopback only | Sealed bug report intake behind nginx (`packaging/linux/cbb-bug.service`). |
| TCP `6466`, `6467` | Android TV / Google TV | Home computer (outbound) | Remote control (`6466`) and pairing (`6467`) for [`cbb remote`](cli.md). |
| TCP `49153` | Apple TV | Home computer (outbound) | Companion protocol pairing and remote control for [`cbb remote`](cli.md). |
| TCP `8060` | Roku | Home computer (outbound) | External Control Protocol (plain HTTP) for [`cbb remote`](cli.md). |
| TCP `8769` | `cbb next link` on a ZX Spectrum Next Pi | Loopback only | Local TCP bridge forwarding member traffic over the Next's ESP8266. |

TV ports listen on the TV; `cbb` only opens outbound connections to them. Installers prompt before
adding inbound firewall rules ([The firewall](../guide/install.md#the-firewall)).

## Files and logs

| System | Keys and state | Settings | Logs |
|---|---|---|---|
| Linux (system install) | `/var/lib/cbb` | `/etc/cbb` | `journalctl -u cbb` (service); `journalctl --user -u cbb-agent` (desktop connector) |
| Linux (rootless install) | `~/.local/state/cbb` | `~/.config/cbb` | `journalctl --user -u cbb` (service); `journalctl --user -u cbb-agent` (desktop connector) |
| FreeBSD, OPNsense | `/var/db/cbb` | `/usr/local/etc/cbb` | syslog (`/var/log/messages`) |
| OpenWrt | `/etc/cbb/state` (preserved across sysupgrade) | `/etc/config/cbb` | `logread -e cbb` |
| macOS | `/Library/Application Support/cbb/state` | `/etc/cbb` | `/Library/Logs/cbb/service.log` (service); `~/Library/Logs/cbb/agent.log` (agent) |
| Windows | `ProgramData\cbb\state` | Service registry key ([Settings files](config.md#settings-files)) | `ProgramData\cbb\logs\service.log` (service); `LocalAppData\cbb\agent.log` (agent) |

Exclude state directories from unencrypted backups and enable full-disk encryption (LUKS,
FileVault, or BitLocker): anyone who copies a device's file-backed keys can impersonate that
device until an admin removes it from the group.
