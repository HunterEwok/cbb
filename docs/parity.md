<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Platform parity

Devices of one class can do the same things. A difference is allowed only where the
system itself forces it, and then it is written here with the reason. The classes:

- **Computers**: Linux, macOS, Windows (`cbb`).
- **Phones**: Android, iPhone, Aurora OS (the apps; the Aurora app also builds for Sailfish OS).
- **Lite devices**: the lite member (`cbb` in Rust) on small Linux devices, the ESP32 firmware, the ZX Spectrum
  Next through its Pi.

A feature added to one platform is planned for its whole class in the same task, or added
here as a gap. This table is kept up to date with every such change.

Marks: **yes**; **OS** (differs because the system forces it; the reason follows);
**gap** (missing for no system reason; the plan below closes it); **planned** (missing
on every platform of the class, on the roadmap).

## Computers

| Capability | Linux | macOS | Windows | Notes |
|---|---|---|---|---|
| Service, agent, autostart | yes | yes | yes | systemd and desktop autostart; LaunchDaemon and LaunchAgent; Windows service and the sign-in entry |
| Every `cbb` command (pair, revoke, admin, freeze, takeover, invite, global, copy, paste) | yes | yes | yes | one program; the service is the same code |
| Secrets from password managers | yes | yes | yes | X11/Wayland hint, `ConcealedType`, the Windows clipboard formats |
| Battery detection | yes | yes | yes | |
| Installer and uninstaller, `--purge` | yes | yes | yes | |
| One-line installer with checksum check | yes (`get.sh`) | yes (`get.sh`) | yes (`get.ps1`) | |
| Package manager | Homebrew | Homebrew | winget (`cbb install` after it) | each release writes the winget manifest; it reaches winget by a pull request to its repository (docs/maintaining.md) |
| Member port other than 8764 | yes (`--port`) | yes (`--port`) | yes (`-Port`) | |
| Inbound only from the home network, in the program | yes | yes | yes | the member port drops other addresses |
| Inbound only from the home network, by the system | yes (ufw, firewalld) | **OS** | yes (Windows Firewall) | the macOS application firewall allows or blocks a program, not an address; a Network Extension of the Mac app (roadmap item 22) |
| Outbound only to the home network, and with `cbb global on` to the group's servers, in the program | yes | yes | yes | `internal/netguard` |
| Outbound only to the home network, and with `cbb global on` to the group's servers, by the system | yes (systemd unit; a hub at its own address: **OS**) | **OS** | yes (firewall rule) | systemd cannot allow one port only, so a hub reached at its own address relies on the program; macOS: as above, roadmap item 22 |
| 100.64.0.0/10 as the home network, on request | yes (`--home-cgnat on`) | yes (`--home-cgnat on`) | yes (`-HomeCgnat on`) | the program, the firewall rules and the outbound limit alike |
| Firewall left alone on request | `--no-firewall`, `CBB_FIREWALL=no` | `--no-firewall`, `CBB_FIREWALL=no` | `-NoFirewall`, `CBB_FIREWALL=no` | |
| Error details switch in `cbb` | `CBB_DEBUG=1`, debug builds | same | same | |
| Error details switch in the installers | yes (`CBB_ERROR_DETAILS=1`) | yes (`CBB_ERROR_DETAILS=1`) | yes (`-Details`, `CBB_ERROR_DETAILS=1`) | |
| Text-console helper (tmux) | yes (`--console`) | **OS** | **OS** | for a Linux machine without a desktop; a Mac and a Windows PC always have one |
| Removal from the system's app list | — | **OS** | yes (Settings, Apps) | Linux has no common list; the Mac app (item 22) brings it to macOS |
| Signed program | — | Developer ID, notarized, and the `.pkg` with CBB.app | ready, needs a certificate | the release signs with Authenticode once the secrets hold a certificate (G5) |
| Device keys in hardware | yes, with a TPM (`internal/tpmkey`) | yes, the Secure Enclave on Apple silicon or the T2 chip (`internal/sekey`) | yes, with a TPM 2.0, not yet tested on a real PC | roadmap item 13 |
| Update itself, by hand and once a day | yes (`cbb update`) | yes, or Homebrew | yes (`cbb update`), or winget | [installing](guide/install.md#updating) |
| Quick actions and remote paste as a target | yes | yes | yes | each off until the device's own user turns it on |
| Firewall rules only with the user's consent, listed one by one; `--express` without questions | yes | yes | yes (`-Express`) | nftables and iptables get the commands only, as their rules do not survive a restart |
| Opening the hub's UDP port in the firewall, with consent | yes (ufw, firewalld; commands for nftables, iptables) | **OS** | yes | `cbb global hub` asks, `-firewall yes` without asking; the macOS application firewall already allows a listed program on every port |
| Finding a firewall the installer does not know, by a check from home | yes | yes | yes | `cbb status` warns when the members at home could not connect and sync only because this computer dials them back |
| Act as a Bluetooth keyboard for a TV, tablet or computer | yes (`cbb keyboard`, BLE) | **OS** | **OS** | macOS and Windows keep the HID service to the system |
| Be the remote of an Android TV, a Google TV, an Apple TV or a Roku | yes (`cbb remote`) | yes | yes | the same Go code everywhere; the phones' apps follow |
| Tested on a real device | yes | yes | not yet | the 0.4 bench |

## Phones

| Capability | Android | iPhone | Aurora OS | Notes |
|---|---|---|---|---|
| Make a group, root key in hardware behind biometrics | yes | yes | yes, the root key in the TEE; no prompt before signing: Aurora 5.1.5 keeps its authentication service out of a regular app's sandbox (a probe on the R570E shows it); making a group not yet tried on the phone | StrongBox or TEE; Secure Enclave |
| Add a computer or a lite device by QR code | yes | yes | yes, as an admin; not yet tried on the phone | the Aurora app reads the code with the core's reader |
| Join another phone's group | yes | yes | yes | |
| Make an admin, remove, take over from a lost root, renew certificates | yes | yes | remove, renew and take over from a lost root (its admin key in the TEE becomes the new root), as the root or an admin; not yet tried on the phone | the core signs (`cbb_core::takeover` for the takeover), the app's admin key in the TEE |
| Make a computer an admin | yes | yes | yes, as the root, for a computer connected; not yet tried on the phone | |
| Sync away from home | yes, in the background | while the app runs | yes, while the app runs, through the lite member's tunnel in the core (`TestFFIPhoneAway`); not yet tried on the phone | **OS**: iOS stops a background app's network |
| Receive copies without a tap | yes (foreground service) | **OS** | yes | iOS lets an app read and write the clipboard only in the foreground; Aurora lets it write in the background |
| Send without a tap | yes (accessibility service) | **OS** | **OS** | iOS: Back Tap or the Action button runs the app's shortcut, one gesture; Aurora reads the clipboard only in the foreground, so the app sends when it comes to the front |
| Send from the share sheet and the text selection menu | yes | yes | yes, text, through the system's share menu; not yet tried on the phone | the iPhone's share extension; its menu's Share |
| One-tap control outside the app | Quick Settings tile, notification button | Control Center control (iOS 18) | the cover's actions: the one button, pause; not yet tried on the phone | the control opens the app for a moment: **OS**, iOS reads the clipboard only in the foreground |
| Home-screen widget | yes | yes | **OS** (no widgets; the cover instead) | "Sync clipboard"; on the iPhone it opens the app for a moment, as the control does |
| Rename a device | yes | yes | yes; not yet tried on the phone | Devices, Rename on an admin phone; `cbb rename` on an admin computer; a signed device record |
| The group's alerts card, and the root's decision on it | yes | yes | yes; not yet tried on the phone | `GroupAlert` in the kits, the core's `alerts` op on Aurora |
| Error details switch without developer tools | yes | yes | yes | seven taps on the version in Settings show it; `adb` and the Xcode launch argument still work |
| Wallpaper colours theme | yes | **OS** | the ambience | Material You exists only on Android |
| Remote paste, images and files | yes | yes | images and files both ways, through the share menu, the clipboard's image and Downloads; not yet tried on the phone. Gap: remote paste | the iPhone takes no remote paste (**OS**: no app may type into another) |
| Remote invitations | planned | planned | planned | roadmap item 12; computers have them |
| Arrange the tiles and collections | yes | yes | gap | kept on each installation; the watches show their phone's |
| Act as a Bluetooth keyboard for a TV, tablet or computer | yes | **OS** | gap | iOS keeps the HID service to the system; some Android makers leave the profile out, which the app says |
| Tested on a real phone | not yet | yes | yes, on Aurora 5.1.5 | the iPhone app on an iPhone 12 Pro Max, built with a developer's own team; the Aurora app on an F+ R570E |

## Lite devices

| Capability | Lite member on Linux | ESP32 | ZX Spectrum Next | Notes |
|---|---|---|---|---|
| Join by the phone's QR code or a computer's code | yes | yes (pairing; on Linux over TAP in CI) | yes, through the Pi | |
| Sync the clipboard | yes | not yet | yes, through the Pi | the firmware's sync is the next step of roadmap item 15 |
| Listen for phones and Macs | yes | not yet | through the Pi | |
| Secrets (`copy -secret`) | yes | not yet | yes (`.cbb text -s`, `.cbb copy -s`) | |
| Sync away from home | yes (`TestLiteMemberAway`) | planned | through the Pi | not on MIPS routers yet: the lite member for MIPS is built without the tunnel |
| Update itself | yes (`cbb update`, Linux and OpenWrt) | planned (OTA, roadmap item 29) | through the Pi | |
| Error details switch | yes (`-debug`, `CBB_DEBUG=1`) | not yet | yes (`.cbb -d`) | |

The ESP32 and the Next are still being built, so "not yet" is progress, not a gap: each
item is on its road to the Linux lite member's set.

## Plan

One pull request each, in this order; anything under 100 lines rides in the open one.

1. **G1**, done: `--port` in the Mac installer and `get.sh` on a Mac, kept in
   `/etc/cbb/cbb.env` as on Linux.
2. **G2**, done: `CBB_ERROR_DETAILS=1` in `install.sh`, `uninstall.sh` and `get.sh` on Linux
   and macOS shows every command as it runs; without it a failure names its exit status.
3. **P5**, done: an error details switch in both apps' Settings, hidden behind a few taps on the
   version, besides the developer launch arguments.
4. **P4**, done: rename a device in both apps (and `cbb rename` on computers), a signed record.
5. **P1, P2**, done: the iPhone's Share extension and Control Center control.
6. **P3**, done: a home-screen widget in both apps.
7. **G4, G5**, done: a winget manifest from every release and `cbb install` after winget;
   Authenticode signing in the release, waiting for the owner's certificate.
8. **G6**, decided by the owner: the firewall rules only with consent, the same on every
   computer. The installer finds the firewall itself (ufw, firewalld, nftables, iptables on
   Linux; Windows Firewall; the macOS application firewall), lists each rule it needs
   (protocol, port, source, purpose) and asks `Add these rules now? [y/N]`. Yes: `cbb`
   manages its rules from then on, the hub's UDP port at `cbb global hub` included (asked
   again, since it faces the internet), and removes them on uninstall. No: it prints the
   exact commands for that firewall and works while the rules are there. `--express` adds
   them without a question and prints the same list as a report. Done: the installers,
   `cbb global hub` and the check from home. A member at home dials
   the computer back, so `cbb status` says when an unknown firewall or a closed rule keeps
   the others out. Messages are formal English, one fact per line.
9. **L1**, done: `.cbb copy -s` and `.cbb text -s`, a secret from the Next (`cbb next copy -secret`).
10. Roadmap item 22, the Mac app: the system's limits on a Mac (in and out), removal
    from the system, the signed `.pkg`.
11. **A1 to A7**, the owner's decision (2026-11-07): the Aurora app closes every gap of its column
    before 0.6, so that the three phones move on together. A1: the devices as tiles or
    a list, a device's page, Settings with the language and the error details. Then adding a
    device by QR code, the admin's actions (after the core sends commands), the one button,
    images and files and the group's alerts (after the phones' node moves into the core), the
    cover, notifications and Share, sync away from home with the phones' tunnel, and a group
    of its own with its root on the phone.
