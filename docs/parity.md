<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Platform parity

For engineers and reviewers: the capabilities supported by each device class and which components
have been tested on physical hardware. For user-facing platform capabilities, ports, and file
paths, see [Devices, ports and files](reference/devices.md). For planned features and open work,
see [Roadmap](roadmap.md).

Devices within a class support the same feature set unless an operating system restriction prevents
it:

- **Computers**: Linux, macOS, and Windows (`cbb` with `cbb-helper`).
- **Phones**: Android, iPhone, Aurora OS (and Sailfish OS, `apps/silica`), and HarmonyOS 5 and
  later (`apps/harmony`).
- **Small devices**: `cbb` without `cbb-helper` on small Linux devices and routers, the Arduino
  Nano ESP32 firmware, and the ZX Spectrum Next (through its Raspberry Pi).

Table markers: **yes** (supported), **OS** (restricted by the operating system; reason noted),
**gap** (not yet implemented for that platform; tracked in [Roadmap](roadmap.md)), and
**not yet** (in progress for an experimental small-device target).

## Computers

| Capability | Linux | macOS | Windows | Notes |
|---|---|---|---|---|
| Service, desktop agent, autostart | yes | yes | yes | systemd and desktop autostart; LaunchDaemon and LaunchAgent; Windows Service and sign-in entry |
| Core `cbb` commands (`pair`, `remove`, `admin`, `freeze`, `recovery`, `invite`, `global`, `copy`, `paste`) | yes | yes | yes | Single `cbb` binary across all three platforms |
| Skip password-manager secrets | yes | yes | yes | X11/Wayland hint, `ConcealedType`, Windows clipboard formats |
| Battery detection | yes | yes | yes | |
| Installer and uninstaller (`--purge` / `-Purge`) | yes | yes | yes | |
| One-line installer with checksum and signature verification | yes (`get.sh`) | yes (`get.sh`) | yes (`get.ps1`) | |
| Package manager | Homebrew | Homebrew | winget (`cbb install` afterward) | Releases generate the winget manifest ([Maintaining](maintainers/maintaining.md)) |
| Custom member port (default `8764`) | yes (`--port`) | yes (`--port`) | yes (`-Port`) | |
| Inbound restricted to home network (in `cbb`) | yes | yes | yes | Member port drops non-home source addresses |
| Inbound restricted to home network (by OS) | yes (ufw, firewalld) | **OS** | yes (Windows Firewall) | macOS application firewall filters per binary, not per IP range |
| Outbound restricted to home network and group servers (in `cbb`) | yes | yes | yes | `internal/netguard` |
| Outbound restricted to home network and group servers (by OS) | yes (systemd unit; direct-address hub: **OS**) | **OS** | yes (Windows Firewall rule) | systemd cannot restrict a single UDP port; macOS lacks per-address app firewall rules |
| Optional `100.64.0.0/10` home network | yes (`--home-cgnat on`) | yes (`--home-cgnat on`) | yes (`-HomeCgnat on`) | Applied consistently to `cbb`, inbound firewall rules, and outbound limits |
| Skip firewall changes on request | `--no-firewall`, `CBB_FIREWALL=no` | `--no-firewall`, `CBB_FIREWALL=no` | `-NoFirewall`, `CBB_FIREWALL=no` | |
| Error details switch in `cbb` | `-debug`, `CBB_DEBUG=1` | same | same | |
| Error details switch in installers | yes (`CBB_ERROR_DETAILS=1`) | yes (`CBB_ERROR_DETAILS=1`) | yes (`-Details`, `CBB_ERROR_DETAILS=1`) | |
| Text-console helper (`tmux`) | yes (`--console`) | **OS** | **OS** | Intended for headless Linux machines |
| Uninstall from OS app list | — | **OS** | yes (Settings, Apps) | Linux has no single system app list |
| Signed binaries and packages | — | Developer ID, notarized, signed `.pkg` with Mac app | Ready; requires Authenticode certificate | Release workflow signs Windows binaries when a certificate secret is present |
| Hardware-backed device keys | yes (TPM 2.0 via `internal/tpmkey`) | yes (Secure Enclave on Apple silicon or T2 via `member/src/sekey.rs`) | yes (TPM 2.0; not yet tested on physical PC hardware) | Falls back to service-only files when no hardware is present |
| Self-update (manual and daily timer) | yes (`cbb update`) | yes (`cbb update` or Homebrew) | yes (`cbb update` or winget) | [Installing: updating](guide/install.md#updating) |
| Remote paste and quick actions as target | yes | yes | yes | Disabled by default until enabled locally by that device's user |
| Consent-based firewall rules (`--express` / `-Express` skips prompts) | yes | yes | yes | Prints manual commands for nftables and iptables |
| Opening hub UDP port in firewall with consent | yes (ufw, firewalld; commands for nftables, iptables) | **OS** | yes | `cbb global hub` prompts (`-firewall yes` skips prompt); macOS firewall allows listed binaries on all ports |
| Detect unknown blocking firewall via home check | yes | yes | yes | `cbb status` warns when home peers cannot connect inbound |
| Act as a Bluetooth LE keyboard | yes (`cbb keyboard`, BlueZ) | **OS** | **OS** | macOS and Windows reserve the Bluetooth HID service for the OS |
| Network TV remote (Android TV, Google TV, Apple TV, Roku) | yes (`cbb remote`) | yes | yes | Shared Go helper implementation |
| Group settings in desktop apps (lifetimes, admin keys, recovery key on YubiKey) | yes (tray app) | yes (Mac app) | yes (tray app) | Invokes `cbb ttl`, `cbb keys`, and `cbb recovery -leave … -yubikey` |
| Group notices and remote invitation join in desktop apps | yes (tray app) | yes (Mac app) | yes (tray app) | Displays `cbb status` notices; runs `cbb pair -invite - -app FILE` |
| Tested on physical hardware | yes | yes | not yet | Windows tested in an Arm Windows 11 VM |

## Phones

| Capability | Android | iPhone | Aurora OS | HarmonyOS | Notes |
|---|---|---|---|---|---|
| Create group with hardware-backed root key | yes (StrongBox or TEE behind biometrics/lock) | yes (Secure Enclave behind Face ID/passcode) | yes (OP-TEE behind app PIN on Aurora 5, D-94; file key on Aurora 4 / Sailfish OS) | yes (HUKS behind User Authentication Kit) | Aurora 5.1.5 exposes no OS biometric API to regular apps |
| Add a computer or small device by QR code | yes | yes | yes | yes | Core QR reader used on Aurora OS |
| Join another group as a member | yes | yes | yes | yes | Every phone joins as a member; main device promotes admins afterward (D-95) |
| Manage devices (make admin, remove, freeze/unfreeze, make hub) | yes | yes | yes | yes | Signed via the Rust core (`cbb_member_manage`) |
| Main-device settings (key level, copy lifetimes, recovery key) | yes | yes | yes | yes | Built and signed in the Rust core (`cbb_member_manage`) |
| Move the group with the recovery key (sheet or YubiKey) | yes: sheet, or YubiKey via NFC or USB-C (`UsbManager`, `ccid_bulk`) | yes: sheet, or YubiKey via NFC or USB-C (`CryptoTokenKit` where supported) | yes: sheet, or YubiKey via USB-C through `pcscd` (`pcsc`) | yes: sheet, or YubiKey via NFC (`IsoDep`) or USB-C (`usbManager`, `ccid_bulk`) | Core implements PIV (`cbb_piv`); moving a group runs on a device already in the group (D-125); USB-C card paths not yet tested on physical cards |
| Sync away from home (**Everywhere**) | yes (background and foreground) | While app is open (**OS**) | While app runs (tunnel and blind relay) | While app runs or continuous task (tunnel and blind relay) | iOS suspends background network connections |
| Receive copies automatically | yes (foreground service) | **OS** (while app is open) | yes | While app is in foreground | iOS restricts clipboard reads and writes to the foreground |
| Send copies without a tap | yes (accessibility service) | **OS** | **OS** | **OS** | iOS uses Back Tap / Action button shortcut; Aurora OS and HarmonyOS send when brought to the foreground |
| Share sheet / share menu | yes (text, images, files up to 100 MiB) | yes (text, links, images, files up to 50 MiB) | yes (text, images, files up to 50 MiB) | yes (text, links, images, files up to 50 MiB) | |
| Quick control outside the app | Quick Settings tile, notification **Send** button | Control Center switch (iOS 18+) | App cover status and sync actions | App icon shortcuts and Intents Kit | iOS Control Center switches cannot long-press to open the app (**OS**) |
| Home-screen widget | yes | yes | **OS** (uses app cover) | yes (Form Kit) | |
| Rename a device | yes | yes | yes | yes | Signed device record |
| Group notices and removed/changed-root cards | yes | yes | yes | yes | Driven by core `notices` and `root_changed` |
| Error details switch without developer tools | yes | yes | yes | yes | Revealed by tapping version 7 times in Settings |
| Dynamic wallpaper color theme | yes (Material You) | **OS** | System ambience | no | Material You is Android-only |
| Images, files, and sending remote paste to computers | yes | yes | yes | yes | Phones do not receive remote paste (D-132); iOS forbids apps from typing into other apps (**OS**) |
| Remote invitations (through a group hub) | yes | yes | yes | yes | |
| Arrange tiles and local collections | yes | yes | yes | yes | Stored locally per installation; mirrored to paired watches |
| Act as a Bluetooth LE keyboard | yes (where OEM includes HID profile) | **OS** | yes (BlueZ) | yes (HID over GATT, without LED reports) | iOS reserves Bluetooth HID for the OS |
| Tested on physical phone | not yet | yes (iPhone 12 Pro Max) | yes (F+ R570E, Aurora 5.1.5) | not yet | Android tested in CI emulator; HarmonyOS native module, ArkTS, and Node logic tests run in CI |

## Small devices

| Capability | `cbb` on small Linux devices | Arduino Nano ESP32 | ZX Spectrum Next (with Pi) | Notes |
|---|---|---|---|---|
| Join by phone QR code or computer code | yes | not yet | yes (through Pi) | |
| Sync clipboard | yes | not yet | yes (through Pi) | ESP32 Wi-Fi, USB, and BLE keyboard firmware is built; sync tracked in [Roadmap](roadmap.md) |
| Accept connections from phones and Macs | yes | not yet | yes (through Pi) | |
| Secrets (`copy -secret`) | yes | not yet | yes (`.cbb text -s`, `.cbb copy -s`) | |
| Sync away from home | yes (`member/tests/away_live.rs`) | not yet | yes (through Pi) | Excluded on 32-bit MIPS routers (no 64-bit atomics for GotaTun) |
| Self-update | yes (`cbb update`, Linux and OpenWrt) | not yet | yes (`.cbb update` through Pi) | |
| Error details switch | yes (`-debug`, `CBB_DEBUG=1`) | not yet | yes (`.cbb -d`) | |

## On real devices

This table records what each component implements, how CI verifies it, and what has run on
physical hardware.

| Component | Build and CI status | Tested on physical hardware |
|---|---|---|
| Linux service, desktop clipboard (X11, Wayland), `tmux`, `cbb copy` / `paste` | Built and tested in CI | Yes (Raspberry Pi, Steam Deck) |
| macOS service and pasteboard agent | Built and tested in CI | Yes |
| Windows service, clipboard agent, installer | Built and tested in CI (`windows-latest`) | Windows 11 Arm virtual machine only; not yet on a physical PC |
| FreeBSD and OPNsense service and installer | Built and tested in CI (FreeBSD 15.1 VM) | Not yet |
| OpenWrt service and installer | Built and tested in CI (OpenWrt in QEMU) | Not yet |
| iPhone app (main device, admin, device list) | Built and tested in CI (iOS Simulator) | Yes (iPhone 12 Pro Max): root key in Secure Enclave with Face ID, admitting computers, promoting an admin computer, two-way sync; second phone and recovery not yet tried |
| Android app (full and reproducible F-Droid APKs) | Built and tested in CI (unit tests, emulator, reproducibility) | Not yet |
| Aurora OS and Sailfish OS app (`apps/silica`) | Built (unsigned RPMs for Aurora 5, Aurora 4, Sailfish OS) and Qt host tests in CI | Yes (F+ R570E on Aurora OS 5.1.5); group creation, YubiKey over `pcscd`, and away sync not yet tried on the phone |
| HarmonyOS app (`apps/harmony`) | Rust core, N-API module, ArkTS compiler/linter, and Node logic tests in CI (HAP requires HarmonyOS CLI / DevEco Studio) | Not yet |
| Mac app (menu bar) and Linux/Windows tray app | Built and tested in CI | Mac app on macOS; tray app in Windows 11 VM; Linux tray app not yet |
| Apple Watch, Wear OS, and HarmonyOS watch apps | Built and tested in CI (Apple Watch, Wear OS, HarmonyOS watch Node tests) | Apple Watch Ultra (device list); Wear OS and HarmonyOS watch not yet |
| `cbb` without `cbb-helper` on small Linux devices | Built and tested in CI e2e | Yes (joined a group on a Raspberry Pi Zero W) |
| Arduino Nano ESP32 firmware | Wi-Fi, USB, and BLE keyboard built and tested in QEMU in CI | Not yet |
| Sync away from home between computers (`cbb global`, `cbb invite`) | Built and tested in CI | Not yet |
| Sync away from home for phones and small devices | Built and tested in CI | Yes: iPhone on mobile data through a Mac hub and the `cbb.tools` forwarder |
| Multiple hubs and self-hosted blind relay (D-134) | Built and tested in CI | Not yet |
| Images, files, and formatted text | Built and tested in CI | Not yet |
| Remote paste and quick actions | Built and tested in CI | Remote paste from iPhone to Mac (at home and away); Windows, Linux, and quick actions not yet |
| TPM 2.0 keys (Linux/Windows), Android Key Attestation, key levels (`cbb keys`) | Built and tested in CI against `swtpm` | Windows VM only; physical TPM PCs and Android hardware not yet |
| Hybrid signed releases, `cbb update`, Android self-update | Built and tested in CI with pinned YubiKey roots (`internal/release/roots/roots.pem`) | Not yet exercised on a published user upgrade |
| Project forwarder and open blind relay (`cbb.tools`) | Deployed and tested | Forwarder carried phone sync to a Mac hub |
| Bluetooth keyboards and network TV remotes (`cbb keyboard`, `cbb remote`) | Built and tested in CI against fake TVs and BlueZ | Yes (typing on an Apple TV 4K) |
| Homebrew (`hunterewok/tap`) and signed macOS `.pkg` / TestFlight | Release workflows configured | Not yet run end to end for a published release |
