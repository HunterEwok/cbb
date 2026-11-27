<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The hardware test bench

For the project maintainer and release testers running pre-release verification on physical devices
and containerized fleets. This page specifies the test bench's goals, device roles, test matrix,
security and release criteria, inventory format, and automation harness (`tools/bench`).

For CI jobs, see [Maintaining](maintaining.md#ci). For all test levels across the repository, see
[Testing](../testing.md). For the full case catalogue, product function map, and step-by-step
procedures, see [Test bench catalogue](testbench-catalogue.md),
[Test bench functions](testbench-functions.md), and [Test bench cases](testbench-cases.md).

## 1. Goal

Before each release, an automated bench of real devices runs the user-facing and security cases
that CI cannot cover and reports pass or fail with logs, without manual copy-and-paste.

CI covers unit tests with `-race`, multi-member Docker end-to-end tests, headless Wayland and X11
clipboard tests, platform installers, cross-implementation tests across Go, Rust, Swift, and
Kotlin, and `cbb` without `cbb-helper`. The hardware bench covers what CI cannot:

- Real hardware and operating systems: a small ARM Linux board running `cbb` without `cbb-helper`,
  a Linux desktop, a Mac, Windows, FreeBSD, OpenWrt, and mobile devices.
- Live desktop clipboards in signed-in sessions (Linux Wayland/X11, macOS pasteboard, Win32
  clipboard), rather than only the service's internal clipboard store.
- A real home network: Wi-Fi, mDNS on the router, multiple subnets, and installer-configured
  firewalls.
- Real internet paths: the hub's WireGuard/AmneziaWG and VLESS-over-XHTTP tunnels from outside the
  home network, a forwarder, a blind relay, NAT, IPv4, and IPv6.
- Long soak runs, reboots, sleep and wake, network loss, and release upgrades.

## 2. Scope

| Area | What is tested |
|---|---|
| Install, update, and remove | `get.sh`/`install.sh`/`uninstall.sh` on Linux, macOS (including Homebrew), OpenWrt, and FreeBSD; `get.ps1`/`install.ps1`/`uninstall.ps1` on Windows; `get.sh --no-helper` for small devices; `cbb update`; firewall rules added and removed; `--purge` / `-Purge`. |
| Group and pairing | `cbb new`, `cbb pair`, `cbb pair -code` (with and without an address, and without `cbb-helper`), QR pairing with phone apps, wrong and expired codes, `cbb remove`, `cbb freeze` / `cbb unfreeze`, `cbb recovery`, certificate renewal, and admin computers. |
| Sync on the home network | Every sender to every receiver, every content class (section 6), ordering and conflict convergence, sync on and off (`cbb sync`), `cbb copy -secret` and its expiry, images, files, and formatted text. |
| Between subnets | The main LAN and a second subnet (`small`): mDNS does not cross by default, so `-peer` addresses, mDNS reflection, and tunnel paths are verified. |
| Sync away from home (**Everywhere**) | `cbb global hub`, `cbb global on` / `off`, `cbb global move`, multiple hubs, `cbb invite` / `cbb pair -invite`, a device on an external network, AmneziaWG obfuscation, VLESS over XHTTP, reconnect, and roaming. |
| Forwarder and blind relay | `cbb forward` and `cbb relay` (`-group` and `-open`): registration by short-lived server credentials, routing, per-group and per-address limits, group isolation, and zero disk or log retention of group data. |
| Remote paste and quick actions | `cbb paste -on`, `cbb paste-receive`, `cbb action`, `cbb keyboard`, and `cbb remote`. |
| Failure cases | Section 8. |
| Security | Section 9 (every security check blocks a release). |
| Release and debug error details | Every tested refusal shows a plain user message by default, shows underlying error details with `CBB_DEBUG=1` or `-debug`, and records full details in service logs in both modes ([Error messages and details](../reference/errors.md)). |

Out of scope for the automated bench harness: app store and TestFlight submission workflows,
performance benchmarking beyond the budgets in section 11, and hardware that is not present in the
bench inventory (see [Platform parity](../parity.md#on-real-devices) for real-hardware test status).

## 3. Devices under test

Devices are identified by role; the private inventory (section 13) maps each role to a real host.

| Role | What it needs | Network | On the bench |
|---|---|---|---|
| `controller` | Always-on headless Linux computer (for example, a Raspberry Pi 4 or mini PC) | Home network | Runs the bench harness (`tools/bench`) and containerized `fleet` / `time` suites; not a device under test itself, though it can host `nas`. |
| `nas` | Docker container running the `cbb` image from `packaging/docker/compose.home.yaml` (`linux/arm64` or `linux/amd64`) | Host's home network | Ordinary member in a locked-down container (P35); never the main device (*root*) or an admin by default (creating a group or offering an admin key requires `CBB_KEYS_IN_FILE=yes`); no desktop clipboard. |
| `small` | Small Linux board (such as an ARMv6 Raspberry Pi), Wi-Fi, headless | Second subnet (when available) | Runs `cbb` without `cbb-helper` (`get.sh --no-helper`); exercises cross-subnet sync; tests must never drop its management network. |
| `desktop` | Linux computer with a desktop session (GNOME or KDE, Wayland or X11) and `ufw` | Home LAN, or the router's isolated away network | Main device in layout A, hub, and live desktop clipboard (`wl-copy`/`wl-paste` on Wayland or `xclip` on X11/XWayland). |
| `mac` | Mac | Home LAN | macOS member, pasteboard agent, and Mac app; can host the Windows VM and simulators. |
| `win` | Windows PC or VM | Home LAN (bridged) | Windows service and `cbbw.exe` agent; reset with `uninstall.ps1 -Purge` and `install.ps1` before each build cycle. |
| `phone` | Android phone or emulator, or iPhone | Home LAN (or emulator NAT) | Phone app as main device in layout B and mobile sync client. |
| `router` | OpenWrt router reachable as root over SSH | Home router | `procd` service on the `lan` zone, dynamic `fw4` rules, and optional router hub. |
| `bsd` | FreeBSD host or VM with passwordless `sudo` | Home LAN (bridged) | `rc.d` service and `pf` or `ipfw` rules; headless member and optional hub. |
| `remote` | Linux server with a public address | Internet | Headless away member with public IPv4/IPv6 and no NAT; also exercises `cbb copy` and `cbb paste` without a desktop. |
| `relay` | Linux server with a public address | Internet | Runs `cbb forward` and `cbb relay -open`; serves as packet capture point; never joins a group. |

The Android emulator sits behind its own NAT: it reaches host loopback as `10.0.2.2` and LAN
addresses, sees no home mDNS, accepts no direct incoming connections without forwarding, and scans
QR codes only via injected images. In the `phone` suite, the harness builds and pushes
`tools/bench/udprelay` onto the emulator and tunnels datagrams over TCP through `adb forward` so
fleet members can reach UDP ports opened by the Android app (because the emulator console's UDP
redirect does not reach Wi-Fi-only Android images). Features that require physical phones (live
mDNS discovery, real battery optimization, hardware security chips, and accessibility overlays)
are tracked in [Platform parity](../parity.md#on-real-devices).

The bench tests two group layouts:

- **Layout A (computer main device)**: `desktop` creates the group with `cbb new` and acts as the
  main device (*root*); other devices join by code; `desktop` promotes another computer to admin
  (`cbb admin`).
- **Layout B (phone main device)**: A phone app creates the group and acts as the main device;
  computers and `small` join its pairing window; a computer becomes an admin.

## 4. Network environments

| ID | Environment | How the bench creates it |
|---|---|---|
| N1 | Single home LAN with mDNS | The home network in its normal state. |
| N2 | Two subnets (LAN + IoT) | Existing secondary subnet with OpenWrt firewall rules toggled between open, LAN-to-IoT only, and closed. |
| N3 | Away: one device on an external network | Isolated router VLAN/Wi-Fi with internet access and no route to LAN/IoT (`desktop` moves there and back), or `remote` on a public server with no NAT. |
| N4 | Away through a forwarder | Same as N3, with the hub reachable only through `cbb forward`. |
| N5 | Degraded network | `tc netem` on Linux devices (latency, packet loss, reordering, bandwidth cap), always paired with an automatic revert timer. |
| N6 | Network outage | Firewall rules dropping the member port or tunnel port temporarily, always paired with an automatic revert timer; never switches Wi-Fi on `small`. |
| N7 | IPv4-only or IPv6-only tunnel | Address family chosen per run in `cbb global hub` addresses. |

## 5. Test design

Every test case has an ID, an expected rule, preconditions, target devices and network environment,
and pass/fail observation criteria. Test cases are implemented in Go under `tools/bench/` and
indexed in Markdown tables:

- [Test bench catalogue](testbench-catalogue.md): one-line summary of every test case, how it runs,
  and what hardware or account it requires.
- [Test bench functions](testbench-functions.md): product functions mapped to the catalogue cases
  that verify them.
- [Test bench cases](testbench-cases.md): step-by-step procedures and common rules `R1`–`R7`.

`go run ./tools/bench coverage` reads `testbench-catalogue.md` and `testbench-functions.md` and
reports coverage counts and gaps.

Observation happens end to end at the user's clipboard wherever a desktop or mobile clipboard
exists:

| Device | Put text in | Read text out |
|---|---|---|
| `remote` (headless) | `cbb copy` | `cbb paste` |
| `small` | `cbb copy` | `cbb paste` (or `cbb watch -0`) |
| `nas` (container) | `docker exec -i cbb cbb copy` | `docker exec -i cbb cbb paste` |
| `desktop` (Wayland) | `wl-copy` | `wl-paste -n` |
| `desktop` (X11 / GNOME XWayland) | `xclip -selection clipboard -i` | `xclip -selection clipboard -o` |
| `mac` | `pbcopy` as the signed-in user | `pbpaste` |
| `win` | `Set-Clipboard` via scheduled task `cbbbench-copy` in the signed-in session (SSH cannot access the desktop clipboard) | `Get-Clipboard` via scheduled task `cbbbench-paste` |
| `phone` | App UI via UI Automator over `adb` | App UI and system clipboard |

Every test payload embeds a unique marker (run ID, case ID, and sender) so a stale clipboard value
cannot produce a false pass.

## 6. Test matrix: sync on the home network (N1)

Every ordered pair of active home devices exchanges each content class (with `remote` joining in
away cases):

| Class | Content |
|---|---|
| C1 | Short ASCII text. |
| C2 | Cyrillic, emoji with skin-tone modifiers, combining marks, right-to-left text (Hebrew, Arabic), and Japanese. |
| C3 | Multi-line text with CR LF and LF line endings, tabs, and trailing spaces (line endings arrive as sent; Windows converts CR LF to LF on read and LF to CR LF on write—see [Design](../design.md)). |
| C4 | Whitespace-only text (syncs) and empty input (refused without changing any clipboard). |
| C5 | Exact text size limit (1 MiB) arrives everywhere; one byte over is refused with a message naming the limit. |
| C6 | `cbb copy -secret`: arrives, clears after the secret lifetime (60 s by default), and never reaches disk. |
| C7 | Burst of 10 copies within 1 s from one sender: the last copy wins everywhere. |
| C8 | Two senders copy at the same moment: every device converges on the same text via hybrid logical clock (HLC) order. |

Expected result: text arrives byte for byte on every other member within 2 s (p95) on N1, and all
devices converge on the same text.

## 7. Group, pairing, and life-cycle cases

- **Pairing**: Join each device type in layout A and layout B.
- **Pairing window limits**: Reject wrong codes (closing the window after three wrong attempts),
  expired codes (after 5 minutes), and reused codes.
- **Removal**: Removing a device (`cbb remove`) stops delivery to it immediately, rejects its old
  keys on every member (including `small`), and prevents rejoining without a reset.
- **Renewal**: Member certificates near expiry renew automatically (verified with the time-scaled
  build in the `time` suite).
- **Admins**: Promoted admins (`cbb admin`) admit, rename, and remove ordinary devices even while
  the main device is offline, and cannot promote admins or remove the main device. Removing an
  admin preserves devices it admitted.
- **Moving the group**: Replacing a lost main device requires the group's recovery key
  (`cbb recovery`, D-117); the new main device assumes authority, remaining members keep syncing
  without re-pairing, and the removed old main device is refused if it returns.
- **Removing an ordinary member**: Removing any non-admin member leaves the group intact with no
  re-pairing required.
- **Upgrades**: Upgrading devices one by one follows the compatibility rules in
  [Versions and compatibility](../reference/compatibility.md) (`tools/e2e/upgrade.sh` tests
  upgrades in CI).
- **Uninstall**: Removing `cbb` leaves no service, agent, or firewall rules, preserves keys without
  `--purge` / `-Purge`, and removes all state with `--purge` / `-Purge`.

### Features and platforms

| ID | Case | Expected |
|---|---|---|
| P1 | Password managers: copy marked secret (macOS concealed type, Windows history/cloud exclusion, Linux password manager hint) | Skipped automatically or treated under C6 secret rules; never synced as plain text. |
| P2 | Rich text (HTML) from a browser or office app, images, a folder of files, and a copy exceeding `max-copy` | Plain text and HTML arrive as supported; images and files arrive intact with sanitized non-executable names and quarantine / Mark of the Web flags; copies over `max-copy` are refused once with a clear message. |
| P3 | Clipboard history (Windows Win+V, GNOME clipboard managers, KDE Klipper) and echo suppression | Received text is never echoed back; no ping-pong loop between members. |
| P4 | Mac as a listening member: `small` and the emulator reach the Mac alone; Mac and Linux connect with one link per pair, including with the macOS application firewall on | Sync works both ways; one connection per pair. |
| P5 | Service options on `small`: `-peer`, `-no-mdns`, `-no-listen`, and `cbb watch` | Each option matches [Command reference](../reference/cli.md). |
| P6 | Alternate member port (`--port`, `-Port`, `CBB_PORT`) on every installer, then back to 8764 | Members discover and sync on the new port; old firewall rules are cleaned up. |
| P7 | Homebrew on macOS: `install.sh --in-place` and `uninstall.sh` before `brew uninstall` | The agent runs Homebrew's binary and the service runs a root-owned copy; uninstall leaves no leftovers. |
| P8 | Text console: `install.sh --console` (`tmux`) on Linux | Copy and terminal-safe paste work inside `tmux`. |
| P9 | Windows service before sign-in and agent after sign-in; fast user switching on Windows and macOS | Only the signed-in user's clipboard receives copies; other user sessions receive nothing. |
| P10 | Phone group (layout B in the emulator): pairing computers and `small`, promoting the Mac to admin, and renewal | Succeeds within the emulator limits in section 3. |
| P11 | Sync away from home: `cbb invite` on the hub, `cbb pair -invite`, `cbb global on` / `off`, IPv6-only hub, and hub behind CGNAT | Joins and syncs both ways; `cbb global` explains any missing prerequisites. |
| P12 | Blind relay without a hub: `cbb relay -open` alongside the forwarder, `cbb global relay` on two members | Members connect through the relay with end-to-end TLS; the relay reads no copies. |
| P13 | `cbb status`, `cbb remove` by name and device ID, and `cbb version` on every platform | Output matches actual group and device state. |
| P14 | Downgrade to the previous release on each platform | Older version either starts cleanly on the state or refuses with a clear message; no keys are lost. |
| P15 | macOS Local Network permission (refused and granted), Gatekeeper on downloaded binaries, application firewall, and Universal Clipboard | `cbb status` explains each state; Universal Clipboard text syncs once without echo; report records paste timing and clipboard types. |
| P16 | Windows locked screen, sign-out and sign-in, SmartScreen on the installer, and `get.ps1` selecting the `arm64` build on ARM | Service continues syncing while locked; agent resumes after sign-in; right architecture installs. |
| P17 | Steam Deck sleep and wake, Game Mode, and lock screen | Reconnects within 30 s of wake; Game Mode and lock screen behavior are recorded. |
| P18 | Router mDNS reflector (`avahi-daemon` `enable-reflector`) off and on between LAN and IoT subnet | With reflector off, `small` syncs via `-peer`; with reflector on, `small` is discovered by mDNS. |
| P19 | Home IPv6: AAAA records, link-local and global addresses, and IPv6-only sync | Members discover and sync over IPv6. |
| P20 | Network blocking UDP (hotel or office Wi-Fi) for an away device | With VLESS enabled (default with a forwarder), sync succeeds over VLESS/XHTTP; with `-no-vless`, `cbb global` reports a clear error and fails closed. |
| P21 | Refused invitations: admin answers `no`, `-for 24h` expired by 1 s, hub offline when used | Refused with a clear message; nothing remains pending on the hub. |
| P22 | `cbb global off` then `on` on a client and hub; forwarder restart | Tunnel keys are cleared and regenerated; hubs re-register automatically. |
| P23 | macOS pasteboard privacy alerts enabled manually and with current macOS defaults | Report records whether reading pasteboard types prompts the user; text continues syncing. |
| P24 | GNOME on Wayland: copy and paste in a native Wayland app before any X11 app starts XWayland | Copy arrives within normal latency and pastes directly without refocusing. |
| P26 | macOS application firewall set to "Block all incoming connections" | Mac still discovers and dials peers; inbound reachability is recorded. |
| P27 | Phone app UI: all ten color palettes in dark, light, and system appearances; tiles, list, and orbit layouts; device details page; iPad and foldable screens | Every tile shows icon, OS, and live status; details match `cbb status`; a phone's MAC address shows "hidden by the system". |
| P28 | Group event notifications on iPhone and Android: add, remove, make admin, freeze/unfreeze, root change, hub offline while away, and individual notification toggles | One notification per enabled event, none when toggled off, never containing clipboard text. |
| P29 | Apple Watch companion app: device list, away switch, recent events, and out-of-reach state | Watch mirrors the iPhone, toggles away mode, and reports when the phone is unreachable. |
| P30 | Dynamic Island on iPhone: adding a device, away-from-home status, and sync feedback | Shows pairing timer, away shield, and brief sync status; never shows copied text. |
| P31 | Mac app: window and menu bar item, send/fetch, layouts, admin actions after authentication, cancelled prompt, stopped service, and error details toggle | Each action matches the corresponding `cbb` command; cancelled prompts change nothing; stopped service displays a plain message with optional underlying details. |
| P32 | Tray app on Linux (GNOME, KDE, SteamOS) and Windows: tray icon, window, send/fetch, layouts, pkexec/UAC prompts, stopped service, error details toggle, and Russian localization | Matches P31; tray icon appears on every desktop (GNOME requires the AppIndicator extension). |
| P33 | Wear OS app with Android phone: device list, away switch, events, out-of-reach state, and phone without Google Play services | Matches P29; phone app operates normally without Play services. |
| P34 | Sync on and off (`cbb sync`) on `desktop`, `win`, `small`, `nas`, and `mac`, across restarts, `cbb paste` while off, and admin `cbb sync -on` | With sync off, automatic sync stops both ways while `cbb paste` prints the group's latest text; state survives restart and appears in peers' status lists. |
| P35 | Container member (`nas`): join, lockdown settings (`docker inspect`), process kill (F1), restart, recreate from same volume, and opt-in admin/hub with `CBB_KEYS_IN_FILE=yes` | Runs unprivileged as configured in `packaging/docker/compose.home.yaml` with no `NET_ADMIN`; group and sync state survive restarts; as hub, `remote` syncs through its tunnel. |
| P36 | Multiple hubs: main device and admin computer both configured as hubs; main hub stops and returns | Standby admin hub takes over within ~1 minute and yields within 5 minutes when the higher-priority hub returns; away devices follow without new invitations or lost copies. |
| P37 | Moving the hub with `cbb global move`: refused for a container or MIPS build without tunnel support; succeeds to an admin computer | New hub serves with the existing forwarder; old hub becomes a client; away devices follow without returning home. |
| P38 | Open blind relay limits: per-address registration cap, busy group rate limit, and group cleanup | Excess registrations fail with a clear message; one busy group does not degrade others; empty groups are forgotten when the last device leaves. |
| P39 | Images and files away from home through a hub with sync off (`cbb sync off`), and `max-copy-away` enforcement | Copies flow both ways without modifying the hub's clipboard; items over `max-copy-away` stay on the home network with a log entry; uplink carries only tunnel traffic. |

Architectures without a dedicated host in the inventory (such as Intel Macs, x86-64 Windows PCs,
or ARMv7 boards) remain covered by CI or containers on matching hosts; see
[Platform parity](../parity.md#on-real-devices) for the real-hardware matrix.

## 8. Failure cases

| ID | Case | Expected |
|---|---|---|
| F1 | Kill the service (`SIGKILL`) on each device | Service manager restarts it automatically; member catches up on the latest copy. |
| F2 | Reboot `desktop`, `win`, and `mac`; power-cycle `small` (manual prompt) | Every device rejoins and syncs without user intervention beyond booting. |
| F3 | Sleep and wake the Mac; suspend and resume the Windows VM | Reconnects within 30 s of wake. |
| F4 | 30% packet loss, 300 ms delay, and reordering (N5) | Copies arrive without duplicates or crashes. |
| F5 | Member port blocked for 5 minutes (N6) | Copies made during the outage converge (latest wins) after the block clears. |
| F6 | Hub stops while devices are away | Away devices report the hub unreachable in `cbb global` and `cbb status` and send nothing elsewhere. |
| F7 | Forwarder stops or becomes unreachable | Away devices report a clear error and never fall back to a cleartext path; sync resumes automatically when the forwarder returns. |
| F8 | Clock skew of several hours on one device | Certificates remain valid within protocol bounds and HLC ordering holds. |
| F9 | State directory filesystem full on Linux | Clear error reported; no state corruption once free space returns. |
| F10 | Truncated or corrupted state file (`identity.json`) | Service refuses to start on the damaged file with a clear message naming the file and preserves the group once restored. |
| F11 | IP address change (DHCP renewal or network switch) | Local devices rediscover each other; away devices roam without new invitations. |
| F12 | Error formatting across F1–F11 | Plain user message by default; underlying error shown under it with `CBB_DEBUG=1` or `-debug`; full details always logged. |

## 9. Security tests

Every security test is a release blocker with no exceptions.

| ID | Test | Pass criteria |
|---|---|---|
| S1 | Capture all traffic on `relay` and the away device's uplink during a full away-sync run | Only WireGuard/AmneziaWG UDP or VLESS-over-XHTTP HTTPS traffic to the hub, forwarder, or relay; zero hits for run markers, group tags, device names, tunnel addresses, plaintext clipboard bytes, or group DNS/SNI leaks. |
| S2 | Capture all traffic on the home LAN | Member traffic on the member port is TLS 1.3 only; zero plaintext run markers. |
| S3 | Client isolation inside a hub tunnel | An away client cannot reach another client's tunnel address or any host/port other than the hub's member port. |
| S4 | Hub tunnel port surface | Port scan of the hub's tunnel address finds only the member port open. |
| S5 | Unknown WireGuard key | Hub and forwarder ignore the handshake with no response indicating whether the key is known. |
| S6 | Removed away device | Hub drops its tunnel key within one record round; device cannot sync or reuse its old invitation. |
| S7 | Invitation file handling | Owner-only permissions, single use, rejected after expiry or when the admin answers `no`, matching key fingerprints on both sides, deleted after use. |
| S8 | Forwarder and blind relay isolation and retention | Groups sharing a forwarder or blind relay cannot reach each other; servers reject invalid or revoked server credentials; neither server writes group data, addresses, or traffic logs to disk (only server keys and the forwarder's hashed credential-version state). |
| S9 | Fail closed | With the tunnel blocked, an away device sends no traffic to any address outside the home network and its configured hub/forwarder/relay. |
| S10 | Secrets off disk | `cbb copy -secret` never appears in state directories or `/tmp`, `MemorySwapMax` is `0` on Linux, and the secret clears after its lifetime (60 s by default). |
| S11 | Local socket access control | Control socket refuses users outside the `cbb` group (`_cbb` on macOS, access list on Windows); admin socket refuses non-administrators. |
| S12 | Installer firewall rules | Rules open only the member port (and mDNS UDP 5353) to local subnets, and the tunnel port only on a hub. |
| S13 | Two groups on one LAN | Zero copies, records, or device lists cross between groups; neither pairs into the other without a valid code. |
| S14 | Unauthenticated LAN peer | Dialing the member port without a valid group certificate, replaying a captured TLS session, or guessing pairing codes fails without revealing group details; three wrong codes close the window. |
| S15 | Log hygiene | Zero clipboard text, pairing codes, or key material in any log on any device in both error modes (`CBB_DEBUG=0` and `1`). |
| S16 | Files at rest | State directories contain only keys and state files with owner-only permissions and zero plaintext clipboard items. |
| S17 | Signed commands (`cbb sync -on`) | Only a valid admin's command, delivered once within its lifetime and clock window, is accepted; frozen admins, out-of-range clocks, and replays are refused with reasons. |

## 10. Long run

A 24-hour soak run verifies long-term stability:

- **Bench container soak (`E10-soak`)**: Four fleet containers run for `-soak-for 24h` with a
  checked copy every 30 s from a random member and a fault every hour (network cut, paused
  container, or killed service). Resident memory and open file descriptors are sampled every 5
  minutes and must stay flat, with zero missed copies and zero unexpected restarts.
- **Local loopback soak (`tools/soak/soak.sh`)**: Runs multi-day `calm` and `load` stands with
  hourly memory/descriptor floor bounds; see [Testing: soak](../testing.md#soak).

For release-gating plans around soak runs, see [Roadmap](../roadmap.md) (item 71).

## 11. Automation

The bench harness is a Go program in `tools/bench/`. It reads a private inventory file on the
controller (`~/.config/cbb-bench/inventory.toml` by default; never committed to the repository)
and drives devices over SSH (`BatchMode=yes` with key authentication) or Docker.

### Reaching the devices

- **Desktops**: The controller connects over SSH as the user signed in to each desktop session so
  the harness exercises the live clipboard (`wl-copy`/`wl-paste` on Wayland, `xclip` on X11 and
  GNOME XWayland, `pbcopy`/`pbpaste` on macOS).
- **Windows**: Because SSH sessions cannot reach the interactive Win32 clipboard,
  `tools/bench/setup-windows.ps1` enables the OpenSSH server and registers three interactive
  scheduled tasks: `cbbbench-copy`, `cbbbench-paste`, and `cbbbench-run`.
- **Headless devices and containers**: `remote`, `small`, `router`, `bsd`, `nas`, and `netns` use
  `cbb copy` and `cbb paste`.
- **Administrator commands**: Commands that modify group or service state run via `sudo -n` on
  Linux, FreeBSD, and macOS (with a root user on OpenWrt, an elevated SSH session on Windows, and
  the service user inside Docker containers). If `sudo -n` requires a password on a device, the
  harness skips those steps with a reason instead of aborting the run. On macOS,
  `tools/bench/setup-mac.sh` grants passwordless `sudo` only for `/usr/local/bin/cbb` and
  `/usr/local/libexec/cbbbench/cbbbench-root` (section 13); F1 also uses
  `/bin/launchctl kill KILL system/tools.cbb`.
- **Non-interactive installs without `cbb-helper`**: Because an interactive install without
  `cbb-helper` starts pairing automatically, automated scripts pass `--no-pair` (or `CBB_PAIR=no`).

### Starting a run

Run the harness from the repository root with `go run ./tools/bench` (or compile a binary with
`go build -o bench ./tools/bench`):

```sh
go run ./tools/bench [flags] <suite>
```

Available suites:

- `check`: verifies SSH reachability, clock skew (within 2 s), `cbb version`, and group status on
  every selected device.
- `reset`: with `-build DIR`, performs a full purge and reinstall (`R1`) of release archives from
  `DIR`; with `-quick`, keeps installs and wipes service state only.
- `smoke`, `full`, `faults`, `desktop`, `away`, `relay`: real-device suites (see [Suites](#suites)).
- `fleet`, `time`, `phone`: self-contained suites that run locally using Docker (and `adb` for
  `phone`) without requiring a device inventory.
- `all`: runs `check`, then each real-device suite separated by a quick reset, plus `fleet` (when
  `-cbb` is set) and `time` (when `-cbb-time` is set), a final quick reset, and the coverage table
  (`coverage.txt` beside the report).
- `coverage`: prints the catalogue coverage table from `testbench-catalogue.md` and
  `testbench-functions.md` without touching any devices.

Key flags (`tools/bench/main.go`):

| Flag | Default | Purpose |
|---|---|---|
| `-inventory FILE` | `~/.config/cbb-bench/inventory.toml` | Inventory file path. |
| `-report DIR` | *(none)* | Write `report.xml` (JUnit), `report.txt`, and `metrics.json` (plus `coverage.txt` for `all` and `flaky.txt` for `-repeat > 1`). |
| `-only a,b` | *(all)* | Comma-separated subset of inventory devices. |
| `-timeout DUR` | `20s` | Maximum wait for a copy to arrive. |
| `-build DIR` | *(none)* | Directory of release archives and `SHA256SUMS` for `reset`. |
| `-quick` | `false` | For `reset`: wipe state only without reinstalling. |
| `-stop-forwarder` | `false` | For `away`: include F7 (stops and restarts the configured forwarder). |
| `-disruptive` | `false` | For `desktop`: enable screen lock, sleep/wake, reboot, and macOS firewall toggling (Q3, I18, H7, H8). |
| `-cbb FILE` | *(none)* | Linux `cbb` binary for `fleet`, `phone`, and `all` (`cbb-helper`, `cbb-forward`, and `cbb-relay` in the same directory are mounted automatically when present). |
| `-cbb-time FILE` | *(none)* | Time-scaled Linux `cbb` binary (`--features benchtime`) for `time` and `all`. |
| `-fleet-size N` | `16` | Member count for `E3-many` in `fleet`. |
| `-scenario LIST` | *(all)* | Comma-separated scenario names to run in `fleet` or `time` (for example `T2-tmux,K6-clock`). |
| `-fuzz-for DUR` | `1m` | Per-target fuzz duration in `S20-fuzz` (use `1h` for a release run). |
| `-soak-for DUR` | `0` | Duration of `E10-soak` (`24h` for a full soak; `0` skips it). |
| `-android DIR` | `apps/android` | Android project directory for `phone`. |
| `-docs DIR` | `docs/maintainers` | Directory holding `testbench-catalogue.md` and `testbench-functions.md` for `coverage` and `all`. |
| `-repeat N` | `1` | Repeat `fleet`, `time`, or `phone` `N` times (`runK/...`) and record flaky cases in `flaky.txt`. |
| `-baseline FILE` | *(none)* | Earlier `metrics.json` to compare against; regressions fail as `baseline/NAME`. |
| `-baseline-slack F` | `0.25` | Allowed regression fraction beyond unit noise. |
| `-coverdir DIR` | *(none)* | Host directory mounted as `/cover` in `fleet` and `time` containers for coverage output. |

The `phone` suite runs automatically in CI's `Android app on an emulator` job. If the real-device
suites are connected to a self-hosted GitHub runner on `controller`, trigger them only via
`workflow_dispatch` or release tags—never on pull requests—with no repository secrets and no
passwordless `sudo` for the runner user.

Install release or CI build artifacts on test devices rather than compiling on the devices so the
bench tests the exact binaries users receive.

### Code coverage

Pass `-coverdir DIR` to `fleet` or `time` to collect execution coverage from every container (the
harness stops services with `SIGTERM` before removing containers so coverage profiles flush):

- **Rust `cbb`**: Build with `eval "$(cargo llvm-cov show-env --sh)"; cargo build --release --bin cbb`.
  After the run, copy `DIR/*.profraw` into `target/`, run
  `cargo llvm-cov report --release --json --summary-only --output-path fleet.json`, and inspect the
  result with `go run ./tools/coverage -llvm rust-service=fleet.json`.
- **Go `cbb-helper`**: Build with
  `CGO_ENABLED=0 go build -cover -coverpkg=./cmd/...,./internal/... -o cbb-helper ./cmd/cbb-helper`.
  After the run, convert with `go tool covdata textfmt -i DIR -o fleet.out` and inspect with
  `go run ./tools/coverage -go fleet.out` ([Testing: coverage](../testing.md#coverage)).

Real devices run uninstrumented release builds. Because instrumentation adds CPU and memory
overhead, ignore `E12` resource budgets during instrumented coverage runs.

### Budgets

Scenario `E12-budgets` (`tools/bench/fleetbudget.go`) holds `cbb` on small devices to fixed
resource budgets inside capped containers:

| Class | Container cap | Idle RSS | Idle CPU | Copy arrival (p95) | RSS after 200 copies | Peak memory |
|---|---|---|---|---|---|---|
| Raspberry Pi Zero (`pi-zero`) | 512 MiB, 0.25 CPU | 16 MiB | 2% of 1 core | 1 s | 20 MiB | 48 MiB |
| Router (`router`) | 128 MiB, 0.25 CPU | 16 MiB | 2% of 1 core | 1 s | 20 MiB | 48 MiB |

Budgets only tighten over time; any change that requires raising a limit must justify why in its
pull request. A real Raspberry Pi Zero and router confirm the same measurements before a release.

### Trends and flaky cases

Load scenarios record quantitative metrics (`E1` home/away p50 and p95 latency, `E2` post-load RSS,
RSS growth, and open file descriptors, `E4` elapsed time for three 50 MiB files, `E10` peak RSS,
and `E12` small-device measurements) to `metrics.json` inside `-report DIR`.

Compare a run against a prior release or weekly baseline with `-baseline FILE`. Any metric that
worsens by more than `-baseline-slack` (`0.25` by default) plus unit noise (`100 ms`, `4 MiB`,
`4 fds`, `2 s`, or `1%` CPU in `tools/bench/trend.go`) fails the run as `baseline/NAME`.

`tools/bench/weekly.sh DIR` automates weekly `fleet` and `time` runs from `cron` against the latest
`origin/main`, comparing each run against the previous week's `metrics.json` and keeping the last
12 runs.

`-repeat N` repeats `fleet`, `time`, or `phone` `N` times, prefixes case names with `runK/`, and
writes any case that both passed and failed to `flaky.txt`. Every failure still fails the run;
track confirmed intermittent failures in [Testing: unstable tests](../testing.md#unstable-tests)
until fixed.

### Reports

`-report DIR` writes:

- `report.xml`: JUnit XML for CI and test summaries.
- `report.txt`: plain-text log of every `PASS`, `FAIL`, and `SKIP` result with command output for
  failures (`CBB_DEBUG=1` also prints failure details live to stdout).
- `metrics.json`: measured performance and memory metrics when any were recorded.
- `coverage.txt`: catalogue coverage summary (written by `all`).
- `flaky.txt`: summary of cases that both passed and failed (written when `-repeat` is greater
  than 1).

Keep reports, device logs, and packet captures private on `controller`; never commit them to the
repository because they contain local network addresses.

### Suites

| Suite | What it runs | Typical time | When to run |
|---|---|---|---|
| `check` | SSH reachability, clock skew (≤ 2 s), `cbb version`, and group state on every selected device (`U1`). | < 1 min | Before any real-device run |
| `smoke` | Forms a layout A group and sends one text from every home member to every other (`G3`, `G23`, `U1`). | ~10 min | After changes to `cbb` |
| `full` | Sync matrix `C1`–`C5`, `C7`, `C8` across all home pairs; `F1` (`SIGKILL` recovery); `P35` (container lockdown, restart, recreate); `P34` (sync on/off); `C6`/`S10` (secret copy off disk and 60 s expiry); `S11` (local socket access); `S16` (state permissions); and `S15` (clean logs). | ~2 h | Before each release candidate |
| `away` | `P11` (invitation join through forwarder, bidirectional sync, `cbb global off`/`on`); `F6` (hub stopped); `P37` (hub move to an admin, refused for container/MIPS); `P36` (multiple-hub failover and failback); and `F7` (forwarder stopped, only with `-stop-forwarder`). | ~15 min | Before each release; after tunnel changes |
| `relay` | `P12`: members meet via the blind relay, sync both ways, and reject a wrong relay key. | ~5 min | Before each release; after relay changes |
| `faults` | `E7` (`tc netem` 30% loss, 300 ms delay, reordering on hub); `E8` (member port blocked 1 min); `E11`/`U6` (`SIGSTOP` hung service); `U5` (stopped service errors in both modes); and `U7` (truncated `identity.json`). Every fault installs a `systemd-run` revert timer on the target. | ~15 min | Before each release |
| `desktop` | Live desktop clipboard, agent, and paste cases on Linux, macOS, and Windows: echo and clipboard-history suppression (`Y24`, `Y25`), password manager marks (`Y31`), received secret marks and expiry (`Y32`), deliberate `cbb copy` with sync off and on (`M2`), Linux agent lifecycle (`H2`), `tmux` copy/paste (`H3`), large-copy fetch progress (`O13`), log rotation (`I21`), Linux primary selection (`Y26`), HTML and PNG transfers (`O1`, `O4`), Wayland/XWayland session check (`H1`), `uinput` keys helper (`T15`), console `tmux` (`H4`), TPM key listing (`K13`), Flatpak portals (`O12`), and Windows remote paste/type, secret hygiene, and paste log (`T3`, `T5`, `T11`, `T12`). With `-disruptive`, also tests quick actions (`Q3`), sleep/wake (`I18`), Windows lock (`H7`), and macOS firewall modes (`H8`). | ~15 min | Before each release; after agent or desktop changes |
| `fleet` | 76 containerized scenarios (`FleetSuite` in `tools/bench/fleetsuite.go`) covering pairing windows and limits, admin roles, freezing, removal, renaming, group isolation, partitions and multi-hop forwarding, sync/mute/TTL settings, discovery/mDNS/dial rules/heartbeats/handshakes/queues/junk, remote paste and TV remotes (via `tools/bench/forge`), quick actions, away-from-home hubs/forwarder/relay/AmneziaWG/VLESS/only-CBB egress checks, end-to-end sealed copies and commands, installer/update/feed/cache/ufw/systemd-hardening cases, packet-capture confidentiality checks (`S1`, `S2`, `S9`, `S18`), protocol fuzzing (`S20`, duration `-fuzz-for`), latency/throughput/large-transfer/many-member load tests (`E1`–`E6`, `E9`, `E12`), random walk (`G40`, repeatable with `CBB_BENCH_SEED`), and optional soak (`E10-soak`, `-soak-for`). Run individual scenarios with `-scenario NAME,...`. | ~60 min | Before each release; weekly via `weekly.sh` |
| `time` | Five time-scaled and clock-shifted scenarios (`TimeSuite` in `tools/bench/timesuite.go`) using `-cbb-time`: `K1-renewal` (certificate renewal `K1`/`K7`, credential periods `W39`, and expiry `K4`), `K6-clock` (1970, +1 h, +3 h, +2 d, +10 d, +3 y, clock mark `Y14`, command clock checks `T8`), `W12-hub-key` (hub WireGuard key handover), `K5-ca-end` (certificates capped at CA expiry), and `W46-xhttp` (VLESS over XHTTP behind a web server and mirror updates `W47`). | ~15 min | Before each release; weekly via `weekly.sh` |
| `phone` | Android instrumented tests (`apps/android/app/src/androidTest`) on an `adb` emulator paired with fleet containers over `10.0.2.2`, `adb forward`, and `tools/bench/udprelay`: pairing by 6-digit code, send/fetch, background receive, send-mode isolation, remote paste, quick-action response, rename/remove notifications, tile/widget send, file sharing, sensitive secrets, and away-from-home hub tunnel (`A1`, `A6`, `A12`, `M7`, `O11`, `Q8`, `T16`, `W5`, `W42`, `Y35`). Runs in CI's `Android app on an emulator` job. | ~15 min | Every pull request touching Android or `cbb` |

In addition to `tools/bench`, CI UI and platform jobs count toward catalogue coverage under the
`ci` suite in `tools/bench/catalogue.go`: headless browser tests for the tray app (`apps/desktop`),
XCUITest for the iPhone and Mac apps (`apps/ios/CBBUITests`, `apps/macos/CBBMacUITests`),
Robolectric tests for Android (`ScreensTest`), OpenWrt/FreeBSD/F-Droid/upgrade jobs, and
`release-check`.

Security cases run inside `full` (real-device `S10`, `S11`, `S15`, `S16`) and `fleet` (`S1`–`S9`,
`S12`–`S14`, `S17`, `S18`, `S20`, `S21`, `S22`, `S24`–`S26`), plus manual real-network captures
where noted in [Test bench cases](testbench-cases.md). Soak runs through `fleet -soak-for 24h
-scenario E10-soak` or `tools/soak/soak.sh`.

## 12. Entry and exit criteria

**Entry criteria** (required before starting a real-device run):

- Every selected device in the inventory is reachable over SSH.
- Binaries under test come from a green CI run (`ci-ok`).
- `relay` runs the forwarder and blind relay from the same commit.
- Every device clock is within 2 s of `controller` (`check` enforces `maxSkew = 2s`).

**Exit criteria** (required before publishing a release):

- All applicable automated suites (`smoke`, `full`, `faults`, `desktop`, `away`, `relay`, `fleet`,
  `time`, and `phone`) pass on the release candidate.
- Every security test passes (section 9 and catalogue `S1`–`S26`); security failures have no
  exceptions.
- Zero open severity-1 or severity-2 defects; any open severity-3 defect is documented in
  `CHANGELOG.md`.
- Real-hardware status rows in [Platform parity](../parity.md#on-real-devices) and `README.md` are
  updated to reflect verified devices.

Defect severity levels:

- **Severity 1**: Clipboard data leaves a device unprotected, or an unauthorized device receives
  group data.
- **Severity 2**: Sync stops working or data is lost.
- **Severity 3**: Wrong error message, degraded performance, or cosmetic issue.

## 13. Inventory

`controller` stores the bench inventory at `~/.config/cbb-bench/inventory.toml` (outside the
repository, because it contains local hostnames and keys). See
`tools/bench/inventory.example.toml` for a complete annotated template.

```toml
controller = "controller"

[device.desktop]
os = "linux"             # linux, darwin, windows, docker, netns, openwrt, freebsd
ssh = "user@desktop.lan" # user signed in on the desktop
clipboard = "x11"        # wayland (KDE/wlroots), x11 (X11 or GNOME XWayland), none, macos, windows
roles = ["member", "hub", "away"]
firewall = "yes"         # linux, windows, freebsd: "yes" opens the member port on reset; "no" leaves it alone

[device.win]
os = "windows"
ssh = "user@win.lan"
clipboard = "windows"
roles = ["member"]
firewall = "yes"

[device.router]
os = "openwrt"           # ssh as root (OpenWrt has no sudo)
ssh = "root@router.lan"
clipboard = "none"
roles = ["member", "hub"]

[device.nas]
os = "docker"            # container on the host reached via ssh
ssh = "user@controller.lan" # user in the docker group
container = "cbb"        # default name from compose.home.yaml
roles = ["member"]       # never hub
setup = "~/cbb/tools/bench/setup-docker.sh"

[device.remote]
os = "linux"
ssh = "user@remote.example.net"
clipboard = "none"
roles = ["away"]         # away only: joins by invitation in the away suite
firewall = "no"

[router]
ssh = "root@router.lan"
kind = "openwrt"
away_network = "bench_away"

[forwarder]
address = "relay.example.net:8764"
key = "<key>"            # cbb forward -show-key on the server
ssh = "user@relay.example.net" # for F7 (-stop-forwarder)
service = "cbb-forward"

[relay]
address = "relay.example.net:8765"
key = "<key>"            # cbb relay -show-key on the server
```

Inventory field rules (`tools/bench/inventory.go`):

- `firewall` (`"yes"` or `"no"`): required for full `reset` on `linux`, `windows`, and `freebsd`.
  `"yes"` passes `--express` (`-Express` on Windows) so the installer opens the member port; `"no"`
  passes `--no-firewall` (`-NoFirewall`) to leave server firewalls untouched. OpenWrt manages rules
  dynamically through `procd`, so `firewall` does not apply there; staged builds on OpenWrt go to
  `/tmp/cbbbench` in RAM rather than flash.
- `setup`: path to `tools/bench/setup-docker.sh` (for `os = "docker"`) or
  `tools/bench/setup-netns.sh` (for `os = "netns"`) on the host, required for full `reset`.
- `address` (`host:port`): explicit pairing address used when mDNS cannot reach the device.
- `peer = true` (`os = "linux"` only): marks a device on another subnet; the bench joins it at the
  printed pairing address and installs a temporary systemd drop-in (`/etc/systemd/system/cbb.service.d/cbbbench.conf`)
  passing `-peer` to the hub for the duration of the run.
- `os = "docker"`: runs `docker exec -i CONTAINER cbb` with `clipboard = "none"` and never takes
  the `hub` role. `setup-docker.sh setup` installs Docker, adds the SSH user to the `docker` group,
  and installs `/usr/local/sbin/cbbbench-kill-container` with a passwordless sudoers rule for F1.
  `setup-docker.sh up CBB` builds and starts a clean container from binary `CBB`; `down` removes
  the container and its volume.
- `os = "netns"`: runs a second Linux member inside a dedicated network namespace whose sole
  interface routes through `tun2socks` to a local SOCKS5 proxy (TCP-only proxies test VLESS;
  UDP-capable proxies also test WireGuard; DNS resolves over TCP via `use-vc`). Device names must
  be 1–10 lowercase letters and digits (`^[a-z0-9]{1,10}$`), keys stay in files (never `hub`), and
  `clipboard` must be `"none"`. `setup-netns.sh` installs files in `/opt/cbbbench-netns/NAME` with
  units `cbbbench-NAME-net` and `cbbbench-NAME`, and the bench invokes
  `sudo -n /opt/cbbbench-netns/NAME/cbb`.

### Setting up and tearing down the bench

Every bench component outside `cbb`'s own installers has paired setup and teardown scripts. Run
each from a checkout of the repository:

| Component | Host | Setup | Teardown |
|---|---|---|---|
| Windows SSH and clipboard tasks | Windows device (elevated PowerShell, signed in as bench user) | `powershell -ExecutionPolicy Bypass -File tools/bench/setup-windows.ps1` | `powershell -ExecutionPolicy Bypass -File tools/bench/setup-windows.ps1 -Remove` |
| Namespace member (`os = "netns"`) | Linux host | `sudo sh tools/bench/setup-netns.sh setup NAME SOCKS TUN2SOCKS` | `sudo sh tools/bench/setup-netns.sh teardown NAME` |
| Container host (`os = "docker"`) | `controller` or Docker host | `sh tools/bench/setup-docker.sh setup` | `sh tools/bench/setup-docker.sh teardown [--group]` |
| Controller SSH to localhost | `controller` | `sh tools/bench/setup-controller.sh setup [KEY]` | `sh tools/bench/setup-controller.sh teardown` |
| Bench build-signing key (for macOS) | `controller` | `ssh-keygen -t ed25519 -N '' -f ~/.ssh/cbb_bench_sign -C cbbbench` | Delete `~/.ssh/cbb_bench_sign` and `~/.ssh/cbb_bench_sign.pub` |
| Mac root helper (`cbbbench-root`) | Mac | `sudo sh tools/bench/setup-mac.sh setup -signer cbb_bench_sign.pub` | `sudo sh tools/bench/setup-mac.sh teardown` |
| Open blind relay (`relay` suite) | Server alongside forwarder | `sudo sh tools/bench/setup-relay.sh setup [PORT]` (open `PORT` TCP/UDP in provider firewall too) | `sudo sh tools/bench/setup-relay.sh teardown [--purge]` |

On macOS, `setup-mac.sh` installs `/usr/local/libexec/cbbbench/cbbbench-root` and a sudoers rule
(`/etc/sudoers.d/cbbbench-root`) allowing the bench user passwordless `sudo` for `cbbbench-root`
and `/usr/local/bin/cbb`. `cbbbench-root` performs only fixed operations: `purge`, `install`,
`grep` (search state directory and `/private/tmp` for a run ID), `perms` (check state permissions),
`stranger` (`cbb status` as `nobody`), `logs`, `fill-log`, and `log-sizes`. It installs an archive
only if its SHA-256 appears in a `SHA256SUMS` file signed by the bench signing key
(`ssh-keygen -Y sign -n cbbbench`, verified against `/usr/local/libexec/cbbbench/allowed_signers`)
or trusted locally via `setup-mac.sh trust SHA256SUMS`. Remove the helper, sudoers rules, and
signing key at the end of a test cycle.

Each test device needs the controller's SSH public key installed for its desktop user. Devices in
the inventory are dedicated test devices: the bench installs, purges, and resets Connect Beyond
Borders on them automatically.

### A test cycle

1. Place the release archives under test (`cbb-<os>-<arch>.tar.gz` and `cbb-windows-<arch>.zip`)
   and `SHA256SUMS` in a directory `DIR` on `controller`. If a Mac is in the inventory, sign
   `SHA256SUMS`:

   ```sh
   ssh-keygen -Y sign -f ~/.ssh/cbb_bench_sign -n cbbbench DIR/SHA256SUMS
   ```

2. Purge and install the build on all devices at once (each device caches the newest three builds
   locally; on Linux desktops the bench verifies or starts the desktop agent in the signed-in
   session):

   ```sh
   go run ./tools/bench -build DIR reset
   ```

3. Verify connectivity and clocks:

   ```sh
   go run ./tools/bench check
   ```

4. Run the suites, using `go run ./tools/bench -quick reset` between real-device suites of the same
   build (or run `all`, which performs quick resets automatically).
5. At the end of the cycle, run the teardown commands from
   [Setting up and tearing down the bench](#setting-up-and-tearing-down-the-bench).
