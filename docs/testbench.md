<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The hardware test bench

The plan for testing Clipboard Bridge on real devices before each release, starting with 0.4,
and how the bench that runs it is built. The bench lives in `tools/bench` (being built, see
"Order of work" at the end); this document is its specification. CI and its jobs are in
[maintaining.md](maintaining.md#ci).

## 1. Goal

Before 0.4 is released, an automated bench of the maintainer's real devices runs every case that
matters to users and reports pass or fail with logs, with no person copying text by hand.
The same bench then runs before every later release.

CI already covers a lot in containers and on hosted runners (unit tests with `-race`, the
Docker e2e of three members, Wayland and X11 under headless compositors, the Windows
installer on windows-latest, the cross tests between Go, Swift and Kotlin, the lite member among
Go members). The bench covers what CI cannot:

- real hardware and real operating systems: an ARMv6 board for the lite member, a Linux
  desktop, a Mac, Windows, an Android phone;
- the real desktop clipboards in a signed-in session (GNOME or another Linux desktop, the
  macOS pasteboard, the Win32 clipboard), not only the service's own store;
- a real home network: Wi-Fi, mDNS on the router, two subnets, firewalls the installers
  configure;
- the real internet path: the hub's WireGuard tunnel from outside the home, the relay
  server (forwarder), NAT, IPv4 and IPv6;
- long runs, reboots, sleep, network loss and upgrades from the previous release.

## 2. Scope

In scope for 0.4:

| Area | What is tested |
|---|---|
| Install, update, remove | `get.sh`/`install.sh`/`uninstall.sh` on Linux and macOS (and Homebrew on macOS), `get.ps1`/`install.ps1`/`uninstall.ps1` on Windows, `get.sh --lite` for the lite member, which moves an old `cbb-lite` install to `cbb`; update from 0.3.x; firewall rules added and removed; `--purge` |
| Group and pairing | `cbb pair` / `cbb pair -code` (with and without an address), `cbb join -code` on the lite member, joining by QR from the Android app, wrong code, expired code, revoke, renewal, admin computers |
| Sync on the home network | every sender to every receiver, every content class (section 6), ordering and conflicts, `copy -secret` and its 60 s expiry, the holder of `clipboardbridge.local` and its handover |
| Between subnets | the main LAN and a second subnet (the lite member's): mDNS does not cross, so `-peer` / addresses and, later, the tunnel |
| Sync away from home | `cbb global hub`, `cbb global on/off`, `cbb invite` / `cbb pair -invite`, a device on another network (mobile data), reconnect, roaming |
| The relay server (forwarder) | `cbb forward` on the relay, the hub registered with `cbb global hub -forwarder ADDR:PORT -forwarder-key KEY`: registration by certificate chain, routing by `mac1`, per-group limits, the computed hourly fallback port (once built), isolation of groups, nothing written to disk or logged |
| Failure cases | section 8 |
| Security | section 9 (top priority for everything off the home network) |
| Debug/release error details | each tested error shows the user message; with `CBB_DEBUG=1` the underlying error too; the log always has it |

Out of scope for 0.4: the iPhone app and the shortcut (paused until the Apple developer
account; the Swift kit stays covered by CI), the ESP32 firmware, the ZX Spectrum Next and
the Arduino, app store and TestFlight builds, performance beyond the limits in section 10.

## 3. Devices under test

Devices are named by their role; the inventory (section 13) maps each role to a real device.

| Role | What it needs | Network | On the bench |
|---|---|---|---|
| `controller` | an always-on Linux computer (an ARM board will do), headless | home network | **the bench controller** (section 11); not a device under test, but it may host `nas` |
| `nas` | the Docker image on a host (`linux/arm64` or `amd64`), from `packaging/docker/compose.home.yaml` | home network (the host's) | an ordinary member in a container, as on a NAS or a home server (P35); never the root or an admin, since the CA keys stay off a container; no desktop clipboard |
| `lite` | an ARMv6 or other small Linux board, Wi-Fi, no keyboard | a second subnet, if there is one | the lite member; the cross-subnet case; must never lose its network from a test |
| `desktop` | a Linux computer with a desktop (GNOME, Wayland), ufw | LAN, or the router's away network | the Linux member: the root in layout A, the hub, the real desktop clipboard (through XWayland, as `cbb agent` uses it on GNOME); also the away device (plugged in, sleep off) |
| `mac` | a Mac | LAN | macOS member and agent; may host the Windows VM |
| `win` | Windows, a VM will do | LAN, bridged | Windows service and `cbbw.exe` agent; reset by `uninstall.ps1 -Purge` and `install.ps1` before each run |
| `phone` | an Android phone, or the emulator | its own NAT for the emulator | Android app: root of a phone group, sync; limited in the emulator, see below |
| `router` | an OpenWrt 25.12 router, reached as root over SSH | the home network's router | the service in procd on the lan zone (P-series as an ordinary member), the hub at the router (its WireGuard port from wan, opened through the init script); the router behind another NAT reaches the away devices through the forwarder or a port forward |
| `bsd` | FreeBSD 15, a VM will do, with `sudo` | LAN, bridged | the rc.d service and pf or ipfw rules; a headless member, may be the hub |
| `remote` | a Linux server with a public address | internet | a headless Linux member away from home: no NAT, public IPv4/IPv6; also covers `cbb copy`/`paste` without a desktop |
| `relay` | a Linux server with a public address | internet | the forwarder (`cbb forward`) and the open relay (`cbb relay -open`); packet capture point; never a group member |

The emulator sits behind its own NAT: it reaches LAN addresses but sees no mDNS from the
home network and takes no incoming connections without port forwarding, and its camera
scans a QR code only from an injected image. The bench tests what works there (the app,
pairing with an injected QR image, sync with members it dials by address); what needs a
real phone (mDNS discovery, the foreground service on a real battery saver, the
accessibility overlay) stays in the README's status table as "not yet" until there is one.

Two group layouts are tested, because both exist for users:

- **A. A computer's group**: `desktop` runs `cbb new` and is the root; the others join by
  code; `desktop` makes `win` an admin (`cbb admin win`).
- **B. A phone's group** (needs `phone`): the Android app is the root; computers and
  `lite` join by its QR code; `mac` becomes an admin.

## 4. Network environments

| ID | Environment | How the bench makes it |
|---|---|---|
| N1 | One LAN, mDNS works | the home network as it is |
| N2 | Two subnets (LAN + IoT) | the existing IoT subnet; the bench switches the OpenWrt firewall rules between them (open, LAN to IoT only, closed) |
| N3 | Away: one device on a different network | a separate network on the OpenWrt router (its own VLAN, Wi-Fi name and subnet, internet only, no route to the LAN or IoT); the bench moves `desktop` there and back. The second VPS (`remote`) is an away computer with a public address and no NAT |
| N4 | Away through the relay | as N3, with the hub reachable only through the forwarder |
| N5 | Bad network | `tc netem` on the Linux devices: latency, loss, reordering, bandwidth limit; always with an automatic revert timer |
| N6 | Network gone | firewall rules that drop the member port or the tunnel port for a time, with an automatic revert; no Wi-Fi switching on `lite` |
| N7 | IPv6 only / IPv4 only for the tunnel | address family chosen per run on the hub's `cbb global hub` addresses |

## 5. Test design

Every test case has an ID, a short statement of what must hold, its preconditions, the
devices and environment it runs on, and how the result is observed. Test cases are kept as
data (one YAML file per area) so the matrix is generated, not typed: `sync` cases are
expanded over sender x receiver x content class x environment.

The observation is always end to end, at the user's clipboard where one exists:

| Device | Put text in | Read text out |
|---|---|---|
| `remote` (headless) | `cbb copy` | `cbb paste` |
| `lite` | `cbb copy` | `cbb watch -0` |
| `desktop` | `xclip` on the GNOME session's XWayland | `xclip -o` on the same display |
| `mac` | `pbcopy` as the signed-in user | `pbpaste` |
| `win` | `Set-Clipboard` inside the signed-in session (a small bench helper started at sign-in; an SSH session cannot reach the desktop clipboard) | `Get-Clipboard` through the same helper |
| `phone` | the app's UI through UI Automator over `adb` (bench only; users never need `adb`) | the app's UI / the system clipboard as the app sees it |

Every case of release 0.6 is in [testbench-catalogue.md](testbench-catalogue.md), one line
each, with how it runs and what it still needs; every function of the product, with the
cases that check it, is in [testbench-functions.md](testbench-functions.md), and
`testbench coverage` counts from both. The cases that have a step-by-step form, with their
preconditions and how to tell pass from fail, are in [testbench-cases.md](testbench-cases.md).

Each run writes a unique marker into every text (run ID, case ID, sender, time) so a stale
clipboard can never pass a test.

## 6. Test matrix: sync on the home network (N1)

Senders and receivers on the home network: `lite`, `desktop`, `mac`, `win`, `phone`; `remote` joins them in the away cases. Every ordered pair
that the protocol allows (20 pairs) runs the content classes:

| Class | Content |
|---|---|
| C1 | short ASCII |
| C2 | Cyrillic, emoji, combining marks, right-to-left text |
| C3 | multi-line with CRLF and LF, tabs, trailing spaces (line endings must arrive as sent; a Windows clipboard holds CR LF and a Windows member sends LF, see design.md, Windows) |
| C4 | empty text and whitespace only |
| C5 | the size limit exactly, and one byte over it (must be refused with a clear message) |
| C6 | `copy -secret`: arrives, is gone 60 s after the copy, never written to disk |
| C7 | ten copies in one second from one sender: the last one wins everywhere |
| C8 | two senders at the same moment: every device ends on the same text (HLC order) |

Expected: the text arrives byte for byte at every other member within 2 s on N1 (p95) and
the same text is on every device at the end.

## 7. Group, pairing and life-cycle cases

- Pair each kind of device into layout A; then layout B with the phone.
- Join with a wrong code (refused, the attempt counter works), with an expired code, twice
  with the same code.
- Revoke a device: it stops receiving within one sync round, cannot rejoin with its old
  keys, and its certificate is refused by every member including `lite`.
- Renewal: certificates near expiry are renewed (the bench sets the clock forward on a
  disposable device, or uses a short test lifetime build).
- Admin: `mac` made an admin in layout B pairs and revokes; in layout A `win`, made an admin
  by `desktop`, pairs a device, serves the shortcut while `desktop` is off, and when `desktop` removes
  it, `desktop` replaces the iPhone CA and the shortcut iPhones pair again.
- Takeover in layout A: with `desktop` off, `win` runs `cbb takeover desktop`; `win` is the root,
  every other device stays and syncs, the shortcut iPhones pair again, `win` makes another
  admin, and `desktop` is refused when it comes back.
- Removing a member that is no admin in layout A (a Linux one, a Windows one, the Mac): the
  group stays, nobody pairs again.
- The holder of `clipboardbridge.local` goes away; another member takes it over.
- Upgrade: every device on 0.3.x, then updated one by one to the 0.4 candidate; mixed
  versions keep syncing during the upgrade; state and keys survive. Then `cbb upgrade` on
  `desktop` with `win` off: `desktop` is the root, the others delete the old keys, `cbb status`
  marks `win` until it is back, `cbb revoke win` is refused until then, and nobody pairs
  again except the shortcut iPhones.
- Uninstall: no service, no firewall rule, no leftover files (except keys without
  `--purge`).

### Features and platforms

Every other way Clipboard Bridge works, so no path ships untested:

| ID | Case | Expected |
|---|---|---|
| P1 | Password managers: a copy marked secret by the app (macOS concealed type, Windows "exclude from history and cloud", the Wayland password hint) | travels as a secret (C6 rules) or not at all, as designed; never as plain text |
| P2 | Rich text from a browser and an office app; images, a folder of files, a copy over a member's limit | the plain text arrives; images and files arrive whole with their names, marked as downloads on Mac and Windows; a copy over the limit is refused once with a clear message |
| P3 | Clipboard history (Windows Win+V, the GNOME clipboard) and copy echo | a received text is not sent back; no ping-pong between two members |
| P4 | The Mac as a full member: the lite member and the emulator reach the Mac with no other computer on; the Mac and a Linux member connect whichever has the lower device ID, also with the Mac's application firewall on | sync works; one connection between each pair |
| P5 | The lite member's options: `-peer`, `-no-mdns`, `-no-listen`, `watch` | each works as `docs/reference/cli.md` says |
| P6 | Another port (`--port`, `CBB_PORT`) on every installer, and back to 8764 | members find each other; the old firewall rule is gone |
| P7 | Homebrew on the Mac, `install.sh --in-place`, `uninstall.sh` before `brew uninstall` | the agent runs Homebrew's binary, the service a root-owned copy of it; nothing is left |
| P8 | Text console: `install.sh --console` (tmux) on a Linux member | copy and paste work in tmux |
| P9 | The Windows service before sign-in, the agent after it; fast user switching on Windows and the Mac | the clipboard of the signed-in user only; no text reaches another user's session |
| P10 | A phone group (layout B in the emulator): QR join of a computer and of `lite`, "Make it an admin" for the Mac, renewal | as on a real phone, within the emulator's limits (section 3) |
| P11 | Sync away from home: `cbb invite` from the hub, `cbb pair -invite`, `cbb global on/off`, a hub with only IPv6 or behind CGNAT | joins and syncs; `cbb global` explains what is missing |
| P12 | A blind relay for a group without a hub: `cbb relay -open` beside the forwarder, `cbb global relay` on two members | members meet through it; it sees only TLS between members |
| P13 | `cbb status` (with the devices list), `cbb revoke` by name and by ID, `cbb version` on every platform | the output matches the state |
| P14 | Downgrade from the 0.4 candidate to 0.3.x on each platform | the older version starts on the newer state or refuses with a clear message; no keys are lost |
| P15 | macOS: the Local Network permission refused and granted, Gatekeeper on the downloaded binary, the application firewall, Universal Clipboard from an iPhone or iPad signed in to the same Apple account | each state is explained by `cbb status`; Universal Clipboard text syncs once, without an echo; the report records whether the item arrived before a paste on the Mac and which types it carried |
| P16 | Windows: locked screen, sign-out and sign-in, SmartScreen on the installer, `get.ps1` installing the arm64 build on ARM | the service keeps syncing; the agent comes back after sign-in; the right architecture |
| P17 | Steam Deck: sleep and wake, Game Mode, the lock screen | reconnects within 30 s of wake; Game Mode and the lock screen are recorded as they behave |
| P18 | mDNS on the router: the avahi reflector on and off between the home network and the IoT subnet | with it off the lite member is reached by address, with it on by mDNS; both work |
| P19 | IPv6 on the home network: AAAA records, link-local and global addresses, an IPv6-only member | members find and reach each other over IPv6 |
| P20 | A network that blocks UDP (a hotel or an office) for an away device | as designed for the transports that exist (WireGuard over UDP fails with a clear message; the TCP transport when it exists) |
| P21 | Invitations: the admin answers `no`; `-for 24h` and one second past it; the hub off when the invitation is used | refused with a clear message each time; nothing is left on the hub |
| P22 | `cbb global off` then `on` on a client and on the hub; a forwarder restart | keys are forgotten and made again; hubs register again by themselves |
| P23 | macOS pasteboard privacy: the alert for pasting from other apps turned on by hand, then on macOS 27.2 with its defaults | the report records whether the agent's reading of the types asks the user; text keeps syncing |
| P24 | GNOME on the Steam Deck: a copy in a native Wayland app (GNOME Text Editor); a received text pasted into it without clicking any window; the same right after sign-in, before any X11 app has started XWayland | the copy arrives within the usual latency; the paste gives the received text |
| P25 | The Mac holds `clipboardbridge.local`: the other full members off or set to `cbb holder never` | `cbb status` on the Mac shows it holds the name; `avahi-resolve` on `desktop` and `Resolve-DnsName` on `win` resolve it to the Mac |
| P26 | The Mac's application firewall set to "Block all incoming connections" | the Mac still finds the members and reaches them; whether they find and reach it is recorded |
| P27 | The phone apps' Glass design: each of the ten colours in dark, light and system; tiles, list and orbits; a device's page; an iPad and a foldable's inner screen | every device shows its icon, system and live dot; the details match `cbb status`; a phone's MAC address reads "hidden by the system" |
| P28 | The group's events on both phones: a device added, removed, made an admin, frozen and unfrozen, a takeover, the hub off while away; each switch off in turn | one notification per event, in its words, none for a switch that is off; nothing shows the clipboard |
| P29 | The Apple Watch with its iPhone: the devices, the away switch, the latest events; the phone out of reach | the watch follows the phone; the switch turns the phone's away mode; out of reach it says so |
| P30 | The Dynamic Island: adding a device, the phone away from home, a sync | the timer while adding, the shield while away, the result for a moment; never the copied text |
| P31 | The Mac app: the window and the menu bar item, send and fetch, each layout, rename, remove, freeze, unfreeze, make an admin and sync away from home after the password, the prompt cancelled, the service stopped, error details on and off | each action does what the same `cbb` command does; a cancelled prompt changes nothing and says nothing; a stopped service is explained, with the error underneath when details are on |
| P32 | The tray app on the Linux members (GNOME, KDE, the Steam Deck) and on Windows: the tray item and the window, send and fetch, each layout, the group's changes after pkexec or UAC, the prompt dismissed, the service stopped, error details on and off, Russian | as P31; the tray item shows on each desktop (GNOME needs the AppIndicator extension) |
| P33 | The Wear OS app with its Android phone: the devices, the away switch, the latest events; the phone out of reach; a phone without Google Play services | as P29; without Play services the phone app works as before |
| P34 | Sync modes: own, receive, send and shared on `desktop` with `win`, then on the lite member, the container and the Mac; a restart; `cbb paste` in own; an admin's `cbb mode -on` | each mode lets through only what design.md says; the mode survives the restart and the others list it; in own `cbb paste` prints the group's text |
| P35 | A member in a container (`nas`): it joins the hub's group; its settings; its process killed, a restart and a new container from the same volume; then, only by an explicit choice for the run, an admin with its keys in a file and the hub for `remote` | it runs unprivileged as compose.home.yaml sets it; the group, the mode and sync survive each restart; as the hub `remote` syncs through its tunnel with no `NET_ADMIN` |
| P36 | Several hubs: the root and an admin computer each with a hub set up, an away device; the root's hub stopped and started again | the admin serves while the root is gone and gives way when it is back; the away device follows both ways with no invitation and loses no copy |
| P37 | Moving the hub with `cbb global move`: to the lite member and to the container (refused), to an admin computer | the new hub serves with the old one's forwarder; the old one becomes its client; the away device follows without coming home |
| P38 | The open relay's limits: registrations from one address, a busy group, groups leaving | over a limit refused with a clear message; one busy group does not slow the others; a group is forgotten when its last device leaves |
| P39 | Images and files away from home through a hub in mode `own`, and the hub's limit away from home | copies go both ways through the hub; one over the hub's limit stays at home with a log line; only WireGuard on the uplink |

Known limits of this bench: it has no Intel Mac (`darwin/amd64`), no x86-64 Windows
(`windows/amd64`) and no ARMv7 Linux; those builds are covered only by CI. Builds without a device of their own run on the bench only where a host has one (the ARM64
Linux build in the container, `nas`, on an ARM controller). It has no real Android phone and no iPhone app
(section 3).


## 8. Failure cases

| ID | Case | Expected |
|---|---|---|
| F1 | Kill the service (`SIGKILL`) on each device | restarts by its service manager; catches up on the latest text |
| F2 | Reboot `desktop`, `win`, `mac`; power cycle `lite` (a manual step: the bench pauses and asks the maintainer to pull the plug) | comes back, rejoins without a person |
| F3 | Mac sleeps and wakes; the VM pauses and resumes | reconnects within 30 s of wake |
| F4 | 30% loss, 300 ms latency, reordering (N5) | texts arrive, no duplicates, no crash |
| F5 | Member port blocked for 5 minutes (N6) | texts copied meanwhile arrive after the block ends (latest wins) |
| F6 | Hub down while devices are away | away devices report it in `cbb global` and `cbb status`; nothing is sent another way |
| F7 | Relay down or unreachable | fallback port tried as designed; then a clear error; never a cleartext path |
| F8 | Clock skew of hours on one device | certificates still accepted within the protocol's margin; HLC order holds |
| F9 | Disk full on a Linux member | clear error, no corrupted state after space returns |
| F10 | Corrupted state file | the service refuses with a clear message and does not lose the group |
| F11 | Address change (DHCP lease, Wi-Fi to mobile data) | the device is found again; away devices roam without a new invitation |
| F12 | Error messages | each failure above shows a friendly message; with `CBB_DEBUG=1` the real error under it; the log has the details in both modes |

## 9. Security tests

Sync off the home network is the project's top priority: if one of these fails, 0.4 does
not ship the feature.

| ID | Test | Pass when |
|---|---|---|
| S1 | Capture all traffic on the relay and on the away device's uplink during a full sync run | only WireGuard UDP (and, later, the VLESS transport) to the hub or relay; no TLS ClientHello, SNI, DNS name of the group, clipboard bytes or tunnel addresses in the clear; the bench searches the capture for every run marker and fails on any hit |
| S2 | The same capture on the LAN | member traffic is TLS 1.3 only; no marker in the clear |
| S3 | Client isolation through the hub | an away client cannot reach another client's tunnel address or any address but the hub's member port (scan from inside the tunnel) |
| S4 | The hub's tunnel exposes only the member port | port scan of the hub's tunnel address: one open port |
| S5 | A key that is not in the group | handshake ignored; no response that tells the key is unknown |
| S6 | Revoked device, away | its tunnel key is dropped on the hub within one record round; it cannot sync or rejoin |
| S7 | Invitation file | used once only; refused after expiry; refused without the admin's `yes`; the fingerprint shown on both sides matches |
| S8 | Relay learns little | groups on the forwarder or the open relay cannot reach each other; neither writes anything to disk but its key (file system checked before and after a run) or keeps logs; registration needs a valid certificate chain and records that do not revoke the device |
| S9 | Fail closed | with the tunnel broken, an away device sends nothing to any other address (capture shows no fallback) |
| S10 | Secrets | `copy -secret` never reaches any disk on any device (search of the state directories and swap-free check on Linux) and is gone after 60 s |
| S11 | Local access | the control socket refuses a user outside the `clipboardbridge` group on Linux, macOS and Windows |
| S12 | Installers | firewall rules open only the member port (and mDNS) to the local subnet; the tunnel port only on the hub |
| S13 | Two groups on one network (two hubs, devices in each) | no text, record or device list crosses between the groups; neither can pair into the other without a code |
| S14 | A stranger on the home network: a device in no group dials the member port, replays a captured connection, tries codes | refused; the code attempt counter stops guessing; nothing is learned about the group |
| S15 | Logs | no clipboard text, code or key in any log on any device, in either error mode (`CBB_DEBUG=0` and `1`) |
| S16 | Files at rest | the state directories hold only keys and certificates with owner-only permissions; no clipboard text is written to disk on any device |
| S17 | Commands (`cbb mode -on`): from an admin, a frozen admin, with a clock out of range, replayed | only a valid admin's command, once, within its lifetime, is taken; each refusal is explained |

## 10. Long run

A soak run of 24 hours on N1 plus one away device: a copy every 30 s from a random device,
one F-case every hour. Pass when every text arrived, memory and file descriptors of each
service stay flat (sampled every 5 minutes), and no service restarted except by a test. The fleet's
`E10-soak` scenario runs it in containers (`-soak-for 24h`): four members, a cut, a frozen
member or a killed service each hour.

## 11. Automation

**The harness** is a Go program in the repository, `tools/bench`, so it follows the rest of
the code (one language for the service and the harness, `go test`-style reports). It reads
an inventory file (devices, addresses, how to reach each one) that lives only on the
controller, never in the repository.

**Reaching the devices**: SSH from the controller with keys only (`BatchMode`), as the user
signed in on each device's desktop, so the bench reaches the real clipboard: `wl-copy` and
`wl-paste` in the Wayland session, `pbcopy` and `pbpaste` on the Mac. On Windows an SSH
session cannot reach the desktop clipboard, so `tools/bench/setup-windows.ps1` turns on the
OpenSSH server and registers scheduled tasks that run in the signed-in session: two move
text between a file and the clipboard, the third runs a script the bench leaves there. Headless devices, the lite member too, use `cbb copy`
and `cbb paste`. Commands that change the group (`cbb new`, `pair`, `mode`, `revoke`, `global`
and the others on the admin socket) run as root, so the bench calls them with `sudo -n`: on
Linux the bench user needs `sudo` without a password, and on the Mac a sudoers rule for
`/usr/local/bin/cbb` (below). A device whose `sudo -n` asks for a password has its steps
skipped, with the reason, instead of failing the run. The install and uninstall cases need
`sudo` without a password for the installers too, set up by a sudoers file in step 3; on the
Mac the file also allows `launchctl kill KILL` of the daemon, for F1. The emulator over
`adb` on the Mac.

**The controller** is the machine that runs the harness. It has to be on the LAN and always
on: `controller`. It is never a device under test, so reboots and failures of
the others do not stop a run. It reaches the router over SSH to switch networks, the Mac
to start the Windows VM and the emulator (`vmrun`, `emulator`, `adb`), and the
relay over SSH.

**Starting a run**:

- by hand on the controller (`go run ./tools/bench check`, `-build DIR reset` or `-quick
  reset` before each suite (section 13, "A test cycle"), `smoke`, `full`, `faults`, `desktop`, `away`,
  `relay`, `fleet`, `time`, `phone`, later `security` and `soak`; `all` runs check and then each suite after a quick
  reset, and ends with the coverage table (`coverage.txt` beside the report); `coverage`
  prints that table alone and needs no devices; `-report DIR` writes `report.xml` and
  `report.txt`, `-only a,b` limits the run to some devices);
- from GitHub: a self-hosted runner on the controller, started **only** by
  `workflow_dispatch` and by release tags, never by pull requests (a pull request from a
  stranger must never run code on the home network). The runner gets no repository
  secrets and runs as its own user without sudo.

**Building what is tested**: the bench takes the binaries from a CI run or a release
(artifacts with checksums and attestations), never builds on the devices, so it tests what
users get.

**Code coverage**: the fleet and time suites can tell which code of the service their cases
run. Build the fleet's `cbb` with `-cover` (`CGO_ENABLED=0 go build -cover
-coverpkg=./cmd/...,./internal/...,./mobile/... -o cbb ./cmd/cbb`, and with `-tags benchtime`
for `-cbb-time`) and pass `-coverdir DIR`: every container writes its counters there, the
services stopped first so that theirs are written too. Then `go tool covdata textfmt -i DIR -o
fleet.out` and `go run ./tools/coverage -go fleet.out` give the table, by package, as CI's
coverage job does ([testing](testing.md#coverage)). The real devices run release builds and are
not counted.

**Reports**: a JUnit XML file for GitHub's test summary, an HTML report with the matrix
(green and red cells), every failure's logs from all devices (`journalctl`, `log show`,
Windows event log, `logcat`) with `CBB_DEBUG=1`, and the packet captures of the security
suite. Reports stay on the controller, never in the public repository: they show the home network's addresses.

**Suites**:

| Suite | Contents | Time | When |
|---|---|---|---|
| smoke | the clocks, every device in no group, pair each one into the hub's group, one text from each device to every other | ~10 min | after each merge that touches the service, on request |
| full | sections 6 to 9; so far C1 to C5, C7 and C8 between every pair of members, F1, P35 for a member in a container, P34 (sync modes), C6 and S10 (a secret copy), S11 (local access), S15 (logs) and S16 (files at rest) | ~2 h | before each release candidate |
| away | P11 (the away devices join by invitation through the hub and its forwarder, sync both ways, `cbb global off` and `on`), F6 (the hub's service stopped), P37 (the hub moved to an admin computer) and P36 (the root and the admin as several hubs); F7 (the forwarder stopped) only with `-stop-forwarder`, since other groups use it | ~15 min | before each release, after each change to the tunnel |
| relay | P12: the members meet at the blind relay, sync, and a wrong key is refused | ~5 min | before each release, after each change to the relay |
| faults | E7 (30% loss, 300 ms delay and reordering at the hub), E8 (a member's port blocked for a minute), E11 and U6 (a hung service), U5 (a stopped service: every command's message, in both modes), U7 (a damaged `identity.json`); each change has a timer on the device that takes it back | ~15 min | before each release |
| desktop | the Macs and Windows PCs with their clipboards, in a group with a Linux member: the agent paused while a text arrives, so its service writes it after the Linux member, cut off, copied a newer one, then the text offered again at once and 10 s later as a clipboard history does, and the Linux member's newer text winning everywhere, which an echo would have beaten; `cbb copy` of the text a desktop already holds still a copy (Y24, Y25; GNOME's and KDE's clipboard managers stay manual); each password manager's mark (macOS ConcealedType, TransientType, AutoGeneratedType; Windows ExcludeClipboardContentFromMonitorProcessing, CanIncludeInClipboardHistory=0) keeping the text on the desktop, also when put back without it (Y31); a received secret carrying the marks, there 40 s after the copy and gone after its minute (Y32); on Windows, the root pasting and typing into a window with the focus: Unicode, tabs and line breaks exactly, 1 MiB pasted and 4 KiB typed, the clipboard's own text back after each paste and no copy made of it (T3, T5), a secret paste in no log (T11), and the log of pastes with sender, length, method and result but no text (T12; another keyboard layout, an RDP session, the notification and the Mac app's target stay manual); each device logging where its system keeps logs, the Windows and Mac services' logs over 1 MiB moved to service.log.1 at the next start, each line after the time (I21); each mode (own, receive, send, shared) letting `cbb copy` through on purpose (M2); one Linux agent per session, a second one saying so and leaving, a restarted one syncing again (H2); tmux copying through `cbb copy` and its paste key pasting the first line (H3); a large copy's fetch shown with its percentage in `cbb status` until it is done (O13); and on the Linux member alone, with or without a Mac or a PC: the primary selection not sent and the group's text in it (Y26), HTML and a PNG copied with their types (O4, O1), the session's kind noted and an X11 program's copy under Wayland (H1), the keys helper refusing keys, a paste without a grant and another user (T15), the console's tmux on a new virtual terminal (H4), the TPM's keys in the hub's device list (K13), and a file a Flatpak app copied from the document portal arriving on a Mac or PC and one from there offered through the FileTransfer portal (O12); with `-disruptive`, only on the owner's word, on each computer from the hub: the quick actions restart, lock (Windows' lock for H7), a reboot cancelled within its minute and a real one (Q3), a sleep woken by `rtcwake` or `pmset schedule wake` and in sync within 30 s (I18), and on a Mac the application firewall on and blocking all (H8) | ~15 min | before each release, after each change to the agents |
| fleet | full members in containers on the controller (`-cbb FILE`, a static Linux `cbb` of the build under test; `-fleet-size N`, 16 by default): the pairing window (G5, G6, G9), admins and their limits, freezing, removal and names (G20 to G23, G30, M5), a takeover and the new root admitting a computer (G26), leaving and joining again (G42), two groups side by side (G43, S13), a network split and a line of members (Y12, Y16), the modes (M3, M6), junk on the member port (D15, S14), many local clients (E5), restarts (E9), remote paste into root's tmux with each refusal and its reason, cleaned text, a paste through another member and off on every device (T1, T2, T6, T7, T9, T10, T13, T14), an admin offline, admins at once, a stolen admin computer and the mode kept (G25, G33, S24, M4), the old root undoing a takeover (G27), joining by address, over carrier-grade NAT, refused on a public network and over IPv6 only (G4, D7, D8), two pairing windows at once (G7), who dials (D2), known networks (D6), heartbeats and a large frame on a slow link (D12), no network at start (I19), the state's disk full (U8), a second instance (U13), quick actions (Q1, Q2, Q4 to Q7), the shortcut played by curl (X1 to X3, K12), commands replayed, changed or for another group or device and records sent in any order or by the thousand, by `tools/bench/forge` in a container with a member's copied state (S17, S23, T8, G31, G32), a device an admin admitted (K14), sync away from home behind a router that stands in for the internet (public addresses of 203.0.113.0/24 passed to the hub, the forwarder and the relay): two clients joined by invitation, directly and through the forwarder, a client's tunnel reaching only the hub's member port and a stranger's key unanswered (played by the forge with the client's copied keys), the hub's address changed, the hub hung and stopped, the forwarder restarted and pinned with a wrong key, and nothing sent elsewhere meanwhile (W3, W10, W11, W13, W19, W20, W31, S3 to S5), obfuscation and the router counting what looks like WireGuard (W18, W35), two groups on one forwarder (W33, S8), the blind relay with members on networks of their own, restarted, a wrong key and a removed device (W36, W37), an open relay's 16 registrations per address (W38), 16 clients copying and the 17th refused by the forwarder (E6, W32), VLESS with REALITY borrowing a stand-in site, with every UDP packet dropped (W34), the hub moved to another member, and the root's member serving while the root is off and giving way when it is back (W14, W15), copies of folders with links, pipes and unsafe names, of 10 000 entries and one more, `cbb paste -o` never replacing a file, an image with its text, the mode `own`, and the sender's and the receiver's limits (O2, O3, O5), every command's `-h`, unknown commands and flags (U2), what a member writes to its clipboard after a network drop, after its service was away and from a hello with a secret, and a member's new address (Y20 to Y23, Y33, D16), a removed client dropped by the hub and the forwarder keeping no address or ID (W21, W40), a hello naming another system (G35), the iPhone CA's name constraints and a new iPhone CA once an admin is removed (X4, G24), keys in files in every devices list and refused for an admin without consent (K9, G34), the time a copy takes at home and through the tunnel, five members copying every 100 ms for three minutes with memory and descriptors watched, three 50 MiB files at once with a text passing them, and a fetch on a slow link cut, its sender restarted and stopped by a newer copy (E1, E2, E4, O7, O8), the control socket's junk and a user's idle connections past the 64 it may hold closed (U11), a member as the remote of an Android TV and a Roku played by the forge: pairing by the code, typing, an admin's paste sent to the TV, a Roku's consent and its control off, an address off the home network (T17, T19), invitations answered no, cancelled, expired, guessed three times, used twice, used by a member and with the hub off, and 24 hours at most (G13), the mDNS records each member publishes, its goodbye and announcement, and whom the full members dial: a full member of their group, not a lite member, a phone or another group (D17, D3), a peer that stops reading closed once its queue is full and catching up when back (D14), 32 handshakes at once, the 33rd connection closed, and the file descriptors run out and back (D13), an event reaching a member by three paths or sent again written once (Y15), a joiner killed at moments through its join never left half joined (G16), a random walk of 200 steps among joins, removals, names, admins, freezes, takeovers, restarts, sleeps, network cuts and copies, with `CBB_BENCH_SEED` to repeat one (G40), renewed certificates for another device or key, ending earlier, for the server only, from a frozen admin for a listed device, from a removed admin and from the root, and a device whose certificate a removed admin renewed staying in the group (K3), the holder of `clipboardbridge.local` among the root and an admin, `cbb holder`'s settings and the handover after a goodbye and after a freeze, asked over mDNS by the forge (D4, D5), a member whose firewall drops its member port still syncing and warned (D11), what a stranger on the LAN learns from mDNS and the member port (S21), a member that is no admin refused as the hub while the hub stays registered (W30), a member's frames fuzzed over member TLS, random bytes to the member port and a pairing window, and the control socket fuzzed, for `-fuzz-for` each (1 min by default, 1 h for a release; S20), keys in files warned in every list (K11), the root and an admin admitting by code alone or with an address, the member removed and refused, on two subnets (G41, Y6), `cbb update` in a container running systemd from a feed that `tools/release-sign` signs with test keys: installed and updated, a changed archive, a release key or keys list no root signed, a minimum version, another platform, an older file, a release that does not run put back and the update method (I8 to I11), `get.sh` on a computer with nothing installed against the same feed: a changed archive before and after SHA256SUMS, a release key or keys list no root signed, keys and the channel expired, no openssl and another `CBB_VERSION` refused, and that version and the latest installed (I3; `get.ps1` is CI's), `get.sh --lite` installing the lite member from a release that holds both members' archives, packed from `-cbb-lite` with lite/packaging/archive.sh (I1; needs cargo and jq), install.sh without a terminal leaving automatic updates unanswered, `cbb update -auto on` and `off` and the timer, and in a group of two the second member taking the archive from the first with a feed of only the signed files (I12), install.sh's options on a computer with systemd and a bare nftables firewall that drops input: `--no-firewall` adding no rule, `--express` printing the rules for the port, `--port 8800` kept by the next run and `--port 8764` back (I2), uninstall leaving only the state and `--purge` nothing of what install.sh added, compared with the files, rules and units from before (I4), two members upgraded from the previous release one at a time, keys and group kept and copying both ways after each step (I6), and the previous release over the new state starting in the same group with the same keys or refusing with a reason (I7), the content cache: a copied file's part readable only by the service, kept a while after the copy is replaced and gone 10 minutes later with no further copy, and none after a restart (O9; about 12 min), a lite member (`-cbb-lite FILE`, its `cbb` for Linux) joined by the code of `cbb pair`: `cbb watch` and `watch -0`, the ZX Next's frames both ways and a damaged one refused (U9), the text that goes with a copy of a file and its last text kept when none does, with nothing of the file fetched (O6), the lite member's `cbb update -check` taking a release the test roots sign and refusing one whose channel or keys no known key signed (S22), the fetch limits asked of a part's holder by the forge: 1 MiB in chunks padded to 16 KiB, a get of a byte more dropped and 80 gets at once closing the connection (O15), a computer in no group listening for the phone during `cbb pair` only, the forge as the phone with the root's identity: another fingerprint and a wrong code refused without ending the window, the right code admitting it, the QR code dead after the join and the port closed once `cbb pair` stops (G17), the forge relaying a join between two TLS sessions with an insider's certificate, refused by CPace's channel binding at the cost of one guess, and the joiner then joining directly with the same code (G8), install.sh run again keeping the group, mode, limits, quick actions, remote paste and keys (I5), the unit's `systemd-analyze security` exposure at or below the recorded score and the TPM reached through `/dev/tpmrm0` alone (I20), with ufw on, exactly the rules install.sh lists added and taken away again, on a kernel without IPv6 too (S12), `get.sh --lite` renaming an old `cbb-lite` install to `cbb` in its group (I26), a join by invitation letting the service reach the hub's addresses and taking them back once it fails (G15), the invitation file readable only by its owner, deleted once used and joining no one after (S7), a removed client's copies reaching no one (S6), the lite member's `-port`, `-no-listen`, `-no-mdns`, `-peer` and `cbb join -addr` (H5), the lite member as a client of the hub's tunnel: plain WireGuard away from home, and refusing an obfuscated hub's offer and staying at home (W17), two computers with systemd and avahi-daemon in groups of their own: avahi still publishing its host and finding the member's service, and neither member connecting to the other group's (D1), a router between an away client and the group's servers counting no packet with the copied text, the run's marker, the group's tag or a device ID in the clear, and at home the member port refusing TLS 1.2 and member connections carrying no copied text in the clear, each counter checked by a canary sent in the clear (S1, S2), and with the hub's WireGuard port blocked the away client sending nothing in the clear and nothing but to the hub and the forwarder for two minutes after a copy (S9), the forwarder and the relay with `CBB_DEBUG=1` keeping in their state directories only their keys, the forwarder's state and the log, with no group tag, device ID, address or copied text there or under `/var/log` (S18; the units' `systemd-analyze security` stays manual), the away client taking a file copied at home through the hub within its `max-copy-away` and leaving one over it at home, its status saying so (O10), a text sent as a secret staying one on both members when sent again without the mark, and 4096 secrets remembered, the oldest forgotten after 4096 more (Y34; the 12 hours are internal/clip's), a failed step of install.sh or uninstall.sh ending it with that step's exit status and saying so with how to see more, or with `CBB_ERROR_DETAILS=1` showing every command (I25; Windows is CI's), the same computer joined away from home by invitation, its unit's drop-in allowing exactly the hub and the forwarder, and after the hub's address changes `cbb global` and `cbb status` saying the limit lags and nothing sent to the new address until `sudo cbb global allow` (W2; Windows and macOS stay manual), a member limited to its home interface with `CBB_INTERFACES` and a second network with no firewall, which `cbb network` takes as the group's, answering member TLS at home and none from the other network (D10), a lite member on another subnet behind a router container that runs avahi: not found with the reflector off, found by mDNS with it on and reached with `-peer` (D9; the two networks need Docker 28 or later), a member with a router's memory passing a 90 MiB copy on to a member that reaches only it, with no OOM kill or restart (O14), a soak of four members for `-soak-for` (none by default, 24 h for a release; section 10) with a fault every hour, a copy every 30 s that must reach every member, and memory and descriptors flat (E10), and many members (E3); each is a scenario that `-scenario NAME,...` runs alone (the names are in `FleetSuite`); every container and its networks are removed after the run | ~60 min | before each release, after each change to groups, sync or sync away from home |
| time | the fleet with the time-scaled build (`-cbb-time FILE`, `cbb` built with `-tags benchtime`): the root renews certificates in their window over connections that stay up and the group keeps syncing (K1, K7), new credential periods reach every member (W39), a member whose certificate ends while no admin is on says so and pairs again (K4), the root's `clipboardbridge.local` certificate is renewed (K2), certificates issued near the CA's end end with the CA and are not renewed past it (K5); at the real pace with moved clocks: a clock in 1970, an hour, three hours, two and ten days and three years ahead (K6, Y13: what syncs, what is refused, the clock shown off, a certificate ended by the member's clock, and back once it is set right), and a member killed right after a copy and started with its clock an hour back (Y14), and commands refused as expired, from the future or to a clock not set (T8); the hub's WireGuard key renewed each credential period, a client away from home holding the next key before the hub switches and using it after, and a client off across the switch with the next key connecting again (W12); `-scenario K1-renewal`, `K6-clock` or `W12-hub-key` runs one part | ~15 min | before each release, after each change to certificates or credentials |
| phone | the Android app on an emulator that `adb` sees, in a group with members of the fleet (`-cbb FILE` as for the fleet; `-android DIR`, apps/android by default): each member's port published on this computer's loopback, which the emulator dials as 10.0.2.2, and a helper there through which the app's instrumented tests (`apps/android/app/src/androidTest`) run cbb on a member, copy there and wait for a text; Gradle runs the tests and each test is a case. The phone makes its own group and admits a computer by its QR code's text, sends its copy and fetches the computer's (A1), takes copies by itself and leaves its clipboard alone in the mode send (M7), pastes on the computer (T16), runs a quick action (Q8), renames and removes a second computer with one notification per event and none with its switch off (A6), sends from the tile's and the widget's screen (A12), shares files both ways (O11), takes a computer's secret marked sensitive (Y35), and reaches a computer it made the hub through the tunnel in the app's process, saying where it stands also while the hub does not answer (W42, W5); the phone is the hub at a forwarder of the run, refused with a wrong key, reached by a computer away and serving an invitation a new computer uses (W16, G14, the guest a computer here); CI's `Android app on an emulator` job runs it on every pull request that touches the app or the service | ~15 min | every pull request that touches the app or the service |
| ci (not a suite) | CI's tests of the apps' windows on every pull request, counted with the harness: the tray app's window in a headless Chrome or Edge (`apps/desktop/window_test.go`, the tray app jobs), with the real `Desk` behind it, a stand-in service on the control socket and a stand-in for running cbb as the administrator: the ten colours in Dark, Light and System, tiles, list and orbit, every kind of device its own icon (A15); a collection made, filled, opened, renamed and ungrouped, a tile moved with Alt and an arrow, back to the group's order, the search and the filters (A8); every text in Russian (A9); a service that does not answer in one plain line, the error underneath only with "Show error details" (U12, A16); rename, remove and "Make it an admin" asking first and running cbb as the administrator, a closed prompt and a cancelled dialog changing nothing, cbb's own error in a line (A5; the pkexec and UAC prompts stay manual); XCUITest of the iPhone app on the simulator (`apps/ios/ClipboardBridgeUITests`): the Start screen and its first-launch note, joining from Start, the ten colours and three themes kept across a launch, the error details switch behind seven taps on the version and its launch argument, Russian, and the language menu for a language without a translation (A14, A15, U12, A9); XCUITest of the Mac app with no service (`apps/macos/ClipboardBridgeMacUITests`): the stopped service in one line, the error underneath only with details on, the Settings switch, Russian (A4, U12, A9); the Android app's screens on Robolectric (`ScreensTest`): the Start screen, each colour and theme kept, the error details switch, Russian (A2, A14, A15, U12, A9) | ~20 s (tray app), a few minutes (phones, Mac) | every pull request that touches an app |
| security | section 9 with captures | ~30 min | before each release, after each change to the tunnel or relay |
| soak | section 10 | 24 h | before each release |

## 12. Entry and exit criteria

Entry (a run may start): every device in the inventory answers; the binaries under test
come from a green CI run (`ci-ok`); the relay runs the forwarder of the same commit; the
clocks are within 1 s (NTP).

Exit (0.4 may be released):

- smoke, full, security and soak suites pass on the release candidate;
- no open defect of severity 1 or 2; every severity-3 defect is in the CHANGELOG's known
  issues;
- every row of the README's status table marked "not yet" on real devices that the bench
  covers is updated;
- every security test (S1 to S16) passes; there are no exceptions for security.

Severity: 1, data leaves the device unprotected or a device that is not in the group gets
data; 2, sync stops or data is lost; 3, a wrong message, a slow path, a cosmetic fault.

## 13. Inventory

The controller keeps the bench's inventory in `~/.config/cbb-bench/inventory.toml`, outside
the repository: it names the home network's addresses and the keys. Its shape:

```toml
controller = "controller"

[device.desktop]
os = "linux"           # linux, linux-lite, darwin, windows, docker, openwrt, freebsd
ssh = "user@desktop.lan"     # the user signed in on the desktop
clipboard = "wayland"  # wayland, x11, none (cbb copy and paste), macos, windows
roles = ["member", "hub", "away"]

[device.win]
os = "windows"
ssh = "user@win.lan"
clipboard = "windows"
firewall = "yes"       # linux, windows: reset lets the installer open the member port; "no" leaves the firewall alone

[device.router]
os = "openwrt"         # ssh as root: OpenWrt has no sudo
ssh = "root@router.lan"
clipboard = "none"
roles = ["member", "hub"]

[device.nas]
os = "docker"          # cbb in a container on the host ssh reaches
ssh = "user@controller.lan"   # a user in the docker group
container = "clipboardbridge"  # the default, compose.home.yaml's name
roles = ["member"]     # never hub: that device makes the group and holds its keys

[router]
ssh = "root@router.lan"
kind = "openwrt"
away_network = "bench_away"   # the network the bench moves the away device to

[device.remote]
os = "linux"
ssh = "user@remote.example.net"
roles = ["away"]       # away only: it joins by invitation in the away suite

[forwarder]
address = "relay.example.net:8764"
key = "<key>"     # cbb forward -show-key on the server
ssh = "user@relay.example.net"  # for F7 only, which stops it
service = "cbb-forward"

[relay]
address = "relay.example.net:8765"
key = "<key>"     # cbb relay -show-key on the server
```

On the Mac the bench user runs two programs as root without a password: `cbb`, and the
bench's helper `cbbbench-root`, which `tools/bench/setup-mac.sh` installs with its sudoers
rule (below).

For `reset`, a Linux or FreeBSD device names `firewall = "yes"` (the installer opens the member port,
as on a home computer) or `"no"` (it leaves the firewall alone, as on a server that does other
work), and the container names `setup`. On OpenWrt the service's own rules come and go with
it, so `firewall` does not apply; the bench sends the build to the router's `/tmp`, in RAM,
not to its flash, the path of `tools/bench/setup-docker.sh` on its
host.

### Setting the bench up, and taking it down

Each piece of the bench outside the devices' installs has a setup and a teardown, so that a
test cycle starts with a few commands and ends with one per piece. Run each from a checkout
of the repository:

| Piece | Where | Setup | Teardown |
|---|---|---|---|
| A member in a namespace | its Linux host | `sudo sh setup-netns.sh setup NAME SOCKS TUN2SOCKS` (the namespace, tun2socks to the proxy, the units) | `sudo sh setup-netns.sh teardown NAME` |
| The container's host | the controller (or another host) | `sh tools/bench/setup-docker.sh setup` (Docker, the docker group, the kill helper for F1) | `sh tools/bench/setup-docker.sh teardown [--group]` |
| SSH to itself, for a device on the controller | the controller | `sh tools/bench/setup-controller.sh setup` | `sh tools/bench/setup-controller.sh teardown` |
| The bench's signing key | the controller | `ssh-keygen -t ed25519 -N '' -f ~/.ssh/cbb_bench_sign -C cbbbench` | delete `~/.ssh/cbb_bench_sign` and its `.pub` |
| The Mac's root helper | the Mac | `sudo sh tools/bench/setup-mac.sh setup -signer cbb_bench_sign.pub` (the public half, copied from the controller) | `sudo sh tools/bench/setup-mac.sh teardown` |
| The blind relay of the relay suite | the server beside the forwarder | `sudo sh setup-relay.sh setup [PORT]` (prints its key; open the port in the provider's firewall too) | `sudo sh setup-relay.sh teardown [--purge]` |

The Mac's helper has fixed steps only: remove the install with its keys, install a release
archive, search the state directory and `/tmp` for a run's text, list the state directory's
open files, run `cbb status` as `nobody` and print the service's log. It installs only an
archive whose SHA-256 is in a build's `SHA256SUMS` that the bench's signing key signed
(`ssh-keygen -Y sign -n cbbbench`, on the controller), checked against the public half that
`setup -signer` keeps root-owned in `/usr/local/libexec/cbbbench/allowed_signers`; so a new
build needs no password on the Mac. Without a signing key, `setup SHA256SUMS` or `trust
SHA256SUMS` lets it install one build's archives. The risk: whoever controls the bench user
on the controller, which holds the signing key, can have the Mac install a build as root; the
same user already reaches the Mac over SSH, and `cbb` runs there as root through the same
rule, which is as much as the group's admin can do anyway. The helper, `allowed_signers` and
both sudoers files belong to one test cycle: teardown removes them, and the signing key on the
controller is deleted with them.

### A test cycle

1. Put the build under test on the controller: its release archives
   (`clipboardbridge-<os>-<arch>.tar.gz`, `clipboardbridge-lite-linux-<arch>.tar.gz`) and
   `SHA256SUMS`, from the release or from CI, in a directory of their own, and sign the sums
   there for a Mac: `ssh-keygen -Y sign -f ~/.ssh/cbb_bench_sign -n cbbbench SHA256SUMS`.
2. `bench -build DIR reset`: every device at once gets its archive (once per build; a
   device keeps the newest three), loses its install and keys (`uninstall.sh --purge`, which
   L10 then checks), installs the build, and answers in no group. On a Linux desktop the
   bench starts the agent again inside the signed-in session, so nobody signs out and in.
   `bench -quick reset` keeps the installs and only wipes the services' state, between
   suites of the same build.
3. `bench check`, then the suites, each after a reset.
4. At the end of the cycle, the teardowns above.

A device with `os = "docker"` is the image running on a host: the bench calls `docker exec
-i CONTAINER cbb` there, as the image's user, and copies and pastes with `cbb copy` and `cbb
paste` (it has no desktop clipboard). `tools/bench/setup-docker.sh setup` prepares the host
once: Docker, the SSH user in the `docker` group, and for F1 the helper
`cbbbench-kill-container`, which that user may run as root without a password (the
container's process belongs to the image's user); `setup-docker.sh up CBB` starts a new
container of the build under test, and `down` removes it with its volume.

A device with `os = "netns"` is a second full member on a Linux host, for a way out that
the host's own member does not take, such as a VPN: it runs in a network namespace whose
only interface is tun2socks's, which carries its traffic to a SOCKS5 proxy on the host:
over a proxy without UDP the member goes away from home with VLESS (`-vless`), over one
with UDP with WireGuard too; it resolves names over TCP. `tools/bench/setup-netns.sh setup NAME SOCKS
TUN2SOCKS` prepares it once in `/opt/cbbbench-netns/NAME`, with the units `cbbbench-NAME-net`
(tun2socks) and `cbbbench-NAME` (the service, as root, with its own state and socket), and
prints the address it goes out from; the bench calls its cbb as `sudo -n
/opt/cbbbench-netns/NAME/cbb`. `up NAME CBB` installs the build under test with its state
empty (reset), `down NAME` stops it and empties its state, and `teardown NAME` removes all of
it. NAME is the device's name, 1 to 10 small letters and digits. Its keys are in files, so it
is never the hub. `address` (`host:port`) on a device is where the others dial it to pair when mDNS cannot
find it; a lite member always joins at an address, which `cbb pair` prints.
`tools/bench/inventory.example.toml` is a complete example. Each device needs the
controller's SSH key for its desktop user; a Windows device also runs
`tools/bench/setup-windows.ps1` once. Devices on the bench are test devices: the bench installs and wipes Clipboard Bridge
on them as it needs.

## 14. Order of work

One pull request per step, merged in order:

1. This document and the inventory format.
2. `tools/bench`: the inventory, the SSH runner, a clipboard driver per platform, the
   report, the `check` and `smoke` suites on N1; the Windows setup script.
3. The full matrix (section 6), the life-cycle cases and the features and platforms (P1 to
   P33, section 7): installing and
   removing with the installers (on Windows too, without a VM snapshot), the emulator, the
   router's away network.
4. Failure cases (section 8) with the network tools and automatic reverts.
5. Away cases through the hub (N3, N7) and security tests S1 to S7, S9 to S16.
6. The relay: the VPS set up as the production relay (hardening, firewall, no logs) running
   `cbb forward`; S8 and N4.
7. The GitHub runner, the soak suite, the release checklist in `docs/maintaining.md`.
8. The 0.4 test run and its report.
