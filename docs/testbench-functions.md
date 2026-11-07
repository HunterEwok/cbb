<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The product's functions, for the bench

Every function of Copy Beyond Borders as release 0.6 has it, one line each, with the cases of
[testbench-catalogue.md](testbench-catalogue.md) that check it. It is gathered from
[design.md](design.md), [protocol.md](protocol.md), [apps.md](apps.md),
[reference/cli.md](reference/cli.md) and the 0.6 plan. "A function" is something a user can
do or rely on, or a rule of the protocol that a device on the bench can break on purpose and
watch being kept.

`testbench coverage` reads this table: a function counts as covered when one of its cases
is in the catalogue, as automatic when one of those runs without a person, and as run when
the harness runs one today. A function with no case says so with `-`, and is listed. Add a
line here with every new function, and a case for it in the catalogue.

## I. Installation, updates and the service's life

| ID | Function | Cases |
|---|---|---|
| I.1 | `install.sh` on Linux | I1 |
| I.2 | `install.sh` on macOS | I1 |
| I.3 | `get.sh` (full member) | I1, I3 |
| I.4 | `get.sh --lite` | I1 |
| I.5 | `install.ps1` on Windows | I1 |
| I.6 | `get.ps1` on Windows | I1, I3 |
| I.7 | winget, then `cbb install` | I1, I11 |
| I.8 | Homebrew, then `install.sh --in-place` | I1, I11, H8 |
| I.9 | The Docker image and compose files | I1, H6 |
| I.10 | The OpenWrt package | I1, I23, H9 |
| I.11 | FreeBSD's rc.d install | I1, H10 |
| I.12 | The OPNsense plugin | I1, H10 |
| I.13 | `--express` and `CBB_FIREWALL=express` | I2 |
| I.14 | `--no-firewall` and `CBB_FIREWALL=no` | I2 |
| I.15 | `--port N`, `$env:CBB_PORT`, `-Port`, back with `--port 8764` | I2, H7 |
| I.16 | `--console` | I2, H4 |
| I.17 | `--uinput` | I2, T2 |
| I.18 | `--home-cgnat on/off`, `-HomeCgnat`, `CBB_HOME_CGNAT` | I2, G4 |
| I.19 | The kept answers: `firewall.answer`, `cbb.env`, the registry key | I2 |
| I.20 | Firewall rules: ufw, firewalld, nftables, iptables | I2, S12 |
| I.21 | Firewall rules: Windows Firewall | I2, S12 |
| I.22 | The macOS application firewall | I2, H8 |
| I.23 | Firewall rules: fw4, pf, ipfw | I2, H9, H10 |
| I.24 | `get.sh` checks `SHA256SUMS` and the signature | I3 |
| I.25 | `CBB_VERSION` | I3 |
| I.26 | `uninstall.sh` and `--purge` | I4 |
| I.27 | `uninstall.ps1`, `-Purge`, Settings' Apps entry | I4 |
| I.28 | Reinstall keeps the state | I5 |
| I.29 | Upgrade from the previous release | I6 |
| I.30 | The agent started again in every session after an update | I6, H2 |
| I.31 | Downgrade behaviour | I7 |
| I.32 | `cbb update -check` | I8 |
| I.33 | `cbb update` (rename into place) | I8 |
| I.34 | The health check and rollback | I10 |
| I.35 | The list of failed versions | I10 |
| I.36 | Refusing a tampered file, a bad signature, an expired manifest | I9 |
| I.37 | Rollback protection (the highest version seen) | I9 |
| I.38 | `min_from` | I9 |
| I.39 | The install method recorded (Homebrew, winget, Docker, packages) | I11 |
| I.40 | `cbb update -auto on/off`, the timers, the installers' question | I12 |
| I.41 | Members passing the manifest and archives to each other | I12 |
| I.42 | The lite member's own update | I13 |
| I.43 | The Nano's update over the air with rollback | I13 |
| I.44 | Android's self-update of the sideloaded APK | I14 |
| I.45 | Sparkle in the Mac app | I15 |
| I.46 | "Update ready" in the tray app and `cbb status` | I15 |
| I.47 | The service manager restarts the service | I16 |
| I.48 | Rejoining after a reboot; Windows before sign-in | I17, H7 |
| I.49 | Sleep and wake | I18 |
| I.50 | Start without a network | I19 |
| I.51 | Waiting for NTP on devices without a real-time clock | I19, H9 |
| I.52 | systemd hardening of the units | I20 |
| I.53 | Logs and their rotation | I21 |
| I.54 | The release's sums, attestations and signed manifest | I22, S22 |
| I.55 | Our signed apk feed | I23 |
| I.56 | mips and mipsle builds | I23 |
| I.57 | Authenticode on Windows | I24 |
| I.58 | `CBB_ERROR_DETAILS` and the installers' errors | I25 |

## G. Groups, pairing and roles

| ID | Function | Cases |
|---|---|---|
| G.1 | `cbb new` | G1 |
| G.2 | Containers make no group; `CBB_KEYS_IN_FILE=yes` | G1, H6 |
| G.3 | The lite member makes no group | G1 |
| G.4 | A phone makes the group, root key in hardware | G2, A1, A2 |
| G.5 | `cbb pair` on an admitter (the code, the wait) | G3 |
| G.6 | `cbb pair -code` found by mDNS | G3, G4 |
| G.7 | `cbb pair -code ADDRESS` | G4 |
| G.8 | `cbb pair -code` on the lite member | G3 |
| G.9 | Joining through an SSH forward or one's own VPN | G4 |
| G.10 | The CGNAT range refused, or taken with `CBB_HOME_CGNAT` | G4 |
| G.11 | The pairing window's 5 minutes | G5 |
| G.12 | Three wrong codes close the window | G5 |
| G.13 | A used code refused | G5, G6 |
| G.14 | The window counts sleep | G5 |
| G.15 | `busy` | G6 |
| G.16 | `taken` | G6 |
| G.17 | Five attempts per address before the count | G6 |
| G.18 | 30 s per attempt | G6 |
| G.19 | Two windows at once | G7 |
| G.20 | CPace: one guess per attempt | G8 |
| G.21 | Channel binding against a relay | G8 |
| G.22 | `cbb pair` on a member that is no admin | G9 |
| G.23 | A device in a group keeps it | G9 |
| G.24 | The Welcome (certificate, records, `issuer`) | G3, K14 |
| G.25 | A computer joins a phone's group by QR code | G10 |
| G.26 | The lite member joins by QR code (`cbb pair`, `-addr`) | G10 |
| G.27 | The Nano joins by the phone | G10, H11 |
| G.28 | A QR code of another session refused | G10 |
| G.29 | The joining computer listens for the phone | G17 |
| G.30 | A second phone joins and becomes an admin | G11 |
| G.31 | The iPad joins as a phone | G11, H15 |
| G.32 | `cbb invite`, `-for`, `-o` | G12, G13 |
| G.33 | `cbb pair -invite` and the guest tunnel | G12 |
| G.34 | Fingerprints on both sides, `yes` | G12 |
| G.35 | Invitations refused (no, reuse, expiry, hub off, failures, cancelled, other group) | G13 |
| G.36 | Nothing left on the hub after an invitation | G13 |
| G.37 | Invitations on a phone that is the hub | G14 |
| G.38 | The hub's addresses allowed for a join and taken back | G15 |
| G.39 | The identity replaced in one step | G16 |
| G.40 | `cbb admin` and `-allow-file-key` | G20 |
| G.41 | An admin computer admits, renews, removes ordinary devices | G21 |
| G.42 | An admin computer cannot make admins or remove admins | G21 |
| G.43 | `cbb freeze` | G22 |
| G.44 | `cbb unfreeze` | G22 |
| G.45 | A mutual freeze | G22, G33 |
| G.46 | Phones' "Unfreeze" | G22, A1 |
| G.47 | `cbb remove` by name and by device ID | G23 |
| G.48 | Removing an admin keeps the devices it admitted | G23 |
| G.49 | Removing a phone (both keys) | G23 |
| G.50 | Connections of a removed device closed at once | G23 |
| G.52 | A removal reaching a device that was off | G25 |
| G.53 | `cbb takeover` | G26 |
| G.54 | A takeover undone | G27 |
| G.55 | A phone takes the group over (`root` records) | G28 |
| G.56 | An old group's records refused (`cbb upgrade` gone) | G29 |
| G.57 | `cbb rename` and the phones' rename | G30, A1 |
| G.58 | Name lengths and Unicode names | G30 |
| G.59 | Records converge in any order | G31 |
| G.60 | Record limits (4096, 1024 per signer) | G32 |
| G.61 | Admins acting at once | G33 |
| G.62 | Key levels decide who may be an admin | G34, K9 |
| G.63 | A new record when a device's system changes | G35 |
| G.64 | A computer of a phone's group made an admin | G36 |
| G.65 | The `watch` role and its key | G37 |
| G.66 | A watch is certified only with a passcode and wrist detection | G37 |
| G.67 | A watch's limits | G38, T7 |
| G.68 | Delivery between the watch and the phone | G39 |
| G.69 | Every sequence of joins, removals, freezes and takeovers | G40 |
| G.70 | Every pair of joiner, admitter and path | G41 |
| G.71 | Leaving and joining again | G42 |
| G.72 | Groups side by side on one network | G43, S13 |

## K. Certificates and keys

| ID | Function | Cases |
|---|---|---|
| K.1 | Member certificates renewed under 240 days | K1 |
| K.2 | The `cert` message and its `issuer` | K1, K3 |
| K.3 | A renewal from an admin phone | K1 |
| K.5 | Checks on a renewal | K3 |
| K.6 | Expiry when no admin renews | K4 |
| K.7 | Certificates that end with their CA; the CA's end | K5 |
| K.8 | A clock behind or ahead | K6 |
| K.9 | The skew shown in `cbb status` | K6, U1 |
| K.10 | The 12 h renewal timer | K7 |
| K.11 | TPM keys on Linux | K8, K13 |
| K.12 | TPM keys on Windows | K8, K13 |
| K.13 | The Mac's signing key through the agent | K8 |
| K.14 | Phones' keys in hardware | K8, G2 |
| K.15 | The sealed WireGuard key | K8 |
| K.16 | The identity file's permissions | K8, S16 |
| K.17 | Key levels 1, 2 and 3 | K9 |
| K.18 | The key store shown (`file`, `hardware`, `proven`) | K9, U1 |
| K.19 | Android attestation (TEE, StrongBox) | K10 |
| K.20 | App Attest | K10 |
| K.21 | TPM EK chains, offline and fetched | K10, K13 |
| K.22 | The revocation list of attestations | K10 |
| K.23 | Warnings for old groups with file keys | K11 |
| K.26 | The TPM evidence flow and its status | K13 |
| K.27 | Chains through an admin CA | K14 |

## D. Discovery and connections

| ID | Function | Cases |
|---|---|---|
| D.1 | Publishing on mDNS | D1, D17 |
| D.2 | Browsing mDNS | D1, D17 |
| D.3 | Living beside avahi, resolved, mDNSResponder, Windows' DNS client | D1 |
| D.4 | Another group's records ignored | D1, G43 |
| D.5 | The lower ID dials | D2 |
| D.6 | The 30 s fallback dial | D2 |
| D.7 | One connection per pair | D2 |
| D.8 | Full members dial lite members | D3 |
| D.9 | Phones dial; a phone hub listens | D3 |
| D.13 | Known networks and quiet interfaces | D6 |
| D.14 | `cbb network` | D6 |
| D.15 | Only private addresses published and accepted | D7 |
| D.16 | IPv6, link-local last | D8 |
| D.17 | `-peer` across subnets | D9, H5 |
| D.18 | The member port refuses WAN | D10 |
| D.19 | The dial-back warning | D11 |
| D.20 | Heartbeats and the 15 s timeout | D12 |
| D.21 | 32 handshakes at once; out of descriptors | D13 |
| D.22 | The queue of 256 messages | D14 |
| D.23 | The 7 MiB frame limit and bad frames | D15 |
| D.24 | ALPN and client certificates required | D15 |
| D.25 | A new address; roaming | D16 |
| D.26 | TXT fields, announcements and goodbyes | D17 |

## Y. Sync of text

| ID | Function | Cases |
|---|---|---|
| Y.1 | Text between every pair | Y1, Y6 |
| Y.2 | Unicode kept | Y2 |
| Y.3 | Invalid UTF-8 refused | Y2 |
| Y.4 | Line endings | Y3 |
| Y.5 | Whitespace and empty texts | Y4 |
| Y.6 | The 1 MiB limit | Y5 |
| Y.7 | Every path | Y6 |
| Y.8 | The last copy wins | Y10, Y11 |
| Y.9 | Convergence after a partition | Y12 |
| Y.10 | The hybrid clock | Y13 |
| Y.11 | Events too far ahead refused | Y13 |
| Y.12 | The clock mark across restarts | Y14 |
| Y.13 | Duplicates written once (4096 IDs) | Y15 |
| Y.14 | Universal Clipboard reported once | Y15 |
| Y.15 | Forwarding between members | Y16 |
| Y.16 | Only live events written | Y20 |
| Y.17 | The 30 s after being away | Y21, Y22 |
| Y.18 | A member that lost its peers keeps its clipboard | Y23 |
| Y.19 | No echo | Y24 |
| Y.20 | Clipboard managers make no event | Y24, Y25 |
| Y.21 | The primary selection | Y26 |
| Y.22 | Auto-paste of a phone's event | Y27 |
| Y.23 | `cbb copy -secret` and its 60 s | Y30 |
| Y.24 | Secrets never on disk | Y30, S10 |
| Y.25 | Password managers' marks respected | Y31 |
| Y.26 | Received secrets carry the marks | Y32 |
| Y.27 | Secrets in hellos are marks | Y33 |
| Y.28 | The memory of skipped secrets | Y34 |
| Y.29 | Secrets from the phones | Y35 |
| Y.30 | `cbb copy` reads standard input | Y1 |
| Y.31 | `cbb paste` prints the clipboard | Y1, M3 |
| Y.32 | `cbb paste -terminal`, `-lines`, `-secret` | Y35, H3 |
| Y.33 | A device that joins reads copies from the next one on | Y36 |

## M. Sync on and off

| ID | Function | Cases |
|---|---|---|
| M.1 | Sync off | M1, M3 |
| M.2 | Sync on | M1 |
| M.5 | Deliberate actions with sync on and off | M2 |
| M.6 | Sync off kept and reported | M4 |
| M.7 | `cbb sync -on DEVICE` | M5 |
| M.8 | The phones' sync switch on a device's page | M5, A1 |
| M.9 | New devices with sync on | M6 |
| M.10 | The phones' automatic paths follow sync | M7 |
| M.11 | The lite member's `cbb sync` | M1 |
| M.12 | `cbb sync off [-for]` and `cbb sync on` on the device itself | M8 |
| M.13 | An admin mutes a device for the group (`cbb mute -on`, the `mute` and `unmute` commands) | M9 |
| M.14 | The group's copies setting (`cbb incoming`) | M10 |

## O. Images, files and formatted text

| ID | Function | Cases |
|---|---|---|
| O.1 | PNG and JPEG images | O1 |
| O.2 | TIFF and HEIC converted | O1 |
| O.3 | JPEG to PNG for a receiver that asks | O1 |
| O.4 | Files and folders | O2 |
| O.5 | The 10 000 entries limit | O2 |
| O.6 | Links and special files left out | O2 |
| O.7 | Names made safe | O2 |
| O.8 | Nothing executable; quarantine; Mark of the Web | O2 |
| O.9 | `cbb copy FILE...` and `-text` | O3 |
| O.10 | `cbb copy -type` | O3 |
| O.11 | `cbb paste -o DIR` | O3 |
| O.12 | HTML | O4 |
| O.13 | HTML size limits | O4 |
| O.14 | `cbb config max-copy` | O5 |
| O.15 | `cbb config max-copy-away` | O5, O10 |
| O.16 | A copy over the limit reported | O5 |
| O.17 | Text-only devices take the text | O6 |
| O.18 | Resuming a fetch | O7 |
| O.19 | A newer copy stops a fetch | O7 |
| O.20 | Chunk hashes | O7 |
| O.21 | The 15 s stall cancel | O7 |
| O.22 | Texts before media | O8 |
| O.23 | The media cache and its cleaning | O9 |
| O.24 | The agent's received folder | O9 |
| O.25 | Media away through the hub | O10 |
| O.26 | `missing` and retry | O10 |
| O.27 | The phones' share sheets | O11, A13 |
| O.28 | The phones save received files | O11 |
| O.29 | The phones serve their own copies | O11 |
| O.30 | Flatpak's document portal and FileTransfer | O12 |
| O.31 | Progress shown | O13 |
| O.32 | A copy passed on by a router's small memory | O14 |
| O.33 | Fetch limits and padding | O15 |

## T. Remote paste

| ID | Function | Cases |
|---|---|---|
| T.1 | `paste-receive on/off`, `-enter`, `-console` | T1 |
| T.2 | Off by default | T1 |
| T.3 | X11 XTEST | T2 |
| T.4 | wlroots' virtual keyboard | T2 |
| T.5 | The RemoteDesktop portal and its restore token | T2 |
| T.6 | The ei protocol | T2 |
| T.7 | The uinput helper | T2, T15 |
| T.8 | tmux, the user's and root's | T2, T6 |
| T.9 | The console helper (TIOCSTI) | T2, T6 |
| T.10 | Windows: Ctrl+V and SendInput | T3 |
| T.11 | The Mac app's target | T3, A4 |
| T.12 | The Android accessibility target | T4 |
| T.13 | The lite member's targets | T4 |
| T.14 | The Nano's USB keyboard | T4, T20 |
| T.15 | Exact text, layouts, sizes | T5 |
| T.16 | The clipboard put back after a paste | T5 |
| T.17 | A locked session refused | T6 |
| T.18 | Elevated windows, Secure Input, missing permissions refused | T6 |
| T.19 | Who may send | T7 |
| T.20 | Command expiry, clock and replay checks | T8 |
| T.21 | Rate limits | T9 |
| T.22 | Cleaning the text | T10 |
| T.23 | Secret pastes | T11 |
| T.24 | The target's notification and log | T12 |
| T.25 | Passing a paste on through a member and the hub | T13 |
| T.26 | Turning it off from afar | T14 |
| T.27 | Sending from the phones | T16 |
| T.28 | Android TV and TV Remote v2, `cbb remote add` | T17 |
| T.29 | Bluetooth keyboards | T18 |
| T.30 | Apple TV, Samsung, LG, Roku | T19 |
| T.31 | Keyboard layouts and the Nano's console | T20 |

## Q. Quick actions

| ID | Function | Cases |
|---|---|---|
| Q.1 | `cbb action` lists them | Q1 |
| Q.2 | `enable`, `disable` and the polkit rule | Q2 |
| Q.3 | lock | Q3 |
| Q.4 | sleep | Q3 |
| Q.5 | reboot and its minute | Q3 |
| Q.6 | shutdown | Q3 |
| Q.7 | cancel-shutdown | Q3 |
| Q.8 | restart the service | Q3 |
| Q.9 | Through the agent on macOS and Windows | Q3 |
| Q.10 | The lite member's presets | Q3 |
| Q.11 | `-by` and `-any-key` | Q4 |
| Q.12 | Own actions: `add`, `remove`, 15 s | Q5 |
| Q.13 | `cbb action -on DEVICE NAME` | Q6 |
| Q.14 | `cbb action off -on`, `-all` | Q7 |
| Q.15 | The apps' buttons | Q8 |

## W. Away from home

| ID | Function | Cases |
|---|---|---|
| W.1 | `cbb global on` | W1 |
| W.2 | `cbb global off`, `-yes` | W1 |
| W.3 | The systemd drop-in | W2 |
| W.4 | The Windows rule `cbb-home-only` | W2 |
| W.5 | The program's own limit on macOS | W2 |
| W.6 | `cbb global allow` | W2 |
| W.7 | Fail closed | W3, S9 |
| W.8 | `cbb global hub` with addresses and `-port` | W4 |
| W.9 | `-firewall ask/yes/no` and closing the port | W4 |
| W.10 | `-obfuscate` (AmneziaWG) | W4, W35 |
| W.11 | `-forwarder`, `-forwarder-key` | W4, W10 |
| W.12 | `-vless` | W4, W34 |
| W.13 | The router as the hub | W4 |
| W.14 | `cbb global` status | W5 |
| W.15 | The hub's offer | W5, W10 |
| W.16 | The order of a hub's addresses | W10 |
| W.17 | The hub's addresses change | W11 |
| W.18 | The hub's key and its next key | W12 |
| W.19 | The hub down or hung | W13 |
| W.20 | Several hubs, failover and back | W14 |
| W.21 | `cbb global move` | W15 |
| W.22 | The phone as the hub | W16 |
| W.23 | "This is my home network" | W16 |
| W.24 | The lite member as a client | W17 |
| W.25 | A client behind on obfuscation | W18 |
| W.26 | Client isolation | W19, S3 |
| W.27 | One port on the hub | W19, S4 |
| W.28 | Unknown WireGuard keys get nothing | W20, S5 |
| W.29 | A removed away device dropped | W21, S6 |
| W.30 | `cbb forward` and its registration | W30 |
| W.31 | `-records` and what the forwarder keeps | W30, W40 |
| W.32 | `-show-key`, `-key` | W31 |
| W.33 | The forwarder restarted or down | W31 |
| W.34 | The forwarder's limits | W32 |
| W.35 | Groups apart on one forwarder | W33 |
| W.36 | `-vless-site`, `-vless-listen` | W34 |
| W.37 | `cbb relay -group`, `-open` | W36 |
| W.38 | `cbb global relay` and its consent | W36 |
| W.39 | Relay credentials and pseudonyms | W37 |
| W.40 | The relay's limits | W38 |
| W.41 | Server credential periods | W39 |
| W.42 | Padded lists | W39 |
| W.43 | The servers keep nothing | W40, S18 |
| W.44 | The push sender | W41 |
| W.45 | Phones away: cbbtun and the loopback port | W42 |
| W.46 | Away on Android in the background | W42 |
| W.47 | A hub that only passes the copies on (`-forward-only`), and `cbb global hub off` | W43 |
| W.48 | The ways out carry only cbb | W44 |
| W.49 | A hub registers inside VLESS | W45, W46 |
| W.50 | VLESS over XHTTP behind a web server | W46 |
| W.51 | Updates through the forwarder's mirror over VLESS | W47 |
| W.52 | The project's relay follows its key and address from the signed lists | W48 |

## U. The command line, the control socket and errors

| ID | Function | Cases |
|---|---|---|
| U.1 | `cbb status` | U1 |
| U.2 | `cbb version`, `help`, `-h` | U2 |
| U.3 | The control socket's group | U3, S11 |
| U.4 | The admin socket | U3 |
| U.5 | The Windows socket's access list | U3 |
| U.6 | Errors in release mode | U4 |
| U.7 | Errors in debug mode, `CBB_DEBUG` | U4 |
| U.8 | The service stopped | U5 |
| U.9 | The service hung | U6, E11 |
| U.10 | Damaged state files | U7 |
| U.11 | A full disk | U8 |
| U.12 | `cbb watch`, `-0` | U9 |
| U.13 | `cbb next` | U9, H12 |
| U.14 | Logs without secrets | U10, S15 |
| U.15 | The control socket's operations and framing | U11 |
| U.16 | The watcher protocol | U11 |
| U.17 | One agent per session | U11, H2 |
| U.18 | The apps' "Show error details" | U12 |
| U.19 | The lite member's global flags | U13 |
| U.20 | `CBB_SOCKET`, `CBB_STATE` | U13 |
| U.21 | `cbb service` and `cbb agent` by hand | U2, H2 |

## H. Platforms

| ID | Function | Cases |
|---|---|---|
| H.1 | GNOME | H1 |
| H.2 | KDE | H1 |
| H.3 | sway and Hyprland | H1 |
| H.4 | X11 desktops | H1 |
| H.5 | The Linux agent's life | H2 |
| H.6 | tmux's copy mode and paste key | H3 |
| H.7 | The text console | H4 |
| H.8 | The lite member's options | H5 |
| H.9 | The container | H6 |
| H.10 | Windows sessions | H7 |
| H.11 | Windows on ARM and x64 | H7 |
| H.12 | macOS Local Network | H8 |
| H.13 | Universal Clipboard | H8, Y15 |
| H.14 | The pasteboard privacy alert | H8 |
| H.15 | OpenWrt: procd, UCI, keep.d, GOMEMLIMIT | H9 |
| H.16 | FreeBSD and OPNsense | H10 |
| H.17 | The Nano ESP32 | H11 |
| H.18 | The ZX Spectrum Next | H12 |
| H.19 | Android TV | H13 |
| H.20 | The Steam Deck's Game Mode | H14 |
| H.21 | The iPad and big screens | H15 |

## A. The apps

| ID | Function | Cases |
|---|---|---|
| A.1 | The iPhone app's screens | A1 |
| A.2 | The Android app's screens | A2 |
| A.3 | Android's foreground service | A2, M7 |
| A.4 | Android's accessibility send | A2, M7 |
| A.5 | The Apple Watch app | A3 |
| A.6 | The Wear OS app | A3 |
| A.7 | The watches' emergency actions | A3, G38 |
| A.8 | The Mac app | A4 |
| A.9 | The Mac app's admin actions | A4 |
| A.10 | The tray app on Linux | A5 |
| A.11 | The tray app on Windows | A5 |
| A.12 | Notifications of the group's events | A6 |
| A.13 | The Dynamic Island | A7 |
| A.14 | Collections and the order of tiles | A8 |
| A.15 | Languages and right-to-left | A9 |
| A.16 | Accessibility labels | A9 |
| A.17 | The F-Droid flavour | A10 |
| A.18 | Background app refresh | A11 |
| A.19 | App Intents, widgets, the Control Center control | A12 |
| A.20 | The share extension | A13 |
| A.21 | First launch and the Start screen | A14 |
| A.22 | Themes and layouts | A15 |
| A.23 | Plain-language paths | A16 |
| A.24 | Add a device: camera and six digits | A1, G3 |
| A.25 | The Aurora OS app: join by QR, sync in front, leave | A17 |

## S. Security

| ID | Function | Cases |
|---|---|---|
| S.1 | Nothing readable on the internet path | S1 |
| S.2 | Nothing readable on the LAN | S2, S21 |
| S.3 | The invitation file | S7 |
| S.4 | What the relay and forwarder learn | S8 |
| S.5 | The installers' rules | S12 |
| S.6 | A stranger at home | S14, S21 |
| S.7 | Files at rest | S16 |
| S.8 | Commands replayed or changed | S17, S23 |
| S.9 | Robustness against fuzzed frames | S20 |
| S.10 | Signed releases checked on the devices | S22 |
| S.11 | A stolen admin computer | S24 |
| S.12 | Copies sealed end to end: no device in between reads them | S25 |
| S.13 | Commands sealed for their receiver | S26 |

## E. Load, concurrency and faults

| ID | Function | Cases |
|---|---|---|
| E.1 | Latency | E1 |
| E.2 | Throughput | E2 |
| E.3 | Many members | E3 |
| E.4 | Big transfers at once | E4 |
| E.5 | Many local clients | E5 |
| E.6 | The hub under load | E6 |
| E.7 | A bad network | E7 |
| E.8 | A blocked member port | E8 |
| E.9 | Restarts at random | E9 |
| E.10 | Days of running | E10 |
