<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Command reference

For users and administrators running `cbb` from the command line on Linux, macOS, Windows,
FreeBSD, OpenWrt, OPNsense, or small devices. This page lists every `cbb` command, flag, and
installer option.

Run `cbb help` for a short summary of the installed version and `cbb version` to print the version,
platform, and core ABI.

## Sockets, permissions, and language

All commands except `service`, `agent`, `forward`, `relay`, `install`, `confirm-setup`,
`own-command`, `version`, and `help` talk to the running `cbb` service over local sockets:

- **Control socket**: Used by everyday operations (`copy`, `paste`, `watch`, `status`, `config`,
  `sync` on this device, and `agent`). Members of the `cbb` group (`_cbb` on macOS) access it
  without `sudo`.
- **Admin socket**: Used by commands that change the group or device settings (`new`, `pair`,
  `invite`, `remove`, `rename`, `admin`, `keys`, `ttl`, `recovery`, `freeze`, `unfreeze`,
  `resolve`, `leave`, `mute`, `unmute`, `sync -on`, `paste-receive`, `action`, `keyboard`,
  `remote`, `network`, and `global` changes). Only root (or an administrator on Windows) reaches
  the admin socket directly.
- **Interactive confirmation**: On Linux (polkit), macOS (Touch ID or password), and Windows
  (Windows Hello), running an admin command without administrator rights sends it over the control
  socket and triggers the system confirmation prompt. Commands that modify system files, firewall
  rules, or services (`global on`, `global allow`, `global off`, `global hub`, `global move`,
  `update`, `action enable` for polkit rules on Linux, `confirm-setup`, `confirm-key`, and
  `install`) still require `sudo` or an administrator terminal.

`cbb` accepts flags with one or two leading dashes (`-flag` or `--flag`).

`cbb` translates its prompts and output using the locale environment variables (`LANGUAGE`,
`LC_ALL`, `LC_MESSAGES`, `LANG`, following gettext precedence) into Arabic (`ar`), Chinese (`zh`),
Hebrew (`he`), Hindi (`hi`), Russian (`ru`), Spanish (`es`), and Swahili (`sw`), falling back to
English (`member/l10n/<language>.json`). Command names, flags, service logs, and errors returned by
the service stay in English.

## Global flags

Place global flags before the command name:

| Flag | Environment variable | Meaning |
|---|---|---|
| `-state DIR` | `CBB_STATE` | Override the state directory. |
| `-socket PATH` | `CBB_SOCKET` | Override the control socket path. |
| `-debug` | `CBB_DEBUG=1` | Print underlying error details under error messages. |

## cbb

Commands are listed in alphabetical order.

| Command | What it does |
|---|---|
| `cbb action` | Lists this device's quick actions (presets `lock`, `sleep`, `reboot`, `shutdown`, `cancel-shutdown`, `restart`, `keyboard-layout`, plus custom actions) and who may run each. All actions are off by default. |
| `cbb action add NAME [-by root,phone,computer,watch] [-any-key] [-yes] -- PROGRAM [ARGS...]` | Adds a custom quick action on this device. The signed-in user's session agent runs `PROGRAM` (full path, exact arguments, no shell) and returns only its exit status; the program must exit within 15 s. `-by` restricts which admin kinds can run it, `-any-key` allows file-backed admin keys, and `-yes` skips the confirmation prompt. |
| `cbb action disable NAME` | Disables quick action `NAME` on this device and removes polkit rights not needed by remaining enabled actions on Linux. |
| `cbb action enable NAME [-by root,phone,computer,watch] [-any-key] [-yes]` | Enables quick action `NAME` on this device (requires `sudo` on Linux for actions that write `/etc/polkit-1/rules.d/60-cbb.rules`). Prints what the action allows and asks for `yes` unless `-yes` is passed. `-by` restricts admin kinds; `reboot` and `shutdown` require hardware-backed admin keys unless `-any-key` is passed. `reboot` and `shutdown` wait 1 minute (`cancel-shutdown` aborts them). |
| `cbb action off [-on DEVICE \| -all]` | Disables all quick actions on this device, or on an admin disables them on `DEVICE` or on every device (`-all`). Only each device's own user can re-enable them. |
| `cbb action -on DEVICE NAME` | On an admin: runs quick action `NAME` on `DEVICE` (by name or device ID) using a signed command. |
| `cbb action remove NAME` | Removes custom quick action `NAME` on this device. |
| `cbb admin [-allow-file-key] NAME` | On the main device (*root*): makes `NAME` (name or device ID) an admin using the admin key it offered when pairing with the main device. A device with file-backed keys requires the group key level `files` (`cbb keys`) and `-allow-file-key`. A container offers no admin key unless `CBB_KEYS_IN_FILE=yes` ([Settings and environment variables](config.md)); a rootless member never offers one. |
| `cbb config [max-copy\|max-copy-away SIZE]` | Shows or sets the maximum size of images and files this device sends or fetches: `max-copy` at home (default `100MiB`, range `1MiB` to `1GiB`) and `max-copy-away` through the tunnel (default `25MiB`, at most `max-copy`). Accepts `KiB`, `MiB`, `GiB` (and `KB`, `MB`, `GB`). |
| `cbb copy [-secret]` | Sends standard input (up to 1 MiB of UTF-8) to the group and this device's clipboard. `-secret` marks it as a secret (memory only, expires after the group's secret lifetime, 60 s by default). |
| `cbb copy [-text TEXT] [-type png\|jpeg\|gif\|html] FILE...` | Sends files and folders to the group and this device's clipboard up to `max-copy`. Recursively includes folders, skips links and special files, and sanitizes names across operating systems. `-text` attaches plain-text fallback. `-type` (`png`, `jpeg`, `jpg`, `gif`, `html`, or their MIME types) sends a single file as typed clipboard data. |
| `cbb forward [-listen ADDRESS:PORT] [-key FILE] [-state FILE] [-records DIR] [-refused FILE] [-show-key] [-vless-xhttp NAME [-vless-path PATH] [-vless-port N] [-vless-listen ADDRESS:PORT]] [-vless-mirror ADDRESS:PORT]` | Runs a forwarder (`cbb-forward` beside `cbb`) on a public server for hubs behind NAT (default `:8764`, UDP and TCP). Holds no group keys. `-key` sets the key file (default `forwarder.pem` in `STATE_DIRECTORY` or the state directory); `-show-key` prints its pin and exits. `-state` sets the credential version state file (default `forward-state.json` next to the key; `none` for memory only). `-records` removes unused per-group files from `DIR` (default `groups` next to the key). `-refused` sets the refused-groups file, reloaded within 10 s of changes (default `refused-groups` next to the key if present; `none` disables). `-vless-xhttp NAME` enables VLESS over XHTTP behind the site's web server (`-vless-port`, default `443`; `-vless-path`, generated and saved in the key file by default; `-vless-listen`, default `127.0.0.1:3276`). `-vless-mirror` exposes a local release mirror over VLESS to clients of registered hubs. See [Running your own servers](../admin/self-hosting.md). |
| `cbb freeze NAME` | On an admin: freezes admin computer `NAME` (name or device ID). Records it signed before the freeze remain valid; later signatures are ignored and members refuse its connections until the main device unfreezes or removes it. Cannot freeze the main device, an admin phone, or a non-admin device. |
| `cbb global` | Shows sync away from home status on this device: on or off, hub, tunnel, relay, and system network limit status. |
| `cbb global allow` | Updates the system outbound network limit (systemd drop-in on Linux, `cbb-home-only` Windows Firewall rule on Windows) to match the group's current hub, forwarder, or relay addresses. Requires `sudo` on Linux or administrator on Windows. Revokes outbound exceptions when sync away from home is off or the device is not in a group. |
| `cbb global entries [export [-qr] \| import STRING]` | Shows the signed entry points held by this device for the project's forwarders and VLESS paths ([Protocol](../protocol.md), section 16, "Entry points"). `export` prints them as a `cbb-entries:` string (`-qr` prints a QR code); `import STRING` verifies and stores them under the pinned release keys. |
| `cbb global hub [-away-on] [-keep] [-port N] [-firewall ask\|yes\|no] [-no-obfuscate] [-forwarder default\|ADDRESS:PORT -forwarder-key KEY] [-no-vless] [ADDRESS:PORT...]` | Makes this device a hub, reached directly at `ADDRESS:PORT...`, through a forwarder, or both (defaults to `-forwarder default`, the project's forwarder at `cbb.tools:8764`, when no address or forwarder is given and `-keep` is not set). `-port` sets the UDP tunnel listen port. Uses AmneziaWG and VLESS (with a forwarder) by default; `-no-vless` disables VLESS, and `-no-obfuscate` disables AmneziaWG. `-keep` retains existing addresses, port, and forwarder when changing obfuscation flags. `-firewall` controls opening the hub UDP port (`ask` by default, `yes` without prompting, `no` prints commands). `-away-on` enables sync away from home first after confirmation. |
| `cbb global hub off [-on DEVICE] [-yes]` | Stops this device from acting as a hub, or on an admin stops `DEVICE`. Connected clients move to the next hub. Refuses to stop the group's only hub unless `-yes` is passed. |
| `cbb global hub -on DEVICE [-forward-only] [-forwarder default\|ADDRESS:PORT -forwarder-key KEY] [ADDRESS:PORT...]` | On an admin: makes `DEVICE` (an admin computer with sync away from home enabled) a hub using the given addresses or forwarder (`default` when omitted). With `-forward-only` (main device only), makes any non-admin computer a forwarding-only hub that passes sealed copies without reading, creating, or pasting them, and exempt from the group's key level. |
| `cbb global hubs NAME...` | On the main device or a hub-capable admin: sets 1 to 16 primary hubs (by name or device ID) in priority order ([Protocol](../protocol.md), section 11, "Several hubs"). The main device's list takes precedence over an admin's. |
| `cbb global move DEVICE [-forwarder default\|ADDRESS:PORT -forwarder-key KEY] [ADDRESS:PORT...]` | On a computer hub (requires `sudo` or administrator): hands the hub role to `DEVICE` (a hub-capable computer with sync away from home enabled), keeping this hub's forwarder unless `-forwarder` is specified. Continues serving away clients for up to 5 minutes after the new hub starts serving, then switches to a client. |
| `cbb global off [-yes]` | Turns sync away from home off on this device, deletes tunnel keys, and restores the home-only outbound network limit (requires `sudo` on Linux or administrator on Windows). Prompts for confirmation when connected only through the tunnel unless `-yes` is passed. |
| `cbb global off -on DEVICE` | On an admin: turns sync away from home off on `DEVICE` and clears its tunnel keys. |
| `cbb global on` | Turns sync away from home on for this device after confirming the key-storage notice, and updates the system outbound network limit (requires `sudo` on Linux or administrator on Windows). |
| `cbb global relay default \| ADDRESS:PORT -key KEY [ADDRESS:PORT -key KEY...] [-yes]` | On the main device: configures 1 to 16 blind relays in the group's settings for syncing without a hub. `default` selects the project's open relay (`cbb.tools:8765`) without `-key`. Displays what a relay can observe and prompts for `yes` unless `-yes` is passed. |
| `cbb global relay off` | On the main device: removes all blind relays from the group's settings. |
| `cbb handover NAME` | Unavailable: changing the main device requires the recovery key (`cbb recovery`). Returns an error pointing to `cbb recovery` ([Decisions](../decisions.md), D-117). |
| `cbb help` | Prints the short command summary (also `-h`, `-help`, `--help`). |
| `cbb install [options]` | Windows only: runs `packaging\windows\install.ps1` beside `cbb.exe` in an administrator terminal, forwarding installer options (for example `-Express`, `-Port N`, `-HomeCgnat on`). Use after `winget install` or `winget upgrade`. |
| `cbb invite [-phone] [-for DURATION] [-o FILE \| -app FILE -answers FILE] [-hub DEVICE]` | On the main device or an admin: creates a single-use remote invitation through this hub or a connected hub (`-hub` picks a specific hub). By default creates a computer invitation file (`cbb.cbbinvite`, overridden by `-o`); with `-phone` prints a QR code for a phone app. Valid for `1h` by default, up to `24h` (`-for`). Waits for the joining device, displays its key fingerprint, and admits it after you type `yes`. `-app` and `-answers` provide JSON status and answer files for desktop apps. |
| `cbb keyboard [on [-layout us\|ru] [-rate N] [-pastes] \| off \| pair \| type [TEXT]]` | Linux only (requires `cbb-helper` and BlueZ 5.50+ with Bluetooth 4.0+): turns this computer into a Bluetooth LE keyboard. With no arguments, shows current status. `on` registers the keyboard (`-layout` defaults to `us`; `-rate` sets 5 to 60 characters/s, default 20; `-pastes` routes incoming remote pastes to the Bluetooth keyboard). `pair` makes the keyboard discoverable for 2 minutes. `type` sends `TEXT` or standard input (up to 4,096 characters). `off` disables it. |
| `cbb keys [proven\|hardware\|files]` | Shows the group's key level, or on the main device sets it ([Keys and attestation](../guide/keys.md#the-three-levels)): `proven` (attested hardware keys only), `hardware` (hardware keys, default), or `files` (file keys allowed after a warning). Cannot set a level that the main device's own key does not satisfy. Existing admins or hubs below the new level are listed and remain until removed or demoted. |
| `cbb leave [-yes]` | Leaves the group: deletes this device's keys and group files, disables remote paste and quick actions, preserves other settings, and restarts the service outside any group. `-yes` skips the confirmation prompt. The main device can leave only when it is the sole device. |
| `cbb mute -on DEVICE [-for DURATION]` | On an admin: mutes `DEVICE` (name or device ID, including this device) for `DURATION` (`1ms` to `720h`) or until an admin runs `cbb unmute -on DEVICE`. Copies from a muted device do not reach the group. |
| `cbb new` | Creates a new group with this computer as the main device (*root*), prints the recovery sheet and QR code once, and stores the root key (in TPM or Secure Enclave when available, otherwise in a file). |
| `cbb pair [-admin] [-app FILE]` | In a group, on the main device or an admin: opens a 5-minute pairing window (closed after 3 wrong code attempts) showing a 6-digit code, QR code, and QR text. `-admin` (main device only) admits a joining phone as an admin. `-app FILE` writes JSON status updates to an existing regular file for desktop apps (removing `FILE` closes the window). `-qr` is unavailable and returns an error pointing to `cbb pair` ([Decisions](../decisions.md), D-119). |
| `cbb pair -code [ADDRESS:PORT] [-name NAME] [-caps LIST]` | Outside a group: joins an open pairing window by reading its 6-digit code or QR text from standard input. Discovers the window by mDNS unless `ADDRESS:PORT` is given (where the QR text replaces the 6 digits). `-name` sets the device name; `-caps` sets a comma-separated subset of `admin`, `dials`, `hub` (or `none`; all three by default). |
| `cbb pair -invite FILE\|- [-app FILE] [-name NAME] [-caps LIST]` | Outside a group: joins from afar through a hub's guest tunnel using an invitation file, or with `-` by reading `cbb://join#...` from standard input. Turns sync away from home on after confirmation, displays this device's key fingerprint, and waits for admin approval. `-app FILE` writes JSON fingerprint and completion status for desktop apps. Requires `sudo` on Linux or administrator on Windows to update outbound network limits. |
| `cbb paste [-terminal [-lines] [-secret]]` | Prints this device's clipboard text (or the group's latest text while sync is off). `-terminal` strips C0 control characters (except tab and line feed), DEL, and C1 control characters, trims trailing line feeds, keeps only the first line unless `-lines` is passed, and refuses secrets unless `-secret` is passed. |
| `cbb paste -o DIR` | Saves images, HTML, or files from the clipboard (or from the group while sync is off) into existing folder `DIR` and prints the top-level paths written. Saves images as `image.png`, `image.jpg`, or `image.gif`, and HTML as `clipboard.html`. Never overwrites existing files and sets non-executable permissions. |
| `cbb paste -on DEVICE [-type] [-enter] [-secret]` | On an admin: sends standard input (up to 1 MiB) or this device's clipboard (when standard input is a terminal) into the focused app or tmux pane on `DEVICE` where remote paste is enabled. `-type` types key by key (up to 4 KiB), `-enter` presses Enter where allowed, and `-secret` sends as a secret (not logged, clipboard cleared afterward). |
| `cbb paste -on DEVICE [-enter] [-image] FILE...`, `cbb paste -on DEVICE [-enter] -copy` | On an admin: sends files or folders (`-image` sends one `.png`, `.jpg`, or `.jpeg` file as an image) to the group, or uses the group's current media copy (`-copy`), and pastes it into the focused desktop app on `DEVICE`. |
| `cbb paste-receive [on [-enter] [-console] [-no-lock-check] \| off [-on DEVICE \| -all]]` | Shows or toggles remote paste on this device. `on` allows admins to paste here; `-enter` allows pressing Enter, `-console` allows Linux text console and root's tmux, and `-no-lock-check` allows pasting on Linux/FreeBSD when logind does not report lock state (running screen lockers still block pastes). On an admin, `off -on DEVICE` or `off -all` disables remote paste remotely. |
| `cbb recovery [-leave NAME]... [-yubikey]` | Replaces a lost main device (*root*): reads the recovery key (sheet text or QR text) from standard input without echo, or reads the YubiKey PIN and unseals the recovery key from a retired PIV slot with `-yubikey` (requires `pcscd` on Linux and FreeBSD), and makes this computer the new main device immediately. `-leave NAME` (repeatable) removes listed devices from the group. |
| `cbb relay (-group GROUP[,GROUP...] \| -open) [-listen ADDRESS:PORT] [-key FILE] [-refused FILE] [-show-key]` | Runs a blind relay (`cbb-relay` beside `cbb`) on a public server (default `:8764`, UDP and TCP). `-group` serves listed groups in `ROOT:RECOVERY:RECOVERY2` hex format (from `cbb status -relay`); `-open` serves any registering group within per-group and per-network limits. `-key` sets the key file (default `relay.pem` in `STATE_DIRECTORY` or the state directory); `-show-key` prints the key pin and exits. `-refused` sets the refused-groups file, reloaded within 10 s of changes (default `refused-groups` next to the key if present; `none` disables). See [Running your own servers](../admin/self-hosting.md). |
| `cbb remote [add [-appletv \| -roku -consent] [-name NAME] ADDRESS \| code \| cancel \| remove TV \| pastes TV on\|off \| type [-tv TV] [TEXT]]` | Controls TVs on the home network (requires `cbb-helper`). With no arguments, lists paired TVs. `add` pairs with an Android TV or Google TV at `ADDRESS` (ports 6466/6467), an Apple TV with `-appletv` (port 49153, requires Allow Access set to Everyone on the Same Network), or a Roku with `-roku -consent` (plain HTTP port 8060, requires Control by mobile apps enabled). `-name` sets a display name. `code` reads the TV's pairing code or PIN from standard input within 2 minutes; `cancel` aborts pairing. `pastes TV on\|off` routes remote pastes to that TV (one TV at a time). `type` sends `TEXT` or standard input (select TV with `-tv` when multiple exist). `remove` forgets a TV. Addresses outside the home network are refused. |
| `cbb remove NAME` | On an admin: removes `NAME` (name or device ID) from the group with a signed revocation record. Only the main device or an admin phone can remove an admin; an admin computer removes ordinary members only. |
| `cbb rename NAME NEW-NAME` | On an admin: renames `NAME` (name or device ID) to `NEW-NAME` (1 to 64 characters) across the group. |
| `cbb resolve` | On the main device: voids both conflicting histories of any key that signed two divergent histories (`cbb status` lists them). The key resumes from the record before the fork. |
| `cbb status [-relay]` | Prints version, available updates, this device's role and key level, sync and mute state, away-from-home state, media size limits, connectivity warnings, and the group's device table (OS, version, role, last seen, clock skew). `-relay` prints only the group's `ROOT:RECOVERY:RECOVERY2` hex tag for `cbb relay -group`. |
| `cbb sync [on \| off [-for DURATION]]` | Shows or toggles clipboard sync on this device (`on` by default). `off` isolates this clipboard for `DURATION` (`1ms` to `720h`) or until `cbb sync on`; while off, `cbb paste` prints the group's latest text and `cbb copy` still sends. |
| `cbb sync -on DEVICE on\|off` | On an admin: sets clipboard sync on or off on connected device `DEVICE` with a signed command. |
| `cbb takeover NAME`, `cbb takeover -delay DURATION` | Unavailable: changing the main device requires the recovery key (`cbb recovery`). Returns an error pointing to `cbb recovery` ([Decisions](../decisions.md), D-117). |
| `cbb ttl [COPY [SECRET]]` | Shows or sets group-wide copy lifetimes (requires main device or admin to change): ordinary copies `1m` to `1h` (default `5m`), secrets `5s` to `1m` (default `1m`). Use `-` to keep one value unchanged (for example `cbb ttl - 30s`). |
| `cbb unfreeze NAME` | On the main device: ends every freeze on admin computer `NAME`. |
| `cbb unmute -on DEVICE` | On an admin: ends the mute on `DEVICE`. |
| `cbb update [-check \| -timer \| -auto [on\|off] \| -mirror [URL\|default] \| -installed-by get\|brew\|winget\|docker\|package]` | Checks for or installs the newest signed release on the `stable` channel (requires `sudo` or administrator except `-check`; rootless installs update as the owning user). Automatically rolls back if the updated service does not report healthy within 1 minute. `-check` checks without installing. `-timer` runs scheduled daily checks and logs to `update.log`. `-auto` shows (`on`, `off`, `unset`) or sets daily automatic updates. `-mirror` shows or sets an `https://` release mirror (`default` restores GitHub with `dl.cbb.tools` fallback). `-installed-by` records the installation method (run by installers; non-`get` installations print their package manager's update command instead of self-updating). |
| `cbb version` | Prints the `cbb` version, platform, build notes, and Rust core version and ABI (also `-version`, `--version`). |
| `cbb watch [-0]` | Streams incoming text copies from the group to standard output, terminated by a newline (or a NUL byte with `-0`). |

### Rarely needed

System service managers, desktop sessions, and installers normally run these commands. Run them by
hand only for debugging or custom setups.

| Command | What it does |
|---|---|
| `cbb agent` | Connects the desktop clipboard (macOS pasteboard, Windows clipboard, Linux Wayland or X11) to the service. Started automatically at desktop sign-in (`cbbw.exe agent` on Windows; `cbb-agent.service` or XDG autostart on Linux; LaunchAgent on macOS). Only one instance runs per session. |
| `cbb confirm-key SID KEY`, `cbb confirm-key -remove SID` | Windows only (administrator): registers or removes a user's Windows Hello public key (RSA, at least 2048 bits) for confirming admin actions. Invoked automatically by `cbb` through UAC. |
| `cbb confirm-setup [USER]` | Linux and macOS (root): writes polkit action definitions on Linux (owned by `USER`, default `cbb`) or macOS authorization rights for interactive admin confirmation. Run by the installers. |
| `cbb network` | Marks the networks this computer is currently connected to as known home networks where the service advertises and accepts connections. Needed only if a router change leaves all home devices in quiet mode (`cbb status` prints `Quiet on`). |
| `cbb own-command NAME -- [COMMAND...]` | Internal helper invoked by `cbb action add` and `cbb action remove` under `sudo` as the invoking user to write or clear `own-actions.json` in that user's config directory. |
| `cbb paste-helper tmux\|console\|uinput` | Runs a remote paste target helper on Unix: `tmux` (started by `cbb`'s `tmux.conf`), `console` (Linux text console, run as root by `cbb-console.service`), or `uinput` (executes `cbb-helper uinput`, run as root by `cbb-uinput.service`). |
| `cbb service [-name NAME] [-state DIR] [-socket PATH] [-user USER] [-port PORT] [-peer HOST:PORT]... [-no-mdns] [-no-listen] [-tunnel-via HOST:PORT] [-caps LIST]` | Runs the background service (normally started by systemd, launchd, rc.d, procd, or Windows Service Manager). `-name` sets the device name; `-state` and `-socket` override paths; `-user` drops privileges to `USER` after opening mDNS sockets as root (FreeBSD rc.d); `-port` sets the member port; `-peer` (repeatable) dials explicit home peers without mDNS; `-no-mdns` disables mDNS; `-no-listen` disables listening on the member port; `-tunnel-via` forwards tunnel UDP packets through a local address (`cbb next link -udp`); `-caps` advertises a comma-separated subset of `admin`, `dials`, `hub` (or `none`). |

## Without cbb-helper

Small devices installed without `cbb-helper` (`get.sh --no-helper`; see
[Small devices](../../member/README.md)) run the same `cbb` binary, paths, and service. Commands
that require `cbb-helper` report that the helper is missing: `cbb keyboard`, `cbb remote`,
`cbb paste-helper uinput`, TPM and Secure Enclave keys, and hardware attestations.

In addition to `cbb pair -code` and `cbb service` flags above, `cbb` provides commands for the ZX
Spectrum Next ([ZX Spectrum Next](../../member/README.md#zx-spectrum-next)):

| Command | What it does |
|---|---|
| `cbb next check-list FILE` | Verifies a signed `keys.json` + `zxnext.json` bundle against pinned release roots and outputs `CBBL` entries for `.cbb update`. |
| `cbb next copy [-secret] LEN CRC32` | Reads `LEN` bytes in the Spectrum character set from standard input, verifies IEEE CRC-32, and copies the text to the group (`-secret` marks it as a secret). |
| `cbb next image [-mode auto\|lo\|hi] [-tape]` | Converts the latest PNG or JPEG clipboard image to ZX Spectrum Next Layer 2 format (`lo`: 320×256 256-color; `hi`: 640×256 16-color; `auto` chooses automatically). `-tape` plays the image as tape audio via `aplay`. |
| `cbb next link -to HOST:PORT [-port PORT] [-serve ESP-PORT:LOCAL-PORT] [-udp LOCAL-PORT:HOST:PORT] [-zone +HH:MM] [-join CODE [-window ID -fp HASH]] [-paste on\|on-enter\|off] [-log FILE] [-trace]` | Bridges `cbb` traffic over the Next's UART and ESP8266. `-to` names the home peer to dial through local TCP `-port` (default `8769`); `-serve` exposes a local port via the ESP; `-udp` relays tunnel UDP packets for `-tunnel-via`; `-zone` sets the UTC offset; `-join` (with optional `-window` and `-fp`) joins a pairing window; `-paste` configures remote paste into the Next; `-log` writes logs to a file; `-trace` enables protocol trace output. |
| `cbb next paste [-max BYTES]` | Outputs the latest clipboard text in the Spectrum character set as a `CBB1` frame (truncated to `BYTES` when `-max` is given). |
| `cbb next speed BAUD BYTES`, `cbb next speed-in BAUD BYTES` | Runs UART baud-rate integrity tests (`115200` to `2000000` baud on Linux, up to 1 MiB) in each direction. |

## Installers

| Installer | Options |
|---|---|
| `get.sh` (Linux, OpenWrt, macOS, FreeBSD) | Downloads the platform archive, verifies `SHA256SUMS` and release signatures, and runs the archive's `install.sh`. Pass options after `sh -s --`: `--express` (add firewall rules without asking), `--no-firewall` (add no rules, print commands), `--port N` (member port, 1024–65535), `--home-cgnat on\|off` (treat `100.64.0.0/10` as home network), `--auto-update on\|off` (daily self-updates), `--no-helper` (Linux: omit `cbb-helper`), `--no-pair` (skip automatic pairing on devices without the helper), `--console` (Linux: enable console tmux and `cbb-console`), `--uinput` (Linux with helper: enable `cbb-uinput`), `--rootless` (Linux, run without `sudo`: install for the current user only). Set `CBB_VERSION=vX.Y.Z` to install a specific release. |
| Linux `install.sh` (`packaging/linux`) | Installs binaries, systemd units, desktop agent/tray entries, and firewall rules (ufw, firewalld, nftables, iptables; persists answer in `/etc/cbb/firewall.answer`). Options: `--console`, `--uinput`, `--port N`, `--home-cgnat on\|off`, `--auto-update on\|off`, `--express`, `--no-firewall`, `--no-helper`, `--no-pair`, `--rootless`. Without `cbb-helper`, starts `cbb pair -code` at the end when output is a terminal unless `--no-pair` or `CBB_PAIR=no` is set. `--rootless` runs `install-rootless.sh` without `sudo` (`--port`, `--home-cgnat`, `--auto-update`, `--no-helper`, `--no-pair`; installs under `~/.local/bin`, `~/.config/cbb`, `~/.local/state/cbb` with systemd user units and no firewall, `--console`, or `--uinput`). |
| Linux `uninstall.sh` (`/usr/local/share/cbb/`, `/opt/cbb/share/` on SteamOS, or `~/.local/share/cbb/` for rootless) | Removes binaries, services, update timer, and installer-managed firewall rules. `--purge` also deletes keys and state (`/var/lib/cbb` or `~/.local/state/cbb`). |
| OpenWrt `install.sh` (`packaging/openwrt`) | Installs `/usr/bin/cbb`, user/group `cbb`, `/etc/init.d/cbb`, `/etc/config/cbb`, NTP hook, and sysupgrade keep list; firewall rules are managed dynamically by procd/fw4. Options: `--port N`, `--auto-update on\|off` (via cron), `--no-helper` (accepted, no helper on OpenWrt), `--no-pair`, `--express`, `--no-firewall` (accepted, rules are service-managed). Starts `cbb pair -code -name router` at the end when interactive unless `--no-pair` is set. |
| OpenWrt `uninstall.sh` (`/usr/share/cbb/`) | Stops the service (removing its dynamic firewall rules) and removes installed files and cron entry. `--purge` also deletes `/etc/cbb` (including keys). |
| FreeBSD `install.sh` (`packaging/freebsd`) | Installs `/usr/local/bin/cbb`, user/group `cbb`, rc.d script, `cbb_enable="YES"` in `rc.conf`, and pf anchor or ipfw rule set 17 (plus OPNsense plugin hook `cbb.inc` on OPNsense). Options: `--port N`, `--home-cgnat on\|off`, `--auto-update on\|off` (via cron), `--express`, `--no-firewall`. |
| FreeBSD `uninstall.sh` (`/usr/local/share/cbb/`) | Removes binaries, rc.d script, `rc.conf` entry, cron entry, and installer-managed firewall rules. `--purge` also deletes `/var/db/cbb`. |
| macOS `install.sh` (`packaging/macos` or `$(brew --prefix)/opt/cbb/share/cbb`) | Creates `_cbb` user/group, installs LaunchDaemon, LaunchAgent, and application firewall entry. Options: `--in-place` (Homebrew: run agent and CLI from their existing path while keeping a root-owned service binary under `/Library/Application Support/cbb/bin`), `--port N`, `--home-cgnat on\|off`, `--auto-update on\|off` (ignored with `--in-place`), `--express`, `--no-firewall`. |
| macOS `uninstall.sh` (`/usr/local/share/cbb/`) | Removes LaunchDaemon, LaunchAgent, authorization rights, firewall entry, and installed binaries (run before `brew uninstall`). `--purge` also deletes `/Library/Application Support/cbb`. |
| Windows `get.ps1` and `install.ps1` (`packaging/windows`) | `get.ps1` reads options from environment variables (`CBB_PORT`, `CBB_HOME_CGNAT`, `CBB_FIREWALL`, `CBB_AUTO_UPDATE`, `CBB_VERSION`, `CBB_ATTESTATION`, `CBB_VERIFY`, `CBB_ERROR_DETAILS`). `install.ps1` accepts `-Port N`, `-HomeCgnat on\|off`, `-AutoUpdate on\|off`, `-Express`, `-NoFirewall`, `-Details`, and `-Bin PATH`. Always installs the outbound home-only firewall rule. |
| Windows `uninstall.ps1` (`$env:ProgramFiles\cbb`, or Settings, Apps) | Removes service, agent, tray app, scheduled update task, PATH entry, and firewall rules. `-Purge` also deletes `ProgramData\cbb` and the local `cbb` group; `-Details` prints full error details on failure. |

## Environment variables

All `CBB_*` environment variables and settings files are documented in
[Settings and environment variables](config.md).
