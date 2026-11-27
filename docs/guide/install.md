<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Installing

For anyone installing, updating, verifying, or removing Connect Beyond Borders on a computer,
router, or home server. For phone, tablet, watch, and TV apps, see [The apps](apps.md).

Connect Beyond Borders runs as a small background service on each computer. Its command-line tool
is `cbb`. Every method below installs the same service; pick the one that fits your system.

## Linux

Supported on Linux systems with `systemd` on x86-64, ARM64, ARMv7, and ARMv6 (laptops, desktops,
Raspberry Pi boards, servers, and Steam Deck).

1. Run the installer in a terminal:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

2. Answer the prompts for firewall rules (when an active firewall is found) and daily automatic
   updates.
3. Log out and log back in once so your account (added to the `cbb` group) can run `cbb` without
   `sudo`.

On x86-64 and ARM64 desktops that have GTK 4 and WebKitGTK 6.0 installed (`libgtk-4-1
libwebkitgtk-6.0-4` on Debian and Ubuntu; `gtk4 webkitgtk6.0` on Fedora), the installer also
installs the tray app (`cbb-desktop`), which starts with your desktop session and appears in your
applications menu. If those libraries are missing, the installer names the packages to install;
re-run the installer after adding them to install the tray app.

You can pass extra options to `get.sh` after `sh -s --`:

- **Text console (`--console`):** For a machine without a desktop, adds copy and paste inside
  `tmux` and installs `cbb-console.service` for remote paste on the text console:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --console
  ```

- **Skip desktop paste dialogs (`--uinput`):** On GNOME and KDE, remote paste asks once in a
  system dialog before pressing keys. Adding `--uinput` installs `cbb-uinput.service` and loads
  the `uinput` kernel module so Connect Beyond Borders presses paste keys directly (never on a
  login or lock screen). This option requires `cbb-helper`.
- **Small devices without the helper (`--no-helper`):** Leaves out `cbb-helper` (the helper
  program that handles TPM keys, desktop clipboards, remote paste key injection, Bluetooth
  keyboards, and TV remotes) on small devices that only sync:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --no-helper
  ```

  See [Small devices](../../member/README.md). MIPS router archives leave out `cbb-helper` by
  default. Once a device is installed without `cbb-helper`, later updates keep it that way.

Homebrew on Linux (x86-64 and ARM64) is also supported:

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/linux/install.sh" "$(brew --prefix)/opt/cbb/bin/cbb"
```

Re-run the second command after each `brew upgrade`.

### Without sudo (rootless)

On a Linux computer where you do not have administrator rights (`sudo`), install Connect Beyond
Borders for your own user account without `sudo`:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

This installs `cbb` into `~/.local/bin` and runs it as a `systemd` user service while you are
logged in. It cannot be installed alongside a system-wide installation.

Use a rootless install only when a normal install is not possible. Because any program running
under your user account can read its key files, a rootless device can never be the **main
device**, an **admin**, or a **hub** ([rootless members](how-it-works.md#rootless-members)). A
rootless install also has no firewall rules, no TPM support, and no `--console` or `--uinput`
helpers.

- **Keep running after logout:** If the installer cannot enable lingering automatically, ask an
  administrator to run `sudo loginctl enable-linger YOUR-USER` once.
- **Without the helper:** Pass `--no-helper --rootless` to omit `cbb-helper` as well (see
  [without sudo on small devices](../../member/README.md#without-sudo-rootless)).
- **Remove:** Run `sh ~/.local/share/cbb/uninstall.sh`.

### SteamOS (Steam Deck)

1. Switch to **Desktop Mode** and open **Konsole**.
2. If you have not set a password for the `deck` user, run `passwd` to set one.
3. Run the Linux installer command:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

SteamOS replaces its root filesystem on every OS update, so the installer places Connect Beyond
Borders in `/opt/cbb` instead of `/usr/local` and registers its `/etc` configuration files in
`/etc/atomic-update.conf.d/cbb.conf`. Your installation and group membership persist across
SteamOS updates.

- After you log out and back in, `cbb` is on your `PATH` in Konsole. Because `sudo` does not
  search `/opt/cbb/bin`, commands that require `sudo` must use the full path, such as
  `sudo /opt/cbb/bin/cbb pair -code`.
- In Desktop Mode, the clipboard syncs as on any KDE Plasma desktop.
- In Game Mode, there is no desktop clipboard, so nothing syncs there; the service stays running
  and catches up when you return to Desktop Mode.
- To remove it, run `sudo sh /opt/cbb/share/uninstall.sh`.

## Mac

Supported on Apple silicon and Intel Macs running macOS 14 or later.

- **Installer package (recommended, includes the menu bar app):** Download `cbb-X.Y.Z.pkg` from
  the [latest GitHub release](https://github.com/HunterEwok/cbb/releases/latest) and open it. The
  package installs the **CBB** menu bar app (`/Applications/CBB.app`) and the background service,
  both signed and notarized.
- **Terminal (service and `cbb` only, without the menu bar app):**

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
  ```

- **Homebrew (service and `cbb` only, without the menu bar app):**

  ```sh
  brew install hunterewok/tap/cbb
  sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
  ```

  Re-run the second command after each `brew upgrade` to restart the service and pasteboard agent
  on the updated version.

## Windows

Supported on Windows 10 (version 1809 or later) and Windows 11, on x86-64 and ARM64.

1. Open PowerShell with **Run as administrator**.
2. Run the installer:

   ```powershell
   irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
   ```

3. Answer the prompts for Windows Firewall rules and daily automatic updates.
4. Open a new terminal window to use `cbb`.

The installer adds the signed-in user to the `cbb` group, starts the background service and
clipboard agent, and installs the tray app (started at sign-in and listed in the Start menu as
**CBB**). Commands that change group membership or settings run in an administrator terminal,
where Linux and macOS use `sudo`.

To install with **winget** (using the `HunterEwok.cbb` package):

```powershell
winget install HunterEwok.cbb
cbb install
```

Run `cbb install` in an administrator terminal to install the service, clipboard agent, tray app,
and firewall rules from the unpacked package, and run it again after each `winget upgrade`.

## OpenWrt

Supported on routers running OpenWrt 25.12 or later (using `apk`) with room for a 25 MB program
(at least 128 MB of flash or eMMC, and 256 MB of RAM).

Connect over SSH as `root` and run:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

The installer sets up `cbb` (without `cbb-helper`) as a `procd` service that listens on the `lan`
zone only and never answers on `wan`. Keys live in `/etc/cbb/state`, which `sysupgrade` keeps;
after an attended sysupgrade (ASU or `owut`), run the install command again. When run in an
interactive terminal, the installer starts pairing right away (`--no-pair` skips this). For
additional zones (such as an IoT network), firewall details, and checks, see
[Routers and FreeBSD](../admin/routers.md#openwrt).

You can also install from the project's `apk` package feed so `apk upgrade` keeps it updated:

1. Check your router's architecture with `grep DISTRIB_ARCH /etc/openwrt_release` and map it to
   the feed directory:
   - `aarch64_*` → `arm64`
   - `arm_cortex-a*` (with `neon` or `vfp` in the name) → `armv7`
   - `mipsel_*` → `mipsle`
   - `mips_*` → `mips`
   - `x86_64` → `amd64`
2. Add the feed key and repository (replace `arm64` with your architecture) and install:

   ```sh
   uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
   echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
   apk update && apk add cbb
   ```

`apk del cbb` removes the package and keeps the keys in `/etc/cbb`. Note that `mips` and `mipsle`
router builds sync on the home network only (no sync away from home).

## FreeBSD

Supported on FreeBSD 15 (`amd64` and `arm64`). Run as `root` (with `sudo` or `doas`):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

The installer installs `cbb`, adds an `rc.d` script that runs the service through `daemon(8)`,
and adds `cbb_enable="YES"` to `rc.conf`. Keys live in `/var/db/cbb` and settings in
`/usr/local/etc/cbb`.

- **OPNsense:** The same installer adds a plugin hook so the service appears under
  **System > Diagnostics > Services** and its firewall rules (in `pf` anchor `cbb`) persist
  across filter reloads. Turn off **Services > mDNS Repeater** while Connect Beyond Borders runs,
  because both need UDP port 5353 and the service answers mDNS on each home interface itself.
- **pfSense (unsupported):** The installer runs on pfSense, prints the rules to add manually
  under **Firewall > Rules**, and may be removed by a pfSense system update.
- **FreeBSD desktops:** On X11, or on Wayland compositors with the data-control protocol (such as
  KDE, sway, and Hyprland), XDG autostart launches `cbb agent` when you log in again. Remote
  paste uses XTEST on X11 and virtual keyboard on wlroots desktops; GNOME on FreeBSD does not
  accept remote paste because lock-screen status is unavailable without `logind`.

## Docker

For a NAS or an always-on home server without a desktop (see the
[Docker image README](../../packaging/docker/README.md)). A container joins as an ordinary
member; create the group on your phone or on a computer you hold.

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair -code
```

Open a pairing window on your phone or an admin computer first, then type the six digits when
`cbb pair -code` prompts for them.

## The firewall

Connect Beyond Borders needs incoming **TCP port 8764** (or your custom member port) and **UDP
port 5353** (mDNS), from your home network only.

The installer detects your firewall (`ufw`, `firewalld`, `nftables`, or `iptables` on Linux;
`pf`, `ipfw`, or OPNsense on FreeBSD; the macOS application firewall; Windows Firewall), lists
every rule it needs, and prompts `Add these rules now? [y/N]` (`Add this rule now? [y/N]` on
macOS):

- **Yes:** The installer adds the rules, keeps them updated on upgrades, and removes them on
  uninstall without changing any other rules.
- **No** (the default, and when no interactive terminal is attached): The installer adds no rules
  and prints the exact commands for you to run yourself.
- **Unattended options:**
  - On Linux, macOS, and FreeBSD: pass `--express` to add rules without asking, or
    `--no-firewall` to decline and print the commands.
  - On Windows: set `$env:CBB_FIREWALL = "express"` or `$env:CBB_FIREWALL = "no"` before running
    `get.ps1` (or pass `-Express` or `-NoFirewall` to `install.ps1`).

Firewall-specific behavior:

- `nftables` and `iptables` always print manual commands only, because runtime rules do not
  survive a reboot.
- FreeBSD `pf` places the rules in its own `cbb` anchor, loaded through three marked lines added
  to the end of `/etc/pf.conf` (removed on uninstall). FreeBSD `ipfw` adds them in rule set 17
  and reloads them on each start.
- If you enable a firewall after installing Connect Beyond Borders, run the installer again.

To use a different member port when TCP 8764 is already in use:

- On Linux, macOS, FreeBSD, and OpenWrt: pass `--port 9000` (for example,
  `... | sudo sh -s -- --port 9000`).
- On Windows: set `$env:CBB_PORT = "9000"` before running `get.ps1` (or pass `-Port 9000` to
  `install.ps1`).

All installer options are listed in the [command reference](../reference/cli.md#installers).

## Updating

Keep every device in a group on the same release. See
[Versions and compatibility](../reference/compatibility.md) for compatibility details.

### Manual updates

- **Installed with `get.sh`, `get.ps1`, or a release archive:**
  - Check for a newer release: `cbb update -check`
  - Install the newest signed release: `sudo cbb update` (on Windows, run `cbb update` in an
    administrator terminal; on rootless Linux, run `cbb update` without `sudo`; on SteamOS, run
    `sudo /opt/cbb/bin/cbb update`).

  `cbb update` keeps your settings and keys, installs only releases signed by the project, refuses
  older versions, and automatically restores the previous version if the updated service fails to
  start within one minute. Re-running the original `get.sh` or `get.ps1` command also updates.
- **Homebrew:** Run `brew upgrade cbb`, then re-run the `install.sh` command from the
  [Mac](#mac) or [Linux](#linux) section.
- **winget:** Run `winget upgrade HunterEwok.cbb`, then run `cbb install` in an administrator
  terminal.
- **Docker:** Run `docker compose -f compose.home.yaml pull` and recreate the container.
- **OpenWrt package feed:** Run `apk update && apk upgrade`.

### Automatic updates

For `get.sh` and `get.ps1` installations, the installer asks once whether to turn on daily
automatic updates. You can preset the answer or change it later:

- **During install:** Pass `--auto-update on` or `--auto-update off` to `get.sh`; on Windows, set
  `$env:CBB_AUTO_UPDATE = "on"` or `"off"` before running `get.ps1` (or pass `-AutoUpdate on|off`
  to `install.ps1`).
- **After install:** Run `sudo cbb update -auto on` or `sudo cbb update -auto off` (without
  `sudo` on rootless Linux; in an administrator terminal on Windows).

When automatic updates are on, a daily schedule checks for signed releases: a `systemd` timer on
Linux (user timer on rootless), a `launchd` job on macOS, a scheduled task as `SYSTEM` on
Windows, or `cron` on OpenWrt and FreeBSD.

Each check downloads small signed metadata files from GitHub (falling back to `dl.cbb.tools` if
GitHub does not answer). GitHub sees the device's IP address and that it requests Connect Beyond
Borders metadata, but nothing about your group. To use a custom mirror instead, run
`sudo cbb update -mirror https://...`; the mirror does not need to be trusted because signatures
are still verified.

Automatic update logs are written to `update.log` in:

| System | Update log directory |
|---|---|
| Linux | `/var/lib/cbb-update` |
| Linux (rootless) | `~/.local/state/cbb-update` |
| SteamOS | `/opt/cbb-update` |
| OpenWrt | `/etc/cbb-update` |
| FreeBSD | `/var/db/cbb-update` |
| macOS | `/Library/Application Support/cbb-update` |
| Windows | `C:\Program Files\cbb-update` |

Devices in a group share notices of the newest signed release any of them has seen, so
`cbb status` and the desktop apps notify you when an update is available. Each device still
verifies signatures itself and downloads its own archive.

## Checking a download

Every release archive is checked in three ways:

1. **Checksums (`SHA256SUMS`):** Both `get.sh` and `get.ps1` verify the downloaded archive
   against the release's `SHA256SUMS` file.
2. **Project release signatures:** Releases are signed with the project's offline root keys and
   release key (which never touch CI): `keys.json` certifies the release keys under the project's
   root keys, `release.json` lists each file's size and SHA-256 hash, and `stable.json` names the
   current stable release ([Protocol](../protocol.md), section 16). Both `get.sh` (using
   `openssl`) and `get.ps1` carry the project's built-in root keys and refuse to install any
   release whose signatures do not verify. `get.sh` checks both ES256 and SLH-DSA-SHA2-128s when
   OpenSSL 3.5 or later is installed (ES256 on older OpenSSL); `get.ps1` checks ES256. To install
   without checking project signatures, set `CBB_VERIFY=skip`.
3. **Build provenance attestation:** Every release file has a GitHub build provenance attestation
   tying it to this repository's release workflow. With the [GitHub CLI](https://cli.github.com/)
   (`gh`), you can verify any file manually:

   ```sh
   gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
   ```

   Both `get.sh` and `get.ps1` run this check automatically when `gh` is installed and signed in
   (`gh auth login`; for `get.sh` under `sudo`, run `sudo gh auth login`). Set
   `CBB_ATTESTATION=require` to refuse installation without a verified attestation, or
   `CBB_ATTESTATION=skip` to skip the attestation check.

## Removing it

Run the uninstall command for your system:

| System | Command or steps |
|---|---|
| Linux and macOS | `sudo sh /usr/local/share/cbb/uninstall.sh` |
| Linux (rootless) | `sh ~/.local/share/cbb/uninstall.sh` |
| SteamOS | `sudo sh /opt/cbb/share/uninstall.sh` |
| FreeBSD | `sudo sh /usr/local/share/cbb/uninstall.sh` (or with `doas`) |
| OpenWrt | `sh /usr/share/cbb/uninstall.sh` (or `apk del cbb` if installed from the feed) |
| Windows | Open **Settings > Apps > CBB > Uninstall**, or run `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1"` as administrator |

If you installed with Homebrew, run the uninstall script first and then run `brew uninstall cbb`.

Uninstalling removes the program, background service, clipboard agent, update timer, firewall
rules added by the installer, and (on macOS) `/Applications/CBB.app` if installed from the
`.pkg`. Your device's keys and group state stay on disk so reinstalling rejoins the same group.

- **Delete keys and group state too:** Add `--purge` on Unix systems, or run `uninstall.ps1
  -Purge` in an administrator PowerShell on Windows. Afterward, remove the device from the group
  on an admin device (`sudo cbb remove NAME` or in the phone app).
- **Leave the group without uninstalling:** Run `sudo cbb leave` (without `sudo` on rootless
  Linux, or `cbb leave` in an administrator terminal on Windows). This deletes the device's keys
  and group files while keeping Connect Beyond Borders installed so the device can join a group
  again.
