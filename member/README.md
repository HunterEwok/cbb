# The lite member

The lite member is a small Copy Beyond Borders member in Rust for weak Linux devices: a
Raspberry Pi, a router, a small board. Its command is `cbb`, as on a full member, with the
same paths and service (`cbb version` says which one a device runs). It speaks the member
protocol of [docs/protocol.md](../docs/protocol.md), but unlike a full member it

- never holds CA keys, so it never admits devices;
- dials the computers on the home network (found by mDNS, or named with `-peer`), and
  publishes itself in mDNS
  and listens on the member port, TCP 8764, so that phones and other lite members
  dial it: a phone syncs with it directly, with no computer on;
- has no desktop clipboard of its own: other programs use `copy`, `paste` and `watch`.

Full members list it with role `lite`. Away from home, or on another subnet where mDNS does
not reach, it syncs through the group's WireGuard tunnel to the hub once `cbb global on` is
run on it ("Sync away from home" below); it dials no address outside the home network
itself.

The protocol core is its own crate, [`core`](../core) (`cbb_core`): certificates, records,
the hybrid clock, the sync engine, the frames and the joiner's side of the pairing, with
CPace in `core/src/third_party/cpace`. It does no I/O and needs no operating system
(no_std with alloc; RustCrypto for P-256, SHA-2 and HMAC), so a lite member on the ESP32
can use it as it is. On a microcontroller the firmware supplies the randomness, as
getrandom's custom backend (`__getrandom_v03_custom`), and the core's locks are spin
locks; with the `std` feature, as the lite member uses it, they are the standard library's.

With the `tls` feature the core has the TLS of members and pairing too (`core/src/tls`):
rustls through its unbuffered API, which needs no standard library, with a crypto
provider of RustCrypto code (TLS 1.3 only, ChaCha20-Poly1305 or AES-128-GCM, X25519,
ECDSA P-256), the certificate checks, a `Session` that does no I/O (the caller moves the
bytes) and the pairing's TLS exporter, which rustls offers only with std: the core takes
the exporter secret from the connection's key log and derives the exporter itself
(RFC 8446, section 7.5). The lite member runs on exactly this code, so the e2e test below
checks the TLS a microcontroller would use against Go members.
The lite member itself (`src`) adds the state files, the sockets, mDNS, the control socket,
the service and the tunnel to the hub (`src/tunnel.rs`, `src/away.rs`): GotaTun's WireGuard
from Mullvad and smoltcp's TCP, in one thread, behind a port on the loopback address that the
member TLS dials. GotaTun gets its ChaCha20-Poly1305 from a stand-in for ring on RustCrypto
([`ring-shim`](../ring-shim), patched in by the top `Cargo.toml`), so the build stays all Rust.

## Build

With Rust 1.85 or later:

```sh
cargo build --release          # target/release/cbb
cargo test --workspace         # unit tests and the vectors in testdata/interop
```

The core alone, with its TLS, for a RISC-V microcontroller such as the ESP32-C6
(`rustup target add riscv32imac-unknown-none-elf`; `.cargo/config.toml` sets getrandom's
backend):

```sh
cargo build -p cbb-core --features tls --release --target riscv32imac-unknown-none-elf
```

For the ESP32-S3 (Xtensa) with Espressif's Rust toolchain (`espup install`, or the
`esp32` job in `.github/workflows/ci.yml`, which fetches the same toolchain directly):

```sh
cargo +esp build -Zbuild-std=core,alloc -p cbb-core --features tls --release \
  --target xtensa-esp32s3-none-elf
```

For a Raspberry Pi (64-bit Raspberry Pi OS or Debian) from an x86 Linux machine:

```sh
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu
```

For a Raspberry Pi Zero, Zero W or Pi 1 (ARMv6, 32-bit Raspberry Pi OS): a static binary,
all Rust, with no cross toolchain (`.cargo/config.toml` holds the settings):

```sh
rustup target add arm-unknown-linux-musleabihf
cargo build --release --target arm-unknown-linux-musleabihf
```

CI builds both for every pull request: the `cbb-lite-linux-arm64` and
`cbb-lite-linux-armv6` artifacts of the `lite member (Rust)` job. A release builds static musl binaries for x86-64,
ARM64 and ARMv6 with Rust's own linker (`.cargo/config.toml`), each in an archive
(`packaging/archive.sh`) with `THIRD_PARTY_NOTICES`, the licenses of the crates it is built
from (`packaging/notices.sh`), and the installer of the full member's Linux archive with the
lite member's own systemd unit (`packaging/cbb.service`).

The e2e test runs the lite member among Go members: it joins through the phone's QR code,
gets no CA keys and syncs both ways.

```sh
CBB_LITE=$PWD/target/release/cbb go test ./internal/service -run TestLiteMember -v
```

## Install

On the device, with systemd (Raspberry Pi OS, Debian, Ubuntu):

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --lite
```

`get.sh --lite` takes the release's static build for this architecture
(`cbb-lite-linux-amd64.tar.gz`, `-arm64`, or `-armv6`, which also runs on
ARMv7), checks it against `SHA256SUMS` and runs its `packaging/linux/install.sh`, the same installer as a full
member's: the program as `/usr/local/bin/cbb`, the `cbb` user and group, the
service `cbb.service`, the tmux configuration, and, with your consent, mDNS and
the member port from the home network in the firewall. `--port N`, `--console`, `--express`
and `--no-firewall` work as for a full member ([the command reference](../docs/reference/cli.md#installers)).
Running it again updates. It refuses to replace a full member, whose keys the lite member
cannot use. Without curl, or for a binary you
built, unpack the archive (or make one with `sh packaging/archive.sh`) and run
`sudo sh cbb-lite/packaging/linux/install.sh cbb-lite/cbb`. To remove it:
`sudo sh /usr/local/share/cbb/uninstall.sh` (`--purge` also deletes the keys). To leave the
group and keep the lite member, for example after the group removed it: `sudo cbb leave`,
then join again.

The service waits until the device joins a group. Since a small device often has no keyboard
and you install it to pair it, the installer starts pairing by itself when the device is in no
group and its output is a terminal (over SSH too): it shows the QR code at once. An update, or
a reinstall that keeps the group, skips it; `--no-pair` (or `CBB_PAIR=no`) skips it for a
scripted install, which a script needs whenever it runs the installer with a terminal (`ssh -t`
too), or it waits up to 5 minutes for a phone; Ctrl+C stops the pairing but not the installer. Joining still takes the code
shown on the device. To pair later, join as the service's user, so that it can read its keys:

```sh
sudo -u cbb cbb pair -name pi
```

It shows a QR code: in the Copy Beyond Borders app (iPhone or Android) tap "Connect a new device"
and scan it. The phone reaches the device on
TCP port 8764 (`-port` to change it), while it joins and afterwards to sync. In a group
without a phone, run `cbb pair` on the group's root or an admin and
`sudo -u cbb cbb pair -code <that member>:8764` here, then type the code.

The installer adds the user who ran `sudo` to the `cbb` group, for the control
socket without `sudo`:

```sh
echo hello | cbb copy          # -secret for a password: the group keeps it 60 s
cbb paste
cbb status                     # this device, the group and its devices
cbb watch                      # one line per text the group sends here
```

`sudo cbb update` installs the newest signed release as a full member's does
([updating](../docs/guide/install.md#updating)): it checks `keys.json`, `stable.json` and
`release.json`, downloads this device's archive with curl, wget or uclient-fetch, checks it
and the program in it, runs its installer, and puts the previous program back when the
service does not report the new version within a minute. `cbb update -check` only says
whether there is one; `sudo cbb update -auto on|off` checks once a day (a systemd timer, or
cron on OpenWrt), as the installer asks once (`--auto-update on|off`).

Without mDNS on the network, name the full members in a drop-in
(`sudo systemctl edit cbb`): `ExecStart=` and then
`ExecStart=/usr/local/bin/cbb service -peer 192.168.0.10:8764 -peer ...`. `service -no-listen`
turns the member port off (the device then only dials the computers).

### Without sudo (rootless)

On a Linux computer where you have no `sudo`, install it for your own user instead
([D-79](../docs/decisions.md), "Rootless installs" in [docs/design.md](../docs/design.md)):

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --lite --rootless
cbb pair -name pi              # later, as yourself, without sudo -u (the installer pairs once)
```

It runs as your own systemd user service (`systemctl --user status cbb`), with the
program in `~/.local/bin`, the keys in `~/.local/state/cbb` and the control socket
in `$XDG_RUNTIME_DIR/cbb`, and its hello and device record say `rootless`. Since
every program you run can read its keys, the system install stays the advice: a rootless
lite member has no firewall rules, no text console target (`paste-receive on -console`
refuses) and no `reboot` or `cancel-shutdown` action (they need a polkit rule; `restart`
stays), and it starts at boot only when an administrator once runs
`sudo loginctl enable-linger YOUR-USER`. The commands above that take `sudo` take none here.
For copy and paste in tmux, add the line the installer prints to `~/.tmux.conf`. To remove
it: `sh ~/.local/share/cbb/uninstall.sh` (`--purge` also deletes the keys).
OpenWrt has no user services, so a router takes the normal install.

### OpenWrt

On a router with OpenWrt 25.12 or later (ARM64, ARMv7, x86-64, MIPS or MIPSel; on MIPS the lite
member syncs only at home for now, without sync away from home), as root:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --lite
su -s /bin/sh cbb -c 'cbb pair -name router'   # later; the installer pairs once
```

It installs OpenWrt's procd service, the same as a full member's
([installing](../docs/guide/install.md#openwrt)), which runs `cbb service` as the user
`cbb`. The keys live in `/etc/cbb/state`, the control socket is
`/var/run/cbb/control.sock`. The member port, mDNS and the QR code's addresses
use only the devices of the `lan` zone, which the service gets as `CBB_INTERFACES`; the same
variable limits the lite member on any Linux.

### Sync away from home

```sh
sudo cbb global on             # read the warning, type yes
cbb global                     # the hub, and whether it is reached through the tunnel
sudo cbb global off            # forget the tunnel's keys
```

Turn it on at home: the device then meets the group's hub (a full member made the hub with
`cbb global hub` there) and keeps the hub's offer, its keys and addresses. Whenever the hub is
neither found on the home network nor connected, it dials the hub through the tunnel: plain
WireGuard to the hub's UDP port, with the member TLS inside, so the clipboard stays encrypted
end to end. At home it sends nothing to the hub's outside addresses. A hub that hides its
tunnel (`-obfuscate` or `-vless`, for networks that block WireGuard) is reached too: the lite
member speaks AmneziaWG, and VLESS over XHTTP through the forwarder's web site, whose
certificate it checks against the system's CA certificates (`ca-certificates`, or the file
`SSL_CERT_FILE` names). Over REALITY, which only the full member speaks, the device syncs at
home only. The keys are in
`/var/lib/cbb/tunnel.json`, a file, so the warning asks you to protect the disk
or memory card.

### Remote paste

```sh
sudo cbb paste-receive on      # the group's admins may paste into tmux here
sudo cbb paste-receive on -console -enter   # also the text console, and Enter
cbb paste-receive              # how it stands, and whether a target runs
sudo cbb paste-receive off
```

An admin phone's "Paste on it…", or `cbb paste --on` on an admin computer, puts a text where
this device's keyboard focus is, as on a full Linux member: into the tmux pane in use, through
the helper that CBB's `tmux.conf` starts in each tmux server, or, with
`-console`, into the active text console, through the `cbb-console` unit that
`--console` installs. The device's own user turns it on, never an admin; a text with a line
break needs `-enter`, since tmux and the console would run it; a locked tmux client or console,
a login prompt or a console without a logged-in user refuse. The last 100 pastes, never their
text, are in `/var/lib/cbb/pastes.json`.

### Quick actions

```sh
sudo cbb action enable reboot      # admins with keys in hardware may reboot it
sudo cbb action enable cancel-shutdown
sudo cbb action enable restart     # and restart the service
cbb action                         # how each stands
sudo cbb action disable reboot
sudo cbb action off                # all of them
```

An admin phone's "Quick actions", or `cbb action -on DEVICE NAME` on an admin computer, runs
one of them here, as on a full Linux member. The lite member has three presets: `reboot`, a
minute after the admin asks, which `cancel-shutdown` stops, and `restart`, which restarts the
service. Each is off until the device's own user turns it on; `-by root,phone,computer,watch`
limits it to those kinds of admins, and a reboot takes only admins whose keys are in hardware
unless `-any-key`. Turning `reboot` on writes a polkit rule that lets the service's user ask
logind for a reboot and nothing else (`/etc/polkit-1/rules.d/60-cbb.rules`), so
the device needs polkit (`polkitd`); `shutdown -r +1` runs it. Any admin turns the actions
off from afar. The last 100 are in `/var/lib/cbb/actions-log.json`.

## ZX Spectrum Next

On the Accelerated ZX Spectrum Next, the lite member runs on the Raspberry Pi wired to the
Next's second UART (docs/roadmap.md, item 14), and the Next's `.cbb` dot command
types `cbb next ...` at NextPi's shell (`SUP>`) on that UART, as NextPi's own tools
do. These commands answer in frames a Z80 reads without a parser:

- Every line ends in CR (13). Every answer ends in one status line: `CBBOK`, or
  `CBBERR <message>` in printable ASCII (with the cause after it in debug mode). Lines that
  start with `CBB#` are notes to skip.
- Texts are in the Spectrum character set: printable ASCII, CR for a new line, the pound
  sign at 0x60 and the copyright sign at 0x7F. Every other character becomes `?` on the way
  to the Next (the backtick too); from the Next, block graphics, UDGs and BASIC tokens
  become `?` and CR LF is one new line. Cyrillic comes later.
- CRC-32 is IEEE 802.3, as zlib and PiTools' `.crc32` compute it, in 8 lowercase hex
  digits.

| Command | Answer |
| --- | --- |
| `cbb next paste [-max bytes]` | `CBB1 <len> <crc32>`, then len bytes of the latest text (cut to bytes), then CR, then the status line. |
| `cbb next copy [-secret] <len> <crc32>` | `CBBGO` once the service answers; the Next then sends exactly len bytes, which the lite member reads with the terminal in raw mode (no echo, no CR to LF; it gives up after 10 s without a byte), checks the CRC-32 and sends to the group, as a secret with `-secret` (as `cbb copy -secret`); then the status line. |
| `cbb next check-list <file>` | For `.cbb update`: the file holds `keys.json` and the release's `zxnext.json`, a line each (at most 16 KiB). It checks them against the pinned roots, refuses a release older than this `cbb`, and writes `CBBL <name> <size> <crc32> <sha256>` for each of the Next's four files; then the status line. |
| `cbb next pair [-name name] [-port port] [-addr host[:port]]...` | `CBBQ <size>`, then size rows of the QR code for the phone app, each of (size + 3) / 4 hex digits with the leftmost module in the high bit of the first digit and a set bit dark; the Next draws it, the phone scans it, and after the pairing the status line (up to 5 minutes). A join payload makes a code of about 41 modules, which fits the 192 lines of the screen at 4 pixels per module. |

### The network through the Next's ESP8266

On a Pi without a radio (the Pi Zero of the Accelerated Next), `cbb next link` gives the
lite member a network through the Next's ESP8266, with a driver on the Next that passes
bytes between the two UARTs (docs/roadmap.md, "The Next's network in the background"). It
runs at NextPi's shell on the Pi's UART until the driver stops it:

```
cbb next link -to 192.168.0.10:8764 -serve 8764:8764 -zone +01:00 -log /ram/link.log
cbb service -peer 127.0.0.1:8769
```

- `-to host:port`: the member to dial, a computer at home; each connection the lite
  member makes to the link's local port (`-port`, 8769 by default) becomes a connection of
  the ESP to it. The member protocol and its TLS run on the Pi, so the ESP and the Z80
  see only ciphertext.
- `-serve esp-port:local-port`: the ESP takes connections on its own port and leads each
  to the local one, where the lite member listens: phones that sync with it, and the phone
  that admits it (`cbb next pair -addr <the ESP's address>:<esp-port>`).
- `-udp local-port:host:port`: a local UDP port that leads, through one UDP connection
  of the ESP, to host:port: the hub, or a forwarder that leads to it. With
  `cbb service -tunnel-via 127.0.0.1:local-port`, the tunnel of sync away from home sends its
  packets there instead of to the hub's own addresses, so the Pi syncs away from home
  through the ESP too; WireGuard's keys stay on the Pi.
- `-join code`: join the group with the code of `cbb pair` on the full member at `-to`,
  through a connection to the link's own port, once the Pi's clock is set; the service
  starts after it has joined. `.cbb pair CODE` on the Next runs the link with it.
- `-paste on|on-enter|off`: tells the service, once it answers, whether the group's admins
  may paste on the Next (`cbb paste-receive`), as `.cbb paste-receive` on the Next set it:
  the Next's user is the Pi's. The Next passes it once after each change of its user's and
  then forgets it, so that an admin's `paste-off` stays until that user turns it on again.
- `-zone`: the Next's clock (the DS1307) keeps local time without a zone; the link sets
  the Pi's clock, which NextPi only saves across a power cut, from it in UTC.
- `-log`: standard error is the UART too, so the link writes its log to a file or
  nowhere.
- `-trace`: the log also shows every byte to and from the ESP, to find where a setup
  stops.

Once the UART is raw, the link writes the line `CBBLINK`; `.cbb net on` turns the driver on
only then, since the shell would echo the driver's frames, and a byte of them could stop
the Pi's output as XOFF. On the UART, the driver and the link exchange frames: the byte 0x7E, a type, a length (0
to 255), that many bytes and the sum of the type, the length and the bytes modulo 256; a
0x7E inside a frame is sent twice. The types: `H` the driver's hello (nothing goes to it
before), `E` bytes from the ESP, `e` bytes for the ESP, `T` the clock (the date and the time in
MS-DOS's form, as NextZXOS's `M_DATE` gives them, each 16 bits little-endian),
`A` how many bytes on the wire the driver has taken (16 bits, little-endian; the link
sends at most 384 ahead, less than the Next's 512-byte buffer), `K` characters to type,
`Q` to stop, `C` what `.cbb` types for the Pi's shell and `c` the answers for it. The link drives the ESP's stock AT firmware (AT 1.2) inside the `e` and `E`
frames, with up to five connections (`AT+CIPMUX=1`) and the data in `+IPD` blocks.

The link is also a remote paste target, `next`: once `cbb paste-receive on` is set, an
admin's paste goes to the driver in `K` frames, 50 characters a second, and the driver types
them into whatever program runs on the Next. As with the text console, the link has to run
as root and a line break needs `-enter`.

While the network runs, `.cbb paste`, `copy` and `text` reach the Pi in `C` frames (driver
0.2): the link takes the line `cbb [-debug] next paste|copy ...`, and nothing else, runs it
as NextPi's shell would, with the link's state, hands it what follows as its input, and
sends what it writes back in `c` frames, then `CR LF SUP>`, the shell's prompt. An empty `C`
frame stops the command; any other line gets `CBBERR` and the prompt.

## Errors

Every error has a short message. `-debug` (before the command), `CBB_DEBUG=1`, or a debug
build adds the cause under it; `CBB_DEBUG=0` hides it in a debug build. The service logs
every error with its cause.
