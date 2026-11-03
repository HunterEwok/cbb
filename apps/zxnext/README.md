# Clipboard Bridge for the ZX Spectrum Next

`.cbb` is a dot command for NextZXOS. It copies text to the Clipboard Bridge group, pastes
the group's latest text, and joins the group, all through the lite member on the Raspberry Pi
inside the Accelerated Next. The Pi is a full lite member of the group (TLS 1.3, the same
certificates as every other device). The Next talks to it only over the UART between the
two, which never leaves the case (docs/roadmap.md, item 14). The frames on that UART are
described in [lite/README.md](../../lite/README.md#zx-spectrum-next).

Not yet run on a real Next: the UART speed taken from NR 0x7F, waking NextPi's shell, the
QR code on the screen, and the timeouts are written from the manual and NextPi's own
tools. Test them on the machine before relying on them.

## Use

```
.cbb paste            show the group's latest text
.cbb paste notes.txt  save it to a file
.cbb copy notes.txt   send a file (up to 8 KB)
.cbb text Hello Next  send the words
.cbb text -s hunter2  send a secret, such as a password (copy -s FILE too)
.cbb pair             join the group: scan the code on the screen with the phone app
                      (through the ESP once .cbb net has its settings)
.cbb net on -to "192.168.0.10:8764" -serve "8764:8764" -zone "+01:00"
                      the Pi's network through the ESP, in the background
.cbb net off          stop it
.cbb net              how it stands: on or off, the settings, the driver's counters
.cbb install          fetch the other files from cbb.tools, and the Pi's cbb (below)
.cbb update           the same, for the files the site has newer
.cbb -d paste         the same, with the cause under each error (debug mode)
```

SPACE stops a command that waits, such as `pair` while the phone has not scanned yet.

Texts use the Spectrum character set: printable ASCII, the pound sign and the copyright
sign. The lite member on the Pi converts them; every other character arrives as `?`. Cyrillic
comes later.

## Install

Through the ESP8266, once it is on the Wi-Fi network (NextZXOS's own tools join it), from
NextBASIC:

```
MKDIR "/cbb": CD "/cbb"
.http -h cbb.tools -u /zxnext -f CBB
../CBB install
```

`.http` fetches `.cbb` itself; `install` fetches the rest from cbb.tools into `/cbb`
(`CBB.DRV` and the lite member for the Pi), then copies the Pi's `cbb` over the
UART to `/NextPi/nextpi`, where it writes a start script `cbb` that keeps the member's state
in `/NextPi/nextpi/cbb-state` (NextPi's root is read-only). Nothing else on the card or the Pi
changes; the Pi's copy is removed from the card once the Pi has it.

A line shows each download: the percentage, the kilobytes, the speed and the time left, and
the border blinks while it runs. SPACE stops it, and `.cbb install` goes on from where a
download stopped or broke off. Every file is checked against the site's list (its size and
CRC-32 on the Next, its MD5 on the Pi) before it replaces the old one. `.cbb update` does
the same and fetches only the files that changed. The files come over plain HTTP, since
neither `.http` nor the ESP has TLS: the checks find a damaged download, not a changed one,
until the list is signed (docs/roadmap.md, "Installing").

Over an earlier installation: `.cbb install` asks for `.cbb net off` first while the network
runs, and replaces only the files that differ. It installs `CBB.DRV` itself, and a driver
already installed, which runs from memory, it uninstalls and installs again when the file is
new. On the Pi it stops the old `cbb service`, so the next `.cbb net on` starts the new
one, and an old `cbb` that is the program itself, not the start script, is kept as
`cbb.old`. A `CBB` in `C:/DOT` that differs from the new one is reported, not touched:
`.cbb` runs that one, `../CBB` in `/cbb` the new one.

Not yet run on a real Next.

## Set up the Pi

1. Make sure NextPi answers: `.pisend -q`.
2. Put the lite member's binary `cbb` for the Pi Zero on the Pi: `.cbb install` (above), or
   by hand from `clipboardbridge-lite-linux-armv6` of a release, for example with `.piput`,
   in `/NextPi/nextpi`, which is on the shell's `PATH`.
3. Give the Pi a network: the Zero W's own Wi-Fi, which NextPi turns off, or the Next's
   ESP8266 through `CBB.DRV` (below). Many Accelerated boards carry a Pi Zero without a radio: NextPi's
   shell shows which (`cat /proc/device-tree/model`), and `ls /sys/class/net` lists only
   `lo` on such a Pi.
4. Start `cbb service` at boot, then run `.cbb pair` on the Next.

The exact NextPi paths and the start script come with the first test on a real Next.

## Test bench: the Pi's shell over the network

`.pibridge` opens NextPi's shell (`SUP>`) to a computer on the home network, so a test can
drive the Pi without typing on the Next, even on a Pi Zero without a radio. The Next's
ESP8266 dials the computer in its stock AT firmware's passthrough mode, and the Z80 copies
bytes between the Pi's UART and the ESP's until SPACE is pressed. The shell is root's and
travels in the clear: use it only on a network of your own, and only while testing. For
that reason `.cbb install` does not fetch it; copy it from CI's artifact when a test needs it.

1. Join the ESP8266 to the Wi-Fi network once, as NextZXOS's own tools do.
2. On the computer, listen on one port and take only the Next's address:

   ```sh
   socat TCP-LISTEN:2323,reuseaddr,range=NEXT_IP/32 -,raw,echo=0
   ```

3. On the Next: `.pibridge COMPUTER_IP 2323` (`.pibridge -d ...` shows the ESP's answers,
   its firmware version among them). The computer gets the `SUP>` prompt. The bridge keeps
   the address in `PIBRIDGE.CFG` next to itself, so later a plain `.pibridge` dials it again.
4. SPACE on the Next stops it. It then says how many bytes went each way, how full its ring
   towards the ESP got, and whether a receive buffer filled up, which would mean lost bytes.

It runs the Z80 at 28 MHz while it works. The ESP can take the Pi's output more slowly than
the Pi writes it, so the bridge sends the Pi XOFF when its ring is three quarters full and
XON when it has room again; that needs `ixon` on the Pi's terminal (`stty -a` shows it).
Tried on a real Next: 12.5 KB of the Pi's output arrived whole; at 3.5 MHz the bridge lost
bytes.

**Updates while it runs.** The computer can replace a file in the bridge's own folder (a new
`PIBRIDGE`, say) without the card leaving the Next. It sends the bytes `00 1B 43 42 42 55`
(`CBBU` after NUL and ESC), then a line `NAME LENGTH CRC32` ending in CR, with an 8.3 name
and the CRC-32 in 8 hex digits as zlib computes it. The bridge answers `CBBU GO`, takes the
file in blocks of 256 bytes, answering `+` after writing each, so the computer sends the
next block only then; it writes to `UPDATE.TMP` and replaces the file only when the CRC-32
matches, then answers `CBBU OK` or `CBBU ERR` with the cause. The Pi waits (XOFF) meanwhile.
NextZXOS keeps a running dot command's file open, and an open file cannot be renamed or
written, so the bridge closes its own file once it has loaded (from 0.4.2); the new version
runs from the next start. Before the first such update, copy the bridge to the card once, for example with NextZXOS's
`.http`, which downloads through the same ESP.

## The driver: the network in the background

`CBB.DRV` (`drv/`) is a NextZXOS driver that gives the lite member on the Pi a network
through the ESP8266 while any program runs (docs/roadmap.md, "The Next's network in the
background"). Its 512 bytes (`stub.asm`) page its 8K bank in at $E000 on every frame's
interrupt and for its API, and put back the bank they found; the bank (`bank.asm`) does
the work:

- it reads the Pi's frames while its 1 KB ring for the ESP has room for one more, so the
  Pi's bytes wait in the Pi's UART, never lost, and sends the ESP what its 64-byte buffer
  takes;
- it sends the Pi up to 48 of the ESP's bytes a frame, how many of the Pi's bytes it has
  taken (the Pi sends at most 384 ahead), a hello every second and the clock every minute
  (NextZXOS's `drv_drvrtc`);
- it types the characters of the Pi's key frames, one a frame once the program took the
  last (`LAST_K` and bit 5 of `FLAGS`, as the ROM does for a key);
- it restores the UART selection it found, and stops on the Pi's quit frame.

The frames are those of `cbb next link` (lite/README.md, "The network through the Next's
ESP8266"). The driver starts off, so that nothing reaches NextPi's shell before the link
runs; its API turns it on: `DRIVER 124,2,1` (1 the counters: the ESP's overflows, dropped
frames, bytes taken; 2 on or off, and turning it on starts the counts again, as the link counts its bytes from 0; 3 whether it is on, in A and DE; 4 the bytes sent to and read from the ESP; 5 the last
dropped frame; 6 the last 64 bytes from the Pi, which `.cbb -d net` shows). Its id, 124, is not
assigned by NextZXOS's maintainers yet.

To use it, put `CBB` and `CBB.DRV` in `/cbb` (`.cbb install` does), join the ESP to the Wi-Fi network as NextZXOS's own
tools do, and run:

```
.cbb net on -to "192.168.0.10:8764" -serve "8764:8764" -zone "+01:00"
```

NextBASIC ends a statement at a colon, so each setting with one goes in quotes; the quotes
do not reach the Pi. After a reset or a power cycle, which drop installed drivers, `.cbb net on` installs
`/cbb/CBB.DRV` again by itself: a dot command cannot run `.install`, so it does what
`.install` does through the driver API (M_DRVAPI with driver 0, and IDE_BANK for the 8K
bank); `.install /cbb/CBB.DRV` still works too. It types `cbb next link` with these settings at NextPi's shell and turns the driver on; it
keeps the settings in `/cbb/NET.CFG`, so the next time `.cbb net on` is enough. `-to` is a
member at home, `-serve` the ESP's port for the phones and the lite member's own,
`-zone` the Next's clock's offset from UTC (lite/README.md, "The network through the Next's
ESP8266"). While the network runs, the ESP's UART is at 19200 (`AT+UART_CUR`, not kept in its
flash): the driver hands the Pi 2400 of its bytes a second, and the ESP has no flow control, so
at its stock 115200 a burst would overflow the Next's 512-byte buffer; `.cbb net off` puts it
back at 115200. The lite member (`cbb service -peer 127.0.0.1:8769`) has to run on the Pi as well.
While the network runs, the Pi's line is the driver's: `.cbb paste`, `copy`, `text` and
`pair` ask for `.cbb net off` first.

On a Pi without a radio, once `.cbb net` has its settings, `.cbb pair` joins the group through the ESP. It asks the ESP
for its address (`AT+CIFSR`), starts `cbb next pair` on the Pi in the background with that
address and the ports of `-serve` (so the settings need `-serve`), draws the QR code, and
starts the network under it, so the phone that scans the code reaches the Pi through the
ESP. The phone app says when the Pi has joined; then `cbb service` starts on the Pi with the
group. With `cbb next link -udp` and `cbb service -tunnel-via`, the Pi syncs away from home
through the ESP as well (lite/README.md).

## Build

With [z88dk](https://github.com/z88dk/z88dk) 2.3 (`zcc` on the `PATH`, `ZCCCFG` pointing
at its `lib/config`):

```sh
make          # build/CBB, build/PIBRIDGE (copy them to C:/DOT) and build/CBB.DRV
make test     # the frame parser's tests with the host's C compiler, and the driver's
              # bank in a Z80 emulator against two played UARTs (drvtest, with cargo)
```

CI's `ZX Spectrum Next` job builds z88dk from its release source, checked against a
SHA-256, and runs both; the run keeps `CBB`, `PIBRIDGE` and `CBB.DRV` as its artifact
`clipboardbridge-zxnext-dot`.
