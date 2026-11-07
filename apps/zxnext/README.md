# Copy Beyond Borders for the ZX Spectrum Next

`.cbb` is a dot command for NextZXOS. It copies text to the Copy Beyond Borders group, pastes
the group's latest text, and joins the group, all through the lite member on the Raspberry Pi
inside the Accelerated Next. The Pi is a full lite member of the group (TLS 1.3, the same
certificates as every other device). The Next talks to it only over the UART between the
two, which never leaves the case (docs/roadmap.md, item 14). The frames on that UART are
described in [member/README.md](../../member/README.md#zx-spectrum-next).

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
.cbb pair             join the group through the ESP: scan the code on the screen with
                      the phone app
.cbb pair 123-456     or join with the code of sudo cbb pair on a computer of the group
.cbb net on           the Pi's network through the ESP, in the background, to a
                      computer of the group it finds (.cbb net on 192.168.0.10 names one)
.cbb net off          stop it
.cbb net              how it stands: on or off, the settings, the driver's counters
.cbb install          fetch the other files from cbb.tools, and the Pi's cbb (below),
                      then pair the Pi (its QR code) when it is in no group, else start
                      the network (a running one stops for it)
.cbb update           the same, for the files the site has newer
.cbb paste-receive on [-enter] | off
                      whether the group's admins may type on the Next from the phone app;
                      off until you turn it on; the next .cbb net on hands it to the Pi
                      once, and an admin's off in the app then stays
.cbb leave            after a Y: the Pi forgets its keys and its group; its cbb stays, and
                      .cbb pair joins the same group or another one
.cbb uninstall        after a Y: stop the network, uninstall CBB.DRV, remove the Pi's cbb
                      and its group, and the files in /cbb; C:/DOT/CBB is yours to ERASE
                      (a /cbb/CBB that runs as ../CBB stays too, with the folder)
.cbb -d paste         the same, with the cause under each error and, at the end, the
                      bytes of the stack never used (debug mode)
```

SPACE stops a command that waits, such as `pair` while the phone has not scanned yet.

Texts use the Spectrum character set: printable ASCII, the pound sign and the copyright
sign. The lite member on the Pi converts them; every other character arrives as `?`. Cyrillic
comes later.

## Install

Through the ESP8266, once it is on the Wi-Fi network (NextZXOS's own tools join it), from
NextBASIC:

```
CD "C:/DOT"
.http -h cbb.tools -u /zxnext -f CBB
.cbb install
```

`.http` fetches `.cbb` itself into `C:/DOT`, where NextZXOS finds dot commands, so `.cbb`
runs from any folder. `install` writes everything else in `/cbb`: it fetches the rest from
cbb.tools (`CBB.OVL`, `CBB.DRV` and the lite member for the Pi), then copies the Pi's `cbb` over the
UART to `/NextPi/nextpi`, where it writes a start script `cbb` that keeps the member's state
in `/NextPi/nextpi/cbb-state` (NextPi's root is read-only). Nothing else on the card or the Pi
changes; the Pi's copy is removed from the card once the Pi has it.

A line shows each download: the percentage, the kilobytes, the speed and the time left, and
the border blinks while it runs. SPACE stops it, and `.cbb install` goes on from where a
download stopped or broke off. After the install's key, a Pi in no group goes on to pair: the
QR code shows at once, as `.cbb pair` shows it.

**At power-on.** NextZXOS runs `C:/NEXTZXOS/AUTOEXEC.BAS` when it starts: `.cbb install`
adds `.cbb net on` to it as its last line, after the user's own lines (or writes one with
only that line), and `.cbb uninstall` takes the line out again and leaves the rest as it
was. A program that never ends, or ends in `.core`, never reaches it; then start the network
by hand. In the first two minutes after power-on `.cbb net on` does not wait for NextPi,
which takes up to a minute to start: it finds the computer through the ESP, hands the line
that starts the link to the driver and returns, so BASIC goes on at once. The driver (call 9)
presses Enter on the Pi's line every two seconds until NextPi's shell shows `SUP>`, types the
line once the shell is quiet, and turns itself on when the link says `CBBLINK`; it gives up
after three minutes. Until then `.cbb net` says that the network starts once the Pi is up,
`.cbb net off` cancels it, and the other commands wait.

A `CBB` fetched into `/cbb` by an earlier manual still works there as `../CBB`; `.cbb update`
replaces the one it runs as, `C:/DOT/CBB` first.

**What is checked.** The files come over plain HTTP, since neither `.http` nor the ESP has
TLS. So each `CBB` carries the size and SHA-256 of the `CBB.OVL`, `CBB.DRV` and the Pi's
`cbb` it was built with, and installs only those, whatever the site or the network serves: the Next
checks the overlay and the driver, and the Pi checks its `cbb` with `sha256sum` before it replaces the old
one. What `CBB` itself is, nothing on the Next can check: the one `.http` fetches is as
trustworthy as the network it came over. For an installation that does not trust the
network, take `CBB` from the release instead, whose files are signed
([installing](../../docs/guide/install.md#checking-a-download)): copy `zxnext/CBB` of
`cbb-zxnext.tar.gz` to `C:/DOT` on the card, then `.cbb install`.

`.cbb update` trusts the network no more than the release: it fetches the site's `SIGNED`
(the release's `zxnext.json`, which the release key signs, and the `keys.json` that names
that key) and hands it to the Pi, whose `cbb` checks it against the root keys it was built
with and refuses a release older than its own (`cbb next check-list`). Only the names,
sizes, CRC-32s and SHA-256s that the Pi's `cbb` writes back count, so `.cbb update` needs a
Pi with a `cbb` of 0.6 or later that answers; without one it changes nothing. Then, without
a newer `CBB`, it installs this `CBB`'s files where they are missing or differ, or says there
are no updates. With one, it fetches it as `CBB.NEW` next to the running one (in `C:/DOT`,
or in `/cbb` for an old install), then the files the signed list names for it, each checked
against that list's size and SHA-256. Last it closes its
own file, which NextZXOS keeps open while a dot command over 8K runs (the API's "Large dot
commands"), erases it and renames `CBB.NEW` in its place; the code in memory runs on. Should
that fail, it says the `ERASE` and `RENAME` to type after it. The network, if it ran, it
leaves off and asks for `.cbb net on` or a restart: starting it is the new `CBB`'s job, since the new
driver and the Pi's new `cbb` may want what the old one does not know.

Over an earlier installation: `.cbb install` asks for `.cbb net off` first while the network
runs, and replaces only the files that differ. It installs `CBB.DRV` itself, and a driver
already installed, which runs from memory, it uninstalls and installs again when the file is
new. On the Pi it stops the old `cbb service`, so the next `.cbb net on` starts the new
one, and an old `cbb` that is the program itself, not the start script, is kept as
`cbb.old`. A `CBB` in `C:/DOT` that differs from one in `/cbb` is reported, not touched:
`.cbb` runs the one in `C:/DOT`.

Not yet run on a real Next.

## Set up the Pi

1. Make sure NextPi answers: `.pisend -q`.
2. Put the lite member's binary `cbb` for the Pi Zero on the Pi: `.cbb install` (above), or
   by hand from `cbb-lite-linux-armv6` of a release, for example with `.piput`,
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
- it carries `.cbb`'s commands while the network runs: their bytes in frames to the Pi, the
  Pi's answers in a 1 KB ring of their own, which `.cbb` reads; while it reads, the Pi's
  frames wait in the Pi's UART when that ring is full too, and answers nobody reads are
  dropped;
- it restores the UART selection it found, and stops on the Pi's quit frame.

The frames are those of `cbb next link` (member/README.md, "The network through the Next's
ESP8266"). The driver starts off, so that nothing reaches NextPi's shell before the link
runs; its API turns it on: `DRIVER 124,2,1` (1 the counters: the ESP's overflows, dropped
frames, bytes taken; 2 on or off, and turning it on starts the counts again, as the link counts its bytes from 0; 3 whether it is on, in A and DE; 4 the bytes sent to and read from the ESP; 5 the last
dropped frame; 6 the last 64 bytes from the Pi, which `.cbb -d net` shows; 7 `.cbb`'s
bytes for the Pi, D = 0 opens, 1 a byte in E, 2 sends what waits, 3 that and the frame that
stops the command, 4 closes; 8 the next byte of the Pi's answers, in E with D = 1, or D = 0
for none yet; driver 0.2). Its id, 124, is not
assigned by NextZXOS's maintainers yet.

To use it, put `CBB` and `CBB.DRV` in `/cbb` (`.cbb install` does), join the ESP to the Wi-Fi network as NextZXOS's own
tools do, and run:

```
.cbb net on
```

It finds a computer of the group each time, as the lite members on a network of their own
do with mDNS: the question for `_cbb._tcp.local` goes from the ESP's UDP port 5354, which the
members answer to that port alone (a legacy unicast query, RFC 6762 section 6.7), and the first
computer to answer (not a lite member nor a phone, TXT `r=lite` or `r=phone`) is the one the
Pi dials, at the port of its SRV record. With more than one group at home, or a network that
drops multicast, name the computer: `.cbb net on 192.168.0.10` is short for
`.cbb net on -to "192.168.0.10:8764" -serve "8764:8764"`; the long form takes `-zone "+01:00"`
too (the zone is UTC without it), and `"HOST:PORT"` another port.

NextBASIC ends a statement at a colon, so each setting with one goes in quotes; the quotes
do not reach the Pi. After a reset or a power cycle, which drop installed drivers, `.cbb net on` installs
`/cbb/CBB.DRV` again by itself: a dot command cannot run `.install`, so it does what
`.install` does through the driver API (M_DRVAPI with driver 0, and IDE_BANK for the 8K
bank); `.install /cbb/CBB.DRV` still works too. It types `cbb next link` with these settings at NextPi's shell and turns the driver on; it
keeps the settings in `/cbb/NET.CFG`, so the next time `.cbb net on` is enough. `-to` is a
member at home, `-serve` the ESP's port for the phones and the lite member's own,
`-zone` the Next's clock's offset from UTC (member/README.md, "The network through the Next's
ESP8266"). While the network runs, the ESP's UART is at 19200 (`AT+UART_CUR`, not kept in its
flash): the driver hands the Pi 2400 of its bytes a second, and the ESP has no flow control, so
at its stock 115200 a burst would overflow the Next's 512-byte buffer; `.cbb net off` puts it
back at 115200. The lite member (`cbb service -peer 127.0.0.1:8769`) has to run on the Pi as well.
While the network runs, the Pi's line is the driver's: `.cbb paste`, `copy` and `text` go
through the driver (calls 7 and 8), and the link on the Pi runs their `cbb next paste` or
`copy` as NextPi's shell would, so the network goes on. With an older driver, which has no
such calls, they stop the network for the Pi's shell and start it again after (some 10 to
15 seconds). `.cbb pair` stops it in any case.

NextPi has no network of its own, so `.cbb pair` joins the group through the ESP, with the network's settings or their defaults. It asks the ESP
for its address (`AT+CIFSR`), starts `cbb next pair` on the Pi in the background with that
address and the ports of `-serve` (so the settings need `-serve`), draws the QR code, and
starts the network under it, so the phone that scans the code reaches the Pi through the
ESP. The phone app says when the Pi has joined; then `cbb service` starts on the Pi with the
group. With `cbb next link -udp` and `cbb service -tunnel-via`, the Pi syncs away from home
through the ESP as well (member/README.md).

Without the phone app, `sudo cbb pair` on a computer of the group shows a code, and
`.cbb pair 123-456` on the Next joins with it: it finds the computer whose pairing window is
open (TXT `p=1`), starts the network to it with `cbb next link -join 123-456`, and the
computer's `cbb pair` says when the Pi has joined. Both ways, `.cbb pair` first asks the
Pi whether its state holds an identity: a Pi in a group already does not join another, so
the Next says so instead of waiting: `.cbb leave` first.

## Build

With [z88dk](https://github.com/z88dk/z88dk) 2.3 (`zcc` on the `PATH`, `ZCCCFG` pointing
at its `lib/config`):

```sh
make PI_CBB=cbb   # build/CBB (to C:/DOT), build/CBB.OVL (to /cbb), build/PIBRIDGE and
                  # build/CBB.DRV;
                  # cbb is the Pi's lite member, which CBB installs (pins.sh)
make test         # the frame parser's and SHA-256's tests with the host's C compiler, the driver's
                  # bank in a Z80 emulator against two played UARTs, and .cbb itself on a played
                  # Next (drvtest, with cargo; below)
```

CI's `ZX Spectrum Next` job builds z88dk from its release source, checked against a
SHA-256, and runs both; the run keeps `CBB`, `CBB.OVL`, `PIBRIDGE` and `CBB.DRV` as its artifact
`cbb-zxnext-dot`.

## Memory

A dot command gets 8K of its own in the divMMC's memory, and NextZXOS gives it 8K pages
for the rest. z88dk's `dotn` loader puts `.cbb` in these parts:

| Part | Where | What | Must leave free |
|---|---|---|---|
| CODE | divMMC, 0x2000-0x3FFF | the library, `far.asm`, `colour()`, the palette, `ovl_load()` | 1K |
| MAIN | 0x8000 up to 0xE000 | `run()`, the link, the frames, the driver's calls, the strings | 3K: 2K for the stack, which starts at 0xE000 and goes down (about 600 bytes used), 1K to grow |
| PAGE_13 | 0xE000-0xFFFF | the install: fetching over the ESP, checking, sending to the Pi, the install screen's bars | 1K |
| PAGE_15 | 0xE000-0xFFFF | the logo, the usage, the install screen, SHA-256, the site's list | 1K |
| PAGE_17 | 0xE000-0xFFFF | `.cbb net` and `pair` | 1K |
| PAGE_19 | 0xE000-0xFFFF, in `CBB.OVL` | `.cbb paste`, `copy`, `text`, `leave`, `uninstall`, `paste-receive` | 1K |

`CBB` stays under 64K: a `CBB` of 64K reset a real Next. So the pages from 19 on are not in
it but in `/cbb/CBB.OVL`, which `.cbb install` fetches: `ovl.sh` cuts them out of the file
z88dk wrote, marks them in its page table to be allocated but not loaded, and writes the
stamp of the build into each and `CBB.OVL`'s size, SHA-256 and stamp into `CBB`. The first
far call into such a page reads it from `CBB.OVL` and checks its stamp (`ovl_load()`), so
there may be as many as the program needs, and the user still types the one command.

The pages share 0xE000, the window of MMU7, so only one is there at a time. MAIN calls
a page through its entry in `far.asm` (`far_install()`, `far_cmd()` and so on), which
puts the page in MMU7 and the old one back after; a page calls MAIN and the divMMC's
8K directly, and another page only through such an entry, never directly. `make` fails
when a part has less free than the table says (`budget.sh`, which prints what each has),
or when a function shares its address with its own static data (`mapcheck.sh`): z88dk
puts a function's own `static const` there when code and data share a section, as in
the pages, so tables in a page are at file scope. String literals always go to MAIN.

NextZXOS's rules that `.cbb` keeps (its API documentation):

- the stack is never in the divMMC's 8K during RST 0x10 or RST 0x18, which is why it
  starts at 0xE000 (z88dk's default, the top of memory, is in MMU7, in the pages' window);
- RST 0x10 runs with IY at 0x5C3A and MMU6 and MMU7 as BASIC left them (`rom_char()` in
  `far.asm`);
- M_P3DOS runs with MMU2 at its default, and M_DRVAPI's buffers are at 0x4000 or above.

## Testing on a played Next

`drvtest` plays a Next well enough to run the real `build/CBB` from start to end: the Z80N's
own instructions, MMU paging, NextZXOS's calls (files on a directory as the card, pages,
drivers, M_P3DOS), the ROM's printing, the keyboard and the interrupts, the two UARTs at
their speeds with their 512-byte buffers, the ESP's AT commands and passthrough to a site
like cbb.tools, and NextPi's shell. It fails a run on what would go wrong on a real Next
even where it happens to work there: a write outside `.cbb`'s own pages and the screen, code
run from 0xE000 with the wrong page there, the stack in the divMMC's 8K during a call, IY
not 0x5C3A at an interrupt, an instruction it does not know.

`make test` runs `tests/install.rs` when build/CBB is there: a clean install, the run after
it with everything current, no Wi-Fi, a site without the files (404), a Pi that does not
answer, a site that closes the connection, SPACE, the usage and a paste. With
`make PI_CBB=build/PIBRIDGE`, the small PIBRIDGE stands in for the Pi's cbb, so that they
take seconds. For a look at one run, with the screen before and after the key:

```sh
sh ../../packaging/zxnext/site.sh build build/PIBRIDGE /tmp/site
cd drvtest && CBB_MAP=../build/cbb.map cargo run --release --example run -- \
    ../build/CBB /tmp/site/zxnext 600 -d install
```

`FAULTS` plays failures (`nowifi`, `status=404`, `close=N`, `silent`, `pisilent`,
`pisha=HEX`, `space=SECONDS`), `CARD=DIR` keeps the card between runs, and `PEER_LOG=1`
prints what the ESP and the Pi were told.
