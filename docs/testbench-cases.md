<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The bench's test cases, step by step

Cases of the hardware test bench ([testbench.md](testbench.md)) written out in full: the
rule it checks, the devices, what must be true before it starts, each step, and how to tell
pass from fail. The list of every case of release 0.6 is
[testbench-catalogue.md](testbench-catalogue.md), with its own IDs; a case there names the
IDs of this document it replaces in brackets. The IDs are the ones of testbench.md (C content classes, sections 6 and 7; P
features and platforms; F failures; S security). Devices are named by their role on the bench
(section 3 there); their addresses and logins are in the controller's inventory only, never
here.

"Runs" says how a case runs today: **auto** (the suite named runs it, `tools/bench`),
**manual** (a person or a session follows the steps; not yet in the harness), or **planned**
(it needs something the bench does not have yet).

## 0. Common procedures

The cases below refer to these instead of repeating them.

### R1. Reset a device

Every device starts a run in no group; the bench never touches a group it did not make.

1. Linux, macOS: `sudo ./uninstall.sh --purge` (or the installer's copy), then install the
   build under test with `install.sh` (or `get.sh`). Lite member: `get.sh --lite` after the
   purge. Windows: `uninstall.ps1 -Purge`, a check that it left nothing (L10), then
   `install.ps1` from the build's zip; no VM snapshot is needed. Container: on its host
   `sh tools/bench/setup-docker.sh up CBB`, which removes
   the old container with its volume and starts one of the image built from CBB, the
   `linux` binary under test for the host's CPU, with `compose.home.yaml`.
2. On the Linux member with a desktop, sign out and in again (or reboot), so the desktop
   agent starts with the `cbb` group.
3. `cbb version` shows the build under test; `cbb status` says "Not in a group" (the lite
   member: "in no group").

### R2. Form the bench group (layout A)

What `smoke` and `full` do first.

1. On every device: the clock is within 2 s of the controller's (`check`); the device is in
   no group (R1).
2. For a lite member in another subnet: a systemd drop-in gives it `-peer HUB:8764` for the
   run (mDNS does not cross subnets) and restarts its service.
3. On the hub: `cbb new`.
4. For each other device: on the hub `cbb pair` (shows a six-digit code and waits); on the
   device `cbb pair -code [HUB:PORT]` (the lite member: `sudo -u cbb cbb pair -code
   HUB:PORT`), the code on standard input. The hub's `cbb pair` ends when the device joins.
5. On every device, right after it made or joined the group: `cbb sync` says that sync is
   on (design.md, "Sync on and off").
6. `cbb status` on every device shows the same group tag.

### R3. End a run

1. The hub revokes every other member (`cbb remove ID`), so nothing copied on them later (the
   Mac is also a real computer) reaches the group.
2. The bench takes back what it changed for the run (the lite member's drop-in, network
   rules, `tc` settings), newest first.
3. Each device is reset (R1) before the next run.

### R4. Put text in, read text out

| Device | In | Out |
|---|---|---|
| Linux member with a desktop | `xclip -selection clipboard -i` on the session's XWayland (GNOME), or `wl-copy` | `xclip -o` / `wl-paste -n` |
| Mac | `pbcopy` as the signed-in user | `pbpaste` |
| Windows | the scheduled task `cbbbench-copy` (from `setup-windows.ps1`) puts a file on the clipboard inside the signed-in session | `cbbbench-paste` writes the clipboard to a file |
| Lite member, away computer | `cbb copy` | `cbb paste` (or `cbb watch -0`) |
| Container (`nas`) | `docker exec -i cbb cbb copy` on its host | `docker exec -i cbb cbb paste` |
| Android emulator | the app's UI through UI Automator over `adb` | the app's UI |

Every text carries the run ID, the case ID and the sender, so a stale clipboard never passes.

### R5. "Arrives"

A text *arrives* on a device when R4's "out" there returns it, compared with trailing line
breaks dropped, within the case's time (default 10 s on the bench, 2 s p95 is the target on N1).
Windows turns CR LF into LF when it reads the clipboard and LF into CR LF when it writes it, so
the expected text is converted that way when Windows sends or receives (docs/design.md,
Windows). It is checked again every second until the time runs out.

### R6. Look at errors in both modes

For each error a case expects: the user message is short and says what to do; with
`CBB_DEBUG=1` (the service's environment, or `CBB_DEBUG=1 cbb …`) the real error (type, code,
underlying message) is shown under it; the log has the details in both modes (Linux and lite:
`journalctl -u cbb`, the agent `journalctl --user`; macOS
`/Library/Logs/cbb/service.log`; Windows `ProgramData\cbb\logs\service.log`
and the agent's `LocalAppData\cbb\agent.log`).

### R7. Capture traffic

`tcpdump -i any -w FILE` on the relay, the away computer or a Linux member, started before the
case and stopped after it. The check: `tcpdump -r FILE -A | grep -F MARKER` (and the same for
the run ID, the group tag, device names and the hub's tunnel addresses) finds nothing; the list
of protocols and ports in the capture (`tshark -r FILE -q -z conv,udp -z conv,tcp`) matches the
case's rule.

## 1. Sync on the home network (section 6)

All on N1 (one LAN), the group of R2 with the hub, the Windows VM, the lite member and, when a
test needs it, the Mac. Each class runs from every member to every other one.

**C1. Short ASCII.** Runs: auto (`full`).
Rule: a plain text reaches every member byte for byte.
1. On each member in turn, put in `cbb-bench RUN ascii from SENDER` (R4).
2. On every other member, wait for it (R5).
Pass: every receiver has it. Fail: any receiver still has another text after the time.

**C2. Unicode.** Runs: auto (`full`).
Rule: any Unicode survives: Cyrillic, an emoji with a skin tone, a combining accent, Hebrew and
Arabic (right to left), Japanese.
1. On each member put in `cbb-bench RUN SENDER` followed by a Russian greeting in Cyrillic,
   U+1F44B U+1F3FD (a waving hand with a skin tone), `e` plus U+0301, a Hebrew and an Arabic
   word and three Japanese characters (the text of `textCases` in `tools/bench/full.go`).
2. Wait for it on every other member.
Pass: the same bytes everywhere (no normalization, no `?`). Fail: any change.

**C3. Line endings.** Runs: auto (`full`).
Rule: line endings arrive as sent (Windows: CR LF on its clipboard, LF on the wire).
1. On each member put in a text with a CR LF line, an LF line, a tab-indented line, a line with
   trailing spaces and a last line without a line break.
2. Wait for it on every other member, converted as R5 says for Windows.
Pass: every line, tab and trailing space is there. Fail: a lost or doubled CR, a trimmed space.

**C4. Whitespace only, and empty.** Runs: auto (`full`).
Rule: a text of only spaces and tabs syncs; an empty text is refused and changes nothing.
1. On each member put in a text of only spaces and tabs (different for each sender); wait for it
   on every other member.
2. On the hub copy a marker text; wait until every member has it.
3. On the hub run `cbb copy` with empty standard input.
4. Wait 2 s, then read every member.
Pass: step 1 arrives everywhere; step 3 exits with an error; every member still has step 2's
text. Fail: the empty copy is taken or any clipboard changes.

**C5. Size limit.** Runs: auto (`full`).
Rule: a text of exactly the limit (1 MiB) arrives everywhere; one byte more is refused with a
message that names the limit, and nothing changes.
1. On the hub `cbb copy` a text of exactly 1 048 576 bytes.
2. Wait for it on every member (twice the usual time).
3. On the hub `cbb copy` the same text plus one byte.
Pass: step 2 arrives everywhere; step 3 fails and its message says "larger than", "too large"
or names the limit; R6 holds. Fail: the larger text is taken, or the message is generic.

**C6. Secret copy.** Runs: auto (`full`, with S10).
Rule: `cbb copy -secret` arrives, is gone 60 s after the copy everywhere, and never reaches a
disk.
1. On a Linux member `printf 'cbb-bench RUN secret' | cbb copy -secret`; note the time.
2. Wait for it on every member.
3. At 55 s read every member: it is still there.
4. At 65 s read every member: the secret is gone (the clipboard is empty or holds the previous
   text, as designed).
5. Search the state directories of every device for the marker (S10).
Pass: steps 2 to 5 as said. Fail: it stays after 60 s anywhere, or appears on a disk.

**C7. Burst.** Runs: auto (`full`).
Rule: ten copies within a second from one member; the last one wins everywhere.
1. On the hub run ten `cbb copy` in a row, `burst 1` to `burst 10`, within about a second
   (fail the case if they take over 3 s).
2. Wait for `burst 10` on every member.
Pass: every member ends on `burst 10`. Fail: any member ends on an earlier one.

**C8. Two senders at once.** Runs: auto (`full`; needs three members).
Rule: two members copy at the same moment; every member ends on the same text (HLC order).
1. On two members other than the hub, copy different texts at the same moment.
2. Read every member until they all agree (twice the usual time).
Pass: every member has the same one of the two texts. Fail: members disagree, or one has a
third text.

## 2. Group, pairing and life cycle (section 7)

**L1. Pair each kind of device (layout A).** Runs: auto (`smoke`, `full`).
1. R1 on every device, then R2.
2. `cbb status` on the hub lists every device with its system (linux, windows, macos), role
   (full, lite) and the hub as root.
Pass: every join succeeds within 2 minutes and the list is right. Fail: a join fails or a
device shows the wrong system or role.

**L2. Wrong code, expired code, reused code.** Runs: manual.
1. On the hub `cbb pair`; on a new device `cbb pair -code` with a wrong code three times.
2. Run `cbb pair` again on the hub; wait 5 minutes and 10 s; type the right code.
3. Run `cbb pair` again; join one device with the code; on a second device use the same code.
Pass: each wrong code is refused and counted; the third closes the window (`too-many`); the late
code is refused (window closed); the second use is refused; each message says what to do (R6).
Fail: any of them joins, or the counter does not stop.

**L3. Revoke.** Runs: auto (part of R3); the extra checks manual.
1. With the group of R2, on the hub `cbb remove NAME` (by name), then another by device ID.
2. Copy a marker on the hub.
3. On the revoked device: `cbb status`; try to sync; try `cbb pair -code` with a fresh code from
   its old keys (no reset).
Pass: the marker does not reach the revoked device; its status says it was removed; the lite
member and every other member refuse its certificate; rejoining without a reset is refused.
Fail: it still receives, or any member accepts it.

**L4. Renewal.** Runs: planned (needs a short-lifetime test build or a disposable device whose
clock can move).
1. Set the member certificate's remaining life below the renewal threshold.
2. Wait one sync round.
Pass: the certificate is renewed by an admin, `cbb status` shows the new expiry, sync goes on.
Fail: it expires or sync stops.

**L5. Admin computer (layout A).** Runs: manual.
1. On the hub (root) `cbb admin WIN` is refused, since its keys sit in a file; `cbb admin
   -allow-file-key WIN` makes it one, and `cbb status` marks the Windows member as admin.
2. On the Windows admin `cbb pair` and admit a new device; then revoke it there.
3. Turn the hub off; the Windows admin still admits a device.
4. Turn the hub on; on it `cbb remove WIN`.
Pass: each step works; after step 4 nothing re-pairs. Fail: an admin cannot admit, or a non-admin can.

**L6. Takeover (layout A).** Runs: manual.
1. Turn the hub (root) off.
2. On the Windows admin `cbb takeover HUB`.
3. Copy on each remaining device; it arrives everywhere. On the new root `cbb admin
   -allow-file-key` another computer.
4. Turn the old root on.
Pass: the Windows computer is root; nobody pairs again; the old root is
refused by every member. Fail: any member follows the old root.

**L7. Remove an ordinary member.** Runs: manual (Linux), auto (R3 for the others).
1. On the root revoke a Linux member, the Windows member and the Mac in turn.
Pass: the group stays, the others keep syncing, nobody pairs again.

**L9. Upgrade from the previous release.** Runs: manual, before each release.
1. Every device on the previous release in one group; copy a marker.
2. Update one device at a time to the candidate; after each, copy from an old and from a new one.
3. When all run the candidate, check `cbb status` on each and copy once more.
Pass: mixed versions sync during step 2; state and keys survive; no device pairs again. From a
release before 0.6 instead: each device leaves the old group at its first start (`cbb status`
says so) and a new group works. Fail: sync stops, a device leaves a group of 0.6 or later, or
keys are lost.

**L10. Uninstall.** Runs: manual.
1. `uninstall.sh` (Windows `uninstall.ps1`), then `--purge` (`-Purge`).
Pass: no service, no agent, no firewall rule (ufw, Windows Firewall), nothing left but the keys
without purge and nothing at all with it. Fail: anything left.

**L11. Layout B (a phone's group).** Runs: planned (the emulator cannot be reached from the LAN;
section 3). See P10.

## 3. Features and platforms (section 7, P1 to P39)

**P1. Password managers.** Runs: manual.
1. On the Mac copy a password from a manager that sets the concealed type; on Windows from one
   that sets "exclude from history and cloud"; on the Linux desktop from one that sets the
   Wayland password hint.
2. Read every other member at once and after 65 s.
Pass: it travels as a secret (C6 rules) or not at all, as designed. Fail: it arrives as a plain
text, or stays after 60 s.

**P2. Rich text, images, files.** Runs: manual.
1. Copy formatted text from a browser and from an office app.
2. Copy a screenshot, then a photo of about 5 MB, on each desktop member in turn; paste each on
   the others.
3. Copy a folder with a few files and an empty file in a file manager; paste it on the others in
   theirs; on `lite` run `cbb paste -o DIR`.
4. On one member `cbb config max-copy 1MiB`, then copy a 3 MB file elsewhere.
Pass: the plain text of step 1 arrives; images and files arrive whole (R5, within 10 s on one
network for a 5 MB photo), with the same names and no exec bit, and carry the quarantine mark
on a Mac and the Mark of the Web on Windows; `lite` keeps the copy's text and saves the files
with `paste -o`; step 4's member says once that the copy is over its limit of 1 MiB and
fetches nothing. Fail: an error, a crash, markup instead of text, or a file that differs.

**P3. History and echo.** Runs: manual.
1. With Windows Win+V history and a GNOME clipboard manager on, copy on the Linux desktop.
2. Watch the Linux member's and Windows member's logs for 30 s.
Pass: the text arrives once; neither member sends it back; no ping-pong. Fail: the text is sent
again or flips between two texts.

**P4. The Mac as a full member.** Runs: manual (bring the Mac in for it only).
1. Only the Mac and the lite member on (others off): copy each way.
2. Mac and the Linux member on: `cbb status` on both shows one connection; turn the Mac's
   application firewall on and repeat.
Pass: sync works both ways; one connection per pair (the lower device ID dials). Fail: no sync
or two connections.

**P5. The lite member's options.** Runs: manual (`-peer` is auto in R2).
1. `cbb service -peer HUB:8764`: it connects without mDNS.
2. `-no-mdns`: it no longer announces itself (`avahi-browse -r _cbb._tcp` shows
   nothing for it) and still dials its peers.
3. `-no-listen`: the member port is closed (`ss -ltn`), it dials and syncs.
4. `cbb watch` prints each received text; `cbb watch -0` ends each with a zero byte.
Pass: each as docs/reference/cli.md says.

**P6. Another port.** Runs: manual.
1. Reinstall each member with `--port 8800` (Windows `-Port 8800`, or `CBB_PORT`).
2. Sync; check the firewall rules.
3. Back to 8764.
Pass: members find each other on 8800; after step 3 the 8800 rule is gone and 8764's is back.

**P7. Homebrew on the Mac.** Runs: manual (blocked until the Mac's command line tools support
the current macOS).
1. `brew install hunterewok/tap/cbb`; `install.sh --in-place`.
2. Check the agent runs Homebrew's binary and the service a root-owned copy.
3. `uninstall.sh`, then `brew uninstall`.
Pass: sync works; nothing is left.

**P8. Text console.** Runs: manual.
1. On a Linux member `install.sh --console`; open tmux.
2. Copy elsewhere; paste in tmux with its paste key; copy in tmux; read elsewhere.
Pass: both ways work; a pasted text has no control characters (`cbb paste -terminal`).

**P9. Sessions.** Runs: manual.
1. Windows before anyone signs in: copy elsewhere; the service receives (`cbb status`), no agent.
2. Sign in: the agent puts the latest text on the clipboard.
3. Fast user switching on Windows and on the Mac: copy elsewhere while the second user is
   active.
Pass: only the signed-in user who installed it gets the text; no other user's session does.

**P10. A phone's group in the emulator.** Runs: manual (partly run; sync needs an address the
emulator can dial).
1. In the Android app create a group (root key).
2. Join a computer and the lite member from its QR code (injected image or pasted QR text) and
   PIN.
3. Make the Mac an admin with "Make it an admin"; renew a certificate.
Pass: each step succeeds within the emulator's limits (testbench.md section 3). Fail: a step
fails for a reason a real phone would share.

**P11. Sync away from home.** Runs: auto (`away`, steps 1 to 5 through the forwarder); step 6 manual.
1. On the hub `cbb global hub ADDRESS:PORT` (or with `-forwarder`), `sudo cbb global on`.
2. On the hub `cbb invite -o FILE`; copy the file to the away computer over SSH.
3. On the away computer `sudo cbb pair -invite FILE`; compare the fingerprints on both sides;
   type `yes` on the hub.
4. Copy each way between the away computer and the home members.
5. Last, since it cuts the away computer off: `cbb global off` there asks first, since it
   meets the hub only through the tunnel and its new keys would reach the hub only on the home
   network; answer `no` (nothing changes), then `yes`; `cbb global on`.
6. A hub with only an IPv6 address; a hub behind CGNAT (only the forwarder).
Pass: it joins, syncs both ways (seconds), and `cbb global` explains anything missing; in step
5 `no` keeps it connected, and after `on` `cbb global` says it waits to meet the hub on the home
network.

**P12. Blind relay.** Runs: auto (`relay`: steps 2, 3 and 5 among the home members); steps 1 and 4 and the capture manual.
Devices: `relay`, `desktop`, `remote`; the group of R2 without a hub (no `cbb global hub` on any
device). The relay runs `cbb relay -open -listen :PORT` as its own service, on a port of its
own (the forwarder keeps 8764), opened in the server's firewall for UDP and TCP.
1. On `relay` `cbb relay -show-key` gives KEY.
2. On `desktop` and `remote` `sudo cbb global relay RELAY:PORT -key KEY`; read what it says the
   relay learns, type `yes`; then `cbb global` on each.
3. Copy each way between `remote` and `desktop` (R4, R5); capture on the relay (R7).
4. Restart `remote`'s service; copy again once it is back.
5. Give `remote` a wrong `-key`.
Pass: they sync both ways, also after the restart (within the 60 s backoff); `cbb global`
names the relay; the capture has only WireGuard UDP and the registration's TLS (no server
name), no marker; with the wrong key nothing is sent and the error says the key does not
match.

**P13. Status, revoke, version.** Runs: partly auto (`check`, R3).
1. On every platform `cbb version`, `cbb status`.
2. `cbb remove` by name and by device ID.
Pass: the output matches the real state (systems, roles, root and admin marks, last seen,
clock); a revoked device's status says it was removed.

**P14. Downgrade.** Runs: manual, before each release.
1. On each platform install the previous release over the candidate's state.
Pass: it starts on the newer state or refuses with a clear message; no key is lost.

**P15. macOS.** Runs: manual.
1. Refuse Local Network access: `cbb status` says so; grant it: sync starts.
2. Download the binary with a browser: Gatekeeper's prompt is as documented.
3. Universal Clipboard: copy on an iPhone or iPad with the same Apple account.
Pass: each state is explained; Universal Clipboard text syncs once, without echo; the report
notes whether it arrived before a paste and which types it carried.

**P16. Windows.** Runs: manual.
1. Lock the screen, copy elsewhere, unlock: the text is there.
2. Sign out and in: the agent comes back.
3. Run the installer downloaded by a browser: SmartScreen as documented.
4. `get.ps1` on ARM installs the arm64 build (`cbb version`).
Pass: each as said.

**P17. Steam Deck.** Runs: manual.
1. Sleep and wake; within 30 s copy each way.
2. Game Mode; the lock screen.
Pass: reconnects within 30 s; Game Mode and the lock screen are recorded as they behave.

**P18. mDNS on the router.** Runs: manual (the router's avahi reflector is off by default).
1. Reflector off: the lite member in the IoT subnet is reached by address (`-peer`).
2. Reflector on (`/etc/avahi/avahi-daemon.conf`, `enable-reflector=yes`): drop `-peer`; it is
   found by mDNS.
3. Put the router back as it was.
Pass: both ways sync in both settings.

**P19. IPv6 at home.** Runs: manual.
1. Check `avahi-resolve` gives AAAA records; block IPv4 between two members (ip6-only rule).
Pass: members find and reach each other over IPv6.

**P20. UDP blocked.** Runs: manual.
1. On the away computer drop outgoing UDP to the hub and forwarder (`iptables -I OUTPUT -p udp
   -d ADDR -j DROP`, with a revert timer).
Pass: `cbb global` shows a clear error; nothing goes another way (S9); with `-vless` the TCP
transport works. Remove the rule.

**P21. Invitations refused.** Runs: manual (run on the bench, see S7).
1. Admin answers `no`. 2. `-for 24h`, use it one second after. 3. Hub off when it is used.
Pass: refused with a clear message each time; nothing is left on the hub (`cbb global` there).

**P22. Global off and on, forwarder restart.** Runs: manual (run on the bench).
1. `cbb global off`, then `on`, on a client and on the hub.
2. Restart the forwarder's service.
Pass: keys are forgotten and made again; sync comes back; the hub registers again by itself
(`cbb status` on the hub: forwarder registered).

**P23. macOS pasteboard privacy.** Runs: manual.
1. Turn on the alert for pasting from other apps by hand; copy elsewhere and on the Mac.
2. Repeat on macOS with its defaults of the newest release.
Pass: the report records whether the agent's reading asks the user; text keeps syncing.

**P24. GNOME on the Steam Deck.** Runs: manual.
1. Copy in GNOME Text Editor (native Wayland); read on another member.
2. Copy elsewhere; paste into the editor without clicking another window.
3. Right after sign-in, before any X11 app started XWayland, repeat 1 and 2.
Pass: each within the usual latency.

**P26. The Mac blocks all incoming.** Runs: manual.
1. Set the application firewall to "Block all incoming connections".
2. Copy each way between the Mac and the others.
Pass: the Mac finds and reaches the members; whether they reach it is recorded.

**P27. The phone apps' Glass design.** Runs: manual (the iPhone and Android phones; an iPad
and a foldable when there is one).
1. In Settings pick each of the ten colours with Dark, Light and System.
2. On Home switch tiles and list (and the orbits on a big screen); open each device's page.
3. Compare each page with `cbb status` on the device.
Pass: every tile shows the icon, system and live dot; type, system, versions, MAC address and
role match; a phone's MAC address reads "hidden by the system".

**P28. The group's events.** Runs: manual (both phones).
1. Add a device, remove it, make a computer an admin, freeze and unfreeze it, take the group
   over, and stop the hub while a phone is away from home.
2. Turn each switch in Settings off in turn and repeat its event.
Pass: one notification per event, in its words; none for a switch that is off; none shows
the clipboard.

**P29. The Apple Watch.** Runs: manual.
1. Look at the devices and the latest events on the watch; turn sync away from home on and
   off there.
2. Put the iPhone out of reach and look again.
Pass: the watch follows the phone; the switch turns the phone's away mode; out of reach it
says the phone does not answer.

**P30. The Dynamic Island.** Runs: manual (an iPhone with the Dynamic Island).
1. Add a device; sync away from home; send and fetch.
Pass: the timer while adding, the shield while away, the result for a moment; never the copied
text.

**P31. The Mac app.** Runs: manual.
1. Open the window and the menu bar item; send and fetch from both; switch tiles, list and
   orbits.
2. Rename a device, freeze and unfreeze an admin computer, make a computer an admin, remove a
   device, turn sync away from home on and off: each after the password.
3. Cancel the password prompt once.
4. Stop the service (`sudo launchctl bootout system/tools.cbb`) and
   look at the window with error details on and off; start it again.
Pass: each action does what the same `cbb` command does; the cancelled prompt changes nothing
and says nothing; the stopped service is explained, with the error underneath when details
are on.

**P32. The tray app.** Runs: manual (the Linux members with GNOME and KDE, the Steam Deck,
Windows).
1. Start `cbb-desktop`; find the tray item; open the window from it and by starting the app
   again.
2. Do steps 1 to 4 of P31, with pkexec on Linux and UAC on Windows (stop the service with
   `sudo systemctl stop cbb`, or `Stop-Service cbb`).
3. Set the system's language to Russian and start the app again.
Pass: as P31; the tray item shows on each desktop (GNOME needs the AppIndicator extension);
the texts are Russian.

**P33. The Wear OS app.** Runs: manual (a Wear OS watch paired with the Android phone).
1. Install both APKs of the release (the watch's with `adb install` over its wireless
   debugging); do steps 1 and 2 of P29 with the watch and the Android phone.
2. Close the phone app, turn sync away from home on and off on the watch again.
3. Install the phone app on a phone without Google Play services and use it as before.
Pass: as P29, also with the phone app closed; without Play services the phone app works and
logs once that there is no watch.

**P34. Sync on and off.** Runs: auto (`full`: steps 1 to 4 on the hub against another member, the headless members of step 5, and `-on` of step 6); the Mac app and the refused and stopped targets of step 6 manual.
1. On desktop `cbb sync off`; copy on desktop's desktop, then on win's.
2. On desktop `cbb paste`.
3. Restart desktop's service (`sudo systemctl restart cbb`); `cbb sync` and `cbb
   status` on desktop, `cbb devices` on win.
4. `cbb sync on` on desktop.
Pass: with sync off neither copy crosses, and `cbb paste` on desktop prints win's text; sync
off survives the restart and win lists it; with sync on both cross (R5).
5. On `lite` `cbb sync off`, copy on `desktop`, then `cbb paste` on `lite`; `cbb sync on`
   and copy again. The same on `nas` through `docker exec`, and on `mac` with the app's
   switch.
6. On `desktop` (the root) `cbb sync -on mac off`, then `cbb sync -on lite off`; `cbb sync`
   on each. On `win` before it is an admin `cbb sync -on desktop off`. With `mac`'s service
   stopped, `cbb sync -on mac on` on `desktop`.
Pass (steps 5 and 6): the lite member keeps sync off in its `sync.json` and prints the
group's text with sync off; the container and the Mac follow the same rules as `desktop`;
the root's commands are taken and each target's `cbb sync` shows it; a member that is not an
admin is refused with a clear message; a stopped target gives an error within 10 s and
nothing changes.

**P35. A member in a container.** Runs: auto (`full`, steps 1 to 4, when the inventory has a
device with `os = "docker"`), manual (step 5).
Devices: `nas`, `desktop` (the hub), `win`, `lite`; `remote` for step 5. The container never makes
the group: the bench refuses the role hub for it, since whoever runs `cbb new` holds the
group's CA keys, and they stay off a container.
1. `smoke` or `full`: `nas` joins `desktop`'s group like the others (R2, `cbb` through `docker
   exec`), and every text arrives everywhere (R5).
2. `docker inspect` of the container: not privileged, a read-only root file system, cap_drop
   ALL, the user 65532:65532, `no-new-privileges`, the host's network, a restart policy.
3. F1 for `nas`: its process is killed from the host (`cbbbench-kill-container`, from
   `setup-docker.sh`, kills the PID that `docker inspect` gives), as a crash would; Docker's
   restart policy starts it again.
4. `docker restart`; then a new container from the same volume (`docker compose up -d
   --force-recreate`, as after `docker compose pull`). After each, `cbb status` shows the same
   group, `cbb sync` says sync is on, and a copy on another member arrives on `nas` and on the rest.
5. Only as an explicit choice for the run, since it puts an admin key in a file
   (the key levels of docs/roadmap.md, level 3): first `cbb admin nas` on `desktop`, which must
   be refused ("offers no admin key"); then `CBB_KEYS_IN_FILE: "yes"` in the compose file
   and `docker compose up -d`; on `desktop` `cbb admin -allow-file-key nas`; on `nas` `cbb
   global on` (it asks about the keys in files), `cbb global hub HOST_ADDRESS:8764 -firewall
   no`, and on the host the rule it prints for the UDP port. `remote` joins sync away from home
   (P11) and syncs with `desktop` through the container's tunnel. At the end `desktop` revokes
   `nas` (R3), which takes its admin key with it.
Pass: steps 1 to 4 as written, with no step needing more than the compose file gives (no
`NET_ADMIN`, no `/dev/net/tun`, no `--privileged`); in step 5 a copy on `remote` arrives on
`desktop` and back (R5), and `cbb status` on `remote` names `nas` as its hub.

**P36. Several hubs.** Runs: auto (`away`, after P37, without the capture and with one copy each way instead of 20 minutes of copies).
Devices: `desktop` (the root), `mac` (an admin), `remote` (away), `relay` (the forwarder). The order
of the hubs is the root first, then the others by device ID (docs/protocol.md, section 11,
"Several hubs"); phones are out of this run.
1. The group of R2. On `desktop` `sudo cbb global on` and `cbb global hub -forwarder ...` (as in
   P11); `cbb admin mac`; on `mac` the same two commands. `remote` joins by `cbb invite` from
   `desktop` (P11).
2. `cbb global` on all three.
3. Stop `desktop`'s service. Copy on `remote` every 10 s and watch `cbb global` on `remote` and `mac`.
4. Start `desktop`'s service; keep copying on `remote` for 20 minutes.
5. Capture `remote`'s uplink during steps 3 and 4 (R7).
Pass: in step 2 `desktop` serves, `mac` is `desktop`'s client and `remote` knows both hubs; in step 3
`mac` serves within about a minute and `remote` reaches it with no new invitation, and the
copies resume on `mac`; in step 4 `mac` stops serving once `desktop` says it serves, and `remote` is
back on `desktop` within 5 minutes; no copy is lost (the last one wins everywhere); the capture
shows only WireGuard to the forwarder or the hubs. The switch times go into the report.

**P37. Moving the hub.** Runs: auto (`away`, steps 1 to 4; the admin is the Mac, or another Linux member at home).
Devices: `desktop` (the root and the hub), `mac` (an admin with sync away from home on and no hub
set up), `lite`, `nas`, `remote` (away, connected through `desktop`).
1. The setup of P36 step 1 without the hub on `mac`.
2. On `desktop` `cbb global move lite`, then `cbb global move nas`.
3. On `desktop` `cbb global move mac`.
4. Copy each way between `remote` and `mac`, and `desktop`; `cbb global` on all three.
5. Turn `remote`'s sync away from home off and on, and copy again.
Pass: step 2 is refused with a clear message (a lite member and a container cannot be the
hub); after step 3 `mac` serves with `desktop`'s forwarder, `desktop` is its client, and `remote`
follows without coming home or a new invitation; copies arrive both ways (R5).

**P38. The open relay's limits.** Runs: planned (a helper that starts throwaway groups in
containers on the controller).
Devices: `relay`, the controller.
1. Start 17 throwaway groups on the controller, each a container with `CBB_KEYS_IN_FILE=yes`
   that runs `cbb new` and `cbb global relay` to the relay of P12; they share one address.
2. Send texts at the size limit in a loop in one group for a minute (above 1 MiB a second).
3. Remove each group's last device; with `CBB_DEBUG=1` on the relay, read its counts.
Pass: the 17th registration from one address is refused with a clear message, and the 16
others work; the busy group is slowed and no other group is; the counts drop to zero groups
once their last devices leave; the relay writes nothing to disk (as S8).

**P39. Images and files away from home.** Runs: manual (`away` once `tools/bench` copies files).
Devices: `desktop` (the hub, in mode `own`), `mac` (at home), `remote` (away, connected through
`desktop`).
1. Copy a 5 MB photo and a folder of a few files on `mac`; paste them on `remote`.
2. Copy a 2 MB file on `remote`; paste it on `mac`.
3. On `desktop` `cbb config max-copy-away 1MiB`; copy a 3 MB file on `mac`, then a 500 KB one.
4. Capture `remote`'s uplink during steps 1 and 2 (R7).
Pass: steps 1 and 2 arrive whole through the hub, though its mode keeps its own clipboard out;
in step 3 the hub's log says the 3 MB copy stays at home, `remote` gets only its text and
then the 500 KB copy; the capture shows only WireGuard. Fail: a copy lost or changed, the hub's clipboard
written in mode `own`, or a copy over the hub's limit through its tunnel.

## 4. Failure cases (section 8)

**F1. Kill the service.** Runs: auto (`full`).
1. On each member kill the service hard: Linux and lite `sudo systemctl kill -s KILL
   Copy Beyond Borders`; Windows `Stop-Process -Force` on the service's process; Mac `sudo launchctl
   kill KILL system/tools.cbb` (the bench's sudoers rule).
2. Within 30 s `cbb status` shows the same group.
3. Copy a marker on another member; wait for it (twice the usual time).
Pass: the service manager restarted it and it gets the marker.

**F2. Reboot.** Runs: manual (a device with an encrypted disk needs a person at its boot prompt;
the lite member's power is pulled by hand).
1. Reboot the Linux member, the Windows VM, the Mac; power-cycle the lite member.
2. When each is back, copy each way.
Pass: each rejoins and syncs with no person's action beyond booting (Windows syncs in the
service before sign-in).

**F3. Sleep.** Runs: manual.
1. Sleep the Mac; pause the Windows VM (VMware's suspend; real sleep needs a real PC).
2. Meanwhile copy between the others; then wake.
Pass: back in sync within 30 s of wake; `cbb status` clock column is right.

**F4. Bad network.** Runs: planned (`tc netem` on the Linux members with a revert timer: `tc
qdisc add dev IF root netem loss 30% delay 300ms reorder 25%`).
1. Apply it on the hub; copy 20 markers from various members.
2. Remove it.
Pass: every marker arrives; no duplicate; no crash; the last one is on every member.

**F5. Member port blocked.** Runs: planned.
1. Block TCP 8764 on one member for 5 minutes (firewall rule with a revert timer).
2. Copy three markers elsewhere meanwhile.
3. After the block: wait.
Pass: the member ends on the last marker.

**F6. Hub down while away.** Runs: auto (`away`, without the capture).
1. With the away computer syncing, stop the hub's service.
2. `cbb global` and `cbb status` on the away computer; capture its uplink (R7).
Pass: both say the hub is unreachable; nothing is sent to any other address.

**F7. Forwarder down.** Runs: auto (`away -stop-forwarder` only, without the capture; the forwarder serves others too).
1. With a hub registered at the forwarder, stop the forwarder.
2. On the away computer watch `cbb global`; capture.
Pass: the fallback port is tried as designed, then a clear error; no cleartext path.

**F8. Clock skew.** Runs: manual.
1. On a disposable member turn NTP off and set the clock 3 hours ahead; copy each way.
2. Set it back.
Pass: certificates are accepted within the protocol's margin (beyond it, a clear message);
`cbb status` shows the skew; HLC order holds (C8 again).

**F9. Disk full.** Runs: planned.
1. On a Linux member fill the state directory's file system (`fallocate`) leaving a few KB.
2. Copy; renew; change the group.
3. Free the space.
Pass: a clear error while full; after step 3 it works with no corrupted state.

**F10. Corrupted state file.** Runs: manual (run on the bench).
1. Stop the service; damage `identity.json` (truncate it); start it.
Pass: it refuses with a clear message that names the file (R6); after restoring the file the
device is still in the group.

**F11. Address change.** Runs: manual.
1. Renew a member's DHCP lease to a new address; move the away computer between networks.
Pass: the member is found again; the away device roams without a new invitation.

**F12. Error messages.** Runs: part of every F case.
For each failure above, R6 holds in both modes.

## 5. Security (section 9)

A failure here stops the release of the feature; there are no exceptions.

**S1. The internet path shows nothing.** Runs: manual.
1. Capture on the relay and on the away computer's uplink (R7) during a full run of P11.
2. Search the capture for every marker, the run ID, the group tag, device names, the hub's
   tunnel addresses, and for TLS ClientHello and DNS names of the group.
Pass: only WireGuard UDP (or VLESS on TCP) to the hub or forwarder; no hit. Fail: any hit.

**S2. The LAN shows nothing.** Runs: manual.
1. Capture on a Linux member during `full`.
2. Check member traffic (port 8764) is TLS 1.3 (`tshark -Y tls.handshake -T fields -e
   tls.handshake.version`) and search for markers.
Pass: TLS 1.3 only, no marker in clear.

**S3. Clients are isolated.** Runs: manual.
1. With two away clients, from inside one's tunnel scan the other client's tunnel address and
   every address of the tunnel subnet (`nmap -sT -p- ADDR`, through the tunnel).
Pass: nothing answers but the hub's member port.

**S4. The hub exposes one port.** Runs: manual.
1. From an away client scan the hub's tunnel address, TCP and UDP.
Pass: one open port, the member port.

**S5. A key outside the group.** Runs: manual.
1. With a WireGuard key the group does not know, send a handshake to the hub (and the
   forwarder).
Pass: no answer of any kind; the hub's log has at most a debug line.

**S6. Revoked device away.** Runs: manual.
1. Revoke the away computer on the hub.
2. Within one record round try to sync and to join again with its old invitation.
Pass: the hub dropped its tunnel key; no sync; rejoin refused.

**S7. Invitation file.** Runs: manual (passed on the bench).
1. Use an invitation; use it again. 2. Use one after its time. 3. Answer `no`. 4. Compare the
   fingerprints shown on both sides.
Pass: second use, expired and `no` are refused; the fingerprints match.

**S8. The relay learns little.** Runs: manual (the forwarder and the open relay of P12 on
`relay`).
1. Two groups registered at the forwarder; from a client of one try to reach the other's hub.
   The same at the open relay: from a device of one group `dial` a device of the other.
2. Before and after a run, list every file changed on the server (`find / -xdev -newer STAMP`
   outside /proc, /sys, /run) and the journals of both services.
3. Register a hub with a wrong certificate chain at the forwarder, and a device with one at
   the relay; register at the relay a device that the group's records revoke.
Pass: groups cannot reach each other; no file and no log line about them (besides the key
files); each bad registration is refused.

**S9. Fail closed.** Runs: manual.
1. Break the tunnel (block the hub's UDP port on the away computer).
2. Copy on the away computer; capture its uplink for 2 minutes.
Pass: no packet to any address but the hub and forwarder; nothing in clear.

**S10. Secrets never reach a disk.** Runs: auto (`full`; Windows not yet).
1. `copy -secret` a marker on each kind of member.
2. On each, search the state directories and `/tmp` for it (`grep -r MARKER`); check swap is off
   for the service on Linux (`systemctl show cbb -p MemorySwapMax` is 0).
3. After 65 s read every clipboard.
Pass: no hit; swap off; gone.

**S11. Local access.** Runs: auto (`full`, Linux, the lite member and the Mac); Windows manual.
1. As a user outside the `cbb` group run `cbb status` and `cbb paste`, on Linux,
   macOS and Windows.
Pass: refused with a message that names the group; the admin socket refuses non-admins too.

**S12. Installers' firewall.** Runs: manual (passed on the bench).
1. After each install list the rules: `ufw status verbose`, `Get-NetFirewallRule -DisplayName
   Copy Beyond Borders*`, the macOS application firewall.
Pass: only the member port and mDNS from the local subnet; the tunnel port only on the hub.

**S13. Two groups on one network.** Runs: manual.
1. Make a second group of other devices with its own hub on the same LAN.
2. Copy markers in each.
Pass: no text, record or device list crosses; neither pairs into the other without a code.

**S14. A stranger at home.** Runs: manual.
1. From a device in no group dial the member port (`openssl s_client -connect MEMBER:8764`).
2. Replay a captured member connection.
3. Try pairing codes against an open window.
Pass: refused each time; the counter stops guessing after three; nothing about the group is
learned (no names, no tag in any answer).

**S15. Logs.** Runs: auto (`full`, in the build's error mode; the other mode manual).
1. After `full`, in both modes (`CBB_DEBUG=0` and `1`), search every log (R6) for markers,
   pairing codes and key material.
Pass: no hit.

**S16. Files at rest.** Runs: auto (`full`; Windows not yet).
1. List the state directories with permissions after `full`.
Pass: only keys and certificates, owner-only permissions; no clipboard text anywhere.

**S17. Commands.** Runs: manual (step 3 planned: a helper that captures and replays a command).
Devices: `desktop` (the root), `win` or `mac` (an admin), `lite`.
1. On the admin `cbb sync -on lite off`; then on `desktop` `cbb freeze` the admin and repeat;
   `cbb unfreeze` it.
2. Set `lite`'s clock 2 minutes back, send a `mode` command (`cbb sync -on lite off`), set the clock right.
3. Send one command twice with the same `id`.
Pass: the admin's command is taken, a frozen admin's is refused; a command more than 60 s
ahead of the receiver's clock is refused; the second copy is refused by the replay cache;
each refusal says why on the sender, and the receiver's log names the sender.

**S18. The servers keep nothing.** Runs: manual (the forwarder and the relay of P12, with
`cbb-forward.service` and `cbb-relay.service` from packaging/linux).
1. With `CBB_DEBUG=0`, then `1`: run P11 through the forwarder and P12 through the relay,
   with a hub and a device on another network, and one handshake with a key the group does
   not know (S5).
2. Search the services' journal (`journalctl -u cbb-forward -u cbb-relay`), the system log
   and every file under the units' state directories and `/var/log` for the addresses of the
   hub and the devices, the group tag, the device IDs and names, and the markers.
3. `systemd-analyze security cbb-forward cbb-relay` on the server.
Pass: no hit; the state directories hold only the keys and the forwarder's state; the
exposure is 2.0 or less.

## 6. Long run (section 10)

**Soak.** Runs: planned (24 h).
1. The group of R2 plus the away computer.
2. Every 30 s a random member copies a marker; every hour one F case runs.
3. Every 5 minutes sample each service's memory and open file descriptors.
Pass: every marker arrived; memory and descriptors stay flat; no service restarted except by a
test.
