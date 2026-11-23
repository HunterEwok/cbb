<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Testing

For contributors and reviewers: how Copy Beyond Borders is tested, from a single function to
real devices, and which level answers which question. The commands are in
[CONTRIBUTING.md](../CONTRIBUTING.md#development), the CI jobs one by one in
[maintaining](maintainers/maintaining.md#ci), and the tests on real devices in the
[test bench](maintainers/testbench.md).

## Levels

| Level | What it shows | Where | Runs |
|---|---|---|---|
| Unit tests | one package or type does what its comment says | `*_test.go`, `cargo test`, `swift test`, `./gradlew -p kit test` | every push, in CI |
| Interop vectors | the four implementations (Go, Rust, Swift, Kotlin) read and write the same bytes | `testdata/interop` | every push, in CI |
| Cross tests | two implementations talk over a real connection | Go tests that start `cbb`, and the kits' tests that join groups of 0.6 through the core | every push, in CI |
| Service tests | several members, with their real services, in one process or as programs | `internal/service`, `member/tests` | every push, in CI |
| System tests | the built program on a real system: containers, sockets, a desktop, an installer | the `e2e`, `mdns with avahi`, `desktop clipboards`, `packaging`, `windows installer`, `OpenWrt`, `freebsd` jobs | every push, in CI |
| App builds and tests | the apps build and their unit tests pass on simulators and runners | the `iPhone app`, `tray app`, `Android app` jobs and the Mac app's part of `test and build (macOS), homebrew, Mac app` | every push, in CI |
| Bench scenarios | real devices pass real copies over real networks | the [test bench](maintainers/testbench.md), its [catalogue](maintainers/testbench-catalogue.md) | before each release |

A change is not done before the levels it touches pass locally (CONTRIBUTING lists the
commands per part); CI then runs the jobs of every part the pull request changes, and the
`ci-ok` job sums them up for the branch rules. Which part a path belongs to, and which parts
read another's files, is in `.github/ci-changes.sh`; a path it does not know, the workflow,
`go.mod` and `testdata/` run every job. A skipped job has nothing new to test: the pull
request is up to date with main, whose run tested those files when they last changed.

## Unit tests

- Go tests run with the race detector on Linux x86-64, Linux ARM64 and macOS, under QEMU
  for big-endian 32-bit MIPS, and on FreeBSD. A change to Go is tested under it on a Mac too
  before it is pushed, since a fault of one system's race build shows only there: gVisor's
  race build on ARM64 kept its network stack from ever sleeping (fixed in its 2026-08 versions),
  which on the runner's three cores slowed the tunnel's tests past their waits, while Linux
  x86-64 passed them in a fraction of a second.
- Time comes from the caller (`now time.Time`), so a test sets the clock; lifetimes and
  renewals are tested at their edges without waiting.
- The TPM code runs against swtpm (`internal/tpmkey`), the ei protocol against a test EIS
  server (`internal/ei/eitest`), the clipboards against wl-clipboard and xclip.
- The Rust core is `no_std`; its tests run on the host, and CI builds it for the ESP32-C6
  and ESP32-S3 and runs the firmware's self-test in Espressif's QEMU.

## Interop vectors

`testdata/interop` holds JSON files of fixed inputs and the exact bytes each implementation
must produce or accept: certificates, device and revocation records, freezes, takeovers,
admin CAs, commands, quick actions, server credentials, releases, attestation evidence, the
watch's state, content hashes, join QR codes and a CPace exchange.

- The files named `go-*.json` and those without a prefix are written by Go tests with
  `-update` and read by the Swift kit, the Kotlin kit and, for what it implements, the lite
  core (`core/src/vectors.rs`).
- `seal-go.json` holds messages Go's `crypto/hpke` sealed with the sealing suite, and
  `seal-rust.json` what the core seals; the core opens both, and no Go test writes the first
  again.
- A Go test fails when a committed vector is out of date, and names the command that
  writes it again.
- `xwing-hpke-pq.json` is the vector of draft-ietf-hpke-pq-05 for the sealing suite, copied
  from the draft; the Rust core opens its messages, and no test writes it.

A change to the wire format changes the vectors in the same pull request, together with
[the protocol](protocol.md) and every implementation.

The [differential run](differential.md) changes these bodies and record sets at random and
checks that all four implementations still read them alike; a case they read differently
becomes a vector here.

## Cross tests

- The Swift and Kotlin kits join groups of 0.6 through the core and sync through its member
  (`CoreMemberTests`, `CorePairingTests`, `WindowTests`; `CoreMemberTest`, `CorePairingTest`).
- `TestAloneMember`, `TestAloneRemotePaste` and `TestAloneQuickActions` run the built cbb
  without its helper (`CBB_TEST_ALONE`) among other services at home. Sync away from home runs only in
  a group of 0.6 (D-122): `member/tests/away_live.rs` and `away_hubs.rs` (the latter with
  `--features testhooks`) run real services of such a group through the hub's tunnel.

## Service and system tests

- `internal/service` starts whole members in one test: sync, pairing, remote paste, quick
  actions, sync away from home through a hub, a forwarder (`TestAwayThroughForwarder`) and a
  relay (`TestAwayThroughRelay`), with obfuscation (`TestAwayObfuscated`).
- `member/tests` runs the Rust `cbb service` as programs on the loopback, without mDNS, and
  talks to them over the control and admin sockets as plain JSON (`common/mod.rs`):
  `control_contract` checks that every operation answers once and on the right socket and
  that a broken client never stops the service; `control_admin` admits, renames, removes,
  freezes, makes admins, hands over and takes over; `remote_commands` carries out remote
  paste and quick actions through a member's watchers; `helper_faults` runs a fake
  cbb-helper that crashes, hangs, writes garbage or plays a TPM. `cli_commands` checks the
  command line against a fake service.
- `tools/e2e/e2e.sh` runs the built static binary as three members and an avahi browser
  in Docker containers: mDNS, pairing with codes, sync, a wrong code.
- The installer jobs install, run and remove the service on each system they cover.

## Running tests in parallel

Go runs the packages of `go test ./...` at the same time, and Cargo the tests of each test
binary; the tests of `internal/service` do not run in parallel within one process, since each
starts whole members that find each other by mDNS on the same network. CI splits them into
parts instead, each on a machine of its own:

- `service tests on the Rust cbb, the build` builds every program once, instrumented for the
  coverage (the Rust `cbb`, `phone-on-linux`, a `cbb-helper` and the Go
  test binaries built with `-cover`), runs the Rust cbb's own tests and hands the build on as
  one archive.
- `service tests on the Rust cbb (1)` to `(6)` each run a part of `internal/service`;
  `(others)` runs the desktop connector, the relay, the phones' tunnel and the previous
  release. Each writes its Go coverage (`cover-go-service-PART.out`) and its Rust profiles.
- `service tests on the Rust cbb, the coverage` adds up the Rust profiles of the build and
  every part into `rust-service`.

`tools/shard` makes the parts: it reads the test names (`service.test -test.list .`) and
prints the `-test.run` expression of one part, filled longest test first from the seconds
in `tools/shard/service.txt`. Every test is in exactly one part, a new one included, which
counts as a median test until the file names it. After the tests' times change much, record
a full run's `-v` output into the file:

```sh
go run ./tools/shard -record tools/shard/service.txt <service-test.log
```

On a computer with Docker, `tools/e2e/parallel.sh` runs the same parts at the same time, each
in a container on a Docker network of its own, after one container has built the programs
and the test binary; IMAGE is a Linux image with Go, Rust, swtpm, Xvfb and xclip:

```sh
sh tools/e2e/parallel.sh -n 6 IMAGE              # every test of internal/service
sh tools/e2e/parallel.sh -run 'Takeover' IMAGE   # only those -run names
```

Other jobs run side by side the same way: the iPhone app's UI tests on an iPhone and an iPad
simulator are two jobs, the Rust workspace's checks and Raspberry Pi builds
(`cbb (Rust), the checks and the Raspberry Pi builds`) and its optimized builds and installers
(`cbb (Rust), the optimized builds and the installers`) run beside its tests (`cbb (Rust)`),
which run as the service tests do: one job builds them once into a cargo-nextest archive,
four parts run a share of its tests each (`--partition`; within a part cargo-nextest runs the
test binaries side by side, `.config/nextest.toml`, and the tests that time their own run
run alone), and `cbb (Rust), the coverage` puts the parts' profiles together into one report,
and the Kotlin kit's tests (`Android kit`) beside the Android apps' build (`Android app`).

The account runs at most 5 macOS jobs at a time, so the macOS jobs do no more than they must:
the iPhone app's jobs build only the simulator's Rust library for the runner's processor
(`ffi/bind.sh ios-sim`; the phone kit's macOS job builds all three with the latest Rust),
they do not run for a change that touches only Go (`iosapp` in `.github/ci-changes.sh`; the
kit's interop tests still do), and jobs shorter than the iPhone app's share a machine: macOS's
`go test`, the macOS archives, Homebrew's formula and the Mac app
(`test and build (macOS), homebrew, Mac app`), and the phone kit with the iPhone's libraries.
So the iPhone and the iPad, the longest, start at once, each booting its simulator while its
Rust builds. The iPhone app's CodeQL analysis (`codeql-swift.yml`, about half an hour, built
for the runner's processor only) runs on a pull request after them, from `ci.yml`, not beside
them.

The jobs that build the most Rust on the way to their tests (the iPhone app, the phone kit
on macOS, the Android phone core and the service tests' build) keep their build in the Actions cache
(`.github/actions/rust-cache`). A pull request saves its own and its later runs take it, so
they compile only the crates it changed; another pull request never reads it, and the release
and F-Droid builds build from nothing.

## Before and beside CI

A change is tested where it can be before it is pushed: the cloud sessions run everything that
runs on Linux (the Rust and Go tests, the service tests on the Rust `cbb`, the e2e, the
format's vectors). Right after the push, while CI runs, a maintainer's macOS machine runs what
only it can (the Apple builds and their unit tests, Go with `-race` on macOS), a Linux machine
builds the Android apps and runs their unit tests, screenshots, lint and the F-Droid build, and
a Windows machine runs Go and Rust on Windows and the installer. The Android emulator suite
needs a machine with hardware virtualization and runs in CI. They
answer in minutes what CI answers in most of an hour, so a red result is fixed before CI ends;
CI stays the gate before the merge.

## Time

Rules that live for days are walked with a moved clock, never waited for.

- The core reads no clock: it takes its own clock for the keys and a leaf's running time as
  inputs. `core/src/longrules.rs` plays the caller hour by hour and day by day: the weekly
  change of the sealing keys with a device that sleeps three weeks and asks for its copies to
  be sealed again, a clock set back by weeks that does not stop that change, a guarded
  leaf's 35-day grant on its running time, and a change of root by the recovery key (rule 33),
  which counts at once whatever the clock says, survives a restart, and leaves the old root's
  later records, at any date, without effect.
- The Rust service has one wall clock, `uptime::wall_ms()`, and one clock of running time,
  `uptime::now()`; `tools/repocheck` refuses a read of the system's wall clock anywhere else
  in `member/src` but the few files that decide no rule. The tests move both through the file
  `CBB_TEST_AHEAD_FILE` names: `testClock.set` moves the wall clock as a person sets it,
  `testClock.run` moves both as if the machine had run that much longer
  (`internal/service/time_test.go`). The Go helper reads no clock.
- When the service moves to the 0.6 core (wave 5), `internal/service/time_test.go` gains the
  core's rules through the whole service: a change of root by the recovery key with a member
  off at the time and one restarted in the middle; the weekly key change with a member
  that slept through two changes and gets its copies sealed again; a guarded leaf whose grant
  goes stale after 35 days of running time and obeys nobody until it has a new one; a wall
  clock set back by days during each of them.

## Power loss

A save cut short must leave the old state or the new one, and a member must never act on
what it has not saved.

- `core/src/powerloss.rs` runs a member's life (records, a removal, commands sent twice,
  copies with a secret sent twice, a change of root by the recovery key with its list) through
  the two-slot store
  of a device with only flash (`crate::store`), and cuts every save after each of its bytes,
  the rest of the slot erased or stale. After each cut it starts again from the flash, is
  sent again what it was handling, and must end as a member never cut: the state reads, is
  the one before or after the save, no command runs twice or is lost, no copy is written
  twice, and a change of root it reported stays.
- The Rust service writes its state files through `files::write_atomic` (a new temporary
  file, sync, rename). Its tests cut that write at every byte and step, as a process that
  dies and as an error of the system, and find the old file or the new one; the temporary
  file a crash leaves is swept at the next start once an hour old (`files::sweep`).
- When the service moves to the 0.6 core, its saves of the core's state (the records with
  the lists of the changes of root, the command counters, the freshness marks) join the same cut at
  every step through the whole service.

## The simulation

`core/src/sim` runs a whole group in one process: 3 to 12 members on a network and clocks the
test plays, every choice drawn from one seed, so that a failure replays from its seed alone.

- The network delivers, drops, duplicates, delays and reorders messages, splits the members into
  two sides and heals; a member crashes, also in the middle of taking a message, and restarts
  from what it wrote; clocks move by up to two minutes either way. Outside actions: copies,
  admissions, removals, freezes and thaws, admins made, checkpoints, a change of root by the
  recovery key on any member, two such changes at one seq (a fork), and a member off while days
  pass, its keys changing on its return.
- During the run: no member shows a copy as new twice; a removed member opens no copy sealed
  after every other member had saved its removal (until a change of root brings it back); a
  member that holds both heads of a fork is halted.
- Then the network goes quiet: healed, every member back with the world's clock, every pair
  synced until nothing changes. Every member of the group holds the same records (in a halted
  group, every member ever admitted is halted on the same fork); a removed
  member has learned its removal; each member restarted from what it wrote has the records and
  the state it saved. Unless the group is halted, two members in turn send a last copy, newer than
  any: it is sealed to every reader of the group and shown as new by each of them.
- The members speak through `sim/exchange.rs`, the glue that stands in for the member protocol's
  sync; wave 5 puts the core's sans-I/O connection in its place, and with it the check that
  connections settle.
- `cargo test -p cbb-core --lib sim::` runs 16 seeds of 300 steps; `SIM_SEEDS`, `SIM_FIRST` and
  `SIM_STEPS` change that, `SIM_SEED` runs one, and `SIM_ALL=1` lists every failing seed rather
  than stopping at the first. A failure is cut down to the fewest steps that still fail and
  prints its replay, `SIM_SEED=… SIM_STEPS=… cargo test -p cbb-core --lib sim::`. The nightly run
  takes a thousand seeds from a fresh start.

## Recovery drills

What a person does after a loss, played on whole members by `sh tools/e2e/drills.sh`: the root
lost and the group taken back with the recovery key, then handed to an admin
(`TestRecovery`); a phone in the group changing the root with the recovery sheet
(`TestFFIPhoneChangeRoot`) or with the secret a YubiKey opens (`TestFFIPhoneYubiKey`), the
phone's member on Linux; a device restored from yesterday's backup that gets back in while
the group went on (`TestDrillRestoreFromYesterday`); a removed device restored from a backup made
before its removal that stays out (`TestDrillRemovedStaysOut`). What a real iPhone's Secure
Enclave and Face ID add is a hand checklist in the bench's test plan, run once before a release.

## Soak

`tools/soak/soak.sh` runs a small group of a build's `cbb` for days on one machine, on 127.0.0.1
only, and checks that what is copied arrives everywhere and that a member killed with SIGKILL
starts whole. Several stands run side by side, each with its own name, folder and ports
(`SOAK_NAME`, `SOAK_DIR`, `SOAK_PORT`), in two profiles:

- **calm**: 3 members; a line every two minutes, checked on every member; a member killed every
  10 to 60 minutes.
- **load**: 8 members; the calm lines, and every ten minutes a burst of a copy a second for a
  minute (one in ten a text at the 1 MiB limit), its last copy checked on every member; every
  half hour a file of up to 64 MiB, checked by its hash on every member; the kills inside the
  bursts. It runs under `nice` on one core, so that a calm stand beside it keeps its numbers.

Once a day a line goes to `soak.log`: copies sent and checked, arrived and missed, kills, whole
and broken starts, the delivery time of the checked copies (p50, p95, max over the slowest
member, and each member's p95, to tell which one was slow; the members are asked in turn, so
each time includes the asking before it), the largest RSS and open files, and how each member's memory and open files moved. A
single sample of RSS swings by megabytes as large copies come and go, so memory is judged by
floors: after an hour's warm-up (again after each restart) a member's samples, one every ten
minutes, go into windows of an hour, and a window's floor is its least RSS and open files.
`soak.sh verdict` prints the pass or fail line so far, and `soak.sh stop` ends with it: PASS when
no copy was missed, every start was whole, no member's RSS floor grew over its first window's by
more than 1 MiB on the calm stand or 4 MiB on the loaded one, no member's RSS floor rose in three
windows in a row (a rise being at least 64 KiB over the previous window's floor), no member's floor of open files rose over its first window's, the members' folders (state, records
and logs) grew by at most 20 MiB a day each (measured from six hours after the first sample), and
the delivery time's p95 is at most 10 s. The bounds were fixed before any long run was measured: a run over
them is a finding, not a reason to move them. Beside the verdict the single samples' numbers are
printed as `raw_*`, for reading. A checked copy that is not on every member within 60 s counts as
missed, also when it was sent just after a kill: a restarted member is back and has it within a
minute, or the run fails. These bounds follow the service's reconnect wait (5 s after a lost
connection, `RECONNECT_WAIT` in `member/src/node.rs`) and the 15 s timeout of a silent peer;
they are set again when the reconnect work (#539) changes either. A third profile, one service
process in two groups (the family case), waits for wave 5, when one service holds several
groups.

One member of each stand is never killed, so that a slow leak inside one long-lived process shows.

A release candidate's build runs seven days on the shared bench's Raspberry Pi 4, the calm and
the load stand side by side, before the release (a release condition), and goes on to thirty.
Both stands run the candidate's build, and the count of days starts again with any change to the
code in the candidate: a fix makes a new candidate and a new seven days. Only changes to the
documents and the site leave the count running. A counted run reports, for each stand: the days, the commit, the hardware (`soak start` writes
the machine and its cores), copies sent, checked and missed, kills and broken starts, the
delivery times, the memory and open files with their growth, and the verdict. The documents
give only numbers measured that way.

## Bench scenarios

Unit and CI tests cannot show that a copy on an iPhone reaches a Windows PC through a café's
Wi-Fi. The [test bench](maintainers/testbench.md) does, on the real devices of each platform, with the
rules R1 to R7 ([cases](maintainers/testbench-cases.md)), a catalogue of the cases of a release with how
each runs, and a coverage report of the product's functions
([functions](maintainers/testbench-functions.md)). Security cases block a release; a case that cannot
run yet is skipped with its reason and stays on the list.

## The apps' languages, accessibility and screenshots

Every app is checked in the project's eight languages (zh en es ru ar sw he hi) and for a
person who uses a screen reader, large text or the keyboard (docs/maintainers/testbench-catalogue.md,
A9 and U14 to U18).

- `tools/repocheck` checks that every text of every app (the String Catalogs, Android's
  `strings.xml`, the tray's and the command line's JSON) is translated into all eight, marked
  done, and keeps the original's placeholders. `tools/tokens` checks that every palette keeps
  WCAG AA contrast for text, the accent included, on the background and on a surface.
- The tray app (`apps/desktop`, `TestWindow` in a headless Chrome): each language without
  English left over, clipped text or a page wider than the window, Arabic and Hebrew from
  right to left and no text set to one side; every control named in the accessibility tree;
  every text's contrast in all ten colours, dark and light; the window at twice the text size;
  Tab through the header and Settings with the focus shown.
- Android (`LanguagesTest`, `AccessibilityTest` on Robolectric): the Start screen and Settings
  in each language, no text cut off or ended with "…", right to left in Arabic and Hebrew,
  every control named and at least 48 dp to touch, nothing cut off at font scale 2.
- The iPhone and the Mac (`ReadersUITests`): each language launched with `-AppleLanguages`,
  the texts checked against the app's catalog, the iPhone's top row swapping sides from right
  to left, and Xcode's accessibility audit (clipped text, descriptions, touch targets; on the
  iPhone also Dynamic Type and clipped text at the largest size in English, Swahili and
  Hindi) passing; each screen's picture is attached to the run's `.xcresult`, uploaded by CI (`ios-screens-iPhone`, `ios-screens-iPad`, `mac-windows`), and the English ones
  are printed into a failed job's log (`.github/pictures.py`), with, on the iPhone, a picture
  of each element the audit fails and of the screen a lost tap met (the test taps Settings
  again and says so in its output). For each failed iPhone test CI also keeps its activities,
  every launch, tap, wait and query with its time (`.github/activities.py`, in `ios-screens-*`
  and the log). The audit's contrast check
  fails text its own picture shows at 6.9:1 and more, so each text's (and on the iPhone each
  button's) contrast is measured on the screen's picture instead: its darkest and lightest
  pixels at least 4.5:1. The iPhone's Start screen scrolls rather than squeeze its texts. The
  audit looks only at what a person can reach.
- The iPad (`PadUITests`, skipped on an iPhone): Home with a made-up group, which a debug
  build starts with when launched with `-showcase` (`App/Showcase.swift`; nothing leaves the
  app): the sidebar's sections, a tile's card beside the tiles, the arrows and Escape, a
  settings part, Command-1, portrait, the card at the left in Arabic, and clipped text at the
  largest size; each screen's picture is attached. Escape is sent as U+241B
  (`XCUIKeyboardKey.simulatorEscape`): the simulator's keyboard has no key for `.escape`'s
  "\u{1B}" and sends nothing for it.
- In CI both run on GitHub's `xcode-27` image with Xcode 27.2 and the newest iOS, as on the
  maintainers' Macs: Xcode 26.6's iOS 26.4 takes whole Devanagari and Chinese texts for clipped
  (the clipped text check compares the first two and the last two letters' frames, which a
  conjunct such as ग्स or a squeezed 「。」 at a line's end share).
- The other big screens: on Android `TabletHomeTest` keeps the sidebar's sections across a
  restart (their keys back to the same section); the HarmonyOS sidebar, keys and drops are
  compiled and linted by `apps/harmony/check.sh`, and the Aurora layout by `qmllint`. None of
  the three is yet run on a tablet.

Screenshots are compared where a picture is the same on every machine that draws it: the
tray window on Linux in the Noto fonts (`fonts-noto-core`, `fonts-noto-mono`,
`fonts-droid-fallback`), and the Android screens in Robolectric's native graphics, which
bring their own fonts. A picture may differ from its reference in 0.3% of its pixels, the
smoothing of text between two builds of a browser, not more. A failed comparison leaves the
new picture and the difference in the job's artifacts. The simulators' pictures change with
each Xcode and iOS, so the iPhone's and the Mac's are kept with the results to look at, not
compared.

After a change to a screen, write the pictures again and look at each before committing it:

```sh
cd apps/desktop && CBB_UPDATE_SCREENSHOTS=1 go test -run 'TestWindow/screenshots' .
cd apps/android && ./gradlew :app:recordRoborazziFullDebug
```

The tray's references are CI's pictures: another build of Chrome smooths text differently in
more than 0.3% of the pixels. When a run elsewhere draws them, compare them by eye and take
the ones to commit from the `tray-screenshots` artifact of the failed CI job.

### The dangerous screens

`TestWindow/dangerous screens` (`apps/desktop/dangerous_test.go`) draws every screen of the tray
app where a person decides something the group's safety depends on, in all eight languages, into
one HTML file: the six digits a joining computer shows, an invitation's fingerprint to compare,
removing a device, making a computer an admin, the takeover warning and the alerts of admins or
claims that split the group, voiding a key's two histories, claiming the group with the recovery
key, and a group taken over from this device. Each picture has its words under it, for a native
speaker to quote. The Android app's part (`DangerousScreensTest`, on Robolectric's native graphics) adds an
invitation's fingerprint, removing a device and the root phone, the alerts, and the recovery
sheet with the question on closing it. It is for a person to read before a release; nothing
compares it. It runs only when asked, Android first, as the tray's test puts its pictures on the
sheet:

```sh
export CBB_DANGEROUS_SHEET=/tmp/sheet
(cd apps/android && ./gradlew :app:testFullDebugUnitTest --tests 'tools.cbb.DangerousScreensTest')
(cd apps/desktop && go test -run 'TestWindow/dangerous' .)
```

The iPhone's screens are not on it yet: they would come from `ReadersUITests` on a Mac.

## Coverage

CI measures how much of the code the tests run, part by part and by kind, and its `coverage`
job prints the table, coverage by kind, in the run's summary. `tools/coverage` adds the
reports up and fails when a row falls more than one point below its floor in
`tools/coverage/floor.json`. The project aims at 90% of the lines in every part
(`-target 90`): a part below that is marked in the table and gets a warning, without failing
the run. A floor only rises: it is set at the whole percent under the part's last measure
whenever tests raise it, so coverage once won is not lost again.

Branches are rows of their own (`PART/branches` in the table and in `floor.json`) where the
report counts them: JaCoCo for the Kotlin kit, llvm-cov for the Swift kit, and for the Rust
core the nightly `rust core, branch coverage` job, since only a nightly compiler counts Rust's
branches. Go counts statements only. The aim is 80% of the branches (`-branch-target 80`),
90% in a core (`-core-branch-target 90`), where each branch is a decision to take or refuse;
a branch row's floor is its first measure, and it only rises. The table shows each row's floor
and target side by side, so the gap between them is in view.

Under the table are the hard gates, which have no floor and fail the job at once:

- every closed finding of the security audits keeps its tests: `testdata/audit/closed.json`
  lists each by an opaque id with the tests that hold it closed, and `-audit` fails when one
  of them is gone; a fix that closes a finding adds its row, and a test removed with the
  code it held names, in the finding, the replacement `tools/repocheck/removed-tests.txt`
  gives it;
- every rule a format reader refuses by name (`Rule::field("grants/replaces")` in `core/src`)
  is the expected refusal of at least one vector in `testdata/format/*.json` (`-rules`,
  `-vectors`): a vector with that `rule` and the verdict `refuse`, or one whose `verdict`
  is the rule itself (`"verdict": "content/type"`, as wave 4's and push's vectors write
  it); the rules of a test's own tables (`tests.rs`) are not counted. A rule whose refusal
  depends on what the reader already holds (a command's counter, a grant's earlier branch,
  a key no longer current, the clock) cannot be a vector of bytes alone: a Rust test in
  `core/src` marked `// refuses: <rule>, <rule>` on the line above its `#[test]` counts
  instead, when its body names the rule, as its string or one of its constants. A stateful
  vector format, which the Go reader would check too, is for 0.7;
- no mutant survives that `tools/mutants/missed.txt` does not name (`-mutants`, as
  `tools/mutants/check.sh` in the nightly jobs).

| Part | What counts | Measured by |
|---|---|---|
| `go` | statements of `cmd`, `internal` and `mobile`, without `third_party` and the packages only tests use (`eitest`, `testnet` and the others `tools/coverage` lists) | the `go coverage` job: every test across packages (`-coverpkg`, so a test of `internal/service` counts for `internal/group` too), the desktop clipboards under sway and Xvfb, the uinput keyboard against the kernel, mDNS beside avahi-daemon, the e2e's members built with `-cover`; the `service tests on the Rust cbb` jobs' tests of `internal/service` and the desktop connector against the Rust `cbb`, whose `cbb-helper` is built with `-cover`; and each system's own files from the `test` jobs on Linux, macOS and Windows |
| `go-core` | the same, in `internal/group`, `clip` and `hlc` | as `go` |
| `rust-core` | lines of `core/src`, without `third_party` | `cargo llvm-cov nextest` in the four `cbb (Rust)` parts, put together by `cbb (Rust), the coverage` |
| `rust-member` | lines of `member/src/`, by the Rust tests alone | as `rust-core` |
| `rust-service` | lines of `member/src/`, by the Rust cbb's own tests and Go's tests of the service together (`internal/service`, the desktop connector and the phones' tunnel, run against a `cbb` built with instrument-coverage) | `cargo llvm-cov` in the `service tests on the Rust cbb, the coverage` job, from the build's and every part's profiles |
| `swift-kit` | lines of the Swift kit's `Sources` | `swift test --enable-code-coverage` in the `phone kit (macos-latest)` job |
| `kotlin-kit` | lines of the Kotlin kit | JaCoCo in the `Android kit` job |

A test that compares two times of its own run is not timed under `cargo llvm-cov`, which counts every step of the code under test and none of its dependencies (`cfg(coverage)`): the full group's fill against its signatures (`records::tests::insert_cost`) is ignored there and runs in the `cbb (Rust), the checks` job's plain build.

The core's tests too slow for a pull request are `#[ignore]` there and run in the nightly `the core's slow tests` job: the record set's restores step by step (`core/tests/read_records.rs`) and the timing tests of the secrets' comparisons (`core/src/secret.rs`, dudect's method, one thread). A coverage build leaves the timing tests out (`cfg(coverage)`), since they never run there. An `#[ignore]` names where the test runs or why it waits.

The Go packages of the `service tests on the Rust cbb` jobs run as test binaries built with `-cover`, beside a `cbb-helper` built with `-cover`, and each part's profile (`cover-go-service-PART.out`) counts in `go` too.
A number is a hint, not the goal: a test that runs a line without checking what it did
raises it and proves nothing.

To see Go's numbers locally:

```sh
go test -coverpkg=./cmd/...,./internal/... -coverprofile=cover.out ./cmd/... ./internal/...
go run ./tools/coverage -go cover.out -floor tools/coverage/floor.json
```

And the Rust service's, on Linux (the tests of `internal/service` need mDNS, so a computer on a
network or a container with one of its own):

```sh
eval "$(cargo llvm-cov show-env --sh)"
cargo llvm-cov clean --workspace
cargo test --release -p cbb-member && cargo build --release -p cbb-member --features testhooks
CGO_ENABLED=0 go build -tags testhooks -o target/release/cbb-helper ./cmd/cbb-helper
CBB_TEST_RUST_SERVICE=$PWD/target/release/cbb CBB_TEST_ALONE=$PWD/target/release/cbb go test ./internal/service
cargo llvm-cov report --release --json --summary-only --output-path service.json
go run ./tools/coverage -llvm rust-service=service.json -floor tools/coverage/floor.json
```

A member finds a pairing window, and the other members, only at a home address (a private,
link-local or unique local one), as on a real network. A container whose one address is
public finds none; run the tests there in a network namespace of their own with a private
address, as root and with `iproute2`:

```sh
unshare -n sh -c 'ip link set lo up && ip link add home0 type bridge &&
  ip link set home0 multicast on && ip addr add 10.77.0.2/24 dev home0 &&
  ip link set home0 up && ip route add default dev home0 && exec "$@"' _ \
  env CBB_TEST_RUST_SERVICE=$PWD/target/release/cbb CBB_TEST_ALONE=$PWD/target/release/cbb \
  go test ./internal/service
```

## Firmware size

A small device takes only the parts of the core it calls, and the linker drops the rest, so
what a part costs shows only in a linked program. `tools/size` is a program for the ESP32-C6's
RISC-V (`riscv32imac-unknown-none-elf`, the workspace's release profile) that calls the parts
its features name with input the linker cannot see through; it is never run. `sh
tools/size/size.sh` builds it empty, once per part (`p256`: X.509 and a chain check; `json`;
`records`: the group's records and their state; `seal`: opening a sealed message, X-Wing;
`copy`: a copy read, checked and opened; `pair`: a joiner and CPace; `tls`: the member TLS),
with all of them, and with the core's whole entry point (`api`), and prints each program's
flash (`.text`, `.rodata` and `.data`) and its cost over the empty one against
`tools/size/baseline.txt`. The `esp32` job runs it on every change to the Rust code and puts
the table in the job's summary; it fails when everything together grows more than 10% over
the baseline. A change that makes the core larger on purpose writes the baseline again with
`sh tools/size/size.sh -update` in the same pull request. The parts overlap (`copy` holds
`records`, `seal` and JSON), so the costs do not add up to `all`.

## Unsafe code

The Rust core has no unsafe code (`forbid(unsafe_code)`). The unsafe code in `member/src` (system
calls) and `ffi/src` (the C functions the phones call) is checked by the nightly workflow: Miri
runs `ffi`'s tests of its C functions pointer by pointer (`cargo +nightly miri test -p cbb-ffi
--features join --lib`), and AddressSanitizer runs the Rust tests of `cbb-member` and `cbb-ffi`
and Go's tests of the service against a `cbb` built with it, which reaches the system calls
Miri cannot.

## Mutation testing

Coverage says a line ran; mutation testing says whether a test would notice if it were wrong.
The nightly workflow changes the code one place at a time (drops a check, turns `<`
into `<=`, returns early) and runs the tests against each change: `cargo mutants` on
the strict form of signed bodies (`core/src/strict.rs`), in eight shards. A change that every test still passes is listed as missed, in the run's
summary and its artifacts. The Rust job fails on a survivor that `tools/mutants/missed.txt`
does not name (no new survivor, from the first day); the list holds the baseline of
2026-11-11, and each of those gets a test or a note why it cannot matter.

The service's readers of outside input already fail on a new one: `cargo mutants` on the
control socket's messages (`member/src/control.rs`), the pairing window
(`member/src/window.rs`) and the seals of the copies (`core/src/seal.rs`), in four shards each, with `tools/mutants/check.sh`, which
compares what lived with the known list, `tools/mutants/missed.txt`, line and column aside. A
mutant on that list either changes nothing a caller can see (an equivalent mutant, with why
in a comment) or lives in code that only Go's end-to-end tests reach, which `cargo mutants`
does not run (the window's exchange with a joiner). A new survivor gets a test; a mutant that
the tests now catch can leave the list.

To run them locally:

```sh
cargo mutants --in-place -p cbb-core -f core/src/strict.rs
cargo mutants --in-place -p cbb-member -f member/src/control.rs -f member/src/window.rs
tools/mutants/check.sh mutants.out/missed.txt tools/mutants/missed.txt
```

## Not tested yet

What has not run on real devices is listed in the [README](../README.md#status): the
Android phones' hardware keys and the fingerprint, Android 17's local network permission,
the iPhone's background app refresh and takeover, and the Windows service on a real PC
among them. Do not rely on
these before the bench has run them.

## Red tests

A failing test is a finding, never noise: find the cause before running it again. A test is
never skipped, disabled or retried until green to make CI pass.

A test that needs something of its machine (an X server, a compositor, the IPv6 loopback, a
tool) skips without it on a developer's machine and says why, but fails in CI, where that
thing is set up on purpose: the environment variable `CI`, or the test's own switch
(`CBB_TEST_IPV6=1`, `CBB_TEST_UINPUT=1`), turns the skip into a failure.

## Known failures

A step that fails for a reason outside the project, shown with evidence, is not skipped: it
stays, wrapped in a strict expected failure (`XCTExpectFailure` with `isStrict`), so it is
still run, it still fails the test the day it starts passing, and the tag `KNOWN-ISSUE(<release>)`
finds it again (`git grep KNOWN-ISSUE`). What it checks is checked by hand until then. The owner
decides each entry.

No step is marked at the moment.

## Unstable tests

A test that fails only now and then is a red test too, with a cause to find: a race in the
code, a wait too short for a slow runner, or an order the test assumes. The nightly
workflow's `unstable` job runs the members' tests ten times over, against the Rust service with
its helper and with `cbb` alone, and its summary lists every test that failed and how often. A test
found there goes into this table with what is known of its cause, and leaves it with the
fix that removes the cause. The bench finds them too: `go run ./tools/bench -repeat 5
-scenario NAME fleet` lists in `flaky.txt` the cases that both passed and failed
([test bench](maintainers/testbench.md#11-automation)).

| Test | Where | Seen | What is known |
|---|---|---|---|
| `TestSeveralHubs` | `internal/service` | about one run in six, 2026-11 | not yet found |
| `TestWindow` | `apps/desktop`, Windows and Linux | rarely: once on Linux in some 300 runs, 2026-11 | Chrome runs but gives no DevTools port within 30 seconds; on Linux its last line came 5 seconds after the start, after failed D-Bus calls to the desktop portal. The test now writes how long each start took to the job's summary and keeps the last 200 lines of Chrome's detailed log (`--v=1`), to be read when it fails again |
