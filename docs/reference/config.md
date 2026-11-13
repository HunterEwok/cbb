<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Settings and environment variables

Every setting Copy Beyond Borders reads from a file or from the environment. The commands and
their flags are in the [command reference](cli.md); where each system keeps its keys,
state and logs is in [devices, ports and files](devices.md#files-and-logs).

Most settings are made by a command or an installer flag, which writes the settings file
for you. Edit the files by hand only where this page says so: `CBB_INTERFACES` has no
option, so it is set by hand, and the installers and `cbb update` keep that line.

## Settings files

| File | Systems | Who writes it | What it holds |
|---|---|---|---|
| `/etc/cbb/cbb.env` | Linux, macOS | the installers (`--port`, `--home-cgnat`); `CBB_INTERFACES` by hand | `CBB_PORT`, `CBB_HOME_CGNAT`, `CBB_INTERFACES`, one `NAME=value` per line; systemd passes them to the service. The service and `cbb` also read the file themselves |
| `/usr/local/etc/cbb/cbb.env` | FreeBSD, OPNsense | the installer | the same as on Linux; rc.d passes them to the service |
| `HKLM\SYSTEM\CurrentControlSet\Services\cbb`, the value `Environment` (a multi-string) | Windows | `install.ps1` (`-Port`, `-HomeCgnat`); `CBB_INTERFACES` by hand, which `install.ps1` keeps | the same values as the file on Linux |
| `/etc/config/cbb` | OpenWrt | the package, then you (UCI) | `port`, the firewall `zone` list the service works in (it becomes `CBB_INTERFACES`), `wait_ntp` (start once NTP has set the clock); apply a change with `/etc/init.d/cbb reload` |
| `/etc/cbb/forward.env` | a server running `cbb forward` | you | `CBB_FORWARD_FLAGS`, see [running your own servers](../admin/self-hosting.md) |
| `/etc/cbb/relay.env` | a server running `cbb relay` | you | `CBB_RELAY_FLAGS`, see [running your own servers](../admin/self-hosting.md) |

The group's own settings (sync modes, remote paste, quick actions, the hubs, sync away from
home) are not in these files: they live in the state directory, are changed by `cbb`
commands or the apps, and some are signed by an admin.

## Environment variables

A variable set in the environment wins over the same name in the settings file.

| Variable | Read by | Meaning |
|---|---|---|
| `CBB_DEBUG` | `cbb`, the tray app | `1` shows the underlying error under each message; `0` hides it in a development build, which shows it by default. The service's log always has the details. In the service's environment, also WireGuard's own messages for sync away from home and the member connections a peer closed or reset. The Mac app and the tray app pass it to `cbb` when their own error details switch is on. |
| `CBB_PORT` | the service, the installers | The member port, 8764 by default. Change it by running the installer again with `--port N` (`-Port N` on Windows), which keeps it in the settings file. |
| `CBB_INTERFACES` | the service | Network interfaces by name, separated by commas or spaces (`br-lan,br-iot`): mDNS, the member port and a listening join work only there, so that a router never answers on its internet side, even with a private address there or a firewall opened by mistake. Unset or empty, every interface. On OpenWrt the init script sets it from the zones in `/etc/config/cbb`. |
| `CBB_HOME_CGNAT` | the service, the installers | `1` counts 100.64.0.0/10, the carrier-grade NAT range, as the home network too, for a home network that uses it: the service accepts and reaches it, publishes its addresses there, and the installers open it in the firewall and in the system's outbound limit (the systemd drop-in `cgnat.conf` on Linux, the Windows rule). Unset or `0`, it is outside the home network. Set it with `--home-cgnat on` (`off` goes back) or `-HomeCgnat on` on Windows. |
| `CBB_TPM` | the service on Linux, Windows and macOS | `off` keeps new member and admin keys out of the TPM and a Mac's Secure Enclave, in files; a key already in one stays there. Unset, a computer with a TPM 2.0 or a Secure Enclave makes its keys in it ([keys and attestation](../guide/keys.md)). |
| `CBB_CONTAINER` | the service | Set by the Docker image: the service runs in a container, whose keys are in a file in its volume, so it makes no group (`cbb new`, `cbb takeover`) and offers no admin key, and the root cannot make it an admin. |
| `CBB_KEYS_IN_FILE` | the service, in a container | `yes` allows a container to hold the group's keys anyway: to make the group, or to be made an admin and so the hub. Anyone who copies its volume then has those keys. |
| `CBB_ROOTLESS` | `cbb` on Linux | `1`, set by the user units of a rootless install (`install.sh --rootless`), makes `cbb` use the user's own paths: the socket in `$XDG_RUNTIME_DIR/cbb`, the state, settings and update folder under the user's home; the service then refuses to be the root, an admin or a hub. Unset, `cbb` in `~/.local/bin` does the same. |
| `CBB_HELPER` | `cbb` | The Go helper `cbb-helper` to start, instead of the one beside the program; empty for none. Like the one beside it, it starts only if nobody but root or `cbb`'s user may change it (docs/design.md, "The service and its helper"). |
| `CBB_SOCKET` | `cbb`, the Mac app | Another control socket, for tests or a second instance. |
| `CBB_ADMIN_SOCKET` | `cbb` | Another admin socket, the one for the commands that change the group; by default the admin socket next to the control socket. |
| `CBB_STATE` | `cbb` | Another state directory. |
| `CBB_STANDBY_GRACE` | `cbb service` | Seconds a hub that lost the hub above it tries the hubs above before it serves again, 60 by default; tests set it shorter. |
| `CBB_UP_CHECK` | `cbb service` | Seconds a device stays on a hub below the first before it tries the hubs above again, 300 by default; tests set it shorter. |
| `CBB_HUB_KEY_AHEAD` | `cbb service` | Seconds a hub's offers carry its key for a new period of the server credentials before it serves with it, three days by default; tests set it shorter. |
| `CBB_TEST_RESOLVE` | `cbb service` | For tests only: `host=ip` pairs, separated by commas, that stand in for DNS when it looks up the project's relay by the names `entries.json` gives. |
| `CBB_TEST_ELSEWHERE` | `cbb service` | For tests only: a folder; while it holds a file named by the device's ID, the device neither publishes itself by mDNS nor dials the members it finds, as if on another network. |
| `CBB_MDNS_TRACE` | `cbb service` | For tests only: a file to which the service appends, by the time of day in UTC, every event its mDNS browsing sees and mdns-sd's debug log (packets sent and received, the cache); the service tests set it and log the file when a test fails. |
| `CBB_TEST_FALLBACK` | `cbb service` | For tests only: milliseconds a member waits for one with a lower device ID to dial it before it dials that one itself (30 s otherwise); set, the member also dials the members with a greater device ID at port 1, as if a firewall there dropped the member port. |
| `CBB_TEST_APPLETV_NAME` | `cbb-helper` | For tests only: the name an Apple TV announces by mDNS, which the helper then takes instead of browsing for it; empty for none. |
| `CBB_TEST_BLUEZ` | cbb-helper on Linux | For tests only: the D-Bus address of a test's BlueZ (`bluetest`), which the Bluetooth keyboard registers with instead of the system bus. |
| `CBB_FORWARD_FLAGS` | `cbb-forward.service` | The flags of `cbb forward`, such as `-vless-xhttp vpn.example.org`. |
| `CBB_RELAY_FLAGS` | `cbb-relay.service` | The flags of `cbb relay`: `-group TAG` or `-open`. |
| `CBB_TRAFFIC_IFACE` | `site/deploy/cbb-traffic.sh` on cbb.tools | The network interface whose traffic counts for [the servers' budget](../relay-budget.md#money-and-traffic); unset, the default route's. |
| `CBB_TRAFFIC_OUT` | `site/deploy/cbb-traffic.sh` on cbb.tools | Where it writes the totals of the last 24 hours; `/srv/cbb.tools/status/traffic.json` by default. |

### The installers

| Variable | Read by | Meaning |
|---|---|---|
| `CBB_FIREWALL` | `get.sh`, Linux, macOS and FreeBSD `install.sh`, Windows `install.ps1` (through `get.ps1` too) | `express` adds the firewall rules without asking (`--express`), `no` adds none and prints the commands (`--no-firewall`); unset, the installer asks. |
| `CBB_VERSION` | `get.sh`, `get.ps1` | A release such as `v0.5.0` instead of the latest. In a build of `cbb`, the version the release passes to `cargo build`. |
| `CBB_AUTO_UPDATE` | the installers | `on` or `off` answers whether the computer updates itself once a day (`--auto-update`, `-AutoUpdate`); unset, they ask once. `cbb update -auto` changes it later. |
| `CBB_PAIR` | `get.sh`, Linux and OpenWrt `install.sh` | `no` skips the pairing the installer starts at the end for a device in no group (`--no-pair`), for a scripted install; unset, it pairs when its output is a terminal. |
| `CBB_INSTALL_METHOD` | the installers | How the program came, which they record for `cbb update` (`cbb update -installed-by`): `get` by default, `brew` for a Homebrew copy (found from its path), `winget` from winget's folder, `package` for the OpenWrt package. |
| `CBB_UPDATING` | the installers | Set by `cbb update` while it runs the new release's installer, so they ask no question about automatic updates. |
| `CBB_UPDATE_FROM`, `CBB_UPDATE_PARENT` | `cbb update` and `install.ps1` on Windows | Set by `cbb update` for the copy of itself it runs the update from: the program it was started as, and its own process ID, which `install.ps1` leaves running and renames aside instead of stopping. Never set by hand. |
| `CBB_VERIFY` | `get.sh`, `get.ps1` | `skip` installs without checking the release's signature (`keys.json`, `stable.json`, `release.json`). Without it the installer stops when it cannot check the signature, for example without `openssl`, once the project's root keys are built into it. |
| `CBB_ATTESTATION` | `get.sh`, `get.ps1` | `require` refuses to install unless GitHub's build attestation of the archive checks out (it needs `gh`, signed in); `skip` does not check it. Unset, it is checked when `gh` is signed in. |
| `CBB_ERROR_DETAILS` | Linux, macOS and FreeBSD `install.sh` and `uninstall.sh`, `get.sh`, Windows `get.ps1`, `install.ps1` and `uninstall.ps1` | `1` shows every command the shell scripts run, so the output shows where and why one failed, and adds the full error record to the Windows scripts' messages (as `-Details` does). Without it a failed shell script names its exit status. |
| `CBB_LANG` | `get.sh`, every `install.sh` and `uninstall.sh`, Windows `get.ps1`, `install.ps1` and `uninstall.ps1` | The language of the installers' messages: `zh`, `en`, `es`, `ru`, `ar`, `sw`, `he` or `hi`. Unset, it is the system's (the locale, as gettext reads it; on a Mac without one, the first of the user's languages; on Windows, the display language), and English where the project has no translation (packaging/l10n.sh). |
| `CBB_OS_RELEASE` | the Linux `install.sh` | For tests: another `/etc/os-release`, whose `ID=steamos` makes it install as on SteamOS. |
| `CBB_PF_CONF` | the FreeBSD firewall script | Another `pf.conf` than `/etc/pf.conf`, for tests. |
| `CBB_IMAGE`, `CBB_PREVIEW` | `cbb`'s tests | For a look by eye at what the ZX Spectrum Next would show: `cargo test -p cbb-member preview -- --ignored` reads the PNG or JPEG `CBB_IMAGE` names and writes what `cbb next image` makes of it to the PNG `CBB_PREVIEW` names. |
| `CBB_RELEASE_DIR` | `get.sh`, `get.ps1` | For tests: takes the release's files from this directory instead of downloading them. |
| `CBB_RELEASE_ROOTS` | `get.sh`, `get.ps1` | For tests, with `CBB_RELEASE_DIR`: a file with the root keys to check the release against instead of the project's own. |

### For tests and development

These change nothing in a normal installation. How the tests use them is in
[CONTRIBUTING.md](../../CONTRIBUTING.md#development).

| Variable | Read by | Meaning |
|---|---|---|
| `CBB_TEST_X11` | Go tests of the desktop connector | Runs the tests against a real X server and xclip or xterm, for example in a container. |
| `CBB_TEST_WAYLAND` | Go tests of the desktop connector | Runs the tests against a real Wayland compositor, such as a headless sway. |
| `CBB_TEST_AVAHI` | Go tests of mDNS | Runs the tests that need avahi-daemon. |
| `CBB_TEST_MDNS_USERS` | Go tests of mDNS | Runs the test of mDNS for other users' sessions, which needs root. |
| `CBB_TEST_UINPUT` | Go tests of the uinput helper | `1` makes a missing `/dev/uinput` a failure instead of a skip. |
| `CBB_TEST_CLIPBOARD` | Go tests of the Windows clipboard | `1` allows the tests to overwrite the clipboard. |
| `CBB_UI_BROWSER` | Go tests of the tray app's window | The Chrome, Chromium or Edge to run the window in; without it the test looks in the usual places, and skips without a browser outside CI. |
| `CBB_UPDATE_SCREENSHOTS` | Go tests of the tray app's window | Set (to anything), `TestWindow/screenshots` writes its pictures to `apps/desktop/testdata/screenshots` instead of comparing with them, after a change to the window. |
| `CBB_SCREENSHOT_OUT` | Go tests of the tray app's window | The folder a failed screenshot comparison leaves the new picture and the difference in; by default `cbb-screenshots` in the system's temporary folder. |
| `CBB_TEST_ACTIONS` | `cbb`, in the Go end-to-end tests (`internal/service`) | A folder that stands for the system's quick actions: a preset with a file `refuse-NAME` there is refused with its text, any other is noted in the file `ran` and not run. Never set by hand. |
| `CBB_TEST_CLOCK` | the bench's time-scaled build (the feature `benchtime`) | What the build adds to the wall clock, so that certificates expire on the bench in minutes. Never in a release. |
| `CBB_TEST_CLOCK_FILE` | the bench's time-scaled build | A file that holds the value of `CBB_TEST_CLOCK` when that is not set, so the bench moves a member's clock with a restart of the service. |
| `CBB_TEST_SCALE` | the bench's time-scaled build | How many times faster long times run: 100000 by default, `1` for cases that move only the clock. |
| `CBB_TEST_XHTTP_CA` | the bench's time-scaled build | A PEM file of a CA that the clients of VLESS over XHTTP trust beside the public ones, for the bench's web server in front of a forwarder (W46). Never in a release. |
| `CBB_BENCH_SEED` | the bench's random walk (G40) | The walk's seed, which the run prints, to repeat a walk step by step. |
| `CBB_TPM_SIMULATOR` | the service, in tests | A TPM simulator's command port (`host:port`, the platform port the next one) used in place of the TPM. |
| `CBB_TPM_REQUIRED` | Go tests of the TPM | Makes a missing `swtpm` a failure instead of a skip, as in CI. |
| `CBB_SE_TEST` | Go tests on a Mac | `1` lets the tests of `internal/sekey` make keys in the Mac's Secure Enclave; without it no test key goes there. |
| `CBB_E2E_COVERDIR` | `tools/e2e/e2e.sh` | A directory where a `cbb` built with `-cover` writes its coverage, as `GOCOVERDIR` in every container (CI's coverage, [testing](../testing.md#coverage)). |
| `CBB_FAKE_HELPER` | `cbb`'s tests | Makes the test program play `cbb-helper` for the helper channel's tests. |
| `CBB_FAKE_HELPER_MODE` | `cbb`'s tests | Makes the test program play a `cbb-helper` that misbehaves as the value says (`crash`, `silent`, `garbage`, `hang`, `die-on-call`) or plays a TPM (`tpm`), for `member/tests/helper_faults.rs`. |
| `CBB_TEST_ALONE` | Go tests of cbb without its helper | The cbb binary they run alone, without `cbb-helper` beside it (`cargo build` at the top, `target/`). |
| `CBB_TEST_RUN_AS` | the Rust cbb's own tests | Set by `sys::tests::gives_up_root` for the copy of the test process it starts as root: that copy becomes `nobody` and checks that it cannot become root again. |
| `CBB_PREVIOUS` | Go tests of the service | The previous release's `cbb` for TestPreviousRelease (a device of version N in one group with N-1), as `tools/e2e/previous.sh` prints it. |
| `CBB_REPO` | `tools/e2e/previous.sh` | The repository on GitHub whose releases it reads, `HunterEwok/cbb` by default. |
| `CBB_WEEKLY_SCENARIO` | `tools/bench/weekly.sh` | Limits the weekly fleet run to these scenarios (`-scenario`); all of them when unset. |
| `CBB_TEST_RUST_RELAY` | Go tests of the relay | The Rust `cbb-relay` binary, which the tests of `internal/relay`, `internal/tunnel` and `internal/service` run as the blind relay; without it they take the `cbb-relay` beside the `cbb` of `CBB_TEST_ALONE` or `CBB_TEST_RUST_SERVICE`, and skip when there is none. |
| `CBB_RELAY_LIMITS` | `cbb-relay`, in tests | An open relay's limits as a JSON object of its fields (`groups`, `per_address`, `per_network`, `per_wide`, `per_provider`, `byte_rate`, `group_record_bytes`, `record_bytes`, `streams`); the Go tests set it. |
| `CBB_RELAY_STATS_MS` | `cbb-relay`, in tests | Logs the counts of groups and devices every so many milliseconds, which the Go tests read. |
| `CBB_TEST_IPV6` | `cbb`'s tests | `1` makes the tests of the tunnel and the relay over IPv6 fail where the system has no IPv6 loopback, instead of skipping them; the bench sets it. |
| `CBB_TEST_RUST_SERVICE` | the Go end-to-end tests (`internal/service`) | The `cbb` binary the tests run as a Linux member with the default configuration, finding their peers by mDNS. |
| `CBB_ESP32_ON_LINUX` | `TestEmbassyJoiner` | The `esp32-on-linux` binary of `embassy/`, run over a TAP interface. |
| `CBB_PHONE_ON_LINUX` | `TestFFIJoiner` | The example `phone-on-linux` of `ffi/` (feature `member`): the Aurora app's joining and syncing with a software key. |
| `CBB_TUNNEL_ON_LINUX` | `TestRustPhoneTunnel` | The example `tunnel-on-linux` of `ffi/` (feature `tunnel`): the phones' Rust tunnel to a Go hub. |
| `CBB_REAL_FORWARDER` | `TestRustPhoneThroughRealForwarder` | A forwarder on the internet, host:port (`cbb.tools:8764` for the project's): the phones' Rust hub registers with it and a Rust client reaches the hub over VLESS with XHTTP, a check from a network that blocks WireGuard; without it the test is skipped. |
| `CBB_REAL_FORWARDER_PIN` | `TestRustPhoneThroughRealForwarder` | That forwarder's pin, base64, when it is not the project's. |
| `CBB_INTEROP_OUT` | the Swift and Kotlin kits' tests, Go's interop tests | A directory where the kits write fresh interop vectors and Go reads them; without it Go reads `testdata/interop`. |
| `CBB_VERDICTS` | the verdict tests of all four implementations (`TestVerdicts`, `command::verdicts`, `VerdictTest`, `VerdictTests`) | A corpus of `tools/difffuzz gen` to write the verdicts on ([differential fuzzing](../differential.md)); without it each runs on a small corpus of its own. |
| `CBB_VERDICTS_OUT` | the same tests | The file the verdicts go to, one line per case. |
| `CBB_TEST_AHEAD_FILE` | `cbb`, in the Go end-to-end tests (`internal/service`) | A file holding the milliseconds the service's wall clock is moved by, read each time; the tests write it to move the clock while the service runs. Never set by hand. |
| `CBB_TEST_RENEW_EVERY` | `cbb`, in the Go end-to-end tests (`internal/service`) | How often, in milliseconds, the root and the admins look for certificates due for renewal, in place of twice a day. Never set by hand. |
| `CBB_TEST_ATTEST_ROOTS` | `cbb-helper`, in the service's tests | A PEM file of the public keys (or certificates) of the roots an Android key attestation must chain to, in place of Google's; read at each check. Never set by hand. |
| `CBB_TEST_TPM_ROOTS` | `cbb-helper`, in the service's tests | A PEM file of the TPM makers' roots an EK certificate must chain to, in place of the built-in ones. Never set by hand. |
| `CBB_TEST_STATUS_URL` | `cbb-helper`, in the service's tests | Where the attestation status list and its keys are fetched from, in place of `https://cbb.tools/attest/`. Never set by hand. |
| `CBB_TEST_STATUS_EVERY` | the Rust service, in the service's tests | How often, in milliseconds, the root fetches the attestation status list, in place of once a day. Never set by hand. |
| `CBB_TEST_DEAD_UDP` | the Rust service, in the service's tests | An address (host:port) that never answers, which replaces the hubs' UDP addresses, as on a network that blocks WireGuard, so that the tunnel goes over VLESS. Never set by hand. |
| `CBB_UPDATE_VECTORS` | the core's keyboard tests | `1` writes the keyboard layouts' vectors again (`cargo test -p cbb-core keyboard`). |
| `CBB_ARCH` | the build of `cbb` in Rust (`member/packaging/build.sh`) | The architecture as the release's archives name it (`amd64`, `arm64`, `armv7`, `armv6`, `mips`, `mipsle`), which `cbb update` downloads for; set by `build.sh`, and without it the one Rust names. |
| `CBB_SOURCE` | the Rust core's build | The commit the core is built from, which its `version` call names ([the core's entry point](../core-api.md)); empty when unset. |
| `CBB_WRITE_INTEROP` | the Swift kit's certificate tests | Writes the certificates that Go's `TestSwiftCertificates` checks. |
| `CBB_SWIFT_INTEROP` | Go's interop tests | The `cbb-interop` tool, which plays the phone in Go tests over plain TCP. |
| `CBB_SWIFT_INTEROP_TLS` | Go's interop tests, on macOS | The same tool for the tests over real TLS, with a key in the keychain. |
| `CBB_TEAM` | `apps/ios/device.sh` | The Apple team that signs the iPhone app for your own phone, its 10-character ID; without it the script takes the Personal Team of the Apple ID signed in to Xcode. |
| `CBB_DEVICE` | `apps/ios/device.sh` | The iPhone to install on, its identifier, when more than one is connected. |
| `CBB_BUNDLE_ID` | `apps/ios/device.sh` | The app's bundle identifier for that build, `dev.<team>.cbb` by default, so that it never takes the release one. |
| `CBB_NFC` | `apps/ios/device.sh` | `1` signs that build with NFC (`Nfc.entitlements`), for the recovery key on a YubiKey, where the team's profile may carry it. |
| `CBB_DERIVED` | `apps/ios/device.sh` | Where the build goes, `/tmp/cbb-device.noindex` by default: a folder the Mac empties at a restart, and Spotlight skips it, so the built apps never show up in a search. |
| `CBB_LOCK_CHILD`, `CBB_MDNS_CHILD` | Go tests | Set by a test for the child process it starts; never set them yourself. |
| `CBB_MAP` | the ZX Next's `drvtest` example `run` | The map of the `CBB` it runs (`apps/zxnext/build/cbb.map`), for the overlays' pages ([apps/zxnext/README.md](../../apps/zxnext/README.md#testing-on-a-played-next)). |
| `CBB_PI` | the ZX Next's `drvtest` install tests | The Pi's cbb that `build/CBB` was built with, when it is not `build/PIBRIDGE`. |
| `CBB_UNLINKED` | the ZX Next's played card | A directory where a file `.cbb` deletes from the card is copied first, to look at it. |
| `CBB_RELEASE_SIGN_DIR` | `tools/release-sign` | Another directory for the release signing tool's files than `tools/release-sign`. |
