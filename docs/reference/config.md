<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Settings and environment variables

Every setting Clipboard Bridge reads from a file or from the environment. The commands and
their flags are in the [command reference](cli.md); where each system keeps its keys,
state and logs is in [devices, ports and files](devices.md#files-and-logs).

Most settings are made by a command or an installer flag, which writes the settings file
for you. Edit the files by hand only where this page says so: `CBB_INTERFACES` has no
option, so it is set by hand, and the installers and `cbb update` keep that line.

## Settings files

| File | Systems | Who writes it | What it holds |
|---|---|---|---|
| `/etc/clipboardbridge/clipboardbridge.env` | Linux, macOS, the lite member | the installers (`--port`, `--home-cgnat`); `CBB_INTERFACES` by hand | `CBB_PORT`, `CBB_HOME_CGNAT`, `CBB_INTERFACES`, one `NAME=value` per line; systemd passes them to the service. A full member's service and `cbb` also read the file themselves; the lite member reads only its environment |
| `/usr/local/etc/clipboardbridge/clipboardbridge.env` | FreeBSD, OPNsense | the installer | the same as on Linux; rc.d passes them to the service |
| `HKLM\SYSTEM\CurrentControlSet\Services\clipboardbridge`, the value `Environment` (a multi-string) | Windows | `install.ps1` (`-Port`, `-HomeCgnat`); `CBB_INTERFACES` by hand, which `install.ps1` keeps | the same values as the file on Linux |
| `/etc/config/clipboardbridge` | OpenWrt | the package, then you (UCI) | `port`, the firewall `zone` list the service works in (it becomes `CBB_INTERFACES`), `wait_ntp` (start once NTP has set the clock), `memlimit` (`GOMEMLIMIT`); apply a change with `/etc/init.d/clipboardbridge reload` |
| `/etc/clipboardbridge/forward.env` | a server running `cbb forward` | you | `CBB_FORWARD_FLAGS`, see [running your own servers](../admin/self-hosting.md) |
| `/etc/clipboardbridge/relay.env` | a server running `cbb relay` | you | `CBB_RELAY_FLAGS`, see [running your own servers](../admin/self-hosting.md) |

The group's own settings (sync modes, remote paste, quick actions, the hubs, sync away from
home) are not in these files: they live in the state directory, are changed by `cbb`
commands or the apps, and some are signed by an admin.

## Environment variables

A variable set in the environment wins over the same name in the settings file.

| Variable | Read by | Meaning |
|---|---|---|
| `CBB_DEBUG` | `cbb`, the lite member, the tray app | `1` shows the underlying error under each message; `0` hides it in a development build, which shows it by default. The service's log always has the details. In the service's environment, also WireGuard's own messages for sync away from home and the member connections a peer closed or reset. The Mac app and the tray app pass it to `cbb` when their own error details switch is on. |
| `CBB_PORT` | the service, the lite member's `cbb run`, the installers | The member port, 8764 by default. Change it by running the installer again with `--port N` (`-Port N` on Windows), which keeps it in the settings file. |
| `CBB_INTERFACES` | the service, the lite member | Network interfaces by name, separated by commas or spaces (`br-lan,br-iot`): mDNS, the member port and a listening join work only there, so that a router never answers on its internet side, even with a private address there or a firewall opened by mistake. Unset or empty, every interface. On OpenWrt the init script sets it from the zones in `/etc/config/clipboardbridge`. |
| `CBB_HOME_CGNAT` | the service, the installers | `1` counts 100.64.0.0/10, the carrier-grade NAT range, as the home network too, for a home network that uses it: the service accepts and reaches it, publishes its addresses there, and the installers open it in the firewall and in the system's outbound limit (the systemd drop-in `cgnat.conf` on Linux, the Windows rule). Unset or `0`, it is outside the home network. Set it with `--home-cgnat on` (`off` goes back) or `-HomeCgnat on` on Windows. |
| `CBB_TPM` | the service on Linux | `off` keeps new member and admin keys out of the TPM, in files; a key already in the TPM stays there. Unset, a computer with a TPM 2.0 makes its keys in it ([keys and attestation](../guide/keys.md)). |
| `CBB_CONTAINER` | the service | Set by the Docker image: the service runs in a container, whose keys are in a file in its volume, so it makes no group (`cbb new`, `cbb upgrade`, `cbb takeover`) and offers no admin key, and the root cannot make it an admin. |
| `CBB_KEYS_IN_FILE` | the service, in a container | `yes` allows a container to hold the group's keys anyway: to make the group, or to be made an admin and so the hub. Anyone who copies its volume then has those keys. |
| `CBB_ROOTLESS` | `cbb` on Linux, the lite member too | `1`, set by the user units of a rootless install (`install.sh --rootless`), makes `cbb` use the user's own paths: the socket in `$XDG_RUNTIME_DIR/clipboardbridge`, the state, settings and update folder under the user's home; the service then refuses to be the root, an admin or a hub. Unset, `cbb` in `~/.local/bin` does the same. |
| `CBB_SOCKET` | `cbb`, the lite member, the Mac app | Another control socket, for tests or a second instance. |
| `CBB_ADMIN_SOCKET` | `cbb` | Another admin socket, the one for the commands that change the group; by default the admin socket next to the control socket. |
| `CBB_STATE` | the lite member | Another state directory. |
| `CBB_FORWARD_FLAGS` | `cbb-forward.service` | The flags of `cbb forward`, such as `-vless-site www.example.com`. |
| `CBB_RELAY_FLAGS` | `cbb-relay.service` | The flags of `cbb relay`: `-group TAG` or `-open`. |

### The installers

| Variable | Read by | Meaning |
|---|---|---|
| `CBB_FIREWALL` | `get.sh`, Linux, macOS and FreeBSD `install.sh`, Windows `install.ps1` (through `get.ps1` too) | `express` adds the firewall rules without asking (`--express`), `no` adds none and prints the commands (`--no-firewall`); unset, the installer asks. |
| `CBB_VERSION` | `get.sh`, `get.ps1` | A release such as `v0.5.0` instead of the latest. In a build of the lite member, the version the release passes to `cargo build`. |
| `CBB_AUTO_UPDATE` | the installers | `on` or `off` answers whether the computer updates itself once a day (`--auto-update`, `-AutoUpdate`); unset, they ask once. `cbb update -auto` changes it later. |
| `CBB_INSTALL_METHOD` | the installers | How the program came, which they record for `cbb update` (`cbb update -installed-by`): `get` by default, `brew` for a Homebrew copy (found from its path), `winget` from winget's folder, `package` for the OpenWrt package. |
| `CBB_UPDATING` | the installers | Set by `cbb update` while it runs the new release's installer, so they ask no question about automatic updates. |
| `CBB_UPDATE_FROM`, `CBB_UPDATE_PARENT` | `cbb update` and `install.ps1` on Windows | Set by `cbb update` for the copy of itself it runs the update from: the program it was started as, and its own process ID, which `install.ps1` leaves running and renames aside instead of stopping. Never set by hand. |
| `CBB_VERIFY` | `get.sh`, `get.ps1` | `skip` installs without checking the release's signature (`keys.json`, `stable.json`, `release.json`). Without it the installer stops when it cannot check the signature, for example without `openssl`, once the project's root keys are built into it. |
| `CBB_ATTESTATION` | `get.sh`, `get.ps1` | `require` refuses to install unless GitHub's build attestation of the archive checks out (it needs `gh`, signed in); `skip` does not check it. Unset, it is checked when `gh` is signed in. |
| `CBB_ERROR_DETAILS` | Linux, macOS and FreeBSD `install.sh` and `uninstall.sh`, `get.sh`, Windows `get.ps1`, `install.ps1` and `uninstall.ps1` | `1` shows every command the shell scripts run, so the output shows where and why one failed, and adds the full error record to the Windows scripts' messages (as `-Details` does). Without it a failed shell script names its exit status. |
| `CBB_OS_RELEASE` | the Linux `install.sh` | For tests: another `/etc/os-release`, whose `ID=steamos` makes it install as on SteamOS. |
| `CBB_PF_CONF` | the FreeBSD firewall script | Another `pf.conf` than `/etc/pf.conf`, for tests. |
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
| `CBB_TEST_CLOCK` | the bench's time-scaled build (`-tags benchtime`) | What the build adds to the wall clock, so that certificates expire on the bench in minutes. Never in a release. |
| `CBB_TEST_CLOCK_FILE` | the bench's time-scaled build | A file that holds the value of `CBB_TEST_CLOCK` when that is not set, so the bench moves a member's clock with a restart of the service. |
| `CBB_TEST_SCALE` | the bench's time-scaled build | How many times faster long times run: 100000 by default, `1` for cases that move only the clock. |
| `CBB_BENCH_SEED` | the bench's random walk (G40) | The walk's seed, which the run prints, to repeat a walk step by step. |
| `CBB_TPM_SIMULATOR` | the service, in tests | A TPM simulator's command port (`host:port`, the platform port the next one) used in place of the TPM. |
| `CBB_TPM_REQUIRED` | Go tests of the TPM | Makes a missing `swtpm` a failure instead of a skip, as in CI. |
| `CBB_E2E_COVERDIR` | `tools/e2e/e2e.sh` | A directory where a `cbb` built with `-cover` writes its coverage, as `GOCOVERDIR` in every container (CI's coverage, [testing](../testing.md#coverage)). |
| `CBB_LITE` | Go tests with the lite member | The lite member's binary (`cargo build` in `lite/`). |
| `CBB_ESP32_ON_LINUX` | `TestEmbassyJoiner` | The `esp32-on-linux` binary of `lite/embassy`, run over a TAP interface. |
| `CBB_INTEROP_OUT` | the Swift and Kotlin kits' tests, Go's interop tests | A directory where the kits write fresh interop vectors and Go reads them; without it Go reads `testdata/interop`. |
| `CBB_VERDICTS` | the verdict tests of all four implementations (`TestVerdicts`, `command::verdicts`, `VerdictTest`, `VerdictTests`) | A corpus of `tools/difffuzz gen` to write the verdicts on ([differential fuzzing](../differential.md)); without it each runs on a small corpus of its own. |
| `CBB_VERDICTS_OUT` | the same tests | The file the verdicts go to, one line per case. |
| `CBB_UPDATE_VECTORS` | the lite core's keyboard tests | `1` writes the keyboard layouts' vectors again (`cargo test -p clipboardbridge-core keyboard`). |
| `CBB_SOURCE` | the Rust core's build | The commit the core is built from, which its `version` call names ([the core's entry point](../core-api.md)); empty when unset. |
| `CBB_WRITE_INTEROP` | the Swift kit's certificate tests | Writes the certificates that Go's `TestSwiftCertificates` checks. |
| `CBB_SWIFT_INTEROP` | Go's interop tests | The `clipboardbridge-interop` tool, which plays the phone in Go tests over plain TCP. |
| `CBB_SWIFT_INTEROP_TLS` | Go's interop tests, on macOS | The same tool for the tests over real TLS, with a key in the keychain. |
| `CBB_TEAM` | `apps/ios/device.sh` | The Apple team that signs the iPhone app for your own phone, its 10-character ID; without it the script takes the Personal Team of the Apple ID signed in to Xcode. |
| `CBB_DEVICE` | `apps/ios/device.sh` | The iPhone to install on, its identifier, when more than one is connected. |
| `CBB_BUNDLE_ID` | `apps/ios/device.sh` | The app's bundle identifier for that build, `dev.<team>.clipboardbridge` by default, so that it never takes the release one. |
| `CBB_DERIVED` | `apps/ios/device.sh` | Where the build goes, `/tmp/cbb-device.noindex` by default: a folder the Mac empties at a restart, and Spotlight skips it, so the built apps never show up in a search. |
| `CBB_LOCK_CHILD`, `CBB_MDNS_CHILD` | Go tests | Set by a test for the child process it starts; never set them yourself. |
| `CBB_RELEASE_SIGN_DIR` | `tools/release-sign` | Another directory for the release signing tool's files than `tools/release-sign`. |
