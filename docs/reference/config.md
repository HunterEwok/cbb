<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Settings and environment variables

For users, administrators, and developers looking up every setting that Connect Beyond Borders
reads from a settings file or environment variable. Commands and flags are in
[Command reference](cli.md); paths for keys, state, and logs are in
[Devices, ports and files](devices.md#files-and-logs).

Installers and `cbb` commands write most settings files automatically. Edit them by hand only when
no command or installer option exists (such as `CBB_INTERFACES`, which installers and `cbb update`
preserve).

Test hooks (`CBB_TEST_*`, `CBB_TPM_SIMULATOR`, `CBB_HELPER`, and in `cbb` itself
`CBB_RELEASE_DIR` and `CBB_RELEASE_ROOTS`) are read only by test builds (`cbb` with feature
`testhooks` or `benchtime`, `cbb-helper` with build tag `testhooks`, and Go test binaries).
Release builds ignore them ([Maintaining](../maintainers/maintaining.md), "Test builds").

## Settings files

| File | Systems | Managed by | Contents |
|---|---|---|---|
| `/etc/cbb/cbb.env` | Linux (system install), macOS | Installers (`--port`, `--home-cgnat`); `CBB_INTERFACES` by hand | `KEY=value` lines (`CBB_PORT`, `CBB_HOME_CGNAT`, `CBB_INTERFACES`). Passed to systemd on Linux and read directly by `cbb` and the service on both systems. |
| `~/.config/cbb/cbb.env` | Linux (rootless install) | `install.sh --rootless` (`--port`, `--home-cgnat`); `CBB_INTERFACES` by hand | Same `KEY=value` format as `/etc/cbb/cbb.env`, for a rootless user service. |
| `/usr/local/etc/cbb/cbb.env` | FreeBSD, OPNsense | Installer (`--port`, `--home-cgnat`); `CBB_INTERFACES` by hand | Same `KEY=value` format as `/etc/cbb/cbb.env`; passed by rc.d and read directly by `cbb`. |
| `HKLM\SYSTEM\CurrentControlSet\Services\cbb` (`Environment` multi-string value) | Windows | `install.ps1` (`-Port`, `-HomeCgnat`); `CBB_INTERFACES` by hand (preserved by `install.ps1`) | Same `NAME=value` entries as `cbb.env`. |
| `/etc/config/cbb` | OpenWrt | Package/installer, then you (UCI) | `port`, firewall `zone` list (translated into `CBB_INTERFACES`), and `wait_ntp` (delay start until NTP sets the clock). Apply changes with `/etc/init.d/cbb reload`. |
| `/etc/cbb/forward.env` | Forwarder server (`cbb-forward.service`) | Operator | `CBB_FORWARD_FLAGS`; see [Running your own servers](../admin/self-hosting.md). |
| `/etc/cbb/relay.env` | Blind relay server (`cbb-relay.service`) | Operator | `CBB_RELAY_FLAGS`; see [Running your own servers](../admin/self-hosting.md). |
| `/etc/cbb/push.env` | Push service (`cbb-push.service`) | Operator | `CBB_PUSH_FLAGS`; see `packaging/linux/cbb-push.service`. |

Group settings (sync mode, remote paste, quick actions, hubs, relays, copy lifetimes, key level,
and sync away from home) live in the state directory and are modified through `cbb` commands or
the apps.

## Environment variables

A variable set in the process environment takes precedence over the same key in a settings file.

### Runtime and service

| Variable | Read by | Meaning |
|---|---|---|
| `CBB_ADMIN_SOCKET` | `cbb` | Override the admin socket path (defaults to `admin.sock` beside the control socket, or `admin\admin.sock` on Windows). |
| `CBB_CONTAINER` | Service | Set by the Docker image (`docker`): marks the service as running in a container with file-backed keys, preventing `cbb new` and suppressing admin key offers unless `CBB_KEYS_IN_FILE=yes`. |
| `CBB_DEBUG` | `cbb`, service, tray app, `cbb-forward`, `cbb-relay`, `cbb-push` | In `cbb`, `1`/`true`/`yes` shows underlying error details and `0`/`false`/`no` hides them (overrides build default; overridden by `-debug`). In the service environment, `1` also logs WireGuard tunnel details and peer connection closes/resets. In `cbb-forward`, `cbb-relay`, and `cbb-push`, `1` logs periodic counts and verbose diagnostics. The Mac and tray apps pass `CBB_DEBUG` to `cbb` according to their **Show error details** setting. |
| `CBB_HOME_CGNAT` | Service, installers | `1` treats `100.64.0.0/10` (carrier-grade NAT range) as part of the home network in service checks, firewall rules, and outbound network limits (`cgnat.conf` on Linux, Windows Firewall rule). Unset or `0` treats it as external. Managed with `--home-cgnat on\|off` (`-HomeCgnat on\|off` on Windows). |
| `CBB_INTERFACES` | Service | Comma- or space-separated network interface names (for example `br-lan,br-iot`) restricting mDNS and the member port. Unset or empty uses all interfaces. Set automatically from UCI zones on OpenWrt. |
| `CBB_KEYS_IN_FILE` | Service (in a container) | `yes` allows a container (`CBB_CONTAINER` set) to create a group or offer an admin key stored in files inside its volume. |
| `CBB_PORT` | Service, installers | Member TCP port (`8764` by default, range `1024`–`65535`). Change with `--port N` (`-Port N` on Windows) so installers update the settings file and firewall rules. |
| `CBB_ROOTLESS` | `cbb` on Linux | `1` (set by rootless systemd user units) switches `cbb` to user-owned paths (`$XDG_RUNTIME_DIR/cbb`, `~/.config/cbb`, `~/.local/state/cbb`) and prevents the device from acting as main device, admin, or hub. Unset, running `cbb` from `~/.local/bin` enables rootless mode automatically. |
| `CBB_SOCKET` | `cbb`, Mac app | Override the control socket path. |
| `CBB_STATE` | `cbb` | Override the state directory path. |
| `CBB_TPM` | Service on Linux, Windows, macOS | `off` creates new member and admin keys in files instead of a TPM 2.0 or Mac Secure Enclave (existing hardware keys stay in hardware). Unset uses hardware keys when available ([Keys and attestation](../guide/keys.md)). |

### Servers and infrastructure

| Variable | Read by | Meaning |
|---|---|---|
| `CBB_FORWARD_FLAGS` | `cbb-forward.service` | Command-line flags passed to `cbb-forward` (for example `-vless-xhttp vpn.example.org`). |
| `CBB_PUSH_FLAGS` | `cbb-push.service` | Command-line flags passed to `cbb-push` (`-apns-team`, `-apns-key-id`, `-apns-sandbox-key-id`, and `-new-state` on first start only; platform keys come from systemd credentials). |
| `CBB_RELAY_FLAGS` | `cbb-relay.service` | Command-line flags passed to `cbb-relay` (`-group GROUP` from `cbb status -relay`, or `-open`). |
| `CBB_TRAFFIC_IFACE` | `site/deploy/cbb-traffic.sh` | Network interface measured for server traffic accounting ([The servers' budget](../relay-budget.md#money-and-traffic)); defaults to the default-route interface. |
| `CBB_TRAFFIC_OUT` | `site/deploy/cbb-traffic.sh` | Output file path for 24-hour traffic totals (`/srv/cbb.tools/status/traffic.json` by default). |

### Installers and updates

| Variable | Read by | Meaning |
|---|---|---|
| `CBB_ATTESTATION` | `get.sh`, `get.ps1` | `require` fails installation unless GitHub build provenance attestation verifies (requires authenticated `gh`); `skip` skips attestation verification. Unset verifies when `gh` is signed in. |
| `CBB_AUTO_UPDATE` | Installers | `on` or `off` sets daily automatic updates (`--auto-update`, `-AutoUpdate`); unset prompts once. Change later with `cbb update -auto`. |
| `CBB_ERROR_DETAILS` | `get.sh`, `get.ps1`, all `install.*` and `uninstall.*` scripts | `1` enables shell command tracing (`set -x`) in POSIX scripts and full PowerShell error records (same as `-Details`) in Windows scripts. |
| `CBB_FIREWALL` | `get.sh`, Linux/macOS/FreeBSD `install.sh`, Windows `get.ps1`/`install.ps1` | `express` adds firewall rules without prompting (`--express`/`-Express`); `no` adds no rules and prints commands (`--no-firewall`/`-NoFirewall`); unset prompts. |
| `CBB_INSTALL_METHOD` | Installers | Installation source recorded via `cbb update -installed-by`: `get` (default), `brew`, `winget`, `docker`, or `package`. |
| `CBB_LANG` | `get.sh`, `get.ps1`, all `install.*` and `uninstall.*` scripts | Override installer message language: `ar`, `en`, `es`, `he`, `hi`, `ru`, `sw`, or `zh`. Unset follows the system locale (falls back to English). |
| `CBB_PAIR` | `get.sh`, Linux and OpenWrt `install.sh` | `no` skips automatic pairing at the end of installation on devices without `cbb-helper` (same as `--no-pair`). |
| `CBB_UPDATE_FROM`, `CBB_UPDATE_PARENT` | `cbb update`, Windows `install.ps1` | Internal variables set by `cbb update` on Windows when running from a temporary copy so `install.ps1` renames instead of terminating the running updater process. Do not set by hand. |
| `CBB_UPDATING` | Installers | Internal variable set by `cbb update` while invoking the new release's installer so interactive update prompts are skipped. |
| `CBB_VERIFY` | `get.sh`, `get.ps1` | `skip` bypasses verifying signed release metadata (`keys.json`, `stable.json`, `release.json`). Unset stops installation if verification cannot run. |
| `CBB_VERSION` | `get.sh`, `get.ps1`, Rust build | Release tag to install (such as `v0.6.0`) instead of the latest release. During builds, passes the release version string to `cargo build`. |

### Tests, builds, and development

These variables do not affect standard installations. See
[Contributing](../../CONTRIBUTING.md#development) for how development and test workflows use them.

| Variable | Read by | Meaning |
|---|---|---|
| `CBB_ARCH` | Rust `cbb` build (`packaging/build.sh`) | Release archive architecture name (`amd64`, `arm64`, `armv7`, `armv6`, `mips`, `mipsle`) used by `cbb update`. |
| `CBB_BENCH_SEED` | Bench random walk (G40) | Seed for replaying a bench random walk. |
| `CBB_BUNDLE_ID` | `apps/ios/device.sh` | Bundle identifier for local iOS device builds (`dev.<team>.cbb` by default). |
| `CBB_DANGEROUS_SHEET` | Tray window tests, Android unit tests | Output directory for multilingual confirmation-screen sheets (`TestWindow/dangerous screens`, `DangerousScreensTest`); skipped when unset. |
| `CBB_DERIVED` | `apps/ios/device.sh` | DerivedData directory for local iOS device builds (`/tmp/cbb-device.noindex` by default). |
| `CBB_DEVICE` | `apps/ios/device.sh` | Target iPhone identifier when multiple devices are connected. |
| `CBB_E2E_COVERDIR` | `tools/e2e/e2e.sh` | Directory for Go `-cover` coverage output (`GOCOVERDIR`) in container tests ([Testing](../testing.md#coverage)). |
| `CBB_FAKE_HELPER` | `cbb` unit tests | Causes the test binary to act as a fake `cbb-helper` for IPC tests. |
| `CBB_FAKE_HELPER_MODE` | `cbb` fault tests (`member/tests/helper_faults.rs`) | Selects fake helper behavior (`crash`, `silent`, `garbage`, `hang`, `die-on-call`, or `tpm`). |
| `CBB_FFI_LIB` | Aurora and HarmonyOS host tests (`apps/silica/tests/qt/run.sh`, `apps/harmony/nodetest/run.sh`) | Path to a prebuilt host `libcbb_ffi.a` instead of rebuilding with Cargo. |
| `CBB_FULL_SIZE` | `cbb-core` record tests | `1` runs record tests at full production size limits. |
| `CBB_HELPER` | `cbb` (`testhooks` build only) | Path to `cbb-helper` binary instead of the binary beside `cbb` (empty string disables helper). Subject to the same ownership check as the default helper. Ignored in release builds. |
| `CBB_IMAGE`, `CBB_PREVIEW` | `cbb` image preview test | Input PNG/JPEG path (`CBB_IMAGE`) and output preview PNG path (`CBB_PREVIEW`) for inspecting `cbb next image` conversion (`cargo test -p cbb-member preview -- --ignored`). |
| `CBB_JS_COVERAGE` | Tray window tests | Output LCOV path for frontend JavaScript coverage (`tools/coverage` row `js-tray`). |
| `CBB_LOCK_CHILD`, `CBB_MDNS_CHILD` | Go tests | Internal markers set for child test processes. Do not set by hand. |
| `CBB_MAP` | ZX Spectrum Next `drvtest` `run` example | Path to `cbb.map` (`apps/zxnext/build/cbb.map`) for overlay page lookup ([apps/zxnext/README.md](../../apps/zxnext/README.md#testing-on-a-played-next)). |
| `CBB_MDNS_TRACE` | `cbb service` | File path for appending UTC-timestamped mDNS browsing events and debug logs. |
| `CBB_NFC` | `apps/ios/device.sh` | `1` signs local iOS builds with `Nfc.entitlements` for YubiKey NFC support. |
| `CBB_OS_RELEASE` | Linux `install.sh` | Alternate `/etc/os-release` path for testing (for example simulating `ID=steamos`). |
| `CBB_PF_CONF` | FreeBSD firewall script | Alternate `pf.conf` path instead of `/etc/pf.conf` for testing. |
| `CBB_PHONE_ON_LINUX` | `TestFFIJoiner` | Path to the `ffi/` `phone-on-linux` example binary (built with `member` and `testhooks`). |
| `CBB_PI` | ZX Spectrum Next `drvtest` install tests | Alternate Pi binary path in place of `build/PIBRIDGE`. |
| `CBB_PREVIOUS` | Go service compatibility tests (`TestPreviousRelease`) | Path to the previous release's `cbb` binary (as printed by `tools/e2e/previous.sh`). |
| `CBB_PUSH_LIVE_ADDR` | Manual `cbb-push` live test (`live_push_to_a_phone`) | Address of a running `cbb-push` instance. |
| `CBB_PUSH_LIVE_KIND` | Manual `cbb-push` live test | Sealed notification kind: `event` (default) or `waits`. |
| `CBB_PUSH_LIVE_PIN` | Manual `cbb-push` live test | Base64 key pin of the target `cbb-push` instance. |
| `CBB_PUSH_LIVE_REG` | Manual `cbb-push` live test | Base64 phone push registration token (from app launch argument `-PushTestTools YES`). |
| `CBB_PUSH_LIVE_ROOTS` | Manual `cbb-push` live test | CA certificate bundle for checking Apple's sandbox APNs server. |
| `CBB_REAL_FORWARDER` | `TestAwayThroughRealForwarder` | `host:port` of a live forwarder (such as `cbb.tools:8764`) for end-to-end VLESS/XHTTP tests; test skips when unset. |
| `CBB_REAL_FORWARDER_PIN` | `TestAwayThroughRealForwarder` | Base64 key pin of `CBB_REAL_FORWARDER` when not using the project's forwarder. |
| `CBB_RELAY_LIMITS` | `cbb-relay` (tests) | JSON object overriding open-relay limits (`groups`, `per_address`, `per_network`, `per_wide`, `per_provider`, `byte_rate`, `streams`). |
| `CBB_RELAY_STATS_MS` | `cbb-relay` (tests) | Interval in milliseconds for logging group and device counts. |
| `CBB_RELEASE_BUILD` | Release workflow Rust build | `1` causes compilation to fail if any test-only feature (`benchtime`, `testhooks`, `fuzzing`) is enabled. |
| `CBB_RELEASE_DIR` | `get.sh`, `get.ps1`, `cbb update` (`testhooks` build only) | Local directory supplying release files instead of downloading over the network. Ignored by release builds of `cbb`. |
| `CBB_RELEASE_PQ_DIR` | `tools/release-sign` | Directory holding age-encrypted post-quantum halves of hardware release keys (`~/.config/cbb-release/pq` by default). |
| `CBB_RELEASE_ROOTS` | `get.sh`, `get.ps1`, `cbb` (`testhooks` build only) | Alternate release root keys file used with `CBB_RELEASE_DIR`. Ignored by release builds of `cbb`. |
| `CBB_RELEASE_SIGN_DIR` | `tools/release-sign` | Alternate directory for `tools/release-sign` files. |
| `CBB_RELEASE_TAG` | `internal/release` tests | Set by release workflows so `TestPinnedRootsComplete` requires both signature halves on every pinned root key. |
| `CBB_REPO` | `tools/e2e/previous.sh` | GitHub repository (`owner/repo`) queried for previous releases (`HunterEwok/cbb` by default). |
| `CBB_SCREENSHOT_OUT` | Tray window tests | Directory for saving failed screenshot diffs (`cbb-screenshots` in the system temp dir by default). |
| `CBB_SE_TEST` | macOS Go tests (`internal/sekey`) | `1` permits tests to create keys in the Mac Secure Enclave. |
| `CBB_SOURCE` | Rust core build | Commit identifier reported by the core's `version` call ([The core's entry point](../core-api.md)). |
| `CBB_TEAM` | `apps/ios/device.sh` | 10-character Apple Team ID for signing local iOS builds (defaults to Xcode's signed-in Personal Team). |
| `CBB_TEST_ACTIONS` | `cbb` (`testhooks` build only) | Directory simulating quick actions (`refuse-NAME` refuses an action; other presets log to `ran`). Ignored in release builds. |
| `CBB_TEST_AHEAD_FILE` | `cbb` (`testhooks` build only) | File holding wall-clock offset in milliseconds, re-read dynamically during tests. Ignored in release builds. |
| `CBB_TEST_ALONE` | Go end-to-end tests | Path to the `cbb` binary tested without `cbb-helper`. |
| `CBB_TEST_APPLETV_NAME` | `cbb-helper` (`testhooks` build only) | Static Apple TV mDNS name used in tests instead of live browsing. Ignored in release builds. |
| `CBB_TEST_ATTEST_ROOTS` | `cbb` and `cbb-helper` (`testhooks` builds only) | PEM file replacing Google's Android key attestation root certificates. Ignored in release builds. |
| `CBB_TEST_AVAHI` | Go mDNS tests | Enables tests that require `avahi-daemon`. |
| `CBB_TEST_BLUEZ` | `cbb-helper` on Linux (`testhooks` build only) | D-Bus address of a mock BlueZ daemon (`bluetest`) instead of the system bus. Ignored in release builds. |
| `CBB_TEST_CLIPBOARD` | Windows Go clipboard tests | `1` permits tests to overwrite the live Windows clipboard. |
| `CBB_TEST_CLOCK` | `benchtime` build | Wall-clock offset (duration or RFC 3339 timestamp) added to the system clock. Ignored in release builds. |
| `CBB_TEST_CLOCK_FILE` | `benchtime` build | File supplying `CBB_TEST_CLOCK` when `CBB_TEST_CLOCK` is unset. Ignored in release builds. |
| `CBB_TEST_DEAD_UDP` | `cbb` (`testhooks` build only) | Unresponsive `host:port` replacing hubs' UDP addresses to force VLESS fallback. Ignored in release builds. |
| `CBB_TEST_ELSEWHERE` | `cbb` (`testhooks` build only) | Directory where a file named after a device ID disables mDNS advertising and local dialing for that device. Ignored in release builds. |
| `CBB_TEST_FALLBACK` | `cbb` (`testhooks` build only) | Milliseconds to wait before reverse-dialing a lower-ID peer (default 30 s) and forces dialing higher-ID peers on port 1 to test firewall fallback. Ignored in release builds. |
| `CBB_TEST_HUB_KEY_AHEAD` | `cbb` (`testhooks` build only) | Seconds before a new credential period that a hub advertises its next key (default 3 days). Ignored in release builds. |
| `CBB_TEST_IPV6` | `cbb` tests | `1` fails IPv6 tests instead of skipping when IPv6 loopback is unavailable. |
| `CBB_TEST_LISTS_MIRROR` | `cbb` (`testhooks` build only) | `PORT CAFILE` pointing signed-list fetches at a local test mirror with custom root CAs. Ignored in release builds. |
| `CBB_TEST_MDNS_USERS` | Go mDNS tests | Enables root-only multi-user mDNS session tests. |
| `CBB_TEST_MOVE_LINGER` | `cbb` (`testhooks` build only) | Seconds a retiring hub continues serving clients after `cbb global move` (default 300). Ignored in release builds. |
| `CBB_TEST_OWN_EVIDENCE` | `cbb` (`testhooks` build only) | Path to a JSON array of attestation evidence sent by the member on every connection (`TestEvidence`). Ignored in release builds. |
| `CBB_TEST_PUSH_AT` | `cbb` and phone member (`testhooks` build only) | `ip:port` overriding the push service address from `keys.json` (`member/tests/phone_push.rs`). Ignored in release builds. |
| `CBB_TEST_REFETCH_EVERY` | `cbb` (`testhooks` build only) | Milliseconds between signed-list refetch attempts on relay failure (default 10 minutes). Ignored in release builds. |
| `CBB_TEST_RENEW_EVERY` | `cbb` (`testhooks` build only) | Milliseconds between sealing-key rotation checks (default 1 hour). Ignored in release builds. |
| `CBB_TEST_RESOLVE` | `cbb` (`testhooks` build only) | Comma-separated `host=ip` overrides for resolving project relay hostnames from `entries.json`. Ignored in release builds. |
| `CBB_TEST_RUN_AS` | `cbb` unit tests (`sys::tests::gives_up_root`) | Internal marker for the unprivileged child process in privilege-drop tests. |
| `CBB_TEST_RUST_RELAY` | Go relay tests | Path to the `cbb-relay` binary (falls back to `cbb-relay` beside `CBB_TEST_ALONE` or `CBB_TEST_RUST_SERVICE`). |
| `CBB_TEST_RUST_SERVICE` | Go end-to-end tests (`internal/service`) | Path to the `cbb` binary tested as a default Linux member using mDNS. |
| `CBB_TEST_SCALE` | `benchtime` build | Time-acceleration multiplier for long intervals (`100000` by default; `1` moves only the clock). Ignored in release builds. |
| `CBB_TEST_STANDBY_GRACE` | `cbb` (`testhooks` build only) | Seconds a standby hub waits before taking over from a higher-priority hub (default 60). Ignored in release builds. |
| `CBB_TEST_STATUS_EVERY` | `cbb` (`testhooks` build only) | Milliseconds between attestation status-list fetches on the main device (default 1 day). Ignored in release builds. |
| `CBB_TEST_STATUS_URL` | `cbb-helper` (`testhooks` build only) | Base URL overriding `https://cbb.tools/attest/` for attestation status-list tests. Ignored in release builds. |
| `CBB_TEST_TPM_ROOTS` | `cbb-helper` (`testhooks` build only) | PEM file replacing built-in TPM manufacturer root certificates for EK verification. Ignored in release builds. |
| `CBB_TEST_UINPUT` | Go uinput helper tests | `1` fails tests instead of skipping when `/dev/uinput` is absent. |
| `CBB_TEST_UP_CHECK` | `cbb` (`testhooks` build only) | Seconds a client waits on a lower-priority hub before probing higher-priority hubs again (default 300). Ignored in release builds. |
| `CBB_TEST_WAYLAND` | Go desktop connector tests | Runs clipboard tests against a live Wayland compositor. |
| `CBB_TEST_X11` | Go desktop connector tests | Runs clipboard tests against a live X11 server. |
| `CBB_TEST_XHTTP_CA` | `cbb` (`testhooks`/`benchtime` builds) | PEM file of extra root CAs trusted by VLESS over XHTTP clients in tests and on the bench. Ignored in release builds. |
| `CBB_TPM_REQUIRED` | Go TPM tests | Fails TPM tests instead of skipping when `swtpm` is missing. |
| `CBB_TPM_SIMULATOR` | `cbb-helper` (`testhooks` build) and Go tests | `host:port` of a TPM simulator command port (platform port is `port + 1`). Ignored in release builds. |
| `CBB_UI_BROWSER` | Tray window tests | Path to Chrome, Chromium, or Edge binary for running tray UI tests. |
| `CBB_UNLINKED` | ZX Spectrum Next simulated SD card | Directory where files deleted by `.cbb` are backed up for inspection. |
| `CBB_UPDATE_SCREENSHOTS` | Tray window tests | Any non-empty value regenerates reference screenshots in `apps/desktop/testdata/screenshots`. |
| `CBB_UPDATE_VECTORS` | `cbb-core` keyboard and push tests | `1` regenerates keyboard layout test vectors (`cargo test -p cbb-core keyboard`). |
| `CBB_VERDICTS` | Cross-implementation verdict tests | Path to a `tools/difffuzz gen` corpus ([Differential fuzzing](../differential.md)). |
| `CBB_VERDICTS_OUT` | Cross-implementation verdict tests | Output file path for verdict results (one line per case). |
| `CBB_WEEKLY_SCENARIO` | `tools/bench/weekly.sh` | Restricts the weekly fleet bench run to specified `-scenario` names. |
| `CBB_WRITE_BOUNDS` | `cbb-core` tests | Any non-empty value regenerates `testdata/format/bounds.json` and the bounds table in `docs/protocol.md` from `core/src/bounds.rs`. |
| `CBB_WRITE_MUTANTS` | `cbb-core` tests | `1` regenerates `testdata/format/wave4-mutants.json` from current reader outputs. |
