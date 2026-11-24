<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Error messages and details

For users, administrators, and bug reporters checking how Connect Beyond Borders displays errors,
exit codes, and diagnostic details across every component. For solutions to common problems, see
[Troubleshooting](../guide/troubleshooting.md).

Every component reports errors in two layers:

- **User message**: A short, plain-language summary of what failed.
- **Details**: The chain of underlying errors, their types, and system error codes.

Release builds show only the user message by default; debug builds show both. Each component has a
switch to display details in a release build, and service and app logs always record the full
details.

## The switch on each part

| Part | Details shown by default | Switch to show or hide details | Where full details are always logged |
|---|---|---|---|
| `cbb` CLI | Debug builds (`cfg!(debug_assertions)`) | `-debug` before the command, or `CBB_DEBUG=1` (`true`, `yes`) to show / `CBB_DEBUG=0` (`false`, `no`) to hide (PowerShell: `$env:CBB_DEBUG = "1"`) | Service log ([Devices, ports and files](devices.md#files-and-logs)) |
| `cbb service`, `cbb-forward`, `cbb-relay`, `cbb-push` | Never in user output (always in logs) | `CBB_DEBUG=1` in the service environment adds WireGuard tunnel messages, peer closes/resets, and periodic server counts | Service log |
| iPhone app | Debug builds | Settings: tap the version seven times to reveal **Show error details**; launch argument `-ShowErrorDetails YES\|NO` | App log |
| Android app | Debug builds | Settings: tap the version seven times to reveal **Show error details**; in debug builds, launch extra `--ez ShowErrorDetails true\|false` | App log |
| Aurora OS and Sailfish OS app | Release off | Settings: tap the version seven times to reveal **Show error details** | App log |
| HarmonyOS app | Release off | Settings: tap the version seven times to reveal **Show error details** | App log |
| Watch apps (Apple Watch, Wear OS, HarmonyOS watch) | Follows paired phone | Follows the paired phone's **Show error details** switch | Paired phone's app log |
| Mac app | Debug builds | Settings: **Show error details** (also `-ShowErrorDetails YES\|NO` or `defaults write tools.cbb.mac ShowErrorDetails -bool YES`); passes `CBB_DEBUG` to `cbb` commands it runs | Service log |
| Tray app (Linux and Windows) | Debug builds | Settings: tap the version seven times to reveal **Show error details**; passes `CBB_DEBUG` to `cbb` commands it runs | Standard error |
| POSIX installers (`get.sh`, `install.sh`, `uninstall.sh`) | Off | `CBB_ERROR_DETAILS=1` prints every command as it runs (`set -x`); otherwise failures print only the exit status | Standard error |
| Windows installers (`get.ps1`, `install.ps1`, `uninstall.ps1`) | Off | `-Details` switch or `CBB_ERROR_DETAILS=1` prints the full PowerShell error record and stack trace | Console output |
| `.cbb` on ZX Spectrum Next | Off | `.cbb -d` | `cbb` log on the attached Raspberry Pi |

All environment variables are listed in [Settings and environment variables](config.md).

## What a message looks like

`cbb` prints errors to standard error prefixed with `cbb:`. When details are enabled, the
underlying cause chain follows under `  details:`:

```text
cbb: cannot reach the CBB service at /run/cbb/control.sock; is it running (systemctl status cbb)?
  details: No such file or directory (os error 2) (std::io::error::Error: Os { code: 2, kind: NotFound, message: "No such file or directory" })
```

Apps display the user message, with the detail text below it when **Show error details** is on.

### Exit codes

`cbb` uses the following process exit codes:

| Exit code | Meaning |
|---|---|
| `0` | Command succeeded. |
| `1` | Command failed or user declined a confirmation prompt. |
| `2` | Invalid command, missing or invalid flag, or usage error (prints usage to standard error). |
| `75` | Interactive admin confirmation prompt (polkit, Touch ID, or Windows Hello) was cancelled. |
| `77` | Interactive admin confirmation is unavailable for this user; rerun with `sudo` or as administrator. |
| `130` | `cbb invite` was cancelled by `SIGINT` or `SIGTERM` (and its invitation file was deleted). |

## Reporting a problem

Enable error details, rerun the failing command or action, and include:

1. The full user message and `details:` lines.
2. The `cbb version` output (or the app version from Settings).
3. The relevant section of the service or app log around the failure time, with any private device
   names or IP addresses removed.

For suspected security vulnerabilities, follow [SECURITY.md](../../SECURITY.md) instead of opening
a public issue.
