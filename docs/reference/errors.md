<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Error messages and details

Every part of Copy Beyond Borders shows an error in two layers: a short message that says what
went wrong in plain words, and the details underneath (the error's type, code and the
underlying message) for finding the cause. Release builds show only the message; debug
builds show both. Each part has one switch that shows the details in a release build too,
and the log always has them. What to do about the common messages is in
[troubleshooting](../guide/troubleshooting.md).

## The switch on each part

| Part | Details shown by default | Switch | Where the details always are |
|---|---|---|---|
| `cbb` on a computer | in a development build (`cbb version` says `dev`) | `CBB_DEBUG=1` shows them, `CBB_DEBUG=0` hides them: `CBB_DEBUG=1 cbb status`, on Windows `$env:CBB_DEBUG = "1"` first | the service's log ([where](devices.md#files-and-logs)) |
| The service | | `CBB_DEBUG=1` in its environment also logs WireGuard's own messages | its log |
| The lite member | in a debug build | `-debug` before the command, or `CBB_DEBUG=1`; `CBB_DEBUG=0` hides them | its log, `journalctl -u cbb` (on OpenWrt `logread -e cbb`) |
| The iPhone and Android apps | in a debug build | Settings: seven taps on the version show the switch "Show error details"; the launch argument `ShowErrorDetails` sets it too (on Android in a debug build only) | the app's log |
| The watch apps | as their phone | follow the phone's switch | the phone app's log |
| The Mac app | in a debug build | "Error details" in Settings; it passes `CBB_DEBUG=1` to the `cbb` commands it runs | the service's log |
| The tray app for Linux and Windows | in a development build | "Error details" in Settings, else `CBB_DEBUG` as for `cbb` | its standard error |
| The installers (`install.sh`, `uninstall.sh`, `get.sh`) | | `CBB_ERROR_DETAILS=1` shows every command as it runs; without it a failure names its exit status | |
| The Windows installers (`get.ps1`, `install.ps1`, `uninstall.ps1`) | | `-Details` or `CBB_ERROR_DETAILS=1` adds the full error record | |
| `.cbb` on the ZX Spectrum Next | | `.cbb -d` | the lite member's log on its Pi |

The variables are in [settings and environment variables](config.md).

## What a message looks like

`cbb` writes the message after `cbb:` on standard error and exits with status 1;
with details on, the cause follows on a line of its own:

```
cbb: the Copy Beyond Borders service is not running; start it with: sudo systemctl start cbb
  Detail: dial unix /run/cbb/control.sock: connect: no such file or directory
```

A wrong command line exits with status 2 and prints the usage. The apps show the message,
with the details under it when the switch is on.

## When you report a problem

Turn the details on, run the command again, and include the message, the detail line and
the part of the log around that time. Remove device names and addresses you do not want to
share. See [SECURITY.md](../../SECURITY.md) for anything that may be a vulnerability.
