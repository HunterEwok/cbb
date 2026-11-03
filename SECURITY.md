# Security policy

## Supported versions

The latest release receives security fixes; older releases do not. Fixes land on the
`main` branch first and go out in the next release.

## Reporting a vulnerability

Please report vulnerabilities privately. Do not open a public issue, pull request or
discussion.

Use GitHub private vulnerability reporting: open the
[Security tab](https://github.com/HunterEwok/cbb/security) of the repository and choose
**Report a vulnerability**. Only the maintainer can see the report.

Include, if you can:

- the affected component (the service on Linux, macOS, Windows, FreeBSD or OpenWrt, the
  desktop connector, the clipboard agents, remote paste, quick actions, sync away from home,
  the forwarder or the relay, `cbb update`, the iPhone, Android, watch, Mac or tray app, the
  iOS shortcut, or the lite member) and the version or commit;
- the steps to reproduce;
- the impact: what an attacker can read, change or run.

## What to expect

- An acknowledgement within 7 days.
- An assessment within 30 days: a plan for a fix, or the reason the report is not accepted.
- For an accepted report: a fix, a published GitHub security advisory, and credit if you
  want it.

Please keep the details private until the advisory is published.

## Scope

In scope: the programs and apps in this repository, the pairing, sync and tunnel
protocols, the installers, the release files (archives, the Android APK, the Homebrew
formula, the OpenWrt package feed, the signed release lists) and the published iOS shortcut.

Out of scope:

- Apple Universal Clipboard, the Shortcuts app, desktop environments and terminal emulators;
- attacks that already require root on a member device or an unlocked device in the
  attacker's hands;
- text that a user deliberately copies and sends.

## Good faith

Test only on your own devices. Do not access other people's data and do not disrupt other
people's networks. The maintainer will not take legal action against research done in good
faith under this policy.

The security design is described in [docs/design.md](docs/design.md#security), the threats
and their defences in [docs/threat-model.md](docs/threat-model.md), and the cryptography in
[docs/cryptography.md](docs/cryptography.md).
