<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Documentation

Pick the part for what you are doing. Each page says at the top who it is for.

## Using Copy Beyond Borders

For anyone with a phone or a computer, in plain words.

| Document | What is in it |
|---|---|
| [Quick start](guide/quickstart.md) | the phone app, the first computer, sharing the clipboard |
| [How it works](guide/how-it-works.md) | the group and its roles, and pictures of every way the devices connect |
| [Installing](guide/install.md) | every system, Homebrew, winget, Docker, the firewall, updating, removing |
| [The apps](guide/apps.md) | the phone, watch and desktop apps |
| [Away from home](guide/away-from-home.md) | the hub, a forwarder, invitations |
| [Networks that block VPNs](guide/blocked-networks.md) | AmneziaWG and VLESS with REALITY |
| [Images, files and formatted text](guide/images-and-files.md) | what goes where, the sizes, saving received files |
| [Remote paste](guide/remote-paste.md) | an admin puts a text into the focused app on another device |
| [Keyboards and TVs](guide/keyboards-and-tvs.md) | type into a TV, tablet, console or computer as a Bluetooth or USB keyboard, or as the TV's remote |
| [Quick actions](guide/quick-actions.md) | lock, sleep or restart a device from a phone or another computer |
| [Privacy](guide/privacy.md) | who outside the group sees what: networks, servers, updates, stores |
| [Keys and attestation](guide/keys.md) | where each device keeps its keys, how devices prove it, the three levels |
| [If a device is lost](guide/lost-device.md) | remove it, freeze an admin, take the group over |
| [Without the app](guide/without-app.md) | a group held by a computer, joining over SSH or a VPN |
| [Troubleshooting](guide/troubleshooting.md) | logs, the firewall, pairing, other networks |

## Running servers and many devices

For administrators: your own server, a router, a NAS.

| Document | What is in it |
|---|---|
| [Running your own servers](admin/self-hosting.md) | a forwarder and a blind relay on your server, with Docker or systemd, and VLESS |
| [Upgrades and backups](admin/upgrade-and-backup.md) | moving to a new release, what to back up, bringing a device or the root back, moving the hub |
| [Routers and FreeBSD](admin/routers.md) | OpenWrt, OPNsense and FreeBSD: what the installers set up, the networks it answers on, the firewall, the checks |
| [Hardening](admin/hardening.md) | the settings that make a group harder to attack, beyond the defaults |
| [Docker image](../packaging/docker/README.md) | the image for a NAS, a home server or a server on the internet |
| [Lite member](../member/README.md) | the lite member for small Linux devices: build, install, use |

## Reference

Complete and exact, without the reasons.

| Document | What is in it |
|---|---|
| [Commands](reference/cli.md) | every `cbb` command, on a full and on the lite member, with every flag |
| [Settings and environment variables](reference/config.md) | the settings files and every `CBB_*` variable |
| [Devices, ports and files](reference/devices.md) | what each device can do, the ports, where the keys and logs are |
| [Limits and lifetimes](reference/limits.md) | sizes, rates, timeouts, certificate lifetimes, the servers' limits |
| [Error messages and details](reference/errors.md) | how each part shows errors and the switch that shows their details |
| [Glossary](reference/glossary.md) | the words the documentation and the apps use |
| [Changelog](../CHANGELOG.md) | what changed in each release |
| [Security policy](../SECURITY.md) | how to report a vulnerability |

## For engineers

How it is built and why, for contributors, for anyone writing another implementation and
for security reviewers.

| Document | What is in it |
|---|---|
| [Design](design.md) | how it works and why, after the arc42 template: goals, context, building blocks, run time, deployment, concepts, quality, risks |
| [Decisions](decisions.md) | every architecture decision, D-1 to D-78, with its status |
| [Threat model](threat-model.md) | the assets, adversaries, trust boundaries, and each threat with its defence and code |
| [Protocol](protocol.md) | the wire format, for anyone writing another implementation |
| [Group records, version 2](records-v2.md) | why the group's authority records moved to version 2 in 0.6 and how they are tested; the rules are in protocol.md, section 10 |
| [The core's entry point](core-api.md) | the one call, bytes in and bytes out, through which the phones and Go use the Rust core's rules, and its error codes |
| [Cryptography](cryptography.md) | every primitive, library, key, its size, lifetime and where it is kept |
| [Testing](testing.md) | the test levels, the interop vectors, the cross tests and the bench |
| [Differential fuzzing](differential.md) | the four implementations reading changed bodies and record sets alike, in CI and nightly |
| [Platform parity](parity.md) | what each computer, phone and lite device can do, the gaps and the plan to close them |
| [App specification](apps.md) | what the apps do and how they look |
| [Roadmap](roadmap.md) | what comes next, the agreed plans not built yet, research |
| [Contributing](../CONTRIBUTING.md) | conventions, building and testing every part |
| [Your own build](own-build.md) | what ties a build to this project's releases, and how to use your own keys and addresses |
| [Security audit](security-audit.md) | the plan of the security audit |
| [The servers' budget](relay-budget.md) | what strangers can make the open relay and the forwarder hold, who pays, and what a genuine group keeps |

## For maintainers

Releasing and testing on real devices.

| Document | What is in it |
|---|---|
| [Maintaining](maintaining.md) | repository settings, CI, releases, signing keys, Homebrew |
| [Test bench](testbench.md) | testing on real devices before a release: the cases, the bench, the criteria |
| [Test bench catalogue](testbench-catalogue.md) | every bench case of 0.6 in one line, with how it runs and what it still needs |
| [Test bench functions](testbench-functions.md) | every function of the product with the cases that check it, for the coverage report |
| [Test bench cases](testbench-cases.md) | bench cases step by step: the rule, the devices, the steps, pass and fail |
