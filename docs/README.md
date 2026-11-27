<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Documentation

Choose the section that matches your task. Each page states at the top who it is for.

## Using Connect Beyond Borders

User guides in plain language for anyone sharing a clipboard across phones and computers.

| Document | Contents |
|---|---|
| [Quick start](guide/quickstart.md) | Set up the phone app, install on your first computer, and share your clipboard. |
| [How it works](guide/how-it-works.md) | Group roles, end-to-end encryption, and diagrams of how devices connect at home and away. |
| [Installing](guide/install.md) | Install, update, verify checksums, configure firewalls, and uninstall on Linux, macOS, Windows, FreeBSD, OpenWrt, and Docker. |
| [The apps](guide/apps.md) | Phone, tablet, watch, Android TV, and desktop apps across all platforms. |
| [Away from home](guide/away-from-home.md) | Set up a hub, configure a forwarder or blind relay, and invite remote devices. |
| [Networks that block VPNs](guide/blocked-networks.md) | Disguise away-from-home traffic with AmneziaWG and VLESS over XHTTP. |
| [Images, files and formatted text](guide/images-and-files.md) | Supported content types, per-device size limits, and sending or saving files. |
| [Remote paste](guide/remote-paste.md) | Paste text, images, or files from an admin device into the focused app on another computer. |
| [Keyboards and TVs](guide/keyboards-and-tvs.md) | Type into a TV, tablet, game console, or computer as a Bluetooth or USB keyboard, or as a TV remote. |
| [The lab](guide/lab.md) | Experimental features: keyboards, TV remotes, Arduino Nano ESP32, and ZX Spectrum Next. |
| [Quick actions](guide/quick-actions.md) | Lock, sleep, restart, or run approved actions on a computer from an admin device. |
| [Privacy: who sees what](guide/privacy.md) | What networks, servers, update checks, push services, and app stores can observe. |
| [Keys and attestation](guide/keys.md) | Where each device stores its keys, how hardware attestation works, and the three key levels. |
| [If a device is lost or stolen](guide/lost-device.md) | Remove a lost device, freeze a stolen admin computer, and move the group to a new main device. |
| [Without the app](guide/without-app.md) | Create and manage a group held by a computer, and pair over SSH or a VPN. |
| [Troubleshooting](guide/troubleshooting.md) | Diagnose logs, firewalls, pairing failures, and cross-network issues. |

## Running servers and many devices

How-to guides for administrators running self-hosted servers, routers, NAS appliances, or small
devices.

| Document | Contents |
|---|---|
| [Running your own servers](admin/self-hosting.md) | Run a self-hosted forwarder or blind relay with Docker or systemd, including VLESS over XHTTP. |
| [Upgrades and backups](admin/upgrade-and-backup.md) | Upgrade releases, choose what to back up, recover a lost device or main device, and move a hub. |
| [Routers and FreeBSD](admin/routers.md) | Install, configure interfaces and firewalls, and verify Connect Beyond Borders on OpenWrt, OPNsense, and FreeBSD. |
| [Hardening](admin/hardening.md) | Strengthen a group beyond default security settings, with trade-offs for each option. |
| [Docker image](../packaging/docker/README.md) | Run the containerized service on a NAS, home server, or public server. |
| [Small devices](../member/README.md) | Build, install, and run `cbb` without `cbb-helper` on small Linux devices and routers. |

## Reference

Exact specifications and lookup tables without background rationale.

| Document | Contents |
|---|---|
| [Command reference](reference/cli.md) | Every `cbb` command, flag, and installer option. |
| [Settings and environment variables](reference/config.md) | Settings files and every `CBB_*` environment variable. |
| [Devices, ports and files](reference/devices.md) | Platform capabilities, network ports, and file and log paths. |
| [Limits and lifetimes](reference/limits.md) | Size limits, rate limits, timeouts, key lifetimes, and server caps. |
| [Versions and compatibility](reference/compatibility.md) | Cross-version compatibility rules and what updates preserve. |
| [Error messages and details](reference/errors.md) | Error display, exit codes, and diagnostic switches across components. |
| [Glossary](reference/glossary.md) | Definitions of user-facing and protocol terms. |
| [Changelog](../CHANGELOG.md) | Release history and user-visible changes. |
| [Security policy](../SECURITY.md) | How to report a security vulnerability privately. |

## For engineers

Architecture, wire specifications, security analysis, and testing guides for contributors,
implementers, and security reviewers.

| Document | Contents |
|---|---|
| [Design](design.md) | System architecture (arc42): goals, context, building blocks, runtime, deployment, cross-cutting concepts, quality, and risks. |
| [Architecture decisions](decisions.md) | Numbered register of active architecture decisions and replaced historical decisions. |
| [Threat model](threat-model.md) | Assets, adversaries, trust boundaries, threats with defences and source locations, and residual risks. |
| [Protocol](protocol.md) | Normative protocol specification: messages, records, rules, and registries. |
| [Wire format](format.md) | Byte-by-byte binary wire encoding of messages, records, commands, credentials, and copies. |
| [The core's entry point](core-api.md) | Byte-in/byte-out ABI (`cbb_core::api` through `ffi/`) used by phone apps and external bindings, plus error codes. |
| [Cryptography](cryptography.md) | Every cryptographic primitive, library, key type, size, lifetime, and storage location. |
| [Testing](testing.md) | Test levels, interoperability vectors, cross-implementation tests, and the test bench. |
| [Differential fuzzing](differential.md) | How CI compares the three parser implementations (Go, Rust core, Kotlin kit), runs native fuzzers, and promotes failures to test vectors. |
| [Platform parity](parity.md) | Capability matrix by device class (computers, phones, small devices) and real-hardware testing status. |
| [App specification](apps.md) | Behavior and user interface specification for the phone and desktop apps. |
| [Roadmap](roadmap.md) | Planned features, agreed designs not yet built, and open research topics. |
| [Contributing](../CONTRIBUTING.md) | Repository conventions, build commands, and test suites for every component. |
| [Your own build and your own keys](own-build.md) | How to replace pinned release keys and update addresses in a custom build, and how to verify reproducible releases. |
| [The servers' budget](relay-budget.md) | Resource caps, payer levels, XHTTP limits, traffic monitoring, and abuse handling for the open relay and forwarder. |

## For maintainers

Release procedures, hardware testing, and security audits.

| Document | Contents |
|---|---|
| [Maintaining](maintainers/maintaining.md) | Repository settings, CI jobs, release signing, notarization, and Homebrew publishing. |
| [Test bench](maintainers/testbench.md) | Specification for running pre-release tests on physical devices. |
| [Test bench catalogue](maintainers/testbench-catalogue.md) | One-line summary of every test bench case, how it runs, and what hardware or account it needs. |
| [Test bench functions](maintainers/testbench-functions.md) | Product functions mapped to the test bench cases that verify them. |
| [Test bench cases](maintainers/testbench-cases.md) | Step-by-step hardware test bench procedures with pass and fail criteria. |
| [Security audit](maintainers/security-audit.md) | Plan and scope of the security audit. |
