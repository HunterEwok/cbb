<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Limits and lifetimes

The sizes, rates, timeouts and lifetimes that Copy Beyond Borders enforces, in one place. A
limit that a device's user can change says so and names the command. The wire format behind
them is in the [protocol](../protocol.md).

## Copies

| What | Limit | Change it |
|---|---|---|
| A text | 1 MiB of UTF-8 | no |
| Images and files at home | 100 MiB per copy | `cbb config max-copy SIZE`, 1 MiB to 1 GiB |
| Images and files through the group's tunnel | 25 MiB per copy | `cbb config max-copy-away SIZE`, at most `max-copy`; the hub's limit caps every device that reaches only it |
| Images and files at all | 1 GiB, at most 10,000 parts and 8 clipboard types per copy | no |
| A file name, a path | 255 bytes, 4,096 bytes | no |
| What the phones' share sheet sends | 100 MiB on Android, 50 MB from the iPhone | no |
| The plain text that goes with images or files | 256 KiB | no |
| HTML from a desktop clipboard | 8 MiB | no |
| A secret (marked by a password manager, or `cbb copy -secret`) | current for 60 s after the copy, kept only in memory; its text is recognised for 12 h after, so that it stays secret when offered again | no |
| How long a copy is still written to the clipboards it reaches | 60 s after the copy; for 30 s after a device comes back, the newest copy is still written there although it is older | no |
| A received time ahead of this device's clock | at most 7 days; a later one is refused, so that no device can move the group's clocks for good | no |

## Remote paste and quick actions

| What | Limit |
|---|---|
| A pasted text | 1 MiB |
| A typed text (`cbb paste -on DEVICE -type`) | 4 KiB |
| Pastes from one sender | one a second, 30 a minute |
| The log of pastes on a device | the last 100, without their text |
| A signed command (paste, action, mode) | valid 30 s after it was signed; its time may be at most 60 s ahead of the receiver's clock |
| An action of your own | must end within 15 s; at most 32 of them, names of up to 32 characters |

## Keyboards and TVs

| What | Limit |
|---|---|
| A text typed by a Bluetooth or USB keyboard | 4,096 characters |
| Typing speed | 5 to 60 characters a second, 20 by default (the Android app: 10, 20 or 40) |
| Making a keyboard discoverable (`pair`) | 2 minutes |
| The code an Android TV shows (`cbb remote code`) | taken within 2 minutes |
| TVs of one computer | 16 |
| Hosts the Nano ESP32's Bluetooth keyboard remembers | 4; a fifth pushes out the oldest |

## Pairing and invitations

| What | Limit |
|---|---|
| A pairing window (`cbb pair`, the QR code) | open 5 minutes; three failed attempts close it |
| A device name | 1 to 64 characters |
| A remote invitation (`cbb invite`) | 1 hour by default, at most 24 hours (`-for`) |

## Certificates and keys

| What | Lifetime |
|---|---|
| The group's CA certificates | 20 years |
| A member certificate (computers, lite members and phones) | 2 years, renewed 240 days before its end |
| A period of the server credentials | 35 days; the root starts the next after 30, which on a phone asks for Face ID or the fingerprint about once a month |
| A release's signed files (`keys.json`, `release.json`) | at most 100 days |
| The signed status of the stable release (`stable.json`) | at most 8 days, so an old one cannot hold back an update |

## The group

| What | Limit |
|---|---|
| Records the group keeps (devices, removals, admins, settings) | 1,024 and 1 MiB together, counted after the root's checkpoint; records past them count for nothing, the root's first ([protocol](../protocol.md), section 10, "Limits") |
| One record | 8 KiB; a checkpoint 64 KiB |
| Devices of one group | 256 |
| Admin keys | 64 |
| Handovers of the group to a new root | 15 |
| Clients of one hub | 256 |
| Members and hubs in one server credential | 256 and 16 |
| Known home networks of one computer | 64 |

## Servers

The defaults of [your own servers](../admin/self-hosting.md).

| What | Forwarder (`cbb forward`) | Blind relay (`cbb relay`) |
|---|---|---|
| Groups at once | 100,000 hubs | 4,096 with `-open`; no limit for the groups `-group` names |
| Devices of one group | 16 client addresses | 64 devices at once |
| Registrations from one address, one network (/24 or /64), one wide network (/16 or /48), one IPv6 provider (/32) | 16, 64, 256, 1024 | 16, 64, 256, 1024 with `-open` |
| Traffic of one group, both ways | 1,000 packets and 2 MiB a second | 1 MiB a second with `-open` |
