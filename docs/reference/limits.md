<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Limits and lifetimes

For users, administrators, and developers looking up every size limit, rate limit, timeout, and
lifetime enforced by Connect Beyond Borders. Where a limit is configurable, the command is listed.
For normative wire bounds, see [Protocol](../protocol.md).

## Copies

| What | Limit | Configurable |
|---|---|---|
| Plain text copy | 1 MiB (`1,048,576` bytes) of UTF-8 | No |
| Images and files at home | 100 MiB default | Yes: `cbb config max-copy SIZE` (`1 MiB` to `1 GiB`) |
| Images and files through the group's tunnel | 25 MiB default | Yes: `cbb config max-copy-away SIZE` (`1 MiB` to `max-copy`; hub limit caps away devices reaching only that hub) |
| Media copy wire ceiling | 1 GiB total, 10,000 parts, 8 clipboard types, 2 MiB combined path bytes | No |
| File name and path length | 765 bytes per name (255 UTF-8 characters up to 3 bytes each); 16 KiB (`16,384` bytes) per path | No |
| Phone share and send limit | 100 MiB on Android; 50 MiB on iPhone, Aurora OS, and HarmonyOS | No |
| Plain-text alternative with images or files | 256 KiB | No |
| HTML from a desktop clipboard | 8 MiB | No |
| Ordinary copy lifetime | 5 min default | Yes: `cbb ttl COPY [SECRET]` (`1m` to `1h`, on main device or admin) |
| Secret lifetime | 60 s default; kept in memory only; up to 1,024 seen secret IDs tracked against replay | Yes: `cbb ttl COPY SECRET` (`5s` to `1m`, on main device or admin) |
| Copy timestamp ahead of receiver's clock | 5 min freshness allowance (copies further ahead are rejected); 7 days hard HLC ceiling | No |
| Sync pause or mute duration (`-for`) | `1ms` to `720h` (30 days) | Set per command (`cbb sync off -for`, `cbb mute -on DEVICE -for`) |

## Remote paste and quick actions

| What | Limit |
|---|---|
| Pasted text (`cbb paste -on`) | 1 MiB |
| Typed text (`cbb paste -on DEVICE -type`) | 4 KiB sent by `cbb` and apps (16 KiB wire ceiling) |
| Remote pastes from one sender | 1 per second, 30 per minute |
| Remote paste log per device | Last 100 entries (text is never logged) |
| Quick action log per device | Last 100 entries |
| Signed command (paste, action, mode, mute, hub) | Issued with 30 s validity (600 s wire ceiling); timestamp at most 60 s ahead of receiver's clock |
| Custom quick actions (`cbb action add`) | 15 s execution timeout; at most 32 custom actions; action names up to 32 characters |
| Reboot and shutdown delay | 1 minute (`cancel-shutdown` cancels during this window) |

## Keyboards and TVs

| What | Limit |
|---|---|
| Text typed by a Bluetooth or USB keyboard | 4,096 characters |
| Typing speed | 5 to 60 characters/s, default 20 (Android, Aurora OS, and HarmonyOS apps offer 10, 20, or 40 characters/s) |
| Bluetooth keyboard discoverable window (`cbb keyboard pair`) | 2 minutes |
| TV pairing code window (`cbb remote code`) | 2 minutes |
| Paired TVs per computer | 16 |
| Bonded hosts remembered by Arduino Nano ESP32 | 4 (a fifth replaces the oldest) |

## Pairing and invitations

| What | Limit |
|---|---|
| Pairing window (`cbb pair`) | Open 5 minutes; closes after 3 wrong code attempts |
| Device name | 1 to 64 characters |
| Remote invitation (`cbb invite`) | 1 hour default, up to 24 hours (`-for`); 5 minutes for admin confirmation once a device connects |

## Keys and signed files

| What | Lifetime |
|---|---|
| Silent admin key retention | 35 days before the main device reclaims the admin key |
| Device offline window for reading and writing copies (keys statement max age) | 35 days |
| Server credential period | 35 days; main device starts the next period after 30 days |
| Interactive admin confirmation cache (everyday changes) | 5 minutes |
| Signed release metadata (`keys.json`, `release.json`) and channel (`stable.json`) | At most 100 days; `stable.json` is signed for 14 days |
| Signed attestation status (`attest-status.json`) | At most 8 days |

## The group

| What | Limit |
|---|---|
| Group record set room | 7,168 record units and 3.5 MiB (`3,670,016` bytes) total (1,536 main device units, 1,536 reserve units, and 256 units per admin key; [Protocol](../protocol.md), section 10) |
| Single record body | 16 KiB; checkpoint body: 256 KiB |
| Devices per group | 256 |
| Admin keys per group | 16 |
| Main device changes (recovery records) over a group's life | 64 |
| Primary hubs in group settings (`cbb global hubs`) | 16 |
| Blind relays in group settings (`cbb global relay`) | 16 |
| Clients per hub | 256 |
| Entries per server credential | 256 members, 64 admins, 16 hubs |
| Known home networks per computer | 64 |

## Servers

Default limits of [Running your own servers](../admin/self-hosting.md):

| What | Forwarder (`cbb forward`) | Blind relay (`cbb relay`) |
|---|---|---|
| Groups at once | 100,000 hubs | 4,096 with `-open`; unlimited for groups listed in `-group` |
| Clients / devices per group | 16 client addresses (64 pending handshakes) | 64 devices at once (16 concurrent calls) |
| Concurrent tunnel connections (all groups) | Bounded by memory and OS limits | 8,192 with `-open` (scaled down if OS open-file limit is lower) |
| Registrations per IP / network (`/24` IPv4 or `/64` IPv6) / wide network (`/16` IPv4 or `/48` IPv6) / IPv6 provider (`/32`) | 16, 64, 256, 1,024 (1,024 over VLESS) | 16, 64, 256, 1,024 with `-open` |
| Traffic per group (both ways combined) | 1,000 packets/s and 2 MiB/s | 1 MiB/s with `-open` |
