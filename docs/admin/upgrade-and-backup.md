<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Upgrades and backups

For whoever looks after the group's devices: moving to a new release, what to back up, and
how to bring a group back after a device is gone. How to install and update each system is
in [installing](../guide/install.md#updating); what to do at once when a device is lost or
stolen is in [if a device is lost](../guide/lost-device.md).

## Upgrading to a new release

1. Read the release's entry in the [changelog](../../CHANGELOG.md); a step that a release
   needs from you is said there.
2. Update the computers first, then the phones and the other devices: `sudo cbb update`
   (on Windows in an administrator terminal), the app stores for the phones, `apk upgrade`
   on an OpenWrt router installed from the feed, and for Docker
   `docker compose -f FILE pull && docker compose -f FILE up -d` with your compose file.
3. Run `cbb status` on any computer of the group: a device that still runs an older release
   than the newest the group knows is marked `(old)`.

Devices of neighbouring releases work together: each ignores fields and messages it does
not know (the [protocol](../protocol.md), "Conventions"). A feature that needs every device
to know it, such as a new kind of record, waits until each device in the group runs a
release that has it, and the changelog says so. With automatic updates on
(`sudo cbb update -auto on`), the computers update by themselves within a day of a release.

An update never takes a release that is older than one this device has already seen, and
it puts the previous programs back when the new service does not report its version within
a minute. A release that went back this way is skipped by the automatic updates; its log is
`update.log` in the update folder of [installing](../guide/install.md#updating).

### Groups made before 0.4

A group whose computers all hold the group's key (made before 0.4) is not read from 0.6 on,
as a group of 0.5 is not: each computer leaves it at its first start, keeps its settings, and
the group is set up again (`cbb new` on one computer, `cbb pair` on the others).

## What to back up

The group itself is not in any one place: every device keeps the records it needs, and the
phones and computers pass them on. What a backup can add is a way back for the group's
**root**, when it is a computer.

| Device | Back it up? | Why |
|---|---|---|
| The root phone | no | its root key is in the Secure Enclave or the Keystore and cannot be copied; keep a second admin phone instead (below) |
| The root computer (a group made with `cbb new`) | yes, encrypted, or keep an admin | its state folder holds the group's root key and the iPhone CA |
| An admin computer | no, if the root or another admin remains | the root makes a new admin in a minute |
| Any other device | no | pairing it again is quicker than a restore, and a copied key is a risk |
| A forwarder or a relay | its key file | a new key means giving every hub the new one; see [running your own servers](self-hosting.md#updating) |

The state folder of each system is in [devices, ports and files](../reference/devices.md#files-and-logs).
Back it up only with the service stopped, and only into storage that is encrypted: whoever
reads the backup can act as that device until it is removed from the group. Keys in a TPM
(Linux computers that have one) cannot be restored on another computer at all; the service
says so ("was the identity copied from another machine?") and refuses to start with them.

### A second admin instead of a backup

The safest way back is a second device that may act for the group:

- **In a phone's group**, make a second phone an admin (on the root phone: Devices, the
  phone, "Make it an admin"). If the root phone is lost, the admin phone takes the group
  over and every device stays in it.
- **In a computer's group**, make another computer an admin (`sudo cbb admin NAME` on the
  root). If the root is lost, `sudo cbb takeover LOST_ROOT` on the admin, with the lost
  root's name or ID, makes the admin the root.

## Bringing a device back

| What happened | What to do |
|---|---|
| A device was reinstalled or replaced | remove the old one (`sudo cbb revoke NAME`, or Remove in the app), then pair the new one as a new device |
| A computer was restored from its own backup, on the same hardware | start the service; it rejoins with its old keys, as long as nobody removed it |
| The root computer is gone and an admin remains | `sudo cbb takeover LOST_ROOT` on the admin, with the lost root's name or ID |
| The root phone is gone and an admin phone remains | remove the lost root on the admin phone; the app takes the group over in the same step |
| The root is gone and no admin remains | the group cannot admit or remove devices any more; make a new group and pair every device into it |
| An OpenWrt router was upgraded | a plain sysupgrade keeps the whole install, keys included; after an attended sysupgrade (ASU, owut) run the install command again, and the keys are still there |
| Docker | the state lives in the compose file's volume; keep the volume and the container comes back in its group |

A removed device cannot come back with its old keys: pair it again.

## Moving the hub

To give the hub's role to another computer, run `sudo cbb global move NAME` on the hub
("Move the hub to a computer" in the phone apps); NAME must be an admin computer with sync
away from home on. The clients' keys move with a signed command and every client follows
without coming home ([commands](../reference/cli.md), the [protocol](../protocol.md),
section 11, "Moving the hub"). Do not copy a hub's state folder onto another computer.
