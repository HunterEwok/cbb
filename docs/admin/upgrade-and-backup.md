<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Upgrades and backups

For administrators managing a group's devices: upgrading to a new release, deciding what to back
up, recovering a lost device or main device, and moving a hub. For per-platform update commands,
see [Installing: updating](../guide/install.md#updating). For immediate steps when a device is lost
or stolen, see [If a device is lost or stolen](../guide/lost-device.md).

## Upgrade to a new release

Keep every device in a group on the same release; interoperability across different releases is not
guaranteed ([Versions and compatibility](../reference/compatibility.md)).

1. Read the release entry in the [changelog](../../CHANGELOG.md) for any required manual steps.
2. Update your computers and servers first, then your phones and other devices:
   - **Computers installed with `get.sh` or `get.ps1`:** Run `sudo cbb update` (on Windows, run
     `cbb update` in an administrator terminal; on rootless Linux, run `cbb update` without `sudo`;
     on SteamOS, run `sudo /opt/cbb/bin/cbb update`).
   - **Package managers:** Run `brew upgrade cbb` followed by `install.sh` (Homebrew),
     `winget upgrade HunterEwok.cbb` followed by `cbb install` (winget), or
     `apk update && apk upgrade` (OpenWrt package feed).
   - **Docker:** Run `docker compose -f FILE pull && docker compose -f FILE up -d` with your
     compose file.
   - **Phones:** Update through the app store, TestFlight, F-Droid, or the release package.
3. Run `cbb status` on any computer in the group. Any device running a version older than the
   newest release the group knows is marked `(old)`.

With automatic updates enabled (`sudo cbb update -auto on`), computers installed with `get.sh` or
`get.ps1` check daily and install signed releases automatically.

`cbb update` refuses any release older than the newest version the device has already seen. If the
updated service fails to report the new version within 1 minute, `cbb update` restores the previous
binaries automatically, records the failed release so automatic updates skip it, and writes details
to `update.log` (see the log directory table in
[Installing: automatic updates](../guide/install.md#automatic-updates)).

## Decide what to back up

A group does not live in one central place: every device keeps the group's signed records and
shares them with peers. In most setups, back up your **recovery key** rather than device state
directories.

| Item or device | Back it up? | Why |
|---|---|---|
| **Recovery key** (recovery sheet or YubiKey) | **Yes (required)** | Only the recovery key can move the group to a new main device if the current main device is lost; it is shown once at group creation and stored on no device |
| **Main phone** | No | Its main key lives in security hardware (Secure Enclave, Android Keystore, OP-TEE, or HUKS) and cannot be exported; keep the recovery key and another device in the group instead |
| **Main computer** (`cbb new`) | Optional (encrypted, file keys only) | Hardware-backed keys (TPM 2.0 or Mac Secure Enclave) cannot move to another machine; keeping the recovery key and another device in the group is safer than restoring a state backup |
| **Admin or ordinary member** | No | Pairing a replacement device is faster and avoids copying keys or creating conflicting signed histories |
| **Forwarder or blind relay** | **Yes** (key file and `.env`) | A new server key requires updating every hub or group that pins it; see [Running your own servers: updating](self-hosting.md#updating) |

State directory paths for each operating system are listed in
[Devices, ports and files: files and logs](../reference/devices.md#files-and-logs). If you back up
a device's state directory, follow these rules:

- **Stop the service first and encrypt the backup.** Anyone who reads file-backed keys from a
  backup can impersonate that device until an admin removes it from the group.
- **Do not copy hardware-bound keys to another machine.** Keys stored in a TPM 2.0 (Linux or
  Windows) or a Mac Secure Enclave are bound to that hardware and cannot load on another computer;
  the service refuses to start if its identity was copied from another machine.
- **Do not restore an outdated backup of a main device or admin.** If a main computer or admin
  computer signs new group records after a backup is taken and is later restored to that older
  backup, it can sign a conflicting history (`two_histories`). That conflict pauses the group until
  the main device resolves it (`sudo cbb resolve` on a main computer, or through the alert on the
  main phone).

### Keep a second device and a second admin

- **To survive a lost main device:** Store your **recovery key** (printed recovery sheet or
  YubiKey) offline in a safe place, and keep at least one other device in the group. Any remaining
  phone or computer in the group can become the new main device using the recovery key
  ([If a device is lost or stolen: move the group](../guide/lost-device.md#3-if-it-was-the-main-device-move-the-group)).
- **For day-to-day resilience:** Make a second phone an admin (on the main phone, open the phone's
  device page and tap **Make it an admin**; on a main computer, run `sudo cbb admin NAME`). An
  admin phone can admit and remove members, freeze a stolen admin computer, and remove a
  compromised admin computer while the main device is offline—though only the recovery key can
  replace a lost main device.

## Recover a device or main device

| Situation | What to do |
|---|---|
| A device was reinstalled or replaced | Remove the old device (`sudo cbb remove NAME`, or **Remove** in the app), then pair the replacement as a new device |
| A computer with file-backed keys was restored from backup | Start the service; it rejoins with its existing keys as long as it was not removed. If it was a main computer or admin restored from an older backup and `cbb status` reports two histories, run `sudo cbb resolve` on the main device |
| The main device is lost and another device remains in the group | Move the group using the recovery key: on a remaining phone, open **Settings > Move the group to this phone**; on a remaining computer, run `sudo cbb recovery -leave LOST-DEVICE` (add `-yubikey` for a YubiKey) or choose **Move the group to this Mac** / **Move the group to this computer** in the desktop app |
| The main device is lost and you have no recovery key (or no other device remains) | The group cannot be moved; leave the old group on any remaining devices (`sudo cbb leave` or **Leave the group** in the app), create a new group, and pair your devices again |
| An OpenWrt router was upgraded | A standard `sysupgrade` keeps the install and keys in `/etc/cbb/state`; after an attended sysupgrade (ASU or `owut`), re-run the install command and your keys remain intact |
| A Docker container was recreated | Keep the compose file's `state` volume (`/var/lib/cbb`), and the container rejoins its group |

A removed device can never rejoin with its old keys: leave the group on that device
(`sudo cbb leave` or **Leave the group** in the app) and pair it again as a new device.

## Move the hub

To hand the hub role from the current hub to another computer, run on the current hub (omit `sudo`
in an administrator terminal on Windows):

```sh
sudo cbb global move DEVICE
```

Requirements and behavior:

- `DEVICE` must be a hub-capable computer in the group (not frozen, with syncing away from home
  turned on): the main computer, an admin computer, or a computer listed in the group's hubs record
  (`sudo cbb global hubs`).
- The new hub inherits the current hub's forwarder unless you pass `-forwarder` (with
  `-forwarder-key` for your own forwarder) or a direct `ADDRESS:PORT`.
- The retiring hub keeps serving away clients until the new hub starts serving, and then for up to
  5 minutes before switching to a client. Away devices that have already met the new hub (at home
  or through a blind relay) switch automatically; away devices that have never met the new hub
  connect to it once they meet it at home or at the group's relay ([Command reference](../reference/cli.md),
  [Protocol](../protocol.md), section 11, "Moving the hub").
- Never copy a hub's state directory onto another computer.
