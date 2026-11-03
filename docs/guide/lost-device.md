<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# If a device is lost or stolen

For anyone whose phone, computer or other device of the group is gone. Remove it from the
group as soon as you can; the other devices stay in the group and keep syncing.

## 1. Remove it

On a phone that is an admin, tap the lost device on **Home**, then **Remove**. On an
admin computer:

```sh
sudo cbb remove NAME     # NAME, or the device ID, as cbb status shows it
```

Every device of the group learns of it and stops talking to the lost one. Only the root, or
an admin phone, removes an admin.

## 2. If it was an admin computer: freeze it first

An admin computer's keys can sign. If it may be in someone else's hands, freeze it from any
admin, so that nothing it signs from now on counts, and then remove it:

```sh
sudo cbb freeze NAME
```

A frozen admin cannot freeze the root or an admin phone. If it freezes back, both stay
frozen until the root decides (`cbb unfreeze` or `cbb remove` on the root, or
**Unfreeze** and **Remove** on the root phone).

## 3. If it was the root: take the group over

The root holds the group's root key. When it is gone, an admin becomes the root, and every
other device stays in the group:

- with phones: on the other phone, which is an admin, remove the lost one; the app takes the
  group over in the same step;
- with computers: on an admin computer, `sudo cbb takeover NAME`, where NAME is the lost
  root.

If someone else holds a removed admin's device, they can stop the group for a while by
signing claims of their own: the devices say the group is stopped. Then the old root ends it,
if you still have it; in 0.6 the new root cannot, and a group whose old root is lost too is
set up again ([protocol](../protocol.md), section 10, "Known limits in 0.6").

iPhones that use the shortcut pair again after a takeover. If the group had no other admin,
it cannot be taken over: make a new group and add the devices again. That is why the apps
suggest a second admin phone, or an admin computer, as soon as the group has a single admin.

## 4. Turn off what it could reach

Removing the device is enough for the group. If you cannot remove it yet, or want to be sure
of the other devices, an admin can also turn off from afar:

| What | Command on an admin computer |
|---|---|
| [Remote paste](remote-paste.md) on a device, or on all | `cbb paste-receive off -on DEVICE`, `-all` |
| [Quick actions](quick-actions.md) on a device, or on all | `cbb action off -on DEVICE`, `-all` |
| Sync away from home on a device | `cbb global off -on DEVICE` |

An admin phone offers the same on the device's page, and an admin watch can send these too.
Only each device's own user turns them on again.

## What a thief gets

It depends on where the device kept its keys ([keys and attestation](keys.md)):

- **Keys in hardware** (phones, Macs with a Secure Enclave, computers with a TPM): nothing to copy. The keys sign
  only on that device, and a phone's root and admin keys sign only after your face,
  fingerprint or passcode.
- **Keys in a file** (Intel Macs without the T2 chip, Windows PCs and Linux computers
  without a TPM, the lite member): whoever copies the file can act as that device until you remove it. Encrypt the
  disk (FileVault, BitLocker, LUKS) so a stolen device gives nothing away.

The clipboard's history is not kept on the devices, and a secret is gone 60 seconds after it
was copied.
