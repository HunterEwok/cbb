<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# If a device is lost or stolen

For anyone whose phone, computer, or other group device is lost or stolen. On this page, you
remove the lost device, freeze a stolen admin computer, move the group to a new main device if
your main device is gone, and turn off remote features on your remaining devices.

Remove a missing device as soon as you notice it is gone. Your remaining devices stay in the group
and continue syncing without needing to pair again.

## 1. Remove the lost device

Removing a device spreads a signed removal record so every other device refuses connections from
it and stops sealing copies to it. Only the **main device** (called *root* in command-line tools)
or an **admin phone** can remove another admin; an admin computer removes ordinary members only.

- **On the main device or an admin phone:**
  1. Open **CBB** and tap the lost device on **Home**.
  2. Tap **Remove** and confirm with your face, fingerprint, passcode, or (on Aurora OS) your
     admin PIN.
- **On the main device or an admin computer (terminal):**

  ```sh
  sudo cbb remove NAME
  ```

  Replace `NAME` with the device's name or device ID from `cbb status` (omit `sudo` in an
  administrator terminal on Windows).
- **In the Mac app or tray app (main device or admin):** Open the lost device's details pane,
  click **Remove**, and confirm.

**Result:** Every connected device refuses the removed device immediately, and offline devices
refuse it as soon as they reconnect. A removed device can rejoin only by pairing again as a new
device.

## 2. If it was an admin computer: freeze it first

An admin computer can sign group changes and send commands. If an admin computer may be in someone
else's hands and you do not have the main device or an admin phone at hand to remove it, freeze it
from any admin device first.

1. Run on any admin device:
   - **Terminal:** `sudo cbb freeze NAME`
   - **Phone or desktop app:** Open the admin computer on **Home**, select **Freeze**, and confirm.

   **Result:** Nothing the frozen admin signs counts from that point on, and every other device
   refuses its connections. A frozen admin cannot freeze the main device or an admin phone.

2. As soon as you have the main device or an admin phone, remove the frozen computer (step 1).

If two admin computers freeze each other before learning of the other's freeze, both stay frozen
until the main device decides: run `sudo cbb unfreeze NAME` or `sudo cbb remove NAME` on the main
computer, or choose **Unfreeze** or **Remove** on the main phone.

## 3. If it was the main device: move the group

The **main device** holds the group's main key. If the main device is lost or broken, move the
group to another device that is already in the group using your group's **recovery key**—the
printed recovery sheet or the YubiKey you saved when you created the group.

Nobody can move the group without the recovery key, not even an admin. If you do not have the
recovery key, you cannot move the group: leave the old group on each remaining device (`sudo cbb
leave` or **Leave the group** in the app), create a new group, and pair your devices again.

### Move the group to a phone in the group

1. On another phone that is already in your group, open **CBB** and go to **Settings > Move the
   group to this phone**.
2. Provide the recovery key:
   - **Recovery sheet:** Scan the QR code on the sheet or type its text.
   - **YubiKey:** Hold the YubiKey to the phone (NFC) or plug it into the USB-C port (on Aurora
     OS, USB-C only), enter its PIN, and touch the YubiKey when prompted.
3. Review the list of devices in the group and untick the lost main device (and any other device
   you want to exclude).
4. Tap **Make this phone the main device** and confirm with your face, fingerprint, passcode, or
   (on Aurora OS) your admin PIN.

**Result:** This phone becomes the group's main device immediately with a new main key. Every
ticked device stays in the group and follows the new main device as soon as it connects; every
unticked device is excluded and refused by the group.

### Move the group to a computer in the group

1. On another computer in your group, open a terminal (as administrator on Windows) and run:
   - **With the recovery sheet:**

     ```sh
     sudo cbb recovery -leave LOST-DEVICE
     ```

   - **With a YubiKey** (requires `pcscd` on Linux and FreeBSD):

     ```sh
     sudo cbb recovery -yubikey -leave LOST-DEVICE
     ```

   Repeat `-leave NAME` for each device you want to exclude. You can also start this flow in the
   Mac app or tray app with **Move the group to this Mac** / **Move the group to this computer**.
2. Review who stays and who leaves, confirm, and then type the recovery key from the sheet on
   standard input (or enter the YubiKey's PIN and touch it when it blinks).

**Result:** The computer's service restarts as the group's new main device, keeps every listed
device, and refuses every excluded device. The computer discards the recovery key after the
change.

## 4. Turn off remote features if needed

Removing the lost device stops it from acting in your group. If you cannot remove it right away,
or want to lock down your remaining devices immediately, any admin can turn these features off
from another device:

| Feature | Command on an admin computer | In an admin phone app |
|---|---|---|
| [Remote paste](remote-paste.md) | `sudo cbb paste-receive off -on DEVICE` (or `-all`) | Open the device page and turn remote paste off |
| [Quick actions](quick-actions.md) | `sudo cbb action off -on DEVICE` (or `-all`) | Open the device page and tap **Turn all off** |
| [Sync away from home](away-from-home.md) | `sudo cbb global off -on DEVICE` | Open the device page and turn syncing away from home off |

**Result:** The affected devices disable those features immediately. Only each device's own user
can turn them back on locally.

## What a thief can access

What someone who steals your device can obtain depends on where that device stores its keys (see
[Keys and attestation](keys.md)):

- **Keys in hardware** (phones with a security chip, Macs with Apple silicon or a T2 chip, and
  Linux or Windows PCs with a TPM 2.0): The keys cannot be copied off the device. On phones, the
  main and admin keys sign only after your face, fingerprint, passcode, or (on Aurora OS) your
  admin PIN.
- **Keys in files** (Intel Macs without a T2 chip, Linux and Windows PCs without a TPM, FreeBSD,
  small devices, Aurora OS 4 and Sailfish OS phones, and rootless Linux installs): Anyone who can
  read the disk can copy the key files and impersonate that device until you remove it. Keep full-disk
  encryption enabled (FileVault, BitLocker, or LUKS).

Connect Beyond Borders keeps no clipboard history. Ordinary copies expire after the group's copy
lifetime (5 minutes by default), and secrets stay in memory only and expire after 60 seconds by
default.
