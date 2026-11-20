<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The apps

Copy Beyond Borders has apps for phones, watches and desktops. The phone apps hold the group;
the desktop apps are a window onto the service that already runs on the computer.

| App | Where to get it | State |
|---|---|---|
| Android | `cbb-X.Y.Z.apk` in each [release](https://github.com/HunterEwok/cbb/releases) | built and tested in CI, not yet on a real phone |
| Android without Google | `cbb-fdroid-X.Y.Z.apk`, and F-Droid once it is accepted: the same app without the Wear OS watch | built and tested in CI |
| iPhone and iPad | TestFlight, when it opens | built and tested in CI; runs on an iPhone built with a developer's own team |
| Wear OS | `cbb-wear-X.Y.Z.apk`, put on the watch from a computer with `adb install` over the watch's wireless debugging, until the app is on Google Play | built |
| Apple Watch | with the iPhone app | built; runs on an Apple Watch with the iPhone app |
| Mac app | not yet a download: built from `apps/macos` for now | built |
| Tray app for Linux and Windows | in the Windows and Linux archives of each release, installed with the service | built; run in a Windows 11 virtual machine |

## Phones

### Start a group

1. [Install](install.md) Copy Beyond Borders on a computer and run `sudo cbb pair` there. It
   shows a QR code.
2. Open the app and tap **Connect a new device**, then scan the code. The app makes the
   group's key in the phone's security chip (the Secure Enclave on an iPhone, the Keystore
   on Android), adds the computer and opens Home.
3. Add each further computer with **+** on Home. A small device joins the same way
   (`sudo -u cbb cbb pair` on it shows its code).

When the camera cannot be used: on an iPhone, type the six digits the computer shows; on
Android, paste the text of the QR code, which `cbb pair` prints too.

### Every day

- **Home** shows every device of the group, as tiles or a list, with a dot that says
  whether it is online. The big button takes a copy from another device that is still live
  (one minute by default; an admin changes it in Settings), and otherwise sends what the
  phone holds.
- **iPhone**: iOS lets an app use the clipboard only while it is in front, so the iPhone
  syncs with one gesture: the "Sync clipboard" action on Back Tap or the Action button, the
  Control Center control, or the home-screen widget. Share, Copy Beyond Borders sends a text
  or a link at once.
- **Android**: copies from the computers arrive by themselves. To send the phone's copies
  by themselves too, turn on **Send my copies by themselves** (an accessibility service;
  the app explains what it reads). Without it, one tap: the **Send clipboard** tile in Quick
  Settings, Send in the notification, the home-screen widget, or Share and text selection,
  Copy Beyond Borders.
- **Notifications** say when a device joins or is removed, becomes an admin, or the hub
  does not answer away from home. Each kind has its own switch in Settings.

### Devices

Tap a device to see its kind, system, version and role. On an admin phone you can also:

- **Rename** or **Remove** it; removing asks once, and then for your face, fingerprint or
  passcode. On Android each signature asks: adding the first computer asks five times (the
  group's own certificates, then the computer's), each further one twice, and each other
  action once; each prompt says which it is ("Signature 2 of 5"). When a computer's certificate needs renewing, or the group's keys for sync
  away from home, the app asks when you open it.
- **Make it an admin**, for a computer: it can then add and remove devices with
  `sudo cbb pair` and `sudo cbb remove`. Its key is a file on the computer, unless it is a
  Linux computer with a TPM, and the app warns you about that first; so choose a computer
  you trust, ideally one that is always on and also the [hub](away-from-home.md).

### A second phone, and a lost one

- **A second phone**: on it, tap **I already use Copy Beyond Borders on another phone**; it
  shows a QR code, which the first phone scans with **+**. The first phone, the root, makes
  it an admin, so that losing one phone loses nothing.
- **A lost phone**: on your other phone, remove it in the devices list. The computers stay
  in the group; if the lost phone was the root, the other phone takes the group over in the
  same step. More in [if a device is lost or stolen](lost-device.md).

### Settings

- **Sync away from home**: see [Away from home](away-from-home.md#3-turn-it-on-on-the-other-devices).
- **Theme**: ten colours, each dark and light, or the system's; on Android also the
  wallpaper's colours.
- **Language**: the system's, English or Russian.
- **Notifications**, one switch for each kind.
- **Show error details**: tap the version seven times to show this switch. With it on, an
  error shows its cause under the short message, which helps when you report a problem.

## Watches

The Apple Watch and Wear OS apps show the group's devices and whether they are online, the
latest events, and the switch for sync away from home. They work through the paired phone.

## Desktop apps

The Mac app and the tray app for Linux and Windows show the same things as the phone: the
devices as tiles, a list or orbits, a device's details, **Send the clipboard** and
**Fetch**, and the switch for sync away from home. Changes to the group (rename, remove,
make an admin) ask for the administrator's password. Adding a device still runs in the
terminal (`sudo cbb pair`). The service keeps syncing whether the app is open or not.

When something does not work, see [Troubleshooting](troubleshooting.md).
