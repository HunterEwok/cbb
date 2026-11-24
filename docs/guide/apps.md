<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The apps

For anyone using the Connect Beyond Borders apps on a phone, tablet, watch, TV, or computer. For
installing the background service on computers, routers, and servers, see
[Installing](install.md). For engineering details, see [App specification](../apps.md).

Connect Beyond Borders provides native apps for phones, tablets, watches, Android TV, and desktop
computers. Phone apps can hold the group's main key and manage devices; desktop apps provide a
window and menu icon over the background service running on that computer.

## Available apps

| App | Where to get it | Notes |
|---|---|---|
| **Android** (Android 10 or later) | `cbb-X.Y.Z.apk` in each [GitHub release](https://github.com/HunterEwok/cbb/releases) | Includes Wear OS watch support, self-updates, and push notifications |
| **Android without Google** (F-Droid build) | `cbb-fdroid-X.Y.Z.apk` in each [GitHub release](https://github.com/HunterEwok/cbb/releases) | Reproducible build with no Google Play services; uses UnifiedPush for closed-app notifications and omits Wear OS |
| **Android TV, Google TV, and Fire OS** | Same Android APK (`cbb-X.Y.Z.apk` or `cbb-fdroid-X.Y.Z.apk`) | D-pad interface; joins as a receive-only member |
| **iPhone and iPad** (iOS 17 or later) | TestFlight (when invited) or built from `apps/ios` with Xcode | Control Center switch requires iOS 18 or later |
| **Apple Watch** (watchOS 10 or later) | Bundled with the iPhone app | Works through the paired iPhone |
| **Wear OS** (Wear OS 3 or later) | `cbb-wear-X.Y.Z.apk` in each [GitHub release](https://github.com/HunterEwok/cbb/releases) (install with `adb install`) | Works through the paired Android phone (full build) |
| **Aurora OS and Sailfish OS** | Built from `apps/silica` (signed RPMs for Aurora OS 5.1.5) | Stores admin keys in OP-TEE behind an app PIN on Aurora 5; file keys on Aurora 4 and Sailfish OS |
| **HarmonyOS** (HarmonyOS 5 or later, phone, tablet, and watch) | Built from `apps/harmony` | Stores keys in HUKS; watch app works through the paired HarmonyOS phone |
| **Mac app** (macOS 14 or later) | `cbb-X.Y.Z.pkg` in each [GitHub release](https://github.com/HunterEwok/cbb/releases) | Menu bar app installed together with the background service |
| **Tray app for Linux and Windows** | Included in the Windows and Linux (x86-64, ARM64) release archives | Installed automatically with the service (requires GTK 4 and WebKitGTK 6.0 on Linux) |

For which apps have been tested on real hardware versus emulators and CI, see
[Platform parity](../parity.md#on-real-devices).

## Phones

### Start or join a group

When you open the app with no group configured, you have three choices:

- **Create a group:** The app creates the group's main key inside your phone's security hardware
  (Secure Enclave on iPhone, Keystore on Android, OP-TEE on Aurora OS 5, or HUKS on HarmonyOS)
  and asks you to confirm with your face, fingerprint, passcode, or (on Aurora OS) the app's own
  PIN. It then shows the group's **recovery key** once and offers **Write on a sheet**, **Write
  to YubiKey** (over NFC or USB-C where supported), or both. After you save it, the app opens the
  **Add a device** pairing window.
- **Join a group:** Scans the QR code shown by **Add a device** on an existing phone or admin
  computer on your home network, or lets you type its six digits. A phone always joins as a
  member; the main device can promote it to an admin afterward.
- **Join with an invitation:** Scans an invitation QR code, pastes its text, or opens an
  invitation file to join a group from away from home through the group's hub.

To add a device from **Home** on the main device or an admin phone, tap **+** and choose
**Add a device** (shows a QR code and six digits for five minutes) or **Send an invitation** (for
a device away from home).

### Everyday syncing

The **Home** screen shows how many devices are online alongside two switches:

- **Sync** (house icon): Tap to turn syncing off or on for this phone. Touch and hold to pause
  syncing for 15 minutes, 1 hour, 8 hours, or until you turn it back on. While sync is off, your
  clipboard stays private to this phone.
- **Everywhere** (globe icon): Turns syncing away from home on or off. While **Sync** is off,
  **Everywhere** waits until you turn **Sync** back on.

Under the header, **Home** shows any group notices, the latest copy received (with a **Copy**
button to put it back on your clipboard), and your group's devices as tiles or a list. Each
device tile shows its online status both as a dot and as text on its details page.

How copying and pasting work depends on your phone's operating system:

- **Opening the app (all phones):** When you open **CBB** or return to it from the background, it
  sends your clipboard if you copied something new; otherwise it pulls the group's latest copy.
  While the app stays open on screen, incoming copies enter your clipboard automatically.
- **iPhone:** iOS lets apps read the clipboard only in the foreground. On first setup, allow
  **Paste from Other Apps** in iOS Settings so iOS does not prompt each time (if you decline, a
  system paste button appears on **Home**). Outside the app, swap your clipboard with the group
  in one gesture using the **Sync clipboard** shortcut (assigned to Back Tap or the Action
  button) or the **Sync clipboard** home-screen widget. Use the **Sync** control in Control
  Center (iOS 18 or later) to toggle sync on or off. **Share → Connect Beyond Borders** queues
  text, links, images, or files (up to 50 MB together) and sends them the next time you open
  **CBB**. On iOS 17 or later, Dynamic Island and the Lock Screen show active pairing, tunnel
  connection time, and sync confirmation (never clipboard text).
- **Android:** Copies from your computers arrive on your phone's clipboard automatically in the
  background. To send copies from your phone automatically too, turn on **Clipboard sync** in
  **Settings** (an accessibility service; on Android 13 or later, APK installs require **Allow
  restricted settings** in App info first). Without **Clipboard sync**, send in one tap using:
  - **Send** in the ongoing CBB notification
  - The **Send clipboard** home-screen widget
  - **Share → Connect Beyond Borders** or the text selection menu (up to 100 MB for files)
  - The **cbb send** launcher entry (usable with Pixel Quick Tap or Samsung Back-Tap)
  - The **Sync** tile in Android Quick Settings toggles sync on or off (long-press to open the
    app).
- **Aurora OS and HarmonyOS:** Opening the app syncs as above. **Share → Connect Beyond Borders**
  sends text, images, and files (up to 50 MB together). Aurora OS shows status and quick sync
  actions on its app cover; HarmonyOS includes a home-screen widget and Live View status.

For images, formatted text, and where received files are saved, see
[Images, files and formatted text](images-and-files.md).

### Organizing devices

You can arrange your devices into custom order and group them into **collections** (for example,
"Office" or "Home"). Your layout and collections stay on that device only and are never shared
with the group or any server.

- Switch between **Tiles** and **List** (and **Orbit** on tablets and desktops) from the menu on
  **Home**.
- Start **Arrange devices** from the menu (or long-press a tile) to drag devices into order or
  drop them into collections, or use **Back to the group's order** to reset.
- When a group has more than 12 devices, **Home** displays a search bar and **Online** / **Needs
  attention** filters.

### Managing devices

Tap any device on **Home** to view its status, role, operating system, and Connect Beyond Borders
version, with extra technical details (device type, MAC address, device ID) under **More**.

If your phone is the main device or an admin, a device's page lets you:

- **Sync** or **Mute / Unmute:** Turn sync on or off on a connected computer, or mute any device
  for 15 minutes, 1 hour, 8 hours, or until an admin unmutes it (you can also mute directly from
  the corner button on a device tile).
- **Paste:** Send text, images, or files directly into the focused app on a computer that has
  remote paste enabled ([Remote paste](remote-paste.md)).
- **Quick actions:** Run allowed actions such as locking or sleeping a computer
  ([Quick actions](quick-actions.md)).
- **Rename:** Change the device's name across the whole group.
- **Make it an admin** (main device only): Let another phone or computer add and remove devices.
  Macs with Apple silicon or a T2 chip keep admin keys in the Secure Enclave, and Linux and
  Windows PCs with a TPM keep them in the TPM. If a computer keeps its keys in a file, the app
  warns you before promoting it ([Keys and attestation](keys.md#the-three-levels)).
- **Make it a hub:** Turn an admin computer into a hub for syncing away from home (a phone is
  never a hub).
- **Freeze / Unfreeze:** Freeze a stolen admin computer so nothing it signs counts until the main
  device unfreezes or removes it.
- **Remove:** Remove a device from the group immediately.

Every action that changes the group asks for your face, fingerprint, passcode, or (on Aurora OS)
your admin PIN. On Aurora OS 5, the phone's secure element enforces the PIN, and seven wrong PINs
lock the admin key permanently (the phone remains in the group as a member). On the main device,
the app also asks to renew the group's away-from-home server credentials every 30 days.

### A second phone and a lost phone

- **Add a second phone:** Tap **+** on your main phone, then tap **Join a group** on the second
  phone and scan the QR code. The second phone joins as a member. Open it on **Home** on your
  main phone and tap **Make it an admin** so you have a second admin phone.
- **If a phone is lost:** Remove it from **Home** on another admin phone. Your other devices stay
  in the group. If the lost phone was the **main device**, open **Settings > Move the group to
  this phone** on another device in the group, provide your recovery key (sheet or YubiKey), and
  leave the lost phone unticked so the group refuses it. See
  [If a device is lost](lost-device.md).

### Settings

Basic settings appear first on the **Settings** screen:

- **Appearance and theme:** Choose **System**, **Dark**, or **Light** appearance and one of
  **eleven themes** (Chalkboard, Blueprint, Precise, Glass, Soft, Swiss, Hardware, Art Deco,
  Liquid Glass, Terminal, and Retro). Android 12 and later also offer **Material You** (wallpaper
  colors); Aurora OS follows the system ambience.
- **Language:** Follow the system language or choose from eight languages: English, Chinese
  (Simplified), Spanish, Russian, Arabic, Swahili, Hebrew, and Hindi. Arabic and Hebrew lay out
  the interface right to left.
- **Notifications:** Turn individual switches on or off for devices joining or leaving, admin
  changes, freezes, main-device changes, and hub connection problems. On iPhone and Android,
  **Notify me when the app is closed** enables sealed push notices that wake the phone without
  revealing your copies.
- **Recovery key** (on the main device) or **Move the group to this phone** (on other phones).
- **Leave the group:** Deletes this phone's keys and group data while keeping your preferences.
- **About and error details:** Tap the **Version** row seven times to reveal **Show error
  details**, which displays the underlying cause beneath short error messages when reporting a
  problem. On Android (full release APK), **About** also includes update checks and automatic
  update settings.

Turn on **Advanced settings** to access:

- **Why it does not sync:** Explains in plain words why this device is not syncing and what to do
  next.
- **Away from home** and **Blind relay:** Shows tunnel status and lets the main device configure
  a blind relay for groups without a hub ([Away from home](away-from-home.md)).
- **Group** (admins only): Set **Copy lifetime** (1 minute to 1 hour; 5 minutes by default),
  **Secret lifetime** (5 seconds to 1 minute; 60 seconds by default), and **Admin keys** (the
  group's key level, on the main device).
- **Lab** (Android, Aurora OS, and HarmonyOS): Experimental features such as the Bluetooth
  keyboard ([The lab](lab.md)).

### Tablets and foldables

On wide screens—iPads, Android tablets, Aurora tablets, HarmonyOS tablets, and unfolded
foldables—the app automatically switches to a split view with a sidebar (sections for **All
devices**, **Needs attention**, collections, and settings), an **Orbit** layout option, a
side-by-side device details pane, keyboard shortcuts, and drag-and-drop (drop text or files onto
a device tile to remote paste, or beside the tiles to copy to the group). On a narrow window, such
as split-screen mode, it switches back to the phone layout.

### Android TV

Installing the Android APK on Android TV, Google TV, or Fire OS gives a D-pad-navigable
interface. A TV joins a group by typing the six-digit pairing code from an admin phone or
computer and runs as a receive-only member.

## Watches

The **Apple Watch**, **Wear OS**, and **HarmonyOS watch** apps work through their paired phone
and never hold your clipboard. Each watch app displays:

- How many devices are online and the device list (organized by your phone's collections)
- Recent group events
- Your phone's **Sync** (house) and **Everywhere** (globe) switches

## Desktop apps

The **Mac app** (menu bar) and the **tray app for Linux and Windows** (system tray) connect to
the background service already running on your computer. Your clipboard syncs automatically
whether the app window is open or closed, so there are no manual Send or Fetch buttons.

Both desktop apps provide:

- **System tray or menu bar icon:** Shows online device count, **Sync** (with pause durations),
  **Everywhere**, **Open CBB**, **Settings**, update notifications, and **Quit**.
- **Main window:** Displays devices as **Tiles**, a **List**, or **Orbit**, supports custom order
  and **collections**, shows group notices and alerts, and opens a device's details pane beside
  the list.
- **Onboarding and pairing:** When not in a group, offers **Create a group**, **Join a group**,
  **Join with an invitation**, and **Move the group to this computer** (using a recovery key).
  When in a group as an admin, **+** opens a pairing window (QR code and six digits) or sends an
  invitation.
- **Admin and hub controls:** Lets you rename, mute, freeze, remove, promote admins, configure
  the computer as a hub (including AmneziaWG, VLESS, and forwarder settings), and adjust group
  lifetimes and key levels. Actions that change the group ask for your administrator password or
  system confirmation (Touch ID, Windows Hello, or polkit).
- **Remote paste on macOS:** The Mac app acts as the remote paste receiver while open, once you
  grant it Accessibility permission in **System Settings > Privacy & Security > Accessibility**.
- **Settings:** Appearance, all eleven themes, eight languages, **Open at sign-in**, **Advanced
  settings** (including **Why it does not sync**), and **Show error details** (seven clicks on
  the version).

When something does not work as expected, see [Troubleshooting](troubleshooting.md).
