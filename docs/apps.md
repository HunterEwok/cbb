<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# App specification

For developers building and maintaining the Connect Beyond Borders apps (iPhone and iPad, Android,
Android TV, Aurora OS and Sailfish OS, HarmonyOS, Apple Watch, Wear OS, HarmonyOS watches, macOS,
and the Linux and Windows tray app). For end-user instructions, see [The apps](guide/apps.md). For
system architecture and the core ABI, see [Design](design.md) and
[The core's entry point](core-api.md). For real-device test coverage, see
[Platform parity](parity.md#on-real-devices). For planned work, see [Roadmap](roadmap.md).

## Principles

- **Only what is needed.** Create or join a group, pair devices, share the clipboard, inspect
  devices, and manage group roles and rules. No clipboard history, accounts, cloud storage, or
  telemetry.
- **Minimal interaction.** Everyday syncing runs automatically where the operating system allows it,
  and otherwise takes one tap or gesture (home-screen widgets, Shortcuts, Share sheets, Quick
  Settings, or Control Center). Adding a device uses a QR scan with a 6-digit fallback when no
  camera is available.
- **Shared visual system.** Eleven themes defined once in `apps/design/tokens.json` (default:
  **Chalkboard**) with monospaced type for codes, device IDs, and fingerprints, WCAG AA contrast
  (4.5:1) across every palette, and reduced motion honored across platforms.
- **Native UI layers over a shared core.** SwiftUI on iOS, watchOS, and macOS; Jetpack Compose on
  Android and Wear OS; Qt 5.6 and Silica QML on Aurora OS and Sailfish OS; ArkTS and ArkUI on
  HarmonyOS; and Go with Wails 3 (plain HTML, CSS, and JavaScript) for the Linux and Windows tray
  app. Every phone app links the same Rust core (`core/` through `ffi/`). Every desktop app talks to
  the local `cbb` service over its control socket. All apps support platform accessibility APIs
  (VoiceOver, TalkBack, font scaling, Dynamic Type, D-pad focus) and haptic feedback.

## Screens

In the user interface, the device that holds the group's root key is called the **main device**
(*root* in the protocol and command-line tools).

1. **Start** (no group configured). Shown on iPhone, Android, Aurora OS, and HarmonyOS:
   - **Settings and language:** iOS (`StartView.swift`) and Android (`Screens.kt`) show both the
     Settings button and the language menu on Start. Aurora OS (`MainPage.qml`) puts **Settings**
     in the pull-down menu, with language inside `SettingsPage.qml`. HarmonyOS (`Start.ets`) places
     language inside **Settings**.
   - **Create a group:** Calls the Rust core (`CorePairing.newGroup` on iOS and Android,
     `cbb_group_new` on Aurora OS and HarmonyOS) to generate a root key in hardware security storage
     (Secure Enclave on iPhone/iPad, StrongBox or TEE on Android, OP-TEE behind an app PIN on Aurora
     OS 5, HUKS on HarmonyOS; file keys on Aurora OS 4 and Sailfish OS). It displays the recovery
     key screen once (**Write on a sheet** and **Write to YubiKey**). On iOS and Android it opens
     the home pairing window behind the recovery sheet; on Aurora OS and HarmonyOS the user opens
     the pairing window from **Add a device**. Because the recovery key is part of the group ID,
     nothing replaces or removes it afterward; losing it prevents changing the main device, so
     recovery requires creating a new group (D-126).
   - **Join a group:** The new device always dials the admin's pairing window
     ([protocol.md](protocol.md), section 6, "The window and who dials"; D-119). On iOS and Android,
     **Join a group** opens the camera to scan the window's QR code and accepts a 6-digit code or
     pasted `cbb://pair?...` link. When the user types 6 digits, the app browses Bonjour (iOS) or
     NSD (Android) for `_cbb._tcp` records carrying `p=1`, `f`, and `i` (never the digits) and
     constructs the link with `Discovery.windowLink`. On Aurora OS and HarmonyOS, the Rust core
     discovers the window over mDNS; Aurora OS also accepts pasted links and HarmonyOS scans QR
     codes with Scan Kit. A wrong code joins no device and writes nothing; three failed attempts or
     one admitted device close the window.
   - **Join with an invitation:** For joining away from home through a group hub
     ([protocol.md](protocol.md), section 12). The user scans the invitation QR code, pastes its
     text, or opens an invitation file (up to 4096 bytes). A confirmation screen warns to join only
     requested invitations (invitations disclose no group, hub, or expiry before joining;
     [format.md](format.md), section 11.3) and offers **Join** or **Decline** (declining sends
     nothing). While joining, the phone shows its key fingerprint for the inviting admin to compare.
   - **Incompatible group directory:** If an app opens a state directory that lacks `group.cbor`
     (D-126), it shows a dedicated screen (`AlertsCard.swift` `Before06Card`, `Leave.kt`
     `Before06Screen`, `MainPage.qml`, `Before06.ets`) offering only **Leave the group**. Old files
     are deleted only when the user confirms leaving.
   - **Group state:** The device list, main-device role, and admin roles come from the member's
     `group` or `devices` operation ([core-api.md](core-api.md)). Joining phones join as ordinary
     members (on iOS and Android, `CorePairing.Joiner` does not pass an admin key during join).

2. **Home.** Displays the online device count, two header switches, any notices or alerts, the last
   received copy, and the group's devices as tiles or a list:
   - **Sync** (house icon): Tap toggles sync on this device; long press pauses sync for 15 minutes,
     1 hour, 8 hours, or until turned on again. When sync is off, the local clipboard stays private
     both ways. Sync mode is persisted in `mode`, and timed pause or mute expiries in `mute.json`
     ([design.md](design.md), "Sync on and off").
   - **Everywhere** (globe icon): Toggles syncing away from home. Turning it on prompts once for
     consent; while **Sync** is off, **Everywhere** waits in a disabled state.
   - **Opening-app sync rule (D-128):** Home has no manual Send button. On launch or return from the
     background (ignoring system sheets or screen rotation), the app sends the clipboard if it
     changed since the app last saw it, or fetches the group's current copy if not, without
     swapping. While the app stays in the foreground, incoming copies write to the clipboard
     automatically; in the background, no phone app writes to the clipboard (including Android,
     `LiveGroup.kt`).
   - **Last received copy:** A compact bar below notices shows the latest received copy, its sender,
     and a **Copy** button. Secrets hide their text and clear when their lifetime expires (D-129).
   - **Platform clipboard prompts:** On first Home launch on iOS, `PasteNote.swift` prompts once to
     trigger the system setting so **Settings > CBB > Paste from Other Apps** appears and can be set
     to **Allow**; if declined or unreadable, Home shows an icon-only system `PasteButton`. On
     Android, if automatic foreground reading fails, Home shows **Send what I copied**.
   - **One-tap triggers outside the app:**
     - **iOS:** The **Sync clipboard** App Intent (`SyncClipboardIntent`, available in Shortcuts,
       Spotlight, Back Tap, and Action button) runs without opening the app and fetches the latest
       copy (or sends text passed from Shortcuts' Get Clipboard action). The **Sync clipboard**
       home-screen widget (`SyncWidget`, iOS 18 and later) opens the app briefly to swap the
       clipboard. The **Sync** Control Center control (`SyncControl`, iOS 18 and later) toggles
       **Sync** when in a group (it has no long press and does nothing without a group).
       **Share > Connect Beyond Borders** (`ShareViewController.swift`) accepts text, links, images,
       or files up to 50 MiB, stores them in `ShareQueue` inside the `group.tools.cbb` app group,
       and sends them on the next foreground launch. Ad-hoc debug builds lack the app group
       entitlement, so their share extension reports no group.
     - **Android:** The **Send clipboard** home-screen widget (`SendWidget`), ongoing notification
       **Send** action, accessibility button/gesture, and **cbb send** launcher alias swap the
       clipboard through a brief transparent activity. The Quick Settings tile (`SyncTileService`)
       toggles **Sync** on tap (lit when on, struck through when off) and opens the app on long
       press or when not in a group.
     - **Aurora OS and HarmonyOS:** See [Notifications](#notifications) and
       [HarmonyOS](#harmonyos).
   - **Adding devices and single-admin hint:** On the main device or an admin phone, **+** opens
     **Add a device** (home pairing window) and its menu offers **Send an invitation**. When a group
     has only one admin, Home shows a dismissible **Lost a phone?** reminder card once.
   - **Group stops:** Conditions that halt sync (conflicting admins, two histories from one key,
     unreadable newer records) appear in [Why it does not sync](#why-it-does-not-sync).
   - **Muting a device** ([design.md](design.md), "Muting a device"): On an admin phone, a device's
     page offers **Mute** (15 minutes, 1 hour, 8 hours, or **Until an admin unmutes it**) for a
     connected device, or **Unmute** for a muted device—never both. Both sign a `mute` command after
     biometric, passcode, or PIN confirmation. A muted device keeps its copies local, and Home
     displays a banner until an admin unmutes it.
   - **Muting from the tile:** Each device tile includes a corner button (at the trailing end of the
     row, so on the left in Arabic and Hebrew) with a 28 pt/dp visual icon inside a 44 pt/dp touch
     target, while the rest of the tile opens the device card. On this device's own tile it toggles
     **Sync** (or pauses via long press / right click); on another device's tile (visible to admins)
     it mutes or unmutes that device for the group. On iOS and Android `MuteCorner` uses the speaker
     glyph on all tiles including this phone; on macOS, the tray app, and Aurora OS, this device's
     tile toggles its own sync switch. When muted, the button fills with the danger color and the
     tile border becomes dashed. The UI updates optimistically and reverts with an error only if the
     command fails. Aurora OS knows another device's mute state while that peer is connected.
   - **Images and files** ([design.md](design.md), "Images and files"): Copies up to 100 MiB sync to
     phones (larger copies stay on computers). Images are deduplicated by hash; iOS sends PNG, JPEG,
     or GIF (converting other formats such as HEIC to JPEG, or PNG when alpha is present). Received
     images enter the clipboard automatically while the app is open (through `FileProvider` on
     Android). Received files save once when the app is open:
     - **Android:** `Downloads/CBB` for files; `Pictures/CBB` or `Movies/CBB` via MediaStore for a
       single image or video. Share accepts up to 100 MiB.
     - **iPhone and iPad:** **Files > On My iPhone > CBB > Received** for files; **Photos**
       (Recents, using write-only `NSPhotoLibraryAddUsageDescription`) for a single image, video, or
       fetched clipboard image.
     - **Aurora OS:** `Downloads/CBB/<timestamp>` for files, `Pictures/CBB` for a single image (also
       copied to the clipboard), and `Videos/CBB` for a single video.
     - **HarmonyOS:** Single received image goes to the pasteboard; other files wait for the user to
       save through `DocumentViewPicker`.

3. **Add a device.** Opens a 5-minute pairing window on the main device or an admin phone
   (`PairingView.swift` / `AddDeviceView.swift`, `Pairing06.kt`, `WindowPage.qml`,
   `OpenWindow.ets`), showing a QR code and 6 digits while announcing `_cbb._tcp` (`p=1`, `f`, `i`)
   on the home network. The joining device scans the QR code or enters the 6 digits and joins
   directly without a second confirmation prompt.

4. **Devices** (tiles on Home and each device's detail card). Each tile shows the device glyph
   (laptop, computer, phone, tablet, TV, board, server, router, game console, watch, retro computer,
   or other; SF Symbols on Apple platforms, `FormGlyph` on Android), an online status dot, name, OS,
   and role/status marks (**This phone**, **main device**, **admin**, **hub**, **frozen**). Tapping
   a tile opens its detail card:
   - **Header and details:** Icon, name, online/offline status, badges (**main device**, **admin**,
     **hub**, **frozen**, plus **This phone** on iOS), OS and CBB version line, and a **More**
     section listing device type, MAC address, role, copy flags, standing, hub status, and device ID.
     (On Android, `LiveGroup.devices06` populates `osVersion`, `version`, `mac`, and `form` for
     this phone only.)
   - **Admin controls:**
     - **Sync switch** (house): Turns sync on or off on a connected computer by signing a `mode`
       command ([protocol.md](protocol.md), section 15).
     - **Mute / Unmute:** Signs a `mute` command.
     - **Paste on it…** ([design.md](design.md), "Remote paste"): Sends text (pasted or typed key by
       key, with optional Enter and secret flag) or picked images/files to a computer or small
       device by signing a `paste` command. On iOS, `PasteView.swift` reads `UIPasteboard.general`
       when the text field is left empty and offers `PhotosPicker` and `fileImporter` (up to
       100 MiB).
     - **Quick actions** ([protocol.md](protocol.md), section 15; iOS and Android): Lists the preset
       and user-defined actions enabled on an online computer; reboot and shutdown ask for a second
       confirmation. **Turn all off** signs `actions-off`.
     - **Overflow menu (`…`):** **Rename**, **Make it an admin** (main device only; warns when a
       computer stores its keys in files), **Make it a hub** (for eligible admin computers; a phone
       is never a hub, D-134; signs a `hub` command per [protocol.md](protocol.md), section 11,
       "Several hubs"), **Freeze** (for another admin computer), **Unfreeze** (main device only),
       and **Remove** (asks once, then requires biometric, passcode, or PIN confirmation). Moving
       the main-device role uses the recovery key rather than device removal.
   - **Non-admin view:** Displays device information without admin actions and states that only an
     admin can add or remove devices.

5. **Settings.** Organized into basic settings first and an **Advanced settings** switch for
   less common controls:
   - **Basic settings:** Appearance (**System**, **Dark**, **Light**) icons, language selector, and
     the **11 themes** (iOS and Android; Aurora OS follows system ambience and omits the theme
     selector), **Notifications**, **Apple Watch** / **Wear OS watch** (on main device when
     applicable), **Recovery key** (main device) or **Move the group to this phone** (other
     devices), **Advanced settings**, **Admin PIN** (Aurora OS 5; see
     [The admin PIN on Aurora](#the-admin-pin-on-aurora)), **Leave the group**, and **About**.
     Tapping the version row 7 times reveals **Show error details**, which prints the underlying
     error under each user-facing message (enabled by default in debug builds; overridden by launch
     argument `-ShowErrorDetails` on iOS, debug-only intent extra `ShowErrorDetails` on Android, and
     `CBB_ERROR_DETAILS` on Aurora OS).
   - **Advanced settings:** [Why it does not sync](#why-it-does-not-sync), **Away from home** and
     **Blind relay** (on Android, the Settings section shows **Blind relay** while away-from-home
     status appears on Home; on Aurora OS, Group and Blind relay stay visible outside **Advanced
     settings**), **Group** (admins: **Copy lifetime** and **Secret lifetime**, D-129; main device:
     **Admin keys**), and **Lab** (Android, Aurora OS, HarmonyOS). Brief inline tips explain complex
     settings until dismissed (`TipKit` on iOS).
   - **Away from home and blind relay:** The Rust member (`member/src/live/away.rs`) manages tunnel
     keys, hub offers, and blind relay connections in user space inside the app process, trying
     AmneziaWG over UDP before VLESS over HTTPS, and exposes state through `away_status`
     ([core-api.md](core-api.md)). The main device configures the group's blind relay (`relay`
     manage action) after displaying what a relay observes; other devices show the relay status
     read-only.
   - **Server credentials renewal:** Group server credentials rotate every 30 days
     ([protocol.md](protocol.md), section 18). On iOS and Android, the main device prompts to renew
     them on foreground launch (**Renew the group's keys for sync away from home**). On HarmonyOS,
     periodic `AppModel.duties()` checks 1 minute after start and every 6 hours. On Aurora OS,
     `RelayPage.qml` provides a renew button when credentials are due or expired.
   - **Remote invitations:** On an admin phone, **+ > Send an invitation** (or the pull-down menu on
     Aurora OS) creates a 1-hour single-use invitation through a connected hub
     ([protocol.md](protocol.md), section 12), displays its QR code, and shares `cbb.cbbinvite`
     (or copies the invitation text on Aurora OS and HarmonyOS) for `cbb pair -invite` on a
     computer. When a device connects, the app shows its fingerprint and asks **Admit …?** before
     signing admission.
   - **Leave the group** (D-83; [design.md](design.md), "Leaving the group"): Asks once, stops
     syncing, deletes all device keys, group files, and tunnel state, keeps UI preferences, and
     returns to **Start**. On iOS and Android, the main device can leave only when no other devices
     remain besides its watch; Aurora OS and HarmonyOS allow leaving after confirmation. When group
     records revoke this phone, Home displays **This phone was removed from the group** with the
     same leave button.

Errors appear inline as a single plain-language line with the next step rather than blocking modal
dialogs.

### Notices

The member produces a list of active group notices (`member/src/notices.rs`), exposed through
`notices` on phones ([core-api.md](core-api.md)) and `cbb status` on desktop apps. Home displays
each notice above the device list (under alerts on macOS and the tray app):

| Notice kind | Parameters | Dismissable | Meaning |
|---|---|---|---|
| `change_arriving` | none | no | A change of the group's main device is arriving. |
| `removals_waiting` | none | no | Removals are waiting until every admin confirms them. |
| `root_room_waiting` | `percent` | no | Shown on the main device when waiting removals fill 50% or more of its record room. |
| `ack_owed` | `removals`, `days_left` | no | This admin device has a removal to confirm on its next admin action. |
| `frozen_holding` | `device` | no | A frozen admin is holding removals back until unfrozen or removed. |
| `checkpoint_stuck` | none | no | A checkpoint is waiting for records that no peer has offered. |
| `returned_after_removal` | `device`, `devices` | yes | A device removed before a main-device change counts again and can be removed again. |

The phone apps also include UI text for `admins_silent` and `recovery_not_saved` if supplied.
Dismissable notices show a **Hide** button that sends `dismiss` over the member or control socket
without administrator elevation; non-dismissable notices stay until the condition clears. Unknown
notice kinds are ignored.

### Changing the main device

Only the group's recovery key changes the main device, and the change takes effect immediately. On a
non-main phone, **Settings > Move the group to this phone** accepts the recovery sheet (QR scan or
text entry) or a YubiKey holding the recovery secret; the key stays in memory only for this
operation.

The core previews the resulting device list (`change_preview`), labeling each device's outcome
(stays, stays an admin, loses admin rights, stays frozen, removed, or already removed). The user can
uncheck devices to remove them in the same operation; the previous main device starts unchecked. If
another main-device change is already arriving, the screen warns and requires an explicit toggle to
overwrite it. Biometric, passcode, or PIN confirmation signs the change (`change_root`). On Android,
the recovery and change-root dialogs set `SecureFlagPolicy.SecureOn` (`FLAG_SECURE`) to prevent
screenshots.

Every device in the group displays a notice naming the new and previous main devices until dismissed,
with a **This wasn't me** button that explains someone holds the recovery key and offers
**Leave the group**.

## Why it does not sync

Every app (iPhone, Android, Aurora OS, HarmonyOS, macOS, and the tray app) includes a
**Why it does not sync** screen under **Advanced settings** that displays the highest-priority
reason first in large type and secondary reasons below it. The Rust core computes all reasons in
`cbb_core::why` (`core/src/why.rs`), verified by `testdata/why/vectors.json`, returning a sorted
list of `{code, level, until_ms?, device?, devices?, value?, detail?}` objects. Desktop apps read
`why` from `cbb status`, phone apps call `why` (or `view.warnings`) on the member
([core-api.md](core-api.md)), and `cbb status` prints the first blocking reason. When **Show error
details** is on, each row also shows its code and `detail` text.

| Code | Level | Parameters | Meaning |
|---|---|---|---|
| `not_in_group` | `stop` | — | Device is not in a group. |
| `removed` | `stop` | — | Group records removed this device; leave and join again. |
| `recovery_fork` | `stop` | — | Recovery key signed two changes at one step; group halted permanently. |
| `root_two_histories` | `stop` | — | Main device key signed two histories; group waits for main device resolution or recovery. |
| `admins_conflict` | `stop` | — | Two admins conflict over a device; main device must resolve. |
| `owner_disagrees` | `stop` | `devices` | Peers follow a different main device; leave and join again. |
| `frozen` | `stop` | — | Group records froze this device's keys. |
| `nothing_here` | `stop` | — | Group records grant this device no clipboard exchange. |
| `stopped` | `stop` | — | Group records halted exchange until the main device decides. |
| `sync_off` | `stop` | `until_ms` | Sync is turned off locally (timed or indefinite). |
| `away_off` | `stop` | — | No group peer is on this network; turn **Everywhere** on. |
| `new_network` | `stop` | `devices` | Computer has not met its group on these interfaces (mark home via app button or `sudo cbb network`). |
| `no_hub` | `stop` | `detail` | **Everywhere** is on, but the group has no hub. |
| `tunnel_blocked` | `stop` | `device`, `detail` | Plain WireGuard tunnel to hub did not connect; network may block it. |
| `hub_unreachable` | `stop` | `device`, `detail` | Hub did not answer even with an obfuscated tunnel. |
| `relay_down` | `stop` | `detail` | Blind relay did not answer. |
| `hub_waiting` | `stop` | `detail` | This device is the active hub and no peer has connected yet. |
| `alone` | `stop` | `detail` | Connected to hub or relay, but no other group device is online. |
| `secrets_stopped` | `warn` | — | Group stopped sending secrets until the main device decides. |
| `no_secrets_here` | `warn` | — | Group does not seal secrets to this device. |
| `change_arriving` | `warn` | — | Main-device change records are still arriving from peers. |
| `checkpoint_stuck` | `warn` | — | Root checkpoint is waiting for records no peer has offered. |
| `muted` | `warn` | `until_ms` | An admin muted this device; local copies do not reach the group. |
| `forwarder_down` | `warn` | `detail` | Hub's forwarder rejected or missed registration. |
| `entries_stale` | `warn` | `detail` | Forwarder entry-point list is out of date. |
| `newer` | `warn` or `stop` | `value` | Group holds records or settings from a newer version (`stop` when `update_needed` is set). |
| `unreached` | `warn` | `devices` | Home peers cannot connect inbound to this computer (firewall). |
| `only_device` | `info` | — | Only device in the group; add another phone or computer. |
| `copy_waits` | `info` | `devices` | Copies are waiting for their senders' device records. |
| `devices_offline` | `info` | `devices` | Listed peers are offline (shown only while at least one peer is connected). |
| `devices_sync_off` | `info` | `devices` | Listed peers have sync turned off. |
| `devices_muted` | `info` | `devices` | Listed peers are muted. |
| `update` | `info` | `value` | A newer CBB release is available. |

## The lab

Experimental features—the ZX Spectrum Next bridge, Arduino Nano ESP32 firmware, network TV remotes
from computers, and Bluetooth keyboard emulation on Linux, Android, Aurora OS, and HarmonyOS—sit
outside the core 1.0 guarantee. In the phone apps that support Bluetooth keyboard emulation
(Android, Aurora OS, HarmonyOS), its screen lives in a **Lab** section at the bottom of
**Advanced settings**. On macOS and the tray app, non-hub hub controls and hub tunnel/forwarder
settings are also gated behind **Advanced settings**.

## Big screens

Layout adapts to window width, independent of device class or group rights. Group rights follow key
protection ([design.md](design.md)): a key in security hardware paired with strong biometrics earns
phone-level trust; without both, the device warns before creating a group.

- **iPad** (universal binary, `apps/ios/CBB/Views/PadHome.swift`): An iPad has the same hardware key
  protection and rights as an iPhone (Secure Enclave). On Start under **Create a group**, it notes
  that the main device is best kept on a device always at hand, such as a phone. In a regular-width
  window, Home uses a split view:
  - **Sidebar** (280–400 pt, 320 pt default): Group header with online count and **Sync** /
    **Everywhere** switches (wrapping below the count via `ViewThatFits` when narrow); **Devices**
    (**All devices**, **Needs attention** when any device is frozen, and each collection with its
    count and rename/ungroup context menu); and **Settings** (Appearance, Notifications, Recovery
    key, Away from home [status and blind relay], Group rules for admins, Why it does not sync, and
    About with Leave). Each settings section opens directly in the detail column without an
    **Advanced settings** switch. Below 1100 pt window width, the sidebar collapses behind its
    toggle button; **+** always resides in the detail toolbar.
  - **Devices column and detail pane:** Notices and last received copy above tiles (default), list,
    or orbit (orbit for **All devices** only), with toolbar search. Selecting a device opens its
    card on the trailing edge at 400 pt (scaling with Dynamic Type up to 520 pt) and outlines the
    selected tile. When less than 360 pt remains for the device list, the card pushes as a separate
    page. Switching sidebar sections closes the detail card.
  - **Keyboard:** `Command-1` through `Command-9` select sidebar sections in order, `Command-,`
    opens Settings, `Command-N` adds a device, arrow keys move selection, and `Escape` closes the
    detail card.
  - **Pointer and drag-and-drop:** Tiles lift on hover; right-click or touch-and-hold opens a
    context menu with remote paste, mute/unmute (for admins), and arrangement actions. Dropping
    text, an image, or files onto a tile that accepts remote paste pastes them there (for admins);
    dropping text or an image beside tiles copies it to the group.
  - **Narrow windows and platform limits:** Compact widths (Slide Over, split screen) switch to the
    phone layout. Start and Join constrain content to 560 pt (`Tokens.readableWidth`). The iPad app
    is single-window (`UIApplicationSupportsMultipleScenes: false`), disabled on macOS and visionOS,
    omits Apple Watch settings, and does not accept incoming remote pastes.
- **Foldable iPhone:** Uses the phone layout on compact screens (locked portrait in
  `Orientation.swift`) and the split-view layout on regular-width screens (rotating freely).
- **Android tablets, foldables, and wide windows** (`apps/android/app/src/main/kotlin/tools/cbb/TabletHome.kt`):
  Switches to the wide layout at 600 dp (`screenWidthDp >= 600`).
  - **Sidebar** (300 dp, scaling up to 1.3× with font scale): Group header and switches; **Devices**
    (**All devices**, **Needs attention**, collections with counts); **Settings** (Appearance,
    Notifications [with auto-send and watch], Recovery key [or Move the group on non-main devices],
    Away from home [blind relay], **Send to the computers** [Share allow-list and Lab Bluetooth
    keyboard], Group [lifetimes, admin keys, leave], Why it does not sync, and About [with updates]).
    The sidebar stays pinned when the window fits sidebar + 360 dp + detail pane; otherwise it opens
    as a drawer behind `☰`. A footer lists keyboard shortcuts.
  - **Devices column and detail pane:** Defaults to **Orbit** (`DeviceLayout.ORBIT`, switchable via
    `⋯` to tiles or list; orbit for **All devices** only), with **+** beside it for admins.
    Selecting a device opens a 400 dp detail pane (scaling up to 520 dp) on the trailing edge when
    at least 360 dp remains for devices, or as a separate page otherwise.
  - **Keyboard, pointer, and drag-and-drop:** `Ctrl+1` through `Ctrl+9` (or `Meta+1..9`),
    `Ctrl+,`, `Ctrl+N` (admin), `Ctrl+F` (when search is active, over 12 devices), arrows, and
    `Esc`. Right-click or long-press opens the tile menu (paste, mute/unmute, arrange). Dragging
    text, images, or files onto a paste-capable tile sends remote paste; dropping beside tiles sends
    to the group.
  - **Key-guard check (`Keys.guardsLikeAPhone`):** Requires both hardware-backed keys (StrongBox or
    TEE) and a strong biometric sensor (`BIOMETRIC_STRONG`, enrolled or unenrolled). On Start under
    **Create a group**, devices lacking either warn that they guard the group less well than a phone
    with both; wide devices with both show the same always-at-hand note as iPad.
  - **Device icons:** Drawn on a 24×24 grid by `DeviceGlyph` (`DeviceKind.kt`) delegating to
    `FormGlyph` (`apps/android/shared/src/main/kotlin/tools/cbb/Glyph.kt`).
- **Aurora tablets and landscape phones** (`apps/silica/qml/pages/MainPage.qml`): Width thresholds
  are measured in `Theme.pixelRatio` units. At 760 units and wider, `DeviceCard.qml` (400 units
  wide, with a header close button and **Close** pull-down action) stands at the trailing edge beside
  the tiles. At 1060 units and wider, a 300-unit sidebar (**All devices**, **Needs attention**,
  collections, and **Settings** pushing `SettingsPage.qml`) appears on the leading edge. Because
  Aurora OS exposes no biometric API to regular apps, `NewGroupPage.qml` always displays the
  key-guard note. Silica provides no keyboard shortcuts or drag-and-drop.
- **HarmonyOS tablets and foldables** (`apps/harmony/entry/src/main/ets/pages/Main.ets`): Switches
  to the wide layout at 720 vp, with tiles, list, or orbit (`Orbit.ets`, for **All devices** only)
  and a 400 vp `DeviceDetail` pane on the trailing edge. Folding below 720 vp clears the selection
  and returns to the phone layout.
  - **Sidebar** (280 vp `SideBarContainer`): Pinned (`Embed`) from 1040 vp and sliding (`Overlay`
    behind `☰`) below 1040 vp. Lists **Devices** (**All devices**, **Needs attention**, collections)
    and **Settings** (Language, Notifications, Recovery key [main device] or Move the group [other
    devices], Blind relay, Group, Lab, Why it does not sync, and About [including 7-tap **Show error
    details**]), opening each section in `components/SettingsBody.ets`. A footer shows keyboard
    shortcuts.
  - **Keyboard, pointer, and drag-and-drop:** `Ctrl+1` through `Ctrl+9`, `Ctrl+,`, `Ctrl+N`
    (admin), arrow keys, and `Esc`. Right-click opens an action sheet (paste, mute/unmute, arrange);
    long-press opens Arrange. Drag-and-drop pastes onto a paste-capable tile or copies to the group
    beside tiles.
  - **Key-guard check (`Keys.guardsLikeAPhone`):** HUKS stores keys in the TEE, so a fingerprint or
    face sensor at ATL3 (enrolled or unenrolled) satisfies phone-level protection. `Start.ets` shows
    the warning when missing, or the always-at-hand note at 600 vp and wider when present.

## Dynamic Island

Live Activities on iPhone (iOS 18 and later, inside the `Widgets` extension in `apps/ios/Widgets/`)
and Live View on HarmonyOS (`apps/harmony/entry/src/main/ets/model/Live.ets`) surface active
operations in the Dynamic Island or Live View and on the Lock Screen using the dark theme palette:

- **Away from home:** Shield icon and elapsed timer while connected through a group hub's tunnel
  (iOS and HarmonyOS).
- **Sync result:** Displays the sync outcome for 4 seconds on iOS (`Island.flash`) and briefly on
  HarmonyOS (`Live.synced`). On iOS, `AppModel.sync` triggered from the app passes a 30-character
  text preview for non-secret copies, whereas Shortcut syncs omit the preview.
- **Adding a device:** Active on HarmonyOS (`Live.ets` displays a timer and completion status). On
  iOS, `StatusActivity.Kind.adding` is defined in `StatusActivity.swift` and rendered by
  `StatusActivityWidget.swift`, though the app does not currently trigger it.

## Notifications

Phone apps detect group changes by comparing the current device list against the previously stored
snapshot, posting local notifications for each enabled event kind (all enabled by default):

- **iPhone** (`apps/ios/CBB/App/GroupEvents.swift` `GroupEvent` / `Notifier`, `PushSetup.swift`,
  `BackgroundRefresh.swift`, `apps/ios/NotificationService/NotificationService.swift`): Five event
  switches—devices joined or removed, admin changes, freezes or unfreezes, main-device changes
  (`takeover`), and hub unreachable for 2 minutes (`Notifier.hubGrace = .seconds(120)`). With
  **Notify me when the app is closed** enabled (default in release builds carrying the app group),
  group peers wake the phone through a sealed push decrypted in `NotificationService` via
  `PushVault` (showing up to 300 characters with a **Copy** action for ordinary text, never secrets,
  or an event notice). Otherwise, `BackgroundRefresh` requests iOS `BGAppRefreshTask` (`tools.cbb.refresh`),
  waiting up to 20 seconds for an online peer plus 3 seconds for records without touching the
  clipboard. Release builds request notification permission at launch through `PushSetup.start()`;
  otherwise `Notifier.askOnce()` asks when first joining a group.
- **Android** (`apps/android/app/src/main/kotlin/tools/cbb/GroupEvents.kt`, `SyncService.kt`,
  `PushSetup.kt`, `PushPlatform.kt`): Same 5 switches and 7 events (sorted by name, removals last,
  2-minute hub grace) posted on channel `"The group's events"`. The foreground service (`SyncService`,
  type `connectedDevice`) keeps group connections alive in the background so events arrive
  immediately, acquiring a `WifiManager.MulticastLock` only during mDNS browsing. Closed-app sealed
  push runs on channel `"While the app is closed"` with a **Copy** action (`PushCopyReceiver`),
  using Firebase Cloud Messaging in the `full` flavor (`src/full/.../PushPlatform.kt`) and
  UnifiedPush in the `fdroid` flavor (`src/fdroid/.../PushPlatform.kt`).
- **Aurora OS** (`apps/silica/src/events.cpp`, `qml/system/Notifier.qml`, `qml/cover/CoverPage.qml`,
  `qml/system/ShareTarget.qml`): Watches `Member::devicesChanged` while the app or its cover runs
  and notifies through `Nemo.Notifications` for 4 event kinds (devices joined or removed, admin
  changes, freezes or unfreezes, main-device changes; it does not implement the 2-minute hub-unreachable
  event). The app cover displays sync/mute state, connected device count, last copy, and latest
  event, with **one** cover action to pause or resume sync. System sharing (`ShareProvider`,
  `X-Share Method text` and `X-Share Method files`) sends text, images, and files up to 50 MiB.
  Opening the app applies the opening rule (D-128) via the core's `opened` and `took` calls against
  a stored clipboard SHA-256 hash (`board/seen`). Incoming copies write to the clipboard only while
  `ApplicationActive`; single images save to `Pictures/CBB` (and clipboard), single videos to
  `Videos/CBB`, and other files to `Downloads/CBB/<timestamp>` with a notification.

## Apple Watch

The Apple Watch app (`apps/ios/Watch`, watchOS 10) has no direct network sockets and communicates
solely with its paired iPhone over WatchConnectivity (`WatchLink` on iPhone, `WatchModel` on watch).
Using the phone's dark theme palette, it displays:

- Online device count and each device with its icon and live status dot (grouped by the phone's
  collections).
- The phone's **Sync** (house) and **Everywhere** (globe) switches, plus away-from-home status.
- Recent group events.

The phone pushes `WatchState` (`hasGroup`, `group`, `devices`, `away`, `sync`, `events`, `signs`,
`theme`; never the clipboard) whenever state changes. The watch caches the latest state and reports
when the iPhone is unreachable. Group notifications mirror from the iPhone automatically.

`WatchKey` (`apps/ios/Watch/WatchKey.swift`) supports generating an unlocked-only Secure Enclave
P-256 key guarded by `LAPolicy.deviceOwnerAuthenticationWithWristDetection`, and `LiveGroup`
exposes the watch management hooks (`addWatch`, `watchActions`, `watchBody`). In the current
implementation, wrist signing is disabled (D-124): the phone sets `WatchState.signs = false` and
omits watch actions, so the watch operates as a read-and-toggle companion (see
[Roadmap](roadmap.md)). When the phone leaves its group or joins a different group, `WatchModel`
deletes any stored watch admin key.

## Wear OS

The Wear OS app (`apps/android/wear`, Wear OS 3 / `minSdk = 30`, Compose for Wear OS) is the
counterpart to the Apple Watch app and communicates only with its paired Android phone over the
Google Play services Wearable Data Layer:

- **State sync:** `WatchLink` (`apps/android/app/src/full/kotlin/tools/cbb/WatchLink.kt`) writes
  `WatchState` (`apps/android/shared`: `hasGroup`, `group`, `devices`, `away`, `sync`, `events`,
  `signs`, `theme`, and error-detail flag; never the clipboard) to data item `/cbb/state`.
- **Switch commands:** The watch sends `/cbb/sync` and `/cbb/away` (`1` or `0`) to `WatchListener`
  on the phone, which toggles the corresponding switch and publishes the updated `/cbb/state`.
- **Shared module and signing:** The phone and watch share application ID `tools.cbb`, the same
  signing key, and `apps/android/shared` (design tokens, device glyphs, `WatchState`).
- **Admin key hooks:** `WearListener` and `WatchKey` implement the Data Layer paths (`/cbb/certify`,
  `/cbb/key`, `/cbb/admitted`, `/cbb/ask`, `/cbb/body`, `/cbb/signed`, `/cbb/done`) with an
  unlocked-only Keystore P-256 key requiring a secure lock screen. As on Apple Watch, wrist signing
  is disabled in the current build (`signs = false`, D-124; see [Roadmap](roadmap.md)).

Group notifications mirror from the Android phone through standard Android notification bridging.

## The Mac app

The Mac app (`apps/macos`, SwiftUI, macOS 14 and later) provides a menu bar item and management
window over the background `cbb` service installed by the `.pkg` installer or Homebrew. The service
and pasteboard agent continue syncing when the app is closed. The app connects to the service's
control socket (`Control.swift`, JSON header line plus payload, as a member of the `_cbb` group) and
polls status and devices every 4 seconds.

- **Menu bar item (`CBBMacApp.swift`, `SettingsView.swift`):** Runs without a Dock icon
  (`LSUIElement: true`). Shows online device count, **Sync** (checkmark with pause-duration
  submenu), **Everywhere** (turning it on opens the window for consent), **Open CBB**, **Settings**,
  any available update, and **Quit**. Uses template SVG images generated by `tools/icon` in three
  states (no group or problem, in group, another device online). Registers as a login item on first
  launch via `SMAppService.mainApp`, toggled by **Open at sign-in**. Launches with no window when
  already in a group, and opens the main window automatically once if not in a group.
- **Start window:** When not in a group, offers **Create a group** (`cbb new`), **Join a group**
  (`JoinSheet.swift`, `cbb pair -code`), **Join with an invitation** (`JoinInviteSheet.swift`,
  `cbb pair -invite - -app FILE` showing this Mac's fingerprint from the status JSON file while
  joining), and **Recovery key**.
- **Main window (`MainView.swift`, `Switches.swift`, `OrbitView.swift`):** Group header with
  **Sync** (direct control socket `sync`, click toggles, hold opens pause durations) and
  **Everywhere** (`cbb global`), update banner, alerts card (`GroupAlerts.swift`: stops, conflicts
  with `cbb resolve` / `cbb remove` on main device, local mute banner, newer records), group notices
  with **Hide** (`dismiss` over the control socket), crash bug-report prompt (`BugSheet.swift`),
  and devices as tiles, list, or orbit around this Mac. A detail pane opens beside the list; search
  and filters appear with more than 12 other devices. Every tile includes the corner mute/sync
  button (`MuteCorner`).
- **Device card (`DeviceDetail.swift`):** Shows name, online dot, badges (**This Mac**, **main
  device**, **admin**, **hub**, **frozen**), OS and CBB version, **Sync** switch (`cbb sync -on` on
  admins for remote computers), **Mute** / **Unmute** (direct control socket `mute`/`unmute` for
  this Mac; `cbb mute -on` / `cbb unmute -on` for other devices), and **More** (type, MAC address,
  role, copies, standing, away/hub status, last seen, device ID).
- **Hub controls:** On a hub device, the card shows **This is the group's hub** and **Stop being the
  hub** (`cbb global hub off -yes`, with `-on <id>` for another device). When **Advanced settings**
  is enabled (or on an existing hub), non-hub cards show the hub line: **Make it a hub**
  (`cbb global hub -firewall no` with `-away-on` if away sync is off on this Mac; or
  `cbb global hub -on <id>` for another admin computer, or `-forward-only` for a non-admin,
  non-rootless computer with the `hub` capability). On non-admin Macs, the hub line appears only on
  this Mac's own card. Tunnel obfuscation (WireGuard, AmneziaWG, VLESS) and forwarder settings
  (`cbb global hub -keep -firewall no`) appear on this Mac's card when it is a hub and **Advanced
  settings** is enabled.
- **Pairing and invitations (`AddDeviceSheet.swift`, `InviteSheet.swift`):** On an admin Mac, **+**
  runs `cbb pair -app FILE` (or with `-admin` on the main device) and displays the QR code and 6
  digits read from the JSON file (`code`, `qr`, `address`, `expires`, `refused`, `done`, `name`);
  closing removes the file and closes the window. **Device far away? Send an invitation** runs
  `cbb invite -for 1h -app FILE -answers FILE`, displays the QR code and text, prompts with the
  joiner's fingerprint, and writes the decision to the answers file.
- **Settings (`SettingsView.swift`):** Sheet (opened from menu bar or `Command-,`) with appearance
  icons, **11 themes** (shared `Theme.swift` and `Tokens.swift`), language (`AppleLanguages`, applied
  on reopen), **Open at sign-in**, **Advanced settings** (Why it does not sync, remote paste
  permission status, **Move the group to this Mac** via `cbb recovery -leave … -yubikey`, and for
  admins **Copy lifetime**, **Secret lifetime** [`cbb ttl`], and **Admin keys** [`cbb keys`]), and
  **About** (7 clicks reveal **Show error details**, also controlled by `ShowErrorDetails` default
  and passed as `CBB_DEBUG=1`).
- **Privilege confirmation (`Admin.swift`):** Runs `cbb` as the regular user first for group
  operations so the service prompts via Touch ID or macOS password confirmation; invokes `osascript`
  (`do shell script … with administrator privileges`) only for operations that require root
  (`update`, `pair -code`, `pair -invite`) or when `cbb` exits with code `77` (`needsAdminExit`).
  Exit code `75` is treated as user cancellation.
- **Remote paste (`PasteTarget.swift`):** Because macOS restricts synthetic input to GUI apps with
  Accessibility permission, the Mac app serves as the remote-paste target while open, keeping a
  `watch` connection with `inject: "desktop"`, `paste_only: true`, `images: true`, `files: true`,
  and `html: true` ([protocol.md](protocol.md), section 8). Text pastes write through the pasteboard
  tagged `org.nspasteboard.TransientType` (and `org.nspasteboard.ConcealedType` for secrets), press
  `Cmd+V`, and restore prior non-Universal-Clipboard items after 0.5 seconds unless `changeCount`
  advanced. Typing posts layout-independent Unicode key events. Media pastes (`paste_media`) write
  files into `Caches/Pasted/<UUID>` (cleaned after 600 s) with `com.apple.quarantine` before pasting
  without restoring the pasteboard. Refuses input without Accessibility permission, on a locked
  screen, in a background session, or under Secure Event Input.

Each release packages the Mac app inside the Developer ID-signed and notarized `cbb-X.Y.Z.pkg`
([maintaining.md](maintainers/maintaining.md#signing-for-macos)). CI builds and tests it ad hoc in
the `test and build (macOS), homebrew, Mac app` job.

## The tray app

The tray app (`apps/desktop`, binary `cbb-desktop`) is the Linux and Windows counterpart to the Mac
app: a standalone Go module built with [Wails 3](https://v3.wails.io) (pinned to a Wails 3 nightly
in `apps/desktop/go.mod`; GTK 4 and WebKitGTK 6.0 on Linux, WebView2 on Windows). It talks to the
local service over the control socket via `internal/control`, while the background service and
clipboard agent keep syncing independently.

- **Window (`frontend/`):** Plain HTML, CSS, and JavaScript with no build step. Displays the group
  header with **Sync** (direct control socket `OpSync`; click toggles, hold or right-click picks
  pause durations) and **Everywhere** (`cbb global`), update banner, alerts card, group notices with
  **Dismiss**, crash bug-report dialog, and devices as tiles, list, or orbit beside a device detail
  card. Opens automatically on startup when not in a group (`Start` screen: **Create a group**,
  **Join a group**, **Join with an invitation**, **Recovery key**); closing the window hides it to
  the tray, and launching `cbb-desktop` again reopens the window. Search and filters appear with
  more than 12 other devices.
- **Device card and tiles (`frontend/app.js`):** Shows name, online dot, badges (**This computer**,
  **main device**, **admin**, **hub**, **frozen**), OS and CBB version, **Sync** switch, **Mute** /
  **Unmute** (direct control socket for this computer; `cbb mute -on` / `cbb unmute -on` for other
  devices), **More**, and hub controls (non-hub hub line and tunnel/forwarder controls appear when
  **Advanced settings** is enabled; supports forward-only hubs via `MakeHub` /
  `cbb global hub -on <id> -forward-only`). Every tile has the corner mute/sync button
  (`muteCorner`) and is draggable at all times (`draggable="true"`); holding 600 ms without moving
  or right-clicking opens `#tile-menu`.
- **Tray item (`desk.go`, `trayicon*.go`):** Shows online device count, **Sync** (with pause
  submenu), **Everywhere**, **Open CBB**, **Settings**, available update, and **Quit**. Uses the
  three-state single-color glyph generated by `tools/icon`: black and white `.ico` files on Windows
  (switched automatically with taskbar theme) and white or black 48 px `.png` files on Linux
  (selected once at startup from the desktop portal's `org.freedesktop.appearance` `color-scheme`).
- **Settings (`frontend/app.js`, `desk.go`):** Stored in `<UserConfigDir>/cbb/desktop.json`.
  Includes appearance icons, language selector (English plus `frontend/l10n/`), **11 themes**
  (`frontend/tokens.js`), **Open at sign-in** (`cbb-tray.desktop` with `Hidden=true` in the user's
  autostart directory on Linux; `StartupApproved\Run` `"cbb tray"` on Windows), **Advanced
  settings** (Why it does not sync, hub and tunnel settings on this computer's card, **Move the
  group to this computer** via `cbb recovery -leave … -yubikey`, and for admins **Copy lifetime**,
  **Secret lifetime** [`cbb ttl`], and **Admin keys** [`cbb keys`]), and **About** (7 clicks reveal
  **Show error details**, matching `CBB_DEBUG=1`/`0` or non-release builds).
- **Privilege confirmation (`admin.go`, `admin_linux.go`, `admin_windows.go`):** Runs `cbb` as the
  regular user first (`userConfirms = true`) so the service confirms through polkit (Linux) or
  Windows Hello (Windows). Falls back to administrator elevation—`pkexec` without a shell on Linux,
  or elevated PowerShell via `ShellExecuteExW` `runas` with single-quoted literal arguments and a
  temp output file on Windows—only for commands that require root (`update`, `pair -app`) or when
  `cbb` exits `77` (`needsAdminExit`). A dismissed prompt changes nothing silently.
- **Pairing and invitations (`admit.go`, `invite.go`, `join.go`):** **Add a device** (`+`) runs
  `cbb pair -app FILE` (or with `-admin` on main device) and reads the status JSON (`code`, `qr`,
  `address`, `expires`, `refused`, `done`, `name`); on Linux `cbb` overwrites the pre-created file
  with `O_NOFOLLOW` without creating files in `/tmp`. **Send an invitation** runs
  `cbb invite -for 1h -app FILE -answers FILE`. **Join a group** runs `cbb pair -code`, and
  **Join with an invitation** runs `cbb pair -invite - -app FILE`.

CI vets, tests, and builds `cbb-desktop` in the `tray app` jobs on Linux and Windows. Windows
releases bundle `cbb-desktop.exe` (built without cgo); `install.ps1` adds the `cbb tray` Run entry
and a Start menu shortcut. Linux amd64 and arm64 releases bundle `cbb-desktop`; `install.sh` checks
GTK 4 and WebKitGTK 6.0 via `ldd`, installing desktop and autostart entries when present or printing
the required packages otherwise.

## Android: the clipboard without taps

Android 10 and later restrict clipboard reads to the app holding input focus (or the default IME),
while clipboard writes are permitted at any time.

**Receiving.** A foreground service (`SyncService.kt`, type `connectedDevice`, with an ongoing
notification) maintains connections to group peers and acquires a multicast lock only during mDNS
browsing. Incoming copies update `lastReceived` in the background and are written to the Android
clipboard when the app is in the foreground (D-128).

**Automatic sending: "Clipboard sync" (`CopyWatcher.kt`).** An optional accessibility service enabled
by the user from Settings:

1. Watches for `TYPE_VIEW_CLICKED` events matching platform and common app "Copy" labels across
   system languages, and on Android 13 and later watches `TYPE_WINDOWS_CHANGED` for the system
   clipboard overlay window.
2. Shows a 1-pixel `TYPE_ACCESSIBILITY_OVERLAY` window briefly to gain input focus (falling back to
   a non-exported transparent `SendActivity` after 700 ms), reads the clipboard, and sends it to the
   group. Copies marked `android.content.extra.IS_SENSITIVE` (password managers and received
   secrets) are skipped automatically, while manual taps still send them.
3. On Android 12 and later, the system displays "CBB pasted from your clipboard" on each read.

Permissions declared in `apps/android/app/src/main/res/xml/accessibility_copy.xml`:

- `typeViewClicked`: Detects clicks on "Copy" actions by reading only the clicked element's label.
- `typeWindowsChanged` with `flagRetrieveInteractiveWindows`: Checks window titles for the system
  clipboard overlay.
- `flagRequestAccessibilityButton`: Registers the system accessibility button or gesture to trigger
  a clipboard swap.
- `canRetrieveWindowContent="true"`: Declared in the service configuration; `CopyWatcher.kt` does
  not inspect screen fields or perform remote paste (phones do not receive remote paste, D-132).
- No package filter: Copying occurs in any app.

On Android 13 and later, APKs installed outside an app store require **App info > ⋮ > Allow
restricted settings** before Android lets the user enable an accessibility service. The setup screen
(`AutoSend` in `Screens.kt`) shows this guidance and an **App info** button on Android 13 and later.

**One-tap sending without the accessibility service:**

- Home-screen widget **Send clipboard** (`SendWidget.kt`).
- **Send** action in the ongoing service notification.
- Text selection (`ACTION_PROCESS_TEXT`) and **Share > Send to the computers**
  (`OutsideSendActivity`, exported). Prompts **Allow** or **Always for this app**, identifying the
  calling app only from Android's system referrer (ignoring intent extras). Approved apps appear in
  Settings with an option to **Ask every app again**.
- **cbb send** launcher alias (`SendLauncher`): Assignable to Pixel Quick Tap or Samsung Good Lock
  RegiStar Back-Tap. Launches from the home screen or system UI sync immediately; launches from any
  other app prompt with **Always for this app** so another app cannot silently pull group copies
  onto the clipboard.
- System accessibility button or gesture when **Clipboard sync** is enabled.
- Opening the app (opening-app rule).

Internal triggers (widget, notification, `CopyWatcher`) open the non-exported `SendActivity`;
external triggers open the exported `OutsideSendActivity`. Each runs briefly with focus, swaps or
sends the clipboard, displays a one-line toast, and closes.

Received secrets clear from the clipboard after their configured secret lifetime (`ttlMS`, 60
seconds by default) even while the app is in the background: `Clipboard.kt` tracks a change counter
incremented on app writes and `CopyWatcher` copy events, clearing the clipboard without reading it
when no subsequent change occurred.

## Android TV

The same Android APK supports Android TV, Google TV, and Fire OS (and sideloaded Meta Quest Horizon
OS) by declaring `LEANBACK_LAUNCHER`, a TV banner (`@drawable/banner`), and optional touchscreen and
camera hardware features. `Tv.isTv` checks `UiModeManager.currentModeType == UI_MODE_TYPE_TELEVISION`.
Every interactive control supports D-pad navigation with an accent focus ring (`Modifier.focusRing`).

TV behavior differs from phone behavior:

- **Joining only:** Start offers only **Join a phone's group**, opening the 6-digit pairing window
  entry screen with no camera. The TV joins as an ordinary member with no admin key. Locally
  `LiveGroup` records `form = "tv"` for UI display; on the wire `CoreMember` and `CorePairing`
  report `os = "android"`.
- **Receive only:** Starts in `receive` sync mode and hides auto-send, accessibility service setup,
  Share confirmation, Bluetooth keyboard, and push registration.

Platform constraints on TVs:

- Android 13 and later require **Allow restricted settings** for sideloaded APKs when enabling
  accessibility services.
- Android 17 Advanced Protection Mode blocks accessibility services for non-accessibility apps.
- Fire OS runs the signed Android APK; Vega OS on newer Fire TV sticks does not run Android apps.
- Meta Quest (Horizon OS) runs the APK as a phone app and receives copies into its clipboard.

## Android: the Bluetooth keyboard

The Android app acts as a Bluetooth HID keyboard through `BluetoothHidDevice`
(`BluetoothKeyboard.kt`, `KeyboardSettings.kt`, under **Settings > Advanced settings > Lab >
Bluetooth keyboard**; hidden on TVs). Nothing needs to be installed on the target device (Android
TV, Google TV, Fire TV, iPhone, iPad, Apple TV, macOS, Windows, Linux, Steam Deck, PlayStation 5;
Xbox and Nintendo Switch require USB HID such as the Nano ESP32).

- **Act as a Bluetooth keyboard:** Registers the app with Android's HID device profile (only one app
  can register at a time). Retries once after 2 seconds if the Bluetooth stack restarts; reports
  unsupported hardware if the profile proxy does not connect within 5 seconds (some vendor builds
  omit `BluetoothHidDevice`).
- **Type into:** Lists paired devices and adopts a host that connects on its own. **Make this phone
  visible** makes the device discoverable for 120 seconds.
- **Keyboard layout:** English (US) or Russian (`apps/android/kit/.../Keyboard.kt`, checked against
  `testdata/interop/keyboard.json` alongside `cbb_core::keyboard`). If any character has no mapping
  in the selected layout, nothing is typed and the app lists the unsupported characters.
- **Speed and limit:** 10, 20 (default), or 40 characters per second; maximum 4096 characters.
- **Type the clipboard:** Types the phone's clipboard onto the connected host.
- **Permissions:** Requests `BLUETOOTH_CONNECT` and `BLUETOOTH_ADVERTISE` on Android 12 and later.

**Linux Bluetooth LE keyboard:** `cbb keyboard` ([cli.md](reference/cli.md)) delegates through
`cbb-helper` (`internal/peripheral/keyboard_linux.go` and `internal/blekeyboard`) to register a HID
over GATT (HOGP) service with BlueZ, preserving classic Bluetooth input devices. `cbb keyboard pair`
makes the adapter discoverable for 2 minutes with a temporary default `NoInputNoOutput` pairing
agent. Bonded hosts (up to 16) are tracked in `keyboard-hosts` so stale authentication bonds are
removed automatically. Uses the same US and Russian layout tables (`internal/keyboard`, verified
against `testdata/interop/keyboard.json`) and tests against a fake BlueZ on a private D-Bus
(`internal/blekeyboard/bluetest`).

**Aurora OS Bluetooth LE keyboard:** `apps/silica/src/blekeyboard.cpp` registers the same HID over
GATT service with BlueZ using the sandbox `Bluetooth` permission, obtaining HID reports and the
report map from the core's `keyboard` operation. **Settings > Advanced settings > Lab > Bluetooth
keyboard** (`KeyboardPage.qml`) provides the enable switch, 2-minute visibility as `"CBB keyboard"`,
layout, speed (10, 20, or 40 chars/s), and **Type the clipboard** (also available from the main
page's pull-down menu while connected). Aurora's system pairing dialog handles pairing.

## A computer as a TV's remote

A computer can type onto a TV over the home network without installing an app on the TV
(`cbb remote` in [cli.md](reference/cli.md), implemented in `internal/tvremote`). The TV is a local
target of that computer, not a group member, and holds no group keys. Paired TVs (up to 16) are
stored in `tvs.json`.

- **Android TV and Google TV (`internal/tvremote/androidtv`):** Speaks Android TV Remote v2 over TLS
  using a self-signed 2048-bit RSA client certificate and pins the TV's SHA-256 certificate at
  pairing. Pairing on TCP 6467 displays a 6-character hexadecimal code (`0–9`, `A–F`) on the TV;
  control on TCP 6466 injects text through the TV's input method with Enter as key 66.
- **Apple TV (`internal/tvremote/appletv`):** Speaks the Companion protocol on TCP 49153 (discovered
  via `_companion-link._tcp`, overridable by explicit port). Pairing uses HomeKit SRP-6a pair-setup
  with the 4-digit PIN shown on the TV and exchanges Ed25519 keys saved in `tvs.json`; each session
  runs X25519 pair-verify and ChaCha20-Poly1305 framing, then replaces the focused text field with
  one `_tiC` event carrying an RTI archive in a binary property list. Requires Apple TV **Settings >
  AirPlay and HomeKit > Allow Access** set to **Everyone on the Same Network** or **Everyone**.
- **Roku (`internal/tvremote/roku`):** Sends HTTP External Control Protocol (`POST /keypress/...`)
  requests on TCP 8060 with no pairing or encryption. Adding a Roku requires explicit consent
  (`-consent`), and Roku OS 14.1 and later require **Control by mobile apps** to be enabled.
- **Home network restriction:** `CheckHost` rejects non-home addresses at add time, and every
  connection enforces `netguard.ControlHome` regardless of DNS changes.
- **Errors and tests:** Errors name the TV, protocol, and required user action, with underlying
  errors in details. Unit tests run against fake servers (`androidtv/atvtest`, `appletv/atvtest`,
  and an `httptest` Roku stub).

## The admin PIN on Aurora

Aurora OS 5.1.5 provides regular sandboxed apps no biometric or OS authentication prompt (authd sits
outside the app sandbox, and neither unlock code nor fingerprint exposes a public API). The Aurora
app therefore uses an app-specific PIN enforced by OP-TEE wherever iPhone uses Face ID (D-94):

- **Two tokens (`src/platform/keystore_tee.cpp`):** The member key lives in the QCA-initialized
  token (`"CBB"`, PIN `0000`), so everyday sync and keyboard actions never ask for a PIN. Once
  initialized or in a group, an unresponsive TEE returns an error and retries rather than
  re-initializing the token (which would wipe the member key). The root or admin key lives in a
  second token in slot `"APP"`, initialized with the user's PIN and an SO PIN that is replaced with
  an unstored random value once the user's PIN succeeds (verified directly against the token rather
  than clearable app settings). Other apps cannot access either token.
- **PIN rules and prompts (`src/pinrule.h`, `tests/pinrule_test.cpp`):** Required before generating
  or signing with the admin key (creating a group, adding devices, device admin actions, main-device
  settings, changing the main device). A new or changed PIN must be 6 to 64 digits and pass
  `pinrule.h` checks rejecting repeats, runs, doubled patterns, 5 or more identical digits, two
  simple segments, palindromes, counting pairs, 6- and 8-digit dates, year-suffix repeats, and 80
  common keypad PINs (existing pre-rule PINs of 4+ characters still unlock their token). The PIN
  dialog advises not to reuse the phone's unlock code. Once handed to OP-TEE, the PIN is wiped from
  memory; the token stays logged in for 5 minutes from last use and logs out immediately when the
  app leaves the foreground. **Settings > Change the admin PIN** updates it after verifying the
  current PIN.
- **Wrong PIN lockout:** OP-TEE enforces 7 attempts. The dialog reports remaining tries from token
  flags and the app's counter (saying only that some tries were used if the local counter was lost).
  A seventh wrong PIN locks the admin token permanently; the phone remains in the group as a member,
  Settings reports the lockout, and restoring admin rights requires reinstalling and joining as a
  new device (or moving the main device with the recovery key).
- **Leaving and file-backed targets:** Leaving deletes the admin key if the token is logged in;
  otherwise the key stays unusable and is marked stale for replacement. Aurora OS 4 and Sailfish OS
  use `src/platform/keystore_file.cpp` (level `file`) and require no PIN.

## Collections and the order of the tiles

Users can reorder device tiles and organize devices into **collections** (D-72)—distinct from
"folder" (copied directory) and "group" (sync group):

- **Local only:** Stored by each device's member in `arrangement.json` inside the state directory;
  never sent to peers, hubs, forwarders, or relays. Paired watches display their phone's layout.
- **Single level:** A device belongs to at most one collection, and collections cannot nest.
- **This device:** Treated as an ordinary tile (first by default, movable or placeable in a
  collection).
- **Display only:** Controls tile order, collection summaries, watch sections, and remote-paste
  pickers.

`cbb_core::arrange` (`core/src/arrange.rs`, verified by `testdata/arrangement/vectors.json`) defines
the rules, and `member/src/view.rs` persists the JSON:

```json
{"v": 1, "group": "<group tag>", "items": [
  {"device": "3f2a…"},
  {"collection": {"id": "c1", "name": "Office", "devices": ["9b01…", "77de…"]}},
  {"device": "a0c4…"}]}
```

Rules:

1. **View:** Stored items render in order. Unlisted device IDs and collections with no listed
   devices (except newly created empty ones) are skipped. Unplaced listed devices append to the top
   level in default order, except this device, which prepends first until placed.
2. **Prune:** Unlisted device IDs (and collections emptied by pruning) are dropped only when the
   complete device list is loaded.
3. **Group or version change:** A different group tag or format version starts empty.
4. **Limits:** At most 32 collections (`MAX_COLLECTIONS`). Collection names are trimmed to 1–64
   bytes (`MAX_NAME`) and need not be unique.
5. **Operations** (validated and applied atomically): `move` (an item before another item or to the
   end of its level; moving a device before a device inside a collection joins that collection;
   collections cannot nest), `into` (append device to collection), `out` (place device immediately
   after its collection), `new` (create collection with smallest free `cN` ID at its first device's
   position, or at the end if empty), `rename`, `ungroup` (replace collection with its devices in
   place), and `reset` (restore default device order while keeping collections, each positioned
   where its first device falls). Moving the last device out of a collection removes the collection.
6. **Default:** Nothing is written until the first user edit.

Platform interactions:

- **iPhone and iPad** (`Views/Arrange.swift`, `AppModel`): Start Arrange mode from **… > Arrange
  devices** or a tile's long-press **Arrange** action; end with **Done**. Tiles show dashed
  outlines, ignore open-on-tap, and drag to reorder or drop onto collections. Context menus and
  VoiceOver custom actions (**Move earlier**, **Move later**, **Move to start**, **Move to end**,
  **Take out of collection**) expose every operation without dragging. Collection tiles display up
  to 4 device icons, name, online count, and a danger indicator if a member is frozen; tapping opens
  the collection page. Groups with more than 12 devices show search and **Online** / **Needs
  attention** filters (flat results, Arrange disabled). **… > Back to the group's order** sends
  `reset`. Orbit keeps default group order.
- **Android** (`Arrange.kt`, `AppModel`): Same Arrange mode, started from **… > Arrange devices** or
  a tile's long-press menu and ended with **Done**. In Arrange mode, each tile also adds a `⋮`
  button reachable by keyboard or D-pad, and TalkBack exposes the same custom actions.
- **Mac app** (`Views/Arrange.swift`, `MacModel`): Same Arrange mode as iOS, with **Arrange
  devices** and **Back to the group's order** in the toolbar, right-click context menus, and
  `Option` with arrow keys, `Home`, or `End` moving the focused tile in Arrange mode.
- **Tray app** (`frontend/app.js`, `arrange.go`, `Desk.Arrange`): Uses no separate Arrange mode.
  Tiles are draggable at all times (`draggable="true"`), dropping a device onto a collection adds it
  to that collection, holding 600 ms without moving or right-clicking opens `#tile-menu` with every
  move/collection action, and `Alt` with arrow keys, `Home`, or `End` moves the focused tile.
  `Escape` closes the open detail pane or collection page. Search and filters appear with more than
  12 other devices. Orbit keeps default group order.
- **Aurora OS** (`qml/pages/DeviceItems.qml`, `ArrangePage.qml`, `CollectionPage.qml`,
  `App::arranged`): Long press without dragging opens `ArrangePage.qml` with all actions; long press
  plus drag lifts and reorders tiles directly with no Arrange mode (holding over the middle of a
  collection drops into it). The main page pull-down menu includes **New collection…** and **Back to
  the group's order**; collection pages put **Rename** and **Ungroup** in their pull-down menu.
- **Watches:** Phones send devices in the user's order with each device's `collection` name in
  `WatchState`. Apple Watch and Wear OS list uncollected devices under **Devices** followed by one
  section per collection; HarmonyOS watches render devices in exact tile order with inline
  collection headers. Watches do not modify the arrangement.

## What the member shows

Every app renders its device list from one member response (`cbb_member_call` on phones, control
socket on computers). The `view` operation returns:

```json
{
  "tiles": [{"device": {"...": "..."}}, {"collection": {"id": "c1", "name": "Office", "devices": []}}],
  "online": 1,
  "others": 3,
  "custom": true,
  "warnings": []
}
```

- `tiles`: Devices and collections in the user's order, including this device.
- `online` / `others`: Count of online peers and total other group members.
- `custom`: Whether a stored arrangement exists.
- `warnings`: Output of `cbb_core::why` (omitted when empty).

The `arrange` operation accepts one `Op` (`move`, `into`, `out`, `new`, `rename`, `ungroup`, or
`reset`), persists the change, and returns the updated `view` response (or returns an error without
modifying state). Devices removed from the group drop out automatically on the next `view` call. No
app computes or stores its own tile order.

## HarmonyOS

The app for HarmonyOS 5 and later (`apps/harmony`, native ArkTS/ArkUI without an Android
compatibility layer) mirrors the Aurora OS architecture over the Rust core. A Node-API native module
(`libcbb_napi.so`, `entry/src/main/cpp/napi_init.cpp`) wraps every C function of
`ffi/include/cbb_core.h`, running blocking and signing calls on worker threads with Promises. Its
protocol OS identifier is `harmonyos`. It provides all standard phone screens—Start, Home (tiles,
list, and wide-screen orbit), Device detail (without Quick actions), Open window, Join window,
Invitations, Recovery key, Change main device, Arrange and collections, Settings, Why it does not
sync, Lab, and `Before06.ets` for incompatible pre-`group.cbor` directories.

- **Keys (`cpp/keys.cpp`, `ets/core/Keys.ets`):** P-256 keys in HUKS inside the TEE (level
  `hardware`). The member key signs silently; the admin/root key requires User Authentication Kit
  (face, fingerprint, or PIN at ATL3) with a 30-second auth timeout (`tokenReuse = 25` s) so
  multi-signature operations prompt once.
- **Clipboard and Share (`common/Clipboard.ets`, `common/Share.ets`, `shareextability/`,
  `model/OneShot.ets`):** Incoming copies write freely while in the foreground (secrets set
  `ShareOption.LOCALDEVICE` and clear on TTL if unchanged). Reading the clipboard uses the system
  `PasteButton` (the app does not request `ohos.permission.READ_PASTEBOARD`). Opening the app uses
  `pasteboard.on('update')` change counts to apply the opening rule (D-128); tapping `PasteButton`
  swaps the clipboard. **Share > CBB** (`ShareExtAbility`, `pages/ShareSheet.ets`) starts a
  short-lived member in `${filesDir}/share-member` (`OneShot.ets`), sends text, links, images, or
  files up to 50 MiB, waits up to 8 seconds for a peer (plus up to 60 seconds for file fetches), and
  stops. Single received images go to the pasteboard; other files wait for saving via
  `DocumentViewPicker`.
- **QR codes (`common/Scan.ets`, `components/QrView.ets`):** Scan Kit reads pairing windows,
  invitations, and recovery sheets. `QrView.ets` renders QR codes from core modules for **Add a
  device**, **Send an invitation**, and the recovery sheet.
- **Remote paste (`pages/Paste.ets`):** Admin phones send pasted or typed text (with optional Enter
  and secret flag) and up to 20 picked files (`DocumentViewPicker`) via `cbb_member_manage` `paste`.
- **Away from home and blind relay (`pages/Relay.ets`, `model/AppModel.ets`):** Uses the Rust
  member's user-space tunnel and blind relay. The main device configures the relay (`relay` action)
  and renews 30-day server credentials inside periodic `AppModel.duties()` (1 minute after start,
  then every 6 hours).
- **Attestations (`model/AppModel.ets`, `model/Member.ets`):** Inside `AppModel.duties()`, the main
  device fetches `keys.json` and `attest-status.json` from `https://cbb.tools/attest/` at most once
  every 24 hours and runs `manage` action `attest` via `cbb_core::attest` whenever peer attestations
  are pending ([protocol.md](protocol.md), section 17).
- **YubiKey (`common/YubiKey.ets`):** Connects `cbb_piv` to NFC reader mode
  (`ohos.permission.NFC_TAG`, IsoDep, transport `apdu`) and USB-C CCID devices (`usbManager`,
  `setCard` bulk flag, transport `ccid_bulk`) for sealing on `Recovery.ets` and opening on
  `ChangeRoot.ets`.
- **Outside the app (`widget/`, `insightintents/`, `model/Live.ets`):** Form Kit home-screen widget
  **Sync clipboard** (`SyncCard.ets`: sync button plus sync-toggle/online-count row), app-icon
  long-press shortcut, Intents Kit (`SyncClipboard` and `ToggleSync`), and Live View (`Live.ets`:
  adding a device, away from home, and quick-sync result; requires Huawei Live View approval).
- **Bluetooth LE keyboard (`model/Keyboard.ets`, `pages/Keyboard.ets`):** Serves HID over GATT via
  `@kit.ConnectivityKit` (`ble` GATT server and advertising) using core report maps and reports,
  typing the clipboard on `PasteButton` tap. Omits the report-mode LED output characteristic (`2a4d`
  ref `0002`) because HarmonyOS indexes characteristics by UUID alone, while keeping `BOOT_OUTPUT`
  (`2a32`).
- **Background (`entryability/EntryAbility.ets`, `module.json5`):** Requests a
  `MULTI_DEVICE_CONNECTION` continuous task while the member runs, falling back to
  `requestSuspendDelay` if unavailable.
- **Notifications and errors (`model/Events.ets`, `core/Errors.ets`, `model/Bugs.ets`):** Posts
  local notifications for 4 event kinds (devices joined/removed, admin changes, freezes/unfreezes,
  main-device changes) plus received files. Seven taps on version in Settings reveal **Show error
  details**. Member panics restart the member and prompt to send a bug report in release builds
  ([core-api.md](core-api.md), "Bug reports").
- **Building and checking:** The Rust core builds with OpenHarmony's free native SDK
  (`ffi/ohos-sdk.sh`, `apps/harmony/build.sh`). `apps/harmony/check.sh` runs OpenHarmony's ArkTS
  compiler and linter without a Huawei developer account, and `apps/harmony/nodetest/run.sh` runs
  the Hypium and watch logic tests under Node.js. Building and signing the `.hap` package requires
  DevEco Studio or HarmonyOS CLI tools and a Huawei developer account.

### HarmonyOS watches

The watch module (`apps/harmony/wearable`, HarmonyOS 5 and later) communicates with the paired
HarmonyOS phone over Wear Engine (`model/Watch.ets` on phone, `model/Link.ets` on watch, sharing
byte-identical `common/WatchState.ets`, `common/Wear.ets`, `core/Errors.ets`, and `core/Text.ets`,
verified by `apps/harmony/check.sh`).

- **State and switches:** The phone scans for a connected watch every 30 seconds (`LOOK_MS = 30000`),
  diffs state every 2 seconds, and sends `WatchState` (never the clipboard). Because Wear Engine
  messages cap near 1 KB (`MAX_MESSAGE = 1000`), `WatchState.fit()` drops events first and then
  trailing devices, recording the omitted count in `more`. The watch sends `sync` and `away`
  toggles, caches the latest state in preferences, and displays devices in the phone's tile order
  with inline collection headers.
- **Wear Engine setup:** Requires Wear Engine approval from Huawei, the AppGallery Connect client ID
  in `module.json5`, and the signing certificate fingerprint in `WatchState.FINGERPRINT`.
- **Admin key hooks:** `wearable/.../model/AdminKey.ets`, `model/Link.ets`, `model/Watch.ets`, and
  `cbb_member_manage_watch` implement HUKS screen-lock-gated P-256 key creation, `add_watch`,
  `watch_actions`, and 600-byte chunked signing verification (`PART_BYTES = 600`). As on Apple Watch
  and Wear OS, wrist signing is disabled in the current build (`WatchState.signs = false`, D-124;
  see [Roadmap](roadmap.md)).

## Releasing the Android app

Each release publishes `cbb-X.Y.Z.apk` (`full` flavor), `cbb-fdroid-X.Y.Z.apk` (`fdroid` flavor),
and `cbb-wear-X.Y.Z.apk` (Wear OS), signed with the project's release key
([maintaining.md](maintainers/maintaining.md#android-signing-key)).

### Updates

The `full` APK installed directly from a GitHub release updates itself (`ApkUpdate.kt`):
**Settings > About > Updates** checks manually, and **Update automatically** (off by default) checks
once a day on foreground launch.

- **Verification:** Fetches `keys.json` and `stable.json` from
  `https://raw.githubusercontent.com/HunterEwok/cbb/channel/`, and `release.json` and
  `cbb-X.Y.Z.apk` from `https://github.com/HunterEwok/cbb/releases/download/v<ver>/`, falling back
  to `https://dl.cbb.tools`, sending no version, device, or group data. Verifies signatures using
  the same rules as `cbb update` ([protocol.md](protocol.md), section 16).
- **Installation:** Confirms the APK matches `release.json` size and SHA-256, has package
  `tools.cbb`, carries a higher `longVersionCode`, and shares this app's signing certificate before
  committing to `PackageInstaller` with `USER_ACTION_NOT_REQUIRED` (Android 12 and later). Android
  prompts once to allow **Install unknown apps** for the first self-update.
- **When hidden:** Copies installed by an app store (Google Play, F-Droid, Amazon, Samsung, Huawei,
  Aurora), the `fdroid` flavor (`BuildConfig.SELF_UPDATE = false`), and builds without pinned
  release roots hide the Updates section.

### F-Droid

`apps/android/app/build.gradle.kts` defines two Gradle flavors from one source tree:

- **`full` (`cbb-X.Y.Z.apk`):** Includes `play-services-wearable` (`src/full/kotlin/tools/cbb/WatchLink.kt`)
  for Wear OS, `firebase-messaging` (`src/full/kotlin/tools/cbb/PushPlatform.kt`) for FCM sealed
  push, and self-update (`BuildConfig.SELF_UPDATE = true` with installer permissions in
  `src/full/AndroidManifest.xml`).
- **`fdroid` (`cbb-fdroid-X.Y.Z.apk`):** Contains no Google Play services or Firebase dependencies.
  Uses a no-op `WatchLink` (`src/fdroid/.../WatchLink.kt`), UnifiedPush
  (`org.unifiedpush.android:connector` in `src/fdroid/.../PushPlatform.kt`) for sealed push, and
  `BuildConfig.SELF_UPDATE = false` with no installer permissions.

Both flavors share application ID `tools.cbb` and signing key so users can switch between them
in place while keeping group state and settings. To support F-Droid reproducible builds
(`packaging/fdroid/tools.cbb.yml`), the build fixes:

- Version metadata in `apps/android/version.properties` (kept in sync with `CHANGELOG.md` by
  `tools/repocheck`).
- Exact NDK (`cbb.ndk`) and Rust toolchain (`cbb.rust`) in `apps/android/gradle.properties`, with
  remapped checkout and Cargo paths in `ffi/bind.sh`.
- Disabled APK metadata blocks (`dependenciesInfo { includeInApk = false }`,
  `vcsInfo.include = false`).

CI's `fdroid` job runs `packaging/fdroid/reproduce.sh` to build the `fdroid` APK twice (the second
from a clean copy without `.git`, different directory, timezone, and umask) and verifies byte-for-byte
equality; the `android` job verifies no Google Play services enter `fdroid`. Fastlane store
metadata and icon live in `apps/android/app/fastlane/metadata/android` (`en-US` and `ru-RU`).

## Languages

- Every user-facing string comes from platform localization catalogs generated from a single source,
  `apps/l10n/<language>.json`, by `go run ./tools/strings` (`tools/strings/catalog/catalog.go`):
  - Apple String Catalogs (`*.xcstrings`) for iOS, ShareExtension, NotificationService, Watch,
    Widgets, AppShortcuts, InfoPlist, and macOS.
  - Android XML (`apps/android/app/src/main/res/values*/strings.xml` and `apps/android/wear/...`).
  - Qt translation files (`apps/silica/translations/cbb-<language>.ts`).
  - HarmonyOS resources (`apps/harmony/{entry,wearable}/src/main/resources/*/element/string.json`).
  - Tray app JSON (`apps/desktop/frontend/l10n/<language>.json`).
- `apps/l10n/en.json` defines each string ID, its `"in"` targets, optional `"en"` override, and
  `"translate": false` for untranslated names. `tools/repocheck` verifies that generated files match
  the source, no translations are missing, and format directives (`%@`, `%s`, `%1$s`, `%1`) match
  the English text.
- Eight supported languages: English (source), Chinese (Simplified), Spanish, Russian, Arabic,
  Swahili, Hebrew, and Hindi. Arabic and Hebrew render right-to-left across all apps (including the
  tray app). Layouts avoid fixed text widths and use leading/trailing alignment.
- Language defaults to the system language with an in-app override in Settings (and always on Start
  on iOS and Android).

### Words in the apps

App copy follows each platform's own conventions (Apple Human Interface Guidelines, Material Design
Writing guidelines, Microsoft Writing Style Guide, and platform-published translations): action
labels use verbs matching dialog titles, sentences stay short and plain without slang, and hardware
actions follow platform sheets (plug in over USB-C, hold to the phone for NFC, touch when blinking).

`go run ./tools/strings -lint` enforces wording in CI (D-133):

- **Termbase (`apps/l10n/terms.json`):** Defines each concept's required term (`use`), detection
  regex (`find`), disallowed variants (`avoid`), and valid exceptions (`except`). When English names
  a concept, every language with a `find` pattern must use its corresponding term.
- **Vale (`tools/strings/lint.go`, `tools/strings/vale/vale.ini`):** Runs a pinned Vale version
  directly through `go run` against generated per-language term rules
  (`tools/strings/vale/styles/<language>/Terms.yml`) and shared formatting rules
  (`tools/strings/vale/styles/Cbb`: ellipsis character, language quotes, single spaces).
- **One English text, one translation:** Strings that share the same English text apart from
  platform placeholders must share the same translation in each language unless given a distinct
  bracketed ID whose translation actually differs in at least one language.

## Themes

- **Eleven themes** defined in `apps/design/tokens.json`: **Chalkboard** (`board`, default—matching
  the website), **Blueprint**, **Precise**, **Glass**, **Soft**, **Swiss**, **Hardware**,
  **Art Deco**, **Liquid Glass**, **Terminal**, and **Retro**.
- Each theme specifies style tokens (display/body/mono fonts, corner radii for buttons/cards/tiles/chips,
  stroke width, material [`flat`, `glass`, `liquid`, `metal`], optional surface grid, dashed
  inactive lines, uppercase small labels) plus separate `dark` and `light` palettes. Appearance
  follows **System**, **Dark**, or **Light**.
- `tokens.json` sets `"default": "board"`; `go run ./tools/tokens` places the default theme first in
  all generated files.
- Themes style only app surfaces, borders, typography, and accent; native system controls (switches,
  sheets, dialogs, biometric prompts) retain the platform look.
- **Glass** and **Liquid Glass** use Liquid Glass on iOS 26 and macOS 26; Android renders glass
  surfaces with palette opacity and a hairline border.
- Android 12 and later add **Material You** (dynamic wallpaper colors using **Precise** geometry).
  Aurora OS follows the system ambience.
- Watch apps and Live Activities / Live Views use the dark palette only.
- `go run ./tools/tokens -check` fails if any palette falls below 4.5:1 WCAG AA contrast for text,
  dim text, danger text, or accent text on background or surface.

## Layout of the repository

- `apps/ios/` — iPhone, iPad, Apple Watch, Widgets, ShareExtension, and NotificationService
  (SwiftUI). `project.yml` generates `CBB.xcodeproj` via XcodeGen (not committed).
  `apps/ios/CBBKit/` wraps the Rust core (`CoreMember`, `CorePairing`, `Discovery`,
  `BonjourBrowser`, `RecoveryCard`, `PhoneGroup`). Platform-independent tests run on Linux;
  network-backed tests (`CoreMemberTests`, `CorePairingTests`, `WindowTests`, `DiscoveryTests`) are
  guarded by `#if canImport(Network)` and run on Apple platforms. The app browses `_cbb._tcp` via
  `BonjourBrowser` (declared in `NSBonjourServices` with `NSLocalNetworkUsageDescription`).
- `apps/android/` — Gradle project (Kotlin, Compose) containing `kit` (JVM protocol/FFI wrapper),
  `shared` (tokens, glyphs, `WatchState`), `app` (`full` and `fdroid` flavors, phone/tablet/TV), and
  `wear` (Wear OS). Reproducible F-Droid recipe lives in `packaging/fdroid/`.
- `apps/silica/` — Aurora OS 5, Aurora OS 4, and Sailfish OS app (Qt 5.6, Silica QML, C++ over
  `ffi/`), with platform-specific keystore and shell layers in `src/platform/` and per-target RPM
  specs in `packaging/`.
- `apps/harmony/` — HarmonyOS 5 and later phone/tablet app (`entry/`) and watch module
  (`wearable/`) in ArkTS/ArkUI over a Node-API C++ wrapper (`entry/src/main/cpp/`), with
  account-free ArkTS checking (`check.sh`) and Node.js logic tests (`nodetest/`).
- `apps/macos/` — macOS menu bar and desktop app (SwiftUI), generated from `project.yml` via
  XcodeGen.
- `apps/desktop/` — Linux and Windows tray app (Go, Wails 3, plain HTML/CSS/JS frontend), a
  standalone Go module.
- `apps/design/` — Shared design tokens (`tokens.json`) and master icons (`icon/light.png`,
  `icon/dark.png`, `icon/aurora.svg`, `icon/tray/*.svg`):
  - `go run ./tools/tokens` generates `apps/ios/CBB/Theme/Tokens.swift` (shared with macOS),
    `apps/android/shared/src/main/kotlin/tools/cbb/Tokens.kt`, `apps/desktop/frontend/tokens.js`,
    and HarmonyOS default-theme color resources
    (`apps/harmony/entry/src/main/resources/{base,dark}/element/color.json` and
    `apps/harmony/wearable/src/main/resources/base/element/color.json`).
  - `go run ./tools/icon` generates launcher icons for iOS (light and dark), Apple Watch, macOS,
    Android adaptive foreground, and HarmonyOS (app, phone, watch); menu bar template SVGs for macOS
    and symbolic SVGs, white/black PNGs, and white/black ICOs in `apps/desktop/trayicon/`; and the
    ZX Spectrum Next logo.
- **YubiKey recovery integration (`cbb_piv`, D-127; [protocol.md](protocol.md), section 9, "The
  recovery key on a YubiKey"):** The Rust core speaks PIV (`seal` and `open` via `RecoveryCard` or
  native bindings), placing the sealed recovery secret in the first unused retired slot (95 down to
  82) without altering the card's management key (requires firmware 5.3 or later). Each platform
  supplies only the card transport:
  - **Android (`YubiKey.kt`: `YubiKeys`, `YubiKeyNfc`, `YubiKeyUsb`):** Activity NFC reader mode
    (`apdu`) and USB-C CCID via `UsbManager` (`ccid_bulk`), listening to both simultaneously.
  - **HarmonyOS (`common/YubiKey.ets`):** NFC IsoDep (`apdu`) and USB-C `usbManager` (`ccid_bulk`),
    listening to both simultaneously.
  - **iPhone and iPad (`App/YubiKeyNfc.swift`, `App/YubiKeyUsb.swift`):** Core NFC sheet (requires
    the NFC entitlement from the Apple developer account; `CBB_NFC=1` in `device.sh`) and
    CryptoTokenKit (`TKSmartCardSlotManager`) for USB-C. Note that `ChangeRootView.swift` currently
    gates **Use a YubiKey instead** on `YubiKeyNfc.available`.
  - **Aurora OS (`PivThread` in `src/app.cpp`):** USB-C only through the system `pcscd` socket
    (transport `pcsc`).
- Shared user-facing terminology lives in [the glossary](reference/glossary.md) and
  `apps/l10n/terms.json`; the wire protocol is specified in [protocol.md](protocol.md).
