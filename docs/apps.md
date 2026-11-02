<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phone apps

The iPhone and Android apps make the phone the root of the group (see "The phone apps"
in [design.md](design.md)). This document fixes what they do and how
they look, so both apps are built to the same plan.

## Principles

- **Only what is needed.** Pair the first computer, add a computer, send and fetch the
  clipboard, see the group's devices and remove one. Nothing else: no history, no accounts,
  no cloud, no statistics.
- **As few taps as possible.** The everyday action is one tap or none: the widget, the
  Back Tap or Action button shortcut, the share sheet, the Android quick-settings tile.
  Adding a computer is "scan" and nothing more; digits are typed only when a camera cannot
  be used.
- **Modern and a little hacker-like.** "Glass": a deep background with a soft glow of the
  accent from the top, tiles and cards on glass; a monospaced face for codes, device IDs and fingerprints; one bright accent
  colour (default: terminal green) for the main action and live states; rounded, generous
  buttons on Liquid Glass (from iOS 26; a material before), cards and fields on glass too;
  short, plain words. Motion is sparing and honours Reduce Motion.
- **Native underneath.** SwiftUI on iOS and Jetpack Compose on Android, the platform's own
  controls, Dynamic Type and font scaling, VoiceOver and TalkBack labels, haptics on success
  and failure.

## Screens

1. **Start** (no group yet): one sentence, the big button "Connect a new device" with a hint
   below it (on a computer, run `cbb pair` and scan the code it shows; `clipboardbridge
   pair -phone` in the mode without the app), and a second button, "I already use
   Clipboard Bridge on another phone", which joins that phone's group. The camera opens at once;
   after the scan the app creates the group key in the Secure Enclave or StrongBox, admits
   the device and goes to Home. At the first launch the app makes this phone's own key and
   says so once, in a card: "This phone is ready", what the key is for in plain words, and
   that the next step is to connect a device. A gear opens Settings (theme and language)
   before there is a group; when the system's language has no translation, a language menu
   sits next to it, with English chosen.
2. **Home**: the one big button (send what this phone holds or fetch the computer's recent
   copy, by the same rule as the shortcut; when the phone's clipboard holds something the
   app cannot read as text, it is left as it is and the line says so), the result in one
   line, and every device of the group under it, as tiles or as a list (the "…" menu
   switches them and opens Settings). A tile shows the device's icon (laptop, computer,
   phone, tablet, TV, board, server, router, game console, watch, retro computer or other;
   SF Symbols on the iPhone), a live dot, its name, its system and its mark ("this phone",
   "root", "admin", "frozen"); a tap opens the device (Devices, below). A "+"
   adds a device (camera). The same button is the app's "Sync clipboard" action, which
   Shortcuts and Spotlight offer as soon as the app is installed (App Intents with an
   App Shortcut): Back Tap or the Action button runs it without opening the app; it waits
   a few seconds for a computer to connect and says what it did in one line. The same
   action is a home-screen widget "Sync clipboard" on both phones (on the iPhone also a
   Control Center control, iOS 18): one tap opens the app for a moment, since iOS lets an
   app read the clipboard only in the foreground, and syncs; on Android the widget sends
   as the tile does. On the iPhone, **Share → Clipboard Bridge** (from any app, and from the
   text selection menu's Share) sends the text or the link at once: the share extension
   dials the group's computers with the phone's member key, which it shares with the app
   through an app group and a keychain access group (both need the Apple developer
   account; a debug build signed ad hoc has neither, and its extension says there is no
   group). Share takes an image or files too, up to 50 MB together: the extension stays
   until a computer fetched them from the phone, at most a minute.

   When the group's records show a likely thief, a card above the button says so
   (`GroupAlerts` in the kits, from the core's state; docs/protocol.md, section 10,
   "Stopping the exchange"): what is stopped (all but the records, or the secrets), why (two
   admins acting against each other, two claims or a disputed one, a key that signed two
   histories), a claim to take the group over with the time left, and a newer version of
   the records that this app cannot read. On the group's root the card offers the decision
   under Face ID or the fingerprint: remove the device of a claim or one of the two admins,
   or void both histories; on any other device it says that the root decides.

   **Images and files** (docs/design.md, "Images and files"): the button sends an image on
   the clipboard as PNG or JPEG (HEIC and other formats are converted) and fetches a
   computer's image whole before it writes it, an image by its hash: the same image twice is
   nothing new. A received image goes to the clipboard by itself as a text does, on Android
   through the app's FileProvider and on the iPhone while the app runs, to this phone only.
   Received files wait for the button, which saves them, with their folders, in Downloads,
   folder "Clipboard Bridge", on Android and in Files, On My iPhone, Clipboard Bridge,
   Received, on the iPhone; it saves a copy once. Android's Share sends a single image as an
   image and anything else as files, up to 100 MiB together. A copy over 100 MiB stays on
   the computers.
3. **Add a device**: the camera with a frame; the device appears in the list when it has
   joined. Fallback: type the six digits. Another phone joins the same way: it shows its own
   QR code ("I already use Clipboard Bridge on another phone" on its Start screen) and this phone
   scans it.
4. **Devices** (the tiles of Home, and a device's page): on its page a summary (type,
   operating system, role, its place in the group, online or not) and the actions below
   it; Back returns to Home. The whole group, one tile per device: its name, an icon and the name of its
   system (Linux, Windows, macOS, iOS, Android, or "device" for firmware; a lite member and an
   iPhone with the shortcut are marked so), a "root", "admin" or "frozen" mark, a live dot when it is online and
   "seen 5 min ago" otherwise, and "this phone" on its own row. The list is the group's
   device records (section 10 of [protocol.md](protocol.md)), so every app and
   `cbb status` show the same. On an admin phone, a row opens the device: rename,
   "Make it an admin" (phones only, on the root phone), "Unfreeze" for an admin computer
   that another admin froze (design.md, "Who may remove an admin"), and "Remove", which asks once, then
   needs Face ID, the fingerprint or the passcode, and is done; removing an admin phone shows
   the devices it had admitted, which stay. On the root phone a computer's row also offers
   "Make it an admin" when the computer offers an admin key (docs/protocol.md, section 10,
   "A computer as admin"): it asks once, warns that the key is a file on the computer, needs
   Face ID, and the computer then adds and removes devices with `cbb pair` and
   `cbb revoke`. If the removed phone held the root, this phone
   takes it over in the same step. A connected computer's page shows its sync mode and, on an admin phone,
   offers "Sync mode": the phone signs a `mode` command (docs/protocol.md, section 15) after
   Face ID or the fingerprint and sends it to that computer, which answers done or why it refused.
   On an admin phone, the page of a computer or a lite member also offers "Paste on it…"
   (docs/design.md, "Remote paste"): a text, typed or taken from the clipboard (on the iPhone
   through the system's Paste button, which asks nothing), pasted or typed key by key, with
   Enter after it and as a secret if asked. The phone signs a `paste` command after Face ID or
   the fingerprint, and a member connected to the computer passes it on when the phone is not.
   The computer answers once the text is in, or why it would not.
   While a computer or a lite member is online, its page also offers "Quick actions"
   (docs/protocol.md, section 15): the actions its hello says are on, the presets by their
   names in words and the user's own by theirs. A tap runs one, after Face ID or the
   fingerprint; reboot and shut down ask again first. "Turn all off" signs `actions-off`,
   after which only the device's own user turns them on again. A phone that is not an admin shows the list without
   actions and says which phones are admins.
5. **Settings**: the theme (System, Dark or Light) and one of ten colours, language, about (seven taps on the version show the switch "Show
   error details", which puts the error itself under each error message; it is on in debug
   builds, and the launch argument or extra `ShowErrorDetails` sets it too), and once there
   is a group, "Away from home": one
   switch that turns sync away from home on for this phone (docs/design.md, "Sync away from
   home"), the words of the design on what changes, and where it stands: waiting for the
   hub's answer, which comes on the next connection at home; at home, syncing directly;
   connecting; connected through the tunnel. Turning it off forgets the phone's tunnel key.
   On Android the WireGuard key sits in the app's files, encrypted with a Keystore key that
   needs no unlock, so the foreground service syncs away from home as it does at home; the
   tunnel runs in the app's process (`mobile/cbbtun`) and opens a loopback port that the kit
   dials with its own member TLS, checking that the peer is the hub. On the iPhone the key
   and the hub's offer sit in the keychain, readable after the first unlock and on this
   device only; the same tunnel (`Cbbtun.xcframework`) runs while the app does, and the
   kit's `AwayFromHome` drives it in both the app and its tests. When the group's hub is
   obfuscated, its offer carries the AmneziaWG settings, and when it has its clients come
   over VLESS, the way there; both apps keep them with the offer and give them to the
   tunnel, which then reaches the hub only over VLESS. Nothing changes on the screen.
   On a root or admin phone, "This phone as the hub" comes first (docs/design.md, "The
   phone as the hub"): a switch, on from the start in a group the phone made; where it
   stands (at home only without a forwarder, registering, registered, or why the forwarder
   refuses it, with the error underneath when details are on); whether the network the
   phone is on is one of the hub's home networks, with "This is my home network" when it
   is not; the forwarder's address and key, as `cbb forward` prints them; and on Android
   "Keep the hub running in the background", which lets the foreground service keep it.
   While the phone is the hub, the switch for its own sync away from home is hidden: a hub
   is nobody's client. Home says "This phone is the hub: sync works while the app is open".
   The hub's WireGuard key, its forwarder, its home networks and its clients sit with the
   away state (Android: a file sealed by a Keystore key; iPhone: the keychain). The kits'
   `PhoneHub` and `MemberListener` do the work, the Android app's `HubOnPhone` and the Swift
   kit's `HubOnPhone` drive cbbtun's hub, and the hub publishes itself on a home network
   with `r=phone` (docs/protocol.md, section 3). While the hub is registered, "Invite a
   device from afar" makes a remote invitation for an hour (docs/protocol.md, section 12):
   the phone shares the file `clipboardbridge.cbbinvite`, the other side runs
   `cbb pair -invite` with it, and the phone asks "Admit …?" with the device's fingerprint,
   which `cbb` shows too; on yes it unlocks the group's key and admits it.

The lost phone case is one path, and the app says so in plain words: "Lost a phone? Open
Devices on your other phone and remove it." When the group has a single admin, Devices
suggests making a second phone an admin.

Errors are one line in plain words with the next step ("Turn on the computer that holds
the group", not a status code), never a dialog that must be dismissed.

## Big screens

- **iPad** (the same app, universal): an iPad is a phone for the group. It joins as an
  admin, or makes its own group, and its root key lives in its Secure Enclave. Its Home
  shows the devices on **orbits** around it, or as tiles or a list (the "…" menu switches
  them). Its centre is the sync button, the toolbar holds the sync button too, and a device
  opens its details in a pane beside the devices, which a cross closes. With a keyboard,
  Command-R sends or fetches, Command-N adds a device, Command-comma opens Settings from
  the "…" menu, and Escape closes the details. An iPad pairs with no Apple Watch, so its
  Settings leave the watch out.
- **A foldable iPhone** (the iPhone duo): the outer screen is the phone's page. The inner
  screen is a big screen like the iPad's: the orbits, the details beside them, and in
  landscape the system moves the toolbar (sync, "+", the menu) to the strip at the right
  edge. A phone's screen stays upright; a big one turns.
- **Android tablets and foldables** do the same from 720 dp wide: the orbits (or tiles or a
  list, which the view button switches), and a device's details in a pane beside them.
  Android draws the device icons itself (`DeviceGlyph`), on the same 24-unit grid as the
  system's line icons.

## Dynamic Island

A Live Activity (iPhone, iOS 17) shows what runs in the Dynamic Island and on the Lock
Screen, in the colour chosen in Settings, and never what was copied:

- **Adding a device**: from the scan until the device is in the group, with a timer; then
  "The device is in the group." or "The device was not added." for a moment.
- **Away from home**: while the phone syncs through the tunnel of the group's hub, a shield
  with the time since it connected.
- **A sync**: its result ("Sent to the computers.", "Fetched from the computers.") for a
  few seconds.

## Notifications

The app notifies of the group's events (design.md, "Watches", step 1), each kind with a switch
in Settings, all on by default: a device joined or was removed, became an admin, was frozen
or unfrozen, the group was taken over, and the hub does not answer through the tunnel for
two minutes while away from home. The app compares the devices with what it saw last time
(`GroupEvent`, `Notifier`), so it hears of an event while it runs and syncs. An iPhone app
has no background sync: until it has push notifications, which need the Apple developer
account, it asks iOS for background app refresh (`BackgroundRefresh`), and iOS runs it for a
few seconds now and then, at times it picks from how the phone is used. It then waits up to
20 seconds for a computer, takes the records and notifies of what changed; it leaves the
clipboard alone, which only the app in front may read. So an event may come within the
hour, or only when the app next opens: iOS runs no refresh with Background App Refresh off
or in Low Power Mode. iOS asks for notifications once, when the phone is first in a group.

The Android app (`GroupEvents.kt`, the same events and the same order) looks whenever
records arrive and at each refresh; its foreground service keeps the connections in the
background, so it hears of most events at once. It posts on its own channel, "The group's
events", with the permission it asks for the service's notification. Android shows them
on a paired watch as well.

## Apple Watch

The watch app (`apps/ios/Watch`, watchOS 10) has no network of its own: watchOS gives an
ordinary app no sockets, so it works only through its iPhone, over WatchConnectivity
(`WatchLink` on the phone, `WatchModel` on the watch). It shows, in the phone's colour:

- how many devices are online, and each device with its icon and live dot;
- the switch for sync away from home, which turns the phone's own away mode on and off as
  Settings does, and where it stands;
- the latest events of the group.

The phone sends the watch its state (`WatchState`: devices, away, events, colour; never
the clipboard) whenever it changes; the watch shows the last one it got and says so when
the phone does not answer. The notifications of the group's events reach the watch as
every iPhone notification does.

The root phone makes the watch an admin with a key of its own (docs/protocol.md, section 10,
rule 8), in Settings, "Apple Watch", while the watch app is open. The phone asks the watch;
the watch checks that it has a passcode and is on the wrist with wrist detection on
(`LAPolicy.deviceOwnerAuthenticationWithWristDetection`), makes a P-256 key in its Secure
Enclave that works only while it is unlocked (`WatchKey`), and answers with the key and a
device ID it picked. The phone, after Face ID, issues the admin CA and signs the watch's
device record (`PhoneGroup.addWatch`), sends the record to the group and the admin CA to the
watch. Removing the watch from the devices revokes the key; a new watch gets one after that.

On a watch that is an admin, a device in the list opens its emergency actions: freeze an
admin computer, remove an ordinary device, turn remote paste, the quick actions or sync away
from home off, or run one of its quick actions marked for a watch. The phone says which
apply (`PhoneGroup.watchActions`). After a tap on what it signs, the watch asks the phone for
the body (`PhoneGroup.watchBody`), checks that it says what was asked, checks the wrist and
signs with its key; the phone adds the record to the group or passes the command on, and
says when it is done.

## Wear OS

The Wear OS app (`apps/android/wear`, Wear OS 3, Compose for Wear OS) is the Apple Watch
app's twin, and works only through its phone as well: a Wear OS watch reaches its phone
through the Wearable Data Layer of Google Play services, the only channel there is, and the
watch's own network would make it a member, which it is not. It shows the same page in the
phone's colour: how many devices are online, each device with its glyph and live dot, the
switch for sync away from home and where it stands, the latest events.

- The phone (`WatchLink`) keeps the state in a data item, `/cbb/state` (`WatchState` in
  `apps/android/shared`: devices, away, events, colour, whether errors show their details;
  never the clipboard), and replaces it whenever it changes; the watch reads it when it
  opens and follows each change.
- The watch's switch sends the message `/cbb/away` (1 on, 0 off); Play services start the
  phone app's listener (`WatchListener`), which turns the phone's own away mode on or off as
  Settings does, and the new state comes back as the data item. Without a phone in reach the
  watch says so and keeps the last state it got.
- The two apps share the application id and the release key, as the Data Layer requires;
  `apps/android/shared` holds what they share (the colours of `tokens.json`, the device
  glyphs, `WatchState`). A phone without Play services has no watch and works as before:
  the one Google library it carries is for the watch only.

The notifications of the group's events reach the watch as every Android notification does,
with or without the app.

The root phone makes the watch an admin as the iPhone does, in Settings, "Wear OS watch":
the phone sends `/cbb/certify`; the watch's listener (`WearListener`) checks for a secure
lock screen, makes a P-256 key in the Keystore (StrongBox where there is one, else the
TEE) that works only while the watch is unlocked (`WatchKey`), and answers on `/cbb/key`.
After the fingerprint, the face or the screen lock, the phone sends the admin CA on
`/cbb/admitted`, and the watch confirms on the same path. Wear OS has no common way to read
the on-wrist setting, so the phone asks the user to keep it on.

The emergency actions work as on the Apple Watch: the watch sends its ask on `/cbb/ask` and
gets the body on `/cbb/body`, then sends what it signed on `/cbb/signed` and gets the
phone's answer on `/cbb/done`; the key signs only while the watch is unlocked.

## The Mac app

The Mac app (`apps/macos`, SwiftUI, macOS 14) is a window and a menu bar item over the
service that the installer or Homebrew put on the Mac; the service and its pasteboard agent
keep syncing without it. It speaks the service's control socket (`Control`, the protocol of
`internal/control`: a JSON header line, then the payload), as a member of the
`_clipboardbridge` group, and reads the status and the devices every few seconds.

- **The window**: the group in a line (how many devices are online, its tag, sync away from
  home and its switch), the devices as tiles, a list or orbits around this Mac (the toolbar
  switches), a device's details in a pane beside them (the summary rows of the phones,
  with its device ID and when it was last seen), and "Send the clipboard" and "Fetch" at the
  bottom. "+" gives the commands that add a device.
- **Alerts**: the phones' card (Home, above) under the group's line, from `cbb status`;
  on the root its buttons run `cbb revoke` or `cbb resolve` as the administrator.
- **The menu bar item**: how many devices are online, send, fetch, the window, Settings.
- **Settings**: the colour and the appearance of the phones (`Theme.swift` and `Tokens.swift`
  of the iPhone app, shared), this Mac's sync mode (`cbb mode`), whether the app may press keys for remote paste, and error details (on in debug builds, off in release ones, and
  the `ShowErrorDetails` default either way).
- What changes the group (rename, remove, make an admin, freeze, unfreeze, sync away from
  home, the sync mode of this Mac or, on an admin, of another computer: `cbb mode -on`) goes only through the admin socket, which only root reaches, so the app runs
  `cbb` with administrator privileges (`Admin`, `do shell script … with administrator
  privileges`): macOS asks for the password, as `sudo cbb` does in Terminal. With error
  details on, `CBB_DEBUG=1` makes cbb name the error underneath.
- **Remote paste**: only an app may press keys on a Mac, once its user allowed it in
  Accessibility, so the app is the Mac's paste target (`PasteTarget`), not the service or its
  agent. While it is open it keeps a `watch` connection with `inject` `desktop` and
  `paste_only` (docs/protocol.md, section 8). A paste goes through the pasteboard, marked
  `org.nspasteboard.TransientType` so the agent does not sync it, and Cmd+V; after half a
  second the pasteboard gets its items back, unless the user copied meanwhile. Typing posts
  Unicode key events, which no layout changes. It refuses without the permission, on the lock
  screen, in a session not on the screen, and under Secure Event Input.
- Pairing runs in Terminal for now (`cbb pair`); the Developer ID app of roadmap item 22
  carries the service itself and a Network Extension.

CI's `Mac app` job builds it and runs its tests, signed ad hoc. Not yet run on a real Mac.

## The tray app

The tray app (`apps/desktop`, `cbb-desktop`) is the Mac app's twin for Linux and Windows: one
program in Go with [Wails 3](https://v3.wails.io) (pinned to its beta until a release; GTK 4
and WebKitGTK on Linux, WebView2 on Windows), a tray item and a window over the service. Like
the Mac app it speaks the control socket, with the service's own `internal/control`, and the
service and its clipboard agent keep syncing without it.

- **The window** (`frontend/`, plain HTML, CSS and JavaScript, no build step): the group in a
  line with the away-from-home switch, the devices as tiles, a list or orbits around this
  computer, a device's details beside them, and "Send the clipboard" and "Fetch".
- **Alerts**: the Mac app's card above the devices, with the same buttons on the root.
- **The tray item**: how many devices are online, send, fetch, the window, Quit. Closing the
  window keeps the tray item; starting the app again opens the window.
- **Settings**: the ten colours (`frontend/tokens.js`, which `go run ./tools/tokens` writes
  with the Swift and Kotlin tokens), the appearance, this computer's sync mode (`cbb mode`),
  and error details (as cbb: on in a
  build without a release version, `CBB_DEBUG=1` or `0`, or the switch). They are kept in
  the user's configuration folder (`clipboardbridge/desktop.json`).
- What changes the group runs `cbb` as the administrator: through `pkexec` on Linux (the
  desktop's password dialog; each argument passed as it is, no shell), and through the UAC
  prompt on Windows (an elevated PowerShell started with `ShellExecuteEx`'s `runas`, each
  argument a single-quoted literal, its output read back from a file). A dismissed prompt
  changes nothing and says nothing.
- Languages: English and Russian (`frontend/l10n/ru.json`, keyed by the English text; the Go
  side reads it for the tray), picked from the system's language.

CI's `tray app` jobs vet, test and build it on Linux and Windows. The installers do not carry
it yet, and it does not start at sign-in by itself; not yet run on a real desktop beyond a
virtual X display.

## Android: the clipboard without taps

Since Android 10 an app reads the clipboard only while it has the input focus, or when it is
the default keyboard; writing works at any time. So the computers' copies reach the phone by
themselves, and the phone's copies need either the app's focus for a moment or a tap.

**Receiving, always automatic.** A foreground service (type `connectedDevice`, with the
ongoing notification Android requires) keeps one connection to each computer of the group
and puts what they copy on the phone's clipboard. It holds a multicast lock only while it
browses mDNS. Nothing to set up.

**Sending, automatic: "Send my copies by themselves".** An accessibility service that the
user turns on once, from a screen in the app that says what it is for and opens the right
page of Settings:

1. The service watches for a copy: a click on a "Copy" action (the platform's and the
   common apps' labels, in every language the system has), and from Android 13 the
   system's clipboard overlay that appears after each copy.
2. It then shows a 1-pixel accessibility overlay window that takes the focus for a moment,
   reads the clipboard, sends the text to the group and goes away. The service reads no
   screen content beyond what tells it that a copy happened, and the app says so.
3. Android 12 and later show "CBB pasted from your clipboard" each time; that
   is the system's notice and cannot be turned off.

What the service asks Android for (`accessibility_copy.xml`), and why each part is needed:

- `typeViewClicked`: the click events, whose text or description tells it that "Copy" was
  pressed. It reads only the clicked element's label.
- `typeWindowsChanged` with `flagRetrieveInteractiveWindows`: the list of windows, whose
  titles show the system's clipboard overlay (step 1). It reads only the titles.
- `canRetrieveWindowContent`: needed by `findFocus`, with which remote paste finds the text
  field that has the focus and pastes into it. It touches no other field.
- No list of packages: a copy can happen in any app, so the service listens in every app.

These are wider than what the code reads, since Android grants window content as a whole.
Whether a narrower set still notices copies and pastes is to be checked on a real phone
before it changes (0.7).

On Android 13 and later, an APK installed from a browser or file manager cannot turn on an
accessibility service until "Allow restricted settings" is chosen in the app's App info
(⋮ menu). The setup screen shows that step with a button to App info; an install from
F-Droid or Google Play skips it. Google Play allows the service only with its accessibility
declaration; the GitHub and F-Droid builds have it from the start.

**Remote paste onto the phone** (docs/design.md, "Remote paste"). The same service is the
phone's paste target, once the phone's user turned remote paste on in Settings ("Let the
group's admins paste here", and apart from it "Let a paste press Enter"). A `paste` command
an admin signed (`PasteReceiver`, with the switches, the limits per sender and the log of
the last 100 pastes without their text, as on a computer) goes into the text field that has
the input focus in another app:

- **paste**: the text goes on the clipboard, marked sensitive for a secret, and the field gets
  `ACTION_PASTE`, or `ACTION_SET_TEXT` where it takes no paste. After half a second the
  clipboard gets its item back, unless something else was copied meanwhile. The service's
  own copy detection ignores that moment, so the text is not sent to the group.
- **type**: the text replaces the field's selection through `ACTION_SET_TEXT`, and the cursor
  goes after it.
- **Enter**: `ACTION_IME_ENTER`, from Android 11.

It refuses while the phone is locked, when no editable field has the focus, and while the
service is off. Settings say so and open the accessibility settings. A notification names
the sender.

**Sending with one tap, without the service** (and always as well):

- the **Quick Settings tile** "Send clipboard", and the **home-screen widget** of the same name;
- the **"Send" button** in the service's notification;
- **text selection → Clipboard Bridge** (`ACTION_PROCESS_TEXT`) and **Share → Clipboard Bridge**,
  which first ask "Allow" or "Always for this app", naming the app, since any app can hand
  over a text. "Always" holds only for the app that Android records as the one that opened
  Clipboard Bridge (never one an intent names itself), and Settings lists those apps and asks
  every app again;
- **double-tap the back**: on a Pixel, Settings → System → Gestures → Quick Tap → Open app →
  "cbb send" (a second launcher entry that sends and closes); on Samsung, Good Lock's
  RegiStar → Back-Tap action → Open app → "cbb send". Opened by the home screen or the
  system it syncs at once; opened by another app (a back-tap app, or any app at all) it
  asks first, with "Always for this app", because a sync may put the computers' latest copy
  on the clipboard, where that app could read it;
- **opening the app**, by the Home button's rule.

Each of these opens a transparent activity for a moment: it has the focus, reads the
clipboard, sends, says what it did in one line (a toast) and closes. The tile, the widget and
the notification open one that other apps cannot (not exported); Share, the selection menu and
"cbb send" open the exported one, which asks as above.

A secret written to the clipboard goes after its minute even while the app is in the
background, where it may not read the clipboard: unless the app learned of a change since
(another text it wrote, or a copy the accessibility service saw), it clears the clipboard
without reading it.

**To check on a device before building on it:** that the accessibility overlay gets the
focus the clipboard needs on Android 10 to 17, on a Pixel and a Samsung; which copy events
each OEM's apps give; that the restricted-settings path is as described on Android 15 to 17.
If the overlay does not get the focus, the service starts the transparent activity instead.

## Android TV

The Android app is also the TV's: the same APK, which a TV (Android TV, Google TV, Fire OS,
the Android set-top boxes and projectors) finds in its launcher by `LEANBACK_LAUNCHER` and
its banner. It needs no touch screen and no camera, and every control takes the D-pad's
focus, with a ring in the accent colour around the focused one. The app tells a TV by
`UiModeManager` and then differs from a phone in a few ways:

- **Joining.** The start screen offers only to join a phone's group: the TV shows its QR
  code and an admin phone scans it in Add a device, so nothing is typed on the TV. It joins
  as a plain member, without an admin key, as a TV has no fingerprint or face to guard one;
  its hello says `tv`.
- **Receive only.** It starts in the receive sync mode and never sends copies of its own:
  the accessibility service there is only the remote paste target, and the settings leave
  out sending copies by themselves, the question before Share, and the watch.
- **Remote paste.** An admin pastes into the field that has the focus, as on a phone, once
  remote paste and the accessibility service are on. When no field has the focus, the
  paste is refused with a hint to open a search or text field with the remote first.

What the TV's system allows:

- **Restricted settings (Android 13 and later).** A TV that installed the APK from outside a
  store turns the accessibility service on only after App info's "Allow restricted
  settings"; on some TVs that menu sits in the system's app settings.
- **Android TV 14** may stop an accessibility service, for example after an update or to free
  memory, while the setting still says on. The app checks the list of running services: its
  settings and the refused paste then say so, and turning the service off and on again in
  the TV's settings brings it back.
- **Advanced Protection Mode (Android 17)** keeps accessibility services of apps that are
  not accessibility tools off; with it on, the TV receives copies but takes no pastes.
- **Fire TV.** Fire OS is Android and takes the signed APK of each release; Vega OS, on the
  newer Fire TV sticks, runs no Android apps, so the app does not run there.
- **Meta Quest.** Horizon OS takes the APK as a phone app and receives into the clipboard;
  whether its accessibility service may paste into other apps is not yet checked on a
  headset, so count on the clipboard only.

**To check on a device before building on it:** the D-pad's order on each screen, the
banner in the Google TV and Fire TV launchers, the accessibility service on Android TV 12 to
14 and the restricted-settings path on a TV.

## Android: the Bluetooth keyboard

The Android app can be a Bluetooth keyboard (roadmap item 25, way 3) through the HID Device
profile, `BluetoothHidDevice`. It types into a TV, a tablet, a console or a computer the
phone is paired with, and nothing is installed there. Settings, Bluetooth keyboard:

- **Act as a Bluetooth keyboard** registers the app as the phone's keyboard. Android allows
  one such app at a time, and the Bluetooth stack forgets the registration when it restarts,
  so the app registers again once and otherwise says another app may hold it.
- **Type into** lists the paired devices. "Make this phone visible" lets a new device find
  the phone for two minutes; the device then pairs from its own Bluetooth settings. A
  device that connects by itself becomes the chosen one.
- **The device's keyboard layout**: English (US) or Russian. A keyboard sends keys, not
  characters, and the device's layout turns them into characters. The key tables are the
  Nano ESP32's (`cbb_core::keyboard`), and the kit's `Keyboard` is checked against
  `testdata/interop/keyboard.json`. A text with a character the layout has no key for is
  not typed at all, and the app names the characters.
- **Speed**: 10, 20 or 40 characters a second; slow devices drop keys typed too fast. A text
  is at most 4096 characters.
- **Type the clipboard** types the phone's clipboard on the connected device.
- **Type remote pastes there** sends remote pastes from the group's admins to that device
  instead of this phone's focused field. Remote paste must be on. Keys there go straight in,
  so a line break presses Enter, and a text with one is refused unless Enter is allowed, as
  for a typed paste on a computer. The phone answers `done` once typing has started.

The phone needs Android's "Nearby devices" permission (`BLUETOOTH_CONNECT` and
`BLUETOOTH_ADVERTISE`, Android 12 and later). Some makers leave the profile out of their
builds: the Fairphone 6 and some Huawei, Honor, older Xiaomi phones and TV boxes. On these,
the profile never connects, and the app says the phone cannot act as a keyboard. With error
details on, it shows the call that failed. TVs leave this section out.

Devices that take a Bluetooth keyboard include Android and Google TV, Fire TV, iPads and
iPhones, Apple TV, Macs, Windows and Linux computers, the Steam Deck and the PlayStation 5.
The Xbox and the Nintendo Switch take only USB keyboards, so use the Nano ESP32 for them.

**To check on a device before building on it:** pairing and typing on a TV, an iPad, a Mac
and a PC; the registration after the Bluetooth stack restarts; and a phone without the
profile.

A Linux computer does the same with `cbb keyboard` (docs/reference/cli.md). It is a Bluetooth
LE keyboard: the service registers the HID over GATT service with BlueZ
(`internal/blekeyboard`). Classic Bluetooth HID would need bluetoothd's input plugin off,
which would cost the computer its own Bluetooth keyboards and mice. `cbb keyboard pair`
makes it discoverable for two minutes, with its own pairing agent as the default
meanwhile. The layouts are the same tables (`internal/keyboard`, checked against the same
vectors). The tests run against a fake BlueZ on a private bus; a real adapter and host are
not yet tried.

## A computer as a TV's remote

A computer can also type on a TV without Bluetooth, as the TV's own remote over the home
network (roadmap item 25, way 2; `cbb remote` in docs/reference/cli.md;
`internal/tvremote`). Nothing is installed on the TV, and the TV is a target of that
computer, never a member: it holds no key of the group.

- **Android TV and Google TV** speak the Android TV Remote v2 protocol of the Google TV app:
  pairing on TCP 6467 shows a six-digit code on the TV, and the remote on TCP 6466 puts a
  text into the open field through the TV's input method, with Enter as a key. Both run
  inside TLS with the computer's own RSA certificate for the TV, kept in `tvs.json` in the
  service's state; the TV's certificate is pinned at pairing, so a reset TV or another
  device at its address is refused until it pairs again. The protocol is not documented;
  `internal/tvremote/androidtv` follows its wire format as androidtvremote2 and AOSP's
  pairing code use it.
- **Roku** takes keys through its External Control Protocol, one HTTP request a character
  on port 8060. It has no pairing and no encryption, so a Roku is added only with the
  user's consent, and since Roku OS 14.1 it needs "Control by mobile apps" on.
- **Only at home.** An address outside the home network is refused when the TV is added,
  and every connection to it is checked again (`netguard.ControlHome`), whatever a name
  resolves to later.
- **Errors** name the TV and the protocol and say what to do: open a text field first, pair
  again after a reset, or turn the Roku's setting on; the underlying error is the detail, as
  everywhere.

The tests run against a fake Android TV (`androidtv/atvtest`) and a fake Roku; a real TV is
not yet tried. Samsung, LG and the Apple TV follow (roadmap item 25).

## Collections and the order of the tiles

The user can put the device tiles in their own order and gather devices into
**collections** (roadmap phase 9b). The word is not "folder",
which means a copied folder of files, nor "group", the sync group. The arrangement is a
view setting like tiles, list or orbit:

- **Kept on this installation only**, beside the app's other settings: `deviceArrangement`
  in UserDefaults on the iPhone, the iPad and the Mac, `device_arrangement` in the
  Android app's settings, `arrangement` in the tray app's `desktop.json`. It is never sent
  to the group, the hub, the forwarder or the relay. The watches show their phone's.
- **One level.** A device is in at most one collection, and a collection holds devices
  only, as folders on a phone's home screen.
- **This device** ("this phone", "this computer") always comes first and does not move.
- **Display only in 0.6**: the order, the collections, a collection tile's summary, the
  watch's sections and the remote paste device picker. Actions on a whole collection may
  come later; a remote paste to several devices never.

The model is the same in the three places that hold it: `apps/desktop/arrange.go` (the
tray app), the Kotlin kit's `Arrangement.kt` (Android) and the Swift kit's
`Arrangement.swift` (iPhone, iPad, Mac). All three pass
`testdata/arrangement/vectors.json`. It is stored as JSON:

```json
{"v": 1, "group": "<group tag>", "items": [
  {"device": "3f2a…"},
  {"collection": {"id": "c1", "name": "Office", "devices": ["9b01…", "77de…"]}},
  {"device": "a0c4…"}]}
```

The rules:

1. **View.** The stored items are shown in order. Device IDs that are not in the devices
   list are skipped, and so is a collection none of whose devices is listed (one made
   empty a moment ago stays). Listed devices that appear nowhere follow at the end of the
   top level, in the app's order, so a new device shows up last and outside every
   collection.
2. **Prune.** IDs that are not listed are dropped only when the list is whole (the group
   loaded and this device in it), so the empty list of a start or a reconnection loses
   nothing. A collection that loses its last device that way goes away.
3. **Another group** (another tag) or another version starts afresh.
4. **Limits.** At most 32 collections; a name is trimmed and has 1 to 64 bytes. Names need
   not be unique.
5. **Changes**, each checked whole and refused whole: *move* an item before another or to
   the end of its level (a device before a device in a collection joins it; a collection
   never goes into another); *into* a collection, at its end; *out* of one, right after
   it; *new* collection where its first device was, or at the end with no devices;
   *rename*; *ungroup*, which puts the devices where the collection was; and *reset*,
   which brings back the app's order and keeps the collections, each where its first
   device now comes. A collection that a move or *out* empties goes away. New
   collections take the smallest free ID `cN`.
6. **The default.** Until the user changes something nothing is stored, and the order is
   the app's as before.

The apps reach every change in an Arrange mode, with a menu path, VoiceOver and TalkBack
actions and the keyboard for each drag.

**On the iPhone and the iPad** (`Views/Arrange.swift`, the model in `AppModel`):

- Arrange mode starts from **Arrange devices** in the "…" menu or **Arrange** in a tile's
  menu (a long press), and ends with **Done**. In it a tap does not open a tile, tiles have
  a dashed outline, and a drag moves a tile as it passes the others; a device dropped on a
  collection goes into it. The drag carries a type of its own that stays in the app.
- Each tile's menu has every change without a drag: **Move to collection** (each
  collection, or **New collection…**), **Take out of collection**, **Move to start**,
  **Move to end**, and on a collection **Rename collection…** and **Ungroup**. In Arrange
  mode VoiceOver has the actions Move earlier, Move later, Move to start, Move to end and
  Take out of collection.
- A collection tile shows up to four of its devices' icons, its name, "2 of 5 online" and
  the danger colour's mark when a device inside needs attention (it is frozen). In the
  list a collection is a section with a header. A tap opens its page, with its devices,
  Arrange mode for them, Rename and Ungroup.
- With more than 12 devices Home has a search (names and systems) and the filters
  **Online** and **Needs attention**; their results are flat, and Arrange mode is off
  while one is on.
- **Back to the group's order** in the "…" menu is *reset*.
- The orbit on a big screen keeps the group's order for now.

**On Android** (`Arrange.kt`, the model in `AppModel`, kept as `device_arrangement`):

- Arrange mode starts from **Arrange devices** in the ⇅ menu beside the view button or
  **Arrange** in a tile's menu (a long press), and ends with **Done**. In it a tap does
  not open a tile, tiles have a dashed outline, and a long press then a drag carries a
  tile over the others; it takes the place of the tile it is dropped on, and a device
  dropped on a collection goes into it.
- Each tile's menu has every change without a drag, as on the iPhone; in Arrange mode
  each tile also has a ⋮ button for it, which a keyboard or the D-pad reaches. TalkBack
  has the actions Move earlier, Move later, Move to start, Move to end and Take out of
  collection.
- The collection tile, the list's sections, the collection's page, the search and filters
  and **Back to the group's order** are the iPhone's. The orbit keeps the group's order.

**In the tray app** (`frontend/app.js`, the model in `arrange.go` through `Desk.Arrange`,
kept as `arrangement` in `desktop.json`, which the window's other settings never
overwrite):

- The ⇅ button beside the views turns Arrange mode on and off, and Escape ends it. In it
  a click does not open a tile, tiles and rows have a dashed outline and are dragged, a
  device dropped on a collection goes into it, and the bar on top has **Back to the
  group's order** and **Done**.
- A right click on a tile, or its ⋮ button in Arrange mode, opens its menu with every
  change. With the keyboard, Alt and the arrow keys move the focused tile, and Alt with
  Home or End moves it to the start or the end.
- A collection is a tile or a section in the list, and a click opens its page, with its
  devices, Arrange mode for them and its menu. The search and filters come with more than
  12 devices. The orbit keeps the group's order.

**In the Mac app** (`Views/Arrange.swift`, the model in `MacModel`, which builds the Swift
kit's `Arrangement.swift` in; kept as `deviceArrangement` in its defaults): as on the
iPhone, with **Arrange devices** and **Back to the group's order** in the toolbar, each
tile's menu on a right click, and Option with the arrow keys, Home or End moving the
focused tile in Arrange mode.

**On the watches**: the phone sends its devices in the user's order, each with the name
of its collection (`collection` in WatchState, absent from a phone before 0.6), and the
watch lists the devices in no collection under **Devices**, then a section for each
collection. The watch does not change the arrangement.

## Releasing the Android app

Each release carries `clipboardbridge-X.Y.Z.apk` and the Wear OS app,
`clipboardbridge-wear-X.Y.Z.apk`, both signed with the project's release key; the key and
its secrets are in [maintaining.md](maintaining.md#android-signing-key). The watch app is
installed on the watch with `adb install` over the watch's wireless debugging until the apps
are on Google Play.

### Updates

An APK installed from a release updates itself (`ApkUpdate.kt`): Settings, "Updates", checks
for a newer release, and "Update automatically" (off until the user turns it on) checks once a
day when the app comes to the front and installs what it finds. Each check fetches the signed
`keys.json`, `stable.json` and `release.json` from GitHub, else `dl.cbb.tools`, and checks them
as `cbb update` does (docs/protocol.md, section 16), sending no version, system or group data.
The release's `clipboardbridge-X.Y.Z.apk` must match release.json's size and SHA-256, be this
app with a higher version code, and carry this app's signing certificate before the system's
`PackageInstaller` gets it with `USER_ACTION_NOT_REQUIRED`: the system asks only for the first
update after an install from elsewhere, which also lets the app install updates ("Install
unknown apps"). A copy that a store installed (Google Play, F-Droid, Amazon, Samsung, Huawei,
Aurora) is left to its store and shows no section, and so do the F-Droid build, wherever it
came from, and a build without the project's root keys. From 2027 a sideloaded app installs only when its developer is registered in
Google's developer verification; the project's registration is under way.

**To check on a device before building on it:** the first update's question, the second
update without one, the question when the app is in the background, and an APK signed with
another key refused with its message.

### F-Droid

One source gives two builds of the app, two Gradle flavors of `apps/android/app`:

- **full**, `clipboardbridge-X.Y.Z.apk`: the releases on GitHub and, later, the stores. It
  has the Wear OS watch, through `play-services-wearable` (`src/full`: `WatchLink.kt` and its
  service in the manifest), and its own update with the installer's permissions.
- **fdroid**, `clipboardbridge-fdroid-X.Y.Z.apk`: no Google Play services and no other
  non-free code, which F-Droid requires. Its `WatchLink` (`src/fdroid`) reaches no watch, so
  Settings offers none; `BuildConfig.SELF_UPDATE` is false and it has no installer
  permission, so it leaves its updates to F-Droid. Everything else is the same code.

F-Droid builds the fdroid flavor itself from each release's tag, by the recipe in
`packaging/fdroid` (in fdroiddata once accepted), and checks it against our
`clipboardbridge-fdroid-X.Y.Z.apk`: when the two are the same apart from the signature, it
publishes ours. Both builds carry the same application id and key, so a phone moves between
them by installing the other one over it, the group and the settings kept; F-Droid offers
its updates to either. That needs the build to be reproducible:

- the version in the source, `apps/android/version.properties`, which the release pull
  request moves on with `CHANGELOG.md` (`tools/repocheck` checks the two agree);
- the tunnel's library built with one NDK, `cbb.ndk` in `apps/android/gradle.properties`,
  and the Go of go.mod's `toolchain` line, with `-trimpath`, no VCS stamp and from one
  path, `/tmp/cbbtun-bind`, a link to the checkout (gomobile's go.mod names the module's
  directory, which goes into the library's build info);
- the Rust core's libraries (`lite/ffi`) built with the same NDK and the Rust of `cbb.rust`
  there, with the paths of the checkout and of cargo's sources written as fixed names
  (`lite/ffi/bind.sh`);
- no dependency block (`dependenciesInfo`) and no commit details (`vcsInfo`) in the APK.

CI's `fdroid` job builds the fdroid APK twice, the second time from a copy without `.git` in
another directory, time zone and umask, and fails when the two differ
(`packaging/fdroid/reproduce.sh`); the `android` job checks that its dependencies carry no
Google Play services. The store texts and the icon are F-Droid's fastlane layout in
`apps/android/app/fastlane/metadata/android`, in English and Russian; screenshots wait for
the app on real devices.

## Languages

- Every user-facing string comes from the platform's catalog from the first screen on: a
  String Catalog (`Localizable.xcstrings`) on iOS, `strings.xml` resources on Android. No
  string literal in views.
- English is the source language; Russian is the first translation. Plurals, numbers and
  dates use the platform's formatters.
- The layout survives longer translations and right-to-left scripts (no fixed widths for
  text; leading and trailing, not left and right).
- The language follows the system, with an in-app choice (System, English, Russian) in
  Settings, and on the Start screen when the system's language has no translation.

## Themes

- Colours, type, spacing and corner radii are design tokens, defined once in
  `apps/design/tokens.json` and generated into Swift and Kotlin, so both apps match.
- One style, **Glass**, in ten colours: Terminal (the default, green), Midnight, Amber,
  Ocean, Teal, Coral, Rose, Lime, Graphite and Ruby. Each colour has a dark and a light
  palette; the theme is System (the system's light or dark mode), Dark or Light.
- `tokens.json` holds each colour's accent for dark and light and the two neutral bases; the
  generator mixes a little of the accent into the background and the surfaces, so adding a
  colour is one line of data.
- On Android 12 and later a further choice, **Wallpaper** (Material You), takes the colours
  from the wallpaper through dynamic colour, in place of one of the ten.
- Android has no Liquid Glass: its tiles and cards are the palette's glass colour with a
  hairline, as the iPhone app draws them before iOS 26, over the same glow of the accent.
- Contrast meets WCAG AA for text in every palette; the generator checks it.

## Layout of the repository

- `apps/ios/` — the app (SwiftUI): `project.yml` describes the Xcode project for XcodeGen
  (`cd apps/ios && xcodegen generate`; the generated project is not committed), built and
  tested on an iPhone simulator in CI without signing; and
  `apps/ios/ClipboardBridgeKit`, the Swift package with the protocol core (CPace, the pairing
  frames, the join QR code, the member protocol and the phone's sync engine). It has no UI
  and runs on Linux too; its tests check it against the vectors that the Go tests write to
  `testdata/interop/` (`go test ./internal/group ./internal/pair ./internal/phone ./internal/node -update`
  regenerates them), and CI runs it against the Go code: pairing over plain TCP on Linux,
  pairing and a member connection over real TLS on macOS.
- The app finds the full members by browsing `_clipboardbridge._tcp` (ClipboardBridgeKit's
  `BonjourBrowser` on iOS) and keeps one connection to each member of its group
  (`MemberDialer`). iOS asks once for local network access: the Info.plist lists
  `_clipboardbridge._tcp` under `NSBonjourServices` and explains the use in
  `NSLocalNetworkUsageDescription`.
- A phone joins another phone's group from its Start screen ("I already use Clipboard Bridge on
  another phone"):
  it makes its admin key, listens with `TLSListener` on a port the system picks, and shows
  the join QR code with its home network addresses (`LocalAddresses`). An admin phone scans
  it in "Add a device". The root phone makes every phone it admits an admin; an admin that
  is not the root admits phones as plain members. An admin phone that removes the root
  phone takes the group over (`PhoneGroup.takeOver`, docs/records-v2.md): it makes a new
  root key in the Secure Enclave behind Face ID and signs a claim with its admin key. The
  claim waits as long as the root decided (72 hours by default, `setTakeoverDelay`), and the
  root's phone may cancel it (`resolve`). Once the wait is over the app finishes the takeover
  by itself (`finishTakeOver`): as the new root it signs its own record, keeps the other
  admins and removes the lost phone. The kit keeps the records file and asks the Rust core
  what it says (`RecordSet`, docs/core-api.md, "The record set"); the Android kit does the
  same, with its root key in the Keystore behind BiometricPrompt.
- `apps/android/` — the Gradle project (Kotlin, Compose), built and tested in CI on Linux;
  the app's `src/full` and `src/fdroid` hold what its two builds do differently, and
  `packaging/fdroid` the F-Droid recipe.
- `apps/macos/` — the Mac app (SwiftUI): `project.yml` for XcodeGen, like the iPhone app's.
- `apps/desktop/` — the tray app for Linux and Windows (Go, Wails 3), a Go module of its own.
- `apps/design/` — tokens and the icon (`icon/light.png` and `icon/dark.png`, the clipboard
  drawings; `go run ./tools/icon` sets each on a fill of its colour as the iPhone app's icon
  for light and dark mode, and the Android app takes the same drawings; `icon/tray/` holds the single-colour glyph of
  the Mac's menu bar and the tray in three states, which the tool copies into the Mac app's asset catalog as template
  images and turns into the tray's symbolic SVGs for Linux and white and black ICOs for Windows in `apps/desktop/trayicon`); `go run ./tools/tokens` turns `tokens.json` into
  `apps/ios/ClipboardBridge/Theme/Tokens.swift` and the Android apps' `Tokens.kt` and fails when a palette misses the
  WCAG AA contrast, and CI checks that the generated files are up to date; `apps/l10n/` — the shared glossary of terms, so
  both apps use the same words.
- The protocol both apps speak is [protocol.md](protocol.md).
