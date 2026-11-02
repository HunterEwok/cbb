<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Remote paste

For anyone who wants to put a text into an app on another device: a password into a TV's
login form, a command into a server's terminal, an address into a computer across the room.
An admin of the group sends the text, and it lands where that device's focus is, pasted or
typed key by key.

Remote paste is off on every device until its own user turns it on there. Nobody can turn
it on from afar.

## Turn it on where the text should land

| Device | How | What it pastes into |
|---|---|---|
| Linux | `sudo cbb paste-receive on` | the focused app of the desktop (X11, Wayland, GNOME and KDE), the active tmux pane; with `-console`, the text console too |
| FreeBSD | `sudo cbb paste-receive on` | the focused app on X11 and on wlroots desktops (sway, Hyprland); not GNOME, since nothing there tells whether its screen is locked |
| Windows | `cbb paste-receive on` in a terminal opened as administrator | the window that has the focus |
| Mac | `sudo cbb paste-receive on`, and the Mac app open, allowed in System Settings, Privacy & Security, Accessibility | the app that has the focus |
| Android phone or TV | Settings, "Let the group's admins paste here", and the app's accessibility service on | the text field that has the focus in another app |
| Lite member | `sudo cbb paste-receive on`; with `-console`, the text console too | the tmux pane in use |

`-enter` (on a phone, "Let a paste press Enter") lets a paste press Enter after the text.
Without it a text with a line break is refused, because a line break may run what comes
before it as a command wherever a terminal does not take the paste as one piece.

On GNOME and KDE the first paste opens the system's dialog for remote control on the screen;
allow it once and it is remembered. To skip the dialog, install the uinput helper:
install again with `--uinput`
(`curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh -s -- --uinput`),
which adds a virtual keyboard that presses only
Shift+Insert and Enter for the user on the screen.

Without a desktop, tmux and the text console need their helpers. Every installation adds
Clipboard Bridge's part of `/etc/tmux.conf`, which starts the tmux helper with tmux;
`install.sh --console` adds the console helper's service.

## Paste from an admin

On an admin computer:

```sh
echo 'the text' | cbb paste -on DEVICE          # pastes it
cbb paste -on DEVICE                            # pastes this computer's clipboard text
cbb paste -on DEVICE -type < note.txt           # types it key by key, up to 4 KiB
cbb paste -on DEVICE -enter -secret < pass.txt  # presses Enter after it; kept as a secret
```

`DEVICE` is the device's name or its ID from `cbb status`. The command says when the text is
in, or why the device refused it.

On an admin phone, open the device's page and choose "Paste on it…": type the text, or leave
the field empty to send what the clipboard holds, choose paste or type, and confirm with Face
ID or the fingerprint. An iPhone asks each time whether the app may read the clipboard, until
Settings, Apps, CBB, "Paste from Other Apps" is set to Allow.

Typing works in any keyboard layout on X11, Wayland compositors with a virtual keyboard,
Windows and the Mac. On GNOME and KDE through the dialog, a paste works but typing does not,
since the keys would follow the user's layout.

## When it is refused

A device never pastes:

- while its screen is locked, a screen saver or a login screen is on;
- into a window that runs as administrator on Windows, or under an administrator prompt;
- on a Mac while a password field or Secure Keyboard Entry holds the keyboard;
- when nobody is attached to tmux or logged in on the console;
- more than once a second, or more than 30 times a minute, from one sender.

The answer on the sender says which one it was.

## Safety

- Whoever is an admin of your group can type into your device while remote paste is on, as
  if at your keyboard. Turn it on only where you need it, and keep the list of admins short.
- Each device keeps a log of its last 100 pastes: who sent them and when, never the text.
  Android also names the sender in a notification.
- Any admin can turn remote paste off on another device or on all of them, for example
  when a phone is lost: `cbb paste-receive off -on DEVICE` or `-all`. Only the device's own
  user turns it on again.

The limits are in [limits and lifetimes](../reference/limits.md#remote-paste-and-quick-actions);
how it works inside is in the [design](../design.md#remote-paste).
