<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Remote paste

For anyone who wants to paste text, images, or files from a phone or admin computer straight into
the focused app on another computer—for example, a password into a login field, a command into a
terminal, or a screenshot into a chat.

An admin signs the paste request, and the target computer puts the content where its keyboard
focus is by pasting or typing key by key. Remote paste is off on every computer until that
computer's own user turns it on locally; nobody can enable it remotely. Phones send remote pastes
to computers and do not receive remote pastes.

## 1. Turn remote paste on at the target computer

Run the setup for the target computer's operating system:

| Target system | Setup steps | Where pastes land |
|---|---|---|
| **Linux** | Run `sudo cbb paste-receive on` | The focused desktop app (X11, Wayland, GNOME, KDE), the active `tmux` pane, and (with `-console`) the Linux text console |
| **FreeBSD** | Run `sudo cbb paste-receive on` | The focused app on X11 and wlroots Wayland compositors (such as sway and Hyprland); GNOME on FreeBSD is not supported because lock-screen state is unavailable |
| **Windows** | Open a terminal as administrator and run `cbb paste-receive on` | The focused window |
| **macOS** | Run `sudo cbb paste-receive on`, keep the **CBB** menu bar app open, and allow it in **System Settings > Privacy & Security > Accessibility** | The focused app |
| **Small Linux device without a desktop** | Run `sudo cbb paste-receive on` (add `-console` for the Linux text console) | The active `tmux` pane or text console |

Optional flags for `cbb paste-receive on`:

- `-enter`: Allows a remote paste to press Enter after the content. Without `-enter`, any text
  containing a line break is refused so a paste cannot accidentally run a command in a terminal.
- `-console`: Allows remote paste into the Linux text console and `root`'s `tmux` sessions (not
  available on rootless installs).
- `-no-lock-check`: On Linux and FreeBSD without `logind`, allows remote paste when the system
  cannot report session lock state (a running screen locker still blocks pastes).

**Result:** Run `cbb paste-receive` with no arguments to confirm that remote paste is on and see
which options are active.

### Extra helpers on Linux

- **GNOME and KDE desktop dialogs:** The first remote paste opens your desktop's remote-control
  confirmation dialog; allow it once so the desktop remembers it. To skip that dialog (and allow
  keystrokes on desktops without another input path), reinstall with `--uinput`:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --uinput
  ```

  This adds `cbb-uinput.service`, a virtual keyboard that presses only Shift+Insert and Enter for
  the signed-in user.
- **Headless `tmux` and text consoles:** Every Linux install adds Connect Beyond Borders' hook to
  `/etc/tmux.conf` so `tmux` starts its paste helper automatically. For the Linux text console,
  install with `--console` (see [Installing on Linux](install.md#linux)).

## 2. Send a remote paste from an admin

### From an admin computer

Run `cbb paste -on DEVICE` in a terminal (`DEVICE` is the target's name or device ID from
`cbb status`):

```sh
echo 'the text' | cbb paste -on DEVICE              # paste text from standard input
cbb paste -on DEVICE                                # paste this computer's clipboard text
cbb paste -on DEVICE -type < note.txt               # type text key by key (up to 4 KiB)
cbb paste -on DEVICE -enter -secret < pass.txt      # paste as a secret and press Enter
cbb paste -on DEVICE photo.jpg notes/               # paste files into the focused app
cbb paste -on DEVICE -image screenshot.png          # paste a PNG or JPEG as an image
cbb paste -on DEVICE -copy                          # paste the group's current image or files
```

**Result:** The command prints `Pasted on DEVICE.` when the target accepts and delivers the paste,
or reports the exact reason the target refused it.

### From an admin phone

1. Open **CBB**, tap the target computer on **Home**, and tap **Paste on it…**.
2. Choose what to send:
   - **Text:** Type the text (or leave the text field empty to send your phone's clipboard),
     optionally select typing key by key, **A secret**, or **Press Enter after it**, and tap
     **Paste**.
   - **Images or files:** Tap **Paste a picture or files…** (on iPhone, **Paste a picture…** or
     **Paste files…**) and pick the items.
3. Confirm with your face, fingerprint, passcode, or (on Aurora OS) your admin PIN.

On iPhone, set **Settings > Apps > CBB > Paste from Other Apps** to **Allow** so iOS does not ask
every time the app reads your clipboard.

**Result:** The target computer pastes or types the content into its focused window and the app
shows **Pasted.**

### Pasting versus typing

- **Paste** works in most desktop apps and supports text (up to 1 MiB), images, and files.
- **Type** (`-type`) sends keystrokes one by one (text only, up to 4 KiB) for apps that block
  clipboard paste. Typing works across keyboard layouts on X11, Wayland compositors with a virtual
  keyboard protocol, Windows, and macOS. On GNOME and KDE through the system remote-control
  dialog, pasting works while typing is unavailable.

## When a target refuses a paste

A target computer refuses a remote paste when:

- Its screen is locked, a screen saver is active, or a login screen is showing.
- On Windows, the focused window runs as administrator or an administrator elevation prompt is
  open.
- On macOS, a password field or Secure Keyboard Entry holds keyboard focus.
- Nobody is attached to `tmux` or logged in on the text console (on headless targets).
- The text contains a line break and `-enter` is not enabled on the target.
- One sender exceeds the rate limit of **1 paste per second** or **30 pastes per minute**.

The error returned to the sender names the reason.

## Safety and turning remote paste off

- **Limit your admins:** Any admin in your group can type into a computer while remote paste is on.
  Enable remote paste only on computers where you need it, and keep your list of admins short.
- **Paste audit log:** Each target records its last 100 paste requests (sender, timestamp, length,
  method, and result—never the pasted text). Secrets leave no trace in the target's clipboard
  after pasting.
- **Turn off locally:** Run `sudo cbb paste-receive off` on the target computer (turning it off
  also resets `-enter`, `-console`, and `-no-lock-check`).
- **Turn off remotely from any admin:** Run `sudo cbb paste-receive off -on DEVICE` (or `-all` to
  turn remote paste off on every computer in the group). Only each computer's own user can turn it
  back on.

For exact size and rate limits, see
[Limits and lifetimes](../reference/limits.md#remote-paste-and-quick-actions). For how remote
paste works internally, see [Design: remote paste](../design.md#remote-paste).
