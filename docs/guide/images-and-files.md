<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Images, files and formatted text

For anyone who copies more than plain text. On this page, you learn which content types sync
between computers and phones, how to send and save images and files from the command line or a
phone, and how to change per-device size limits.

When you copy an image, files from a file manager, or formatted text on one device, the copying
device seals the content end to end and announces it to your group. Other devices with **Sync** on
fetch it automatically up to their size limits. For how end-to-end encryption works, see
[How it works](how-it-works.md#what-happens-when-you-copy).

## What goes where

| Copied content | Computers with a desktop | Phones | Computers and small devices without a desktop |
|---|---|---|---|
| **Formatted text** (HTML from a browser or office app) | Pasted with formatting (up to 8 MiB of HTML) | Pasted as plain text | Plain text |
| **Image** (PNG, JPEG, GIF; TIFF on macOS and HEIC on phones are converted) | Pasted directly as an image | Syncs to the clipboard when you open **CBB** or tap the sync button; also saved to the gallery on Android and Aurora OS or **Photos** on iPhone when received as a file | Plain text only; save the image with `cbb paste -o DIR` |
| **Files and folders** | Pasted as files in a file manager or app | **Android:** saved in `Downloads/CBB` (a single image or video goes to the `CBB` gallery album). **iPhone:** saved in **Files > On My iPhone > CBB** (a single image or video goes to **Photos**). **Aurora OS:** saved in `Downloads/CBB` (images in the gallery). **HarmonyOS:** saved with the **Save the received files** button | Save with `cbb paste -o DIR` |

Cutting files in a file manager is treated as a copy: Connect Beyond Borders never deletes source
files on any device. When a desktop clipboard contains both text and an image without separate
file selection, plain text takes precedence unless an image is copied explicitly.

## Send and save from a phone

1. **Send files or images from a phone:** Open a file manager, gallery, or other app, choose
   **Share > Connect Beyond Borders**, and confirm if asked. On Android, iPhone, Aurora OS, and
   HarmonyOS, shared images and files sync to your group's computers.
2. **Save files received on a phone:** Open **CBB** (or trigger sync). On Android, iPhone, and
   Aurora OS, files save automatically to the locations in the table above. On HarmonyOS, tap
   **Save the received files** on **Home** when notified that files are ready.

**Result:** Shared images appear on your computers' clipboards, and received files appear in your
phone's downloads, files, or gallery folder.

## Send and save from the command line

Run these commands on any computer or small device without `sudo`:

1. **Send files and folders as one copy:**

   ```sh
   cbb copy photo.jpg notes/
   ```

   Add `-text "summary"` to include a plain-text fallback for devices that take text only.

   **Result:** Connect Beyond Borders prints how many files and bytes it copied to the group.

2. **Send a single image or HTML file as clipboard data:**

   ```sh
   cbb copy -type png screenshot.png
   ```

   `-type` accepts `png`, `jpeg` (or `jpg`), `gif`, or `html`.

   **Result:** Desktop computers receive the file as clipboard image or HTML data rather than as a
   file attachment.

3. **Save the clipboard's current images or files to a folder:**

   ```sh
   cbb paste -o ~/Downloads
   ```

   **Result:** `cbb` waits if the copy is still transferring, writes files and folders by their
   names (or `image.png`, `image.jpg`, `image.gif`, or `clipboard.html` for clipboard data), and
   prints each top-level path it created. It never overwrites existing files and makes nothing
   executable.

4. **Check transfer progress:** Run `cbb status` to see if a large copy is still arriving or was
   skipped because it exceeds this device's size limit.

## Change size limits

Each device enforces its own size limits for images and files. Away from home, the hub's
`max-copy-away` limit caps every device that connects through that hub.

| Scope | Default | Allowed range | How to change |
|---|---|---|---|
| **At home** (computers and small devices) | 100 MiB per copy | 1 MiB to 1 GiB | `cbb config max-copy SIZE` |
| **Through the group's tunnel** (computers, small devices, and hubs) | 25 MiB per copy | 1 MiB to `max-copy` | `cbb config max-copy-away SIZE` |
| **Phone share sheet** | 100 MiB on Android; 50 MB on iPhone, Aurora OS, and HarmonyOS | Fixed | Cannot be changed |

To view or change limits on a computer:

1. View the current limits:

   ```sh
   cbb config
   ```

2. Raise or lower a limit (for example, to 250 MiB at home or 50 MiB away from home):

   ```sh
   cbb config max-copy 250MiB
   cbb config max-copy-away 50MiB
   ```

**Result:** The device applies the new limit immediately. Lowering `max-copy` below `max-copy-away`
lowers `max-copy-away` to match. Copies larger than a device's limit are not fetched on that
device, and `cbb status` notes that the copy was skipped.

For all copy size and part limits (including the 10,000-part limit and 256 KiB fallback text
limit), see [Limits and lifetimes](../reference/limits.md#copies).

## Safety

- **Private temporary storage:** On desktop computers, the clipboard agent unpacks received files
  into a private folder inside your user cache (`~/.cache/cbb/received` on Linux and FreeBSD,
  `~/Library/Caches/cbb/received` on macOS, `%LocalAppData%\cbb\received` on Windows) readable
  only by your user, and deletes older copy folders 10 minutes after a newer copy arrives.
- **Download warnings:** Received files are never marked executable. macOS adds the
  `com.apple.quarantine` attribute and Windows adds the Mark of the Web (`Zone.Identifier`) so the
  operating system warns before opening a received program.
- **Safe filenames:** Connect Beyond Borders sanitizes filenames across operating systems and
  skips symbolic links and special files inside copied folders.
- **Plain-text secrets:** Formatting is never read for secrets; a secret travels as plain text
  only.
- **Service cache:** The background service keeps at most the last 8 sealed copy blobs in its state
  directory while running and empties that cache on every restart.
