<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Images, files and formatted text

For anyone who copies more than plain text. A picture, files from a file manager or text
with its formatting, copied on one device, can be pasted on the others as they are.

## What goes where

| Copied | Computers with a desktop | Phones | A computer without a desktop | Lite member |
|---|---|---|---|---|
| Text with its formatting (a browser, an office program) | pasted with its formatting | pasted as plain text | plain text | plain text |
| An image (PNG, JPEG; TIFF on a Mac, HEIC on a phone are converted) | pasted as the image | the app's button pastes it; it also comes by itself, on the iPhone while the app runs | only its text; `cbb paste -o DIR` saves the image | only its text; it passes the image on |
| Files and folders | pasted as copied files | the app saves them: Downloads on Android, the app's folder in Files on the iPhone | `cbb paste -o DIR` saves them | passes them on, keeps none |

A copy with a text and an image goes as text. A cut in a file manager is taken as a copy:
nothing is deleted anywhere.

## How it travels

The copy itself stays on the device where it was made. The others learn that there is a new
copy, with its size, and those with sync on fetch it at once
from that device, or from another that has it, over the same encrypted connections as the
text.

Away from home, the hub fetches each copy and passes it on through the group's tunnel, up to
its own limit.

## Sizes

| Where | Default | Change it on each device |
|---|---|---|
| At home | 100 MiB per copy | `cbb config max-copy SIZE`, 1 MiB to 1 GiB |
| Through the group's tunnel | 25 MiB per copy | `cbb config max-copy-away SIZE`, at most `max-copy` |
| From the phones' share sheet | 100 MiB on Android, 50 MB from the iPhone | no |

A copy over a device's limit is not fetched there, and `cbb status` says so. The hub's
`max-copy-away` caps every device that reaches it from afar. All the limits are in
[limits and lifetimes](../reference/limits.md#copies).

## From the command line

```sh
cbb copy photo.jpg notes/              # sends files and folders as one copy
cbb copy -type png screenshot.png      # sends one image as an image
cbb paste -o ~/Downloads               # saves the clipboard's images or files there
cbb status                             # shows a copy that is still arriving
```

`cbb paste -o` waits while a copy is still arriving, never replaces a file and makes nothing
executable.

## Safety

- Received files are saved in a folder of their own in your user's cache, readable only by
  you, and removed 10 minutes after a newer copy. A Mac marks them as downloaded
  (quarantine) and Windows with the Mark of the Web, so the system warns before opening a
  program among them. Nothing is made executable.
- Names are made safe for every system, and links and special files in a folder are left
  out.
- A secret's formatting is never read; a secret goes as plain text only.
- The service keeps the current copy and older ones for 10 minutes in its state directory,
  and nothing after a restart.
