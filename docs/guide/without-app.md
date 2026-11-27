<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Without the app

For anyone who wants to create and manage a Connect Beyond Borders group using computers only,
without a phone app. On this page, you create a group on one computer, add more computers on your
home network, set up a second admin, and add computers from another network over SSH or a VPN.

![A Linux computer holds the group and adds the Mac and Windows by a six-digit code](../images/without-app.svg)

A computer that creates a group becomes its **main device** (called *root* in command-line tools). A [rootless Linux install](install.md#without-sudo-rootless) can never be the main
device or an admin, and a Docker container requires `CBB_KEYS_IN_FILE=yes` in its environment
before holding group keys.

## 1. Create the group on a computer

Pick a computer that is on regularly (Linux, macOS, Windows, or FreeBSD) and
[install Connect Beyond Borders](install.md).

1. Run on that computer (omit `sudo` in an administrator terminal on Windows, or click **Create a
   group** in the Mac app or tray app):

   ```sh
   sudo cbb new
   ```

2. Save the **recovery sheet** shown on screen—four lines of letters and digits plus a QR code.
   Print or write it down and store it separately from your devices.

**Result:** This computer becomes the group's main device. On a Mac with Apple silicon or a T2
chip, or a Linux or Windows PC with a TPM 2.0, its keys live in security hardware; otherwise they
live in protected files (`cbb keys` starts at `files`; see [Keys and attestation](keys.md)).
Nothing keeps a copy of the recovery sheet—it is the only way to move the group if this computer
is lost.

## 2. Add computers on your home network

Install Connect Beyond Borders on each additional computer on the same home network, then pair it:

1. On the main device (or any admin computer), open a pairing window:

   ```sh
   sudo cbb pair
   ```

   **Result:** The terminal displays a 6-digit pairing code and a QR code, and waits for 5 minutes.
   You can also open a pairing window from the **+** button in the Mac app or tray app.

2. On the new computer, join the group:
   - **Terminal:** Run `sudo cbb pair -code` (omit `sudo` in an administrator terminal on Windows)
     and type the 6 digits when prompted.
   - **Desktop app:** Open **CBB**, choose **Join a group**, and type the 6 digits.

   Each wrong code uses one of 3 attempts; the window closes after 3 failed attempts or as soon as
   a device joins.

**Result:** Both computers confirm the join, and your clipboards sync automatically. Copy text on
one computer and paste it on the other to verify (see
[Quick start: copy on one, paste on another](quickstart.md#4-copy-on-one-paste-on-another)).

## 3. Add a second admin and keep your recovery sheet safe

Promote a second computer to **admin** so you can still add and remove devices when the main
device is offline. Note that a computer can be promoted to admin only if it paired directly with
the main device.

1. Find the computer's name or device ID with `cbb status`.
2. On the main device, promote the computer:
   - **Computer with a TPM 2.0 or Secure Enclave:**

     ```sh
     sudo cbb admin NAME
     ```

   - **Computer whose keys live in files** (requires key level `files`, set with `sudo cbb keys
     files`):

     ```sh
     sudo cbb admin -allow-file-key NAME
     ```

     Anyone who copies a file-key admin's key files can act as an admin until another admin
     removes that computer, so promote only computers you keep physically secure and disk-encrypted.

**Result:** `cbb status` lists the second computer as an admin, and it can run `sudo cbb pair` and
`sudo cbb remove NAME` for ordinary members.

If the main device is ever lost or broken, move the group to another computer in the group using
your recovery sheet:

```sh
sudo cbb recovery -leave LOST-DEVICE
```

Then type the recovery key from the sheet when prompted (or pass `-yubikey` if you sealed it on a
YubiKey). See [If a device is lost or stolen](lost-device.md) for the complete procedure.

## Joining from another network

To add a computer that is not on your home network, you can send an
[invitation through a hub](away-from-home.md#a-computer-that-is-not-at-home-an-invitation), or pair
through an SSH tunnel or your own VPN.

### Over SSH

1. On the new computer, forward a local port to the main device's or admin's member port (8764 by
   default):

   ```sh
   ssh -N -L 18764:localhost:8764 user@admin-machine
   ```

2. In a separate SSH session on the main device or admin computer, open a pairing window:

   ```sh
   sudo cbb pair
   ```

   Copy the full `cbb://pair?...` line printed beneath the 6 digits. (Without local network
   discovery, the 6 digits alone cannot identify the window; the `cbb://pair?...` line carries
   both the window details and the code.)

3. On the new computer, join through the forwarded port and paste the `cbb://pair?...` line when
   prompted:

   ```sh
   sudo cbb pair -code 127.0.0.1:18764
   ```

**Result:** The new computer joins the group over the SSH tunnel inside TLS 1.3.

### Over your own VPN

1. On Linux, if you set up the VPN after installing Connect Beyond Borders, re-run the installer so
   the firewall rules allow your VPN subnet.
2. On the main device or admin computer, run `sudo cbb pair` and copy the `cbb://pair?...` line
   printed beneath the 6 digits.
3. On the new computer, join using the admin computer's VPN address and port, and paste the
   `cbb://pair?...` line when prompted:

   ```sh
   sudo cbb pair -code ADMIN-VPN-ADDRESS:8764
   ```

**Result:** The new computer joins your group over the VPN inside TLS 1.3.

The pairing secret never travels in the clear: both computers derive session proof inside TLS 1.3.
The new computer continues syncing over the temporary pairing path until its service restarts; to
keep syncing permanently after closing SSH or your VPN, set up
[sync away from home](away-from-home.md) on both devices first.
