<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Troubleshooting

For anyone whose devices are not syncing, failing to pair, or returning errors. Each entry below
lists the **symptom**, **cause**, and **fix**.

## Start with diagnostics

Before changing settings, check what Connect Beyond Borders reports:

- **In a phone or desktop app:** Open **Settings**, turn on **Advanced settings**, and check **Why
  it does not sync** for a plain-language explanation and next step. To show underlying technical
  errors under short messages, tap **Version** seven times in **Settings** and turn on **Show
  error details**.
- **In a terminal:** Run `cbb status` to see whether the service is running, your group status,
  connected devices, and away-from-home state. Prefix any command with `CBB_DEBUG=1` (on Windows
  PowerShell, run `$env:CBB_DEBUG = "1"` first) to print the underlying error:

  ```sh
  CBB_DEBUG=1 cbb status
  ```

- **Check service logs:** On Linux, run `journalctl -u cbb` for the service and
  `journalctl --user` for the desktop clipboard agent. Log paths for macOS, Windows, FreeBSD, and
  OpenWrt are in [Devices, ports and files](../reference/devices.md#files-and-logs), and debug
  switches for every component are in [Error messages and details](../reference/errors.md).

## Commands and service

### "the Connect Beyond Borders service is not running"

- **Cause:** The background service is stopped or failed to start.
- **Fix:** Start the service for your operating system and inspect its log if it exits again:
  - **Linux:** `sudo systemctl start cbb` (rootless: `systemctl --user start cbb`)
  - **macOS:** `sudo launchctl kickstart -k system/tools.cbb`
  - **Windows (administrator PowerShell):** `Start-Service cbb`
  - **FreeBSD:** `sudo service cbb start`
  - **OpenWrt:** `/etc/init.d/cbb start`

### "permission denied" on the control socket after installing

- **Cause:** The installer added your user account to the `cbb` group (`_cbb` on macOS), and new
  group memberships take effect only after your next sign-in.
- **Fix:** Log out and log back in (on Windows, open a new terminal window). Until you sign in
  again, run commands with `sudo cbb ...`.

## Devices do not see each other at home

### `cbb status` warns that devices at home cannot connect to this computer

- **Cause:** The computer's firewall blocks incoming **TCP port 8764** (or your custom member
  port) or **UDP port 5353** (mDNS).
- **Fix:** Re-run the installer and answer `y` to the firewall prompt, or add the rules manually
  using the commands in [Installing: the firewall](install.md#the-firewall).

### `cbb status` says "Quiet on" for your home network

- **Cause:** Computers announce themselves and accept local connections only on known home
  networks. If you replaced your router or changed subnets, the computer treats the network as
  unfamiliar.
- **Fix:** Mark the current network as a home network: run `sudo cbb network` on the computer, or
  click **This is my home network** in the Mac app or tray app.

### Devices are on different subnets or VLANs

- **Cause:** Local network discovery (mDNS) does not cross routers between separate subnets (for
  example, `192.168.0.x` and `192.168.20.x`).
- **Fix:** Connect both networks through a hub ([Away from home](away-from-home.md)), run `cbb` on
  a router connected to both subnets, or pass `-peer HOST:PORT` to the service on a small device
  ([Small devices](../../member/README.md#install)).

### Devices on Wi-Fi cannot connect to each other at all

- **Cause:** The router has **Guest Wi-Fi** or **AP / client isolation** enabled, which prevents
  wireless devices from communicating directly.
- **Fix:** Move your devices to your main home Wi-Fi network or disable client isolation on the
  router.

### Two devices are online but never exchange copies

- **Cause:** One device is in a different group, **Sync** is off, or an admin muted the device.
- **Fix:**
  - Check **Sync** on both devices (`cbb status` or **Home** in the app) and make sure neither
    device is muted.
  - Check the group tag in `cbb status`. If a computer is in the wrong group, run `sudo cbb leave`
    on it, pair it with the right group, and remove its old entry from the wrong group.

### `cbb status` or the app says this device was removed from the group

- **Cause:** An admin removed this device, so all other group members refuse its connections.
- **Fix:** Run `sudo cbb leave` on the computer (or tap **Leave the group** in the phone or
  desktop app), then pair the device again as a new device.

## Pairing fails

### Pairing reports "wrong code" or the window closes

- **Cause:** Each pairing window stays open for 5 minutes and closes automatically after 3 wrong
  attempts.
- **Fix:** Open a new pairing window (`sudo cbb pair` on an admin computer, or **+ > Add a
  device** in an app) and enter the new 6-digit code or scan the new QR code.

### Phone cannot reach the computer after scanning the QR code

- **Cause:** The phone and computer are on different networks, the computer's firewall blocks TCP
  port 8764, or iOS Local Network access is denied.
- **Fix:**
  1. Confirm both devices are on the same home Wi-Fi or LAN.
  2. Verify the computer's firewall allows TCP port 8764 ([the firewall](install.md#the-firewall)).
  3. On iPhone, enable **Settings > Privacy & Security > Local Network > CBB**.

## Sync away from home

### Away device cannot connect to the hub

- **Cause:** One of four common issues:
  - Your router does not forward UDP port 8764 to the hub, the hub's firewall drops it, or the
    public address given to `cbb global hub` is behind carrier-grade NAT.
  - The away device has not met the hub on your home network since syncing away from home was
    turned on or since the hub changed its tunnel settings (`-no-obfuscate`, `-no-vless`).
  - Your home IP address changed and the computer's system outbound rule still allows only the old
    address.
  - The network you are visiting blocks WireGuard or UDP traffic.
- **Fix:**
  1. Run `cbb global` on both the away device and the hub to read the exact failure.
  2. If your home is behind carrier-grade NAT or port forwarding fails, switch the hub to a
     forwarder (`sudo cbb global hub` for the project's forwarder; see
     [Away from home](away-from-home.md#5-when-the-internet-cannot-reach-your-home-a-forwarder)).
  3. If `cbb global` says the system's outbound network rule lags behind, run `sudo cbb global
     allow` on that computer.
  4. If the device never met the hub at home after a settings change, connect it to your home
     network once (and open the phone app briefly).
  5. If the visited network filters VPNs, verify AmneziaWG and VLESS are enabled on the hub
     ([Networks that block VPNs](blocked-networks.md)). If the project's forwarder entry points
     are stale, import fresh signed entry points with `sudo cbb global entries import STRING`.
  6. To log WireGuard handshakes on Linux, set `CBB_DEBUG=1` on the service and restart it:

     ```sh
     sudo systemctl edit cbb
     ```

     Add these lines, save, and restart:

     ```ini
     [Service]
     Environment=CBB_DEBUG=1
     ```

     ```sh
     sudo systemctl restart cbb
     ```

     Then inspect `journalctl -u cbb`.

## Phones

### Android: "Restricted setting" blocks turning on the accessibility service

- **Cause:** Android 13 and later restrict accessibility permissions for apps installed from an
  APK outside an app store.
- **Fix:** Open Android **Settings > Apps > CBB** (App info), tap the **⋮** menu in the top
  corner, tap **Allow restricted settings**, and then turn on **Clipboard sync** in Accessibility
  settings.

### Android: copies from computers stop arriving in the background

- **Cause:** Battery optimization stopped the app's background foreground service.
- **Fix:** Open Android **Settings > Apps > CBB > Battery** and set it to **Unrestricted**.

### iPhone: iOS asks for paste permission every time you sync

- **Cause:** iOS defaults **Paste from Other Apps** to **Ask**.
- **Fix:** Open iPhone **Settings > Apps > CBB > Paste from Other Apps** and choose **Allow**.

### Aurora OS 5: admin key is locked

- **Cause:** Seven wrong admin PIN attempts permanently lock the admin key in the phone's secure
  element. The phone stays in the group as an ordinary member.
- **Fix:** Leave the group, reinstall **CBB**, and join again as a new device.

## Still stuck

Open a [GitHub issue](https://github.com/HunterEwok/cbb/issues) and include:

- The output of `CBB_DEBUG=1 cbb status` (and `cbb global` for away-from-home problems)
- The relevant lines from the service or app log
- The operating systems and Connect Beyond Borders versions involved

Remove any copied text, personal addresses, or device names you do not want to share. Report
security vulnerabilities privately by following [SECURITY.md](../../SECURITY.md).
