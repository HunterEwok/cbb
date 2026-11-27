<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Away from home

For anyone who wants their devices to keep syncing outside their home network. On this page, you
set up a computer at home as a **hub**, turn on syncing away from home on your other devices,
optionally configure a **forwarder** or **blind relay**, and invite devices that are not at home.

At home, your devices connect directly on your local network. Away from home, they reach a hub at
home through your group's own encrypted WireGuard tunnel. For how hubs, forwarders, and blind
relays work, see [How it works](how-it-works.md#away-from-home-the-hub). For what each server can
see, see [Privacy: who sees what](privacy.md).

Syncing away from home stays off until you turn it on at the hub and on each device that needs it.
Set it up **while all devices are on your home network**, because devices exchange tunnel keys
locally with the hub.

## 1. Choose the hub

A **hub** is a computer, router, or small board at home (Linux, macOS, Windows, FreeBSD, OpenWrt,
or OPNsense). A phone, watch, or [rootless Linux install](install.md#without-sudo-rootless) is
never a hub. Pick a device that stays on most of the time, such as a home server, NAS, router, or
Raspberry Pi. While the hub is off, syncing away from home pauses, while devices at home continue
syncing directly.

Choose which kind of hub you want:

- **A hub that reads copies:** Your group's **main device** (if it is a computer) or an **admin**
  computer. Devices seal copies to it like to any other reading device, and your group's
  [key level](keys.md#the-three-levels) applies to its keys.
- **A hub that only passes copies on:** Any ordinary computer or small board in your group.
  Devices seal copies end to end past it, so it reads no copies, makes no copies of its own, takes
  no remote pastes or quick actions, and needs no hardware security chip. Only the group's main
  device can designate a hub that only passes copies on.

A group can have several hubs in a priority order; only the highest-priority online hub serves at
a time. To set the order from the main device (or an admin computer that can be a hub), run
`sudo cbb global hubs NAME...`.

## 2. Turn it on, on the hub

You can set up the hub from a desktop app, from an admin phone, or from a terminal.

### Using the Mac app or tray app

1. Open **CBB** on the computer you want to use as the hub.
2. Open that computer's own device page and click **Make it a hub**.
3. If prompted, choose **A hub that reads the copies** or **A hub that only passes them on**, and
   confirm turning syncing away from home on.

**Result:** The app turns syncing away from home on for this computer and configures it as a hub
using the project's forwarder at `cbb.tools`, so you do not need to open a port on your router.

### Using an admin phone

1. On the computer you want to make a hub, turn syncing away from home on first (`sudo cbb global
   on`, or turn **Everywhere** on in the desktop app).
2. On your phone, open **CBB** and tap the computer on **Home**.
3. If the computer is not an admin yet (and you want a hub that reads copies), tap **Make it an
   admin** and confirm.
4. Tap **Make it a hub** and confirm with your face, fingerprint, passcode, or (on Aurora OS) your
   admin PIN.

**Result:** The computer becomes a hub through the project's forwarder at `cbb.tools`.

### Using a terminal

On Linux, macOS, or FreeBSD, run these commands on the hub computer (on Windows, omit `sudo` and
use an administrator terminal):

1. Turn syncing away from home on:

   ```sh
   sudo cbb global on
   ```

   If the computer keeps its keys in files, read the warning and type `yes`.

   **Result:** The service allows outbound tunnel connections to your group's servers and leaves
   all other internet destinations blocked.

2. Make the computer a hub. Choose one of the following:
   - **Direct connection with a public home address** (IPv4, IPv6, or a domain name pointing to
     your home):

     ```sh
     sudo cbb global hub 203.0.113.7:8764
     ```

   - **Through a forwarder** (when your home has no public address or you do not want to open a
     router port):

     ```sh
     sudo cbb global hub
     ```

   **Result:** If you gave a home address, `cbb global hub` lists the UDP firewall rule it needs
   and asks before adding it. Without addresses, the hub registers with the project's forwarder at
   `cbb.tools`.

3. If you gave a public home address and your hub sits behind a router, open your router's settings
   and forward **UDP port 8764** (or the port you set with `-port`) to the hub's local IP address.
   Look for **Port Forwarding** or **Virtual Server** in your router settings.

   On an **OpenWrt router** acting as the hub, run the commands above as `root` without `sudo`.
   No port forwarding is needed unless the router sits behind another router (double NAT): when
   you confirm the firewall prompt, Connect Beyond Borders adds the WAN UDP rule to the service's
   own firewall rules without editing `/etc/config/firewall`.

To make another computer a hub that only passes copies on from the main device (called *root* in
command-line tools), turn syncing away from home on at that computer first, then run on the main
device:

```sh
sudo cbb global hub -on DEVICE -forward-only
```

## 3. Turn it on, on the other devices

While all devices are on your home network and the hub is running:

- **Computers and small devices:** Run `sudo cbb global on` (in an administrator terminal without
  `sudo` on Windows), or turn **Everywhere** on in the Mac app or tray app. Note that MIPS router
  builds sync on the home network only; see [Devices, ports and files](../reference/devices.md).
- **Phones:** Open **CBB** and turn **Everywhere** (the globe switch) on from **Home**, then keep
  the app open briefly at home so it exchanges tunnel keys with the hub. Android phones keep
  syncing away from home in the background; iPhone, Aurora OS, and HarmonyOS phones sync while the
  app is open.

**Result:** Each device receives the hub's tunnel offer and exchanges tunnel keys with it.

## 4. Check it

1. On each computer, run:

   ```sh
   cbb global
   ```

   **Result:** The output shows whether syncing away from home is on, which device is the hub,
   whether the tunnel is connected, and any error.

2. Move a phone or laptop off your home Wi-Fi (for example, switch a phone to mobile data) and
   copy a line of text.

   **Result:** The copied text arrives on your devices at home.

If the tunnel does not connect, check your router's UDP port forward and public address, or see
[Troubleshooting: sync away from home](troubleshooting.md#sync-away-from-home).

If your home's public address changes later, the hub shares the new address the next time your
devices meet. When `cbb global` or `cbb status` reports that the system's outbound network rule
lags behind, run `sudo cbb global allow` on that computer to update the rule.

## 5. When the internet cannot reach your home: a forwarder

Many internet providers place homes behind carrier-grade NAT (a shared public IP address), which
blocks incoming connections even with port forwarding. A **forwarder** solves this: your hub opens
an outgoing connection to the forwarder, and away devices send encrypted tunnel packets to the hub
through it. No router ports need to be opened, and the forwarder holds no group keys.

Choose one of two options on your hub:

- **Use the project's forwarder at `cbb.tools`:** Run `sudo cbb global hub` with no address, or
  add `-forwarder default` alongside your hub's own public addresses:

  ```sh
  sudo cbb global hub -forwarder default 203.0.113.7:8764
  ```

- **Use your own forwarder:** Run a forwarder on any server with a public address
  ([Running your own servers](../admin/self-hosting.md#a-forwarder)), then pass its address and
  key to the hub:

  ```sh
  sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key KEY
  ```

**Result:** When a hub has both direct addresses and a forwarder, away devices try the direct
addresses first and fall back to the forwarder if direct connections fail.

## 6. Networks that block VPNs

Hotels, offices, mobile operators, and some countries block WireGuard. By default, a hub disguises
its tunnel with **AmneziaWG** and (when using a forwarder that supports it) **VLESS** over HTTPS.
To configure or adjust tunnel disguising, see [Networks that block VPNs](blocked-networks.md).

## A computer that is not at home: an invitation

Once syncing away from home works through a hub, you can invite a computer or a phone that is not
on your home network. An invitation works once and lasts 1 hour by default (up to 24 hours with
`-for`).

### Invite and admit a device

1. On the main device or an admin, create an invitation:
   - **In a terminal on an admin computer:** Run `sudo cbb invite` for a computer (writes
     `cbb.cbbinvite`), or `sudo cbb invite -phone` for a phone (prints a QR code). Keep the
     command running until the new device joins.
   - **In a phone or desktop app:** Tap **+** on **Home** (or choose **Add a device > Device far
     away? Send an invitation** in a desktop app) and follow the prompt.
2. Send the invitation file, text (`cbb://join#...`), or QR code to the new device through a
   channel you trust. Anyone who holds an unused invitation can ask to join, though you still
   approve the admission by matching key fingerprints.
3. On the new device, use the invitation:
   - **On a computer (terminal):** Run `sudo cbb pair -invite cbb.cbbinvite` (or `sudo cbb pair
     -invite -` and paste the `cbb://join#...` text on standard input).
   - **On a computer (desktop app):** Choose **Join with an invitation** and paste the invitation
     text.
   - **On a phone:** Open **CBB**, tap **Join with an invitation**, and scan the QR code, paste
     the invitation text, or open the invitation file.

   **Result:** Both devices display the new device's key fingerprint.

4. Compare the key fingerprint shown on the inviting device with the fingerprint shown on the new
   device. Type `yes` (or tap **Admit**) only if they match exactly.

**Result:** The new device joins your group and starts syncing through the hub. `cbb invite`
deletes the temporary invitation file when it exits.

To add a computer from another network over SSH or your own VPN instead, see
[Without the app: joining from another network](without-app.md#joining-from-another-network).

## No computer for a hub

A phone is never a hub. If your group has no computer, router, or small board to act as a hub (for
example, a phones-only group), your devices can meet at a **blind relay** instead. Both devices
must be online at the same time to exchange a copy.

A blind relay cannot read your clipboard, but it sees which temporary device pseudonyms are online
together, their IP addresses, timing, and traffic volume. Only the group's **main device** turns a
blind relay on or off for the group, and only after you agree to what the relay sees.

### Turn on a blind relay

- **On a phone (main device):** Open **Settings**, turn on **Advanced settings**, tap **Blind
  relay**, and choose the project's relay or enter your own relay's address and key. Confirm the
  prompt.
- **On a computer (main device):**
  - Use the project's open relay at `cbb.tools:8765`:

    ```sh
    sudo cbb global relay default
    ```

  - Use your own relay ([Running your own servers](../admin/self-hosting.md#a-blind-relay)):

    ```sh
    sudo cbb global relay 198.51.100.9:8764 -key KEY
    ```

  Read what the relay can see and type `yes`.

**Result:** Your group's settings name the relay, and devices with **Everywhere** on meet there.

To stop using a blind relay, run `sudo cbb global relay off` on the main computer, or open
**Settings > Advanced settings > Blind relay** on the main phone and tap **Leave the relay**.

## Turning it off

### Stop a computer from being a hub

To stop a computer from acting as a hub while keeping syncing away from home enabled on it:

- **In the Mac app or tray app:** Open the hub's device page and click **Stop being the hub**.
- **In a terminal:** Run `sudo cbb global hub off` on the hub, or `sudo cbb global hub off -on
  NAME` from an admin computer.

**Result:** Connected away devices switch to the group's next hub automatically. If the group has
no other hub, Connect Beyond Borders asks for confirmation before stopping (pass `-yes` in scripts
to confirm), because away devices stop syncing until another hub is configured.

### Turn syncing away from home off on a device

- **On a computer:** Run `sudo cbb global off` (on Windows, `cbb global off` in an administrator
  terminal), or turn **Everywhere** off in the desktop app.
- **On a phone:** Turn **Everywhere** off on **Home**.

**Result:** The device forgets its tunnel keys and stops syncing away from home. On Linux and
Windows, `cbb global off` also removes the group's servers from the system outbound network rule.
Because new tunnel keys are exchanged with the hub on your home network, a device that turns
syncing away from home off while away resumes away syncing only after it reconnects at home.
