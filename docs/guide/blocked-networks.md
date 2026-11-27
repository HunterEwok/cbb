<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Networks that block VPNs

For anyone syncing away from home on networks that filter or block WireGuard, such as hotel Wi-Fi,
office networks, mobile operators, or countries with strict traffic filtering. On this page, you
verify or change how your hub disguises its tunnel.

Away from home, your devices reach your hub through your group's WireGuard tunnel. By default, a
hub uses both **AmneziaWG** and (when paired with a VLESS-capable forwarder) **VLESS** so your
tunnel gets through filtering networks. Regardless of the disguise, your copies stay inside
WireGuard, mutual TLS 1.3, and end-to-end encryption; see
[How it works](how-it-works.md#networks-that-block-vpns).

| Transport | What the network sees | Requirements | Supported devices |
|---|---|---|---|
| **AmneziaWG** (on by default) | UDP packets with randomized headers and padding | Hub or forwarder | Computers, small devices (except MIPS routers), phones |
| **VLESS** (on by default with a VLESS forwarder) | An HTTPS connection to the forwarder's website | Forwarder with VLESS enabled (the project's forwarder at `cbb.tools` has it) | Computers, small devices (except MIPS routers), phones |
| **Plain WireGuard** (`-no-obfuscate -no-vless`) | Standard WireGuard UDP packets | Hub or forwarder | Computers, small devices (except MIPS routers), phones |

## How the devices choose

When a hub uses a VLESS-capable forwarder, away devices try **AmneziaWG** over UDP first because
UDP is faster where the network allows it. If UDP is blocked—as on networks that allow only web
traffic—they switch automatically to **VLESS** over HTTPS (TCP port 443) to the forwarder and stay
on the transport that succeeded.

When VLESS is enabled, devices never fall back to plain WireGuard, so filtering networks do not see
unmasked VPN traffic. A hub without a forwarder offers AmneziaWG alone.

No tunnel disguise helps on a network that allows connections only to a fixed list of approved IP
addresses or domains.

## Configure tunnel disguising in the desktop app

On a hub running the Mac app or the tray app for Linux and Windows:

1. Open **CBB** and select this computer's device page.
2. Under **Strict networks**, toggle:
   - **Networks that block VPNs (AmneziaWG)** to turn AmneziaWG on or off.
   - **Networks that let only the web through (VLESS)** to turn VLESS on or off (requires a
     forwarder that supports VLESS).
3. Confirm with your administrator password, Touch ID, Windows Hello, or polkit prompt.
4. Connect each laptop and phone to your home network once so it receives the hub's updated tunnel
   settings.

**Result:** The hub saves the updated settings and shares them with your devices the next time
they meet at home.

## AmneziaWG

Every hub enables AmneziaWG by default as soon as you set it up:

```sh
sudo cbb global hub 203.0.113.7:8764
```

The hub generates random AmneziaWG parameters for your group and rotates them automatically with
each server-credential period (about once a month), sharing the next set ahead of time.

To switch to plain WireGuard on networks where nothing blocks VPNs (which reduces packet overhead):

1. Run on the hub (use `-keep` to preserve the hub's existing addresses and forwarder):

   ```sh
   sudo cbb global hub -keep -no-obfuscate -no-vless
   ```

2. Connect each away laptop and phone to your home network once (keep the phone app open briefly)
   so it receives the new settings.

**Result:** Your devices use plain WireGuard once they pick up the updated offer at home.

## VLESS

VLESS carries your AmneziaWG-disguised tunnel inside what looks to the network like a normal HTTPS
connection to the forwarder's website. Keeping AmneziaWG inside VLESS hides WireGuard packet sizes
that could otherwise stand out inside HTTPS.

1. **Choose a forwarder with VLESS:**
   - **The project's forwarder at `cbb.tools`** already has VLESS enabled; to the network, your
     devices appear to visit `cbb.tools`.
   - **Your own forwarder:** Run `cbb forward` behind a web server that holds your site's TLS
     certificate:

     ```sh
     cbb forward -vless-xhttp vpn.example.org
     ```

     Configure your web server to proxy the path `cbb forward` prints to the forwarder's local
     listener (`127.0.0.1:3276` by default) while serving your own web pages to everyone else. Open
     **TCP port 443** on the server's firewall alongside UDP and TCP port 8764. See
     [Running your own servers: VLESS on the forwarder](../admin/self-hosting.md#vless-on-the-forwarder).

2. **Point your hub at the forwarder:** On the hub, register with the project's forwarder or your
   own:

   ```sh
   sudo cbb global hub -forwarder default
   ```

   For your own forwarder, pass its address and key instead:

   ```sh
   sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key KEY
   ```

   **Result:** The hub requests VLESS automatically. If the forwarder supports VLESS, it sends the
   hub its site name and path; otherwise the hub registers for UDP alone. To turn VLESS off while
   keeping AmneziaWG, pass `-no-vless` (for example, `sudo cbb global hub -keep -no-vless`).

3. **Sync once at home:** Bring each laptop and phone onto your home network (and open the phone
   app briefly) after changing hub settings.

   **Result:** Your devices receive the hub's VLESS offer and use it automatically whenever UDP is
   blocked.

## Tips for countries that filter traffic

- **Set up and test at home before you travel.** Devices receive a hub's tunnel settings only on
  your home network.
- **Host your forwarder outside the filtering country** on a provider whose IP addresses are not
  blocked there.
- **Expect domain blocking:** The forwarder's domain name appears in the TLS handshake (SNI). If a
  network blocks `cbb.tools`, run your own forwarder behind a different domain name.
- **Keep your system VPN:** The Connect Beyond Borders tunnel runs inside the app as ordinary
  traffic and does not take your phone's VPN slot, so your own VPN continues working alongside it.
- **Refresh blocked entry points:** If the project's forwarder entry points change and a device
  cannot reach them, export signed entry points from a connected computer with `cbb global entries
  export` (or `-qr`) and import them on the affected computer with `sudo cbb global entries import
  STRING`.
- **Inspect failures:** Run `cbb global` on a laptop to see why the tunnel failed, and enable
  `CBB_DEBUG=1` on the service to view WireGuard handshake logs
  ([Troubleshooting: sync away from home](troubleshooting.md#sync-away-from-home)).
