<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Networks that block VPNs

Away from home, your devices reach the hub through the group's own WireGuard tunnel. Some
networks block WireGuard: hotel and office Wi-Fi, some mobile operators, and whole
countries that filter VPNs. Copy Beyond Borders has two ways around it, and a hub uses both
unless you turn them off; the devices pick up a change the next time they meet the hub at
home.

| Way | What the network sees | You need | Works on |
|---|---|---|---|
| **AmneziaWG** (on by default; `-no-obfuscate` with `-no-vless` turns it off) | UDP packets that look like nothing in particular | the hub or a forwarder | computers, phones |
| **VLESS** (on by default at a forwarder; `-no-vless` turns it off) | an HTTPS connection to a website | a forwarder with VLESS on (the project's has it) | computers, phones |
| Plain WireGuard (`-no-obfuscate -no-vless`) | WireGuard packets | the hub or a forwarder | computers, phones, lite member |

Whatever you choose, the clipboard stays inside the group's tunnel and the devices' own TLS,
so nothing between your devices can read it. The disguise only changes how the packets look on the wire.

## How the devices choose

The devices try **AmneziaWG** over UDP first, which is the fastest where the network lets it
through: most filters that look for WireGuard do not recognise it. Where even that is
blocked, as in countries that block every unknown kind of traffic, they reach the forwarder
over **VLESS**, which needs a forwarder that takes VLESS on TCP port 443: the project's at
cbb.tools does, or your own. A hub without a forwarder offers AmneziaWG alone.

Nothing helps on a network that lets through only a list of approved addresses.

## AmneziaWG

A hub speaks AmneziaWG as soon as it is one:

```sh
sudo cbb global hub 203.0.113.7:8764
```

It makes the group's settings once, at random, and keeps them. On a network where nothing is
blocked, plain WireGuard is a little faster:

```sh
sudo cbb global hub -no-obfuscate -no-vless 203.0.113.7:8764
```

Bring each laptop and phone home once after a change, or keep the app open at home, so it
takes the new settings. The lite member speaks only plain WireGuard: in a group whose hub
hides its tunnel it syncs at home only.

## VLESS

VLESS runs between your devices and the forwarder, inside what looks to the network like an
ordinary HTTPS connection to a website.

1. **The forwarder.** The project's forwarder at cbb.tools has VLESS on: to the network,
   your devices visit `cbb.tools`. A forwarder of your own runs it one of two ways:

   ```sh
   cbb forward -vless-xhttp vpn.example.org   # behind your site's web server
   cbb forward -vless-site www.example.com    # REALITY, on a server without a site
   ```

   Behind a web server that has your site's certificate, the web server passes the path the
   forwarder prints to it. REALITY borrows a large site's TLS, and anyone who connects
   without the group's keys, a censor probing it for example, gets that site's own pages:
   pick a site that is not blocked where you travel and supports TLS 1.3, and open TCP 443
   in the server's firewall, beside UDP and TCP 8764. Setting up the server is in
   [running your own servers](../admin/self-hosting.md#vless-on-the-forwarder).

2. **On the hub**: nothing to do. A hub at a forwarder asks for VLESS:

   ```sh
   sudo cbb global hub -forwarder default
   ```

   (`-forwarder 198.51.100.9:8764 -forwarder-key <key>` for your own.) The forwarder tells
   the hub which way it runs; one without VLESS registers the hub for UDP alone. VLESS
   comes with AmneziaWG: inside VLESS it hides the sizes of WireGuard's packets, which would
   otherwise show through the HTTPS. `-no-vless` turns VLESS off.

3. **On the devices**: meet the hub at home once, as after any change. From then on they
   try AmneziaWG over UDP first, which is faster where the network lets it through, and
   VLESS when it does not, and keep to the way that worked. They never try plain WireGuard,
   so the network you want to hide the tunnel from never sees it.

## Tips for countries that filter

- **Set everything up at home, before you travel.** The devices take the hub's settings
  only on the home network.
- Choose a forwarder outside the filtering country, at a hosting provider that is not
  blocked there.
- For VLESS with REALITY, choose a site that people in that country use every day, so
  blocking it would hurt; and one served from a different provider than your forwarder.
- The forwarder's site shows in every connection's first packet: a network that blocks the
  site blocks the way too. A forwarder of your own, on another site, is the answer then.
- A phone's own VPN keeps working: the app's tunnel is ordinary traffic of the app and does
  not take the phone's VPN slot.
- If the tunnel stops working on a trip, `cbb global` on a laptop says what fails, and
  `CBB_DEBUG=1` shows the details ([troubleshooting](troubleshooting.md#sync-away-from-home)).
