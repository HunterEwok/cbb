<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Networks that block VPNs

Away from home, your devices reach the hub through the group's own WireGuard tunnel. Some
networks block WireGuard: hotel and office Wi-Fi, some mobile operators, and whole
countries that filter VPNs. Copy Beyond Borders has two ways around it. Both are switched on
at the hub, and the devices pick them up the next time they meet the hub at home.

| Way | What the network sees | You need | Works on |
|---|---|---|---|
| Plain WireGuard (default) | WireGuard packets | the hub or a forwarder | computers, phones, lite member |
| **AmneziaWG** (`-obfuscate`) | UDP packets that look like nothing in particular | the hub or a forwarder | computers, phones |
| **VLESS with REALITY** (`-vless`) | an HTTPS connection to a well-known website | a forwarder with VLESS on | computers, phones |

Whatever you choose, the clipboard stays inside the group's tunnel and the devices' own TLS,
encrypted end to end. The disguise only changes how the packets look on the wire.

## Which one to use

1. Try **plain WireGuard** first. It is the fastest and works on most networks.
2. If the tunnel does not come up on some network, or is cut after a while, turn on
   **AmneziaWG**. Most filters that look for WireGuard no longer recognise it.
3. If even that is blocked, as in countries that block every unknown kind of traffic, use
   **VLESS with REALITY**. It needs a forwarder (your own or, later, the project's) that
   listens on TCP port 443.

Nothing helps on a network that lets through only a list of approved addresses.

## AmneziaWG

On the hub:

```sh
sudo cbb global hub -obfuscate 203.0.113.7:8764
```

With a forwarder, add `-obfuscate` the same way:

```sh
sudo cbb global hub -obfuscate -forwarder 198.51.100.9:8764 -forwarder-key <key>
```

The hub makes the group's settings once, at random, and keeps them while `-obfuscate`
stays. Bring each laptop and phone home once afterwards, or keep the app open at home, so it
takes the new settings. The lite member speaks only plain WireGuard: in an obfuscated group
it syncs at home only.

## VLESS with REALITY

VLESS runs between your devices and the forwarder. REALITY makes the forwarder answer like
a real, well-known website: anyone who connects to it without the group's keys, a censor
probing it for example, gets that site's own pages. So the forwarder must be set up for it
first, then the hub.

1. **On the forwarder**, pick a large HTTPS site that is not blocked in the country where
   you travel and supports TLS 1.3, and start the forwarder with it:

   ```sh
   cbb forward -vless-site www.example.com
   ```

   The forwarder now also listens on TCP 443 (`-vless-listen` for another port). Open that
   port in the server's firewall, beside UDP and TCP 8764. Setting up the server is in
   [running your own servers](../admin/self-hosting.md#vless-on-the-forwarder).

2. **On the hub**:

   ```sh
   sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key> -vless
   ```

   Add `-obfuscate` too if you like; both then apply.

3. **On the devices**: meet the hub at home once, as after any change. From then on they
   reach the forwarder only through VLESS, never with plain WireGuard first, so the network
   you want to hide the tunnel from never sees it.

## Tips for countries that filter

- **Set everything up at home, before you travel.** The devices take the hub's settings
  only on the home network.
- Choose a forwarder outside the filtering country, at a hosting provider that is not
  blocked there.
- For VLESS, choose a site that people in that country use every day, so blocking it would
  hurt; and one served from a different provider than your forwarder.
- A phone's own VPN keeps working: the app's tunnel is ordinary traffic of the app and does
  not take the phone's VPN slot.
- If the tunnel stops working on a trip, `cbb global` on a laptop says what fails, and
  `CBB_DEBUG=1` shows the details ([troubleshooting](troubleshooting.md#sync-away-from-home)).
