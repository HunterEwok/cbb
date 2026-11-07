<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# When something does not work

Start with `cbb status` on the device that misbehaves: it says whether the service runs, which
group it is in, which members are connected and the state of sync away from home. Each
message is short; `CBB_DEBUG=1 cbb status` (on Windows `$env:CBB_DEBUG = "1"` first) shows
the underlying error under it. The service's log always has the details: on Linux
`journalctl -u cbb`, and the desktop connector's in the session's journal,
`journalctl --user`; the other systems are in [files and logs](../reference/devices.md#files-and-logs).
The details switch of every part, the apps and the installers included, is in
[error messages and details](../reference/errors.md).

## Commands

**"the CBB service is not running"**: start it
(`sudo systemctl start cbb` on Linux; `sudo launchctl kickstart -k system/tools.cbb`
on a Mac; `Start-Service cbb` on Windows) and look at its log.

**"permission denied" on the control socket, right after installing**: the installer added
you to the `cbb` group, and a group counts only from the next login. Log out and
in again (on Windows, open a new terminal); until then, `sudo cbb ...` works.

## Devices do not see each other

- **Firewall.** Members need TCP 8764 (or your port) and UDP 5353 (mDNS) from the home
  network. The installers add them when you answer Yes; which firewalls they know, and the
  commands for the others, are in [the firewall](install.md#the-firewall). With a firewall
  turned on later, run the installer again. If `cbb status` warns that the others cannot
  connect to this computer, its firewall is blocking the member port.
- **Another subnet or VLAN.** mDNS does not cross routers, so devices on, say,
  192.168.0.x and 192.168.20.x do not find each other. Turn on [sync away from home](away-from-home.md)
  with a hub on one side, or, for a lite member, name a computer with `-peer` in its
  service ([lite member](../../member/README.md#install)).
- **Guest Wi-Fi or client isolation** on the router keeps devices from talking to each
  other at all; put them on the main network.
- **A different group.** `cbb status` shows the group; devices of two groups never
  sync. To move a computer to the right one, run `sudo cbb leave` on it, then pair it with
  the right group, and remove it from the wrong one there.
- **Removed from the group.** `cbb status` says so, and its members refuse it. Run
  `sudo cbb leave` on it (in the apps: Leave the group), then pair it again.

## Pairing fails

- **"wrong code"**: each pairing window allows three attempts; run `cbb pair` again for a
  new code.
- **The phone cannot reach the computer after scanning its QR code**: the phone and the
  computer must be on the same network, and the computer's port must be open (above). On
  iOS, allow Local Network for the app (Settings, Privacy & Security, Local Network).

## Sync away from home

`cbb global` on the device and on the hub says what is wrong. The usual causes: the router does
not forward the hub's UDP port to the hub, the hub's firewall drops it, or the address given
to `cbb global hub` is not the one the internet reaches. A device that has not met the hub
at home since sync away from home was turned on, or since the hub changed its settings
(`-obfuscate`, `-vless`), does not know how to reach it: bring it home once. A network that
blocks VPNs needs [AmneziaWG or VLESS](blocked-networks.md). With `CBB_DEBUG=1` in the service's
environment the log also shows WireGuard's handshakes. On Linux:

```sh
sudo systemctl edit cbb     # add the two lines below, save
# [Service]
# Environment=CBB_DEBUG=1
sudo systemctl restart cbb
```

## Android

- **The accessibility service cannot be turned on** ("restricted setting"): on Android 13
  and later, open the app's App info, ⋮, "Allow restricted settings", then turn it on.
- **Copies from the computers stop arriving**: the foreground service may have been stopped
  by a battery saver; let the app run unrestricted in its battery settings.

## Still stuck

Open an [issue](https://github.com/HunterEwok/cbb/issues) with the output of
`CBB_DEBUG=1 cbb status`, the relevant part of the log and the systems involved. Remove
anything you copied that is private. Security problems go to [SECURITY.md](../../SECURITY.md)
instead.
