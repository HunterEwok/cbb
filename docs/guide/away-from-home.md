<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Away from home

At home your devices sync by themselves. To keep syncing when a laptop or a phone is
somewhere else, one computer at home becomes the group's **hub**, and the devices that
travel reach it through the group's own encrypted tunnel. The pictures of each case are in
[How it works](how-it-works.md#away-from-home-the-hub).

Sync away from home is off until you turn it on, on the hub and on each device that should
use it. Set it up **while all the devices are at home**: that is when they hand each other
the tunnel's keys.

## 1. Choose the hub

The hub is a computer that is an admin of the group: Linux, Windows, a Mac, FreeBSD or a
router with OpenWrt or OPNsense. The best one is always on: a home server, a NAS, a Raspberry Pi. A NAS in Docker
can be the hub only with its keys in a file, which it refuses unless you allow it
([the image's README](../../packaging/docker/README.md#keys)). A computer you switch on only when you need it works too; while the hub is
off, nothing syncs away from home, and everything at home still syncs.

In a group made on a phone, make that computer an admin first: on the phone, tap the
computer and **Make it an admin**.

## 2. Turn it on, on the hub

On Linux, in a terminal on the hub (on Windows, without `sudo`, in an administrator
terminal):

```sh
sudo cbb global on                        # read what it says about the keys, type yes
sudo cbb global hub 203.0.113.7:8764      # the address the internet reaches your home at
```

- **The address** is your home's public IP address (IPv4 or IPv6), or a name that points
  to it. Your router's status page shows it, or a site such as `ifconfig.me`.
- **The router** must forward UDP port 8764 to the hub. Look for "port forwarding" or
  "virtual server" in its settings.
- **The hub's firewall**: `cbb global hub` lists the rule it needs and asks before it adds
  it.

**An OpenWrt router as the hub** needs no port forwarding: run the same commands on the
router, as root without `sudo`. With Yes, the rule for the hub's UDP port from `wan` becomes
part of the service's own firewall rules, which come and go with the service;
`/etc/config/firewall` stays as it was. A router behind another router (double NAT) still
needs the forwarding on the router in front, or a forwarder.

No public address, because your provider puts you behind carrier-grade NAT? Then the
router cannot help; use a forwarder instead (step 5).

## 3. Turn it on, on the other devices

At home, with the hub on:

- **Computers**: `sudo cbb global on` (on Windows, in an administrator terminal).
- **Phones**: in the app, Settings, **Sync away from home**. Then keep the app open for a
  moment at home, so it meets the hub. An iPhone syncs away from home while the app is
  open; Android also in the background. In a group made on a phone, that phone starts as the
  hub, and the switch shows once it is no longer: under **Move the hub to a computer** make
  the computer the hub (with the forwarder saved on the phone first), or turn **This phone
  as the hub** off.
- **Lite member**: `sudo cbb global on` on the device ([lite member](../../lite/README.md#sync-away-from-home)).

## 4. Check it

```sh
cbb global
```

On each computer it shows whether sync away from home is on, which device is the hub,
whether the tunnel is up, and what went wrong if it is not. Then take a laptop or a phone
off the home Wi-Fi (a phone's mobile data is enough) and copy something.

When it does not connect, the usual reasons are that the router does not forward the port,
or the address is not the one the internet sees. [Troubleshooting](troubleshooting.md#sync-away-from-home)
has more.

When your home's address changes, the hub tells the devices the next time they meet; on a
computer, `cbb global` then says to run `sudo cbb global allow`.

## 5. When the internet cannot reach your home: a forwarder

Behind carrier-grade NAT, the hub registers with a **forwarder** on the internet instead,
by an outgoing connection, so nothing at home has to be opened. The forwarder only passes
encrypted packets and holds no keys.

```sh
sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key>
```

The address and the key come from the forwarder. You can [run your own](../admin/self-hosting.md#a-forwarder)
on any small server. The project's forwarder at `cbb.tools` is not open to everyone yet;
its address and key will be here when it is.

The hub may have its own address and a forwarder at once: devices try the hub first and the
forwarder last.

## 6. Networks that block VPNs

Hotels, offices, and some countries block WireGuard. The hub can disguise the tunnel with
AmneziaWG or hide it inside VLESS: see [Networks that block VPNs](blocked-networks.md).

## A computer that is not at home: an invitation

A computer far away can join the group with an invitation from the hub, once sync away from
home works:

```sh
sudo cbb invite        # on the hub: writes clipboardbridge.cbbinvite, valid for an hour
```

Send the file to the new computer through a channel you trust, such as a messenger you use
with yourself; it is a secret until it is used. There, run
`sudo cbb pair -invite clipboardbridge.cbbinvite`. Both computers show the new one's key
fingerprint; on the hub, type `yes` only if they match. Phones cannot join by invitation
yet: add them at home.

Other ways to join from afar, through SSH or your own VPN, are in
[Without the app](without-app.md#joining-from-another-network).

## No computer for a hub

A phone can be the hub while its app is open (Settings, **This phone as the hub**). Or the
devices meet at a **blind relay** on a server of your own instead of a hub: the computers with
`cbb global relay`, the phones under **Blind relay** in Settings. The relay cannot read the
clipboard but sees which devices talk, when and how much. See
[running your own servers](../admin/self-hosting.md#a-blind-relay).

Coming later: a blind relay at `cbb.tools` that any group can use.

## Turning it off

```sh
sudo cbb global off
```

It forgets the tunnel's keys on that device. The new keys of a later `cbb global on` reach the
hub only on the home network, so a device that is away now syncs again only once it is home.
On a phone, turn the switch off in Settings.
