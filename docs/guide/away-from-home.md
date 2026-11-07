<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Away from home

At home your devices sync by themselves. To keep syncing when a laptop or a phone is
somewhere else, one computer at home becomes the group's **hub**, and the devices that
travel reach it through the group's own encrypted tunnel. The pictures of each case are in
[How it works](how-it-works.md#away-from-home-the-hub).

> Between computers this is built and tested in CI, not yet on real devices; the iPhone has
> synced on mobile data through a Mac hub and the project's forwarder. The README's
> [status table](../../README.md#status) says what has been tried where.

Sync away from home is off until you turn it on, on the hub and on each device that should
use it. Set it up **while all the devices are at home**: that is when they hand each other
the tunnel's keys.

## 1. Choose the hub

The hub is a computer: Linux, Windows, a Mac, FreeBSD or a router with OpenWrt or OPNsense.
The best one is always on: a home server, a NAS, a Raspberry Pi. A computer you switch on only
when you need it works too; while the hub is off, nothing syncs away from home, and everything
at home still syncs.

A hub is one of two kinds, and you choose which when you make it one:

- **A hub that reads the copies** is an admin of the group, so the copies are sealed to it
  like to your other devices, and the group's [key level](keys.md#the-three-levels) applies
  to its keys. In a group made on a phone, the phone makes the computer an admin first.
- **A hub that only passes copies on** is any other computer of the group. The copies are
  sealed end to end to your other devices and never to it, so it reads none, and its keys
  need no security chip: a Raspberry Pi or a NAS in Docker with its keys in a file is a good
  one. It makes, reads and pastes no copies of its own.

On the phone, tap the computer, then **Make it a hub** and the kind; the Mac app and the tray
app ask the same. From an admin computer, `sudo cbb global hub -on DEVICE -forward-only`
makes another computer a hub that only passes copies on. Sync away from home must be on there
first (step 2 below, with `sudo cbb global on`).

## 2. Turn it on, on the hub

On Linux, in a terminal on the hub (on Windows, without `sudo`, in an administrator
terminal):

```sh
sudo cbb global on                        # read what it says about the keys, type yes
sudo cbb global hub 203.0.113.7:8764      # the address the internet reaches your home at
```

In the Mac app or the tray app, open the computer's own page and choose **Make it a hub**: it
asks once and turns sync away from home on with it, through the project's forwarder.

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
- **Lite member**: `sudo cbb global on` on the device ([lite member](../../member/README.md#sync-away-from-home)).

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
sudo cbb global hub
```

Without addresses of its own, the hub goes through the project's forwarder at `cbb.tools`:
cbb knows its address and key, and a phone that is the hub uses it too. `-forwarder default`
adds it to a hub that has its own addresses as well. For [your own forwarder](../admin/self-hosting.md#a-forwarder), on any small server, give its
address and key instead: `sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key>`; on a
phone, under **This phone as the hub**.

The hub may have its own address and a forwarder at once: devices try the hub first and the
forwarder last.

## 6. Networks that block VPNs

Hotels, offices, and some countries block WireGuard. The hub can disguise the tunnel with
AmneziaWG or hide it inside VLESS: see [Networks that block VPNs](blocked-networks.md).

## A computer that is not at home: an invitation

A computer far away can join the group with an invitation from the hub, once sync away from
home works:

```sh
sudo cbb invite        # on the hub: writes cbb.cbbinvite, valid for an hour
```

Send the file to the new computer through a channel you trust, such as a messenger you use
with yourself; it is a secret until it is used. There, run
`sudo cbb pair -invite cbb.cbbinvite`. Both computers show the new one's key
fingerprint; on the hub, type `yes` only if they match. Phones cannot join by invitation
yet: add them at home.

Other ways to join from afar, through SSH or your own VPN, are in
[Without the app](without-app.md#joining-from-another-network).

## No computer for a hub

A phone can be the hub while its app is open (Settings, **This phone as the hub**). The
switch is only in Settings, not on the phone's page in the device list as on a computer: a
phone serves only while its app is open (an Android phone also in the background, at the cost
of its battery), so a computer that is always on is the better hub. Or the
devices meet at a **blind relay** on a server of your own instead of a hub: the computers with
`cbb global relay`, the phones under **Blind relay** in Settings. The relay cannot read the
clipboard but sees which devices talk, when and how much. See
[running your own servers](../admin/self-hosting.md#a-blind-relay).

The project runs a blind relay at `cbb.tools` that any group can use: `sudo cbb global relay default`
knows its address and key, and keeps up by itself when the project changes them.

## Turning it off

To stop a computer being the hub but keep syncing away from home on it, run
`sudo cbb global hub off` there, or choose **Stop being the hub** on its page in the Mac app
or the tray app; an admin can do it for another computer too (`sudo cbb global hub off -on
NAME`). The devices connected to it go to the group's next hub. When there is no other hub,
it asks first, since the devices away from home then stop syncing until a device is a hub
again.

```sh
sudo cbb global off
```

It forgets the tunnel's keys on that device. The new keys of a later `cbb global on` reach the
hub only on the home network, so a device that is away now syncs again only once it is home.
On a phone, turn the switch off in Settings.
