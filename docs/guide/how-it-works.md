<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# How it works

This page explains Copy Beyond Borders in pictures: who is in a group, how the devices find
each other at home, and every way they can stay in touch when they are away. The exact
rules are in the [design](../design.md); you do not need them to use it.

## The group

Your devices form a **group**. Only devices you let in belong to it, and they talk only to
each other, always encrypted (TLS). On top of that every copy is encrypted end to end: the
device that copies seals it for the devices of the group that read copies and signs it, so a
device that only passes it on cannot read it, change it or forge one. Each device has a role:

| Role | Who | What it does |
|---|---|---|
| **Root** | the phone that made the group (or the computer, [without the app](without-app.md)) | holds the group's key, adds and removes devices, makes admins |
| **Admin** | a second phone, or a computer the root chose | adds and removes devices, like the root |
| **Member** | every computer and phone | syncs the clipboard |
| **Lite member** | a small Linux device: a router, a Raspberry Pi Zero | syncs, never adds anyone ([lite member](../../member/README.md)) |
| **Rootless member** | a Linux computer installed without `sudo` | syncs like a member, never the root, an admin or a hub ([below](#rootless-members)) |
| **Hub** | a computer at home, or a phone while its app is open, if you want one | lets your devices sync when they are away from home; one that only passes copies on reads none |

The phone's keys are made in its security chip (the Secure Enclave, Android's Keystore) and
never leave it; each signature with the group's root key or an admin key asks for your face,
fingerprint or passcode, while the key it syncs with works without asking. A computer keeps its
keys in files that only Copy Beyond Borders reads.

### Rootless members

Normally the installer needs `sudo` once, so that Copy Beyond Borders runs under an
account of its own: your browser, your games and every other program you run cannot read
its keys, and the system keeps the service in a tight sandbox. A rootless install skips
that, for a computer where you have no `sudo`, at work for example. It syncs like any
member, but any of your programs could copy its key and pose as it, so it can never be the
root, an admin or the hub, even if you ask. The device list marks it "rootless". A Steam
Deck does not need it: it takes the normal install ([installing](install.md#steamos-steam-deck)).

## Two kinds of group

A group can have a computer at its heart, or be made of phones only. Both are supported in
full, and you can move from one to the other at any time. We recommend a computer that is
often on, for the reason below the table.

| | With a computer | Phones only |
|---|---|---|
| Who holds the group's key | the phone (in its security chip), or the computer [without the app](without-app.md) | the phone, in its security chip |
| Sync at home | every device directly | every device directly |
| Sync away from home | through the computer as the hub, at any time | through the phone as the hub while its app is open (on Android also in the background), or a blind relay |
| What you need | a computer that is often on | nothing more |

Why we recommend a computer: it is on far more often than an app is open on a phone, and the
iPhone gives an app little time in the background, so sync away from home just works.
When a computer that is always on joins a group of phones, the phone app offers to make it
the hub.

## At home: no hub needed

On one home network the devices find each other by themselves (mDNS) and connect directly.
Nothing leaves your network, and there is no server in the middle: any device can be off,
and the others go on syncing.

![At home every device talks to every other one directly, with no server](../images/at-home.svg)

**Two networks at home**, for example a separate network for smart devices: mDNS does not
cross the router, so devices on different networks do not find each other by themselves.
The phone apps remember each computer's addresses from its QR code and still reach it; a
lite member can be told a computer's address
([`-peer`](../../member/README.md#install)); and for
everything else a hub (below) joins both sides.

## Away from home: the hub

When a laptop or a phone leaves home, it needs a way back. One computer at home becomes
the group's **hub**: the devices that are away connect to it through the group's own
encrypted tunnel (WireGuard), and it passes the clipboard on to everyone at home.

![Away from home, the laptop and the phone reach the hub at home through the group's WireGuard tunnel](../images/hub.svg)

- The hub is your own computer: Linux, Windows, a Mac, FreeBSD or a router. It is one of two
  kinds. **A hub that reads the copies** is an admin, so the copies are sealed to it like to
  your other devices. **A hub that only passes copies on** can be any computer of the group,
  a Raspberry Pi with its keys in a file say: the copies are sealed end to end past it, so it
  reads none, and its keys need no security chip.
- Your router forwards one UDP port (8764) to the hub, so the internet can reach it.
- The hub does not have to stay on. While it is off, nothing syncs away from home, and the
  devices at home still sync without it.
- Devices pick up the hub's details while they are at home, so turn sync away from home on
  before you leave.

Setting it up is in [Away from home](away-from-home.md).

## When the internet cannot reach your hub: a forwarder

Many internet providers put homes behind a shared address (carrier-grade NAT), and then no
port forward helps. The hub can instead register with a **forwarder**, a server on the
internet that passes the tunnel's encrypted packets between your devices and your hub. The
hub dials out to the forwarder, so nothing at home has to be opened.

![The hub behind the provider's NAT dials out to a forwarder, which passes the tunnel from the devices away](../images/forwarder.svg)

The forwarder holds no keys and cannot read anything: it only sees encrypted packets going
to your hub, where they come from, when, and how large they are. Two kinds:

- **Your own**: `cbb forward` on any server with a public address, a cheap virtual server
  for example ([running your own servers](../admin/self-hosting.md)).
- **The Copy Beyond Borders forwarder** at `cbb.tools`, run by the project for everyone. It
  is being tested and not open to everyone yet; its address and key will be on this page
  when it opens.

Devices try the hub's own address first and the forwarder last.

## When the network blocks WireGuard

Some networks (hotels, offices, some countries) block VPN traffic. The hub can disguise the
group's tunnel:

- **Obfuscation** (`-obfuscate`): the tunnel speaks AmneziaWG, which does not look like
  WireGuard on the wire. Computers and both phone apps support it.
- **VLESS with REALITY** (`-vless`, through a forwarder): the devices reach the forwarder
  inside what looks like an ordinary HTTPS connection to a well-known website. For networks
  that block both of the above. Computers and both phone apps support it.

The lite member speaks only plain WireGuard, so with either of these it syncs at home only.

## Phones only: the phone as the hub

A group of just phones, or phones and a Mac, has no computer to be the hub. Two ways keep it
syncing away from home:

- **The phone as the hub**, while its app is open (Settings, **This phone as the hub**; on
  from the start in a group made on a phone). The other phones, TVs and lite members connect
  to it at home, and with a forwarder they reach it from afar too. On Android it can keep
  running in the background; an iPhone serves only while the app is open.
- **A blind relay of your own** (`cbb relay` on your server). It stands in for the hub as
  the meeting point, but it is not a member: the devices' encryption runs end to end through
  it, so it cannot read the clipboard. It does see which of your devices talk, and when.
  Computers and both phone apps can use it.

![A blind relay joins the laptop away and the Mac at home; the encryption runs end to end through it](../images/relay.svg)

A group may have several hubs: the root, every admin with a hub set up, and the hubs that only
pass copies on. Devices away from
home use the first one that answers, phones first, so a group of phones and a computer keeps
working while the phone's app is closed.

**Planned:** a blind relay at `cbb.tools` for everyone who does not want to run a hub or a
relay. It will see which devices talk and when, never what they copy, and you turn it on
yourself.

## What each server can see

| Server | Reads the clipboard | Knows which of your devices talk, and when | Whose it is |
|---|---|---|---|
| Hub that reads the copies | yes, it is your device and an admin | yes | yours |
| Hub that only passes copies on | no: the copies are sealed past it | yes | yours |
| Forwarder | no | no: it sees the addresses encrypted packets come from and go to your hub, when, and their sizes | yours, or the project's at `cbb.tools` |
| Blind relay | no | yes | yours (one at `cbb.tools` is planned) |

Nothing else is involved: no accounts, no cloud, no telemetry. Everyone else who can see
something, from your Wi-Fi to the update check, is listed in [privacy](privacy.md). With
sync away from home on, the Copy Beyond Borders service on a computer may reach only the home
network and the group's own hub, forwarder and relay.
