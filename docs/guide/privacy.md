<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Privacy: who sees what

For anyone who wants to know what leaves their devices. Copy Beyond Borders has no accounts, no
cloud and no telemetry: what you copy goes only to the devices of your group, and every
device of the group can read it. On the way it is encrypted between each two devices, so no
server or network in between can. This page lists everything else that someone outside the
group can see, and how to turn it off.

## What you copy

Texts, images and files pass only between the devices of your group, inside TLS 1.3 with
the group's own certificates. Away from home they also pass inside WireGuard, through your
hub, and perhaps through a forwarder or a relay. No server, network or provider can read
them, the project's servers included. A device that is removed from the group gets nothing
more.

Two things are exceptions, and both are your choice:

- A **Roku** added with `cbb remote add -roku -consent` gets its text as plain HTTP on your
  home network ([keyboards and TVs](keyboards-and-tvs.md#a-computer-as-the-tvs-remote)).
- A **hub** is one of your own devices, so it reads the copies like any other member and
  passes them on. The clipboard is not encrypted end to end from the device that copies to
  the one that pastes: each device of the group reads it. Only commands, such as a remote
  paste or a quick action, are sealed to the one device they are for, so a hub that passes
  them on cannot read them ([remote paste](remote-paste.md)).

## Everyone else

| Who | What they can see | How to avoid it |
|---|---|---|
| Others on your home network | that devices there run Copy Beyond Borders, their random device IDs and your group's tag in mDNS, and which of them talk and how much; never device names or contents | nothing to do; a computer publishes only on the home networks it knows (a lite member on every network) |
| Others on a network away from home (a café, a hotel) | that the device talks WireGuard, or with VLESS that it opens a TLS connection to your hub or forwarder, when and how much | a system VPN hides even that |
| The forwarder (yours, or the project's at `cbb.tools`) | the addresses that encrypted packets come from and go to your hub, when, and how large they are; not which group or device they belong to | run your own, or forward a port to your hub and use none |
| A blind relay | which devices of a group are online now and talk to each other, when and how much; it keeps none of it | run your own, or use a hub |
| The company that hosts a forwarder or relay | the addresses that talk to it, when and how much | a system VPN on the device |
| GitHub, or `dl.cbb.tools` when GitHub does not answer | your address and that you use Copy Beyond Borders, at each update check and download; nothing about the group | `sudo cbb update -auto off`, or a mirror of your own (`-mirror`) |
| `cbb.tools` | the root's address, once a day, when it fetches the signed copy of Google's list of revoked Android keys (once that copy starts, with the project's signing keys) | none needed: it is the same file for everyone |
| Apple, Intel or AMD | that a device of that kind asked them to vouch for its key, from your address | only at the **strict** key level; the default asks no one ([keys](keys.md#the-three-levels)) |
| The App Store, Google Play, F-Droid, Homebrew, winget | that you installed the app, as for any app | install the signed file from the release instead |

Nothing reports crashes or usage. The logs stay on each device; with error details on
(`CBB_DEBUG=1`), they hold more of the cause, still only on that device.

## The website

`cbb.tools` counts visits with its own GoatCounter, without cookies and without sending
anything to another company. The apps and the service never load anything from it apart
from the files above.

## More detail

- What a forwarder and a relay keep, and what their hosting provider sees:
  [running your own servers](../admin/self-hosting.md#what-the-server-keeps).
- What each server learns, field by field: the [protocol](../protocol.md), sections 13
  and 14.
- The attacks Copy Beyond Borders defends against, and those it does not: the
  [threat model](../threat-model.md).
