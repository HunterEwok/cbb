<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Privacy: who sees what

For anyone who wants to know what leaves their devices. Copy Beyond Borders has no accounts, no
cloud and no telemetry: what you copy is encrypted end to end, sealed on the device that
copies it for the devices of your group that read copies, and nothing else can open it: no
server, no network, no device in between. This page says what the devices that pass a copy on
can still see, and everything that someone outside the group can see, and how to turn it off.

## What you copy

Texts, images and files are sealed end to end. The device that copies encrypts each copy
with a key made for that copy alone, wraps the key for each device of the group that reads
copies (X-Wing, which joins X25519 and the post-quantum ML-KEM-768) and signs the copy with its
member key. Only those devices can open it; every device checks the signature, so none can
change a copy or make one in another's name. The sealed copy then travels inside TLS 1.3 with
the group's own certificates, and away from home inside WireGuard as well, through your hub
and perhaps a forwarder or a relay. No server, network or provider can read it, the project's
servers included. A device that is removed from the group gets nothing more, and a device that
joins reads copies from its next one on, not the ones made before it.

## What the devices in between see

A copy often reaches a device through another: through the hub away from home, or through a
computer that passes it on at home. Those devices read nothing of a copy that is not sealed to
them, but passing it on needs a little, which stays outside the seal:

- **Which device sent it, and when.** The time decides which copy is the newest, which every
  device needs, a hub that only passes copies on included.
- **Which devices it is sealed to.** That is the group's list of devices, which they know
  anyway.
- **Its size in steps** (1, 4, 16, 64 and 256 KB, 1 MB, then each further megabyte), and
  whether it has an image or files, with their total to 64 KB. All the files of one copy are
  one sealed piece, so their number does not show.

What never shows: whether it is a text, a secret, an image or files; the text; the files'
names; the exact size.

## Exceptions

Both are your choice:

- A **Roku** added with `cbb remote add -roku -consent` gets its text as plain HTTP on your
  home network ([keyboards and TVs](keyboards-and-tvs.md#a-computer-as-the-tvs-remote)).
- A **hub that reads the copies** is an admin you chose, so the copies are sealed to it like
  to your other devices. Make an always-on computer whose keys are only in a file, such as a
  Raspberry Pi, a **hub that only passes copies on** instead: no copy is sealed to it, so it
  reads none ([away from home](away-from-home.md)). Commands, such as a remote paste or a
  quick action, are sealed to the one device they are for in either case
  ([remote paste](remote-paste.md)).
- An **Apple Watch** or a **Wear OS** watch gets the copies from its phone over the channel
  the system encrypts between the two, not sealed by Copy Beyond Borders.

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
