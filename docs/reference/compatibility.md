<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Versions and compatibility

Which releases of Copy Beyond Borders work together, what an update keeps, and how a device
of an older release behaves when it meets something newer. The reasons are in the
[decisions](../decisions.md) (D-92) and the [design](../design.md), "Versions in one group";
the rules behind each line are in the [protocol](../protocol.md).

## The promise

From 0.6 on, a device of one release works in a group with devices of the release before it:
0.7 with 0.6, 0.8 with 0.7. The same holds for every kind of device: a computer, a small
device, a phone, a tablet and a watch.

| You have | It works |
|---|---|
| A group where every device runs the same release | yes |
| A group of 0.7 devices and 0.6 devices | yes, while you update them one at a time, in any order |
| A group of 0.8 devices and 0.6 devices | not promised: update the 0.6 devices first |
| A group made with 0.5 or earlier, on 0.6 | no: set the group up again once (below) |

An update never breaks a group and never makes you set it up again. Before 1.0.0 the
promise covers one release back; it does not wait for 1.0.0.

## Version numbers

Releases follow [Semantic Versioning](https://semver.org/). Before 1.0.0 the middle number
(0.6, 0.7) marks a release with new features, and the last (0.6.1) a release with fixes
only, which works with every device of its own release. Security fixes go into the latest
release only ([SECURITY.md](../../SECURITY.md), "Supported versions"), so keep every device
on it; the promise above is what lets you update them one at a time.

The formats on the wire have numbers of their own, which change far less often than the
release and never because of it:

| Format | In 0.6 | Where |
|---|---|---|
| The member protocol | ALPN `cbb/3` | [protocol](../protocol.md), section 4, "Hello" |
| Pairing | ALPN `cbb-pair/2` | [protocol](../protocol.md), section 6 |
| The group's signed records | `v` 2 | [protocol](../protocol.md), section 10 |
| mDNS | TXT `v=1` | [protocol](../protocol.md), section 3 |

A change that a device of the release before could not read takes a new record version,
message field or feature name, never a new meaning for an old one.

## Updating a group

Update the devices in any order. A computer or a small device updates with `cbb update` or
its daily timer, a phone or a tablet from its app store; the [installation guide](../guide/install.md#updating)
has the commands. Each update keeps the device's settings, keys and place in the group,
and a computer goes back to the previous version by itself if the new one does not start.

While some devices are updated and some are not, copies go both ways between them. The
devices of a group tell each other of the newest signed release any of them has seen, so
`cbb status`, the tray app and the apps say when a device has a newer release waiting, and
the devices list marks the devices that run an older one.

## When an older device meets something newer

Something only a newer release understands never stops an older device:

- **A new kind of record** (a new type or field in the group's signed records) comes with a
  new record version. An older device keeps such a record, passes it on in sync unchanged
  and asks its user to update; the group goes on under the records it can read. Only the
  group's root and admins can sign one, so nobody else can raise this request
  ([protocol](../protocol.md), section 10, "Records of a later version").
- **A new message or field** between members is ignored by a device that does not know it.
  A member says what it supports beyond its protocol in its hello (`features`), never by its
  release number, so a newer device does not send an older one what it cannot read
  ([protocol](../protocol.md), section 4, "Hello").
- **A new capability or mDNS key** is ignored by a device that does not know it, in a hello or
  in a TXT record ([protocol](../protocol.md), sections 3 and 4).

## Groups made before 0.6

0.6 changed the group's records (version 2, in one strict form of CBOR) and reads no records
of earlier releases, so a group made with 0.5 is not carried over. At its first start on 0.6
a device leaves the old group, says so in `cbb status`, keeps its settings, and joins a new
group like a new device: make the group again on the phone or with `cbb new`, then add the
devices ([quick start](../guide/quickstart.md), or [without the app](../guide/without-app.md)). This happens once; from 0.6 on
every group is carried over.

## What is checked

- CI's upgrade test (`tools/e2e/upgrade.sh`) takes members of the last published release,
  makes a group with them, then updates them to the build under test one at a time: the
  group, its devices and copies both ways must survive each step.
- The interop vectors (`testdata/interop`) fix the records' and messages' bytes, so a later
  release that reads a vector differently fails its own tests.
- Every release is signed, and a device installs only a signed release and never an older
  one ([protocol](../protocol.md), section 16).
