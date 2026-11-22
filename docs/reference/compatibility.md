<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Versions and compatibility

Which releases of Copy Beyond Borders work together, and what an update keeps. The reasons are
in the [decisions](../decisions.md) (D-131); the rules behind each line are in the
[protocol](../protocol.md).

## Keep one release in a group

0.6 promises no more than 0.5 did: a device works in a group with devices of its own release,
and the format of the group's records and messages may still change before 0.7 (D-131).

| You have | It works |
|---|---|
| A group where every device runs the same release | yes |
| A group with devices of different releases | not promised: update every device to the same release |
| A group made with 0.5 or earlier, on 0.6 | no: set the group up again once (below) |

## Version numbers

Releases follow [Semantic Versioning](https://semver.org/). Before 1.0.0 the middle number
(0.6, 0.7) marks a release with new features, and the last (0.6.1) a release with fixes
only. Security fixes go into the latest release only ([SECURITY.md](../../SECURITY.md),
"Supported versions"), so keep every device on it.

The formats on the wire have numbers of their own:

| Format | In 0.6 | Where |
|---|---|---|
| The member protocol | ALPN `cbb/4` | [protocol](../protocol.md), section 4, "The member protocol in 0.6" |
| Pairing | ALPN `cbb-pair/3` | [protocol](../protocol.md), section 6, "Pairing in 0.6" |
| The group's signed records | the records of 0.6, in one strict form of CBOR | [protocol](../protocol.md), section 10, "Records in 0.6" |
| mDNS | TXT `v=1` | [protocol](../protocol.md), section 3 |

## Updating a group

Update every device of the group. A computer or a small device updates with `cbb update` or
its daily timer, a phone or a tablet from its app store; the
[installation guide](../guide/install.md#updating) has the commands. Each update keeps the
device's settings, keys and place in the group, and a computer goes back to the previous
version by itself if the new one does not start.

## Groups made before 0.6

0.6 reads no records of earlier releases, so a group made with 0.5 is not carried over. At its
first start on 0.6 a device leaves the old group, says so in `cbb status`, keeps its settings,
and joins a new group like a new device: make the group again on the phone or with `cbb new`,
then add the devices ([quick start](../guide/quickstart.md), or
[without the app](../guide/without-app.md)).

## What is checked

- CI's upgrade test (`tools/e2e/upgrade.sh`) takes members of the last published release and
  updates them to the build under test: a member of a group made before 0.6 leaves it, says
  so and keeps its settings, and a new group works.
- Between fix releases of 0.6, the service's TestPreviousRelease puts a device of the previous
  fix release (`tools/e2e/previous.sh`) in one group with this build.
- Every release is signed, and a device installs only a signed release and never an older
  one ([protocol](../protocol.md), section 16).
