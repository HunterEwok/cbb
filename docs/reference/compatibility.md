<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Versions and compatibility

For users and administrators checking which releases of Connect Beyond Borders work together in
one group and what updates preserve. For architectural rationale, see
[Decisions](../decisions.md) (D-131); for normative wire rules, see [Protocol](../protocol.md).

## Group release compatibility

Every device in a group must run the same release (D-131). Interoperability across different
releases is not guaranteed while the wire format and record rules remain preliminary.

| Group configuration | Supported |
|---|---|
| All devices on the same release | Yes |
| Devices on different releases in one group | Not guaranteed; update all devices to the same release |
| Group created on 0.5 or earlier, upgraded to 0.6 | No; recreate the group once (see below) |

## Version numbers

Releases follow [Semantic Versioning](https://semver.org/). Prior to 1.0.0, minor versions (such
as `0.6.0`) introduce features or format changes, and patch versions (such as `0.6.1`) contain
fixes only. Security fixes ship in the latest release only ([SECURITY.md](../../SECURITY.md)).

### Wire format identifiers

| Component | Identifier | Specification |
|---|---|---|
| Member protocol | ALPN `cbb/4` | [Protocol](../protocol.md), section 4, "The member protocol in 0.6" |
| Pairing | ALPN `cbb-pair/3` | [Protocol](../protocol.md), section 6, "Pairing in 0.6" |
| Forwarder registration | ALPN `cbb-forward/3` | [Protocol](../protocol.md), section 13 |
| Blind relay registration | ALPN `cbb-relay/3` | [Protocol](../protocol.md), section 14 |
| Group signed records | Strict deterministic CBOR | [Protocol](../protocol.md), section 10, "Records in 0.6" |
| Local discovery (mDNS) | TXT `v=1` | [Protocol](../protocol.md), section 3 |

## Updating a group

Update every device in your group to the same release. Computers and small devices update with
`cbb update` or the daily update timer; phones and tablets update from their app store or release
APK ([Installing](../guide/install.md#updating)).

Within a compatible release series, an update preserves keys, settings, and group membership. If an
updated computer service fails to report the new version within 1 minute, `cbb update` rolls back
to the previous binaries automatically.

## Groups from 0.5 or earlier

Release 0.6 does not read record formats from 0.5 or earlier. On first start after updating from
0.5, a device leaves its old group automatically, keeps its local settings, and notes the reset in
`cbb status`. Recreate the group on your main device (in the phone app or with `cbb new`) and add
each device again ([Quick start](../guide/quickstart.md) or
[Without the app](../guide/without-app.md)).

## Automated compatibility checks

- **Upgrade check (`tools/e2e/upgrade.sh`)**: Starts members on the previous published release and
  upgrades them to the build under test, verifying that pre-0.6 groups leave cleanly with settings
  intact and that new groups sync.
- **Previous-release check (`TestPreviousRelease`, `tools/e2e/previous.sh`)**: Runs a member from
  the previous compatible 0.6 patch release alongside the build under test in one group.
- **Release signatures**: Every release is signed; devices install only verified releases and
  reject downgrades ([Protocol](../protocol.md), section 16).
