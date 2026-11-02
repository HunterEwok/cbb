# Authorized security audit (pre-0.4)

This document specifies an authorized security audit of Clipboard Bridge, run before the 0.4
release. It is a defensive exercise: we confirm that clipboard data cannot be read on the
network and that an outsider with no access cannot join a group or get a useful answer from
the servers.

Read it together with [the hardware test bench](testbench.md), whose section 9 lists the
security tests this audit carries out, and with [the protocol](protocol.md) and
[the design](design.md), which this audit measures against.

## 1. Authorization and framing

All devices and servers in scope are owned by the project owner, and the audit runs with the
owner's consent on the owner's own infrastructure. The goal is defensive: to confirm that the
clipboard data cannot be read on the network and that an outsider cannot join the group or
reach the servers.

We own and hold all of the group's keys and certificates, but we deliberately run this audit
**without** them, from the outside, to measure how well the system resists an outsider who has
no access. Only independently obtained tools are used; our own keys, certificates and internal
files are not. The audit changes nothing on the servers beyond what `cbb` itself changes, and
never any firewall configuration.

## 2. Posture: an outsider with no access

The auditor acts as an attacker who is on the network but holds none of the group's secrets.
To keep the result honest, the audit observes these rules:

- **No project secrets.** The group CA, admin CAs, member certificates and keys, tunnel
  preshared keys, invitation files and tokens are never used by the audit. Any secret the
  audit relies on must be obtained the way an outsider would: from captured traffic or by
  guessing, never read from a device or from the inventory.
- **No internal access.** The bench SSH keys, the device inventory, and any credentials left
  on a device for operational convenience are off limits. The audit box reaches the targets
  only as a peer on the network would.
- **The audit box is the attacker's own machine.** Installing tools on it and giving it normal
  admin rights is fine; that models an attacker's own equipment. The group and the servers are
  attacked only from the outside, with no owner secret.
- **Independently obtained tools only.** Packet capture, scanners, fuzzers and TLS clients are
  obtained independently (standard open-source tooling), not taken from the project's own
  build or helpers.

## 3. Scope

### Devices and servers in scope

| Target | What it is | Notes |
|---|---|---|
| `controller` | the bench's controller on the home network | also the audit box (attacker's machine) |
| `desktop` | a Linux member with a desktop, the hub | home network or the away network |
| `win` | Windows member | in a VM |
| `lite` | the lite member | a second subnet |
| `mac` | macOS member | home network |
| `cbb.tools` | the project's production forwarder | **touch only `cbb`/`cbb forward`; never change `ufw` or any other service** |
| `remote` | a server away from home, also running other services | **touch only `cbb`; never change `ufw` or any other service** |

The bench's inventory (docs/testbench.md, section 13) maps each role to a real device.

Everything reachable on these targets may be probed. On the two VPSes the audit interacts
only with Clipboard Bridge's own processes and ports; it does not stop, reconfigure or firewall
anything else, and does not alter `ufw`.

### Out of scope

The iPhone app and the shortcut (paused until the Apple developer account), the ESP32
firmware, the ZX Spectrum Next and the Arduino, and any device not listed above. Denial of
service against the production forwarder beyond brief, bounded probing is out of scope: the aim
is to measure resistance to reading and joining, not to take the service down.

## 4. Objectives

The audit answers five questions, each a property the design claims:

1. **Traffic confidentiality.** On the wire, only ciphertext is visible — no clipboard text,
   no device or group names, no routing metadata beyond what is unavoidable at the IP layer.
2. **Join resistance.** A group refuses to admit a device that offers invalid, expired,
   replayed or self-signed credentials, and tells an outsider nothing useful when it refuses.
3. **Servers refuse without a key.** The forwarder (`cbb.tools`) and a hub answer only peers
   that present a valid certificate chain; without one they give no useful response.
4. **Robustness to malformed input.** Members, the forwarder and the hub stay up and leak
   nothing when fed malformed frames and unexpected input.
5. **Exposure.** Port scanning shows only the ports the design intends to be open, and fuzzing
   finds no crash or information leak.

## 5. Method

Each block below maps to the security tests in [testbench.md](testbench.md) section 9. The
auditor records every command and its output; findings go to the report in section 7.

### 5.1 Traffic confidentiality (S1, S2, S9, S10)

Capture all traffic at two points: on the LAN (member traffic) and on the away device's uplink
and at the forwarder (tunnel traffic). During capture, run a full sync: copy known **marker**
strings from each device and note each marker and each device name.

Pass when the capture holds only TLS 1.3 records on the LAN and only WireGuard UDP (later also
the VLESS transport) to the hub or forwarder away from home, with no marker string, device
name, group name, TLS SNI, DNS name or tunnel address in the clear. The capture is searched for
every marker and every name; any hit is a finding. Break the tunnel mid-run and confirm an away
device sends nothing to any other address (fail closed). Confirm `copy -secret` text never
appears and is gone after its 60 s expiry.

### 5.2 Join resistance (S5, S7, S13, S14)

From the audit box, which is in no group, attempt to join or to be answered as a member:

- dial a member's port and present no certificate, a self-signed certificate, and a
  certificate from a different (foreign) CA;
- replay a connection captured earlier on the LAN;
- run `cbb pair -code` with a wrong code, an expired code, and a code
  reused after it was already spent;
- offer a forged hello and a record signed by a key that is not in the group.

Pass when every attempt is refused, the pairing attempt counter stops guessing within the
window, a spent or expired code is refused, and nothing about the group is revealed by the
refusal. With two groups on one network, confirm no text, record or device list crosses
between them and neither can pair into the other without a code.

### 5.3 Servers refuse without a key (S3, S4, S6, S8)

Against the forwarder and a hub, from outside the group:

- register / knock with no certificate, a foreign certificate, and malformed registration
  frames; confirm registration needs a valid certificate chain and a bad one is refused
  without a useful error;
- from inside a tunnel the audit box obtains as a client (if it can obtain one at all), scan
  for other clients' tunnel addresses and for any port other than the hub's member port;
- confirm a revoked device's tunnel key is dropped within one record round and it cannot sync
  or rejoin;
- confirm groups on the forwarder cannot reach each other, and that the forwarder writes
  nothing to disk but the groups' roots, removals and freezes, and keeps no logs (file system checked before and after a run).

Pass when only valid peers are answered, clients are isolated, the hub's tunnel address shows
only the member port, and the forwarder learns and stores nothing but the groups' roots, removals and freezes.

### 5.4 Robustness to malformed input (F-cases, S15)

Feed each listening endpoint — the member port, the control socket, the forwarder's
registration and forwarding paths — truncated frames, oversized length prefixes, wrong message
order, and random bytes. Watch each service's memory and file descriptors.

Pass when no service crashes, restarts or leaks; every surfaced error shows the friendly
message, with the real error under it only when `CBB_DEBUG=1`, and the log always records the
details. No log, in either error mode, holds clipboard text, a code or a key.

### 5.5 Port scanning and fuzzing (S4, S11, S12, S16)

Scan each target's ports from the network and, where obtained, from inside a tunnel. Confirm
the installers opened only the member port (and mDNS) to the local subnet and the tunnel port
only on the hub. Confirm the control socket refuses a user outside the `clipboardbridge` group.
Confirm the state directories hold only keys and certificates with owner-only permissions and
no clipboard text at rest. Fuzz the open ports for crashes and leaks.

## 6. Timing and conduct

The audit follows the 0.4 soak run and is a separate, bounded block:

1. the 4-hour soak run on the home network plus one away device (testbench section 10);
2. immediately after it, a 2-hour audit block that runs the method above.

The two run in that order, not at the same time, so a finding is not confused with soak
noise. The auditor keeps a timestamped log of every action against every target, so each step
can be traced and undone.

## 7. Reporting

Findings go into a written report, and nothing leaves the owner's hands. Each finding records
what was attempted, what was observed, whether it passed or failed against the objective in
section 4, and, for a failure, a recommendation. The report states plainly where a property
held and where it did not; a property that could not be tested is marked as such rather than
assumed to pass.

Per the project's documentation rule, the report is written in English for the repository and
accompanied by a Russian copy for the owner that is not committed.

## 8. Exit criteria

The audit is complete when every block in section 5 has run against every in-scope target it
applies to, each objective in section 4 has a pass/fail/not-tested result backed by recorded
evidence, and the report (with its Russian copy) is delivered. A failure of any confidentiality
or join-resistance objective is a release blocker for the off-home-network feature, consistent
with the top priority stated in [testbench.md](testbench.md) section 9.
