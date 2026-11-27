<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Authorized security audit

For the project maintainer and authorized auditors. This document defines the scope, rules,
objectives, test method, and exit criteria for an external, zero-knowledge security audit of
Connect Beyond Borders on the maintainer's own infrastructure.

This document is an audit plan, not a report. Audit findings stay private until fixed; fixes enter
[`CHANGELOG.md`](../../CHANGELOG.md) without disclosing vulnerability details
([SECURITY.md](../../SECURITY.md)). Read this plan alongside the
[hardware test bench](testbench.md) (section 9 lists the security test IDs referenced here),
[Threat model](../threat-model.md), [Protocol](../protocol.md), and [Design](../design.md).

## 1. Authorization and framing

All devices and servers in scope belong to the project owner, and the audit runs with the owner's
explicit authorization on owner-operated infrastructure. Its goal is defensive verification: confirm
that clipboard data cannot be read on the network, that an outsider cannot join a group or extract
useful information from members or servers, and that services stay stable under malformed input.

Although the owner holds all group keys, the audit runs **without** any group keys or internal
files to measure resistance against an unprivileged network attacker. The audit modifies nothing on
production or remote servers beyond normal `cbb` protocol traffic and never changes firewall rules.

## 2. Posture: an outsider with no access

The auditor operates as an attacker on the network holding none of the group's secrets:

- **No project secrets**: Root keys, admin keys, recovery keys, member keys, sealing keys, tunnel
  keys, server credentials, and invitations are never provided to the audit. Any secret the auditor
  uses must come from captured network traffic or online guessing.
- **No internal access**: Bench SSH keys, the device inventory, and operational credentials on
  target machines are off limits. The audit box communicates with targets only over the network as
  an external peer.
- **Independent attacker machine**: Installing standard open-source security tooling (packet
  captures, port scanners, TLS clients, and fuzzers) with local administrator rights on the audit
  box is permitted; do not use project-built binaries or internal test helpers to bypass protocol
  checks.

## 3. Scope

### Targets in scope

Targets are identified by their test bench roles (mapped to real devices in the private inventory
described in [The hardware test bench](testbench.md), section 13):

| Target | Role | Notes |
|---|---|---|
| `controller` | Bench controller on the home network | Acts as the audit box (attacker machine) |
| `desktop` | Linux desktop member and hub | Tested on the home network and on the away network |
| `win` | Windows member | Virtual machine on the home network |
| `small` | `cbb` without `cbb-helper` on a small Linux device | Second subnet |
| `mac` | macOS member | Home network |
| `cbb.tools` | Project production forwarder (`cbb-forward`) and blind relay (`cbb-relay`) | **Probe only CBB service ports; never modify `ufw` or any other service** |
| `remote` | Headless away member on a public server running other services | **Probe only CBB service ports; never modify `ufw` or any other service** |

On `cbb.tools` and `remote`, interact only with CBB's own listening ports. Do not stop,
reconfigure, or alter firewall rules (`ufw`) or unrelated services.

### Out of scope

- Phone and watch apps (iPhone, Android, Aurora OS, HarmonyOS), ESP32 firmware, Arduino Nano ESP32,
  and ZX Spectrum Next.
- Sustained denial-of-service floods against `cbb.tools` beyond brief, bounded probes; resource
  exhaustion caps are covered by automated budget tests in
  [The servers' budget](../relay-budget.md).
- Any device or host not listed in the scope table above.

## 4. Objectives

The audit verifies five security properties claimed by [Design](../design.md) and
[Threat model](../threat-model.md):

1. **Traffic confidentiality**: Only ciphertext travels on the wire—no clipboard content, device
   names, group names, TLS SNI, or routing metadata beyond unavoidable IP headers.
2. **Join resistance**: A group rejects devices presenting missing, unknown, expired, replayed, or
   revoked keys or pairing codes, and reveals nothing useful about the group on refusal.
3. **Server authentication and isolation**: The forwarder, blind relay, and hubs answer only peers
   presenting valid server credentials or authorized tunnel keys, isolate groups and clients from
   each other, and retain no clipboard content or group membership records.
4. **Robustness to malformed input**: Members, hubs, the forwarder, and the blind relay remain
   running and leak no sensitive data when sent malformed frames or unexpected input.
5. **Minimal exposure**: Port scans show only intended listening ports, local sockets enforce
   access control, state files carry owner-only permissions with no clipboard plaintext at rest,
   and fuzzing finds no crashes or leaks.

## 5. Method

Each block below corresponds to the security test IDs in [The hardware test bench](testbench.md),
section 9. Record every command, timestamp, and output for the audit report.

### 5.1 Traffic confidentiality (S1, S2, S9, S10)

Capture full packet traces on the home LAN (member traffic) and on both the away device's uplink
and `cbb.tools` (tunnel traffic). During capture, copy unique **marker** strings from each device
and record every marker and device name.

**Pass criteria**:

- LAN captures contain only TLS 1.3 records; away captures contain only WireGuard/AmneziaWG UDP
  packets or VLESS-over-XHTTP HTTPS traffic to the hub, forwarder, or blind relay.
- Searching captures for every marker string, device name, group name, TLS SNI, DNS group name, or
  internal tunnel address returns zero hits.
- Breaking the tunnel mid-run confirms the away device fails closed and sends nothing to any
  fallback address.
- Text sent with `cbb copy -secret` never appears in clear traffic or on disk and disappears after
  the group's secret lifetime (60 s by default).

### 5.2 Join resistance (S5, S7, S13, S14)

From the audit box (outside any group), attempt to join or connect as a member:

1. Dial a member port presenting no client key, an unknown self-signed key container, a key from
   another group, and a revoked device's key.
2. Replay a previously captured LAN TLS session.
3. Run `cbb pair -code` (on a computer and on a small device) with a wrong code, an expired code,
   and a code already spent.
4. Send a forged hello and a group record signed by a key outside the group.

**Pass criteria**:

- Every unauthorized connection and pairing attempt is refused, and refusal messages reveal nothing
  about group membership or keys.
- Three failed code attempts close the pairing window, and spent or expired codes fail.
- With two groups sharing one home network, no copies, records, or device lists cross between them,
  and neither can join the other without an authorized pairing code.

### 5.3 Server authentication and isolation (S3, S4, S6, S8)

Probe the forwarder (`cbb-forward`), blind relay (`cbb-relay`), and hub from outside the group:

1. Attempt registration with missing, malformed, expired, or unauthorized server credentials and
   confirm refusal returns no useful details.
2. If the audit box obtains a client tunnel session (for example, as a controlled test client),
   scan inside the tunnel for other clients' tunnel addresses and for any port on the hub other
   than the member port.
3. Revoke an away device and confirm the hub drops its tunnel key within one record round so it
   cannot sync or reconnect.
4. Confirm two groups on the forwarder or blind relay cannot reach each other, and compare
   server filesystem state before and after runs to verify that `cbb-forward` writes only its key
   and hashed credential-version state (no device lists, group records, or traffic logs) and
   `cbb-relay` writes only its own keys (no logs).

**Pass criteria**:

- Servers and hubs answer only authorized peers.
- Tunnel clients are isolated from one another, and a hub's tunnel interface exposes only the
  member port.
- Neither the forwarder nor the blind relay stores clipboard content, device names, device IDs, or
  group records on disk.

### 5.4 Robustness to malformed input (F-cases, S15)

Send truncated frames, oversized length prefixes, out-of-order messages, and random bytes to every
reachable endpoint: the member port, local control and admin sockets, the forwarder's registration
and forwarding listeners, and the blind relay's registration and tunnel listeners. Monitor process
memory and open file descriptors throughout.

**Pass criteria**:

- No service crashes, restarts, or leaks memory or file descriptors.
- Surfaced CLI errors show the plain user message by default, show underlying details only when
  `-debug` or `CBB_DEBUG=1` is set ([Error messages and details](../reference/errors.md)), and
  service logs record full error details in both modes.
- No log in either mode contains clipboard text, pairing codes, or private keys.

### 5.5 Port scanning, local access, and fuzzing (S4, S11, S12, S16)

1. Port-scan every in-scope target from the LAN and from inside an active tunnel.
2. Confirm installer firewall rules open only the member port (and mDNS UDP 5353) to the local
   subnet, and the UDP tunnel port only on a hub.
3. Confirm the control socket rejects users outside the `cbb` group (`_cbb` on macOS) and the admin
   socket rejects non-administrator users.
4. Inspect state directories ([Devices, ports and files](../reference/devices.md#files-and-logs))
   to confirm owner-only permissions on keys and state files and zero plaintext clipboard or secret
   items at rest.
5. Fuzz open ports for crashes, hangs, or information leaks.

## 6. Timing and conduct

Run the audit as a dedicated block separate from stability testing so security findings are not
mixed with soak noise:

1. Complete the soak run ([The hardware test bench](testbench.md), section 10).
2. Immediately afterward, run a bounded 2-hour audit block executing section 5 against every
   in-scope target.

Keep a timestamped log of every action against each target so every probe can be traced and
verified.

## 7. Reporting

Deliver all findings in a private written report to the project owner—never commit raw findings or
vulnerability details to the repository. For each objective in section 4, record:

- what was attempted and the exact commands run;
- what was observed (with log and capture references);
- the verdict (**pass**, **fail**, or **not tested**—never assume an untested property passes);
- for any failure, a concrete remediation recommendation.

Keep any private Russian translation for the owner outside the repository as well.

## 8. Exit criteria

The audit is complete when:

1. Every test block in section 5 has run against every applicable in-scope target.
2. Every objective in section 4 has an evidence-backed verdict (**pass**, **fail**, or
   **not tested**).
3. The private audit report has been delivered to the owner.

Any failure of traffic confidentiality or join resistance blocks the release, matching the priority
in [The hardware test bench](testbench.md), section 9.
