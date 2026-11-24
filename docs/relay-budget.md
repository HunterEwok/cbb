<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The servers' budget

For engineers and security reviewers: what unauthenticated or unknown clients can make the open
blind relay and the forwarder allocate or compute, how multi-level accounting bounds that cost,
how `cbb.tools` monitors traffic, and how abuse reports are handled.

Both the open blind relay (`cbb relay -open`) and the forwarder (`cbb forward`) serve any
registering group without accounts. To protect existing groups against resource exhaustion, every
state allocation and unit of work is charged to its source across multiple network-prefix levels,
and full caps reject new requests without evicting existing groups.

The forwarder (Go) implements this accounting in `internal/budget` (`budget.Count` for held state,
`budget.Rates` for per-second work with burst). The relay (Rust) implements the same model in
`member/src/relayd/budget.rs` (`Count`, `Rates`). Wire protocols are specified in
[Protocol](protocol.md), sections 13 and 14; user-facing server limits are summarized in
[Limits and lifetimes](reference/limits.md#servers).

## Payers

Every source IP address pays simultaneously at each prefix level below, plus a global cap across
all sources:

| Level | IPv4 | IPv6 | Represents |
|---|---|---|---|
| Address | `/32` | `/128` | Single host |
| Network | `/24` | `/64` | Single home or office |
| Wide network | `/16` | `/48` | Single site or ISP customer allocation |
| Provider | (same `/16`) | `/32` | Single IPv6 provider (an IPv4 `/16` is its own provider and pays once) |
| All | — | — | All sources combined |

A charge is checked against every level of its source at once and rejected without charging
anything if any level would exceed its cap. Selected resources are also charged per group (its
devices or calls) or per VLESS user ID (its handshakes).

## Accounting rules

1. **Reject new work when full.** Full caps reject incoming registrations or allocations; the
   server never evicts an existing group or source to make room.
2. **Rejections leave no state.** A refused registration stores nothing about the refused group
   (no period, version, or counter) and leaves existing registrations untouched.
3. **Caps resist horizontal spreading.** Gaining more capacity requires more wide networks (not
   more addresses within one) and, over IPv6, more `/32` providers (not more `/48` prefixes inside
   one `/32`). Every wide-network cap sits under an IPv6 provider cap.
4. **Idle state expires.** Registrations end when their TCP connection closes; a group's period
   entry on the relay ends when its last device disconnects; credential versions on the forwarder
   expire with their credential (at most 35 days).

## The relay

| State or work | Cost | Lifetime | Charged to | Cap per payer | Global cap | When full |
|---|---|---|---|---|---|---|
| Registration setup | OS thread (256 KiB stack) and TLS handshake; one ECDH | 15 s max | address, network, wide network, provider | 16, 64, 128, 128 | 256 | Connection closed |
| Setup work rate | 4 units per setup | — | address, network, wide network, provider | 64, 256, 1,024, 2,048 units/s (bursts: 1,536, 4,096, 8,192, 16,384) | — | Connection closed |
| Registered device (open relay) | Tunnel peer and entry (~2 KiB) | Duration of registration TCP connection | address, network, wide network, provider; group | 16, 64, 256, 1,024; 64 per group | 4,096 groups; 4,096 devices | Refused |
| Period entry | Period key, versions, member list | Until last device of group leaves | group | 1 per period tag | 4,096 groups | Refused |
| In-tunnel request being read | OS thread (256 KiB stack) | 5 s max | device, group; registration source (address, network, wide, provider) | 16, 32; 32, 64, 64, 128 | 256 | Connection closed |
| Pending call waiting for answer | Ticket | 10 s max | called device | 16 | — | Refused |
| Joined call pairs | Two forwarding streams | While both ends stay connected | group | 256 | — | Refused |
| Call connection, waiting or joined (open relay) | Tunnel socket, two 64 KiB buffers | While open | group; each end's registration source (address, network, wide, provider) | 512 per group; 128, 256, 1,024, 2,048 | 4,096 (half of tunnel connections) | Refused |
| Tunnel TCP connection (opening or open) | Tunnel socket, two 64 KiB buffers, 3 open file descriptors | Opening: 5 s max; half-closed drain: 10 s max | device; beyond first 2 per device: registration source (address, network, wide, provider); opening also by source | 80 per device (first 2 guaranteed regardless of load; 4 opening); beyond first 2: 296, 592, 2,368, 4,736; opening: 8, 32, 128, 256 | 9,472 plus 2 per device; 1,024 opening | Ignored |
| WireGuard handshake initiation | One Diffie-Hellman (~50 µs) | — | source network, wide network, provider; for a client's last-seen IP: address and network | Valid `mac1` required first; above 512 DH/s, cookie required for unknown IPs; 32, 128, 512/s for unknown IPs; 4 and 32/s for known client IPs | 1,536/s unknown + 512/s known client IPs | Dropped |
| Data forwarding | Bandwidth | — | group | 1 MiB/s (2 s burst) | — | Throttled |
| Queued watch note | Queued line | Until sent | watching device | 32 | — | Watch closed |
| Source rate-limit bucket | ~150 bytes per payer | Until refilled (<30 s) | self | — | Swept past 4,096 entries when full | Evicted when full |

### Relay guarantees

- **No eviction**: No volume of unknown registrations evicts a previously registered device or
  period.
- **Registration headroom**: Exhausting 4,096 groups requires holding connections open from at
  least 16 wide networks (`4,096 / 256`) or 4 IPv6 providers (`4,096 / 1,024`).
- **Short-lived slots**: Exhausting all 256 request slots requires at least 4 wide networks
  (`256 / 64`) or 2 IPv6 providers (`256 / 128`), and each slot clears within 5 s. Exhausting all
  256 setup slots requires at least 2 wide networks or 2 IPv6 providers, and each clears within
  15 s. Allowing one provider up to half of these short-lived slots is an accepted bound; lasting
  registration state requires at least 4 providers.
- **Tunnel sockets and open files**: Because the open relay registers at most half as many devices
  (4,096) as its base tunnel connections (8,192), every registered device keeps room for its watch
  connection, while the other half serves calls. Taking all 4,096 call slots requires at least 4
  wide networks or 2 IPv6 providers. Every device's first 2 connections bypass shared caps so its
  watch and one call survive full load; additional connections charge the registration source
  (296 / 592 / 2,368 / 4,736). Connections ended by the relay terminate 10 s after the last read
  even if the peer keeps TCP alive. Worst-case memory is `(9,472 + 2 × 4,096)` sockets of two
  64 KiB buffers (~2.2 GiB plus bridge queues) and ~57,600 file descriptors. At startup, the relay
  raises its soft `RLIMIT_NOFILE` to the hard limit (`LimitNOFILE=65536` in
  `packaging/linux/cbb-relay.service`, `ulimits` in `packaging/docker/compose.server.yaml`) and
  scales down tunnel connections and device caps if the OS grants fewer (`limits_fit_the_open_files`).
  Unrecognized loopback connections to the tunnel stream port are closed immediately
  (`stream_port_knows_only_the_hub_s_connections`).
- **Handshake CPU protection**: WireGuard initiations require a valid `mac1` under the relay's
  public key before costing a Diffie-Hellman. Above 512 DH/s, unknown source IPs must also echo a
  stateless cookie. Unknown sources share 1,536 DH/s (32 / 128 / 512 per network / wide /
  provider), while 512 DH/s (4 per IP, 32 per network) are reserved for clients' last-seen IPs so
  existing clients can rekey during floods. A spoofed flood from a client's IP consumes only that
  IP's 4/s and network's 32/s share. Device hubs apply the same limits (AmneziaWG hubs omit cookies
  while keeping the same per-source caps).
- **No lingering state**: After unknown devices disconnect, only temporary rate buckets remain,
  which sweep once full (`open_relay_forgets_strangers`).

A private relay (`cbb relay -group`) enforces the per-group and setup/request/call caps and
refuses all unlisted groups.

## The forwarder

| State or work | Cost | Lifetime | Charged to | Cap per payer | Global cap | When full |
|---|---|---|---|---|---|---|
| Registration (setup or active) | Goroutine and TLS connection | Duration of registration TCP connection | address, network, wide network, provider (including over VLESS) | 16, 64, 256, 1,024 | 256 in setup; 100,000 groups | Closed / refused |
| Client state per group | Entry per client address, pending handshake, and session | 10 s handshake, 200 s session | group | 16 client addresses, 64 pending handshakes | — | Dropped |
| Packet forwarding | Bandwidth and packet rate | — | group | 1,000 packets/s and 2 MiB/s | — | Dropped |
| Credential version (period entry) | ~400 bytes RAM, ~200 bytes disk | Until newest credential expires (35 days max) | network, wide network, provider | 256, 1,024, 4,096 | 100,000 | Refused |
| VLESS user ID | Xray user entry | Duration of registration | registration | 1 per group | Same as registrations (1,024 over VLESS) | Refused |
| Handshake from unknown IP | One keyed BLAKE2s per registered group | — | source address, network, all | 10/s per IP; 1/16 of global per network | 500,000 checks/s | Dropped |
| Handshake over VLESS | One check against user ID's group | — | VLESS user ID | 10/s | — | Dropped |
| Handshake from IP with active session | One check per group on that IP | — | source address | 10/s | — | Dropped |
| Source and network rate-limit LRUs | One bucket entry each | Until evicted | — | — | `4 × Groups` entries | Oldest evicted |

### Forwarder guarantees

- **No eviction or record storage**: Unknown traffic never evicts an active hub registration or
  credential version. The forwarder stores no device lists or group records
  (`TestRegistrationKeepsNoRecords`).
- **Period renewal headroom**: Filling the 100,000-entry version table requires at least 98 wide
  networks (`100,000 / 1,024`) or 25 IPv6 providers (`100,000 / 4,096`) holding entries across
  their 35-day lifetime (`TestVersionsProviderLeavesRoom`). Every new version entry requires a full
  registration.
- **Active clients stay unaffected**: Rekey handshakes from an IP with an existing session check
  that group directly without spending the global scan budget, and VLESS clients route directly by
  user ID (one check), isolating them from UDP handshake floods.
- **New client scan budget**: An initial UDP handshake from a new IP must scan registered groups
  and shares the 500,000 checks/s budget (each network is capped at 1/16). Because UDP source IPs
  can be spoofed, floods can delay new UDP clients until the flood pauses and clients retry every
  5 s; this is an accepted bound.
- **Bounded memory**: Stored version state is bounded by 100,000 entries of ~400 bytes
  (`TestVersionsMemoryBounded`).

### XHTTP

VLESS over XHTTP behind a front-end web server (`cbb forward -vless-xhttp`) can queue uploads in
Xray before identifying the VLESS user and retain unopened sessions for 30 s. Because the front-end
web server connects over loopback, it passes the client IP in `X-Real-IP`, and the forwarder's
HTTP front (`internal/vless/front.go`) enforces upload budgets before forwarding to Xray:

| Resource | Limit | Enforced by |
|---|---|---|
| Single upload body | 32 KiB (`MaxPostBytes`) | Forwarder and web server (`client_max_body_size`) |
| Queued uploads per session | 8 (`MaxBufferedPosts`, 256 KiB per session for 30 s) | Forwarder |
| Uploads to sessions without an open download (`GET`) | 32/s per IP and network, 64/s per wide network, 128/s per IPv6 provider, 256/s global (bursts: 64, 64, 128, 256, 512) | Forwarder HTTP front |
| HTTP requests | 150/s per IP (burst 300) | Web server |
| Concurrent HTTP requests | 16 per IP, 1,024 global | Web server |

Uploads to a session whose `GET` download stream is already open drain immediately and cost
nothing. Unopened-session uploads are capped at `(512 + 30 × 256) × 32 KiB ≈ 256 MiB` across all
sources—fitting within `GOMEMLIMIT=768MiB` and `MemoryMax=1G` in
`packaging/linux/cbb-forward.service`. A single IP or network can hold at most ~30 MiB, and filling
the global share requires at least 2 wide networks or 2 IPv6 providers. Legitimate clients open
their `GET` download on startup and send uploads of at most 32 KiB, so floods delay at most their
initial few uploads.

Hub registrations over VLESS (`RegistrationID`) share the same setup slots and per-source caps
using the client IP from `X-Real-IP`. If the web server does not supply a client IP, VLESS
registrations share at most 1/8 of setup slots so direct registrations keep headroom, and total
VLESS registrations are capped at 1,024.

## Money and traffic

The project's forwarder and open relay run on a fixed-price rented server at `cbb.tools` alongside
the website and release mirror. Traffic does not increase the monthly bill, but sustained high
transfer triggers a hosting-provider bandwidth throttle (200 Mbit/s when the 24-hour total exceeds
~2 TB on the current plan), which would slow every group, the website, and the mirror.

Traffic is monitored publicly without recording per-group or per-IP data:

- `site/deploy/cbb-traffic.timer` (`site/README.md`, "The server", step 8) samples the network
  interface every 15 minutes and publishes rolling 24-hour totals at
  `https://cbb.tools/status/traffic.json`.
- The `monitor` workflow (`.github/workflows/monitor.yml`;
  [Maintaining](maintainers/maintaining.md), "Watching cbb.tools") alerts the maintainer if
  24-hour traffic exceeds 1 TB (half the throttle threshold) or if `traffic.json` is more than 2
  hours old.

Response order when the check alerts:

1. **Check for abuse from one source**: Inspect provider metrics and firewall counters; if a source
   loads the servers intentionally, block it at its network or provider level per the
   [terms](https://cbb.tools/terms.html) ("What is not allowed").
2. **Scale for legitimate growth**: Add a second forwarder or relay server (distributed to devices
   via signed entry points without a release) or upgrade the server plan ([Roadmap](roadmap.md),
   items 54 and 56).
3. **Never add global byte caps per group**: Per-group rate limits already isolate groups from one
   another, and a total byte quota would break active groups.

## Abuse reports

Abuse reports go to `abuse@cbb.tools` ([terms](https://cbb.tools/terms.html), "Reports and
changes"). Because the servers inspect no clipboard content, keep no traffic logs, and store no
group names, enforcement is scoped strictly to refusing the reported group tag:

- `cbb forward` and `cbb relay` read `refused-groups` beside their key file (or the path passed to
  `-refused`; `-refused none` disables). Each line lists a 16-hex-character group tag (from
  `cbb status`) or `period TAG` (a 32-hex-character period tag for credential-based registrations;
  [protocol.md](protocol.md), section 18). Comments begin with `#`, and trailing text after a tag
  is ignored.
- Servers reload the file within 10 s without restarting. Listed groups are refused at registration
  with a message citing the operator's terms, and their active registrations are dropped. Invalid
  syntax or unreadable files fail startup (preventing silent bypass) and retain the previous list
  on reload. A file missing on one reload keeps the previous list (safe across atomic editor saves)
  and clears the list if missing on two consecutive reloads.
- Removing a tag lets the group register again immediately.
- Reports must include the group or period tag shown by a device in that group. Groups using
  rotating server credentials present a new period tag each 35-day period by design, so a
  `period TAG` refusal lasts until that period ends.
- Refused tags and abuse reports remain private with the maintainer and are never committed to the
  repository.

Refused-list handling is tested by `TestRefusedGroups` (`internal/forward`), `refused_groups`
(`member/src/relayd/tests.rs`), `internal/refused`, and `member/src/relayd/refused.rs`.

## Tests

The forwarder's guarantees are tested in Go (`internal/budget`, `internal/forward`,
`internal/vless`) and the relay's in Rust (`member/src/relayd/tests.rs`,
`member/src/nettest/relayd.rs`, `member/src/hub.rs`):

- **Clean refusals**: `a_refused_registration_leaves_nothing` (relay),
  `TestRefusedRegistrationLeavesForwarder` (forwarder).
- **Property tests across payers (fixed seed)**: `TestCountProperty`, `open_relay_budget_property`,
  `TestVersionsBudgetProperty`.
- **Bounded memory and state cleanup**: `open_relay_forgets_strangers`,
  `TestVersionsMemoryBounded`, `TestRegistrationKeepsNoRecords`.
- **Per-level payer caps and client isolation**: `TestCountProvider`,
  `TestVersionsWideNetworkLeavesRoom`, `TestVersionsProviderLeavesRoom`,
  `registrations_bound_by_provider`, `TestRegistrationsBoundByEveryLevel`,
  `requests_bound_by_wide_network`, `TestVLESSUsersLeaveTheScanBudget`,
  `TestKnownClientKeepsItsGroup`.
- **Relay tunnel sockets, open files, and handshake CPU limits**:
  `a_closed_connection_is_not_held_open`, `open_connections_are_shared_by_source`,
  `call_connections_bound_by_source_and_group`, `registrations_bound_by_the_tunnel`,
  `connections_are_held_per_client`, `half_open_connections_hold_a_client_s_share_only`,
  `a_full_hub_still_takes_each_client_s_few`, `TestManyDevicesThroughRelay`,
  `limits_fit_the_open_files`, `stream_port_knows_only_the_hub_s_connections`,
  `initiations_are_checked_before_the_hub_pays_for_them`, `handshakes_are_shared_by_source`,
  `garbage_does_not_put_the_hub_under_load`.
- **XHTTP and VLESS budgets**: `TestXHTTPHoldsLittleForStrangers`, `TestFrontUploadsPayBySource`,
  `TestFrontClientAddress`, `TestRegistrationStream`, `TestRegistrationsOverVLESSPayBySource`.

Add every new server limit to this document and to `internal/budget` /
`member/src/relayd/budget.rs` together so adjacent states cannot bypass it.
