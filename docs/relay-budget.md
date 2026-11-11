<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The servers' budget

For engineers and security reviewers: what strangers can make the open relay and the
forwarder hold and do, who pays for it, and what a genuine group keeps whatever they do.

The open relay (`cbb relay -open`) and the forwarder (`cbb forward`) serve any group that
registers, not only their operator's: that is one of the project's goals, and it stays. It
also means that anyone on the internet can make groups of their own and register them. The
servers stay safe for the groups already on them by a budget: every piece of state and work
a stranger can start is charged to whoever started it, each payer has a cap, and what is full
refuses the new. The code keeps the accounting in one place, `internal/budget`, which both
servers use; the wire format and the numbers a client sees are in [protocol.md](protocol.md),
sections 13 and 14, and the user-facing limits in [limits](reference/limits.md).

## Payers

A source address pays at each of its levels, and all sources together at one more:

| Level | IPv4 | IPv6 | What it stands for |
|---|---|---|---|
| Address | /32 | /128 | one host |
| Network | /24 | /64 | one home or one office: a host usually gets one address of an IPv4 /24 or a whole IPv6 /64 |
| Wide network | /16 | /48 | one site or one provider's customer |
| Provider | (the /16) | /32 | one provider, which hands out tens of thousands of /48s from its /32; IPv4 addresses are too scarce for one source to hold many /16s, so an IPv4 /16 is its own provider and pays once |
| All | | | every source together |

A charge goes to all the levels of its source at once, and is refused when any level would
pass its cap; a refusal charges nothing. Besides the sources, some state is charged to the
group (its devices, its records) or to a VLESS user ID (the handshakes of its clients).
State that is held (registrations, entries, records) is counted by `budget.Count`; work that
is done (setups, record checks) is paid for by the second, with a burst, by `budget.Rates`.

## Rules

1. **Refuse the new.** When a cap is full, the new registration, entry or record is refused.
   Nothing a source or a group holds is taken from it to make room for another. The one
   exception is memory nobody holds: the records the forwarder remembers of groups that are
   not registered now, which are forgotten once 32 MiB are held, from the provider that
   holds the most of them.
2. **A refusal leaves the server as it was.** A refused registration, for any reason, keeps
   nothing of the refused group: no period, version, record or count; the devices and groups
   registered before stay as they were.
3. **Every cap has a payer that cannot be spread thin.** A stranger who wants more needs more
   wide networks, not more addresses inside one; and over IPv6 more providers, not more /48s
   inside one /32, which a provider has by the ten thousand. Every cap of a wide network has
   a cap of the IPv6 provider above it.
4. **What a stranger leaves behind ends.** Registrations end with their connections; a
   group's records and period on the relay go with its last device; the forwarder's versions
   go when their credential expires, at most 35 days after they were kept.

## The relay

| State | Cost | Lifetime | Charged to | Cap per payer | Cap in all | When full |
|---|---|---|---|---|---|---|
| Registration being set up | a goroutine and a TLS handshake, about 50 KiB; one ECDH | 15 s at most | address, network, wide network, provider | 16, 64, 128, 128 | 256 | the connection is closed |
| Setup, paid by the second | 4 units | | address, network, wide network, provider | 64, 256, 1024, 2048 units a second; bursts of 1536, 4096, 8192, 16384 | | the connection is closed |
| Registered device (open relay) | a tunnel peer and its entry, about 2 KiB | while its connection lasts | address, network, wide network, provider; group | 16, 64, 256, 1024; 64 devices of a group | 4096 groups | refused |
| A group's authority records | their bytes; one ECDSA check each, once | until the group's last device leaves | the group; the network, wide network and provider that brought them | 256 KiB a group; 1 MiB a network, 4 MiB a wide network, 16 MiB a provider | 128 MiB | refused, none of them kept |
| Record check | about 45 µs | | address, network, wide network, provider | 1 unit each, from the same allowance as setups | | refused |
| Period (registration with credentials) | the period key, versions and members' list | until the group's last device leaves | the group | one per period tag | 4096 groups | refused |
| Request being read in a tunnel | a goroutine | 5 s at most | device, group; address, network, wide network, provider the device registered from | 16, 32; 32, 64, 64, 128 | 256 | the connection is closed |
| Call waiting for an answer | a ticket | 10 s at most | the called device | 16 | | refused |
| Joined connections | two copies | while both last | the group | 256 | | refused |
| Copying | bandwidth | | the group | 1 MiB a second, two seconds' burst | | slowed down |
| Note to a device | a queued line | until sent | the watching device | 32 | | the watch is closed |
| Allowance of a source | about 150 bytes for each of its payers | until full again: under 30 s | itself | | forgotten past 4096 sources when full | |

What the relay guarantees:

- **A device registered before cannot be pushed out** by any number of strangers: nothing
  they register removes another group's devices, records or period.
- **A new group from elsewhere finds room** unless strangers hold 4096 groups, which takes at
  least 16 wide networks (4096 / 256) holding their registrations open, and over IPv6 at
  least 4 providers (4096 / 1024), or 128 MiB of records, which takes at least 32 wide
  networks (128 MiB / 4 MiB), over IPv6 in at least 8 providers (128 MiB / 16 MiB)
  (`TestRegistrationsBoundByProvider`).
- **Requests**: strangers in fewer than 4 wide networks (256 / 64), or over IPv6 in fewer
  than 2 providers (256 / 128), cannot take every request slot, and each slot is free again
  within 5 s.
- **Setups**: strangers in fewer than 2 wide networks (256 / 128), or over IPv6 in fewer
  than 2 providers, cannot take every setup slot, and each is free again within 15 s. One
  provider may hold half of the setups and half of the requests being read: these slots are
  short-lived and refilled in seconds, so this is the accepted bound; the state that lasts
  (registrations, records) takes at least 4 providers.
- After strangers register and leave, the relay keeps nothing of them but their sources'
  allowances, which it forgets once full again (`TestOpenRelayForgetsStrangers`).

A relay for the user's own groups (`-group`) has the limits of every relay (setups, requests,
calls, members) and serves no stranger's group at all.

## The forwarder

| State | Cost | Lifetime | Charged to | Cap per payer | Cap in all | When full |
|---|---|---|---|---|---|---|
| Registration, being set up or held | a goroutine, a TLS connection | while its connection lasts | address, network, wide network, provider, also over VLESS ("XHTTP" below) | 16, 64, 256, 1024 | 256 being set up; 100,000 groups | the connection is closed; refused |
| A group's clients | an entry per address, handshake and session | 10 s a handshake, 200 s a session | the group | 16 addresses, 64 handshakes waiting | | dropped |
| A group's packets | forwarding | | the group | 1000 packets and 2 MiB a second | | dropped |
| Credential version (a period's entry) | about 400 bytes in memory, 200 on disk | until the last credential it saw expires, 35 days at most | the network, wide network and provider it came from | 256, 1024, 4096 | 100,000 | refused |
| Remembered records (hubs from before the credentials) | their bytes | while the group is registered; after, until 32 MiB of the groups that are away are held | the group; the network, wide network and provider that brought them; while the group is away, the provider that brought most of them | 256 KiB a group; 1 MiB a network, 4 MiB a wide network, 16 MiB a provider | 32 MiB and 100,000 groups that are away; the groups registered now are not counted | refused; of the groups that are away, the provider that holds the most forgets its oldest |
| VLESS user ID | a user of the VLESS server | with its registration | the registration | one per group | as registrations | refused |
| Handshake to a group not known for its address | one keyed BLAKE2s per registered group | | the source address; its network; all | 10 handshakes a second; 1/16 of all; 500,000 checks a second | | dropped |
| Handshake over VLESS | one check, against the group of its user ID | | the VLESS user ID | 10 handshakes a second | | dropped |
| Handshake from an address with a session | a check per group the address has | | the source address | 10 handshakes a second | | dropped |
| Sources' and networks' budgets | an entry each | until full again | | | 4 per group, the oldest dropped | the oldest is forgotten |

What the forwarder guarantees:

- **A group that registered before cannot be pushed out**: nothing strangers do removes a
  registration, a credential's version or a registered group's records.
- **A group that renews on time finds room** for its new period unless the table holds
  100,000 versions, which takes at least 98 wide networks (100,000 / 1024) keeping them for
  their whole lifetime, over IPv6 in at least 25 providers (100,000 / 4096); a network of
  its own holds fewer than its share (`TestVersionsProviderLeavesRoom`). A stranger who adds
  a version pays a whole registration for it.
- **A client that is connected stays connected**: its next handshakes from the same address
  are checked against its own group first and spend nothing of the scan budget, and a client
  over VLESS reaches only its own group's hub and costs one check, so no flood of handshakes,
  over VLESS or not, cuts it off.
- **A new client of a group**, whose handshake must be checked against every group, competes
  for the scan budget. A source can forge its address, so this is the one budget strangers
  can spend from anywhere; a network gets a sixteenth of it, and the client's own retries
  every 5 s get through once the flood pauses. This is the accepted bound.
- The memory that strangers leave is bounded by the table's numbers: 100,000 versions of
  about 400 bytes (`TestVersionsMemoryBounded`), 32 MiB of remembered records.
- **The records of a group that is away stay** while strangers register groups with records,
  however many: the groups registered now are not counted against the 32 MiB. Once strangers'
  groups are away too, the forwarder forgets from the provider (an IPv6 /32, an IPv4 /16)
  that holds the most of them, so a genuine group's few kilobytes go only once every other
  provider holds no more than that: for 10 KiB of records, over 3000 providers (32 MiB /
  10 KiB), unless the strangers are in the group's own provider
  (`TestMemoryKeepsGroupsThatAreAway`).

### XHTTP

VLESS over XHTTP behind a web server (`cbb forward -vless-xhttp`) is the one place where a
stranger spends memory before any check of the forwarder's: Xray queues a session's uploads
before it knows the VLESS user and keeps a session that no client opens for 30 seconds. Behind
the web server every request comes from the loopback address, so the web server names the
client's address (`X-Real-IP`), and the forwarder's own front, which passes the requests on
to Xray, charges it:

| What | Limit | Where |
|---|---|---|
| One upload | 32 KiB (`MaxPostBytes`) | the forwarder; the web server's `client_max_body_size` |
| Uploads a session holds | 8 (`MaxBufferedPosts`), so 256 KiB a session, for 30 s | the forwarder |
| Uploads to a session whose download is not open | 32 a second from an address and from a network, 64 from a wide network, 128 from a provider, 256 from all sources; bursts of 64, 64, 128, 256 and 512 | the forwarder's front |
| Requests | 150 a second from an address, bursts of 300 | the web server |
| Requests open at once | 16 from an address, 1024 in all | the web server |

An upload to a session whose download (GET) is open is read at once and pays nothing; one to
any other session may stay queued for 30 seconds, so it pays. What strangers make the
forwarder hold is then at most the uploads of 30 seconds from all sources, about 256 MiB
((512 + 30 × 256) × 32 KiB), whatever the number of their addresses, within the unit's
memory limits (`GOMEMLIMIT` and `MemoryMax` in `packaging/linux/cbb-forward.service`); an
address or a network holds at most about 30 MiB of it, and filling all sources' share takes
at least 2 wide networks, over IPv6 2 providers. A genuine client opens its download as it
starts, so a flood delays at most its first few uploads, which it sends again: this is the
accepted bound, as for the scan budget. Our clients send at most 32 KiB an upload, so the
limits never cut them off. Xray's defaults, 1 MB an upload and 30 of them, let one session
hold about 30 MB.

A hub's registration over VLESS (`RegistrationID`) pays as a direct one, from the same setup
slots and caps, charged to the client's address: the one the web server names. When the address is not known (a web server that does
not name it), the registrations over VLESS share at most an eighth of the setup slots, so
that they never keep out a hub that registers directly; all of them together are bounded by
1024.

## Tests

The guarantees above are tested, in Go:

- a refused registration, for each reason, leaves the server as it was:
  `TestRefusedRegistrationLeavesState` (relay), `TestRefusedRegistrationLeavesForwarder`;
- for each payer, sources at their cap leave room for a group from elsewhere and never push
  out one that came before, with random sources, groups and orders under a fixed seed:
  `TestCountProperty`, `TestOpenRelayBudgetProperty`, `TestVersionsBudgetProperty`;
- what strangers leave behind is bounded and measured: `TestOpenRelayForgetsStrangers`,
  `TestVersionsMemoryBounded`;
- the payers of each kind: `TestCountProvider`, `TestVersionsWideNetworkLeavesRoom`,
  `TestVersionsProviderLeavesRoom`, `TestRegistrationsBoundByProvider`,
  `TestMemoryChargesTheSource`,
  `TestMemoryKeepsGroupsThatAreAway`,
  `TestRecordBytesChargedToTheSource`, `TestRequestsBoundByWideNetwork`,
  `TestVLESSUsersLeaveTheScanBudget`, `TestKnownClientKeepsItsGroup`;
- XHTTP takes no upload over its limit and queues no more than its limit for a session
  that no client opened: `TestXHTTPHoldsLittleForStrangers`.
- Uploads to sessions whose download is not open pay by source and from all sources
  together: `TestFrontUploadsPayBySource`; the client's address comes only from the web
  server on the loopback: `TestFrontClientAddress`, `TestRegistrationStream`.
- Registrations over VLESS pay by source, and those from addresses not known leave the
  direct ones room: `TestRegistrationsOverVLESSPayBySource`.

A new limit goes into this page and into `internal/budget` first: a cap added alone, in one
file, is one a neighbouring state can go around.
