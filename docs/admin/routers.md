<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Routers and FreeBSD

For administrators who run Copy Beyond Borders on an OpenWrt router, on OPNsense or on a FreeBSD
server, and for any computer with several networks. A router is always on and sits on every
home network, so it makes a good member and a good hub. This page covers what the
installers set up, how to limit the service to the right networks, and how to check it.
The install commands themselves are in [installing](../guide/install.md#openwrt).

## Which networks it answers on

The service publishes itself in mDNS and takes connections on the member port only on the
interfaces it is given. Everywhere else it neither answers nor listens, so the internet side
of a router never sees it, even with a private address there or a firewall rule opened by
mistake.

| System | Where the list comes from | Default |
|---|---|---|
| OpenWrt | `list zone` in `/etc/config/clipboardbridge`: the devices of those firewall zones | `lan` |
| FreeBSD, OPNsense | `CBB_INTERFACES` in `/usr/local/etc/clipboardbridge/clipboardbridge.env` | every interface |
| Linux, macOS | `CBB_INTERFACES` in `/etc/clipboardbridge/clipboardbridge.env` | every interface |

`CBB_INTERFACES` takes interface names separated by commas or spaces (`igb1,igb1_vlan20`).
Name it on any machine with a guest, IoT or internet interface. A full member also answers
only on the home networks it knows ([hardening](hardening.md)); the list of interfaces is
the firmer limit, as it does not depend on what a network looks like.

## OpenWrt

OpenWrt 25.12 or later. The full member needs about 25 MB of storage and 256 MB of RAM; on
a smaller router install the lite member (`get.sh --lite`), which on MIPS has no sync away
from home yet ([roadmap](../roadmap.md), item 37).

What the installer sets up:

| What | Where |
|---|---|
| The program | `/usr/bin/cbb` |
| The service | `/etc/init.d/clipboardbridge` (procd), as the user `clipboardbridge` without capabilities and with `no_new_privs`; restarted if it stops |
| Its settings | `/etc/config/clipboardbridge`, kept when it exists |
| The keys and the group's state | `/etc/clipboardbridge/state`, mode 0700; a plain sysupgrade keeps the whole install, keys included |
| The NTP hook | `/etc/hotplug.d/ntp/50-clipboardbridge`: the service starts once NTP has set the clock, as certificates need the time |
| The log | the system log: `logread -e clipboardbridge` |

The settings, applied with `/etc/init.d/clipboardbridge reload`:

| Option | Default | Meaning |
|---|---|---|
| `port` | `8764` | the member port |
| `list zone` | `lan` | the firewall zones the service works in; `wan`, and PPPoE, WireGuard and tunnel devices never count |
| `wait_ntp` | `1` | start only once NTP has set the clock; `0` for a router whose clock keeps running while it is off |
| `memlimit` | `64MiB` | a soft limit for the service's memory (`GOMEMLIMIT`) |

**The firewall.** The service's firewall rules come and go with it, through procd;
`/etc/config/firewall` is never changed. A zone other than `lan` gets two rules while the
service runs: the member port over TCP and mDNS over UDP 5353, from that zone. For an IoT
network:

```sh
uci add_list clipboardbridge.main.zone='iot'
uci commit clipboardbridge
/etc/init.d/clipboardbridge reload
/etc/init.d/firewall reload     # loads the service's new rules
```

**The hub.** `cbb global hub` on the router (as root, without `sudo`) asks before it opens the
hub's UDP port from `wan`; with yes, that rule joins the service's own rules. No port
forwarding is needed, unless another router sits in front ([away from
home](../guide/away-from-home.md#2-turn-it-on-on-the-hub)).

**Updates.** From the package feed, `apk upgrade` keeps it current. Installed with `get.sh`,
it updates itself once a day from cron if you said yes (`cbb update -auto on|off`). An
attended sysupgrade (ASU, owut) leaves the program out: run the install command again after
one; the keys stay.

**Removing it.** `apk del clipboardbridge` for the package, or
`sh /usr/share/clipboardbridge/uninstall.sh`. Both keep the keys in `/etc/clipboardbridge`;
`uninstall.sh --purge` deletes them too. `uninstall.sh` also deletes
`/etc/config/clipboardbridge`, so note your zones first.

## FreeBSD and OPNsense

FreeBSD 15 on amd64 or arm64, and OPNsense on the same FreeBSD.

| What | Where |
|---|---|
| The program | `/usr/local/bin/cbb` |
| The service | the rc.d script `clipboardbridge`, through daemon(8); `clipboardbridge_enable="YES"` in rc.conf |
| Its settings | `/usr/local/etc/clipboardbridge/clipboardbridge.env` |
| The keys and the group's state | `/var/db/clipboardbridge` |
| The log | syslog, `/var/log/messages` |

**The firewall.** The installer finds pf or ipfw, lists the rules it needs (the member port
over TCP and mDNS over UDP 5353, from the private address ranges only) and asks before it
adds them; `--express` adds them without asking, `--no-firewall` only prints them.

- **pf**: the rules live in the anchor `clipboardbridge`, loaded from
  `/usr/local/etc/clipboardbridge/pf.anchor`. Three lines at the end of `/etc/pf.conf`, a
  marker comment and the two that load the anchor, name it; the uninstaller removes exactly
  those lines.
- **ipfw**: rules in set 17, numbers 10500 and up, added again by the rc.d script after each
  boot.
- **OPNsense** writes pf's whole ruleset at each filter reload, so the installer adds a
  plugin hook instead of touching `pf.conf`: the anchor follows every reload, and the
  service shows under System, Diagnostics, Services. Turn off the mDNS repeater (Services,
  mDNS Repeater): both need UDP 5353, and the service answers mDNS on each home interface
  itself.

The hub's port goes into the same anchor or rule set when `cbb global hub` opens it.

**pfSense** is not supported: the installer runs, but it prints the rules for Firewall,
Rules instead of adding them, and a pfSense update may remove Copy Beyond Borders.

**Removing it.** `sh /usr/local/share/clipboardbridge/uninstall.sh` removes the program, the
service and its firewall rules, and keeps the keys in `/var/db/clipboardbridge`; `--purge`
deletes them too.

## Check it

| Check | OpenWrt | FreeBSD, OPNsense | Linux |
|---|---|---|---|
| The service runs | `/etc/init.d/clipboardbridge status` | `service clipboardbridge status` | `systemctl status clipboardbridge` |
| The group and the devices it sees | `cbb status` | `cbb status` | `cbb status` |
| The interfaces it works on | `cat /var/run/clipboardbridge/interfaces` | `grep CBB_INTERFACES /var/log/messages` | `journalctl -u clipboardbridge \| grep CBB_INTERFACES` |
| The firewall rules | `nft list ruleset \| grep clipboardbridge`; empty with only `lan`, which needs none | `pfctl -a clipboardbridge -s rules`, or `ipfw set 17 show` | as [the installer](../guide/install.md#the-firewall) reports them |
| The log | `logread -e clipboardbridge` | `grep clipboardbridge /var/log/messages` | `journalctl -u clipboardbridge` |

The service logs the interfaces it keeps to at start, when `CBB_INTERFACES` is set. A
`CBB_INTERFACES` line set by hand stays when the installer runs again or `cbb update`
installs a new release.

If the service does not start on OpenWrt, the log says why: the zones have no devices, or
NTP has not set the clock yet. Every setting is in
[settings and environment variables](../reference/config.md), every port in
[devices, ports and files](../reference/devices.md#ports).
