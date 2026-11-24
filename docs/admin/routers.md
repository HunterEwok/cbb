<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Routers and FreeBSD

For administrators running Connect Beyond Borders on an OpenWrt router, an OPNsense firewall, a
FreeBSD server, or any computer connected to multiple networks.

Because a router stays on and connects to every home network, it works well as an always-on member
or hub. This page covers restricting the service to the right interfaces, what each installer sets
up, how firewall rules work, and how to check the service. For installation commands, see
[Installing: OpenWrt](../guide/install.md#openwrt) and
[Installing: FreeBSD](../guide/install.md#freebsd).

## Choose which networks the service answers on

The service advertises over mDNS and accepts connections on the member port only on its configured
interfaces. On all other interfaces, it neither listens nor answers—so the internet side of a
router never sees it, even if that interface has a private IP address or an accidental firewall
rule.

| System | Where the interface list is set | Default |
|---|---|---|
| OpenWrt | `list zone` in `/etc/config/cbb` (translated to `CBB_INTERFACES` by `/etc/init.d/cbb`) | `lan` |
| FreeBSD, OPNsense | `CBB_INTERFACES` in `/usr/local/etc/cbb/cbb.env` | All interfaces |
| Linux (system install), macOS | `CBB_INTERFACES` in `/etc/cbb/cbb.env` | All interfaces |
| Linux (rootless install) | `CBB_INTERFACES` in `~/.config/cbb/cbb.env` | All interfaces |
| Windows | `CBB_INTERFACES` in the service's `Environment` registry value ([Settings files](../reference/config.md#settings-files)) | All interfaces |

Set `CBB_INTERFACES` to interface names separated by commas or spaces (for example,
`igb1,igb1_vlan20`) on any machine that has a guest, IoT, or WAN interface. Computers also stay
quiet on unfamiliar networks ([Hardening](hardening.md)), while `CBB_INTERFACES` enforces a hard
interface boundary regardless of network addressing.

## OpenWrt

Supported on OpenWrt 25.12 or later (using `apk`). An OpenWrt router runs `cbb` without
`cbb-helper`. MIPS (`mips` and `mipsle`) builds sync on the home network only and do not include
syncing away from home ([Devices, ports and files](../reference/devices.md)).

### What the installer sets up

| Component | Location and behavior |
|---|---|
| Program | `/usr/bin/cbb` |
| Service | `/etc/init.d/cbb` (`procd`), running as user `cbb` with empty capabilities (`/etc/capabilities/cbb.json`), `no_new_privs`, and automatic restart |
| Settings | `/etc/config/cbb` (preserved when reinstalling) |
| Keys and group state | `/etc/cbb/state`, mode `0700`; listed in `/lib/upgrade/keep.d/cbb` so a standard `sysupgrade` keeps the full install and keys |
| NTP hook | `/etc/hotplug.d/ntp/50-cbb`: starts the service after NTP sets the clock, because copy lifetimes and signed timestamps require an accurate clock |
| Log | System log (`logread -e cbb`) |

### Configuration options

Edit `/etc/config/cbb` (or use `uci`) and apply changes with `/etc/init.d/cbb reload`:

| Option | Default | Meaning |
|---|---|---|
| `port` | `8764` | Member TCP port |
| `list zone` | `lan` | Firewall zones where the service operates; `wan`, `wan6`, and PPPoE, WireGuard, and tunnel devices are always excluded |
| `wait_ntp` | `1` | Wait for NTP before starting (`0` for a router with a battery-backed clock) |

### Firewall rules and extra zones

`procd` publishes the service's `fw4` firewall rules dynamically while `cbb` runs and drops them
when it stops; `/etc/config/firewall` is never edited. Every listed zone other than `lan` (which
already accepts input by default) gets two rules while the service runs: incoming TCP on the member
port and incoming UDP on port 5353 (mDNS).

To add another zone (such as an `iot` network):

```sh
uci add_list cbb.main.zone='iot'
uci commit cbb
/etc/init.d/cbb reload
/etc/init.d/firewall reload     # loads the service's new rules
```

### Use the router as a hub

On non-MIPS routers, run `cbb global on` and `cbb global hub` as `root` (without `sudo`). When you
give a public address, `cbb global hub` prompts before adding the hub's UDP rule from `wan` to the
service's `procd` rules (`/etc/cbb/firewall.hub`). No port forwarding is needed unless another
router sits in front ([Away from home: turn it on, on the hub](../guide/away-from-home.md#2-turn-it-on-on-the-hub)).

### Update and remove on OpenWrt

- **Updates:** If installed from the `apk` package feed, run `apk update && apk upgrade`. If
  installed with `get.sh`, daily automatic updates run from `cron` when enabled
  (`cbb update -auto on|off`). An attended sysupgrade (ASU or `owut`) omits packages outside
  standard OpenWrt feeds: re-run the install command afterward, and your keys in `/etc/cbb/state`
  remain intact.
- **Removal:** Run `apk del cbb` (package feed) or `sh /usr/share/cbb/uninstall.sh` (`get.sh`
  install). Both keep your keys in `/etc/cbb`; `sh /usr/share/cbb/uninstall.sh --purge` deletes
  `/etc/cbb` as well. `uninstall.sh` removes `/etc/config/cbb`, so note your configured zones
  before uninstalling.

## FreeBSD and OPNsense

Supported on FreeBSD 15 (`amd64` and `arm64`) and OPNsense running on FreeBSD 15.

### What the installer sets up

| Component | Location and behavior |
|---|---|
| Program | `/usr/local/bin/cbb` (with `cbb-helper`, `cbb-forward`, and `cbb-relay` beside it) |
| Service | `/usr/local/etc/rc.d/cbb`, running through `daemon(8)` with `cbb_enable="YES"` in `/etc/rc.conf` |
| Settings | `/usr/local/etc/cbb/cbb.env` |
| Keys and group state | `/var/db/cbb` |
| Log | Syslog (`/var/log/messages`) |

### Firewall rules

The installer detects OPNsense, `pf`, or `ipfw`, lists the required rules (incoming TCP on the
member port and incoming UDP on port 5353 from private address ranges only, plus `100.64.0.0/10` if
`--home-cgnat on` is set), and asks before adding them. Pass `--express` to add them without
prompting or `--no-firewall` to print manual commands only.

- **`pf`:** Rules live in anchor `cbb`, loaded from `/usr/local/etc/cbb/pf.anchor`. The installer
  appends three marked lines to `/etc/pf.conf` to load the anchor; the uninstaller removes only
  those three lines.
- **`ipfw`:** Rules are added in set 17 starting at rule 10500 and reloaded by `/usr/local/etc/rc.d/cbb`
  on each start.
- **OPNsense:** OPNsense regenerates the full `pf` ruleset on every filter reload, so the installer
  adds the plugin hook `/usr/local/etc/inc/plugins.inc.d/cbb.inc` instead of editing `pf.conf`. The
  anchor persists across filter reloads, and the service appears under **System > Diagnostics >
  Services**. Turn off **Services > mDNS Repeater**, because both use UDP port 5353 and `cbb`
  answers mDNS directly on each home interface.

When `cbb global hub` opens the hub's UDP port, it adds the rule to the same `pf` anchor or `ipfw`
set 17.

**pfSense is not supported:** The installer adds `/usr/local/etc/rc.d/cbb.sh` and prints rules to
add manually under **Firewall > Rules**, and a pfSense update may remove Connect Beyond Borders.

### Remove on FreeBSD and OPNsense

Run `sh /usr/local/share/cbb/uninstall.sh` as `root` to remove the binaries, service, OPNsense
plugin hook, and installer-managed firewall rules while keeping your keys in `/var/db/cbb`. Add
`--purge` to delete `/var/db/cbb` as well.

## Check the service

| Check | OpenWrt | FreeBSD and OPNsense | Linux |
|---|---|---|---|
| Service status | `/etc/init.d/cbb status` | `service cbb status` | `systemctl status cbb` |
| Group and peers | `cbb status` | `cbb status` | `cbb status` |
| Active interfaces | `cat /var/run/cbb.interfaces` | `grep CBB_INTERFACES /var/log/messages` | `journalctl -u cbb \| grep CBB_INTERFACES` |
| Firewall rules | `nft list ruleset \| grep cbb` (empty when only `lan` is configured) | `pfctl -a cbb -s rules` or `ipfw set 17 show` | See [Installing: the firewall](../guide/install.md#the-firewall) |
| Service log | `logread -e cbb` | `grep cbb /var/log/messages` | `journalctl -u cbb` |

When `CBB_INTERFACES` is set, the service logs its allowed interfaces on startup. A `CBB_INTERFACES`
entry added by hand stays intact when you re-run the installer or update with `cbb update`.

If the service does not start on OpenWrt, `logread -e cbb` shows why: either the listed zones have
no eligible devices or the service is waiting for NTP to set the clock.

For all settings, see [Settings and environment variables](../reference/config.md). For all ports,
see [Devices, ports and files: ports](../reference/devices.md#ports).
