<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Running your own servers

Copy Beyond Borders needs no server at home: the hub is one of your own computers. A server on
the internet helps in two cases:

- a **forwarder**, when the internet cannot reach your hub (carrier-grade NAT), or for VLESS
  in networks that block VPNs;
- a **blind relay**, when the group has no computer that can be the hub.

Neither holds any of your group's keys or can read the clipboard. What each one sees is in
[How it works](../guide/how-it-works.md#what-each-server-can-see). Any small Linux server
with a public address will do: a virtual server with 1 CPU and 512 MB of memory is plenty.

| | Forwarder | Blind relay |
|---|---|---|
| Command | `cbb forward` | `cbb relay -group TAG` |
| Serves | any hub that registers with it | only the groups you list |
| Devices connect with | the hub's `-forwarder ADDRESS -forwarder-key KEY` | `cbb global relay ADDRESS -key KEY` on each computer; Settings on the phones |
| Ports | UDP and TCP 8764; TCP 443 with VLESS | UDP and TCP 8764 |
| AmneziaWG, VLESS | yes | not yet |
| Phones | yes | yes, while the app syncs |

## Getting `cbb` onto the server

Run it in Docker, or as a systemd service. Do not install the full service with `get.sh`
on the same server: it would take TCP 8764 for itself.

### With Docker

The image is published with each release from 0.5. The repository's
[compose.server.yaml](../../packaging/docker/compose.server.yaml) runs a forwarder:

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.server.yaml
docker compose -f compose.server.yaml up -d
docker compose -f compose.server.yaml exec forward cbb forward -show-key
```

The last command prints the forwarder's key, 44 characters of base64. For a relay, change `command:`
in the file to `["relay", "-group", "TAG", "-listen", ":8764"]`. More in the
[image's README](../../packaging/docker/README.md).

### As a systemd service

Download the release for the server's CPU and put `cbb` in place:

```sh
curl -fsSLO https://github.com/HunterEwok/cbb/releases/latest/download/cbb-linux-amd64.tar.gz
tar -xzf cbb-linux-amd64.tar.gz
sudo install -m 755 cbb/cbb /usr/local/bin/cbb
```

(`-arm64` for an ARM server. Check the archive against the release's `SHA256SUMS` as in
[Installing](../guide/install.md#checking-a-download).)

The archive carries the servers' systemd units, `cbb-forward.service` and
`cbb-relay.service`. Install the one you want and start it:

```sh
sudo install -m 644 cbb/packaging/linux/cbb-forward.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cbb-forward
journalctl -u cbb-forward | grep key          # its key, 44 characters of base64
```

The key file is made on the first start, in the service's own state directory
(`/var/lib/private/cbb-forward/forwarder.pem`), and the forwarder prints its key in its
log each time it starts. Keep that file: a new key means giving every hub the new one.

The units run `cbb` as a user of its own made for the service, with no privileges, no
access to the rest of the system and a short list of system calls
(`systemd-analyze security` rates them 1.2, "OK"). Their flags go in a file the unit reads,
`/etc/cbb/forward.env` (`CBB_FORWARD_FLAGS=...`) or `relay.env`
(`CBB_RELAY_FLAGS=...`), owned by root with mode 0644; it holds no secret. `cbb-forward`
needs no file; `cbb-relay` needs one with the groups to serve, written before it starts
(see [A blind relay](#a-blind-relay)). `CBB_DEBUG=1` on a line of its own in the same file
turns on the counts described in [what the server keeps](#what-the-server-keeps). Reading
the journal needs `sudo` or the `systemd-journal` group.

Run the servers only through their units, never by hand: by hand, `cbb` keeps its key in
`/var/lib/cbb` instead of the unit's state directory, so the key the hubs
were given would change when the unit takes over.

### The firewall

Open the ports on the server, and in the hosting provider's firewall if it has one: UDP and
TCP 8764 for the forwarder or the relay (the relay's port is the one after `-listen`), and
TCP 443 only with VLESS. With ufw:

```sh
sudo ufw allow 8764/udp comment 'Copy Beyond Borders'
sudo ufw allow 8764/tcp comment 'Copy Beyond Borders'
sudo ufw allow 443/tcp comment 'Copy Beyond Borders VLESS'    # only with VLESS
```

With firewalld: `sudo firewall-cmd --permanent --add-port=8764/udp --add-port=8764/tcp`
(and `--add-port=443/tcp` with VLESS), then `sudo firewall-cmd --reload`.

## A forwarder

Without a forwarder of your own, a hub without addresses uses the project's at `cbb.tools`
([Sync away from home](../guide/away-from-home.md#5-when-the-internet-cannot-reach-your-home-a-forwarder)),
open to every group under the [terms of the public servers](https://cbb.tools/en/terms.html):
free, as is, with no promise of uptime, and shared by the [budget](../relay-budget.md).
Once yours runs, give the hub its address and key instead:

```sh
sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key>
```

A name works in place of the address (`vpn.example.org:8764`); the hub looks it up once.
`cbb global` on the hub shows the registration. The forwarder needs no settings per group:
each hub registers by itself with its group's certificate, and every group is kept apart
from the others.

The forwarder writes nothing to its log about the hubs or their clients, and keeps on disk
only its key and a table of hashed tags (see [What the server keeps](#what-the-server-keeps)).

### VLESS on the forwarder

For networks that block VPNs ([Networks that block VPNs](../guide/blocked-networks.md)),
the forwarder also takes VLESS, in one of two ways. The hub asks for VLESS with `-vless`
and gets the rest from the forwarder, whichever way it runs.

#### Behind your site's web server (XHTTP)

If the server already has a website with its certificate on TCP 443, as `cbb.tools` does,
the web server passes one path to the forwarder, which listens only on the loopback
address; to the network it is HTTPS to your site. The site's name must point at the
forwarder's own address.

```sh
echo 'CBB_FORWARD_FLAGS=-vless-xhttp vpn.example.org' | sudo tee /etc/cbb/forward.env
sudo systemctl restart cbb-forward
sudo journalctl -u cbb-forward | grep XHTTP     # the path the web server passes
```

Then give that path to the web server (nginx): the limits in the `http` block, the location
in the site's `server` block for TCP 443:

```nginx
limit_req_zone $binary_remote_addr zone=cbb_vless_addr:10m rate=150r/s;
limit_conn_zone $binary_remote_addr zone=cbb_vless_conn:10m;
limit_conn_zone $server_name zone=cbb_vless_all:1m;

location /PATH-FROM-THE-LOG {
    client_max_body_size 32k;
    limit_req zone=cbb_vless_addr burst=300 nodelay;
    limit_conn cbb_vless_conn 16;
    limit_conn cbb_vless_all 1024;
    limit_req_status 429;
    limit_conn_status 429;
    proxy_pass http://127.0.0.1:3276;
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_redirect off;
    proxy_set_header Host $host;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    access_log off;
}
```

- The limits bound what strangers, who need no VLESS user to send uploads, make the
  forwarder hold ([the servers' budget](../relay-budget.md#xhttp)); the clients' uploads are
  never larger than 32 KiB.
- The path is made at random once and kept in the forwarder's key file; `-vless-path /PATH`
  sets one of your own (a slash and 8 to 64 letters, digits, `-` or `_`). It keeps scanners
  off the forwarder; the groups' security does not rely on it.
- `-vless-listen` picks the loopback port (default `127.0.0.1:3276`), `-vless-port` the web
  server's port if it is not 443.
- The web server sees the group's VLESS user ID and WireGuard's encrypted packets, nothing
  more; `access_log off` keeps even that out of its log.

#### Without a web server (REALITY)

On a server without a site of its own, the forwarder takes VLESS with REALITY on TCP 443
itself, borrowing the TLS of a well-known site:

```sh
echo 'CBB_FORWARD_FLAGS=-vless-site www.example.com' | sudo tee /etc/cbb/forward.env
sudo systemctl edit cbb-forward      # add the three lines below under [Service]
sudo systemctl restart cbb-forward
```

```ini
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
PrivateUsers=no
```

The first two lines let it take port 443; the third is needed because a capability inside
the unit's own user namespace does not cover the host's network, so the bind would be
refused. The unit gives it no privileges otherwise.

(In Docker, add `"-vless-site", "www.example.com"` to `command:` and publish `443:443/tcp`.)

- The site must support TLS 1.3 and must not be blocked where your devices travel. Big
  sites people use every day are the best choice.
- The REALITY key is kept in the forwarder's key file; nothing else to configure.
- `-vless-listen ADDRESS:PORT` picks another port; 443 looks the most ordinary.

## A blind relay

A relay serves only the groups you list. Find your group's tag with `cbb status` on any of
its computers, then set it up on the server:

```sh
echo 'CBB_RELAY_FLAGS=-group 0123456789abcdef' | sudo tee /etc/cbb/relay.env   # several: -group TAG1,TAG2
sudo install -m 644 cbb/packaging/linux/cbb-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cbb-relay
sudo journalctl -u cbb-relay | grep key          # its key, 44 characters of base64
```

In Docker, `docker compose -f compose.server.yaml exec forward cbb relay -show-key` prints
the key.

To serve anyone's groups, as the project's relay does, run `cbb relay -open` instead: it
takes every group that registers, within limits per group and per network
([protocol](../protocol.md), section 14).

On each computer of the group, after `sudo cbb global on`, in place of a hub:

```sh
sudo cbb global relay 198.51.100.9:8764 -key <key>
```

It says what the relay learns and asks you to type yes. On a phone, give the same address
and key under **Blind relay** in Settings; the app says the same and asks before it meets the
group there.

The devices then meet at the relay whenever they are not on one network. Both must be
online at once, since the relay stores nothing. It speaks plain WireGuard only.

Groups that do not want to run their own can use the project's open relay at `cbb.tools:8765`:
`sudo cbb global relay default` knows its address and key. Planned ([roadmap](../roadmap.md),
item 28): AmneziaWG and VLESS on the relay, as on the forwarder.

## What the server keeps

The forwarder and the relay keep nothing about the devices:

- **No logs about them.** They log when they start, with their key, and their own errors.
  No line names an address, a group or a device: an error from the network or from
  WireGuard is logged without the addresses and keys in it. With `CBB_DEBUG=1` they log
  counts once a minute: the forwarder its hubs, sessions and handshakes waiting, the relay
  its groups and devices, and the relay also WireGuard's own messages, without addresses or
  keys either. A test checks it for both (`TestNoLogs`).
- **Almost nothing on disk.** The relay keeps only its keys. The forwarder keeps its key and,
  for the hubs that register with a credential, a table of hashed tags with the version of
  each period's newest credential, which names no group and changes each month
  ([protocol](../protocol.md), section 13, "What it keeps").
- **In memory, while it lasts.** To pass packets they must know the addresses of the
  devices online now, and the relay which devices of a group are online. That goes when the
  device does, or when the server restarts.

## What the hosting provider sees, and what a VPN hides

The program cannot hide what passes the server's network. Whoever runs the server's
machine, the hosting provider included, can see:

- the addresses of the hubs and devices that talk to the server, when, and how much;
- what the server itself sees, if it reads the server's memory: for a forwarder, section 13
  of the [protocol](../protocol.md), "What the forwarder learns"; for a relay, the list
  `cbb global relay` shows.

It never sees the texts, files or images: they pass encrypted end to end between the
devices of the group, in TLS inside WireGuard. Your own firewall and system logs on the
server are yours to set: ufw logs blocked packets by default (`sudo ufw logging off` stops
it), and the server's journal keeps the service's few lines.

A system VPN on a device, from a VPN provider, hides the device's address from the server
and from its hosting provider: they see the VPN's address instead. The VPN provider then sees
that the device talks to the server, when and how much, but not what. On the phones the
app's tunnel goes inside the app, so a system VPN on the phone carries it as it carries the
phone's other traffic; on a computer, the same holds for its system VPN.

The project's servers on `cbb.tools` run with these units, and the same is true of them.

## Updating

Download the new release and replace `/usr/local/bin/cbb`, keeping the old one, then
`sudo systemctl restart cbb-forward`. If the release's changelog says the units changed,
install them again from the archive and run `sudo systemctl daemon-reload` first. In Docker:
`docker compose -f compose.server.yaml pull && docker compose -f compose.server.yaml up -d`.
The key stays, so the hubs and devices need no change.

**Rolling back**: put the old `cbb` back and restart, or in Docker pin the previous
release's digest in `image:` and run `up -d` again.

**Backing up**: the key is all a server has to keep, `forwarder.pem` or `relay.pem` (with
the forwarder's `forward-state.json`) in `/var/lib/private/cbb-forward` or
`/var/lib/private/cbb-relay`, or the Docker volume; and your `/etc/cbb/*.env`
and drop-ins. To restore, put the files back in the same directory before the unit starts;
systemd gives them to the unit's user. The forwarder's file also holds its REALITY key.

**Removing it**: `sudo systemctl disable --now cbb-forward` (or `cbb-relay`), delete the unit
and its drop-ins in `/etc/systemd/system`, and `/var/lib/private/cbb-forward` if the key
should go too.
