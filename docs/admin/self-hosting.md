<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Running your own servers

For administrators who want to run their own **forwarder** or **blind relay** on a Linux server
with a public address.

Connect Beyond Borders needs no server at home: one of your own computers acts as the hub. A server
on the internet helps in two cases:

- **Forwarder (`cbb forward`):** Relays encrypted WireGuard packets between your away devices and a
  hub that incoming internet connections cannot reach (for example, behind carrier-grade NAT), or
  carries VLESS traffic on networks that block VPNs.
- **Blind relay (`cbb relay`):** Provides a meeting point when a group has no computer to act as a
  hub (such as a phones-only group).

Neither server holds group keys or can read your clipboard. For what each server can observe, see
[How it works: what each server can see](../guide/how-it-works.md#what-each-server-can-see). Any
small Linux virtual server with a public address works: 1 CPU and 512 MB to 1 GB of memory is
enough for personal use.

| | Forwarder | Blind relay |
|---|---|---|
| Command (binary) | `cbb forward` (`cbb-forward`) | `cbb relay -group TAG` or `cbb relay -open` (`cbb-relay`) |
| Groups served | Any hub that registers | Only listed groups (`-group`), or any group (`-open`) |
| Group configuration | `sudo cbb global hub -forwarder ADDRESS:PORT -forwarder-key KEY` on the hub | `sudo cbb global relay ADDRESS:PORT -key KEY` on the main computer, or **Settings > Advanced settings > Blind relay** on the main phone |
| Firewall ports | UDP and TCP 8764; TCP 443 with VLESS | UDP and TCP 8764 |
| AmneziaWG and VLESS | Yes | No (plain WireGuard only) |
| Phone support | Yes | Yes, while the app syncs |

## Install on the server

Run the server in Docker or as a systemd service. Do not install the computer member service with
`get.sh` on the same machine, because the member service uses TCP port 8764.

### With Docker

The official image `ghcr.io/hunterewok/cbb` is published with each release. The repository's
[compose.server.yaml](../../packaging/docker/compose.server.yaml) runs a forwarder:

1. Download the compose file:

   ```sh
   curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.server.yaml
   ```

2. Start the container:

   ```sh
   docker compose -f compose.server.yaml up -d
   ```

3. Print the forwarder's 44-character base64 key pin:

   ```sh
   docker compose -f compose.server.yaml exec forward cbb forward -show-key
   ```

To run a blind relay instead, change `command:` in `compose.server.yaml` to
`["relay", "-group", "TAG", "-listen", ":8764"]` (or `["relay", "-open", "-listen", ":8764"]`),
start the container, and print its key with
`docker compose -f compose.server.yaml exec forward cbb relay -show-key`. For image verification
and volume details, see the [Docker image README](../../packaging/docker/README.md).

### With systemd

1. Download and verify the Linux release archive for your server's CPU (`amd64` or `arm64`; see
   [Checking a download](../guide/install.md#checking-a-download)), then install the server
   binaries into `/usr/local/bin/`:

   ```sh
   curl -fsSLO https://github.com/HunterEwok/cbb/releases/latest/download/cbb-linux-amd64.tar.gz
   tar -xzf cbb-linux-amd64.tar.gz
   sudo install -m 755 cbb/cbb cbb/cbb-forward cbb/cbb-relay /usr/local/bin/
   ```

   `cbb-forward.service` runs `/usr/local/bin/cbb-forward`, and `cbb-relay.service` runs
   `/usr/local/bin/cbb-relay`. Installing `cbb` beside them also lets you run `cbb forward` and
   `cbb relay` commands.

2. Install the unit file from the archive and start the service. For a forwarder:

   ```sh
   sudo install -m 644 cbb/packaging/linux/cbb-forward.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now cbb-forward
   ```

   For a blind relay, write `/etc/cbb/relay.env` first (see [A blind relay](#a-blind-relay)), then
   install and enable `cbb-relay.service`.

3. Read the server's 44-character base64 key pin from the journal (reading the journal requires
   `sudo` or membership in the `systemd-journal` group):

   ```sh
   sudo journalctl -u cbb-forward | grep key
   ```

On first start, the service generates its key file in its private systemd state directory
(`/var/lib/private/cbb-forward/forwarder.pem` or `/var/lib/private/cbb-relay/relay.pem`) and logs
its key pin on every startup. Back up that file: generating a new key requires updating every hub
or group that pins it.

Both systemd units run under an isolated dynamic user (`DynamicUser=yes`) with no capabilities,
`ProtectSystem=strict`, `MemorySwapMax=0`, `IPAccounting=no`, and restricted address families and
system calls. The forwarder unit caps memory at 1 GiB (`GOMEMLIMIT=768MiB`, `MemoryMax=1G`), and
the relay unit sets `LimitNOFILE=65536`.

Pass flags to a unit through an environment file owned by `root` with mode `0644` (it holds no
secrets):

- **Forwarder:** `/etc/cbb/forward.env` with `CBB_FORWARD_FLAGS=...` (optional; not needed for
  default settings).
- **Blind relay:** `/etc/cbb/relay.env` with `CBB_RELAY_FLAGS=...` (required before first start to
  pass `-group` or `-open`).
- **Debug counts:** Add `CBB_DEBUG=1` on its own line in either file to log aggregate counts once a
  minute (see [What the server keeps](#what-the-server-keeps)).

Run `cbb-forward` and `cbb-relay` only through their systemd units, not by hand. Running them by
hand stores keys in `/var/lib/cbb` instead of the unit's `STATE_DIRECTORY`, which produces a
different key when the unit starts.

### Open the firewall ports

Allow the server's ports in both the host firewall and your hosting provider's firewall:

- **Forwarder or blind relay:** UDP and TCP port 8764 (or the port set with `-listen`).
- **VLESS on a forwarder:** TCP port 443 (only when using VLESS behind a web server).

With `ufw`:

```sh
sudo ufw allow 8764/udp comment 'Connect Beyond Borders'
sudo ufw allow 8764/tcp comment 'Connect Beyond Borders'
sudo ufw allow 443/tcp comment 'Connect Beyond Borders VLESS'    # only with VLESS
```

With `firewalld`:

```sh
sudo firewall-cmd --permanent --add-port=8764/udp --add-port=8764/tcp
sudo firewall-cmd --permanent --add-port=443/tcp    # only with VLESS
sudo firewall-cmd --reload
```

## A forwarder

Without your own forwarder, a hub with no direct addresses uses the project's forwarder at
`cbb.tools` ([Away from home: a forwarder](../guide/away-from-home.md#5-when-the-internet-cannot-reach-your-home-a-forwarder)),
provided under the [terms of the public servers](https://cbb.tools/en/terms.html) and shared under
[the servers' budget](../relay-budget.md).

Once your forwarder is running, point your hub to its address and key pin:

```sh
sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key KEY
```

You can pass a hostname instead of an IP address (such as `vpn.example.org:8764`); `cbb` resolves
it once when you run the command (preferring IPv4), so re-run the command if the server's IP
address changes. Run `cbb global` on the hub to verify registration.

The forwarder needs no per-group configuration. Each hub registers using its group's rotating
**server credentials** ([Protocol](../protocol.md), sections 13 and 18), and every group stays
isolated from the others. The forwarder logs nothing about hubs or clients and stores only its key
and a table of hashed period tags on disk (see [What the server keeps](#what-the-server-keeps)).

### VLESS on the forwarder

For networks that block VPNs ([Networks that block VPNs](../guide/blocked-networks.md)), the
forwarder accepts VLESS over XHTTP behind an existing HTTPS website on TCP port 443. The web server
terminates TLS with your site's certificate and forwards one secret path to the forwarder on
loopback; to filtering networks, traffic looks like ordinary HTTPS to your site. Your site's domain
name must resolve to the forwarder's public IP address.

Hubs request VLESS automatically unless started with `-no-vless`.

1. Enable `-vless-xhttp` on the forwarder and print its XHTTP path:

   - **With systemd:**

     ```sh
     sudo mkdir -p /etc/cbb
     echo 'CBB_FORWARD_FLAGS=-vless-xhttp vpn.example.org' | sudo tee /etc/cbb/forward.env
     sudo systemctl restart cbb-forward
     sudo journalctl -u cbb-forward | grep XHTTP
     ```

   - **With Docker:** Add `"-vless-xhttp"`, `"vpn.example.org"`, `"-vless-listen"`, `":3276"` to
     `command:` in `compose.server.yaml`, publish `"127.0.0.1:3276:3276/tcp"` under `ports:`, run
     `docker compose -f compose.server.yaml up -d`, and read the path with
     `docker compose -f compose.server.yaml logs forward | grep XHTTP`.

2. Configure nginx to proxy that path to the forwarder. Place the three `limit_*_zone` lines in the
   `http` block, and the `location` block inside your site's TCP 443 `server` block:

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
       proxy_set_header X-Real-IP $remote_addr;
       proxy_read_timeout 86400s;
       proxy_send_timeout 86400s;
       access_log off;
   }
   ```

3. Test and reload nginx (`sudo nginx -t && sudo systemctl reload nginx`), and open TCP port 443 on
   your server's firewall.

Configuration notes:

- **Limits and client IP header:** The nginx rate limits and `client_max_body_size 32k` bound how
  much unauthenticated uploads can make the forwarder buffer
  ([The servers' budget: XHTTP](../relay-budget.md#xhttp)); client uploads never exceed 32 KiB.
  `X-Real-IP` passes the client's real address so the forwarder applies per-address quotas to
  unauthenticated uploads and VLESS hub registrations; without it, every client shares one quota
  and VLESS registrations share one-eighth of the setup slots.
- **Custom path:** The forwarder generates a random path once and saves it inside `forwarder.pem`.
  Pass `-vless-path /PATH` (a leading slash followed by 8 to 64 letters, digits, `-`, or `_`) to
  choose your own. The path keeps scanners off the listener; group encryption does not rely on it.
- **Custom ports:** Pass `-vless-listen` to change the loopback listener (default `127.0.0.1:3276`)
  and `-vless-port` if your web server listens on a TCP port other than `443`.
- **Web server visibility:** The web server sees only each group's VLESS user ID and encrypted
  WireGuard packets; `access_log off` keeps even those out of its access logs.

## A blind relay

A blind relay serves either a fixed list of groups (`-group`) or any group that registers (`-open`).

### Set up a private blind relay

1. On any computer in your group, print the group's relay tag (`ROOT:RECOVERY:RECOVERY2` in hex):

   ```sh
   cbb status -relay
   ```

2. On the server, write `/etc/cbb/relay.env` with that tag (for multiple groups, separate tags with
   commas: `-group TAG1,TAG2`), install `cbb-relay.service`, and start it:

   ```sh
   sudo mkdir -p /etc/cbb
   echo 'CBB_RELAY_FLAGS=-group ROOT:RECOVERY:RECOVERY2' | sudo tee /etc/cbb/relay.env
   sudo install -m 644 cbb/packaging/linux/cbb-relay.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now cbb-relay
   sudo journalctl -u cbb-relay | grep key
   ```

   To run an open relay that serves any registering group within per-group and per-network limits
   ([Protocol](../protocol.md), section 14; [Limits and lifetimes](../reference/limits.md#servers)),
   set `CBB_RELAY_FLAGS=-open` instead of `-group`.

3. On your group's **main device** (*root*), configure the relay in the group's settings:

   - **Main computer:** Run the command below, read what the relay observes, and type `yes`:

     ```sh
     sudo cbb global relay 198.51.100.9:8764 -key KEY
     ```

     A hostname with a port works and is resolved once (preferring IPv4). You can list up to 16
     relays in one command:

     ```sh
     sudo cbb global relay 198.51.100.9:8764 -key KEY1 203.0.113.5:8764 -key KEY2
     ```

   - **Main phone:** Open **Settings > Advanced settings > Blind relay**, enter the address and
     key, and confirm.

Only the main device can set the group's relays ([Protocol](../protocol.md), section 10). Every
other device in the group receives the relay setting automatically from the group's signed settings
and meets there whenever syncing away from home (**Everywhere**) is on and the devices are not on
the same home network.

Both devices must be online at the same time to exchange a copy, because a blind relay stores
nothing. A blind relay speaks plain WireGuard only.

### Switch, remove, or rekey a blind relay

- **Use the project's open relay (`cbb.tools:8765`):** Run `sudo cbb global relay default` on the
  main computer (or select the project's relay in **Settings > Advanced settings > Blind relay** on
  the main phone). Devices track key and address changes for `cbb.tools:8765` automatically through
  signed project lists ([Protocol](../protocol.md), section 14, "The project's relay").
- **Stop using any blind relay:** Run `sudo cbb global relay off` on the main computer (or tap
  **Leave the relay** in **Settings > Advanced settings > Blind relay** on the main phone).
- **Replace the relay's key:** If you generate a new `relay.pem`, run
  `sudo cbb global relay ADDRESS:PORT -key NEW-KEY` once on the main computer (or update the key on
  the main phone); the updated key propagates to every device in the group.

For optional abuse handling on open servers, both `cbb-forward` and `cbb-relay` support a
`refused-groups` file beside their key file (configured with `-refused`, reloaded within 10
seconds; see [The servers' budget: abuse reports](../relay-budget.md#abuse-reports)).

## What the server keeps

Both `cbb-forward` and `cbb-relay` store minimal operational data and never log device identities:

- **No per-device or per-group logs:** Both servers log startup (including their own key pin) and
  their own errors, stripping IP addresses and keys from network and WireGuard error messages. With
  `CBB_DEBUG=1` in `/etc/cbb/forward.env` or `/etc/cbb/relay.env`, both log aggregate counts once a
  minute: the forwarder logs hubs, sessions, and waiting handshakes; the relay logs groups and
  devices plus redacted WireGuard diagnostics. Automated tests verify this for both servers
  (`TestNoLogs` for the forwarder; `its_log_names_no_device` for the relay).
- **Minimal files on disk:** The relay keeps only `relay.pem`. The forwarder keeps `forwarder.pem`
  (which also holds its XHTTP path) and `forward-state.json`, a table of hashed period tags and
  newest credential versions that names no group and expires with each 35-day credential period
  ([Protocol](../protocol.md), section 13, "What it keeps").
- **In-memory state while connected:** Both servers keep active network addresses in memory to
  route packets, and the relay tracks which temporary device pseudonyms of a group are online
  together. That state disappears when a device disconnects or the server restarts.

## What the hosting provider sees and what a VPN hides

The server software cannot hide network traffic from the machine's operator or hosting provider.
Anyone with access to the server or its network can observe:

- The IP addresses of hubs and devices connecting to the server, connection times, and traffic
  volume.
- Whatever the server holds in memory, if memory is inspected (see [Protocol](../protocol.md),
  section 13, "What the forwarder learns", and the notice displayed by `cbb global relay`).

Neither the server nor the hosting provider can read clipboard text, images, or files: every copy
travels sealed end to end inside mutual TLS 1.3 inside WireGuard.

Review your server's own firewall and system logs as well. For example, `ufw` logs blocked packets
by default (`sudo ufw logging off` disables firewall logging), and the systemd journal keeps the
service's startup and error lines.

Running a system VPN on a device hides that device's IP address from the server and its hosting
provider (shifting connection metadata visibility to the VPN provider). Because Connect Beyond
Borders runs its WireGuard tunnel inside the app and service, a system VPN on a phone or computer
carries it like any other network traffic.

The project's servers on `cbb.tools` run with these same systemd units and policies.

## Updating

### Update a systemd server

1. Download and verify the new Linux release archive, then back up your current server binary.
2. Install the new `/usr/local/bin/cbb-forward` or `/usr/local/bin/cbb-relay` (and
   `/usr/local/bin/cbb` if installed).
3. If the [changelog](../../CHANGELOG.md) notes unit file changes, reinstall the `.service` file
   from the archive and run `sudo systemctl daemon-reload`.
4. Restart the service:

   ```sh
   sudo systemctl restart cbb-forward    # or cbb-relay
   ```

Your key file stays intact, so hubs and groups need no reconfiguration.

### Update a Docker server

```sh
docker compose -f compose.server.yaml pull && docker compose -f compose.server.yaml up -d
```

### Roll back, back up, and remove

- **Roll back:** Restore your backed-up binary to `/usr/local/bin/` and restart the systemd
  service. In Docker, pin the previous release's digest in `image:` in `compose.server.yaml` and
  run `docker compose -f compose.server.yaml up -d`.
- **Back up:** Back up the key file (`forwarder.pem` and `forward-state.json` in
  `/var/lib/private/cbb-forward`, or `relay.pem` in `/var/lib/private/cbb-relay`, or the Docker
  `state` volume), along with `/etc/cbb/forward.env` or `/etc/cbb/relay.env` and any systemd
  drop-ins. `forwarder.pem` also holds the generated XHTTP path. To restore on systemd, place the
  files back in the same state directory before starting the unit so systemd assigns ownership to
  the service's dynamic user.
- **Remove:** Stop and disable the service (`sudo systemctl disable --now cbb-forward` or
  `cbb-relay`), delete the unit file and any drop-ins in `/etc/systemd/system/`, run
  `sudo systemctl daemon-reload`, and remove `/usr/local/bin/cbb-forward` (or `cbb-relay`) and
  `/etc/cbb/forward.env` (or `relay.env`). Delete `/var/lib/private/cbb-forward` (or `cbb-relay`) if
  you also want to remove the key.
