<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The Copy Beyond Borders image

The full service in a container, for machines that are always on but have no desktop: a
NAS, a home server, or a rented server for a forwarder or a relay. The design is in
[docs/design.md](../../docs/design.md#docker).

The image is built `FROM scratch`: the static `cbb` of a release, which carries its own
certificate roots, a user (65532) and its two directories. It runs as that user, needs no
capabilities, no `/dev/net/tun` and no `--privileged` (the tunnel runs in the process), and
works with a read-only root file system. Its state is one volume, `/var/lib/clipboardbridge`.

Each release publishes it as `ghcr.io/hunterewok/clipboardbridge` (from 0.5), tagged with its
version and `latest`, with a build provenance attestation; the release notes give its
digest. Pin it by that digest, `image: ghcr.io/hunterewok/clipboardbridge@sha256:...`, and
check it with `gh attestation verify oci://ghcr.io/hunterewok/clipboardbridge@sha256:...
--repo HunterEwok/clipboardbridge`.

## At home

[compose.home.yaml](compose.home.yaml) runs it as an always-on member with the host's
network, since mDNS and the member port must be on the home network:

```sh
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec clipboardbridge cbb pair
```

The container is named `clipboardbridge`, so `docker exec -it clipboardbridge cbb pair` works
too. `cbb pair` shows the QR code for the phone app and takes the code of `cbb pair` on the
group's root or an admin. Join it as an ordinary member: the keys that admit devices belong
on the devices you hold, not on a server. The container cannot change the host's firewall;
let the home network reach TCP 8764 (or `CBB_PORT`) and UDP 5353.

On a NAS, give the container the host's network (Synology Container Manager and QNAP
Container Station call it "host", Unraid "Host", TrueNAS's apps "Host Network") and a
folder or volume for `/var/lib/clipboardbridge` that user 65532 may write; then run
`cbb pair` in its terminal.

### Keys

The container keeps its keys in a file in its volume, where anyone who copies the volume
has them. So it holds none of the keys that admit and remove devices: `cbb new` there
refuses to make a group, and it offers no admin key, so the root cannot make it an admin
(the image sets `CBB_CONTAINER`). Make the group on the phone or on a computer you hold.

That also keeps it from being the hub for sync away from home, since the members take the
hub's offer from the root or an admin only. If you accept the risk and guard the volume,
set `CBB_KEYS_IN_FILE: "yes"` in its `environment`, make it an admin (`cbb admin -allow-file-key NAME` on the
root), turn on sync away from home and run `cbb global hub -firewall no PUBLIC_ADDRESS:8764`
(or with `-forwarder`), which prints the
rule the host needs for its UDP port.

## On a server

[compose.server.yaml](compose.server.yaml) runs a forwarder (`cbb forward`) with its ports
published, or with the command changed, a blind relay of your own groups (`cbb relay`).
Neither holds any group's keys; the forwarder's own key stays in the volume:

```sh
docker compose -f compose.server.yaml exec forward cbb forward -show-key
```

## Building it

```sh
CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -o cbb-amd64 ./cmd/cbb
sh packaging/docker/context.sh build amd64=cbb-amd64
docker build -t clipboardbridge build
sh tools/e2e/docker.sh clipboardbridge     # two containers pair and sync
```

`context.sh` takes `amd64`, `arm64` and `armv7` binaries; `docker build --platform` picks
the one for the platform.
