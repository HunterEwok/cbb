#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Prepares a Linux host for the bench's member in a container (a device with
# os = "docker" in the inventory; docs/maintainers/testbench.md). Run it from a checkout
# of the repository, as the user the bench connects as, who has sudo:
#
#   sh tools/bench/setup-docker.sh setup        # once: Docker, the docker group, the kill helper
#   sh tools/bench/setup-docker.sh up CBB       # a new container of the cbb binary CBB, its volume empty
#   sh tools/bench/setup-docker.sh down         # the container and its volume go (R1, R3)
#   sh tools/bench/setup-docker.sh teardown [--group]  # down, the image and the kill helper go;
#                                               # --group also takes the user out of the docker group
#
# setup installs Docker and its compose plugin from the distribution, puts
# the user in the docker group (sign in again for it to count) and installs
# cbbbench-kill-container with a sudoers rule that lets the user run exactly
# that without a password: F1 kills the container's process from the host,
# as a crash would, since docker kill counts as stopping it by hand and its
# restart policy would not start it again.
#
# up builds the image cbb:bench from CBB, a static cbb for this
# host's CPU (CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/cbb on a
# Pi), and runs it with packaging/docker/compose.home.yaml in ~/cbb-nas, so
# the container is named cbb and holds no group.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
dir=$HOME/cbb-nas
helper=/usr/local/sbin/cbbbench-kill-container
image=cbb:bench

usage() {
	echo "usage: setup-docker.sh setup | up CBB | down | teardown [--group]" >&2
	exit 2
}

compose() {
	docker compose -p cbb-nas -f "$dir/compose.yaml" "$@"
}

case ${1:-} in
setup)
	[ $# -eq 1 ] || usage
	if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
		sudo apt-get update
		sudo apt-get install -y docker.io docker-compose
	fi
	docker compose version >/dev/null 2>&1 || {
		echo "setup-docker.sh: Docker has no compose plugin here; install docker-compose-plugin from Docker's repository" >&2
		exit 1
	}
	sudo usermod -aG docker "$(id -un)"
	# The helper kills the process of one container of the image, by the
	# PID Docker gives, and nothing else.
	sudo tee "$helper" >/dev/null <<'HELPER'
#!/bin/sh
# Installed by tools/bench/setup-docker.sh: kills a cbb
# container's process as a crash would, for the bench's F1.
set -eu
case ${1:-} in '' | *[!A-Za-z0-9_.-]*) echo "usage: cbbbench-kill-container NAME" >&2; exit 2 ;; esac
case $(docker inspect -f '{{.Config.Image}}' "$1") in
cbb:* | ghcr.io/hunterewok/cbb*) ;;
*) echo "cbbbench-kill-container: $1 is not a cbb container" >&2; exit 1 ;;
esac
pid=$(docker inspect -f '{{.State.Pid}}' "$1")
[ "$pid" -gt 0 ] || { echo "cbbbench-kill-container: $1 is not running" >&2; exit 1; }
kill -KILL "$pid"
HELPER
	sudo chmod 0755 "$helper"
	echo "$(id -un) ALL=(root) NOPASSWD: $helper" | sudo tee /etc/sudoers.d/cbbbench-docker >/dev/null
	sudo chmod 0440 /etc/sudoers.d/cbbbench-docker
	sudo visudo -cf /etc/sudoers.d/cbbbench-docker >/dev/null
	echo "Docker is ready. Sign in again, so that $(id -un) is in the docker group."
	;;
up)
	[ $# -eq 2 ] || usage
	cbb=$2
	case $(uname -m) in
	x86_64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	armv7l) arch=armv7 ;;
	*)
		echo "setup-docker.sh: no image for $(uname -m)" >&2
		exit 1
		;;
	esac
	ctx=$(mktemp -d)
	trap 'rm -rf "$ctx"' EXIT
	sh "$repo/packaging/docker/context.sh" "$ctx" "$arch=$cbb"
	docker build -q -t "$image" "$ctx" >/dev/null
	mkdir -p "$dir"
	[ ! -f "$dir/compose.yaml" ] || compose down -v
	sed "s#^\( *image:\).*#\1 $image#" "$repo/packaging/docker/compose.home.yaml" >"$dir/compose.yaml"
	compose up -d
	docker exec cbb cbb version
	;;
down)
	[ $# -eq 1 ] || usage
	[ ! -f "$dir/compose.yaml" ] || compose down -v
	;;
teardown)
	[ $# -le 2 ] || usage
	[ ! -f "$dir/compose.yaml" ] || compose down -v
	rm -rf "$dir"
	docker image rm "$image" >/dev/null 2>&1 || true
	sudo rm -f "$helper" /etc/sudoers.d/cbbbench-docker
	if [ "${2:-}" = --group ]; then
		sudo gpasswd -d "$(id -un)" docker
	fi
	echo "The bench's container, image and kill helper are gone."
	;;
*)
	usage
	;;
esac
