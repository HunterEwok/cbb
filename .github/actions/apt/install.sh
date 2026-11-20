#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs $PACKAGES with apt, keeping the .deb files it downloads in ~/apt-debs
# (action.yml saves that folder in the Actions cache). If apt cannot download
# them, it installs the copies already in ~/apt-debs. After a download it writes
# the cache key, $KEY_PREFIX and a hash of the files, to $GITHUB_OUTPUT.
set -euo pipefail

debs=$HOME/apt-debs
mkdir -p "$debs/partial"
export DEBIAN_FRONTEND=noninteractive
# A stalled download gives up early and tries again.
printf 'Acquire::Retries "2";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' |
	sudo tee /etc/apt/apt.conf.d/80-retries >/dev/null

read -r -a pkgs <<<"$PACKAGES"
options=(-y -q)
if [ "${NO_RECOMMENDS:-false}" = true ]; then
	options+=(--no-install-recommends)
fi

tidy() {
	sudo rm -rf "$debs/partial" "$debs/lock"
	sudo chown -R "$(id -un)" "$debs"
}

# apt-get update ends with 0 when it cannot fetch the lists, with a warning, and
# the runner image's lists stay; the install then says whether the files came.
sudo apt-get update -q || true
if sudo -E apt-get install "${options[@]}" -o Dir::Cache::Archives="$debs" "${pkgs[@]}"; then
	tidy
	# Keep only the files of the versions now installed, so the cache does not
	# grow with each new version and its files never conflict.
	for f in "$debs"/*.deb; do
		[ -e "$f" ] || continue
		read -r name version < <(dpkg-deb -f "$f" Package Version | awk '{print $2}' | paste -sd' ')
		installed=$(dpkg-query -W -f='${Version}' "$name" 2>/dev/null || true)
		[ "$installed" = "$version" ] || rm -f "$f"
	done
	hash=$(find "$debs" -maxdepth 1 -name '*.deb' -printf '%f\n' | sort | sha256sum | cut -c1-16)
	echo "key=$KEY_PREFIX$hash" >>"$GITHUB_OUTPUT"
	exit 0
fi

tidy
shopt -s nullglob
cached=("$debs"/*.deb)
if [ ${#cached[@]} -eq 0 ]; then
	echo "::error::apt could not install ${PACKAGES}, and the Actions cache holds no copies of them"
	exit 1
fi
echo "::warning::apt could not download ${PACKAGES}; installing the ${#cached[@]} files kept in the Actions cache"
sudo -E apt-get install "${options[@]}" --no-download -o Dir::Cache::Archives="$debs" "${pkgs[@]}" ||
	sudo -E apt-get install "${options[@]}" "${cached[@]}"
