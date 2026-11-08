#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# CI's build of the Aurora app: ci.sh PSDK ARCHS OUT sets up the Platform SDK in
# PSDK (psdk.sh, with sudo), builds the Rust core and the icons, builds an RPM
# for each architecture in ARCHS (armv7hl, aarch64, or both separated by a
# space) and copies them into OUT. SYSTEM in the
# environment picks the package, as for psdk.sh: aurora5 (the default),
# aurora4 or sailfish. With
# SIGN_KEY_FILE and SIGN_CERT_FILE (the developer certificate's key
# and certificate, PEM) and KEY_PASSPHRASE (the key's password) set, it signs
# the RPMs; without them they stay unsigned.
set -eu
[ $# -eq 3 ] || { echo "usage: ci.sh PSDK ARCHS OUT" >&2; exit 2; }
psdk=$1
archs=$2
mkdir -p "$3"
out=$(cd "$3" && pwd)
here=$(cd "$(dirname "$0")" && pwd)

system=${SYSTEM:-aurora5}
case $system in
sailfish) name=harbour-cbb ;;
*) name=tools.cbb.aurora ;;
esac
sdk=$(SYSTEM=$system "$here/psdk.sh" "$psdk" name)

# shellcheck disable=SC2086 # $archs is a list on purpose
sudo SYSTEM="$system" "$here/psdk.sh" "$psdk" setup $archs
"$here/build.sh" prepare
home=$psdk/root/home/builder
for arch in $archs; do
	sudo rm -rf "$home/silica"
	sudo cp -a "$here" "$home/silica"
	sudo rm -rf "$home/silica/build"
	sudo chroot "$psdk/root" chown -R builder /home/builder/silica
	sudo SYSTEM="$system" "$here/psdk.sh" "$psdk" run "~/silica/build.sh rpm $sdk-$arch.default $system"
	# builder's home is not the caller's to read.
	rpm=$(sudo sh -c "ls $home/silica/build/*/RPMS/$name-*.$arch.rpm")

	if [ -n "${SIGN_KEY_FILE:-}" ]; then
		# The key goes into the SDK only for the one command and is removed after.
		sudo install -m 600 -o 1000 "$SIGN_KEY_FILE" "$home/sign-key.pem"
		sudo install -m 644 -o 1000 "$SIGN_CERT_FILE" "$home/sign-cert.pem"
		trap 'sudo rm -f "$home/sign-key.pem"' EXIT
		# The password reaches rpmsign-external in its environment, never on a
		# command line.
		export KEY_PASSPHRASE
		b=/home/builder
		sudo --preserve-env=KEY_PASSPHRASE chroot --userspec="1000:$(stat -c %g "$home")" "$psdk/root" /usr/bin/env HOME=$b \
			rpmsign-external sign --key $b/sign-key.pem --cert $b/sign-cert.pem "$b/silica/build/$(basename "$(dirname "$(dirname "$rpm")")")/RPMS/$(basename "$rpm")"
		sudo rm -f "$home/sign-key.pem"
	fi
	sudo cp "$rpm" "$out/"
	sudo chown "$(id -u):$(id -g)" "$out/$(basename "$rpm")"
done
ls -la "$out"
