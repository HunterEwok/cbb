#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# get.sh against every way of writing release.json that the readers must
# agree on (internal/release.Envelopes, the same as the interop vectors):
# each is taken or refused as Go and the core take or refuse it. CI runs it
# as root in a Debian container, where get.sh stops after the check (no
# service there), so each case reads what get.sh says of the signature:
# docker run ... debian:<release> sh .github/get-sh-envelopes.sh RELEASE-SIGN,
# with release-sign built for linux/amd64 without cgo.
set -eu
sign=$1
if ! command -v openssl >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null
	apt-get install -y -qq openssl ca-certificates >/dev/null
fi
openssl version
rel=$(mktemp -d)
envs=$(mktemp -d)
# Any archive: get.sh checks it and its signed files, then fails to install.
mkdir "$rel/x" && echo x >"$rel/x/cbb" && tar -czf "$rel/cbb-linux-amd64.tar.gz" -C "$rel/x" cbb
(cd "$rel" && sha256sum -- *.tar.gz >SHA256SUMS)
export CBB_RELEASE_DIR="$rel" CBB_RELEASE_ROOTS="$rel/roots.pem"
"$sign" drill -version 0.6.0 -envelopes "$envs" "$rel" "$rel/roots.pem"
bad=0
while read -r id ok name; do
	cp "$envs/$id.json" "$rel/release.json"
	sh packaging/get.sh --no-firewall --no-helper >"$rel/out" 2>&1 || true
	if grep -q "signature checks out" "$rel/out"; then took=true; else took=false; fi
	if [ "$took" != "$ok" ]; then
		echo "get.sh: $name: taken $took, the readers say $ok" >&2
		sed 's/^/  /' "$rel/out" >&2
		bad=1
	fi
done <"$envs/list"
# keys.json's body at the largest a reader takes, and one byte more.
for n in 262144 262145; do
	"$sign" drill -version 0.6.0 -pad-keys "$n" "$rel" "$rel/roots.pem"
	sh packaging/get.sh --no-firewall --no-helper >"$rel/out" 2>&1 || true
	if grep -q "signature checks out" "$rel/out"; then took=true; else took=false; fi
	if [ "$took" != "$([ "$n" -eq 262144 ] && echo true || echo false)" ]; then
		echo "get.sh: keys.json with a body of $n bytes: taken $took" >&2
		sed 's/^/  /' "$rel/out" >&2
		bad=1
	fi
done
[ "$bad" -eq 0 ] || exit 1
echo "get.sh reads the $(wc -l <"$envs/list") envelopes as Go and the core do, with $(openssl version)"
