#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# get.sh's check of both signatures, ES256 and SLH-DSA-SHA2-128s, where
# openssl checks SLH-DSA (OpenSSL 3.5 or later): CI runs it in a Debian
# trixie container, docker run ... debian:trixie sh .github/get-sh-pq.sh
# RELEASE-SIGN, with release-sign built for linux/amd64 without cgo. get.sh
# stops after the check (no service in the container), so each case reads
# its words: what it says of the signature.
set -eu
sign=$1
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq openssl ca-certificates >/dev/null
openssl version
openssl list -signature-algorithms | grep -qi 'SLH-DSA-SHA2-128s' || { echo "this openssl does not check SLH-DSA" >&2; exit 1; }
rel=$(mktemp -d)
# Any archive: get.sh checks it and its signed files, then fails to install.
mkdir "$rel/x" && echo x >"$rel/x/cbb" && tar -czf "$rel/cbb-linux-amd64.tar.gz" -C "$rel/x" cbb
(cd "$rel" && sha256sum -- *.tar.gz >SHA256SUMS)
export CBB_RELEASE_DIR="$rel" CBB_RELEASE_ROOTS="$rel/roots.pem"
run() { sh packaging/get.sh --no-firewall --no-helper >"$rel/out" 2>&1 || true; }
"$sign" drill -version 0.6.0 "$rel" "$rel/roots.pem"
run
grep -F "signature checks out (0.6.0): ES256 and SLH-DSA-SHA2-128s" "$rel/out" || { cat "$rel/out"; exit 1; }
for f in broken-pq no-pq same-name high-s broken-twin alg-zero; do
	"$sign" drill -version 0.6.0 -fault "$f" "$rel" "$rel/roots.pem"
	run
	if grep -q "signature checks out" "$rel/out"; then
		echo "get.sh took a release with the fault $f" >&2
		cat "$rel/out"
		exit 1
	fi
	grep -q "not signed by" "$rel/out" || { echo "get.sh did not refuse the signature for $f" >&2; cat "$rel/out"; exit 1; }
done
# A forwarder's pin that no reader takes refuses keys.json, whatever its use.
for f in pin-alg-zero pin-not-p256; do
	"$sign" drill -version 0.6.0 -fault "$f" "$rel" "$rel/roots.pem"
	run
	grep -q "keys.json is not valid\|keys.json holds a key that is not valid" "$rel/out" || { echo "get.sh took keys.json with the fault $f" >&2; cat "$rel/out"; exit 1; }
done
echo "get.sh checks both signatures with $(openssl version)"
