#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs or updates cbb on a Linux machine, an OpenWrt router
# (25.12 or later), a Mac or FreeBSD from a release (Windows has get.ps1):
#
#   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
#
# Options go after "sh -s --": --express adds the firewall rules
# cbb needs without asking and says what it added, --no-firewall
# adds none and prints the commands that would, --port N moves the member
# port from 8764 to N, --home-cgnat on counts 100.64.0.0/10 as the home
# network too (a home network on the carrier-grade NAT range); on Linux,
# --no-helper leaves out cbb-helper, the Go helper beside cbb (keys in the
# TPM, the desktop's clipboard and keys, Bluetooth), for a small device that
# needs none of it, --console also starts tmux after a login on the text
# console, and --uinput adds the uinput helper for remote paste on desktops
# without another way to press keys. The archive of each system decides the
# rest: a router's (MIPS) has no helper. cbb without its helper starts
# pairing as soon as it runs in no group and shows its QR code; --no-pair,
# for a scripted install, leaves that for later.
# --rootless, run without sudo (curl ... | sh -s -- --rootless), installs cbb
# for the user who runs it, on Linux only (D-79).
# CBB_ATTESTATION=require refuses to install unless GitHub's build
# provenance attestation of the archive checks out (it needs gh, signed in);
# CBB_ATTESTATION=skip does not check it. CBB_VERSION=v1.2.3 picks a
# release instead of the latest; CBB_RELEASE_DIR, for tests, takes the files
# from a directory instead of downloading them.
#
# It downloads the archive for this system and architecture and SHA256SUMS
# from the release, checks the archive against it and, when gh is there and
# signed in, against the release workflow's attestation, and runs the archive's
# install.sh for this system, which finds the firewall, lists the rules
# cbb needs and asks whether to add them. On a Mac, Homebrew is
# the other way (docs/guide/install.md).
set -eu

# l10n begin
# The messages in the user's language: packaging/l10n.sh from beside get.sh
# in a checkout, else English; the release puts l10n.sh and the catalogs
# here (packaging/l10n-embed.sh).
if [ -f "${0%/*}/l10n.sh" ]; then
	cbb_l10n=${0%/*}/l10n
	# shellcheck source=packaging/l10n.sh
	. "${0%/*}/l10n.sh"
else
	# shellcheck disable=SC2059 # the format is the text
	t() {
		cbb_f=$1
		shift
		printf -- "$cbb_f" "$@"
	}
	say() {
		t "$@"
		echo
	}
	sayerr() {
		t "$@" >&2
		echo >&2
	}
	note() {
		printf '%s: ' "$1" >&2
		shift
		sayerr "$@"
	}
fi
# l10n end

# A failure says so with its exit status; CBB_ERROR_DETAILS=1 shows every
# command as it runs, so that the output shows where and why it failed.
if [ "${CBB_ERROR_DETAILS:-}" = 1 ]; then
	set -x
fi
failed() {
	rc=$1
	if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ] && [ "${CBB_ERROR_DETAILS:-}" != 1 ]; then
		note get.sh "failed (exit status %s). For every command it ran: CBB_ERROR_DETAILS=1, and run it again." "$rc"
	fi
}

repo=https://github.com/HunterEwok/cbb
console=
uinput=
port=
cgnat=
auto=
firewall=${CBB_FIREWALL:-ask}
nohelper=
nopair=
rootless=
while [ $# -gt 0 ]; do
	case $1 in
	--console) console=--console ;;
	--uinput) uinput=--uinput ;;
	--port)
		[ $# -gt 1 ] || {
			note get.sh "--port needs a port number"
			exit 2
		}
		port="--port $2"
		shift
		;;
	--home-cgnat)
		[ $# -gt 1 ] || {
			note get.sh "--home-cgnat needs on or off"
			exit 2
		}
		cgnat="--home-cgnat $2"
		shift
		;;
	--auto-update)
		case ${2:-} in
		on | off) auto="--auto-update $2" ;;
		*)
			note get.sh "--auto-update needs on or off"
			exit 2
			;;
		esac
		shift
		;;
	--express) firewall=express ;;
	--no-firewall) firewall=no ;;
	--no-helper) nohelper=--no-helper ;;
	--no-pair) nopair=--no-pair ;;
	--rootless) rootless=--rootless ;;
	*)
		note get.sh "unknown option %s (known: --no-helper, --no-pair, --rootless, --console, --uinput, --port N, --home-cgnat on|off, --auto-update on|off, --express, --no-firewall)" "$1"
		exit 2
		;;
	esac
	shift
done

# fail TEXT ARG... says why get.sh stops, and stops.
fail() {
	note get.sh "$@"
	exit 1
}

if [ -n "$rootless" ]; then
	[ "$(id -u)" -ne 0 ] || fail "--rootless installs for your own user: run it without sudo: %s" "curl -fsSL $repo/releases/latest/download/get.sh | sh -s -- --rootless"
	if [ "$(uname -s)" != Linux ] || [ -f /etc/openwrt_release ]; then
		fail "--rootless is for Linux computers"
	fi
else
	[ "$(id -u)" -eq 0 ] || fail "run it with sudo: %s" "curl -fsSL $repo/releases/latest/download/get.sh | sudo sh"
fi
case $(uname -s) in
Linux)
	os=linux
	case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	armv7l | armv8l) arch=armv7 ;;
	armv6l) arch=armv6 ;;
	# uname says mips for either byte order; OpenWrt's package
	# architecture tells them apart.
	mips)
		case $(sed -n "s/^DISTRIB_ARCH='\{0,1\}\([^_']*\).*/\1/p" /etc/openwrt_release 2>/dev/null) in
		mipsel) arch=mipsle ;;
		mips) arch=mips ;;
		*) fail "no release for this MIPS system: it is not OpenWrt, which names its byte order" ;;
		esac
		;;
	*) fail "no release for the architecture %s" "$(uname -m)" ;;
	esac
	if [ -f /etc/openwrt_release ]; then
		os=openwrt
		if [ "${arch%le}" = mips ]; then
			note get.sh "cbb for MIPS has no sync away from home yet (roadmap item 37)."
		fi
		[ -z "$console" ] || fail "--console is not for a router"
		[ -z "$uinput" ] || fail "--uinput is not for a router"
		[ -z "$cgnat" ] || fail "--home-cgnat is not for a router"
	fi
	;;
Darwin)
	os=darwin
	[ -z "$nohelper" ] || fail "--no-helper is for Linux"
	[ -z "$console" ] || fail "--console is for Linux"
	[ -z "$uinput" ] || fail "--uinput is for Linux"
	# A shell under Rosetta reports x86_64 on an Apple chip.
	if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ]; then
		arch=arm64
	else
		arch=amd64
	fi
	;;
FreeBSD)
	os=freebsd
	[ -z "$nohelper" ] || fail "--no-helper is for Linux"
	[ -z "$console" ] || fail "--console is for Linux"
	[ -z "$uinput" ] || fail "--uinput is for Linux"
	case $(uname -m) in
	amd64) arch=amd64 ;;
	arm64) arch=arm64 ;;
	*) fail "no release for the architecture %s" "$(uname -m)" ;;
	esac
	;;
*) fail "this installer is for Linux, macOS and FreeBSD; on Windows use get.ps1" ;;
esac
command -v tar >/dev/null 2>&1 || fail "tar is required"
if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif [ "$os" = freebsd ]; then
	sha256() { command sha256 -q "$1"; }
else
	fail "sha256sum or shasum is required"
fi
if [ -n "${CBB_RELEASE_DIR:-}" ]; then
	fetch() { cp "$CBB_RELEASE_DIR/${1##*/}" "$2"; }
elif command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif [ "$os" = openwrt ] && command -v uclient-fetch >/dev/null 2>&1; then
	# OpenWrt's wget is often uclient-fetch, which does not take
	# --https-only; it checks the server's certificate by itself.
	fetch() { uclient-fetch -q -O "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q --https-only -O "$2" "$1"; }
elif [ "$os" = freebsd ]; then
	# FreeBSD's own fetch(1), which checks the server's certificate.
	fetch() { command fetch -q -o "$2" "$1"; }
else
	fail "curl or wget is required"
fi

version=${CBB_VERSION:-latest}
case $version in
latest) base=$repo/releases/latest/download ;;
v*) base=$repo/releases/download/$version ;;
*) fail "CBB_VERSION must look like v1.2.3" ;;
esac
# OpenWrt takes the Linux archive, which carries its installer too.
archive=cbb-$os-$arch.tar.gz
[ "$os" != openwrt ] || archive=cbb-linux-$arch.tar.gz
dir=cbb

# The project's release root keys (docs/protocol.md, section 16), which sign
# keys.json: two YubiKeys, each with its ES256 half and its SLH-DSA half
# (the halves of one root share its Name), as internal/release/roots/roots.pem.
release_roots='-----BEGIN PUBLIC KEY-----
Name: root-1

MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9sLfrcGBi23XveQN8dK8Z+lbEuxT
LOgnQ9s/gzp/k7xx88IFvkdMuyoL2K7j1necQGYLmq3ifie9wDrF69AO/A==
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
Name: root-2

MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExGbAq55XGXip3Dtq6jsM2bOYUeoY
fDxsggXLisjwoCQoDM28pCYkIoZAfcjwR3aAGOAUWZX+L53og7/TLLpnfg==
-----END PUBLIC KEY-----'

# Where the current keys.json and stable.json are: the branch channel, since
# a published release takes no new files and these are signed again while
# it is current (docs/protocol.md, section 16).
channel_files=https://raw.githubusercontent.com/HunterEwok/cbb/channel

roots=$release_roots
if [ -n "${CBB_RELEASE_DIR:-}" ] && [ -n "${CBB_RELEASE_ROOTS:-}" ]; then
	roots=$(cat "$CBB_RELEASE_ROOTS")
fi
# verifying tells whether the release's signature is checked.
verifying() { [ "${CBB_VERIFY:-}" != skip ] && [ -n "$roots" ]; }

# field NAME FILE prints the string field NAME of the compact JSON in FILE,
# number NAME FILE a number field: enough for the files Go's encoding/json
# writes, which is all these are.
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" "$2" | head -n 1; }
number() { sed -n "s/.*\"$1\":\([0-9][0-9]*\).*/\1/p" "$2" | head -n 1; }

# strict FILE tells whether the body in FILE is in the strict form as far as
# get.sh reads it (docs/protocol.md, "Signed bodies"): every member name 1 to
# 64 of a-z, 0-9 and _, no null, no backslash (the signer writes none in these
# files), and no field get.sh reads written twice, so that field and number,
# which take the first, read a body as the other programs do.
strict() {
	! grep -qF "\\" "$1" || return 1
	! grep -o '"[^"]*":' "$1" | grep -qv '^"[a-z0-9_]\{1,64\}":$' || return 1
	! grep -q '[:,[]null' "$1" || return 1
	for n in v type seq time_ms expires_ms keys version channel release release_sha256 files; do
		[ "$(grep -o "\"$n\":" "$1" | wc -l)" -le 1 ] || return 1
	done
}

# Every file carries a signature of each algorithm (docs/protocol.md,
# section 16, "Two signatures"): 1, ES256, which every openssl checks, and 4,
# SLH-DSA-SHA2-128s, which OpenSSL 3.5 and later check. checked names those
# this openssl checks, set by algorithms.
checked=
algorithms() {
	checked=1
	# The post-quantum half where this openssl has SLH-DSA (OpenSSL 3.5 and
	# later). It must sign and check it as the project does, with the
	# context "cbb release v1": a round trip with a key of its own, which
	# another context must refuse. An openssl that has SLH-DSA and reads the
	# options otherwise stops the install rather than checking one
	# signature quietly.
	openssl list -signature-algorithms 2>/dev/null | grep -qi 'SLH-DSA-SHA2-128s' || return 0
	printf 'cbb' >"$tmp/slh.msg"
	openssl genpkey -algorithm SLH-DSA-SHA2-128s -out "$tmp/slh.key" 2>/dev/null &&
		openssl pkey -in "$tmp/slh.key" -pubout -out "$tmp/slh.pub" 2>/dev/null &&
		openssl pkeyutl -sign -rawin -inkey "$tmp/slh.key" -in "$tmp/slh.msg" -out "$tmp/slh.sig" -pkeyopt "context-string:cbb release v1" >/dev/null 2>&1 &&
		slh_verify "$tmp/slh.pub" "$tmp/slh.sig" "$tmp/slh.msg" &&
		! openssl pkeyutl -verify -pubin -inkey "$tmp/slh.pub" -rawin -in "$tmp/slh.msg" -sigfile "$tmp/slh.sig" -pkeyopt "context-string:cbb release v0" >/dev/null 2>&1 &&
		checked="1 4"
	rm -f "$tmp/slh.key" "$tmp/slh.pub" "$tmp/slh.sig" "$tmp/slh.msg"
	[ "$checked" = "1 4" ] ||
		fail "%s has SLH-DSA-SHA2-128s but does not check it as cbb signs it; update openssl (or CBB_VERIFY=skip to install unchecked)" "$(openssl version)"
}
slh_verify() {
	openssl pkeyutl -verify -pubin -inkey "$1" -rawin -in "$3" -sigfile "$2" -pkeyopt "context-string:cbb release v1" >/dev/null 2>&1
}
# roots_list writes the root keys as keys.list writes keys.json's: a line
# "ALG USE KEY NAME" for each half, KEY its SubjectPublicKeyInfo in base64.
roots_list() {
	printf '%s\n' "$roots" | awk '
		/^-----BEGIN PUBLIC KEY-----$/ { name = ""; key = ""; body = 0; next }
		/^-----END PUBLIC KEY-----$/ {
			alg = 0
			if (key ~ /^MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/) alg = 1
			if (key ~ /^MDAwCwYJYIZIAWUDBAMUAyEA/) alg = 4
			print alg, "root", key, name
			next
		}
		!body && /^Name:/ { sub(/^Name:[ \t]*/, ""); name = $0; next }
		!body && /^$/ { body = 1; next }
		{ body = 1; key = key $0 }
	'
}

# small FILE tells whether FILE is no larger than a release file may be,
# 1 MiB.
small() { [ "$(wc -c <"$1" | tr -d ' ')" -le 1048576 ]; }

# algs_valid tells whether every line of its input is an algorithm number
# as the readers take it: 1 to 2^31-1, written without leading zeros.
algs_valid() {
	awk '!/^[1-9][0-9]*$/ || length($0) > 10 || $0 + 0 > 2147483647 { bad = 1 } END { exit bad }'
}

# low_s FILE tells whether the ES256 signature in FILE (DER) has the low S,
# at most half the order of P-256, the one form every reader takes.
low_s() {
	s=$(openssl asn1parse -inform DER -in "$1" 2>/dev/null | awk -F: '/INTEGER/ { v = $NF } END { print v }')
	[ -n "$s" ] || return 1
	awk -v s="$s" 'BEGIN {
		h = "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8"
		s = toupper(s); sub(/^0+/, "", s)
		if (length(s) > 64) exit 1
		while (length(s) < 64) s = "0" s
		exit !(s <= h)
	}'
}

# opened FILE NAME LIST USES... checks the envelope in FILE with the keys of
# LIST (lines "ALG USE KEY NAME") of the uses USES, and leaves its body in
# $tmp/NAME.body. It takes the file when the halves of one key signed it
# with every algorithm of $checked, and refuses it when a listed key's
# signature that this openssl checks does not verify, or the body is not of
# the type NAME. A signature of another algorithm, or of a key not listed,
# is passed over, as every reader does.
opened() {
	f=$1 kind=$2 list=$3
	shift 3
	field body "$f" | openssl base64 -d -A >"$tmp/$kind.body" 2>/dev/null || return 1
	# Each signature read whole, in the form the signer writes; one that
	# does not read so refuses the file, as it does in every reader.
	small "$f" || return 1
	grep -oE '\{"alg":[0-9]+,"key":"[A-Za-z0-9+/=]*","sig":"[A-Za-z0-9+/=]*"\}' "$f" >"$tmp/$kind.sigs" || return 1
	[ "$(wc -l <"$tmp/$kind.sigs")" -eq "$(grep -o '"alg":' "$f" | wc -l)" ] || return 1
	# At most 8 signatures, each of an algorithm 1 to 2^31-1, and a body
	# of 256 KiB at most, as every reader takes.
	[ "$(wc -l <"$tmp/$kind.sigs")" -le 8 ] || return 1
	sed 's/^{"alg":\([0-9]*\),.*/\1/' "$tmp/$kind.sigs" | algs_valid || return 1
	[ "$(wc -c <"$tmp/$kind.body" | tr -d ' ')" -le 262144 ] || return 1
	# A key is its halves under one use and name, one of each algorithm:
	# two of one algorithm there would make one key of two.
	awk '{ n = $0; sub(/^[^ ]* [^ ]* [^ ]* /, "", n); if (seen[$1 " " $2 " " n]++) exit 1 }' "$list" || return 1
	: >"$tmp/$kind.good"
	n=0
	while read -r alg use key name; do
		n=$((n + 1))
		case " $checked " in *" $alg "*) ;; *) continue ;; esac
		case " $* " in *" $use "*) ;; *) continue ;; esac
		khash=$(printf '%s' "$key" | openssl base64 -d -A | openssl dgst -sha256 -binary | openssl base64 -A)
		grep -F "\"alg\":$alg,\"key\":\"$khash\"," "$tmp/$kind.sigs" >"$tmp/$kind.sig.lines" || continue
		printf '%s' "$key" | openssl base64 -d -A | openssl pkey -pubin -inform DER -out "$tmp/$kind.pub-$n.pem" 2>/dev/null || return 1
		# Every signature by this half must verify, not only the first.
		while read -r line; do
			printf '%s\n' "$line" >"$tmp/$kind.sig.json"
			field sig "$tmp/$kind.sig.json" | openssl base64 -d -A >"$tmp/$kind.sig" 2>/dev/null || return 1
			# A signature longer than 16 KiB is passed over, as every reader does.
			[ "$(wc -c <"$tmp/$kind.sig" | tr -d ' ')" -le 16384 ] || continue
			case $alg in
			1)
				low_s "$tmp/$kind.sig" || return 1
				openssl dgst -sha256 -verify "$tmp/$kind.pub-$n.pem" -signature "$tmp/$kind.sig" "$tmp/$kind.body" >/dev/null 2>&1 || return 1
				;;
			4) slh_verify "$tmp/$kind.pub-$n.pem" "$tmp/$kind.sig" "$tmp/$kind.body" || return 1 ;;
			esac
			printf '%s %s %s\n' "$alg" "$use" "$name" >>"$tmp/$kind.good"
		done <"$tmp/$kind.sig.lines"
	done <"$list"
	# One key, by its use and name, signed with every algorithm checked.
	awk -v n="$(echo "$checked" | wc -w)" '{ k = $0; sub(/^[^ ]* /, "", k); if (!seen[$0]++) c[k]++ }
		END { for (k in c) if (c[k] == n) ok = 1; exit !ok }' "$tmp/$kind.good" || return 1
	strict "$tmp/$kind.body" || fail "the signed %s file is not in the strict form of signed bodies; not installing" "$kind"
	[ "$(field type "$tmp/$kind.body")" = "$kind" ] || return 1
	[ "$(number v "$tmp/$kind.body")" = 1 ] || return 1
	[ -n "$(number time_ms "$tmp/$kind.body")" ] || return 1
	return 0
}

# verify_release checks keys.json against the root keys, release.json and,
# for the latest release, stable.json against its release (or channel) keys,
# and the archive against release.json. Without openssl it stops unless
# CBB_VERIFY=skip, since the sums come from the same server as the archive.
verify_release() {
	if [ "${CBB_VERIFY:-}" = skip ]; then
		say "Not checked: the release's signature (CBB_VERIFY=skip)."
		return
	fi
	if [ -z "$roots" ]; then
		return
	fi
	command -v openssl >/dev/null 2>&1 ||
		fail "openssl is required to check the release's signature (or CBB_VERIFY=skip to install it unchecked)"
	algorithms
	roots_list >"$tmp/roots.list"
	if ! fetch "$channel_files/keys.json" "$tmp/keys.json" || ! fetch "$base/release.json" "$tmp/release.json"; then
		fail "%s has no signed release files; not installing it (CBB_VERIFY=skip installs it unchecked)" "$version"
	fi
	opened "$tmp/keys.json" keys "$tmp/roots.list" root || fail "keys.json is not signed by the project's root key; not installing"
	now_ms=$(($(date +%s) * 1000))
	[ "$(number expires_ms "$tmp/keys.body")" -gt "$now_ms" ] || fail "keys.json has expired; check the clock, or try again later"
	# Each half with its use: a release key (no use) signs release.json and
	# stable.json, a channel key only stable.json, a key of another use
	# neither. Each entry is read whole, as the signer writes it (a name may
	# hold a brace), and one that does not read so, or a use written empty,
	# refuses the file.
	grep -oE '\{"alg":[0-9]+,"key":"[A-Za-z0-9+/=]*","name":"[^"]*"(,"use":"[a-z]+")?\}' "$tmp/keys.body" >"$tmp/keys.entries" || true
	[ "$(wc -l <"$tmp/keys.entries")" -eq "$(grep -o '{"alg":' "$tmp/keys.body" | wc -l)" ] ||
		fail "keys.json is not valid; not installing"
	: >"$tmp/keys.list"
	while read -r entry; do
		printf '%s\n' "$entry" >"$tmp/key"
		case $(field use "$tmp/key") in
		"" | release) use=release ;;
		channel) use=channel ;;
		*) continue ;;
		esac
		alg=$(number alg "$tmp/key")
		printf '%s\n' "$alg" | algs_valid || fail "keys.json is not valid; not installing"
		# A half this openssl checks must be a key it reads.
		case " $checked " in
		*" $alg "*)
			field key "$tmp/key" | openssl base64 -d -A | openssl pkey -pubin -inform DER -noout 2>/dev/null ||
				fail "keys.json holds a key that is not valid"
			;;
		esac
		printf '%s %s %s %s\n' "$alg" "$use" "$(field key "$tmp/key")" "$(field name "$tmp/key")" >>"$tmp/keys.list"
	done <"$tmp/keys.entries"
	grep -q ' release ' "$tmp/keys.list" || fail "keys.json holds no release key"
	opened "$tmp/release.json" release "$tmp/keys.list" release || fail "release.json is not signed by a release key; not installing"
	got_version=$(field version "$tmp/release.body")
	if [ -n "$named" ]; then
		opened "$tmp/stable.json" channel "$tmp/keys.list" release channel ||
			fail "stable.json is not signed by a release or channel key; not installing"
		[ "$(field channel "$tmp/channel.body")" = stable ] || fail "stable.json is not the stable channel's"
		[ "$(number expires_ms "$tmp/channel.body")" -gt "$now_ms" ] || fail "stable.json has expired; check the clock, or try again later"
		# The release must be one for this channel, as cbb update checks.
		if [ "$(field release_sha256 "$tmp/channel.body")" != "$(sha256 "$tmp/release.body")" ] ||
			[ "$(field release "$tmp/channel.body")" != "$got_version" ] ||
			[ "$(field channel "$tmp/release.body")" != stable ]; then
			fail "release.json is not the release stable.json names; not installing"
		fi
	else
		[ "v$got_version" = "$version" ] || fail "release.json is for %s, not %s" "$got_version" "$version"
	fi
	entry=$(grep -o "{\"name\":\"$archive\",\"size\":[0-9]*,\"sha256\":\"[0-9a-f]*\"" "$tmp/release.body" | head -n 1)
	[ -n "$entry" ] || fail "release.json does not list %s" "$archive"
	printf '%s\n' "$entry" >"$tmp/entry"
	if [ "$(field sha256 "$tmp/entry")" != "$got" ] || [ "$(number size "$tmp/entry")" != "$(wc -c <"$tmp/$archive" | tr -d ' ')" ]; then
		fail "%s does not match the signed release.json; not installing it" "$archive"
	fi
	if [ "$checked" = "1 4" ]; then
		say "The release's signature checks out (%s): ES256 and SLH-DSA-SHA2-128s." "$got_version"
	else
		say "The release's signature checks out (%s): ES256; SLH-DSA-SHA2-128s not checked, it needs OpenSSL 3.5 or later." "$got_version"
	fi
}

tmp=$(mktemp -d)
trap 'rc=$?; rm -rf "$tmp"; failed $rc' EXIT
# The latest release is the one stable.json names, checked below, rather
# than GitHub's latest: the two differ for a few minutes after a release.
named=
if [ "$version" = latest ] && verifying; then
	command -v openssl >/dev/null 2>&1 ||
		fail "openssl is required to check the release's signature (or CBB_VERIFY=skip to install it unchecked)"
	fetch "$channel_files/stable.json" "$tmp/stable.json" || fail "could not download %s" "$channel_files/stable.json"
	named=$(field body "$tmp/stable.json" | openssl base64 -d -A 2>/dev/null | sed -n 's/.*"release":"\([^"]*\)".*/\1/p')
	case $named in
	[0-9]*.[0-9]*.[0-9]*) ;;
	*) fail "stable.json names no release" ;;
	esac
	version=v$named
	[ -n "${CBB_RELEASE_DIR:-}" ] || base=$repo/releases/download/$version
fi
say "Downloading %s (%s)..." "$archive" "$version"
fetch "$base/$archive" "$tmp/$archive" || fail "could not download %s" "$base/$archive"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download %s" "$base/SHA256SUMS"
want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
got=$(sha256 "$tmp/$archive")
[ -n "$want" ] || fail "SHA256SUMS does not list %s" "$archive"
[ "$want" = "$got" ] || fail "%s does not match SHA256SUMS; not installing it" "$archive"
# SHA256SUMS comes from the same release, so it shows only that the download
# is whole. The signed release files show that the project signed this
# release (docs/protocol.md, section 16).
verify_release
# The attestation shows that this repository's release workflow built the
# archive.
attestation=${CBB_ATTESTATION:-check}
if [ -n "${CBB_RELEASE_DIR:-}" ] || [ "$attestation" = skip ]; then
	:
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
	gh attestation verify "$tmp/$archive" --repo HunterEwok/cbb >/dev/null ||
		fail "%s does not have this repository's build attestation; not installing it" "$archive"
	say "The archive's build attestation checks out."
elif [ "$attestation" = require ]; then
	fail "CBB_ATTESTATION=require needs gh, signed in (gh auth login), to check the archive's build attestation"
else
	say "Not checked: the archive's build attestation (it needs gh, signed in). SHA256SUMS matched."
fi
tar -xzf "$tmp/$archive" -C "$tmp"

if [ "$os" = darwin ]; then
	# shellcheck disable=SC2086 # $port, $cgnat and $auto are words or none
	CBB_FIREWALL=$firewall sh "$tmp/$dir/packaging/macos/install.sh" $port $cgnat $auto "$tmp/$dir/cbb"
elif [ "$os" = freebsd ]; then
	# shellcheck disable=SC2086 # $port, $cgnat and $auto are words or none
	CBB_FIREWALL=$firewall sh "$tmp/$dir/packaging/freebsd/install.sh" $port $cgnat $auto "$tmp/$dir/cbb"
elif [ "$os" = openwrt ]; then
	# shellcheck disable=SC2086 # $port, $auto, $nohelper and $nopair are words or none
	sh "$tmp/$dir/packaging/openwrt/install.sh" $port $auto $nohelper $nopair "$tmp/$dir/cbb"
else
	# shellcheck disable=SC2086 # $rootless, $console, $uinput, $port, $cgnat, $auto, $nohelper and $nopair are words or none
	CBB_FIREWALL=$firewall sh "$tmp/$dir/packaging/linux/install.sh" $rootless $console $uinput $port $cgnat $auto $nohelper $nopair "$tmp/$dir/cbb"
fi

