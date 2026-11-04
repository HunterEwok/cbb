#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Checks site/deploy/nginx.conf with nginx -t in nginx's own image, from the
# repository's root. The image has no ACME module, so its directives give way
# to a throwaway certificate, and the secret preview map, which lives only on
# the server, to a closed site. The VLESS location comes from site/README.md,
# "VLESS", with a path of its own.
set -eu

image=nginx:1.29.0
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
	-subj /CN=cbb.tools -keyout "$dir/key.pem" -out "$dir/cert.pem" 2>/dev/null
# shellcheck disable=SC2016 # nginx's variables, not the shell's
printf 'map $cookie_cbb_preview $cbb_closed { default 1; }\n' >"$dir/cbb-preview.conf"
# The location as README's heredoc writes it, its shell escapes undone.
awk '
	/^sudo tee \/etc\/nginx\/cbb-vless-location\.conf <<EOF$/ { on = 1; next }
	on && /^EOF$/ { exit }
	on { gsub(/\$P/, "/check-path"); gsub(/\\\$/, "$"); print }
' site/README.md >"$dir/cbb-vless-location.conf"
grep -q '^location /check-path {' "$dir/cbb-vless-location.conf" || {
	echo "nginx-check.sh: no VLESS location in site/README.md" >&2
	exit 1
}
printf 'events {}\nhttp {\n    include /check/cbb.tools.conf;\n}\n' >"$dir/nginx.conf"
awk '
	/^acme_issuer / { skip = 1 }
	skip { if ($0 ~ /^}/) skip = 0; next }
	/^acme_shared_zone / || /^[ \t]*acme_certificate / { next }
	{
		gsub(/\$acme_certificate_key/, "/check/key.pem")
		gsub(/\$acme_certificate/, "/check/cert.pem")
		sub(/include \/etc\/nginx\/cbb-preview\.conf;/, "include /check/cbb-preview.conf;")
		sub(/include \/etc\/nginx\/cbb-vless-location\*\.conf;/, "include /check/cbb-vless-location.conf;")
		print
	}
' site/deploy/nginx.conf >"$dir/cbb.tools.conf"
if grep -q acme "$dir/cbb.tools.conf"; then
	echo "nginx-check.sh: an ACME directive is left; teach this script about it" >&2
	exit 1
fi
chmod -R a+rX "$dir"
docker run --rm -v "$dir:/check:ro" "$image" nginx -t -c /check/nginx.conf
