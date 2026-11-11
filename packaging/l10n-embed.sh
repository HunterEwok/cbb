#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Prints get.sh or get.ps1 with its messages' translations in itself, for
# the release:
#
#   sh packaging/l10n-embed.sh packaging/get.sh >dist/get.sh
#   sh packaging/l10n-embed.sh packaging/windows/get.ps1 >dist/get.ps1
#
# Each runs alone (curl ... | sh, irm ... | iex), before any archive with the
# catalogs is there, so the release puts its l10n file (packaging/l10n.sh,
# packaging/windows/l10n.ps1) and the translations of its own texts from
# every catalog, packaging/l10n/<language>.tsv, between its lines
# "# l10n begin" and "# l10n end", in place of what is there: that takes the
# l10n file from beside it in a checkout, and speaks English without it.
# get.ps1 gets them in base64, as Windows PowerShell reads a downloaded
# script as Latin-1.
set -eu

[ $# -eq 1 ] || {
	echo "usage: sh packaging/l10n-embed.sh path/to/get.sh|get.ps1" >&2
	exit 2
}
here=$(cd "$(dirname "$0")" && pwd)
script=$1
if ! grep -q '^[[:space:]]*# l10n begin$' "$script" || ! grep -q '^[[:space:]]*# l10n end$' "$script"; then
	echo "l10n-embed.sh: $script has no \"# l10n begin\" and \"# l10n end\" lines" >&2
	exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The lines of every catalog whose text the script says, each as
# "language<tab>English<tab>translation". A text is in the script as it is,
# or with its quotes escaped: \" in sh, '' in PowerShell.
for f in "$here"/l10n/*.tsv; do
	awk -v l="$(basename "$f" .tsv)" -v script="$script" '
		BEGIN {
			FS = "\t"
			while ((getline line < script) > 0) src = src line "\n"
		}
		function escaped(s, q, r,   out, i, c) {
			out = ""
			for (i = 1; i <= length(s); i++) {
				c = substr(s, i, 1)
				out = out (c == q ? r : c)
			}
			return out
		}
		NF == 2 && (index(src, $1) || index(src, escaped($1, "\"", "\\\"")) || index(src, escaped($1, "'\''", "'\'''\''"))) {
			print l "\t" $0
		}
	' "$f"
done >"$work/lines"

case $script in
*.ps1)
	{
		echo '	# l10n begin: put in by packaging/l10n-embed.sh'
		printf "	\$cbbL10nAll = '%s'\n" "$(openssl base64 -A <"$work/lines")"
		echo "	\$CatalogDir = ''"
		# l10n.ps1 without its license header, which get.ps1 has, and its
		# parameter, set above.
		sed -e '1,/^$/d' -e '/^param(/d' "$here/windows/l10n.ps1" | sed 's/^./	&/'
		echo '	# l10n end'
	} >"$work/block"
	;;
*)
	{
		echo '# l10n begin: put in by packaging/l10n-embed.sh'
		# Single quotes closed and opened around an escaped one.
		printf "cbb_l10n_all='%s'\n" "$(sed "s/'/'\\\\''/g" "$work/lines")"
		# l10n.sh without its license header, which get.sh has.
		sed '1,/^$/d' "$here/l10n.sh"
		echo '# l10n end'
	} >"$work/block"
	;;
esac
awk -v block="$work/block" '
	/^[[:space:]]*# l10n begin$/ { while ((getline line < block) > 0) print line; skip = 1; next }
	/^[[:space:]]*# l10n end$/ { skip = 0; next }
	!skip { print }
' "$script"
