# shellcheck shell=sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The installers' messages in the user's language (docs/roadmap.md, item 49),
# sourced by get.sh, the installers and uninstallers and update.sh.
#
# A script sets cbb_l10n to the directory of the catalogs, packaging/l10n,
# and sources this file. Each catalog, l10n/<language>.tsv, holds one text a
# line: the English text, a tab and its translation. get.sh, which runs
# before any archive is there, carries this file and every catalog in itself
# instead (packaging/l10n-embed.sh puts them in when the release is built),
# in cbb_l10n_all: one text a line, the language, a tab, the English text, a
# tab and the translation.
#
# say and sayerr print a text and a newline, to the standard output or
# error, and t prints it without the newline, for a question. A text is a
# printf format whose only directive is %s (%% for a percent sign), and the
# arguments after it fill its %s in order; tools/repocheck checks that every
# catalog translates every text with the same number of them.
#
# The language is CBB_LANG when it is set (the scripts a script starts get
# its own so), else the locale's as gettext
# reads it (LANGUAGE, unless the locale is C, then LC_ALL, LC_MESSAGES,
# LANG), else on a Mac the first of the user's languages; English when the
# project has no translation (zh es ru ar sw he hi have one).

# cbb_pick VALUE... prints the language of the first value set: one of the
# project's or en. A value may be a list (LANGUAGE's ru:en), and C and POSIX
# mean English.
cbb_pick() {
	for cbb_v in "$@"; do
		[ -n "$cbb_v" ] || continue
		cbb_ifs=$IFS
		IFS=:
		for cbb_e in $cbb_v; do
			cbb_c=$(printf '%s' "${cbb_e%%[_.@-]*}" | tr '[:upper:]' '[:lower:]')
			case $cbb_c in
			c | posix | en)
				IFS=$cbb_ifs
				echo en
				return
				;;
			zh | es | ru | ar | sw | he | hi)
				IFS=$cbb_ifs
				echo "$cbb_c"
				return
				;;
			esac
		done
		IFS=$cbb_ifs
		# The first value set decides, as in gettext.
		echo en
		return
	done
	echo en
}

# cbb_lang prints the user's language.
cbb_lang() {
	if [ -n "${CBB_LANG:-}" ]; then
		cbb_pick "$CBB_LANG"
		return
	fi
	cbb_locale=${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}
	case $cbb_locale in
	C | C.* | POSIX)
		echo en
		return
		;;
	"")
		# A Mac's shell may have no locale: the language is then the
		# user's first one in the system settings.
		if [ "$(uname -s)" = Darwin ]; then
			if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
				cbb_langs=$(sudo -u "$SUDO_USER" defaults read -g AppleLanguages 2>/dev/null) || cbb_langs=
			else
				cbb_langs=$(defaults read -g AppleLanguages 2>/dev/null) || cbb_langs=
			fi
			cbb_first=$(printf '%s\n' "$cbb_langs" |
				sed -n 's/^[[:space:]]*"\{0,1\}\([A-Za-z][A-Za-z-]*\).*/\1/p' | head -n 1)
			cbb_pick "$cbb_first"
			return
		fi
		echo en
		return
		;;
	esac
	cbb_pick "${LANGUAGE:-}" "$cbb_locale"
}

cbb_l10n_lang=$(cbb_lang)
# The scripts this one starts speak the same language, although the
# installers set LC_ALL=C for the tools whose output they read.
CBB_LANG=$cbb_l10n_lang
export CBB_LANG
cbb_user_lc_all=${LC_ALL-unset}

# in_locale CMD ARG... runs CMD in the user's own locale, for a program
# that talks to the user itself, such as cbb pair.
in_locale() {
	if [ "$cbb_user_lc_all" = unset ]; then
		env -u LC_ALL "$@"
	else
		env LC_ALL="$cbb_user_lc_all" "$@"
	fi
}

# The catalog is read once, so that the texts stay when a script removes it
# (uninstall.sh), in cbb_l10n_all's form.
cbb_tab=$(printf '\t')
if [ -z "${cbb_l10n_all:-}" ] && [ "$cbb_l10n_lang" != en ] && [ -f "${cbb_l10n:-}/$cbb_l10n_lang.tsv" ]; then
	cbb_l10n_all=$(awk -v l="$cbb_l10n_lang" 'NF { print l "\t" $0 }' "$cbb_l10n/$cbb_l10n_lang.tsv")
fi

# cbb_text TEXT prints the translation of the English TEXT, or TEXT.
cbb_text() {
	cbb_m=
	if [ "$cbb_l10n_lang" != en ] && [ -n "${cbb_l10n_all:-}" ]; then
		cbb_m=$(printf '%s\n' "$cbb_l10n_all" | awk -F "$cbb_tab" -v l="$cbb_l10n_lang" -v k="$1" '$1 == l && $2 == k { print $3; exit }')
	fi
	printf '%s' "${cbb_m:-$1}"
}

# t TEXT ARG... prints the translated TEXT with its %s filled.
t() {
	cbb_f=$(cbb_text "$1")
	shift
	# shellcheck disable=SC2059 # the format is the catalog's text
	printf -- "$cbb_f" "$@"
}

# say TEXT ARG... prints it and a newline.
say() {
	t "$@"
	echo
}

# sayerr TEXT ARG... prints it and a newline to the standard error.
sayerr() {
	t "$@" >&2
	echo >&2
}

# note NAME TEXT ARG... prints "NAME: " and the text to the standard error,
# as the scripts' warnings and errors.
note() {
	printf '%s: ' "$1" >&2
	shift
	sayerr "$@"
}

# is_yes REPLY tells whether a reply to a [y/N] question is yes: y or yes,
# or the words the user's language has for them.
is_yes() {
	case $1 in
	y | Y | yes | Yes | YES) return 0 ;;
	"") return 1 ;;
	esac
	[ "$1" = "$(cbb_text y)" ] || [ "$1" = "$(cbb_text yes)" ] || [ "$1" = "$(cbb_text Y)" ] || [ "$1" = "$(cbb_text Yes)" ]
}
