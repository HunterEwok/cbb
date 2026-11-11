# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The Windows installers' messages in the user's language (docs/roadmap.md,
# item 49), dot-sourced by install.ps1 and uninstall.ps1 with the directory
# of the catalogs:
#
#   . (Join-Path $PSScriptRoot 'l10n.ps1') (Join-Path $PSScriptRoot '..\l10n')
#
# The shell scripts' twin is packaging/l10n.sh, whose catalogs,
# packaging/l10n/<language>.tsv, these share. get.ps1, which runs before any archive is there, carries this
# file and its own texts' translations instead (packaging/l10n-embed.sh puts
# them in when the release is built), in $cbbL10nAll: base64 of UTF-8 lines
# of the language, a tab, the English text, a tab and the translation, since
# Windows PowerShell reads a downloaded script as Latin-1.
#
# T TEXT ARG... returns the text in the user's language with its %s filled
# by the arguments in order (%% is a percent sign); tools/repocheck checks
# that every catalog translates every text with as many %s. The language is
# CBB_LANG when it is set, else Windows' display language; English when the
# project has no translation (zh es ru ar sw he hi have one). The scripts it
# starts get the same CBB_LANG.
param([string]$CatalogDir = '')

$cbbLang = if ($env:CBB_LANG) { [string]$env:CBB_LANG } else { (Get-UICulture).TwoLetterISOLanguageName }
$cbbLang = ($cbbLang.ToLowerInvariant() -split '[-_.@]')[0]
if ($cbbLang -notin @('zh', 'es', 'ru', 'ar', 'sw', 'he', 'hi')) {
	$cbbLang = 'en'
}
$env:CBB_LANG = $cbbLang

# The translations of the user's language, English text to translation.
$cbbL10n = New-Object 'System.Collections.Generic.Dictionary[string,string]'
$cbbLines = @()
if ($cbbLang -ne 'en') {
	if ((Get-Variable -Name cbbL10nAll -ErrorAction SilentlyContinue) -and $cbbL10nAll) {
		$cbbLines = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($cbbL10nAll)) -split "`n" |
			Where-Object { $_.StartsWith("$cbbLang`t") } | ForEach-Object { $_.Substring($cbbLang.Length + 1) }
	} elseif ($CatalogDir -and (Test-Path (Join-Path $CatalogDir "$cbbLang.tsv"))) {
		$cbbLines = Get-Content -Encoding UTF8 (Join-Path $CatalogDir "$cbbLang.tsv")
	}
}
foreach ($cbbLine in $cbbLines) {
	$cbbPair = $cbbLine.TrimEnd("`r") -split "`t", 2
	if ($cbbPair.Count -eq 2 -and $cbbPair[1]) {
		$cbbL10n[$cbbPair[0]] = $cbbPair[1]
	}
}

function T([string]$Text) {
	$f = $Text
	if ($cbbL10n.ContainsKey($Text)) {
		$f = $cbbL10n[$Text]
	}
	$out = New-Object Text.StringBuilder
	$n = 0
	for ($k = 0; $k -lt $f.Length; $k++) {
		if ($f[$k] -eq '%' -and $k + 1 -lt $f.Length) {
			if ($f[$k + 1] -eq 's') {
				if ($n -lt $args.Count) { [void]$out.Append([string]$args[$n]) }
				$n++
				$k++
				continue
			}
			if ($f[$k + 1] -eq '%') {
				[void]$out.Append('%')
				$k++
				continue
			}
		}
		[void]$out.Append($f[$k])
	}
	$out.ToString()
}

# Test-Yes tells whether a reply to a [y/N] question is yes: y or yes, or
# the words the user's language has for them.
function Test-Yes([string]$Reply) {
	$r = $Reply.Trim()
	$r -and ($r -in @('y', 'yes') -or $r -ceq (T 'y') -or $r -ceq (T 'yes') -or $r -ceq (T 'Y') -or $r -ceq (T 'Yes'))
}
