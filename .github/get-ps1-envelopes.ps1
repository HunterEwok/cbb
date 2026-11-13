# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# get.ps1 against every way of writing release.json that the readers must
# agree on (internal/release.Envelopes, the same as the interop vectors):
# each is taken or refused as Go and the core take or refuse it, and
# keys.json's body is taken at the largest size and refused one byte over.
# get.ps1's own functions check each, cut out of it as they are, so nothing
# is installed. Windows PowerShell 5.1 and PowerShell 7:
#   powershell -File .github/get-ps1-envelopes.ps1 -Sign RELEASE-SIGN.EXE
param([Parameter(Mandatory = $true)][string]$Sign)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$work = Join-Path ([IO.Path]::GetTempPath()) ("cbb-envelopes-" + [Guid]::NewGuid())
$rel = Join-Path $work 'release'
$envs = Join-Path $work 'envelopes'
New-Item -ItemType Directory -Path $rel, $envs | Out-Null
$archive = 'cbb-windows-amd64.zip'
# Any archive: get.ps1's check reads only its hash.
$src = Join-Path $work 'cbb.exe'
[IO.File]::WriteAllBytes($src, [byte[]](1, 2, 3))
Compress-Archive -Path $src -DestinationPath (Join-Path $rel $archive)
$sum = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes((Join-Path $rel $archive))) | ForEach-Object { $_.ToString('x2') })
"$sum  $archive" | Set-Content (Join-Path $rel 'SHA256SUMS')
$roots = Join-Path $work 'roots.pem'

function Invoke-Sign([string[]]$arguments) {
	$ErrorActionPreference = 'Continue'
	& $Sign @arguments *> $null
	if ($LASTEXITCODE -ne 0) { throw "release-sign $($arguments -join ' ') failed" }
}

# get.ps1 up to its main flow: its settings and functions.
$lines = Get-Content (Join-Path $PSScriptRoot '..\packaging\windows\get.ps1')
$from = [Array]::IndexOf($lines, '& {') + 1
$to = [Array]::IndexOf($lines, "`ttry {") - 1
if ($from -le 0 -or $to -le $from) { throw 'get.ps1 is not as this test reads it' }
$funcs = Join-Path $work 'funcs.ps1'
$lines[$from..$to] | Set-Content $funcs

# Test-Taken runs get.ps1's check of the files in the release folder as
# get.ps1 does for the latest release, and returns what it said: its
# words when it took them, its refusal otherwise.
function Test-Taken {
	$env:CBB_RELEASE_DIR = $rel
	$env:CBB_RELEASE_ROOTS = $roots
	$tmp = Join-Path $work ('t' + [Guid]::NewGuid())
	New-Item -ItemType Directory -Path $tmp | Out-Null
	Copy-Item (Join-Path $rel $archive), (Join-Path $rel 'stable.json') $tmp
	try {
		. $funcs
		$channelFiles = 'x'
		return Test-Release -base 'x' -version 'v0.6.0' -named '0.6.0' -archive $archive -got $sum -tmp $tmp 6>&1 | Out-String
	} catch {
		return "refused: $($_.Exception.Message)"
	} finally {
		Remove-Item -Recurse -Force $tmp
	}
}

$bad = 0
Invoke-Sign @('drill', '-version', '0.6.0', '-envelopes', $envs, $rel, $roots)
foreach ($line in Get-Content (Join-Path $envs 'list')) {
	$id, $ok, $name = $line -split ' ', 3
	Copy-Item (Join-Path $envs "$id.json") (Join-Path $rel 'release.json') -Force
	$said = Test-Taken
	$took = $said -match 'signature checks out'
	if ($took -ne ($ok -eq 'true')) {
		Write-Host "get.ps1: ${name}: taken $took, the readers say $ok; get.ps1 said: $said"
		$bad++
	}
}
foreach ($n in 262144, 262145) {
	Invoke-Sign @('drill', '-version', '0.6.0', '-pad-keys', "$n", $rel, $roots)
	$said = Test-Taken
	$took = $said -match 'signature checks out'
	if ($took -ne ($n -eq 262144)) {
		Write-Host "get.ps1: keys.json with a body of $n bytes: taken $took; get.ps1 said: $said"
		$bad++
	}
}
Remove-Item -Recurse -Force $work
if ($bad -gt 0) { exit 1 }
Write-Host "get.ps1 reads the envelopes as Go and the core do, with PowerShell $($PSVersionTable.PSVersion)"
