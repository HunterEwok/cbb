# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs or updates cbb on Windows from a release, in a
# PowerShell opened with "Run as administrator":
#
#   irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
#
# Options, which a piped script cannot take, come from the environment:
# CBB_PORT=N moves the member port from 8764 to N, CBB_HOME_CGNAT=1 counts
# 100.64.0.0/10 as the home network too (0 goes back), CBB_FIREWALL=express
# adds the firewall rules cbb needs without asking and says what
# it added, CBB_FIREWALL=no adds none and prints the commands that would
# (without either, install.ps1 lists the rules and asks), CBB_AUTO_UPDATE=on
# or off answers whether it updates itself once a day to a signed release
# (without it, install.ps1 asks), CBB_VERSION=v1.2.3
# picks a release instead of the latest, CBB_ATTESTATION=require refuses to
# install unless GitHub's build provenance attestation of the archive checks
# out (it needs gh, signed in), CBB_ATTESTATION=skip does not check it,
# CBB_VERIFY=skip installs a release whose signed release files
# (docs/protocol.md, section 16) do not check out,
# CBB_ERROR_DETAILS=1 shows the full
# error of a failure, and
# CBB_RELEASE_DIR, for tests, takes the files from a directory instead of
# downloading them.
#
# It downloads the archive for this machine's architecture and SHA256SUMS
# from the release, checks the archive against it and, when gh is there and
# signed in, against the release workflow's attestation, and runs
# install.ps1 from the archive.

& {
	Set-StrictMode -Version 3
	$ErrorActionPreference = 'Stop'
	$ProgressPreference = 'SilentlyContinue'
	$repo = 'https://github.com/HunterEwok/cbb'
	$details = $env:CBB_ERROR_DETAILS -eq '1'

	# l10n begin
	# The messages in the user's language: l10n.ps1 from beside get.ps1 in a
	# checkout, else English; the release puts l10n.ps1 and the translations
	# here (packaging/l10n-embed.sh).
	# A call with two values names -Text, as PSScriptAnalyzer flags three
	# positional arguments.
	if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot 'l10n.ps1'))) {
		. (Join-Path $PSScriptRoot 'l10n.ps1') (Join-Path $PSScriptRoot '..\l10n')
	} else {
		function T([string]$Text) {
			$n = 0
			$out = New-Object Text.StringBuilder
			for ($k = 0; $k -lt $Text.Length; $k++) {
				if ($Text[$k] -eq '%' -and $k + 1 -lt $Text.Length -and $Text[$k + 1] -in @('s', '%')) {
					if ($Text[$k + 1] -eq 's') {
						if ($n -lt $args.Count) { [void]$out.Append([string]$args[$n]) }
						$n++
					} else {
						[void]$out.Append('%')
					}
					$k++
					continue
				}
				[void]$out.Append($Text[$k])
			}
			$out.ToString()
		}
	}
	# l10n end
	$step = T 'starting'

	# The project's release root keys (docs/protocol.md, section 16), base64
	# SubjectPublicKeyInfos, which sign keys.json: the ES256 halves of the two
	# YubiKeys, as internal/release/roots/roots.pem. Their SLH-DSA halves are
	# left out, since PowerShell cannot check them (Test-Release says so).
	$releaseRoots = @(
		'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9sLfrcGBi23XveQN8dK8Z+lbEuxTLOgnQ9s/gzp/k7xx88IFvkdMuyoL2K7j1necQGYLmq3ifie9wDrF69AO/A==',
		'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExGbAq55XGXip3Dtq6jsM2bOYUeoYfDxsggXLisjwoCQoDM28pCYkIoZAfcjwR3aAGOAUWZX+L53og7/TLLpnfg=='
	)

	# Where the current keys.json and stable.json are: the branch channel,
	# since a published release takes no new files and these are signed
	# again while it is current (docs/protocol.md, section 16).
	$channelFiles = 'https://raw.githubusercontent.com/HunterEwok/cbb/channel'

	# The roots the release is checked against; none while CBB_VERIFY=skip.
	$roots = $releaseRoots
	if ($env:CBB_RELEASE_DIR -and $env:CBB_RELEASE_ROOTS) {
		# Each block without its headers (Name), the ES256 halves only.
		$roots = @(((Get-Content -Raw $env:CBB_RELEASE_ROOTS) -split '-----END PUBLIC KEY-----') |
			ForEach-Object { ($_ -replace '-----BEGIN PUBLIC KEY-----', '' -replace '(?m)^.*:.*$', '' -replace '\s', '') } |
			Where-Object { $_.StartsWith('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE') })
	}
	$verifying = $env:CBB_VERIFY -ne 'skip' -and $roots.Count -gt 0

	# Invoke-Quietly runs a program without its output and returns its exit
	# code. Windows PowerShell 5.1 turns a program's redirected stderr into
	# errors, which Stop would throw, so the preference is relaxed here only.
	function Invoke-Quietly($program, [string[]]$arguments) {
		$ErrorActionPreference = 'Continue'
		& $program @arguments *> $null
		return $LASTEXITCODE
	}

	# Get-ReleaseFile downloads a release file, or copies it from CBB_RELEASE_DIR.
	function Get-ReleaseFile($url, $path) {
		if ($env:CBB_RELEASE_DIR) {
			Copy-Item (Join-Path $env:CBB_RELEASE_DIR (Split-Path $url -Leaf)) $path
		} else {
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $path
		}
	}

	# A P-256 key from its SubjectPublicKeyInfo, for .NET Framework too.
	function Get-P256Key([byte[]]$spki) {
		$prefix = [Convert]::FromBase64String('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE')
		if ($spki.Length -ne 91 -or -not (Test-ByteEqual $spki[0..26] $prefix)) {
			throw (T 'a key is not P-256')
		}
		$p = New-Object Security.Cryptography.ECParameters
		$p.Curve = [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
		$q = New-Object Security.Cryptography.ECPoint
		$q.X = [byte[]]$spki[27..58]
		$q.Y = [byte[]]$spki[59..90]
		$p.Q = $q
		[Security.Cryptography.ECDsa]::Create($p)
	}

	function Test-ByteEqual([byte[]]$a, [byte[]]$b) {
		if ($a.Length -ne $b.Length) { return $false }
		for ($i = 0; $i -lt $a.Length; $i++) {
			if ($a[$i] -ne $b[$i]) { return $false }
		}
		$true
	}

	# A DER ECDSA signature as the 64 bytes r || s that .NET takes.
	function ConvertFrom-DerSignature([byte[]]$der) {
		$out = New-Object byte[] 64
		if ($der.Length -lt 8 -or $der[0] -ne 0x30 -or $der[1] -ne $der.Length - 2) { return $null }
		$i = 2
		foreach ($half in 0, 1) {
			if ($der[$i] -ne 0x02) { return $null }
			$n = $der[$i + 1]
			$v = [byte[]]$der[($i + 2)..($i + 1 + $n)]
			$i += 2 + $n
			while ($v.Length -gt 32 -and $v[0] -eq 0) { $v = [byte[]]$v[1..($v.Length - 1)] }
			if ($v.Length -gt 32) { return $null }
			[Array]::Copy($v, 0, $out, $half * 32 + 32 - $v.Length, $v.Length)
		}
		if ($i -ne $der.Length) { return $null }
		# Only the low S, at most half the order of P-256, the one form every
		# reader takes.
		$halfOrder = [Convert]::FromBase64String('f////4AAAAB//////////95zfVbTi89CedzlYX4xkqg=')
		for ($j = 0; $j -lt 32; $j++) {
			if ($out[32 + $j] -lt $halfOrder[$j]) { break }
			if ($out[32 + $j] -gt $halfOrder[$j]) { return $null }
		}
		$out
	}

	# Test-Alg tells whether a, read from JSON, is an algorithm number as
	# every reader takes it: a whole number 1 to 2^31-1.
	function Test-Alg($a) {
		($a -is [int] -or $a -is [long]) -and $a -ge 1 -and $a -le 2147483647
	}

	# Test-StrictBody tells whether text, a body, is in the strict form as far
	# as get.ps1 reads it (docs/protocol.md, "Signed bodies"): every member
	# name 1 to 64 of a-z, 0-9 and _, no null, no backslash (the signer writes
	# none in these files), and no field this script reads written twice, so
	# that ConvertFrom-Json, which matches names in any case and keeps one of
	# two, reads a body as the other programs do.
	function Test-StrictBody([string]$text) {
		if ($text.Contains('\')) { return $false }
		foreach ($m in [regex]::Matches($text, '"([^"]*)":')) {
			if ($m.Groups[1].Value -cnotmatch '^[a-z0-9_]{1,64}$') { return $false }
		}
		if ($text -match '[:,\[]null') { return $false }
		foreach ($n in 'v', 'type', 'seq', 'time_ms', 'expires_ms', 'keys', 'version', 'channel', 'release', 'release_sha256', 'files') {
			if ([regex]::Matches($text, '"' + $n + '":').Count -gt 1) { return $false }
		}
		$true
	}

	# Open-ReleaseFile checks the envelope at path with the ES256 keys (P-256
	# SubjectPublicKeyInfos) and returns its body, decoded, or throws. Each
	# file carries a signature of each algorithm (docs/protocol.md, section
	# 16, "Two signatures"): the ES256 one of a listed key must verify, and a
	# failed one refuses the file; the SLH-DSA one is passed over here, as a
	# signature of an algorithm a reader does not check.
	function Open-ReleaseFile($path, $type, $keys) {
		$name = Split-Path $path -Leaf
		# A release file is 1 MiB at most, its body 256 KiB, with 1 to 8
		# signatures, each of an algorithm 1 to 2^31-1, as every reader takes.
		if ((Get-Item $path).Length -gt 1048576) { throw (T '%s is not a valid release file; not installing' $name) }
		# The file whole, as the signer writes it and every reader takes it
		# (docs/protocol.md, section 16, "Two signatures"): whitespace around
		# it, then the envelope in its canonical form, with only body and
		# sigs, and in each signature only alg, key and sig, base64 in its one
		# form; any other shape refuses the file.
		# Its bytes as they came: Get-Content would drop a byte order mark.
		$raw = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($path)).Trim(" `t`r`n".ToCharArray())
		$b64 = '[A-Za-z0-9+/]*={0,2}'
		$one = "\{`"alg`":[1-9][0-9]*,`"key`":`"($b64)`",`"sig`":`"($b64)`"\}"
		if ($raw -cnotmatch "^\{`"body`":`"($b64)`",`"sigs`":\[$one(,$one)*\]\}\z") { throw (T '%s is not a valid release file; not installing' $name) }
		foreach ($m in [regex]::Matches($raw, "`"(body|key|sig)`":`"($b64)`"")) {
			$v = $m.Groups[2].Value
			try { $same = [Convert]::ToBase64String([Convert]::FromBase64String($v)) -ceq $v } catch { $same = $false }
			if (-not $same) { throw (T '%s is not a valid release file; not installing' $name) }
		}
		$f = $raw | ConvertFrom-Json
		$body = [Convert]::FromBase64String($f.body)
		$sigs = @($f.sigs)
		if ($body.Length -gt 262144 -or $sigs.Count -lt 1 -or $sigs.Count -gt 8 -or @($sigs | Where-Object { -not (Test-Alg $_.alg) }).Count -gt 0) {
			throw (T '%s is not a valid release file; not installing' $name)
		}
		$sha = [Security.Cryptography.SHA256]::Create()
		$ok = $false
		foreach ($s in @($sigs | Where-Object { $_.alg -eq 1 })) {
			$id = [Convert]::FromBase64String($s.key)
			$k = $keys | Where-Object { Test-ByteEqual $sha.ComputeHash([byte[]]$_) $id } | Select-Object -First 1
			if (-not $k) { continue }
			$der = [Convert]::FromBase64String($s.sig)
			# A signature longer than 16 KiB is passed over, as every reader does.
			if ($der.Length -gt 16384) { continue }
			$sig = ConvertFrom-DerSignature $der
			if (-not $sig -or -not (Get-P256Key $k).VerifyData($body, $sig, [Security.Cryptography.HashAlgorithmName]::SHA256)) {
				throw (T '%s is not signed by the project''s key; not installing' $name)
			}
			$ok = $true
		}
		if (-not $ok) { throw (T '%s is not signed by the project''s key; not installing' $name) }
		$text = [Text.Encoding]::UTF8.GetString($body)
		if (-not (Test-StrictBody $text)) { throw (T '%s is not a valid release file; not installing' $name) }
		$b = $text | ConvertFrom-Json
		if ($b.type -cne $type -or $b.v -ne 1 -or -not $b.PSObject.Properties['time_ms']) {
			throw (T '%s is not signed by the project''s key; not installing' $name)
		}
		@{ Bytes = $body; Value = $b }
	}

	# Test-Release checks keys.json against the root keys, release.json and,
	# for the latest release ($named), stable.json against its release or
	# channel keys, and the archive against release.json. CBB_VERIFY=skip
	# skips it.
	function Test-Release($base, $version, $named, $archive, $got, $tmp) {
		if ($env:CBB_VERIFY -eq 'skip') {
			Write-Host (T 'Not checked: the release''s signature (CBB_VERIFY=skip).')
			return
		}
		if (-not $verifying) { return }
		try {
			Get-ReleaseFile "$channelFiles/keys.json" (Join-Path $tmp 'keys.json')
			Get-ReleaseFile "$base/release.json" (Join-Path $tmp 'release.json')
		} catch {
			throw (T '%s has no signed release files; not installing it (CBB_VERIFY=skip installs it unchecked)' $version)
		}
		$nowMS = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
		$keys = Open-ReleaseFile -path (Join-Path $tmp 'keys.json') -type 'keys' -keys @($roots | ForEach-Object { , [Convert]::FromBase64String($_) })
		if ([long]$keys.Value.expires_ms -le $nowMS) { throw (T 'keys.json has expired; check the clock, or try again later') }
		# A release key (no use) signs release.json and stable.json, a channel
		# key only stable.json, a key of another use neither.
		# Under strict mode a key without use has no such property to read. A
		# use is never written empty.
		if (@($keys.Value.keys | Where-Object { $u = $_.PSObject.Properties['use']; $u -and $u.Value -ceq '' }).Count -gt 0) {
			throw (T 'keys.json holds a key whose use is empty; not installing')
		}
		if (@($keys.Value.keys | Where-Object { -not (Test-Alg $_.alg) }).Count -gt 0) {
			throw (T '%s is not a valid release file; not installing' 'keys.json')
		}
		# Every key is checked as the other readers check it, whatever its use:
		# a key of algorithm 1 is P-256 and one of 4 SLH-DSA-SHA2-128s; a key
		# of an algorithm no reader knows yet is kept unread.
		$slhPrefix = [Convert]::FromBase64String('MDAwCwYJYIZIAWUDBAMUAyEA')
		foreach ($k in @($keys.Value.keys)) {
			$spki = [Convert]::FromBase64String($k.key)
			if ($k.alg -eq 1) {
				$null = Get-P256Key $spki
			} elseif ($k.alg -eq 4 -and ($spki.Length -ne 50 -or -not (Test-ByteEqual $spki[0..17] $slhPrefix))) {
				throw (T '%s is not a valid release file; not installing' 'keys.json')
			}
		}
		# The ES256 halves; a half of another algorithm is not checked here.
		$es256 = @($keys.Value.keys | Where-Object { $_.alg -eq 1 })
		$releaseKeys = @($es256 | Where-Object { $u = $_.PSObject.Properties['use']; -not $u -or $u.Value -ceq 'release' } |
			ForEach-Object { , [Convert]::FromBase64String($_.key) })
		$channelKeys = @($es256 | Where-Object { $u = $_.PSObject.Properties['use']; $u -and $u.Value -ceq 'channel' } |
			ForEach-Object { , [Convert]::FromBase64String($_.key) })
		$rel = Open-ReleaseFile -path (Join-Path $tmp 'release.json') -type 'release' -keys $releaseKeys
		if ($named) {
			$ch = Open-ReleaseFile -path (Join-Path $tmp 'stable.json') -type 'channel' -keys ($releaseKeys + $channelKeys)
			if ($ch.Value.channel -cne 'stable') { throw (T 'stable.json is not the stable channel''s') }
			if ([long]$ch.Value.expires_ms -le $nowMS) { throw (T 'stable.json has expired; check the clock, or try again later') }
			$sum = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($rel.Bytes) | ForEach-Object { $_.ToString('x2') })
			# The release must be one for this channel, as cbb update checks.
			if ($ch.Value.release_sha256 -cne $sum -or $ch.Value.release -cne $rel.Value.version -or $rel.Value.channel -cne $ch.Value.channel) {
				throw (T 'release.json is not the release stable.json names; not installing')
			}
		} elseif ("v$($rel.Value.version)" -cne $version) {
			throw (T -Text 'release.json is for %s, not %s' ($rel.Value.version) $version)
		}
		$entry = $rel.Value.files | Where-Object { $_.name -ceq $archive } | Select-Object -First 1
		if (-not $entry) { throw (T 'release.json does not list %s' $archive) }
		if ($entry.sha256 -cne $got -or -not $entry.PSObject.Properties['size'] -or [long]$entry.size -ne (Get-Item (Join-Path $tmp $archive)).Length) {
			throw (T '%s does not match the signed release.json; not installing it' $archive)
		}
		# PowerShell has no SLH-DSA: the post-quantum signature waits for a
		# .NET that checks it, and the user is told so.
		Write-Host (T 'The release''s signature checks out (%s): ES256; SLH-DSA-SHA2-128s not checked, PowerShell cannot check it.' ($rel.Value.version))
	}

	try {
		$step = T 'checking for administrator rights'
		$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
		if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
			throw (T 'run it in a PowerShell opened with "Run as administrator"')
		}

		$step = T 'finding the architecture'
		# A 32-bit PowerShell on 64-bit Windows sees its own architecture; the
		# machine's is in PROCESSOR_ARCHITEW6432.
		$machine = $env:PROCESSOR_ARCHITEW6432
		if (-not $machine) {
			$machine = $env:PROCESSOR_ARCHITECTURE
		}
		switch ($machine) {
			'AMD64' { $arch = 'amd64' }
			'ARM64' { $arch = 'arm64' }
			default { throw (T 'no release for the architecture %s' $machine) }
		}

		$version = $env:CBB_VERSION
		if (-not $version) {
			$version = 'latest'
		}
		if ($version -eq 'latest') {
			$base = "$repo/releases/latest/download"
		} elseif ($version -match '^v\d') {
			$base = "$repo/releases/download/$version"
		} else {
			throw (T 'CBB_VERSION must look like v1.2.3')
		}
		$archive = "cbb-windows-$arch.zip"
		$tmp = Join-Path ([IO.Path]::GetTempPath()) ("cbb-" + [Guid]::NewGuid())
		New-Item -ItemType Directory -Path $tmp | Out-Null
		try {
			# The latest release is the one stable.json names, checked below,
			# rather than GitHub's latest: the two differ for a few minutes
			# after a release.
			$named = $null
			if ($version -eq 'latest' -and $verifying) {
				$step = T 'finding the latest release'
				Get-ReleaseFile "$channelFiles/stable.json" (Join-Path $tmp 'stable.json')
				$named = ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content -Raw (Join-Path $tmp 'stable.json') |
								ConvertFrom-Json).body)) | ConvertFrom-Json).release
				if ($named -notmatch '^\d+\.\d+\.\d+(-rc\.\d+)?$') { throw (T 'stable.json names no release') }
				$version = "v$named"
				if (-not $env:CBB_RELEASE_DIR) { $base = "$repo/releases/download/$version" }
			}
			$step = T -Text 'downloading %s (%s)' $archive $version
			Write-Host (T -Text 'Downloading %s (%s)...' $archive $version)
			foreach ($f in @($archive, 'SHA256SUMS')) {
				if ($env:CBB_RELEASE_DIR) {
					Copy-Item (Join-Path $env:CBB_RELEASE_DIR $f) (Join-Path $tmp $f)
				} else {
					[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
					Invoke-WebRequest -UseBasicParsing -Uri "$base/$f" -OutFile (Join-Path $tmp $f)
				}
			}

			$step = T 'checking %s against SHA256SUMS' $archive
			$want = $null
			foreach ($line in Get-Content (Join-Path $tmp 'SHA256SUMS')) {
				$fields = $line -split '\s+'
				if ($fields.Count -ge 2 -and ($fields[1] -eq $archive -or $fields[1] -eq "*$archive")) {
					$want = $fields[0].ToLowerInvariant()
				}
			}
			if (-not $want) {
				throw (T 'SHA256SUMS does not list %s' $archive)
			}
			$got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $archive)).Hash.ToLowerInvariant()
			if ($got -ne $want) {
				throw (T '%s does not match SHA256SUMS; not installing it' $archive)
			}

			# SHA256SUMS comes from the same release, so it shows only that
			# the download is whole. The signed release files show that the
			# project signed this release (docs/protocol.md, section 16).
			$step = T 'checking the release''s signature'
			Test-Release -base $base -version $version -named $named -archive $archive -got $got -tmp $tmp

			# The attestation shows that this repository's release workflow
			# built the archive.
			$step = T 'checking the build attestation of %s' $archive
			$attestation = if ($env:CBB_ATTESTATION) { $env:CBB_ATTESTATION } else { 'check' }
			$gh = Get-Command gh -ErrorAction SilentlyContinue
			$signedIn = $false
			if ($gh) {
				$signedIn = (Invoke-Quietly -program $gh.Source -arguments 'auth', 'status') -eq 0
			}
			if ($env:CBB_RELEASE_DIR -or $attestation -eq 'skip') {
			} elseif ($signedIn) {
				if ((Invoke-Quietly -program $gh.Source -arguments 'attestation', 'verify', (Join-Path $tmp $archive), '--repo', 'HunterEwok/cbb') -ne 0) {
					throw (T '%s does not have this repository''s build attestation; not installing it' $archive)
				}
				Write-Host (T 'The archive''s build attestation checks out.')
			} elseif ($attestation -eq 'require') {
				throw (T 'CBB_ATTESTATION=require needs gh, signed in (gh auth login), to check the build attestation')
			} else {
				Write-Host (T 'Not checked: the build attestation of the archive (it needs gh, signed in). SHA256SUMS matched.')
			}

			$step = T 'unpacking %s' $archive
			Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp

			$step = T 'running install.ps1'
			$arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $tmp 'cbb\packaging\windows\install.ps1'))
			if ($env:CBB_PORT) {
				$arguments += @('-Port', $env:CBB_PORT)
			}
			& powershell.exe @arguments
			if ($LASTEXITCODE -ne 0) {
				throw (T 'install.ps1 exited with %s' $LASTEXITCODE)
			}
		} finally {
			Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
		}
	} catch {
		Write-Host (T -Text 'get.ps1: %s failed: %s' $step ($_.Exception.Message)) -ForegroundColor Red
		if ($details) {
			$_ | Format-List * -Force | Out-String | Write-Host
			Write-Host $_.ScriptStackTrace
		} else {
			Write-Host (T 'For the full error: $env:CBB_ERROR_DETAILS = "1", and run it again.')
		}
	}
}
