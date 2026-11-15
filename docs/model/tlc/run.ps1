# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# One lane of the exhaustive check of the records rules (RecordsCore.tla) with TLC. Every lane
# takes the next start not yet taken from the shared queue file (one "<set>/<start>" per line,
# heaviest first), so no lane sits idle while another still has work. Each start appends one
# line to the summary: set | start | verdict | TLC's result | distinct states | seconds, where
# the verdict compares the result with models\expected.txt (OK or UNEXPECTED).
#
# Usage: powershell -ExecutionPolicy Bypass -File run.ps1 -Queue <queue.txt> -Java <java.exe> `
#          -Jar <tla2tools.jar> -Work <folder for temporaries> -Summary <file> -Workers 8 -Heap 16g
param(
  [Parameter(Mandatory = $true)][string]$Queue,
  [Parameter(Mandatory = $true)][string]$Java,
  [Parameter(Mandatory = $true)][string]$Jar,
  [Parameter(Mandatory = $true)][string]$Work,
  [Parameter(Mandatory = $true)][string]$Summary,
  [int]$Workers = 8,
  [string]$Heap = "16g"
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$expected = @{}
foreach ($l in Get-Content (Join-Path $here "models\expected.txt")) {
  if ($l -match '^\s*(#|$)') { continue }
  $p = $l -split '\s+'
  $expected[$p[0]] = $p[1]
}
# Claims sit beside the queue, shared by all lanes (each lane has its own -Work).
$claims = Join-Path (Split-Path -Parent (Resolve-Path $Queue).Path) "claims"
New-Item -ItemType Directory -Force -Path $claims | Out-Null
foreach ($item in (Get-Content $Queue | Where-Object { $_ -match '\S' })) {
  # Taking a start is creating its claim file; New-Item fails if another lane made it first.
  $claim = Join-Path $claims (($item -replace '[\\/]', '_') + ".claim")
  try { New-Item -ItemType File -Path $claim -ErrorAction Stop | Out-Null } catch { continue }
  $set, $m = $item -split '/'
  $dir = Join-Path $here "models\$set"
  $tmp = Join-Path $Work "$set-$m"
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  # Every start extends RecordsCore, which TLC looks for beside it; copied once per set, since
  # another lane's TLC may be reading the copy already there.
  $core = Join-Path $dir "RecordsCore.tla"
  if (-not (Test-Path $core)) { Copy-Item (Join-Path $here "RecordsCore.tla") $core }
  $free = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB
  if ($free -lt 6) {
    "$set | $m | UNEXPECTED | skipped: only $([math]::Round($free,1)) GB free | | " | Add-Content $Summary
    Remove-Item $claim
    continue
  }
  $log = Join-Path $dir "$m.log"
  $t0 = Get-Date
  Push-Location $dir
  & $Java "-Xss64m" "-XX:+UseParallelGC" "-Xmx$Heap" "-Djava.io.tmpdir=$tmp" -cp $Jar tlc2.TLC `
      -workers $Workers -metadir (Join-Path $tmp "states") -config "$m.cfg" "$m.tla" *> $log
  Pop-Location
  $secs = [int]((Get-Date) - $t0).TotalSeconds
  $res = Select-String -Path $log -Pattern "No error has been found|is violated|Exception|rror" | Select-Object -First 1
  $st = Select-String -Path $log -Pattern "distinct states found" | Select-Object -Last 1
  # The parts that broke: printed as <<"VIOLATED", name, ...>>, or the invariant TLC names.
  $broke = @(Select-String -Path $log -Pattern '"VIOLATED", "([^"]+)"' -AllMatches |
             ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value }) | Sort-Object -Unique
  if ($res -and $res.Line -match 'Invariant (\S+) is violated' -and $broke.Count -eq 0) { $broke = @($Matches[1]) }
  $want = $expected["$set/$m"]
  $clean = $res -and $res.Line -match 'No error has been found'
  $ok = if ($want) { (-not $clean) -and $res -and ($want -eq '*' -or $broke -contains $want) } else { $clean }
  $verdict = if ($ok) { "OK" } else { "UNEXPECTED" }
  $what = if ($broke.Count) { " [" + ($broke -join ",") + "]" } else { "" }
  "$set | $m | $verdict | $($res.Line)$what | $($st.Line) | $secs s" | Add-Content $Summary
  Remove-Item -Recurse -Force (Join-Path $tmp "states") -ErrorAction SilentlyContinue
}
"lane done $(Get-Date -Format o)" | Add-Content $Summary
