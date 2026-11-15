# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# One lane of the exhaustive check of the records rules (RecordsCore.tla) with TLC:
# runs every start (P_*.cfg) of the given sets, one after another, and appends one
# line per start to the summary file. The calibration starts g30/P_g30GTSF and
# s31/P_s31SF switch the seen line off and are expected to break; every other start
# is expected to find no error.
#
# Usage: powershell -ExecutionPolicy Bypass -File run.ps1 -Sets k3-w,w29 -Java <java.exe> `
#          -Jar <tla2tools.jar> -Work <folder for temporaries> -Summary <file> -Workers 12 -Heap 20g
param(
  [Parameter(Mandatory = $true)][string[]]$Sets,
  [Parameter(Mandatory = $true)][string]$Java,
  [Parameter(Mandatory = $true)][string]$Jar,
  [Parameter(Mandatory = $true)][string]$Work,
  [Parameter(Mandatory = $true)][string]$Summary,
  [int]$Workers = 12,
  [string]$Heap = "20g"
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
# A lane started with -File gets "a,b" as one string: split it here.
foreach ($set in ($Sets | ForEach-Object { $_ -split "," } | Where-Object { $_ })) {
  $dir = Join-Path $here "models\$set"
  $tmp = Join-Path $Work $set
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  $env:TMP = $tmp; $env:TEMP = $tmp
  # Every start extends RecordsCore, which TLC looks for beside it.
  Copy-Item (Join-Path $here "RecordsCore.tla") $dir -Force
  Set-Location $dir
  foreach ($m in (Get-ChildItem $dir -Filter "P_*.cfg" | ForEach-Object { $_.BaseName })) {
    $free = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB
    if ($free -lt 6) { "$set | $m | skipped: only $([math]::Round($free,1)) GB free" | Add-Content $Summary; continue }
    $meta = Join-Path $tmp "states-$m"
    $t0 = Get-Date
    & $Java "-Xss64m" "-XX:+UseParallelGC" "-Xmx$Heap" "-Djava.io.tmpdir=$tmp" -cp $Jar tlc2.TLC `
        -workers $Workers -metadir $meta -config "$m.cfg" "$m.tla" *> "$m.log"
    $secs = [int]((Get-Date) - $t0).TotalSeconds
    $res = Select-String -Path "$m.log" -Pattern "No error has been found|is violated|Exception|rror" | Select-Object -First 1
    $st = Select-String -Path "$m.log" -Pattern "distinct states found" | Select-Object -Last 1
    "$set | $m | $($res.Line) | $($st.Line) | $secs s" | Add-Content $Summary
    Remove-Item -Recurse -Force $meta -ErrorAction SilentlyContinue
  }
  "$set | SET DONE" | Add-Content $Summary
}
