# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Prepares a Windows device for the test bench (docs/maintainers/testbench.md). Run it
# once, in an elevated PowerShell, while signed in as the user the bench
# connects as:
#
#   powershell -ExecutionPolicy Bypass -File setup-windows.ps1
#
# It turns on the OpenSSH server and registers scheduled tasks that run in
# this user's desktop session, where the clipboard is: cbbbench-copy puts
# C:\ProgramData\cbbbench\in.txt on the clipboard, cbbbench-paste writes the
# clipboard to out.txt, and cbbbench-run runs run.ps1 and writes what it
# printed to run.out. An SSH session cannot reach the desktop clipboard
# itself. Only this user, administrators and the system may write to the
# folder, since its scripts run as this user. The controller's public key goes into
# C:\ProgramData\ssh\administrators_authorized_keys (for an administrator) or
# ~\.ssh\authorized_keys by hand.
#
# Run it again to update; -Remove takes the tasks and the folder away.
param([switch]$Remove)
$ErrorActionPreference = 'Stop'

$dir = 'C:\ProgramData\cbbbench'
$tasks = 'cbbbench-copy', 'cbbbench-paste', 'cbbbench-run'

if ($Remove) {
	foreach ($t in $tasks) { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue }
	Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
	Write-Output 'The bench tasks are removed. The OpenSSH server stays.'
	exit 0
}

if ((Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0').State -ne 'Installed') {
	Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
}
Set-Service sshd -StartupType Automatic
Start-Service sshd

New-Item -ItemType Directory -Force $dir | Out-Null
# The tasks run with the user's plain token and must delete in.txt, which the
# bench writes from an elevated SSH session; by SID, as names of groups and
# users differ between languages of Windows. No other user may write here.
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*${sid}:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE) { throw "icacls could not give $sid access to $dir" }
Set-Content -Encoding UTF8 "$dir\copy.ps1" @'
$f = 'C:\ProgramData\cbbbench\in.txt'
if (Test-Path $f) {
	Set-Clipboard -Value ([IO.File]::ReadAllText($f, [Text.Encoding]::UTF8))
	Remove-Item $f
}
'@
Set-Content -Encoding UTF8 "$dir\paste.ps1" @'
$t = Get-Clipboard -Raw
if ($null -eq $t) { $t = '' }
$tmp = 'C:\ProgramData\cbbbench\out.tmp'
[IO.File]::WriteAllText($tmp, $t, (New-Object Text.UTF8Encoding $false))
Move-Item -Force $tmp 'C:\ProgramData\cbbbench\out.txt'
'@
Set-Content -Encoding UTF8 "$dir\run-task.ps1" @'
$ErrorActionPreference = 'Stop'
$d = 'C:\ProgramData\cbbbench'
if (Test-Path "$d\run.ps1") {
	try {
		$o = & "$d\run.ps1" *>&1 | Out-String
	} catch {
		$o = 'cbbbench-run failed: ' + ($_ | Out-String)
	}
	Remove-Item "$d\run.ps1"
	[IO.File]::WriteAllText("$d\run.tmp", $o, (New-Object Text.UTF8Encoding $false))
	Move-Item -Force "$d\run.tmp" "$d\run.out"
}
'@

$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive
foreach ($name in 'copy', 'paste', 'run') {
	$file = "$name.ps1"
	if ($name -eq 'run') { $file = 'run-task.ps1' }
	$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $dir\$file"
	Register-ScheduledTask -TaskName "cbbbench-$name" -Action $action -Principal $principal -Force | Out-Null
}
Write-Output "Ready: OpenSSH server on, tasks for $user. Stay signed in: the tasks run in this session."
