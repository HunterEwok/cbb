# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.ps1 installed, in an administrator PowerShell, or
# from Settings, Apps, Clipboard Bridge, Uninstall:
#
#   powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\clipboardbridge\uninstall.ps1" [-Purge]
#
# It stops and deletes the service, stops the agents, and removes the
# files in Program Files, the PATH entry, the sign-in entries, the Start menu
# shortcut of the tray app, the uninstaller
# entry, the update task with cbb update's folder and the firewall rules that
# install.ps1 added, and only those. The
# device's keys and group membership, in ProgramData\clipboardbridge, stay
# for a reinstall unless -Purge, which also deletes the clipboardbridge
# group. -Details (or CBB_ERROR_DETAILS=1) shows the full error of a
# failure.
[CmdletBinding()]
param(
	[switch]$Purge,
	[switch]$Details
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$name = 'clipboardbridge'
$programDir = Join-Path $env:ProgramFiles $name
$dataDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) $name
$details = $Details -or $env:CBB_ERROR_DETAILS -eq '1'
$step = 'starting'

trap {
	Write-Host "uninstall.ps1: $step failed: $($_.Exception.Message)" -ForegroundColor Red
	if ($details) {
		$_ | Format-List * -Force | Out-String | Write-Host
		Write-Host $_.ScriptStackTrace
	} else {
		Write-Host 'Run it again with -Details for the full error.'
	}
	exit 1
}

$step = 'checking for administrator rights'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	# Settings starts the uninstaller without elevation: ask for it.
	$arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
	if ($Purge) {
		$arguments += '-Purge'
	}
	if ($Details) {
		$arguments += '-Details'
	}
	Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
	exit 0
}

$step = 'deleting the service'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
	Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
	& sc.exe delete $name | Out-Null
}

$step = 'stopping the agents and the tray app'
Get-Process -Name cbbw, cbb, cbb-desktop -ErrorAction SilentlyContinue | Where-Object {
	$_.Path -and $_.Path.StartsWith("$programDir\", [StringComparison]::OrdinalIgnoreCase)
} | Stop-Process -Force
Start-Sleep -Milliseconds 500

$step = 'removing the update task and cbb update''s folder'
if (Get-ScheduledTask -TaskName 'clipboardbridge update' -ErrorAction SilentlyContinue) {
	Unregister-ScheduledTask -TaskName 'clipboardbridge update' -Confirm:$false -ErrorAction SilentlyContinue
}
Remove-Item -Recurse -Force (Join-Path $env:ProgramFiles 'clipboardbridge-update') -ErrorAction SilentlyContinue

$step = 'removing the firewall rules'
Get-NetFirewallRule -Group $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule

$step = 'removing the sign-in entries, the Start menu shortcut and the uninstaller entry'
foreach ($run in @($name, "$name tray")) {
	Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $run -ErrorAction SilentlyContinue
}
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Clipboard Bridge.lnk') -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$name" -ErrorAction SilentlyContinue

$step = 'removing clipboardbridge from PATH'
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$kept = ($path -split ';') | Where-Object { $_ -and $_ -ne $programDir }
[Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')

$step = "removing $programDir"
Remove-Item -Recurse -Force $programDir -ErrorAction SilentlyContinue

if ($Purge) {
	$step = "removing $dataDir and the $name group"
	Remove-Item -Recurse -Force $dataDir -ErrorAction SilentlyContinue
	# With errors allowed: Windows PowerShell 5.1 stops on a program's error output.
	& { $ErrorActionPreference = 'Continue'; & net.exe localgroup $name /delete 2>&1 | Out-Null }
	Write-Host "Clipboard Bridge is removed, with this device's keys; it left its group."
} else {
	Remove-Item -Recurse -Force (Join-Path $dataDir 'run') -ErrorAction SilentlyContinue
	Write-Host "Clipboard Bridge is removed. Its keys stay in $dataDir for a reinstall; -Purge removes them."
}
