# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.ps1 installed, in an administrator PowerShell, or
# from Settings, Apps, CBB, Uninstall:
#
#   powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1" [-Purge]
#
# It stops and deletes the service, stops the agents, and removes the
# files in Program Files, the PATH entry, the sign-in entries, the Start menu
# shortcut of the tray app, the uninstaller
# entry, the update task with cbb update's folder and the firewall rules that
# install.ps1 added, and only those. The
# device's keys and group membership, in ProgramData\cbb, stay
# for a reinstall unless -Purge, which also deletes the cbb
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

# The messages in the user's language (l10n.ps1, beside this file where
# install.ps1 put it, with its catalogs, or in the archive).
$catalogs = Join-Path $PSScriptRoot 'l10n'
if (-not (Test-Path $catalogs)) {
	$catalogs = Join-Path $PSScriptRoot '..\l10n'
}
. (Join-Path $PSScriptRoot 'l10n.ps1') $catalogs

$name = 'cbb'
$programDir = Join-Path $env:ProgramFiles $name
$dataDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) $name
$details = $Details -or $env:CBB_ERROR_DETAILS -eq '1'
$step = T 'starting'

trap {
	Write-Host (T 'uninstall.ps1: %s failed: %s' $step ($_.Exception.Message)) -ForegroundColor Red
	if ($details) {
		$_ | Format-List * -Force | Out-String | Write-Host
		Write-Host $_.ScriptStackTrace
	} else {
		Write-Host (T 'Run it again with -Details for the full error.')
	}
	exit 1
}

$step = T 'checking for administrator rights'
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

$step = T 'deleting the service'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
	Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
	& sc.exe delete $name | Out-Null
}

$step = T 'stopping the agents and the tray app'
Get-Process -Name cbbw, cbb, cbb-desktop, cbb-helper -ErrorAction SilentlyContinue | Where-Object {
	$_.Path -and $_.Path.StartsWith("$programDir\", [StringComparison]::OrdinalIgnoreCase)
} | Stop-Process -Force
Start-Sleep -Milliseconds 500

$step = T 'removing the update task and cbb update''s folder'
if (Get-ScheduledTask -TaskName 'cbb update' -ErrorAction SilentlyContinue) {
	Unregister-ScheduledTask -TaskName 'cbb update' -Confirm:$false -ErrorAction SilentlyContinue
}
Remove-Item -Recurse -Force (Join-Path $env:ProgramFiles 'cbb-update') -ErrorAction SilentlyContinue

$step = T 'removing the firewall rules'
Get-NetFirewallRule -Group $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule

$step = T 'removing the sign-in entries, the Start menu shortcut and the uninstaller entry'
foreach ($run in @($name, "$name tray")) {
	Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $run -ErrorAction SilentlyContinue
}
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'CBB.lnk') -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$name" -ErrorAction SilentlyContinue

$step = T 'removing cbb from PATH'
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$kept = ($path -split ';') | Where-Object { $_ -and $_ -ne $programDir }
[Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')

$step = T 'removing %s' $programDir
Remove-Item -Recurse -Force $programDir -ErrorAction SilentlyContinue

if ($Purge) {
	$step = T 'removing %s and the %s group' $dataDir $name
	Remove-Item -Recurse -Force $dataDir -ErrorAction SilentlyContinue
	# With errors allowed: Windows PowerShell 5.1 stops on a program's error output.
	& { $ErrorActionPreference = 'Continue'; & net.exe localgroup $name /delete 2>&1 | Out-Null }
	Write-Host (T 'CBB is removed, with this device''s keys; it left its group.')
} else {
	Remove-Item -Recurse -Force (Join-Path $dataDir 'run') -ErrorAction SilentlyContinue
	Write-Host (T 'CBB is removed. Its keys stay in %s for a reinstall; -Purge removes them.' $dataDir)
}
