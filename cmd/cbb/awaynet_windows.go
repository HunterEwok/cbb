// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"slices"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const needRootText = "on this computer the system limits what the service may reach, and only an administrator can change that: run the command again in a terminal opened as administrator"

// allowHint is the command that lets the service reach the group's servers.
const allowHint = "run cbb global allow in a terminal opened as administrator"

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// homeCGNAT reports whether the service counts 100.64.0.0/10 as the home
// network, as install.ps1 -HomeCgnat on keeps in its environment, so that
// the rule leaves that range to it too.
var homeCGNAT = func() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\cbb`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	env, _, err := k.GetStringsValue("Environment")
	return err == nil && slices.Contains(env, "CBB_HOME_CGNAT=1")
}

// adminName is who may change the firewall.
const adminName = "an administrator"

// closeHint closes the hub's port that cbb opened.
const closeHint = "run Remove-NetFirewallRule -Name cbb-hub in a PowerShell opened as administrator"

// expressHint is how the installer adds the firewall rules without asking.
const expressHint = "-Express"
