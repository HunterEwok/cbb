// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// letServiceQuery lets the service's account look up this agent's session
// and user: it may query the process, and the process's token, whose access
// list is its own. The service runs as NT SERVICE\clipboardbridge, which may not
// open another user's process; without this it names the agent's user
// nobody, and gives it no remote pastes and no quick actions.
func letServiceQuery() error {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+serviceName)
	if err != nil {
		return fmt.Errorf("the service's account: %w", err)
	}
	if err := grantAccess(windows.CurrentProcess(), sid, windows.PROCESS_QUERY_LIMITED_INFORMATION); err != nil {
		return fmt.Errorf("this process's access list: %w", err)
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.READ_CONTROL|windows.WRITE_DAC, &tok); err != nil {
		return fmt.Errorf("this process's token: %w", err)
	}
	defer tok.Close()
	if err := grantAccess(windows.Handle(tok), sid, windows.TOKEN_QUERY); err != nil {
		return fmt.Errorf("the token's access list: %w", err)
	}
	return nil
}

// grantAccess adds an entry that lets sid have access to the kernel object h.
func grantAccess(h windows.Handle, sid *windows.SID, access windows.ACCESS_MASK) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, old)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
