// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package actions

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the agent runs the presets as the signed-in user, who holds
// the right to shut down; the service's virtual account does not (design.md,
// "Quick actions"). Windows itself keeps the minute before a reboot or
// shutdown and warns the users signed in.

// Session returns the runner of the presets in this session.
func Session() Runner { return win{} }

type win struct{}

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	powrprof          = windows.NewLazySystemDLL("powrprof.dll")
	advapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procLock          = user32.NewProc("LockWorkStation")
	procSuspend       = powrprof.NewProc("SetSuspendState")
	procAbortShutdown = advapi32.NewProc("AbortSystemShutdownW")
)

// The reason the event log records: planned, other.
const shutdownReason = 0x80000000

// errNoShutdown is ERROR_NO_SHUTDOWN: no shutdown was pending.
const errNoShutdown = syscall.Errno(1116)

func (win) Run(ctx context.Context, name string) error {
	switch name {
	case Lock:
		return call(procLock)
	case Sleep:
		if err := shutdownRight(); err != nil {
			return err
		}
		return call(procSuspend, 0, 0, 0)
	case Reboot, Shutdown:
		if err := shutdownRight(); err != nil {
			return err
		}
		msg, _ := windows.UTF16PtrFromString("CBB: an admin of your group asked for this.")
		return windows.InitiateSystemShutdownEx(nil, msg, uint32(ScheduleDelay.Seconds()), false, name == Reboot, shutdownReason)
	case Cancel:
		if err := shutdownRight(); err != nil {
			return err
		}
		if err := call(procAbortShutdown, 0); errors.Is(err, errNoShutdown) {
			return &Refusal{Reason: "no reboot or shutdown is pending here"}
		} else if err != nil {
			return err
		}
		return nil
	}
	return &Refusal{Reason: fmt.Sprintf("this device has no action %q", name)}
}

// call calls a function that returns a BOOL.
func call(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return err
	}
	r, _, err := p.Call(args...)
	if r == 0 {
		return err
	}
	return nil
}

// shutdownRight enables SeShutdownPrivilege in this process's token: the
// user holds it, disabled until a program asks for it.
func shutdownRight() error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeShutdownPrivilege"), &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil); err != nil {
		return err
	}
	if windows.GetLastError() == windows.ERROR_NOT_ALL_ASSIGNED {
		return &Refusal{Reason: "the user signed in here may not shut this PC down"}
	}
	return nil
}
