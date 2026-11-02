// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID: the process ID at the
// other end of an AF_UNIX socket.
const sioAFUnixGetPeerPID = 0x58000100

// connPeer finds the process at the other end, then its user and session.
func connPeer(c net.Conn) peer {
	raw, ok := rawConn(c)
	if !ok {
		return peer{why: "not a socket"}
	}
	var pid uint32
	var err error
	raw.Control(func(fd uintptr) {
		var n uint32
		err = windows.WSAIoctl(windows.Handle(fd), sioAFUnixGetPeerPID, nil, 0, (*byte)(unsafe.Pointer(&pid)), 4, &n, nil, 0)
	})
	if err != nil || pid == 0 {
		return peer{why: fmt.Sprintf("its process: %v", err)}
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(pid, &session); err != nil {
		return peer{why: fmt.Sprintf("the session of process %d: %v", pid, err)}
	}
	sid, err := processSID(pid)
	if err != nil {
		return peer{why: fmt.Sprintf("the user of process %d: %v", pid, err)}
	}
	return peer{known: true, sid: sid, session: session}
}

// processSID returns the SID of the user a process runs as.
func processSID(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return tu.User.Sid.String(), nil
}

// privileged reports the system's account and the service's own.
func (p peer) privileged() bool {
	if p.sid == "S-1-5-18" {
		return true
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && p.sid == tu.User.Sid.String()
}

// atScreen allows a process in an active session: the one at the console,
// or one connected by Remote Desktop.
func atScreen(p peer, _ string) verdict {
	var info *windows.WTS_SESSION_INFO
	var n uint32
	if windows.WTSEnumerateSessions(0, 0, 1, &info, &n) != nil {
		return refused
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	for _, si := range unsafe.Slice(info, n) {
		if si.SessionID == p.session && si.State == windows.WTSActive {
			return allowed
		}
	}
	return refused
}
