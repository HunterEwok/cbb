// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/HunterEwok/cbb/internal/control"
)

// listenControl listens on the control socket. Windows checks a client's
// right to write the socket file when it connects, and the file takes its
// access list from its directory, so the directory gets a protected list
// first: full access for the system, administrators and the service's own
// account, read and write for the cbb group. Nobody else can
// connect, and the list is in place before the socket exists. The admin
// socket's directory lets in only the system, administrators and the
// service's account.
func listenControl(path string, admin bool) (net.Listener, error) {
	dir := filepath.Dir(path)
	mk := dir
	if admin {
		mk = filepath.Dir(dir) // ownDir makes dir itself, with its list
	}
	if err := os.MkdirAll(mk, 0o700); err != nil {
		return nil, err
	}
	sddl, err := controlSDDL(admin)
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("the access list of the control socket: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, fmt.Errorf("the access list of the control socket: %w", err)
	}
	const narrow = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	if admin {
		// The admin socket's directory sits in run\, where the group may
		// make directories: one that another user made first would stay
		// that user's, who could change its access list whatever the
		// service sets. It is made again unless the system, the
		// administrators or the service owns it, and narrowed through the
		// handle that was checked.
		h, err := ownDir(dir, sd)
		if err != nil {
			return nil, err
		}
		err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, narrow, nil, nil, dacl, nil)
		windows.CloseHandle(h)
		if err != nil {
			return nil, fmt.Errorf("narrowing %s: %w", dir, err)
		}
	} else if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, narrow, nil, nil, dacl, nil); err != nil {
		return nil, fmt.Errorf("narrowing %s: %w", dir, err)
	}
	// A socket left by a service that did not stop cleanly blocks the name;
	// anything else there, which a member of the group may have made in the
	// control socket's directory, is moved aside rather than entered.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket == 0 {
		if err := moveAside(path); err != nil {
			return nil, err
		}
	} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	return &controlListener{UnixListener: ul, path: path}, nil
}

// ownDir makes sure the directory dir is a directory, not a link, that
// belongs to the system, the administrators or the service's own account,
// and returns it open. Anything else at dir is moved aside, never entered
// or removed, so that nothing another user placed in it, such as a
// junction, leads the service elsewhere. A directory it makes has the
// access list of sd from the start, so nobody else can put anything in it
// before it is narrowed.
func ownDir(dir string, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for range 2 {
		h, ok, err := openOwnDir(dir)
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
			if err := windows.CreateDirectory(p, sa); err != nil {
				return 0, fmt.Errorf("making %s: %w", dir, err)
			}
			continue
		case err != nil:
			return 0, fmt.Errorf("the owner of %s: %w", dir, err)
		case ok:
			return h, nil
		}
		if err := moveAside(dir); err != nil {
			return 0, err
		}
		if err := windows.CreateDirectory(p, sa); err != nil {
			return 0, fmt.Errorf("making %s: %w", dir, err)
		}
	}
	h, ok, err := openOwnDir(dir)
	if err == nil && ok {
		return h, nil
	}
	return 0, fmt.Errorf("%s belongs to another user", dir)
}

// moveAside renames what is at path, without following or entering it,
// to a name beside it that nothing else uses.
func moveAside(path string) error {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	return os.Rename(path, fmt.Sprintf("%s.untrusted-%x", path, b))
}

// openOwnDir opens what is at path without following a link and reports
// whether it is a directory, not a reparse point, that the system, the
// administrators or the service's own account owns; only then it returns
// the handle, which may change the access list.
func openOwnDir(path string) (windows.Handle, bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, false, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, false, err
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		windows.CloseHandle(h)
		return 0, false, err
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return 0, false, nil
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		windows.CloseHandle(h)
		return 0, false, err
	}
	ok, err := trustedSID(sd)
	if err != nil || !ok {
		windows.CloseHandle(h)
		return 0, false, err
	}
	return h, true, nil
}

// trustedSID reports whether the system, the administrators or the
// service's own account is the owner in sd.
func trustedSID(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		owner.Equals(tu.User.Sid), nil
}

// controlSDDL describes the access list of the socket's directory, which
// its files inherit. A user's sign-in token lists only the groups the user
// was in at sign-in, so the list also names each member of the
// cbb group as the service finds it at start: a user that
// install.ps1 just added may connect before signing in again. Without the
// group, as when the service runs by hand on a machine where nothing was
// installed, only administrators and the service's account may connect.
func controlSDDL(admin bool) (string, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("the service's account: %w", err)
	}
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + tu.User.Sid.String() + ")"
	if admin {
		return sddl, nil
	}
	sid, _, typ, err := windows.LookupSID("", control.Group)
	if err != nil || typ != windows.SidTypeAlias {
		return sddl, nil
	}
	sddl += "(A;OICI;GRGW;;;" + sid.String() + ")"
	members, err := groupMembers(control.Group)
	if err != nil {
		return "", fmt.Errorf("the members of the %s group: %w", control.Group, err)
	}
	for _, m := range members {
		sddl += "(A;OICI;GRGW;;;" + m + ")"
	}
	return sddl, nil
}

var procNetLocalGroupGetMembers = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetLocalGroupGetMembers")

// groupMembers returns the SIDs of the members of a local group.
func groupMembers(name string) ([]string, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var buf *byte
	var read, total uint32
	r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(n)), 0,
		uintptr(unsafe.Pointer(&buf)), 0xFFFFFFFF, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), 0)
	if r != 0 {
		return nil, windows.Errno(r)
	}
	defer windows.NetApiBufferFree(buf)
	// LOCALGROUP_MEMBERS_INFO_0 holds only the member's SID.
	infos := unsafe.Slice((**windows.SID)(unsafe.Pointer(buf)), read)
	out := make([]string, 0, read)
	for _, sid := range infos {
		if sid != nil && sid.IsValid() {
			out = append(out, sid.String())
		}
	}
	return out, nil
}

// controlListener removes the socket when it is closed.
type controlListener struct {
	*net.UnixListener
	path string
	once sync.Once
}

func (l *controlListener) Close() error {
	err := l.UnixListener.Close()
	l.once.Do(func() { os.Remove(l.path) })
	return err
}
