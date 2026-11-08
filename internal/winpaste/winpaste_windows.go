// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package winpaste

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/HunterEwok/cbb/internal/connector"
)

var (
	user32 = windows.NewLazySystemDLL("user32.dll")

	procSendInput                 = user32.NewProc("SendInput")
	procOpenInputDesktop          = user32.NewProc("OpenInputDesktop")
	procCloseDesktop              = user32.NewProc("CloseDesktop")
	procGetUserObjectInformationW = user32.NewProc("GetUserObjectInformationW")
)

const (
	inputKeyboard = 1      // INPUT_KEYBOARD
	uoiName       = 2      // UOI_NAME
	desktopRead   = 0x0001 // DESKTOP_READOBJECTS

	// keyPause lets the window with the focus take a batch of keys before
	// the next.
	keyPause = 3 * time.Millisecond
	// batch is how many keys go in one SendInput call.
	batch = 64
)

// keybdInput is KEYBDINPUT.
type keybdInput struct {
	vk, scan    uint16
	flags, time uint32
	extra       uintptr
}

// input is INPUT with a keyboard event; the padding makes it the size of
// the union's largest member, MOUSEINPUT.
type input struct {
	typ uint32
	ki  keybdInput
	_   [8]byte
}

// Target pastes into the window with the focus in the agent's session.
type Target struct {
	b  connector.PasteBoard
	mu sync.Mutex // one paste at a time
}

// New returns the target that pastes through the clipboard b.
func New(b connector.PasteBoard) *Target { return &Target{b: b} }

// Target names the target (connector.Target).
func (t *Target) Target() string { return "desktop" }

// Inject puts text into the window with the focus (connector.Target).
func (t *Target) Inject(ctx context.Context, text, method string, enter, secret bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if method != "paste" && method != "type" {
		return &connector.Refusal{Reason: fmt.Sprintf("this desktop pastes or types, not %q", method)}
	}
	if why := blocked(); why != "" {
		return &connector.Refusal{Reason: why}
	}
	var err error
	if method == "paste" {
		err = connector.PasteThrough(t.b, text, secret, func() error { return send(ctx, pasteKeys()) })
	} else {
		err = send(ctx, typeKeys(text))
	}
	if err == nil && enter {
		err = send(ctx, enterKeys())
	}
	return err
}

// InjectMedia pastes images or files into the window with the focus
// (connector.MediaTarget): write puts them into the clipboard, then
// Ctrl+V.
func (t *Target) InjectMedia(ctx context.Context, write func() error, enter bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if why := blocked(); why != "" {
		return &connector.Refusal{Reason: why}
	}
	if err := write(); err != nil {
		return err
	}
	err := send(ctx, pasteKeys())
	if err == nil && enter {
		err = send(ctx, enterKeys())
	}
	return err
}

// blocked says why keys cannot go to the window with the focus now, or "".
func blocked() string {
	if name, err := inputDesktop(); err != nil || !strings.EqualFold(name, "Default") {
		// The secure desktop: UAC's prompt, the lock screen, the sign-in
		// screen. A process in the session cannot open it.
		return "the secure desktop shows (the lock screen or an administrator prompt)"
	}
	hwnd := windows.GetForegroundWindow()
	if hwnd == 0 {
		return "no window has the focus"
	}
	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err != nil || pid == 0 {
		return "no window has the focus"
	}
	mine, err := integrity(windows.CurrentProcess())
	if err != nil {
		return ""
	}
	theirs, err := processIntegrity(pid)
	if err != nil || theirs > mine {
		return "the window with the focus runs as administrator, and Windows drops keys sent to it"
	}
	return ""
}

// inputDesktop returns the name of the desktop that takes input.
func inputDesktop() (string, error) {
	h, _, err := procOpenInputDesktop.Call(0, 0, desktopRead)
	if h == 0 {
		return "", fmt.Errorf("OpenInputDesktop: %w", err)
	}
	defer procCloseDesktop.Call(h)
	var name [256]uint16
	var n uint32
	ok, _, err := procGetUserObjectInformationW.Call(h, uoiName, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&n)))
	if ok == 0 {
		return "", fmt.Errorf("GetUserObjectInformation: %w", err)
	}
	return windows.UTF16ToString(name[:]), nil
}

func processIntegrity(pid uint32) (uint32, error) {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(p)
	return integrity(p)
}

// integrity returns the integrity level of a process: the RID of its
// token's mandatory label (0x2000 medium, 0x3000 high).
func integrity(p windows.Handle) (uint32, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return 0, err
	}
	defer tok.Close()
	var n uint32
	windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return 0, errors.New("the token has no integrity level")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return 0, err
	}
	// The label's SID lies in buf after the TOKEN_MANDATORY_LABEL. It is
	// read from buf by its offset: SID's accessors in x/sys return
	// pointers that Windows computed, which checkptr (on with -race)
	// rejects inside a Go allocation.
	sid := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid
	return lastSubAuthority(buf, int(uintptr(unsafe.Pointer(sid))-uintptr(unsafe.Pointer(&buf[0]))))
}

// lastSubAuthority returns the last sub-authority of the SID at off in
// buf: a revision byte, the count of sub-authorities, six bytes of
// identifier authority, then the sub-authorities, little-endian uint32s.
func lastSubAuthority(buf []byte, off int) (uint32, error) {
	if off < 0 || off+8 > len(buf) {
		return 0, errors.New("the integrity label lies outside the token's answer")
	}
	c := int(buf[off+1])
	if c == 0 {
		return 0, errors.New("the integrity label has no level")
	}
	end := off + 8 + 4*c
	if end > len(buf) {
		return 0, errors.New("the integrity label lies outside the token's answer")
	}
	return binary.LittleEndian.Uint32(buf[end-4:]), nil
}

// send presses the keys in batches; it stops early when ctx ends.
func send(ctx context.Context, ks []key) error {
	for len(ks) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(ks), batch)
		in := make([]input, n)
		for i, k := range ks[:n] {
			in[i] = input{typ: inputKeyboard, ki: keybdInput{vk: k.vk, scan: k.scan, flags: k.flags}}
		}
		sent, _, err := procSendInput.Call(uintptr(n), uintptr(unsafe.Pointer(&in[0])), unsafe.Sizeof(in[0]))
		if int(sent) != n {
			return fmt.Errorf("pressing keys: the system took %d of %d: %v", sent, n, err)
		}
		ks = ks[n:]
		time.Sleep(keyPause)
	}
	return nil
}
