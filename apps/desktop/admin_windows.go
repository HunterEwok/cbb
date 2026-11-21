// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const deniedText = "No permission to use the service: add your user to the cbb group and sign in again."

// userConfirms: the service confirms admin actions on Windows with Windows
// Hello; cbb registers the user's key once through the UAC prompt.
const userConfirms = true

// hideWindow keeps cbb's console from showing.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// runAdmin runs cbb as the administrator through the UAC prompt: an
// elevated PowerShell, started with ShellExecuteEx's runas, calls cbb with
// each argument as a literal and writes what it printed to a file the app
// reads after. input, unless empty, is cbb's standard input, from a file in
// the user's temporary folder: never on the command line, which other
// programs may read.
func runAdmin(args []string, input string, details bool) error {
	out, err := os.CreateTemp("", "cbb-desktop-*.txt")
	if err != nil {
		return err
	}
	outPath := out.Name()
	out.Close()
	defer os.Remove(outPath)
	inPath := ""
	if input != "" {
		in, err := os.CreateTemp("", "cbb-desktop-in-*.txt")
		if err != nil {
			return err
		}
		inPath = in.Name()
		defer os.Remove(inPath)
		_, err = in.WriteString(input)
		if cerr := in.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}

	script := psScript(cbbPath(), args, inPath, details, outPath)
	ps, err := powershellPath()
	if err != nil {
		return &adminError{msg: "Windows did not start cbb as the administrator.", detail: err.Error()}
	}
	code, err := elevate(ps, "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand "+encodePS(script))
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return errCancelled
	}
	if err != nil {
		return &adminError{msg: "Windows did not start cbb as the administrator.", detail: err.Error()}
	}
	if code == 0 {
		return nil
	}
	printed, _ := os.ReadFile(outPath)
	return cbbFailed(string(printed), fmt.Sprintf("cbb exited with %d", code))
}

// psScript is the PowerShell that runs cbb: every argument a single-quoted
// literal, so no name can run anything; with inPath, that file is its
// standard input.
func psScript(cbb string, args []string, inPath string, details bool, outPath string) string {
	var b strings.Builder
	if details {
		b.WriteString("$env:CBB_DEBUG = '1'\n")
	}
	if inPath != "" {
		b.WriteString("Get-Content -Raw -LiteralPath " + psQuote(inPath) + " | ")
	}
	b.WriteString("& " + psQuote(cbb))
	for _, a := range args {
		b.WriteString(" " + psQuote(a))
	}
	b.WriteString(" *> " + psQuote(outPath) + "\nexit $LASTEXITCODE\n")
	return b.String()
}

func psQuote(s string) string {
	// PowerShell ends a single-quoted string at any of its single quotes,
	// the typographic ones too, and takes each doubled as one.
	for _, q := range []string{"'", "\u2018", "\u2019", "\u201a", "\u201b"} {
		s = strings.ReplaceAll(s, q, q+q)
	}
	return "'" + s + "'"
}

// encodePS is PowerShell's -EncodedCommand: base64 of UTF-16LE.
func encodePS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// cbbPath is where install.ps1 puts cbb.exe. Program Files comes from the
// system, not from the environment, which the user sets: the elevated run
// must start the installed cbb.
func cbbPath() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		dir = `C:\Program Files`
	}
	return filepath.Join(dir, "cbb", "cbb.exe")
}

var (
	shell32             = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

// shellExecuteInfo is SHELLEXECUTEINFOW.
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         windows.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     windows.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hIcon        windows.Handle
	hProcess     windows.Handle
}

const seeMaskNoCloseProcess = 0x40

// elevate starts a program as the administrator, waits for it and returns
// its exit code; ERROR_CANCELLED when the user declined the prompt.
func elevate(file, params string) (uint32, error) {
	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       windows.StringToUTF16Ptr("runas"),
		lpFile:       windows.StringToUTF16Ptr(file),
		lpParameters: windows.StringToUTF16Ptr(params),
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return 0, err
	}
	defer windows.CloseHandle(info.hProcess)
	if _, err := windows.WaitForSingleObject(info.hProcess, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return 0, err
	}
	return code, nil
}

// powershellPath is Windows PowerShell in the system's own folder: the
// elevated program is never looked up by its name, which would try the
// current folder and App Paths first.
func powershellPath() (string, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe"), nil
}
