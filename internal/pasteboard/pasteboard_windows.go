// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pasteboard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/connector"
)

// maxHTML is the largest formatted text read; a larger one is left out
// and its text goes alone.
const maxHTML = connector.MaxHTML

// Supported reports whether this build reaches the clipboard.
const Supported = true

// On Windows the pasteboard is the clipboard of the user's session, read
// and written through the Win32 API. Its change counter is the clipboard
// sequence number. A password manager marks a secret with the formats that
// Windows documents for clipboard monitors and the clipboard history;
// received secrets are written with them. Windows apps end lines with CR LF:
// the text is read with LF and written with CR LF, so the group carries one
// form. A text with a NUL ends there, since the clipboard's text format ends
// at the first NUL.
//
// Formatted text, the "HTML Format" that browsers and Office write, is read
// next to the text, never with a secret, and written with it.
//
// An image is read when the clipboard holds no text: the "GIF" format that
// browsers put there for an animation, the "PNG" format of browsers and
// Office, else the bitmap as a PNG. One is written as a PNG and as a bitmap
// with alpha, CF_DIBV5, from which Windows makes the older bitmap formats;
// a GIF also as itself, with its first frame in the others. A copy of files in Explorer, CF_HDROP, is read
// as their paths before anything else; files are written the same way,
// with the drop effect that tells Explorer to copy them, never move them.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procEmptyClipboard             = user32.NewProc("EmptyClipboard")
	procGetClipboardData           = user32.NewProc("GetClipboardData")
	procSetClipboardData           = user32.NewProc("SetClipboardData")
	procIsClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	procRegisterClipboardFormatW   = user32.NewProc("RegisterClipboardFormatW")
	procGetClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")
	procCreateWindowExW            = user32.NewProc("CreateWindowExW")
	procGlobalAlloc                = kernel32.NewProc("GlobalAlloc")
	procGlobalFree                 = kernel32.NewProc("GlobalFree")
	procGlobalLock                 = kernel32.NewProc("GlobalLock")
	procGlobalUnlock               = kernel32.NewProc("GlobalUnlock")
	procGlobalSize                 = kernel32.NewProc("GlobalSize")
)

const (
	cfDIB         = 8
	cfHDrop       = 15
	cfDIBV5       = 17
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
	hwndMessage   = ^uintptr(2) // HWND_MESSAGE, (HWND)-3
)

// The formats that mark a secret. A clipboard monitor skips an item with
// ExcludeClipboardContentFromMonitorProcessing, and the clipboard history
// and the cloud clipboard skip one whose CanIncludeInClipboardHistory or
// CanUploadToCloudClipboard is the number 0. "Clipboard Viewer Ignore" is
// the older mark that KeePass and other password managers also set.
var (
	formatsOnce                                   sync.Once
	cfExclude, cfViewerIgnore, cfHistory, cfCloud uintptr
	cfPNG                                         uintptr // an image as a PNG file
	cfGIF                                         uintptr // an image as a GIF file, perhaps animated
	cfHTML                                        uintptr // formatted text, "HTML Format"
	cfDropEffect                                  uintptr // whether pasted files are copied or moved
)

func registerFormats() {
	formatsOnce.Do(func() {
		cfPNG = register("PNG")
		cfGIF = register("GIF")
		cfHTML = register("HTML Format")
		cfDropEffect = register("Preferred DropEffect")
		cfExclude = register("ExcludeClipboardContentFromMonitorProcessing")
		cfViewerIgnore = register("Clipboard Viewer Ignore")
		cfHistory = register("CanIncludeInClipboardHistory")
		cfCloud = register("CanUploadToCloudClipboard")
	})
}

func register(name string) uintptr {
	p, _ := windows.UTF16PtrFromString(name)
	r, _, _ := procRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(p)))
	return r
}

// A Board is the clipboard. Its calls run on one locked thread, which owns
// the hidden window that the clipboard needs as the owner of what this
// program writes.
type Board struct{}

// General returns the clipboard of the user's session.
func General() *Board { return &Board{} }

// Private returns the clipboard too: Windows has no private ones, so the
// tests that use it run only when asked to (CBB_TEST_CLIPBOARD=1).
func Private(string) *Board { return &Board{} }

// Release does nothing on Windows.
func (b *Board) Release() {}

// ChangeCount returns the clipboard sequence number, which grows with every
// change of the clipboard.
func (b *Board) ChangeCount() int64 {
	r, _, _ := procGetClipboardSequenceNumber.Call()
	return int64(uint32(r))
}

// Read returns the clipboard's text, and false if it holds none.
func (b *Board) Read() (Item, bool, error) {
	var it Item
	var ok bool
	err := onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		it.Change = b.ChangeCount()
		if available(cfHDrop) {
			var err error
			ok, err = readFiles(&it)
			return err
		}
		if !available(cfUnicodeText) {
			var err error
			ok, err = readImage(&it)
			return err
		}
		h, _, err := procGetClipboardData.Call(cfUnicodeText)
		if h == 0 {
			return fmt.Errorf("pasteboard: reading the clipboard: %w", err)
		}
		text, err := globalText(h)
		if err != nil {
			return err
		}
		registerFormats()
		it.Text = strings.ReplaceAll(text, "\r\n", "\n")
		it.Secret = available(cfExclude) || available(cfViewerIgnore) || zero(cfHistory)
		if !it.Secret && it.Text != "" {
			it.HTML = readHTML()
		}
		ok = true
		return nil
	})
	return it, ok, err
}

// readHTML returns the open clipboard's formatted text, or "" when it
// holds none, or one that is too large or cannot be read: its text then
// goes alone.
func readHTML() string {
	if !available(cfHTML) {
		return ""
	}
	h, _, _ := procGetClipboardData.Call(cfHTML)
	if h == 0 {
		return ""
	}
	data, err := globalBytes(h, maxHTML)
	if err != nil {
		return ""
	}
	html, err := parseCFHTML(data)
	if err != nil {
		return ""
	}
	return html
}

// WriteHTML puts formatted text on the clipboard as "HTML Format", with
// its plain text, and returns the new change counter.
func (b *Board) WriteHTML(html, text string) (int64, error) {
	text = windowsText(text)
	registerFormats()
	err := onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		if r, _, err := procEmptyClipboard.Call(); r == 0 {
			return fmt.Errorf("pasteboard: emptying the clipboard: %w", err)
		}
		return errors.Join(set(cfUnicodeText, utf16Bytes(text)), set(cfHTML, append(makeCFHTML(html), 0)))
	})
	if err != nil {
		return 0, err
	}
	return b.ChangeCount(), nil
}

// Write puts a text on the clipboard and returns the new change counter.
// A secret carries the marks, so clipboard histories, the cloud clipboard
// and other monitors skip it.
func (b *Board) Write(text string, secret bool) (int64, error) {
	text = windowsText(text)
	err := onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		if r, _, err := procEmptyClipboard.Call(); r == 0 {
			return fmt.Errorf("pasteboard: emptying the clipboard: %w", err)
		}
		if err := set(cfUnicodeText, utf16Bytes(text)); err != nil {
			return err
		}
		if secret {
			registerFormats()
			var errs []error
			errs = append(errs, set(cfExclude, []byte{0}))
			errs = append(errs, set(cfViewerIgnore, []byte{0}))
			errs = append(errs, set(cfHistory, []byte{0, 0, 0, 0}))
			errs = append(errs, set(cfCloud, []byte{0, 0, 0, 0}))
			if err := errors.Join(errs...); err != nil {
				procEmptyClipboard.Call() // never leave a secret without its marks
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	// Closing the clipboard counts as changes too, as Windows adds the
	// formats it converts the text to, so the counter is read after it.
	return b.ChangeCount(), nil
}

// dropFiles is the size of DROPFILES, the header of CF_HDROP: the offset
// of the paths, a point, and two BOOLs, the last saying the paths are
// UTF-16.
const dropFiles = 20

// readFiles reads the open clipboard's files: CF_HDROP's paths, each
// ended by a NUL, the list by another.
func readFiles(it *Item) (bool, error) {
	h, _, err := procGetClipboardData.Call(cfHDrop)
	if h == 0 {
		return false, fmt.Errorf("pasteboard: reading the clipboard's files: %w", err)
	}
	data, err := globalBytes(h, clip.MaxPaths*4)
	if err != nil {
		return false, err
	}
	paths, err := parseDrop(data)
	if err != nil {
		return false, err
	}
	it.Files = paths
	return len(paths) > 0, nil
}

// parseDrop reads the paths of a CF_HDROP block.
func parseDrop(data []byte) ([]string, error) {
	if len(data) < dropFiles {
		return nil, errors.New("pasteboard: a CF_HDROP too short")
	}
	off := int(binary.LittleEndian.Uint32(data))
	wide := binary.LittleEndian.Uint32(data[16:]) != 0
	if off < dropFiles || off > len(data) {
		return nil, errors.New("pasteboard: a CF_HDROP whose paths are outside it")
	}
	var paths []string
	rest := data[off:]
	for {
		var p string
		if wide {
			u := make([]uint16, 0, 64)
			for len(rest) >= 2 {
				c := binary.LittleEndian.Uint16(rest)
				rest = rest[2:]
				if c == 0 {
					break
				}
				u = append(u, c)
			}
			p = string(utf16.Decode(u))
		} else {
			i := bytes.IndexByte(rest, 0)
			if i < 0 {
				i = len(rest)
			}
			p, rest = string(rest[:i]), rest[min(i+1, len(rest)):]
		}
		if p == "" {
			return paths, nil
		}
		paths = append(paths, p)
	}
}

// dropData is the CF_HDROP block of paths.
func dropData(paths []string) []byte {
	data := make([]byte, dropFiles)
	binary.LittleEndian.PutUint32(data, dropFiles)
	binary.LittleEndian.PutUint32(data[16:], 1)
	for _, p := range paths {
		for _, c := range utf16.Encode([]rune(p)) {
			data = binary.LittleEndian.AppendUint16(data, c)
		}
		data = append(data, 0, 0)
	}
	return append(data, 0, 0)
}

// WriteFiles puts files on the clipboard, as Explorer copies them, and
// returns the new change counter.
func (b *Board) WriteFiles(paths []string) (int64, error) {
	if len(paths) == 0 {
		return 0, errors.New("pasteboard: no files")
	}
	for _, p := range paths {
		if strings.IndexByte(p, 0) >= 0 {
			return 0, errors.New("pasteboard: a path with a NUL")
		}
	}
	registerFormats()
	err := onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		if r, _, err := procEmptyClipboard.Call(); r == 0 {
			return fmt.Errorf("pasteboard: emptying the clipboard: %w", err)
		}
		// DROPEFFECT_COPY: a paste copies the files.
		return errors.Join(set(cfHDrop, dropData(paths)), set(cfDropEffect, []byte{1, 0, 0, 0}))
	})
	if err != nil {
		return 0, err
	}
	return b.ChangeCount(), nil
}

// readImage reads the open clipboard's image, if it holds one.
func readImage(it *Item) (bool, error) {
	registerFormats()
	format := uintptr(0)
	switch {
	case available(cfGIF):
		format = cfGIF
	case available(cfPNG):
		format = cfPNG
	case available(cfDIBV5):
		format = cfDIBV5
	case available(cfDIB):
		format = cfDIB
	default:
		return false, nil
	}
	h, _, err := procGetClipboardData.Call(format)
	if h == 0 {
		return false, fmt.Errorf("pasteboard: reading the clipboard's image: %w", err)
	}
	data, err := globalBytes(h, clip.MaxMedia)
	if err != nil {
		return false, err
	}
	typ := clip.TypePNG
	switch format {
	case cfGIF:
		typ = clip.TypeGIF
	case cfPNG:
	default:
		if data, err = dibToPNG(data); err != nil {
			return false, err
		}
	}
	it.ImageType, it.Image = typ, data
	return true, nil
}

// globalBytes copies a clipboard memory block of at most limit bytes.
func globalBytes(h uintptr, limit int) ([]byte, error) {
	n, _, _ := procGlobalSize.Call(h)
	if int64(n) > int64(limit) {
		return nil, errors.New("pasteboard: the clipboard holds more than the group carries")
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		return nil, fmt.Errorf("pasteboard: reading the clipboard: %w", err)
	}
	defer procGlobalUnlock.Call(h)
	return bytes.Clone(unsafe.Slice((*byte)(ptr(p)), n)), nil
}

// WriteImage puts an image of a type on the clipboard as a PNG and as a
// bitmap, with its text, if any, and returns the new change counter.
func (b *Board) WriteImage(typ string, data []byte, text string) (int64, error) {
	img, err := decodeImage(typ, data)
	if err != nil {
		return 0, err
	}
	dib := imageDIBV5(img)
	var gif []byte
	if typ == clip.TypeGIF {
		gif = data
	}
	if typ != clip.TypePNG {
		// The PNG is made from the DIB, so the decoded pixels can go first
		// (imageBytes). They do only once the collector has run: left to
		// its own pace, it lets the heap grow to about twice the count
		// before it frees them.
		r := img.Bounds()
		img = nil
		runtime.GC()
		if data, err = dibPNG(dib, r.Dx(), r.Dy()); err != nil {
			return 0, err
		}
	}
	text = windowsText(text)
	registerFormats()
	err = onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		if r, _, err := procEmptyClipboard.Call(); r == 0 {
			return fmt.Errorf("pasteboard: emptying the clipboard: %w", err)
		}
		var errs []error
		if gif != nil {
			errs = append(errs, set(cfGIF, gif))
		}
		errs = append(errs, set(cfPNG, data), set(cfDIBV5, dib))
		if text != "" {
			errs = append(errs, set(cfUnicodeText, utf16Bytes(text)))
		}
		return errors.Join(errs...)
	})
	if err != nil {
		return 0, err
	}
	return b.ChangeCount(), nil
}

// windowsText is a text as the clipboard holds it: up to its first NUL,
// with CR LF line ends.
func windowsText(text string) string {
	if i := strings.IndexByte(text, 0); i >= 0 {
		text = text[:i]
	}
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
}

// Clear empties the clipboard, for a secret that expired.
func (b *Board) Clear() int64 {
	onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		procEmptyClipboard.Call()
		return nil
	})
	return b.ChangeCount()
}

// open opens the clipboard, waiting a little while another program has it
// open.
func open(hwnd uintptr) error {
	var err error
	for range 20 {
		var r uintptr
		r, _, err = procOpenClipboard.Call(hwnd)
		if r != 0 {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("pasteboard: another program keeps the clipboard open: %w", err)
}

func available(format uintptr) bool {
	if format == 0 {
		return false
	}
	r, _, _ := procIsClipboardFormatAvailable.Call(format)
	return r != 0
}

// zero tells whether the clipboard holds the format as the number 0.
func zero(format uintptr) bool {
	if !available(format) {
		return false
	}
	h, _, _ := procGetClipboardData.Call(format)
	if h == 0 {
		return false
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return false
	}
	defer procGlobalUnlock.Call(h)
	n, _, _ := procGlobalSize.Call(h)
	return n >= 4 && *(*uint32)(ptr(p)) == 0
}

// globalText reads the UTF-16 text in a clipboard memory block, up to its
// first NUL or its end.
func globalText(h uintptr) (string, error) {
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		return "", fmt.Errorf("pasteboard: reading the clipboard: %w", err)
	}
	defer procGlobalUnlock.Call(h)
	n, _, _ := procGlobalSize.Call(h)
	u := unsafe.Slice((*uint16)(ptr(p)), n/2)
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	return string(utf16.Decode(u)), nil
}

// ptr turns the address of locked global memory, which is outside Go's
// heap, into a pointer.
func ptr(p uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&p)) }

func utf16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	u = append(u, 0)
	return unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), 2*len(u))
}

// set puts data in a format on the open clipboard, which then owns the
// memory.
func set(format uintptr, data []byte) error {
	if format == 0 {
		return errors.New("pasteboard: a clipboard format could not be registered")
	}
	h, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(len(data)))
	if h == 0 {
		return fmt.Errorf("pasteboard: out of memory: %w", err)
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return fmt.Errorf("pasteboard: writing the clipboard: %w", err)
	}
	copy(unsafe.Slice((*byte)(ptr(p)), len(data)), data)
	procGlobalUnlock.Call(h)
	if r, _, err := procSetClipboardData.Call(format, h); r == 0 {
		procGlobalFree.Call(h)
		return fmt.Errorf("pasteboard: writing the clipboard: %w", err)
	}
	return nil
}

// The clipboard thread: a locked OS thread with a hidden message-only
// window, on which every call that opens the clipboard runs.
var (
	threadOnce sync.Once
	calls      chan func(hwnd uintptr)
	threadErr  error
)

func onThread(f func(hwnd uintptr) error) error {
	threadOnce.Do(startThread)
	if threadErr != nil {
		return threadErr
	}
	done := make(chan error, 1)
	calls <- func(hwnd uintptr) { done <- f(hwnd) }
	return <-done
}

func startThread() {
	calls = make(chan func(uintptr))
	ready := make(chan uintptr)
	go func() {
		runtime.LockOSThread()
		class, _ := windows.UTF16PtrFromString("STATIC")
		hwnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(class)), 0, 0, 0, 0, 0, 0, hwndMessage, 0, 0, 0)
		if hwnd == 0 {
			threadErr = fmt.Errorf("pasteboard: the clipboard window could not be made: %w", err)
		}
		ready <- hwnd
		if hwnd == 0 {
			return
		}
		for f := range calls {
			f(hwnd)
		}
	}()
	<-ready
}
