// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/screensaver"
	"github.com/jezek/xgb/xfixes"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/connector"
)

// X11 is the clipboard of an X11 session, or of XWayland on GNOME: the
// CLIPBOARD selection, watched with XFixes, and, for writes, PRIMARY too.
//
// Reading a selection is a conversation: ask for its targets, then for the
// text, and take large texts in INCR pieces. Owning one means answering
// every other program's requests, also in pieces for large texts. All of it
// runs on one goroutine that owns the event stream.
type X11 struct {
	x     *xgb.Conn
	win   xproto.Window
	atoms map[string]xproto.Atom
	chunk int // the largest property this server takes in one piece
	logf  func(string, ...any)
	inj   x11Inject
	// kb presses a paste's keys in a Wayland session, whose compositor
	// takes no keys from XWayland's XTEST; nil without a way.
	kb keyboard

	files transfers // the written files, for Flatpak apps

	mu     sync.Mutex
	text   string // what this client owns the selections with
	secret bool
	// data is what it owns them with besides a text, by type: an image,
	// or a list of files; types is its order.
	data    map[string][]byte
	types   []string
	owned   bool // this client still owns CLIPBOARD
	item    connector.Item
	has     bool
	changes chan connector.Item
	errc    chan error
	queued  []func() // work for the event goroutine

	// The event goroutine's own state.
	read    *x11Read
	sends   map[sendKey]*x11Send
	pending []xfixes.SelectionNotifyEvent // owner changes waiting for the read to finish
}

// x11Read is a conversion of CLIPBOARD in progress.
type x11Read struct {
	stage   int // readTargets, readText or readIncr
	targets []xproto.Atom
	secret  bool
	image   string      // the image type it reads, "" for a text
	files   string      // the type of a list of files it reads, "" for none
	text    xproto.Atom // the text target to read when the list holds no file
	html    bool        // the owner offers formatted text, read after the text
	plain   []byte      // the text, while the formatted text is read
	limit   int         // the most bytes it takes: maxText, or more for an image or files
	initial bool        // the clipboard at open: what it holds, not a change
	data    []byte
	started time.Time
}

const (
	readTargets = iota
	readText
	readIncr
)

// x11Send is an INCR transfer to another program.
type x11Send struct {
	data    []byte
	typ     xproto.Atom
	started time.Time
}

// sendTimeout is how long an INCR transfer may take before it is dropped,
// with its copy of the text, which may be a secret: a program that asked
// and went away never finishes it.
const sendTimeout = 30 * time.Second

type sendKey struct {
	win  xproto.Window
	prop xproto.Atom
}

var x11Atoms = []string{"CLIPBOARD", "PRIMARY", "TARGETS", "UTF8_STRING", "STRING", "TEXT", "text/plain;charset=utf-8",
	"text/plain", "INCR", "ATOM", "TIMESTAMP", secretType, "CBB_SELECTION", "MULTIPLE", clip.TypePNG, clip.TypeJPEG,
	clip.TypeHTML, uriListType, gnomeFilesType, portalFilesType}

// An xgb extension's Init writes the package-wide tables of its events and
// errors, which the reader of every connection reads as events come in: an
// Init while any connection takes events is a fatal concurrent map access.
// So each extension's Init runs once in the process, on the first connection
// before it asks for events (OpenX11 starts all three the members use); later
// ones only learn the extension's opcode, which is all Init sets on a
// connection.
var x11Ext struct {
	sync.Mutex
	done map[string]bool
}

// initExt makes the extension name usable on x, through init the first time.
func initExt(x *xgb.Conn, name string, init func(*xgb.Conn) error) error {
	x11Ext.Lock()
	defer x11Ext.Unlock()
	if !x11Ext.done[name] {
		if err := init(x); err != nil {
			return err
		}
		if x11Ext.done == nil {
			x11Ext.done = map[string]bool{}
		}
		x11Ext.done[name] = true
		return nil
	}
	reply, err := xproto.QueryExtension(x, uint16(len(name)), name).Reply()
	if err != nil {
		return err
	}
	if !reply.Present {
		return fmt.Errorf("the X server has no extension %s", name)
	}
	x.ExtLock.Lock()
	x.Extensions[name] = reply.MajorOpcode
	x.ExtLock.Unlock()
	return nil
}

// OpenX11 connects to the X server in $DISPLAY.
func OpenX11(logf func(string, ...any)) (*X11, error) {
	xgb.Logger = log.New(io.Discard, "", 0) // its notes about missing authority files are noise
	x, err := xgb.NewConn()
	if err != nil {
		return nil, fmt.Errorf("x11: %w", err)
	}
	// Before any events: remote paste and the lock check use these later,
	// when this connection's reader is busy. A server without them only
	// refuses those.
	_ = initExt(x, "XTEST", xtest.Init)
	_ = initExt(x, "MIT-SCREEN-SAVER", screensaver.Init)
	if err := initExt(x, "XFIXES", xfixes.Init); err != nil {
		x.Close()
		return nil, fmt.Errorf("x11: the server has no XFixes: %w", err)
	}
	if _, err := xfixes.QueryVersion(x, 5, 0).Reply(); err != nil {
		x.Close()
		return nil, err
	}
	setup := xproto.Setup(x)
	screen := setup.DefaultScreen(x)
	win, err := xproto.NewWindowId(x)
	if err != nil {
		x.Close()
		return nil, err
	}
	err = xproto.CreateWindowChecked(x, screen.RootDepth, win, screen.Root, -10, -10, 1, 1, 0,
		xproto.WindowClassInputOutput, screen.RootVisual, xproto.CwEventMask,
		[]uint32{xproto.EventMaskPropertyChange}).Check()
	if err != nil {
		x.Close()
		return nil, err
	}
	b := &X11{x: x, win: win, atoms: map[string]xproto.Atom{}, logf: logf, files: transfers{logf: logf},
		changes: make(chan connector.Item, 4), errc: make(chan error, 1), sends: map[sendKey]*x11Send{}}
	// Leave room for the request header in each piece.
	b.chunk = min(int(setup.MaximumRequestLength)*4-64, 1<<16)
	for _, name := range x11Atoms {
		r, err := xproto.InternAtom(x, false, uint16(len(name)), name).Reply()
		if err != nil {
			x.Close()
			return nil, err
		}
		b.atoms[name] = r.Atom
	}
	mask := uint32(xfixes.SelectionEventMaskSetSelectionOwner | xfixes.SelectionEventMaskSelectionWindowDestroy |
		xfixes.SelectionEventMaskSelectionClientClose)
	if err := xfixes.SelectSelectionInputChecked(x, win, b.atoms["CLIPBOARD"], mask).Check(); err != nil {
		x.Close()
		return nil, err
	}
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		b.kb = pasteKeys(logf)
	}
	go b.loop()
	// Read what the clipboard holds now; it is not reported as a change.
	// An owner change can come before this request does: its read tells
	// what the clipboard holds, and is a change.
	b.request(func() {
		if b.read != nil {
			return
		}
		b.startRead()
		b.read.initial = true
	})
	return b, nil
}

// Close closes the connection.
func (b *X11) Close() error {
	closeKeys(b.kb)
	b.files.close()
	b.x.Close()
	return nil
}

// request runs f on the event goroutine, by waking it with an event it
// sends to itself.
func (b *X11) request(f func()) {
	b.mu.Lock()
	b.queued = append(b.queued, f)
	b.mu.Unlock()
	ev := xproto.ClientMessageEvent{Format: 32, Window: b.win, Type: b.atoms["CBB_SELECTION"],
		Data: xproto.ClientMessageDataUnionData32New(make([]uint32, 5))}
	xproto.SendEvent(b.x, false, b.win, 0, string(ev.Bytes()))
}

func (b *X11) loop() {
	for {
		ev, err := b.x.WaitForEvent()
		if ev == nil && err == nil {
			select {
			case b.errc <- fmt.Errorf("%w: the connection to the X server closed", connector.ErrBoardGone):
			default:
			}
			return
		}
		if err != nil {
			b.logf("cbb: X11 error: %v", err)
			continue
		}
		switch e := ev.(type) {
		case xproto.ClientMessageEvent:
			b.mu.Lock()
			queued := b.queued
			b.queued = nil
			b.mu.Unlock()
			for _, f := range queued {
				f()
			}
		case xfixes.SelectionNotifyEvent:
			b.ownerChanged(e)
		case xproto.SelectionNotifyEvent:
			b.converted(e)
		case xproto.PropertyNotifyEvent:
			b.property(e)
		case xproto.SelectionRequestEvent:
			b.serve(e)
		case xproto.SelectionClearEvent:
			if e.Selection == b.atoms["CLIPBOARD"] {
				b.mu.Lock()
				b.owned = false
				b.mu.Unlock()
			}
		}
	}
}

// ownerChanged starts a read when another program takes the clipboard.
func (b *X11) ownerChanged(e xfixes.SelectionNotifyEvent) {
	if e.Owner == b.win {
		return // our own write
	}
	if e.Owner == xproto.WindowNone {
		b.mu.Lock()
		b.item, b.has = connector.Item{}, false
		b.mu.Unlock()
		return
	}
	if b.read != nil && time.Since(b.read.started) < readTimeout {
		b.pending = append(b.pending[:0], e) // read again when this one is done
		return
	}
	b.startRead()
}

func (b *X11) startRead() {
	b.read = &x11Read{stage: readTargets, started: time.Now(), limit: maxText}
	xproto.ConvertSelection(b.x, b.win, b.atoms["CLIPBOARD"], b.atoms["TARGETS"], b.atoms["CBB_SELECTION"], xproto.TimeCurrentTime)
}

// finishRead ends a read, reports its item, and starts the next one if the
// owner changed meanwhile.
func (b *X11) finishRead(it connector.Item, ok bool) {
	initial := b.read != nil && b.read.initial
	b.read = nil
	b.mu.Lock()
	// A read that ends while this client owns CLIPBOARD was answered by
	// itself, or its text was replaced by a write: it is no copy.
	owned := b.owned
	if !owned {
		b.item, b.has = it, ok
	}
	b.mu.Unlock()
	if ok && !owned && !initial {
		select {
		case b.changes <- it:
		default:
			select {
			case <-b.changes:
			default:
			}
			b.changes <- it
		}
	}
	if len(b.pending) > 0 {
		b.pending = b.pending[:0]
		b.startRead()
	}
}

// converted handles the answer to a conversion of CLIPBOARD.
func (b *X11) converted(e xproto.SelectionNotifyEvent) {
	r := b.read
	if r == nil || e.Selection != b.atoms["CLIPBOARD"] {
		return
	}
	if e.Property == xproto.AtomNone {
		b.failRead() // the owner refused
		return
	}
	prop, err := xproto.GetProperty(b.x, true, b.win, e.Property, xproto.GetPropertyTypeAny, 0, uint32(r.limit+3)/4).Reply()
	if err != nil {
		b.failRead()
		return
	}
	if prop.BytesAfter > 0 {
		// More than the group carries, in one piece: skip it rather than
		// report the beginning as the whole text.
		b.logf("cbb: the clipboard holds more than %d bytes", r.limit)
		b.failRead()
		return
	}
	switch r.stage {
	case readTargets:
		for i := 0; i+4 <= len(prop.Value) && prop.Format == 32; i += 4 {
			r.targets = append(r.targets, xproto.Atom(xgb.Get32(prop.Value[i:])))
		}
		r.secret = slices.Contains(r.targets, b.atoms[secretType])
		target := xproto.Atom(0)
		for _, t := range textTypes {
			if a := b.atoms[t]; slices.Contains(r.targets, a) {
				target = a
				break
			}
		}
		// An image without a text: a copy in an image editor, or a
		// screenshot. A text wins, as in a spreadsheet, which offers a
		// picture of the cells too.
		for _, t := range imageTypes {
			if a := b.atoms[t]; target == 0 && slices.Contains(r.targets, a) {
				target, r.image, r.limit = a, t, connector.MaxImage
			}
		}
		// Files win over the text of their paths that file managers add.
		for _, t := range fileTypes {
			if a := b.atoms[t]; r.files == "" && slices.Contains(r.targets, a) {
				if r.image == "" {
					r.text = target
				}
				target, r.files, r.image, r.limit = a, t, "", maxFileList
			}
		}
		if target == 0 {
			// An owner that lists no text target may still convert to
			// UTF8_STRING, as many old programs do.
			target = b.atoms["UTF8_STRING"]
		}
		r.html = !r.secret && slices.Contains(r.targets, b.atoms[clip.TypeHTML])
		r.stage = readText
		xproto.ConvertSelection(b.x, b.win, b.atoms["CLIPBOARD"], target, b.atoms["CBB_SELECTION"], xproto.TimeCurrentTime)
	case readText:
		if prop.Type == b.atoms["INCR"] {
			r.stage = readIncr // the pieces follow as property changes
			return
		}
		b.finished(prop.Value)
	}
}

// finished ends a read with the bytes read, or reads the text instead of
// a list of files that names no file here, or the formatted text after
// the text.
func (b *X11) finished(data []byte) {
	r := b.read
	if r.files != "" && len(filePaths(r.files, data)) == 0 && r.text != 0 {
		r.files, r.stage, r.limit, r.data = "", readText, maxText, nil
		xproto.ConvertSelection(b.x, b.win, b.atoms["CLIPBOARD"], r.text, b.atoms["CBB_SELECTION"], xproto.TimeCurrentTime)
		return
	}
	if r.html && r.plain == nil && r.image == "" && r.files == "" && len(data) > 0 {
		r.plain, r.stage, r.limit, r.data = data, readText, connector.MaxHTML, nil
		xproto.ConvertSelection(b.x, b.win, b.atoms["CLIPBOARD"], b.atoms[clip.TypeHTML], b.atoms["CBB_SELECTION"], xproto.TimeCurrentTime)
		return
	}
	it := r.item(data)
	b.finishRead(it, r.plain != nil || len(data) > 0 && (r.files == "" || len(it.Files) > 0))
}

// failRead ends a read that failed: with the text alone when it was the
// formatted text that failed, else with nothing.
func (b *X11) failRead() {
	if r := b.read; r != nil && r.plain != nil {
		b.logf("cbb: the clipboard's formatted text could not be read; its text goes alone")
		b.finishRead(connector.Item{Text: string(r.plain)}, true)
		return
	}
	b.finishRead(connector.Item{}, false)
}

// item makes the item of the bytes read.
func (r *x11Read) item(data []byte) connector.Item {
	if r.image != "" {
		return connector.Item{Image: &connector.Image{Type: r.image, Data: data}}
	}
	if r.files != "" {
		return connector.Item{Files: filePaths(r.files, data)}
	}
	if r.plain != nil {
		return connector.Item{Text: string(r.plain), HTML: htmlText(data)}
	}
	return connector.Item{Text: string(data), Secret: r.secret}
}

// property handles property changes: the pieces of an INCR read on our
// window, and the requests for the next piece of an INCR send.
func (b *X11) property(e xproto.PropertyNotifyEvent) {
	if e.Window == b.win && e.Atom == b.atoms["CBB_SELECTION"] && e.State == xproto.PropertyNewValue {
		r := b.read
		if r == nil || r.stage != readIncr {
			return
		}
		prop, err := xproto.GetProperty(b.x, true, b.win, e.Atom, xproto.GetPropertyTypeAny, 0, uint32(r.limit+3)/4).Reply()
		if err != nil {
			b.failRead()
			return
		}
		if len(prop.Value) == 0 {
			b.finished(r.data)
			return
		}
		r.data = append(r.data, prop.Value...)
		if len(r.data) > r.limit {
			b.logf("cbb: the clipboard holds more than %d bytes", r.limit)
			b.failRead()
		}
		return
	}
	if e.State != xproto.PropertyDelete {
		return
	}
	k := sendKey{e.Window, e.Atom}
	s := b.sends[k]
	if s == nil {
		return
	}
	n := min(len(s.data), b.chunk)
	xproto.ChangeProperty(b.x, xproto.PropModeReplace, e.Window, e.Atom, s.typ, 8, uint32(n), s.data[:n])
	s.data = s.data[n:]
	if n == 0 {
		delete(b.sends, k) // the empty piece ends the transfer
	}
}

// serve answers another program's request for a selection we own.
func (b *X11) serve(e xproto.SelectionRequestEvent) {
	b.mu.Lock()
	text, secret, data, types := b.text, b.secret, b.data, b.types
	b.mu.Unlock()
	// The text targets, none for an image without one.
	texts := textTypes
	if text == "" && len(types) > 0 {
		texts = nil
	}
	prop := e.Property
	if prop == xproto.AtomNone {
		prop = e.Target // an obsolete client
	}
	ok := true
	switch t := e.Target; {
	case t == b.atoms["TARGETS"]:
		targets := []xproto.Atom{b.atoms["TARGETS"], b.atoms["TIMESTAMP"]}
		for _, typ := range types {
			targets = append(targets, b.atoms[typ])
		}
		for _, name := range texts {
			targets = append(targets, b.atoms[name])
		}
		if secret {
			targets = append(targets, b.atoms[secretType])
		}
		data := make([]byte, 4*len(targets))
		for i, a := range targets {
			xgb.Put32(data[4*i:], uint32(a))
		}
		xproto.ChangeProperty(b.x, xproto.PropModeReplace, e.Requestor, prop, b.atoms["ATOM"], 32, uint32(len(targets)), data)
	case t == b.atoms[secretType]:
		xproto.ChangeProperty(b.x, xproto.PropModeReplace, e.Requestor, prop, b.atoms["UTF8_STRING"], 8, 6, []byte("secret"))
	case slices.ContainsFunc(types, func(name string) bool { return b.atoms[name] == t }),
		slices.ContainsFunc(texts, func(name string) bool { return b.atoms[name] == t }):
		out := []byte(text)
		typ := t
		if t == b.atoms["TEXT"] {
			typ = b.atoms["UTF8_STRING"]
		}
		for _, name := range types {
			if b.atoms[name] == t {
				out = data[name]
			}
		}
		if len(out) > b.chunk {
			// INCR: announce the size, then send pieces each time the
			// requestor deletes the property.
			b.pruneSends()
			xproto.ChangeWindowAttributes(b.x, e.Requestor, xproto.CwEventMask, []uint32{xproto.EventMaskPropertyChange})
			b.sends[sendKey{e.Requestor, prop}] = &x11Send{data: out, typ: typ, started: time.Now()}
			size := make([]byte, 4)
			xgb.Put32(size, uint32(len(out)))
			xproto.ChangeProperty(b.x, xproto.PropModeReplace, e.Requestor, prop, b.atoms["INCR"], 32, 1, size)
		} else {
			xproto.ChangeProperty(b.x, xproto.PropModeReplace, e.Requestor, prop, typ, 8, uint32(len(out)), out)
		}
	default:
		ok = false
	}
	notify := xproto.SelectionNotifyEvent{Time: e.Time, Requestor: e.Requestor, Selection: e.Selection, Target: e.Target, Property: prop}
	if !ok {
		notify.Property = xproto.AtomNone
	}
	xproto.SendEvent(b.x, false, e.Requestor, 0, string(notify.Bytes()))
}

// pruneSends drops the INCR transfers that took too long.
func (b *X11) pruneSends() {
	for k, s := range b.sends {
		if time.Since(s.started) > sendTimeout {
			delete(b.sends, k)
		}
	}
}

// Current returns what the clipboard holds.
func (b *X11) Current() (connector.Item, bool, error) {
	deadline := time.Now().Add(readTimeout)
	for {
		b.mu.Lock()
		it, has := b.item, b.has
		b.mu.Unlock()
		if has || time.Now().After(deadline) {
			return it, has, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Next waits for a change that is not our own.
func (b *X11) Next(ctx context.Context) (connector.Item, bool, error) {
	select {
	case it := <-b.changes:
		return it, true, nil
	case err := <-b.errc:
		return connector.Item{}, false, err
	case <-ctx.Done():
		return connector.Item{}, false, ctx.Err()
	}
}

// Write owns CLIPBOARD and PRIMARY with the text.
func (b *X11) Write(text string, secret bool) error {
	return b.write(connector.Item{Text: text, Secret: secret}, nil, nil)
}

// WriteImage owns CLIPBOARD and PRIMARY with the image, and its text, if
// any.
func (b *X11) WriteImage(img connector.Image, text string) error {
	return b.write(connector.Item{Text: text, Image: &img}, map[string][]byte{img.Type: img.Data}, []string{img.Type})
}

// WriteHTML owns CLIPBOARD and PRIMARY with formatted text and its plain
// text.
func (b *X11) WriteHTML(html, text string) error {
	return b.write(connector.Item{Text: text, HTML: html}, map[string][]byte{clip.TypeHTML: []byte(html)}, []string{clip.TypeHTML})
}

// WriteFiles owns CLIPBOARD and PRIMARY with the files, as a file manager
// copies them, and their paths as text.
func (b *X11) WriteFiles(paths []string) error {
	data := fileData(paths, b.files.start(paths))
	types := []string{uriListType, gnomeFilesType}
	if _, ok := data[portalFilesType]; ok {
		types = append(types, portalFilesType)
	}
	it := connector.Item{Text: strings.Join(paths, "\n"), Files: paths}
	return b.write(it, data, types)
}

// write owns the selections with the item: its text, and data of other
// types.
func (b *X11) write(it connector.Item, data map[string][]byte, types []string) error {
	if it.Files == nil {
		b.files.stop()
	}
	b.mu.Lock()
	b.text, b.secret, b.data, b.types, b.owned = it.Text, it.Secret, data, types, true
	b.item, b.has = it, true
	b.mu.Unlock()
	for _, sel := range []string{"CLIPBOARD", "PRIMARY"} {
		if err := xproto.SetSelectionOwnerChecked(b.x, b.win, b.atoms[sel], xproto.TimeCurrentTime).Check(); err != nil {
			return err
		}
	}
	return nil
}

// ClearIfUnchanged gives up the selections if we still own CLIPBOARD.
func (b *X11) ClearIfUnchanged() error {
	b.mu.Lock()
	owned := b.owned
	if owned {
		b.text, b.data, b.types, b.owned = "", nil, nil, false
	}
	b.mu.Unlock()
	if !owned {
		return nil
	}
	for _, sel := range []string{"CLIPBOARD", "PRIMARY"} {
		r, err := xproto.GetSelectionOwner(b.x, b.atoms[sel]).Reply()
		if err == nil && r.Owner == b.win {
			xproto.SetSelectionOwner(b.x, xproto.WindowNone, b.atoms[sel], xproto.TimeCurrentTime)
		}
	}
	// Transfers still running hold a copy of the expired text.
	b.request(func() { clear(b.sends) })
	return nil
}
