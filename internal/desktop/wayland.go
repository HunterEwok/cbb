// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/wl"
)

// The data-control protocols let a client without a window read and set
// the clipboard. The standard one, ext-data-control-v1, and the older
// wlr-data-control-unstable-v1 have the same requests and events.
var dataControls = []string{"ext_data_control_manager_v1", "zwlr_data_control_manager_v1"}

// Opcodes, the same in both protocols.
const (
	mgrCreateSource = 0
	mgrGetDevice    = 1

	devSetSelection        = 0
	devSetPrimarySelection = 2
	devEvDataOffer         = 0
	devEvSelection         = 1
	devEvFinished          = 2
	devEvPrimarySelection  = 3

	srcOffer     = 0
	srcDestroy   = 1
	srcEvSend    = 0
	srcEvCancel  = 1
	offerReceive = 0
	offerDestroy = 1
	offerEvOffer = 0
)

// textTypes are the MIME types and X11 targets of text, the best first.
var textTypes = []string{"text/plain;charset=utf-8", "UTF8_STRING", "text/plain", "STRING", "TEXT"}

// imageTypes are the image types the group carries, the best first.
var imageTypes = []string{clip.TypePNG, clip.TypeJPEG}

// secretType is the type KDE's password managers add to a secret; any
// value counts.
const secretType = "x-kde-passwordManagerHint"

const (
	maxText      = 1 << 20
	readTimeout  = 2 * time.Second
	writeTimeout = 5 * time.Second // for a program that asked for the text and does not read it
	// imageTimeout bounds reading or writing an image, which may be large.
	imageTimeout = 30 * time.Second
)

// Wayland is the clipboard of a Wayland session through data-control.
type Wayland struct {
	d      *wl.Display
	mgr    uint32
	device uint32
	ifaces string // the protocol's prefix, for the offer and source interfaces
	logf   func(string, ...any)
	seat   uint32
	vkm    uint32 // the virtual keyboard manager, 0 if the compositor has none
	inj    waylandInject
	kb     keyboard  // a paste's keys on GNOME and KDE, which have no virtual keyboard; nil without a way
	files  transfers // the written files, for Flatpak apps

	mu         sync.Mutex
	offers     map[uint32][]string // the types of each live offer
	current    uint32              // the clipboard's offer, 0 if empty
	own        uint32              // the clipboard source this client set, 0 if none
	ownPrimary uint32              // the primary selection source this client set, 0 if none
	ownPending int                 // selection events still to come for our own writes
	opened     bool                // the selection at open was announced; later ones are changes
	sources    map[uint32]bool     // the sources not yet destroyed
	item       connector.Item
	has        bool
	changes    chan connector.Item
	errc       chan error
}

// OpenWayland connects to the Wayland session and binds data-control.
func OpenWayland(logf func(string, ...any)) (*Wayland, error) {
	d, err := wl.Connect()
	if err != nil {
		return nil, err
	}
	reg, err := d.GetRegistry()
	if err != nil {
		d.Close()
		return nil, err
	}
	w := &Wayland{d: d, logf: logf, offers: map[uint32][]string{}, sources: map[uint32]bool{}, files: transfers{logf: logf},
		changes: make(chan connector.Item, 4), errc: make(chan error, 1)}
	var mgr wl.Global
	found := false
	for _, name := range dataControls {
		if mgr, found = reg.Find(name); found {
			break
		}
	}
	if !found {
		d.Close()
		return nil, errors.New("wayland: the compositor offers no data-control protocol")
	}
	seat, ok := reg.Find("wl_seat")
	if !ok {
		d.Close()
		return nil, errors.New("wayland: the compositor has no seat")
	}
	w.ifaces = mgr.Interface[:len(mgr.Interface)-len("manager_v1")]
	w.mgr = reg.Bind(mgr, 2, nil)
	seatID := reg.Bind(seat, 1, nil)
	w.seat = seatID
	if vkm, ok := reg.Find(virtualKeyboards); ok {
		w.vkm = reg.Bind(vkm, 1, nil)
	} else {
		w.kb = pasteKeys(logf)
	}
	w.device = d.NewID(w.deviceEvent)
	if err := d.Send(w.mgr, mgrGetDevice, (&wl.Request{}).Uint(w.device).Uint(seatID)); err != nil {
		d.Close()
		return nil, err
	}
	// The device announces the current selection right away; it is what
	// the clipboard holds, not a change.
	if err := d.Roundtrip(); err != nil {
		d.Close()
		return nil, err
	}
	w.mu.Lock()
	w.opened = true
	w.mu.Unlock()
	go w.loop()
	return w, nil
}

// Close closes the connection.
func (w *Wayland) Close() error {
	closeKeys(w.kb)
	w.files.close()
	return w.d.Close()
}

func (w *Wayland) loop() {
	for {
		if err := w.d.Dispatch(); err != nil {
			select {
			case w.errc <- fmt.Errorf("%w: %v", connector.ErrBoardGone, err):
			default:
			}
			return
		}
	}
}

func (w *Wayland) deviceEvent(op uint16, a *wl.Args) error {
	switch op {
	case devEvDataOffer:
		id := a.Uint()
		if a.Err != nil {
			return a.Err
		}
		w.mu.Lock()
		w.offers[id] = nil
		w.mu.Unlock()
		w.d.SetHandler(id, func(op uint16, a *wl.Args) error {
			if op == offerEvOffer {
				t := a.String()
				w.mu.Lock()
				if types, ok := w.offers[id]; ok {
					w.offers[id] = append(types, t)
				}
				w.mu.Unlock()
			}
			return a.Err
		})
	case devEvSelection:
		id := a.Uint()
		if a.Err != nil {
			return a.Err
		}
		w.selection(id)
	case devEvPrimarySelection:
		// Mouse selections are not sent to the group; let the offer go.
		if id := a.Uint(); id != 0 {
			w.dropOffer(id)
		}
	case devEvFinished:
		return errors.New("wayland: the data-control device was taken away")
	}
	return a.Err
}

// dropOffer destroys an offer once. It holds the lock while it sends, as
// read does, so a receive never follows the destroy.
func (w *Wayland) dropOffer(id uint32) {
	w.mu.Lock()
	_, live := w.offers[id]
	delete(w.offers, id)
	if live {
		w.d.Send(id, offerDestroy, nil)
	}
	w.mu.Unlock()
	w.d.Forget(id)
}

// selection handles a new clipboard selection: it reads the text in the
// background, since reading our own selection needs the event loop.
func (w *Wayland) selection(id uint32) {
	w.mu.Lock()
	old := w.current
	w.current = id
	types := slices.Clone(w.offers[id])
	// Our writes come back in order, one selection event each. A copy
	// made by another program between them would be taken for ours, and
	// ours for a copy, which the engine then sees as an echo.
	own := id != 0 && w.ownPending > 0
	if own {
		w.ownPending--
	}
	change := w.opened
	w.mu.Unlock()
	if old != 0 && old != id {
		w.dropOffer(old)
	}
	if id == 0 {
		w.mu.Lock()
		w.item, w.has = connector.Item{}, false
		w.mu.Unlock()
		return
	}
	if own {
		return // our own write coming back
	}
	go func() {
		it, ok, err := w.read(id, types)
		if err != nil {
			w.logf("cbb: reading the clipboard: %v", err)
			return
		}
		w.mu.Lock()
		if w.current != id {
			w.mu.Unlock()
			return // already replaced
		}
		w.item, w.has = it, ok
		w.mu.Unlock()
		if ok && change {
			select {
			case w.changes <- it:
			default:
				// The connector is behind; the latest item wins below.
				select {
				case <-w.changes:
				default:
				}
				w.changes <- it
			}
		}
	}()
}

// read receives the text of an offer, or its files, as a file manager
// copies them, or its image if it has no text.
func (w *Wayland) read(id uint32, types []string) (connector.Item, bool, error) {
	for _, t := range fileTypes {
		if !slices.Contains(types, t) {
			continue
		}
		data, err := w.receive(id, t, maxFileList, readTimeout)
		if err != nil {
			return connector.Item{}, false, err
		}
		if paths := filePaths(t, data); len(paths) > 0 {
			return connector.Item{Files: paths}, true, nil
		}
		break // links, not files: the text, if any
	}
	mime, image, limit := "", "", maxText
	for _, t := range textTypes {
		if slices.Contains(types, t) {
			mime = t
			break
		}
	}
	for _, t := range imageTypes {
		if mime == "" && slices.Contains(types, t) {
			mime, image, limit = t, t, connector.MaxImage
		}
	}
	if mime == "" {
		return connector.Item{}, false, nil
	}
	timeout := readTimeout
	if image != "" {
		timeout = imageTimeout
	}
	data, err := w.receive(id, mime, limit, timeout)
	if err != nil {
		return connector.Item{}, false, err
	}
	if image != "" {
		return connector.Item{Image: &connector.Image{Type: image, Data: data}}, len(data) > 0, nil
	}
	it := connector.Item{Text: string(data), Secret: slices.Contains(types, secretType)}
	// Formatted text next to the text, as a browser or an office program
	// copies it; without it, or when it cannot be read, the text alone.
	if len(data) > 0 && !it.Secret && slices.Contains(types, clip.TypeHTML) {
		if html, err := w.receive(id, clip.TypeHTML, connector.MaxHTML, readTimeout); err == nil {
			it.HTML = htmlText(html)
		} else {
			w.logf("cbb: reading the clipboard's formatted text: %v; its text goes alone", err)
		}
	}
	return it, len(data) > 0, nil
}

// receive reads the offer's data of the type mime through a pipe, at most
// limit bytes within timeout; none when the offer is gone.
func (w *Wayland) receive(id uint32, mime string, limit int, timeout time.Duration) ([]byte, error) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		return nil, err
	}
	// Only a non-blocking descriptor takes a deadline, so a program that
	// never writes or never closes cannot hold the read.
	unix.SetNonblock(p[0], true)
	r := os.NewFile(uintptr(p[0]), "clipboard")
	defer r.Close()
	// A newer selection may have destroyed the offer meanwhile; a receive
	// for a destroyed offer is a protocol error that ends the connection.
	w.mu.Lock()
	_, live := w.offers[id]
	var err error
	if live {
		err = w.d.Send(id, offerReceive, (&wl.Request{}).String(mime).FD(p[1]))
	}
	w.mu.Unlock()
	unix.Close(p[1])
	if !live || err != nil {
		return nil, err
	}
	r.SetReadDeadline(time.Now().Add(timeout))
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("the clipboard holds more than %d bytes", limit)
	}
	return data, nil
}

// Current returns what the clipboard holds.
func (w *Wayland) Current() (connector.Item, bool, error) {
	// The first selection may still be reading; give it a moment.
	deadline := time.Now().Add(readTimeout)
	for {
		w.mu.Lock()
		it, has, cur := w.item, w.has, w.current
		w.mu.Unlock()
		if has || cur == 0 || time.Now().After(deadline) {
			return it, has, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Next waits for a change that is not our own.
func (w *Wayland) Next(ctx context.Context) (connector.Item, bool, error) {
	select {
	case it := <-w.changes:
		return it, true, nil
	case err := <-w.errc:
		return connector.Item{}, false, err
	case <-ctx.Done():
		return connector.Item{}, false, ctx.Err()
	}
}

// Write sets the clipboard and the primary selection, so Ctrl+V works in
// applications and Shift+Insert and the middle button in terminals.
func (w *Wayland) Write(text string, secret bool) error {
	return w.write(connector.Item{Text: text, Secret: secret}, nil, nil)
}

// WriteImage sets the clipboard and the primary selection to the image,
// with its text, if any.
func (w *Wayland) WriteImage(img connector.Image, text string) error {
	return w.write(connector.Item{Text: text, Image: &img}, map[string][]byte{img.Type: img.Data}, []string{img.Type})
}

// WriteHTML sets the clipboard and the primary selection to formatted
// text, with its plain text.
func (w *Wayland) WriteHTML(html, text string) error {
	return w.write(connector.Item{Text: text, HTML: html}, map[string][]byte{clip.TypeHTML: []byte(html)}, []string{clip.TypeHTML})
}

// WriteFiles sets the clipboard and the primary selection to the files,
// as a file manager copies them, with their paths as text.
func (w *Wayland) WriteFiles(paths []string) error {
	data := fileData(paths, w.files.start(paths))
	types := []string{uriListType, gnomeFilesType}
	if _, ok := data[portalFilesType]; ok {
		types = append(types, portalFilesType)
	}
	return w.write(connector.Item{Text: strings.Join(paths, "\n"), Files: paths}, data, types)
}

// write sets the selections to the item: its text, if any, and data of
// other types, the first of types the best.
func (w *Wayland) write(it connector.Item, data map[string][]byte, types []string) error {
	if it.Files == nil {
		w.files.stop()
	}
	types = slices.Clone(types)
	if len(types) == 0 || it.Text != "" {
		types = append(types, textTypes...)
	}
	if it.Secret {
		types = append(types, secretType)
	}
	src, err := w.source(it, data, types)
	if err != nil {
		return err
	}
	w.mu.Lock()
	old := w.own
	w.own = src
	w.ownPending++
	w.mu.Unlock()
	if old != 0 {
		defer w.destroySource(old)
	}
	if err := w.d.Send(w.device, devSetSelection, (&wl.Request{}).Uint(src)); err != nil {
		w.mu.Lock()
		w.ownPending--
		w.mu.Unlock()
		return err
	}
	if primary, err := w.source(it, data, types); err == nil {
		w.mu.Lock()
		w.ownPrimary = primary
		w.mu.Unlock()
		w.d.Send(w.device, devSetPrimarySelection, (&wl.Request{}).Uint(primary))
	}
	w.mu.Lock()
	w.item, w.has = it, true
	w.mu.Unlock()
	return nil
}

// source makes a data source that serves the item's text and data for the
// types.
func (w *Wayland) source(it connector.Item, data map[string][]byte, types []string) (uint32, error) {
	var id uint32
	id = w.d.NewID(func(op uint16, a *wl.Args) error {
		switch op {
		case srcEvSend:
			mime := a.String()
			fd := a.FD()
			if a.Err != nil {
				return a.Err
			}
			go func() {
				unix.SetNonblock(fd, true) // so the deadline works
				f := os.NewFile(uintptr(fd), "clipboard")
				defer f.Close()
				switch {
				case mime == secretType:
					f.SetWriteDeadline(time.Now().Add(writeTimeout))
					f.WriteString("secret")
				case data[mime] != nil:
					f.SetWriteDeadline(time.Now().Add(imageTimeout))
					f.Write(data[mime])
				default:
					f.SetWriteDeadline(time.Now().Add(writeTimeout))
					f.WriteString(it.Text)
				}
			}()
		case srcEvCancel:
			w.mu.Lock()
			if w.own == id {
				w.own = 0
			}
			if w.ownPrimary == id {
				w.ownPrimary = 0
			}
			w.mu.Unlock()
			w.destroySource(id)
		}
		return a.Err
	})
	w.mu.Lock()
	w.sources[id] = true
	w.mu.Unlock()
	if err := w.d.Send(w.mgr, mgrCreateSource, (&wl.Request{}).Uint(id)); err != nil {
		return 0, err
	}
	for _, t := range types {
		if err := w.d.Send(id, srcOffer, (&wl.Request{}).String(t)); err != nil {
			return 0, err
		}
	}
	return id, nil
}

// destroySource destroys a source once, however often it is called: by a
// newer write, and by the compositor's cancel. Until the compositor confirms
// with delete_id, a send event may still come for it; its descriptor is
// closed, so it does not stay queued for the next event that takes one.
func (w *Wayland) destroySource(id uint32) {
	w.mu.Lock()
	live := w.sources[id]
	delete(w.sources, id)
	w.mu.Unlock()
	if !live {
		return
	}
	w.d.SetHandler(id, func(op uint16, a *wl.Args) error {
		if op == srcEvSend {
			_ = a.String() // the type
			if fd := a.FD(); fd >= 0 {
				unix.Close(fd)
			}
		}
		return a.Err
	})
	w.d.Send(id, srcDestroy, nil)
}

// ClearIfUnchanged empties the clipboard if it still holds our last write,
// and the primary selection if it still holds ours.
func (w *Wayland) ClearIfUnchanged() error {
	w.mu.Lock()
	own, primary := w.own, w.ownPrimary
	w.mu.Unlock()
	if own != 0 {
		if err := w.d.Send(w.device, devSetSelection, (&wl.Request{}).Uint(0)); err != nil {
			return err
		}
	}
	if primary != 0 {
		w.d.Send(w.device, devSetPrimarySelection, (&wl.Request{}).Uint(0))
	}
	return nil
}
