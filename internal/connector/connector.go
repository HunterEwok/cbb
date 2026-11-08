// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package connector links a desktop clipboard to the service: the Mac's
// pasteboard agent and the Linux desktop connector run it with their own
// clipboard access.
//
// It watches the service's control socket: copies on the desktop go to the
// service, and the writes the service decides on go to the clipboard, in
// order. A secret it wrote is given up when it expires, unless the user
// copied something else meanwhile. A text the group does not carry, such as
// one over 1 MiB, is not sent. When the service goes away, it connects
// again with a growing pause; while the service refuses to be watched, as
// on a device in no group yet, it asks again every refusedWait, so the
// first text after the device joins reaches the clipboard soon.
//
// A connector whose Board is also a Target, or that has a Target of its
// own, offers it for remote paste: the service sends it the pastes an
// admin signed for this device (design.md, "Remote paste"). The tmux and
// console helpers run a connector with a Target and no Board.
package connector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
)

// ErrBoardGone is the error a Board returns when its display connection is
// gone; Run then returns, so the caller can open the display again.
var ErrBoardGone = errors.New("connector: the display connection is gone")

// Item is what the clipboard holds.
type Item struct {
	Text   string
	Secret bool // a password manager marked it; it is never sent
	Remote bool // it came through Universal Clipboard
	// Image is the clipboard's image, on an ImageBoard; Text is then its
	// plain-text alternative, if any.
	Image *Image
	// Files are the paths of the clipboard's files, on a FileBoard.
	Files []string
	// HTML is the clipboard's formatted text, on an HTMLBoard; Text is
	// then its plain text.
	HTML string
}

// media says whether the item is an image, files, or formatted text that
// goes with its plain text (formatted).
func (it Item) media() bool { return it.Image != nil || len(it.Files) > 0 || it.formatted() }

// formatted says whether the item's formatted text goes to the group: a
// copy whose plain text fits as its alternative, and which is no secret.
// The others go as their plain text alone.
func (it Item) formatted() bool {
	return it.HTML != "" && len(it.HTML) <= MaxHTML && utf8.ValidString(it.HTML) && !it.Secret &&
		it.Text != "" && len(it.Text) <= clip.MaxAltText && utf8.ValidString(it.Text)
}

// A Board is a desktop clipboard.
type Board interface {
	// Current returns what the clipboard holds now, and false if no text,
	// image or files.
	Current() (Item, bool, error)
	// Next blocks until the clipboard changes, other than by Write, and
	// returns the new item, or false if it holds no text, image or files.
	Next(ctx context.Context) (Item, bool, error)
	// Write puts a text into the clipboard.
	Write(text string, secret bool) error
	// ClearIfUnchanged empties the clipboard if it still holds what the
	// last Write put there.
	ClearIfUnchanged() error
}

// A Target puts a text where the focus is, for remote paste.
type Target interface {
	// Target names what it pastes into, as the watch request offers it:
	// "desktop", "tmux" or "console"; "" offers nothing, as an X11 board
	// in a Wayland session, whose windows its keys would not reach.
	Target() string
	// Inject puts text where the focus is, by method "paste" (through the
	// clipboard and the paste keys) or "type" (key by key), then presses
	// Enter if enter is set. It checks first that the session is not
	// locked. A secret leaves no copy behind. An error that is a *Refusal
	// says why it would not; any other says how it failed.
	Inject(ctx context.Context, text, method string, enter, secret bool) error
}

// A MediaTarget is a Target that pastes images and files too: it checks
// that the session is not locked, lets write put them into the clipboard,
// presses the paste keys, then Enter if enter is set. The clipboard keeps
// them, as the group's copy they are.
type MediaTarget interface {
	InjectMedia(ctx context.Context, write func() error, enter bool) error
}

type keysGrant struct{}

// WithKeysGrant returns ctx carrying grant, the service's grant of an
// inject for the uinput helper.
func WithKeysGrant(ctx context.Context, grant string) context.Context {
	if grant == "" {
		return ctx
	}
	return context.WithValue(ctx, keysGrant{}, grant)
}

type noLockCheck struct{}

// WithoutLockCheck returns ctx for an inject whose device lets a target
// paste where it cannot tell whether the session is locked.
func WithoutLockCheck(ctx context.Context, yes bool) context.Context {
	if !yes {
		return ctx
	}
	return context.WithValue(ctx, noLockCheck{}, true)
}

// NoLockCheck reports whether the inject that ctx carries out may paste
// where the target cannot tell whether the session is locked.
func NoLockCheck(ctx context.Context) bool {
	yes, _ := ctx.Value(noLockCheck{}).(bool)
	return yes
}

// KeysGrant returns the grant of the inject that ctx carries out, which the
// uinput helper needs to press its keys, or "".
func KeysGrant(ctx context.Context) string {
	g, _ := ctx.Value(keysGrant{}).(string)
	return g
}

// A Refusal is a Target's reason not to paste, such as a locked session.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

// Config configures Run.
type Config struct {
	Socket string // the control socket
	Board  Board  // nil for a paste target without a clipboard
	Target Target // nil to use Board's when it is one
	// Actor runs the quick actions' presets in this session; nil where
	// the service runs them itself. Commands runs the user's own actions
	// here, as a desktop's agent does.
	Actor    Actor
	Commands bool
	// Files is the folder the received files of a FileBoard are kept in,
	// a folder for each copy; "" takes no files.
	Files string
	Logf  func(format string, args ...any)
}

// An Actor runs a quick action (internal/actions) in the user's session.
// An error that is an *actions.Refusal is a reason not to, for the sender;
// any other is a failure.
type Actor interface {
	Run(ctx context.Context, name string) error
}

// target returns the paste target the connector offers, or nil.
func (cfg Config) target() Target {
	if cfg.Target != nil {
		return cfg.Target
	}
	if t, ok := cfg.Board.(Target); ok && t.Target() != "" {
		return t
	}
	return nil
}

const (
	minBackoff  = time.Second
	maxBackoff  = 30 * time.Second
	refusedWait = 2 * time.Second
)

// refusedError is the service's answer to a watch request it turned down.
type refusedError struct{ err error }

func (e *refusedError) Error() string { return e.err.Error() }
func (e *refusedError) Unwrap() error { return e.err }

// Run links the clipboard to the service until ctx is done. A secret it
// wrote is given up when it expires, also when the service connection ended
// meanwhile, and at once when Run returns because ctx is done.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	var exp *expiry
	var cp *copies
	if cfg.Board != nil {
		exp = &expiry{b: cfg.Board, logf: cfg.Logf}
		if _, ok := cfg.Board.(FileBoard); ok {
			cp = newCopies(cfg.Files, cfg.Logf)
		}
	}
	backoff := minBackoff
	refused := "" // the last refusal logged, so a waiting connector logs it once
	for {
		start := time.Now()
		err := session(ctx, cfg, exp, cp)
		if ctx.Err() != nil {
			exp.now()
			return nil
		}
		if errors.Is(err, ErrBoardGone) {
			exp.stop()
			return err
		}
		if time.Since(start) > maxBackoff {
			backoff = minBackoff
		}
		wait := backoff
		var re *refusedError
		if errors.As(err, &re) {
			wait, backoff = refusedWait, minBackoff
			if err.Error() != refused {
				refused = err.Error()
				cfg.Logf("cbb: the service does not take the clipboard yet: %v; asking again every %v", err, wait)
			}
		} else {
			refused = ""
			cfg.Logf("cbb: the service connection ended: %v; trying again in %v", err, wait)
			backoff = min(2*backoff, maxBackoff)
		}
		select {
		case <-ctx.Done():
			exp.now()
			return nil
		case <-time.After(wait):
		}
	}
}

// expiry gives up a written secret when it expires.
type expiry struct {
	b    Board
	logf func(string, ...any)
	mu   sync.Mutex
	t    *time.Timer
}

// set starts the timer for a secret just written, or stops it for a text.
func (e *expiry) set(secret bool, ttl time.Duration) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.t != nil {
		e.t.Stop()
		e.t = nil
	}
	if secret {
		e.t = time.AfterFunc(ttl, e.clear)
	}
}

func (e *expiry) stop() { e.set(false, 0) }

// now gives up a pending secret at once.
func (e *expiry) now() {
	if e == nil {
		return
	}
	e.mu.Lock()
	pending := e.t != nil && e.t.Stop()
	e.t = nil
	e.mu.Unlock()
	if pending {
		e.clear()
	}
}

func (e *expiry) clear() {
	if err := e.b.ClearIfUnchanged(); err != nil {
		e.logf("cbb: giving up an expired secret: %v", err)
	}
}

// session runs one connection to the service. The watch request tells the
// service what the clipboard holds now, without an event.
func session(ctx context.Context, cfg Config, exp *expiry, cp *copies) error {
	c, err := control.Dial(cfg.Socket)
	if err != nil {
		return err
	}
	defer c.Close()
	watchReq := &control.Message{Header: control.Header{Op: control.OpWatch}}
	tgt := cfg.target()
	if tgt != nil {
		watchReq.Inject = tgt.Target()
	}
	watchReq.Act = cfg.Actor != nil || cfg.Commands
	_, watchReq.Images = cfg.Board.(ImageBoard)
	_, watchReq.HTML = cfg.Board.(HTMLBoard)
	watchReq.Files = cp != nil
	if cfg.Board != nil {
		if it, ok, err := cfg.Board.Current(); err == nil && ok && !it.media() {
			if m := report(control.OpClipboard, it); m != nil {
				watchReq.Kind, watchReq.Via, watchReq.Payload = m.Kind, m.Via, m.Payload
			}
		}
	}
	if m, err := c.Do(watchReq); err != nil {
		if m != nil {
			return &refusedError{err}
		}
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()

	var sendMu sync.Mutex
	send := func(m *control.Message) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return c.Send(m)
	}
	errc := make(chan error, 2)
	if cfg.Board != nil {
		go func() { errc <- watch(ctx, cfg.Socket, cfg.Board, send, cfg.Logf) }()
	}
	go func() { errc <- apply(ctx, cfg.Socket, cfg.Board, tgt, cfg.Actor, c, send, exp, cp, cfg.Logf) }()
	err = <-errc
	cancel()
	return err
}

// report makes the message for a clipboard item: a copy, or, for a marked
// secret, only what the clipboard holds, so the service remembers it. It
// returns nil for a text the group does not carry: empty, larger than
// clip.MaxText, or not valid UTF-8.
func report(op string, it Item) *control.Message {
	if it.Text == "" || len(it.Text) > clip.MaxText || !utf8.ValidString(it.Text) {
		return nil
	}
	kind, via := control.KindText, control.ViaCopy
	if it.Secret {
		kind, op = control.KindSecret, control.OpClipboard
	}
	if it.Remote {
		via = control.ViaUniversal
	}
	return &control.Message{Header: control.Header{Op: op, Kind: kind, Via: via}, Payload: []byte(it.Text)}
}

// watch reports clipboard changes to the service. An image or files go on
// the side, and a newer copy stops them.
func watch(ctx context.Context, socket string, b Board, send func(*control.Message) error, logf func(string, ...any)) error {
	stopMedia := func() {}
	defer func() { stopMedia() }()
	for {
		it, ok, err := b.Next(ctx)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		stopMedia()
		if it.media() {
			mctx, cancel := context.WithCancel(ctx)
			stopMedia = cancel
			go func() {
				if err := sendMedia(mctx, socket, it, logf); err != nil && mctx.Err() == nil {
					what := "a copied image"
					switch {
					case it.formatted():
						what = "a copied formatted text"
					case it.Image == nil:
						what = "copied files"
					}
					logf("cbb: %s not synced: %v", what, err)
				}
			}()
			continue
		}
		m := report(control.OpCopied, it)
		if m == nil {
			if it.Text != "" {
				logf("cbb: a copy of %d bytes is not synced: larger than 1 MiB, or not UTF-8 text", len(it.Text))
			}
			continue
		}
		if err := send(m); err != nil {
			return err
		}
	}
}

// apply writes what the service sends into the clipboard, in order, and
// sets the expiry of a secret; it hands remote pastes to the target, one
// at a time, and answers each. An image is fetched on the side, and
// written only if no newer write came meanwhile.
func apply(ctx context.Context, socket string, b Board, tgt Target, act Actor, c *control.Client, send func(*control.Message) error, exp *expiry, cp *copies, logf func(string, ...any)) error {
	var last uint64
	var mu sync.Mutex // orders the writes: a copy's with the newer ones
	stopMedia := func() {}
	defer func() { stopMedia() }()
	for {
		m, err := c.Receive()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if m.Op == control.OpInject && m.Kind == control.KindMedia {
			mu.Lock()
			ans := injectedMedia(ctx, socket, b, tgt, cp, m, logf)
			mu.Unlock()
			if err := send(ans); err != nil {
				return err
			}
			continue
		}
		if m.Op == control.OpInject {
			if err := send(injected(ctx, tgt, m, logf)); err != nil {
				return err
			}
			continue
		}
		if m.Op == control.OpAct {
			if err := send(acted(ctx, act, m, logf)); err != nil {
				return err
			}
			continue
		}
		if b == nil || m.Op != control.OpWrite || m.Seq <= last {
			continue
		}
		last = m.Seq
		stopMedia()
		if m.Kind == control.KindMedia {
			mctx, cancel := context.WithCancel(ctx)
			stopMedia = cancel
			text := string(m.Payload)
			go func() {
				got, err := fetchMedia(mctx, socket, cp, "")
				mu.Lock()
				defer mu.Unlock()
				if mctx.Err() != nil {
					return // a newer write came
				}
				if err != nil {
					err = fmt.Errorf("fetching it: %w", err)
				} else {
					err = writeMedia(b, got)
				}
				if err != nil {
					logf("cbb: the group's copy of images, files or formatted text: %v", err)
					if text == "" {
						return
					}
					err = b.Write(text, false) // its plain-text alternative instead
				}
				if err != nil {
					logf("cbb: writing the clipboard: %v", err)
					return
				}
				exp.set(false, 0)
			}()
			continue
		}
		secret := m.Kind == control.KindSecret
		mu.Lock()
		err = b.Write(string(m.Payload), secret)
		mu.Unlock()
		if err != nil {
			logf("cbb: writing the clipboard: %v", err)
			continue
		}
		ttl := time.Duration(m.TTLMS) * time.Millisecond
		if ttl <= 0 {
			ttl = time.Minute
		}
		exp.set(secret, ttl)
	}
}

// injected carries out an inject and makes its answer. A refusal's reason
// is for the sender as it is; a failure keeps its cause in Detail.
func injected(ctx context.Context, tgt Target, m *control.Message, logf func(string, ...any)) *control.Message {
	ans := &control.Message{Header: control.Header{Op: control.OpInjected, Seq: m.Seq}}
	if tgt == nil {
		ans.Error, ans.Refused = "this watcher does not paste", true
		return ans
	}
	err := tgt.Inject(WithoutLockCheck(WithKeysGrant(ctx, m.Keys), m.NoLockCheck), string(m.Payload), m.Method, m.Enter, m.Kind == control.KindSecret)
	var r *Refusal
	switch {
	case err == nil:
	case errors.As(err, &r):
		ans.Error, ans.Refused = r.Reason, true
	default:
		ans.Error, ans.Detail = "the "+tgt.Target()+" target could not paste", err.Error()
		logf("cbb: a remote paste failed: %v", err)
	}
	return ans
}

// injectedMedia carries out a remote paste of the group's copy of images
// or files that m names: it fetches the copy, and the target writes it
// into the clipboard and presses the paste keys.
func injectedMedia(ctx context.Context, socket string, b Board, tgt Target, cp *copies, m *control.Message, logf func(string, ...any)) *control.Message {
	ans := &control.Message{Header: control.Header{Op: control.OpInjected, Seq: m.Seq}}
	mt, ok := tgt.(MediaTarget)
	if !ok || b == nil {
		ans.Error, ans.Refused = "this paste target pastes only text, not images or files", true
		return ans
	}
	ctx = WithoutLockCheck(WithKeysGrant(ctx, m.Keys), m.NoLockCheck)
	var got media
	err := mt.InjectMedia(ctx, func() error {
		var err error
		if got, err = fetchMedia(ctx, socket, cp, string(m.Payload)); err != nil {
			return fmt.Errorf("fetching the copy: %w", err)
		}
		return writeMedia(b, got)
	}, m.Enter)
	var r *Refusal
	switch {
	case err == nil:
	case errors.As(err, &r):
		ans.Error, ans.Refused = r.Reason, true
	default:
		ans.Error, ans.Detail = "the "+tgt.Target()+" target could not paste the images or files", err.Error()
		logf("cbb: a remote paste of images or files failed: %v", err)
	}
	return ans
}

// acted runs a quick action and makes its answer, as injected does for a
// paste.
func acted(ctx context.Context, act Actor, m *control.Message, logf func(string, ...any)) *control.Message {
	ans := &control.Message{Header: control.Header{Op: control.OpActed, Seq: m.Seq}}
	var err error
	switch {
	case len(m.Command) > 0:
		err = actions.RunCommand(ctx, m.Command)
	case act == nil:
		ans.Error, ans.Refused = "this session runs no presets: the service runs them", true
		return ans
	default:
		err = act.Run(ctx, m.Name)
	}
	var r *actions.Refusal
	switch {
	case err == nil:
	case errors.As(err, &r):
		ans.Error, ans.Refused = r.Reason, true
	default:
		ans.Error, ans.Detail = "the session could not run "+m.Name, err.Error()
		logf("cbb: the action %s failed: %v", m.Name, err)
	}
	return ans
}
