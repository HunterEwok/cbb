// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package clip keeps the group's current clipboard text on one member and
// decides what goes into the member's own clipboard.
//
// Group state. Every copy becomes an Event with a hybrid timestamp, and the
// group's current text is the latest event. Members forward every event the
// first time they see it and exchange their current event in a hello whenever
// a connection starts, so all members converge on the same event whatever the
// delivery order, duplicates or broken connections. A secret travels in a
// hello only as a mark without its text, so the group converges on it too.
//
// The member's own clipboard is a separate, local matter (Local). An event
// that becomes the group's current event is written there when it is live
// (copied at most a minute ago), or, in the window after the member itself
// was away (Rejoin), unless the member copied something before it was in sync
// with the group again. So a member that returns with an old copy does not
// overwrite the clipboards of the others, a member that wakes up gets the
// latest text, and a copy made while away is replaced only by a live copy
// made after it.
//
// Copies reach the engine two ways: Copied for what a clipboard watcher
// reports, which says nothing when the clipboard did not really change, and
// Send for deliberate actions, which always make an event.
//
// The sync mode (Mode) decides whether the copies Copied reports go to the
// group and whether the group's events are written to the local clipboard;
// everything else works the same in every mode.
//
// Durations are measured on a clock that counts sleep and never jumps
// (package uptime). The Engine only decides; the caller does the networking
// and touches the local clipboard.
package clip

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/HunterEwok/cbb/internal/hlc"
	"github.com/HunterEwok/cbb/internal/uptime"
)

const (
	// MaxText is the largest text, in bytes, that the group carries.
	MaxText = 1 << 20
	// DefaultSecretTTL is how long after the copy a secret stays current.
	DefaultSecretTTL = 60 * time.Second
	// DefaultLiveWindow is how long after the copy an event is still written
	// to the clipboards of the members it reaches.
	DefaultLiveWindow = 60 * time.Second
	// DefaultRejoinWindow is how long after Rejoin a new current event is
	// still written although it is old.
	DefaultRejoinWindow = 30 * time.Second
	// DefaultSecretMemory is how long the engine recognises the text of a
	// secret after it expired, so that it stays secret when offered again.
	DefaultSecretMemory = 12 * time.Hour
	// echoWindow is how long a text written to the local clipboard is still
	// recognised when the clipboard reports it back.
	echoWindow = 10 * time.Second
	// maxAge caps the age of an event; older events count as this old.
	maxAge = 365 * 24 * time.Hour
	// maxSkews bounds the number of peers whose clock skew is kept.
	maxSkews = 1024
	// maxSecrets bounds the number of secret texts remembered.
	maxSecrets = 4096
)

// Kind tells normal text from a secret, such as a password, and from
// images and files.
type Kind uint8

const (
	Text   Kind = iota // normal text
	Secret             // kept only in memory, expires, sent in a hello only as a mark
	Media              // images or files: a manifest, and maybe a plain-text alternative
)

// MarshalText implements encoding.TextMarshaler.
func (k Kind) MarshalText() ([]byte, error) {
	switch k {
	case Text:
		return []byte("text"), nil
	case Secret:
		return []byte("secret"), nil
	case Media:
		return []byte("media"), nil
	}
	return nil, fmt.Errorf("clip: unknown kind %d", k)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *Kind) UnmarshalText(b []byte) error {
	switch string(b) {
	case "text":
		*k = Text
	case "secret":
		*k = Secret
	case "media":
		*k = Media
	default:
		return fmt.Errorf("clip: unknown kind %q", b)
	}
	return nil
}

// Via tells how a text reached the member that made the event.
type Via uint8

const (
	Copy      Via = iota // copied on that member
	Phone                // sent from a phone's app
	Universal            // reached a Mac through Universal Clipboard, from an iPhone or another Mac
)

// MarshalText implements encoding.TextMarshaler.
func (v Via) MarshalText() ([]byte, error) {
	switch v {
	case Copy:
		return []byte("copy"), nil
	case Phone:
		return []byte("phone"), nil
	case Universal:
		return []byte("universal-clipboard"), nil
	}
	return nil, fmt.Errorf("clip: unknown via %d", v)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (v *Via) UnmarshalText(b []byte) error {
	switch string(b) {
	case "copy":
		*v = Copy
	case "phone":
		*v = Phone
	case "universal-clipboard":
		*v = Universal
	default:
		return fmt.Errorf("clip: unknown via %q", b)
	}
	return nil
}

// Event is one copy, as it travels between members.
type Event struct {
	ID     string        `json:"id"`     // 128 random bits, 32 lowercase hex characters
	Origin string        `json:"origin"` // the device ID of the member that made the event
	Via    Via           `json:"via,omitempty"`
	Time   hlc.Timestamp `json:"time"`
	Age    int64         `json:"age_ms"` // milliseconds since the copy, when the event was sent
	Kind   Kind          `json:"kind"`
	Text   string        `json:"text"` // empty only in the mark of a secret, and in media without a text
	// Media is the content of a media event, which only it has.
	Media *Manifest `json:"media,omitempty"`
}

// IsMark reports whether e is the mark of a secret: the event without its text.
func (e Event) IsMark() bool { return e.Kind == Secret && e.Text == "" }

// Validate checks an event received from another member.
func (e Event) Validate() error {
	switch {
	case !isID(e.ID):
		return errors.New("clip: bad event ID")
	case !isID(e.Origin):
		return errors.New("clip: bad origin device ID")
	case e.Time.IsZero() || !e.Time.Valid():
		return errors.New("clip: bad timestamp")
	case e.Kind > Media:
		return fmt.Errorf("clip: unknown kind %d", e.Kind)
	case (e.Kind == Media) != (e.Media != nil):
		return errors.New("clip: only a media event has a manifest, and it always does")
	case e.Via > Universal:
		return fmt.Errorf("clip: unknown via %d", e.Via)
	case e.Age < 0:
		return fmt.Errorf("clip: negative event age %d ms", e.Age)
	case e.IsMark():
		return nil
	case e.Kind == Media:
		if err := e.Media.Validate(); err != nil {
			return err
		}
		if e.Text == "" {
			return nil
		}
		if len(e.Text) > MaxAltText {
			return fmt.Errorf("clip: a media event's text of %d bytes is larger than %d", len(e.Text), MaxAltText)
		}
	}
	return checkText(e.Text)
}

// key identifies the content of e for the echo checks.
func (e Event) key() string {
	if e.Media != nil {
		return e.Media.key()
	}
	return e.Text
}

// later reports whether e sorts after f: by timestamp, then by ID, so that
// every member orders any two events the same way.
func (e Event) later(f Event) bool {
	if c := e.Time.Compare(f.Time); c != 0 {
		return c > 0
	}
	return e.ID > f.ID
}

func checkText(s string) error {
	switch {
	case s == "":
		return errors.New("clip: empty text")
	case len(s) > MaxText:
		return fmt.Errorf("clip: text of %d bytes is larger than %d", len(s), MaxText)
	case !utf8.ValidString(s):
		return errors.New("clip: text is not valid UTF-8")
	}
	return nil
}

// isID reports whether s is 32 lowercase hex characters: an event or device ID.
func isID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// NewID returns a random event or device ID.
func NewID() string {
	b := make([]byte, 16)
	rand.Read(b) // never fails, see crypto/rand
	return hex.EncodeToString(b)
}

// Config configures an Engine.
type Config struct {
	Self         string               // the device ID of this member
	Clock        *hlc.Clock           // the member's hybrid clock
	Wall         func() time.Time     // the wall clock, sent in hellos for skew reports; time.Now if nil
	Uptime       func() time.Duration // local durations, counting sleep; uptime.Now if nil
	SecretTTL    time.Duration        // DefaultSecretTTL if zero
	LiveWindow   time.Duration        // DefaultLiveWindow if zero
	RejoinWindow time.Duration        // DefaultRejoinWindow if zero
	SecretMemory time.Duration        // DefaultSecretMemory if zero
	Mode         Mode                 // the sync mode at the start; SetMode changes it
}

// Engine holds the state of one member. It is safe for concurrent use.
type Engine struct {
	cfg Config
	key [32]byte // keys the hashes of written texts and secrets

	mu       sync.Mutex
	current  Event         // the group's current event; the zero Event when there is none
	copiedAt time.Duration // uptime of the copy that made current
	local    localText     // what this member's own clipboard holds
	seen     recentIDs
	written  hashRing     // texts recently written to the local clipboard
	secrets  secretMemory // texts recently known as secrets
	seq      uint64       // counts writes, so the caller can apply them in order
	mode     Mode
	skews    map[string]time.Duration // per connected peer, from its hello

	peers       map[string]int // open connections per peer
	synced      bool           // a hello was reconciled since the last Rejoin, and a connection is up
	offlineCopy bool           // a copy made before this member was back in sync
	rejoined    bool           // Rejoin was called at least once
	rejoinAt    time.Duration  // uptime of the last Rejoin
}

// localText is the text of the member's own clipboard, as far as cbb
// knows it: the last local copy or the last text it wrote there.
type localText struct {
	text  string // empty when unknown, or media without a text
	kind  Kind
	media *Manifest     // with kind Media
	at    time.Duration // uptime of the copy
}

// key identifies the content, as Event.key.
func (l localText) key() string {
	if l.media != nil {
		return l.media.key()
	}
	return l.text
}

// New returns an Engine without a current text.
func New(cfg Config) *Engine {
	if cfg.Wall == nil {
		cfg.Wall = time.Now
	}
	if cfg.Uptime == nil {
		cfg.Uptime = uptime.Now
	}
	if cfg.SecretTTL == 0 {
		cfg.SecretTTL = DefaultSecretTTL
	}
	if cfg.LiveWindow == 0 {
		cfg.LiveWindow = DefaultLiveWindow
	}
	if cfg.RejoinWindow == 0 {
		cfg.RejoinWindow = DefaultRejoinWindow
	}
	if cfg.SecretMemory == 0 {
		cfg.SecretMemory = DefaultSecretMemory
	}
	e := &Engine{
		cfg:     cfg,
		seen:    newRecentIDs(4096),
		written: newHashRing(8),
		secrets: secretMemory{at: make(map[[sha256.Size]byte]time.Duration)},
		skews:   make(map[string]time.Duration),
		peers:   make(map[string]int),
	}
	e.mode = cfg.Mode
	rand.Read(e.key[:])
	return e
}

// Mode returns the sync mode.
func (e *Engine) Mode() Mode {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mode
}

// SetMode changes the sync mode; it applies to the copies and events that
// come after it.
func (e *Engine) SetMode(m Mode) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mode = m
}

// Current returns the group's current event, with its age as of now. It
// reports false when there is none, or when it is a secret that expired or is
// known here only by its mark.
func (e *Engine) Current() (Event, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.live() {
		return Event{}, false
	}
	return e.withAge(), true
}

// Local returns the text of this member's own clipboard, as far as cbb
// knows it, and how long ago it was copied. cbb paste and the iPhone
// button use it. It reports false when unknown or an expired secret; for
// images or files, their plain-text alternative, as a Text.
func (e *Engine) Local() (string, Kind, time.Duration, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Uptime()
	switch {
	case !e.localLive(now) || e.local.kind == Media && e.local.text == "":
		return "", Text, 0, false
	case e.local.kind == Media:
		return e.local.text, Text, now - e.local.at, true
	}
	return e.local.text, e.local.kind, now - e.local.at, true
}

// LocalMedia returns the images or files of this member's own clipboard,
// with their plain-text alternative and how long ago they were copied:
// what cbb paste -o writes. It reports false when the clipboard holds no
// media, as far as cbb knows.
func (e *Engine) LocalMedia() (*Manifest, string, time.Duration, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Uptime()
	if e.local.media == nil {
		return nil, "", 0, false
	}
	return e.local.media, e.local.text, now - e.local.at, true
}

// ClipboardIs records what the local clipboard holds without making an event:
// for a connector that starts and reads the clipboard, and for an item that
// automatic sync skips because a password manager marked it, which the
// engine then also remembers as a secret. An invalid text, such as an empty
// one, records that nothing is known.
func (e *Engine) ClipboardIs(text string, kind Kind) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if checkText(text) != nil || kind != Text && kind != Secret { // media is never only told
		e.local = localText{}
		return
	}
	now := e.cfg.Uptime()
	e.local = localText{text: text, kind: kind, at: now}
	if kind == Secret {
		e.secrets.add(e.sum(text), now)
	}
}

// KnownSecret reports whether text was recently a secret, so that it is not
// treated as a new normal text when it is offered again without the mark.
func (e *Engine) KnownSecret(text string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.secrets.has(e.sum(text), e.cfg.Uptime(), e.cfg.SecretMemory)
}

// Copied records a change that a clipboard watcher reported: a desktop
// connector or the Mac's pasteboard agent. It returns the event to send to
// the connected members, or false when the clipboard did not really change
// for the group:
//   - the text is already what the local clipboard holds, for example offered
//     again by a clipboard manager;
//   - it is the echo of a text this member recently wrote;
//   - it is the group's own text coming back through Universal Clipboard;
//   - it was recently a secret and is offered again without its mark;
//   - the sync mode keeps this member's copies to itself (Mode.Sends): it
//     is recorded as the local clipboard's text only.
func (e *Engine) Copied(text string, kind Kind, via Via) (Event, bool, error) {
	if err := checkCopy(text, kind, via); err != nil {
		return Event{}, false, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Uptime()
	e.settle(now)
	sum := e.sum(text)
	switch {
	case e.localHas(text, now), e.written.has(sum, now, echoWindow):
		return Event{}, false, nil
	case via == Universal && e.live() && e.current.Text == text:
		// A Mac's pasteboard received the group's own text from another
		// Apple device: record it, but it is not a new copy.
		e.local = localText{text: text, kind: e.current.Kind, at: e.copiedAt}
		return Event{}, false, nil
	case kind == Text && e.secrets.has(sum, now, e.cfg.SecretMemory):
		// A clipboard manager restores an earlier secret without its mark.
		e.local = localText{}
		return Event{}, false, nil
	case !e.mode.Sends():
		e.local = localText{text: text, kind: kind, at: now}
		if kind == Secret {
			e.secrets.add(sum, now)
		}
		return Event{}, false, nil
	}
	return e.newEvent(text, kind, via, sum, now), true, nil
}

// Send makes an event from a deliberate action: the iPhone button,
// cbb copy, tmux, or "send even if secret" on a Mac. It always makes an
// event, and the text also goes to this member's own clipboard: Result.Write
// tells whether it must be written there. A text that was recently a secret
// stays a secret.
func (e *Engine) Send(text string, kind Kind, via Via) (Event, Result, error) {
	if err := checkCopy(text, kind, via); err != nil {
		return Event{}, Result{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Uptime()
	e.settle(now)
	sum := e.sum(text)
	if e.secrets.has(sum, now, e.cfg.SecretMemory) {
		kind = Secret
	}
	var res Result
	if !e.localHas(text, now) {
		e.seq++
		res.Write, res.Seq = true, e.seq
		e.written.add(sum, now)
	}
	return e.newEvent(text, kind, via, sum, now), res, nil
}

// SendMedia makes a media event from a deliberate action, such as cbb copy
// FILE, whose content the caller already holds; text is its plain-text
// alternative, or "". As Send, Result.Write tells whether it must go to the
// member's own clipboard.
func (e *Engine) SendMedia(m *Manifest, text string, via Via) (Event, Result, error) {
	ev := Event{Kind: Media, Media: m, Text: text, Via: via}
	if err := checkMedia(ev); err != nil {
		return Event{}, Result{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Uptime()
	e.settle(now)
	var res Result
	if !e.localHolds(ev, now) {
		e.seq++
		res.Write, res.Seq = true, e.seq
		e.written.add(e.sum(ev.key()), now)
	}
	return e.newMedia(ev, now), res, nil
}

// CopiedMedia records images or files that a clipboard watcher reported,
// whose content the caller holds, as Copied does a text: it returns the
// event to send, or false when the clipboard did not really change for the
// group.
func (e *Engine) CopiedMedia(m *Manifest, text string, via Via) (Event, bool, error) {
	ev := Event{Kind: Media, Media: m, Text: text, Via: via}
	if err := checkMedia(ev); err != nil {
		return Event{}, false, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Uptime()
	e.settle(now)
	switch {
	case e.localHolds(ev, now), e.written.has(e.sum(ev.key()), now, echoWindow):
		return Event{}, false, nil
	case via == Universal && e.live() && e.current.Kind == Media && e.current.key() == ev.key():
		e.local = localText{text: e.current.Text, kind: Media, media: e.current.Media, at: e.copiedAt}
		return Event{}, false, nil
	case !e.mode.Sends():
		e.local = localText{text: text, kind: Media, media: m, at: now}
		return Event{}, false, nil
	}
	return e.newMedia(ev, now), true, nil
}

func checkMedia(ev Event) error {
	if ev.Media == nil || ev.Via > Universal {
		return errors.New("clip: bad media or via")
	}
	if err := ev.Media.Validate(); err != nil {
		return err
	}
	if ev.Text != "" && (len(ev.Text) > MaxAltText || checkText(ev.Text) != nil) {
		return errors.New("clip: a media event's text is not valid or too long")
	}
	return nil
}

// newMedia makes a local media event current and the local clipboard's
// content.
func (e *Engine) newMedia(ev Event, now time.Duration) Event {
	ev.ID, ev.Origin, ev.Time = NewID(), e.cfg.Self, e.cfg.Clock.Now()
	e.seen.add(ev.ID)
	e.current, e.copiedAt = ev, now
	e.local = localText{text: ev.Text, kind: Media, media: ev.Media, at: now}
	e.offlineCopy = !e.synced || len(e.peers) == 0
	return ev
}

func checkCopy(text string, kind Kind, via Via) error {
	if err := checkText(text); err != nil {
		return err
	}
	if kind != Text && kind != Secret || via > Universal {
		return errors.New("clip: bad kind or via")
	}
	return nil
}

// newEvent makes a local event current and the local clipboard's text.
func (e *Engine) newEvent(text string, kind Kind, via Via, sum [sha256.Size]byte, now time.Duration) Event {
	ev := Event{ID: NewID(), Origin: e.cfg.Self, Via: via, Time: e.cfg.Clock.Now(), Kind: kind, Text: text}
	e.seen.add(ev.ID)
	e.current, e.copiedAt = ev, now
	e.local = localText{text: text, kind: kind, at: now}
	if kind == Secret {
		e.secrets.add(sum, now)
	}
	e.offlineCopy = !e.synced || len(e.peers) == 0
	return ev
}

// Result tells the caller what to do with a received event.
type Result struct {
	// Forward is the event to send on to the other connected members, except
	// the one it came from. It is nil when there is nothing new to send. The
	// caller adds the time the event waits in a queue to its Age.
	Forward *Event
	// Write tells to write the event's text to the local clipboard.
	Write bool
	// Seq orders the writes: apply a write only if its Seq is greater than
	// that of the last write applied by this Engine.
	Seq uint64
}

// Received applies an event that a peer delivered.
func (e *Engine) Received(ev Event) (Result, error) {
	if err := ev.Validate(); err != nil {
		return Result{}, err
	}
	if e.cfg.Clock.Ahead(ev.Time) {
		return Result{}, errAhead
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.receive(ev), nil
}

// errAhead refuses an event whose time is more than hlc.MaxAhead ahead of
// this member's clock: it would stay the current event and hold every
// clock of the group near the end of time.
var errAhead = errors.New("clip: the event's time is more than 7 days ahead of this device's clock; check the sender's date")

// Hello is what a member sends when a connection starts.
type Hello struct {
	// Wall is the sender's wall clock in milliseconds since the Unix epoch,
	// for reporting clock skew.
	Wall int64 `json:"wall_ms"`
	// Current is the sender's current event, with its age as of now; for a
	// secret, only its mark. It is nil when there is none.
	Current *Event `json:"current,omitempty"`
}

// Connected records an open connection to peer and returns the hello to send
// on it. The caller adds the connection to the set it forwards events to
// before calling Connected, so that no event falls between the hello and the
// first forward; an event that arrives both ways is a harmless duplicate.
func (e *Engine) Connected(peer string) Hello {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.peers[peer]++
	h := Hello{Wall: e.cfg.Wall().UnixMilli()}
	if e.current.ID != "" {
		ev := e.withAge()
		if ev.Kind == Secret {
			ev.Text = ""
		}
		h.Current = &ev
	}
	return h
}

// Disconnected records that a connection to peer is gone.
func (e *Engine) Disconnected(peer string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.peers[peer] > 1 {
		e.peers[peer]--
		return
	}
	delete(e.peers, peer)
	delete(e.skews, peer)
	if len(e.peers) == 0 {
		e.settle(e.cfg.Uptime())
		e.synced = false
	}
}

// Rejoin records that this member itself was away: the service just started,
// or the machine woke up. The caller first closes the connections from before
// the absence. Until a hello is reconciled again, copies count as made while
// away; and for the next RejoinWindow an event that becomes the group's
// current event is written to the local clipboard even when it is old, unless
// such a copy was made. So is the current event when a hello brings it again
// after it was taken before Rejoin, as by a hello that came right after
// waking up. A member that only lost its peers, because they went away, must
// not call Rejoin: its clipboard is kept.
func (e *Engine) Rejoin() {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Uptime()
	e.settle(now)
	e.rejoined, e.rejoinAt, e.synced = true, now, false
}

// Reconcile applies the hello that a peer sent when the connection started.
func (e *Engine) Reconcile(peer string, h Hello) (Result, error) {
	if h.Current != nil {
		if err := h.Current.Validate(); err != nil {
			return Result{}, err
		}
		if h.Current.Kind == Secret && !h.Current.IsMark() {
			return Result{}, errors.New("clip: a hello must not carry a secret's text")
		}
		if e.cfg.Clock.Ahead(h.Current.Time) {
			// Taken as no current event; the connection stays.
			h.Current = nil
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, known := e.skews[peer]; h.Wall > 0 && (known || len(e.skews) < maxSkews) {
		e.skews[peer] = time.Duration(h.Wall-e.cfg.Wall().UnixMilli()) * time.Millisecond
	}
	var res Result
	if h.Current != nil {
		res = e.receive(*h.Current)
	}
	e.synced = len(e.peers) > 0
	return res, nil
}

// Skews returns, for each connected peer, how far its wall clock was ahead of
// this member's (negative when behind) when its hello arrived.
func (e *Engine) Skews() map[string]time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]time.Duration, len(e.skews))
	for k, v := range e.skews {
		out[k] = v
	}
	return out
}

func (e *Engine) receive(ev Event) Result {
	now := e.cfg.Uptime()
	// Cap before converting: a huge age_ms would overflow time.Duration.
	age := time.Duration(min(ev.Age, maxAge.Milliseconds())) * time.Millisecond
	if e.seen.has(ev.ID) {
		if e.current.ID != ev.ID {
			return Result{}
		}
		// The full event may follow the mark of the same secret: take its text.
		if e.current.IsMark() && !ev.IsMark() {
			e.current, e.copiedAt = ev, now-age
			e.secrets.add(e.sum(ev.Text), now)
			fwd := ev
			return e.decideWrite(Result{Forward: &fwd}, now)
		}
		// A member that took the current event before it noticed that it
		// had been away, such as a hello right after waking up, writes it
		// when it is back in sync.
		if e.rejoined && !e.synced && e.inRejoinWindow(now) {
			return e.decideWrite(Result{}, now)
		}
		return Result{}
	}
	e.cfg.Clock.Observe(ev.Time)
	e.seen.add(ev.ID)
	if ev.Kind == Secret && !ev.IsMark() {
		e.secrets.add(e.sum(ev.Text), now)
	}
	fwd := ev
	res := Result{Forward: &fwd}
	if e.current.ID != "" && !ev.later(e.current) {
		return res
	}
	e.current, e.copiedAt = ev, now-age
	return e.decideWrite(res, now)
}

// decideWrite decides whether the new current event goes to the local
// clipboard: when the sync mode lets the group's copies in, and the event is
// live, or in the rejoin window when no copy was made before this member was
// back in sync.
func (e *Engine) decideWrite(res Result, now time.Duration) Result {
	e.settle(now)
	if !e.mode.Receives() || !e.live() || e.localHolds(e.current, now) {
		return res
	}
	if now-e.copiedAt > e.cfg.LiveWindow && (!e.inRejoinWindow(now) || e.offlineCopy) {
		return res
	}
	e.seq++
	res.Write, res.Seq = true, e.seq
	e.local = localText{text: e.current.Text, kind: e.current.Kind, media: e.current.Media, at: e.copiedAt}
	e.written.add(e.sum(e.current.key()), now)
	e.offlineCopy = false
	return res
}

// settle forgets a copy made while away once it no longer matters: the
// member is in sync again and the rejoin window has closed.
func (e *Engine) settle(now time.Duration) {
	if e.offlineCopy && e.synced && !e.inRejoinWindow(now) {
		e.offlineCopy = false
	}
}

func (e *Engine) inRejoinWindow(now time.Duration) bool {
	return e.rejoined && now-e.rejoinAt < e.cfg.RejoinWindow
}

// live reports whether the group's current event has a text that may be used.
func (e *Engine) live() bool {
	if e.current.ID == "" || e.current.IsMark() {
		return false
	}
	return e.current.Kind != Secret || e.cfg.Uptime()-e.copiedAt < e.cfg.SecretTTL
}

func (e *Engine) localLive(now time.Duration) bool {
	if e.local.text == "" && e.local.media == nil {
		return false
	}
	return e.local.kind != Secret || now-e.local.at < e.cfg.SecretTTL
}

func (e *Engine) localHas(text string, now time.Duration) bool {
	return e.localLive(now) && e.local.media == nil && e.local.text == text
}

// localHolds reports whether the local clipboard holds the content of ev.
func (e *Engine) localHolds(ev Event, now time.Duration) bool {
	return e.localLive(now) && (e.local.media != nil) == (ev.Media != nil) && e.local.key() == ev.key()
}

// withAge returns the current event with its age as of now.
func (e *Engine) withAge() Event {
	ev := e.current
	ev.Age = min(max(0, e.cfg.Uptime()-e.copiedAt), maxAge).Milliseconds()
	return ev
}

func (e *Engine) sum(text string) [sha256.Size]byte {
	m := hmac.New(sha256.New, e.key[:])
	m.Write([]byte(text))
	var s [sha256.Size]byte
	m.Sum(s[:0])
	return s
}

// hashRing remembers keyed hashes of texts with the time they were seen.
type hashRing struct {
	sums []entry
	next int
}

type entry struct {
	sum  [sha256.Size]byte
	at   time.Duration
	used bool
}

func newHashRing(n int) hashRing { return hashRing{sums: make([]entry, n)} }

func (r *hashRing) add(sum [sha256.Size]byte, at time.Duration) {
	r.sums[r.next] = entry{sum: sum, at: at, used: true}
	r.next = (r.next + 1) % len(r.sums)
}

func (r *hashRing) has(sum [sha256.Size]byte, now, within time.Duration) bool {
	for _, e := range r.sums {
		if e.used && now-e.at <= within && e.sum == sum {
			return true
		}
	}
	return false
}

// secretMemory remembers keyed hashes of secret texts with the time they
// were last seen, up to maxSecrets; the oldest go first.
type secretMemory struct {
	at map[[sha256.Size]byte]time.Duration
}

func (m *secretMemory) add(sum [sha256.Size]byte, now time.Duration) {
	if _, known := m.at[sum]; !known && len(m.at) >= maxSecrets {
		var oldest [sha256.Size]byte
		first := true
		for s, at := range m.at {
			if first || at < m.at[oldest] {
				oldest, first = s, false
			}
		}
		delete(m.at, oldest)
	}
	m.at[sum] = now
}

func (m *secretMemory) has(sum [sha256.Size]byte, now, within time.Duration) bool {
	at, ok := m.at[sum]
	return ok && now-at <= within
}

// recentIDs remembers the most recent event IDs, up to a fixed number.
type recentIDs struct {
	set  map[string]struct{}
	ring []string
	next int
}

func newRecentIDs(n int) recentIDs {
	return recentIDs{set: make(map[string]struct{}, n), ring: make([]string, n)}
}

func (r *recentIDs) has(id string) bool {
	_, ok := r.set[id]
	return ok
}

func (r *recentIDs) add(id string) {
	if r.has(id) {
		return
	}
	if old := r.ring[r.next]; old != "" {
		delete(r.set, old)
	}
	r.ring[r.next] = id
	r.set[id] = struct{}{}
	r.next = (r.next + 1) % len(r.ring)
}
