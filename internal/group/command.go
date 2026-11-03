// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/core"
	"github.com/HunterEwok/cbb/internal/seal"
)

// The types of commands (docs/protocol.md, section 15): CommandMode sets
// the sync mode of one member; CommandHub makes the receiver, a computer
// that is an admin, the group's hub for sync away from home in place of the
// sender, with the sender's clients (section 11, "Moving the hub");
// CommandPaste puts a text where the receiver's focus is, and
// CommandPasteOff turns remote paste off on the receiver (design.md,
// "Remote paste"); CommandAction runs one of the receiver's quick actions
// by its name, and CommandActionsOff turns them all off there (design.md,
// "Quick actions"); CommandAwayOff turns sync away from home off on the
// receiver, which only its own user turns on again (design.md, "Sync away
// from home"). A watch signs only the commands that turn things off and
// action (WatchCommand).
const (
	CommandMode       = "mode"
	CommandHub        = "hub"
	CommandPaste      = "paste"
	CommandPasteOff   = "paste-off"
	CommandAction     = "action"
	CommandActionsOff = "actions-off"
	CommandAwayOff    = "away-off"
)

// WatchCommand reports whether a watch's admin key may sign a command of
// type t (docs/protocol.md, section 10, "Watches"): one that turns remote
// paste, the quick actions or sync away from home off, or that runs a
// quick action, which the receiver's user allows for each kind of signer.
func WatchCommand(t string) bool {
	switch t {
	case CommandPasteOff, CommandActionsOff, CommandAwayOff, CommandAction:
		return true
	}
	return false
}

// MaxActionName bounds the name of a quick action.
const MaxActionName = 32

// ValidActionName reports whether name may name a quick action: 1 to
// MaxActionName of a-z, 0-9 and -, starting with a letter. The name is all
// the network carries; the member defines what it does.
func ValidActionName(name string) bool {
	if name == "" || len(name) > MaxActionName || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, c := range []byte(name) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// The ways a paste command puts its text in: PasteByClipboard writes the
// clipboard and presses the paste keys, PasteByTyping types each character.
const (
	PasteByClipboard = "paste"
	PasteByTyping    = "type"
)

// The longest text of a paste command, in bytes of UTF-8: typing is slow,
// so it takes less.
const (
	MaxPasteText = 1 << 20
	MaxTypeText  = 4 << 10
)

// MaxHubClients bounds the clients a hub command hands over, as many as a
// hub keeps.
const MaxHubClients = 256

// maxCommandBody bounds a command's body: a hub command carries the keys of
// up to MaxHubClients clients. maxPasteBody bounds a paste command's, whose
// text JSON may escape.
const (
	maxCommandBody = 64 << 10
	// commandVersion is the version of command bodies with their orders in
	// the open, sealedCommandVersion of those with their orders sealed to
	// the receiver (docs/protocol.md, section 15, "Sealed commands").
	commandVersion       = 1
	sealedCommandVersion = 2
	maxPasteBody         = 2 << 20
)

// The limits of a command's times: it expires at most CommandLifetime after
// it was signed, and its time may be at most CommandAhead ahead of the
// receiver's clock.
const (
	CommandLifetime = 30 * time.Second
	CommandAhead    = 60 * time.Second
)

// A CommandBody is what a command orders: an admin's order for one member,
// signed like a record and never stored. A Command is signed the same way
// as a Record and has its form.
type CommandBody struct {
	V         int       `json:"v"`
	Type      string    `json:"type"`
	Group     string    `json:"group"`
	By        DeviceID  `json:"by"`
	To        DeviceID  `json:"to"`
	ID        string    `json:"id"` // 128 random bits in hex, for the receiver's replay cache
	TimeMS    int64     `json:"time_ms"`
	ExpiresMS int64     `json:"expires_ms"`
	Mode      string    `json:"mode,omitempty"`   // mode: own, shared, receive or send; paste: PasteByClipboard or PasteByTyping
	Hub       *HubOrder `json:"hub,omitempty"`    // hub: how the receiver is the hub
	Enter     bool      `json:"enter,omitempty"`  // paste: press Enter after the text
	Kind      string    `json:"kind,omitempty"`   // paste: text or secret
	Text      string    `json:"text,omitempty"`   // paste: what to put in
	Action    string    `json:"action,omitempty"` // action: the name of the action
	// Sealed holds the orders above, sealed to the receiver's key, in a
	// command of version 2 (SealCommand); Open opens them.
	Sealed []byte `json:"sealed,omitempty"`
	// Opened reports that Open took the orders out of Sealed.
	Opened bool `json:"-"`
}

// commandOrders are the fields of a command that a sealed command seals:
// all but its open header.
type commandOrders struct {
	Mode   string    `json:"mode,omitempty"`
	Hub    *HubOrder `json:"hub,omitempty"`
	Enter  bool      `json:"enter,omitempty"`
	Kind   string    `json:"kind,omitempty"`
	Text   string    `json:"text,omitempty"`
	Action string    `json:"action,omitempty"`
}

func (b *CommandBody) orders() commandOrders {
	return commandOrders{Mode: b.Mode, Hub: b.Hub, Enter: b.Enter, Kind: b.Kind, Text: b.Text, Action: b.Action}
}

func (b *CommandBody) setOrders(o commandOrders) {
	b.Mode, b.Hub, b.Enter, b.Kind, b.Text, b.Action = o.Mode, o.Hub, o.Enter, o.Kind, o.Text, o.Action
}

// commandAAD is a sealed command's associated data: its open header, each
// string with its length before it (4 bytes, big-endian) and each time in
// 8 bytes, big-endian, after the context "cbb command v2".
// Sealed orders open only under the header they were sealed with, so that
// no other signer can send them again in a command of its own.
func (b *CommandBody) aad() []byte {
	var out []byte
	for _, f := range []string{"cbb command v2", b.Type, b.Group, string(b.By), string(b.To), b.ID} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	out = binary.BigEndian.AppendUint64(out, uint64(b.TimeMS))
	return binary.BigEndian.AppendUint64(out, uint64(b.ExpiresMS))
}

// marshalCommand writes v as JSON without the escapes of HTML, which
// would make a text of brackets six times longer.
func marshalCommand(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// SealCommand returns body, a command with its orders in the open, with
// the orders sealed to public, the receiver's key for sealed messages
// (the seal of its device record): a command of version 2, which only the
// receiver reads. Sign it with SignCommand.
func SealCommand(body CommandBody, public []byte) (CommandBody, error) {
	body.V, body.Sealed, body.Opened = commandVersion, nil, false
	if err := body.check(); err != nil {
		return CommandBody{}, err
	}
	plain, err := marshalCommand(body.orders())
	if err != nil {
		return CommandBody{}, err
	}
	if len(plain) > body.maxBody() {
		return CommandBody{}, errors.New("group: the command is too large")
	}
	sealed, err := seal.Seal(public, body.aad(), plain)
	if err != nil {
		return CommandBody{}, fmt.Errorf("group: sealing the command: %w", err)
	}
	body.setOrders(commandOrders{})
	body.V, body.Sealed = sealedCommandVersion, sealed
	return body, nil
}

// Open takes the orders of a sealed command out of its sealed part with
// secret, this device's secret for sealed messages, and checks them as
// those of a command in the open. A command in the open stays as it is.
func (b *CommandBody) Open(secret []byte) error {
	if b.V != sealedCommandVersion {
		return nil
	}
	if secret == nil {
		return errors.New("group: the command is sealed, and this device has no key for sealed commands")
	}
	plain, err := seal.Open(secret, b.aad(), b.Sealed)
	if err != nil {
		return errors.New("group: the sealed command does not open with this device's key")
	}
	if len(plain) > b.maxBody() {
		return errors.New("group: the command is too large")
	}
	if err := checkStrict(plain); err != nil {
		return err
	}
	var o commandOrders
	if err := json.Unmarshal(plain, &o); err != nil {
		return fmt.Errorf("group: a sealed command: %w", err)
	}
	opened := *b
	opened.V, opened.Sealed = commandVersion, nil
	opened.setOrders(o)
	if err := opened.checkBase64(plain); err != nil {
		return err
	}
	if err := opened.check(); err != nil {
		return err
	}
	opened.V, opened.Opened = sealedCommandVersion, true
	*b = opened
	return nil
}

// A HubOrder is what a hub command tells the new hub: where its clients
// reach it away from home (a forwarder, its own addresses, or both) and the
// clients of the old hub, each with the tunnel key and the preshared key it
// has, so that they move without meeting the new hub first.
type HubOrder struct {
	Forwarder *HubForwarder `json:"forwarder,omitempty"`
	Endpoints []string      `json:"endpoints,omitempty"` // "ip:port" or "[ipv6]:port"
	Clients   []HubClient   `json:"clients,omitempty"`
}

// HubForwarder is the forwarder of a hub command: its address and the pin
// of its key, as cbb global hub -forwarder and -forwarder-key take them.
type HubForwarder struct {
	Endpoint string `json:"endpoint"`
	Key      string `json:"key"`
}

// HubClient is a client the old hub hands over: its device, its WireGuard
// public key and its preshared key, 32 bytes each.
type HubClient struct {
	Device DeviceID `json:"device"`
	Key    []byte   `json:"key"`
	PSK    []byte   `json:"psk"`
}

// NewCommandID returns a random command ID.
func NewCommandID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// SignCommand signs a command with key, a root's key (chain empty) or an
// admin CA key (chain holds the admin CA certificate).
func SignCommand(body CommandBody, key crypto.Signer, chain ...*x509.Certificate) (Record, error) {
	body.V = commandVersion
	if len(body.Sealed) > 0 {
		body.V = sealedCommandVersion
	}
	if err := body.check(); err != nil {
		return Record{}, err
	}
	// A paste's text is sent as it is: without the escapes of HTML.
	data, err := marshalCommand(body)
	if err != nil {
		return Record{}, err
	}
	if len(data) > body.maxBody() {
		return Record{}, errors.New("group: the command is too large")
	}
	sum := sha256.Sum256(data)
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return Record{}, err
	}
	r := Record{Body: data, Sig: sig}
	for _, c := range chain {
		r.Chain = append(r.Chain, c.Raw)
	}
	return r, nil
}

func (b *CommandBody) check() error {
	switch {
	case b.V != commandVersion && b.V != sealedCommandVersion:
		return fmt.Errorf("group: unknown command version %d", b.V)
	case len(b.ID) != 32 || strings.Trim(b.ID, "0123456789abcdef") != "":
		return errors.New("group: a command has no valid ID")
	case b.V == commandVersion && len(b.Sealed) > 0:
		return errors.New("group: a command of version 1 carries a sealed part")
	case b.V == sealedCommandVersion:
		// Its orders are sealed: none of them in the open, and a type
		// they are checked for once opened.
		if len(b.Sealed) == 0 {
			return errors.New("group: a sealed command has no sealed part")
		}
		if b.orders() != (commandOrders{}) {
			return errors.New("group: a sealed command carries orders in the open")
		}
		if !knownCommand(b.Type) {
			return fmt.Errorf("group: unknown command type %q", b.Type)
		}
		return b.checkHeader()
	}
	if b.Type != CommandPaste && (b.Enter || b.Kind != "" || b.Text != "") {
		return fmt.Errorf("group: a %s command carries a paste", b.Type)
	}
	if b.Type != CommandAction && b.Action != "" {
		return fmt.Errorf("group: a %s command names an action", b.Type)
	}
	switch b.Type {
	case CommandMode:
		if b.Mode == "" || b.Hub != nil {
			return errors.New("group: a mode command names no mode")
		}
	case CommandHub:
		if b.Hub == nil || b.Mode != "" {
			return errors.New("group: a hub command has no order")
		}
		if err := b.Hub.check(); err != nil {
			return err
		}
	case CommandPaste:
		if err := b.checkPaste(); err != nil {
			return err
		}
	case CommandPasteOff, CommandActionsOff, CommandAwayOff:
		if b.Mode != "" || b.Hub != nil {
			return fmt.Errorf("group: a %s command carries an order", b.Type)
		}
	case CommandAction:
		if b.Mode != "" || b.Hub != nil {
			return errors.New("group: an action command carries an order")
		}
		if !ValidActionName(b.Action) {
			return fmt.Errorf("group: an action command's name %q is not 1 to %d of a-z, 0-9 and -, starting with a letter", b.Action, MaxActionName)
		}
	default:
		return fmt.Errorf("group: unknown command type %q", b.Type)
	}
	return b.checkHeader()
}

// knownCommand reports whether t is a type of command.
func knownCommand(t string) bool {
	switch t {
	case CommandMode, CommandHub, CommandPaste, CommandPasteOff, CommandAction, CommandActionsOff, CommandAwayOff:
		return true
	}
	return false
}

// checkHeader checks a command's open header past its version and ID: the
// receiver and the signer's device, and the lifetime.
func (b *CommandBody) checkHeader() error {
	if _, err := ParseDeviceID(string(b.To)); err != nil {
		return err
	}
	if _, err := ParseDeviceID(string(b.By)); err != nil {
		return errors.New("group: a command's by is not a device ID")
	}
	// A time before 1970 is no signing time; from it the difference cannot overflow.
	if b.TimeMS < 0 || b.ExpiresMS <= b.TimeMS || b.ExpiresMS-b.TimeMS > CommandLifetime.Milliseconds() {
		return errors.New("group: a command's lifetime is not valid")
	}
	return nil
}

// VerifyCommand checks a command for the member self at the time now: its
// signer is a root on the path, or an admin key under one that is listed,
// neither revoked nor frozen, and whose newest root record gives it the
// command's type in commands (docs/records-v2.md, "What else changes with
// it"); its by is the signer's device; it is for self in this group, has
// not expired, and was not signed in the future. The caller keeps the
// replay cache.
func (s *Records) VerifyCommand(c Record, self DeviceID, now time.Time) (CommandBody, error) {
	var body CommandBody
	body, err := parseCommandBody(c.Body)
	if err != nil {
		return body, err
	}
	if body.Group != s.tag {
		return body, errors.New("group: the command is for another group")
	}
	if body.To != self {
		return body, errors.New("group: the command is for another device")
	}
	signer, anchor, err := s.signerOf(c)
	if err != nil {
		return body, err
	}
	path := s.path()
	if signer == anchor && anchor != KeyHashOf(path[len(path)-1]) {
		return body, errors.New("group: the command's signer is not the group's current root")
	}
	dev, _, ok := s.signerDevice(signer, anchor)
	if signer != anchor {
		if !ok || !dev.Admin || s.Revoked(signer) || s.Frozen(signer) {
			return body, errors.New("group: the command's signer is not an admin of the group")
		}
		if !slices.Contains(dev.Commands, body.Type) {
			return body, fmt.Errorf("group: the command's signer may not sign %s commands", body.Type)
		}
	}
	// by names the signer's device whenever the records show it, and
	// otherwise no device the records show.
	if ok && dev.ID != body.By {
		return body, errors.New("group: a command's by is not the device of its signer")
	} else if !ok && s.listedDevice(body.By) {
		return body, errors.New("group: a command's by names a device that does not hold its signer's key")
	}
	ms := now.UnixMilli()
	switch {
	case body.ExpiresMS <= ms:
		return body, errors.New("group: the command expired; check the clocks of both devices")
	case body.TimeMS > ms+CommandAhead.Milliseconds():
		return body, errors.New("group: the command was signed in the future; check the clocks of both devices")
	}
	return body, nil
}

// parseCommandBody reads and checks a command's body, in the strict form
// of signed bodies.
func parseCommandBody(data []byte) (CommandBody, error) {
	var body CommandBody
	if checked, err := core.CheckBody(core.KindCommand, data); checked {
		if err != nil {
			return body, fmt.Errorf("group: a command: %w", err)
		}
		if err := json.Unmarshal(data, &body); err != nil {
			return body, fmt.Errorf("group: a command: %w", err)
		}
		return body, nil
	}
	if len(data) > maxPasteBody {
		return body, errors.New("group: the command is too large")
	}
	if err := checkStrict(data, "v", "type", "group", "by", "to", "id", "time_ms", "expires_ms"); err != nil {
		return body, err
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return body, fmt.Errorf("group: a command: %w", err)
	}
	if err := body.checkBase64(data); err != nil {
		return body, err
	}
	if len(data) > body.maxBody() {
		return body, errors.New("group: the command is too large")
	}
	return body, body.check()
}

// CommandSigner returns the device whose admin key signed the command c,
// which VerifyCommand took: the device that holds the group's root when
// the root's own key signed it (root true), or the device whose record
// names the admin CA that did. ok is false when no listed device holds the
// key, as for an admin phone whose own record is not here yet.
func (s *Records) CommandSigner(c Record) (dev Device, root, ok bool) {
	signer, anchor, err := s.signerOf(c)
	if err != nil {
		return Device{}, false, false
	}
	return s.signerDevice(signer, anchor)
}

// CommandSender returns whom the limits per sender and the logs count for
// the command c, with by, that VerifyCommand took: by, verified, when the
// records show that its device holds the signing key, and otherwise the
// signing key itself, as "key " and its hash in hex.
func (s *Records) CommandSender(c Record, by DeviceID) (sender string, verified bool) {
	signer, anchor, err := s.signerOf(c)
	if err != nil {
		return "", false
	}
	if dev, _, ok := s.signerDevice(signer, anchor); ok && dev.ID == by {
		return string(by), true
	}
	return "key " + hex.EncodeToString(signer[:]), false
}

// signerOf returns the key that signed r, a command, and the root on the
// path it was signed under: a root's own key with no chain, or the admin
// CA of the chain, certified by that root.
func (s *Records) signerOf(r Record) (signer, anchor KeyHash, err error) {
	sum := sha256.Sum256(r.Body)
	path := s.path()
	switch len(r.Chain) {
	case 0:
		for _, root := range path {
			if pub, ok := root.PublicKey.(*ecdsa.PublicKey); ok && ecdsa.VerifyASN1(pub, sum[:], r.Sig) {
				k := KeyHashOf(root)
				return k, k, nil
			}
		}
		return KeyHash{}, KeyHash{}, errors.New("group: the command is not signed by a root of the group")
	case 1:
		ca, err := x509.ParseCertificate(r.Chain[0])
		if err != nil {
			return KeyHash{}, KeyHash{}, fmt.Errorf("group: the command's admin CA: %w", err)
		}
		pub, ok := ca.PublicKey.(*ecdsa.PublicKey)
		if !ok || !ecdsa.VerifyASN1(pub, sum[:], r.Sig) {
			return KeyHash{}, KeyHash{}, errors.New("group: the command's signature does not verify")
		}
		for _, root := range path {
			if ca.CheckSignatureFrom(root) == nil {
				return KeyHashOf(ca), KeyHashOf(root), nil
			}
		}
		return KeyHash{}, KeyHash{}, errors.New("group: the command's admin CA is not from a root of the group")
	}
	return KeyHash{}, KeyHash{}, errors.New("group: a command's chain holds more than its admin CA")
}

// signerDevice is CommandSigner for the key signer under the root anchor.
// listedDevice reports whether the devices list shows the device id.
func (s *Records) listedDevice(id DeviceID) bool {
	for _, d := range s.Devices() {
		if d.ID == id {
			return true
		}
	}
	return false
}

func (s *Records) signerDevice(signer, anchor KeyHash) (dev Device, root, ok bool) {
	var id DeviceID
	if signer == anchor {
		id, _ = s.RootMember()
		if id == "" {
			return Device{}, true, false
		}
	}
	for _, d := range s.Devices() {
		if (id != "" && d.ID == id) || (id == "" && d.AdminKey != nil && *d.AdminKey == signer) {
			return d, signer == anchor, true
		}
	}
	return Device{}, signer == anchor, false
}

// checkBase64 checks that the bytes of the hub order's clients in data,
// the body b came from, are in the standard form of base64.
func (b *CommandBody) checkBase64(data []byte) error {
	if b.Hub == nil && len(b.Sealed) == 0 {
		return nil
	}
	var raw struct {
		Sealed string `json:"sealed"`
		Hub    struct {
			Clients []struct {
				Key string `json:"key"`
				PSK string `json:"psk"`
			} `json:"clients"`
		} `json:"hub"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("group: a command: %w", err)
	}
	if len(b.Sealed) > 0 {
		if _, err := decodeStrictBase64(raw.Sealed); err != nil {
			return fmt.Errorf("group: a sealed command: %w", err)
		}
	}
	for _, c := range raw.Hub.Clients {
		if _, err := decodeStrictBase64(c.Key); err != nil {
			return fmt.Errorf("group: a hub command: %w", err)
		}
		if _, err := decodeStrictBase64(c.PSK); err != nil {
			return fmt.Errorf("group: a hub command: %w", err)
		}
	}
	return nil
}

func (b *CommandBody) maxBody() int {
	if b.Type == CommandPaste {
		return maxPasteBody
	}
	return maxCommandBody
}

func (b *CommandBody) checkPaste() error {
	limit := MaxPasteText
	switch b.Mode {
	case PasteByClipboard:
	case PasteByTyping:
		limit = MaxTypeText
	default:
		return fmt.Errorf("group: a paste command's way %q is not paste or type", b.Mode)
	}
	switch {
	case b.Hub != nil:
		return errors.New("group: a paste command carries a hub order")
	case b.Kind != "text" && b.Kind != "secret":
		return fmt.Errorf("group: a paste command's kind %q is not text or secret", b.Kind)
	case b.Text == "":
		return errors.New("group: a paste command has no text")
	case len(b.Text) > limit:
		return fmt.Errorf("group: a paste command's text is longer than %d bytes", limit)
	}
	return nil
}

func (o *HubOrder) check() error {
	switch {
	case o.Forwarder == nil && len(o.Endpoints) == 0:
		return errors.New("group: a hub command gives no forwarder and no address")
	case len(o.Endpoints) > 8:
		return errors.New("group: a hub command gives too many addresses")
	case len(o.Clients) > MaxHubClients:
		return errors.New("group: a hub command hands over too many clients")
	case o.Forwarder != nil && (o.Forwarder.Endpoint == "" || o.Forwarder.Key == ""):
		return errors.New("group: a hub command's forwarder has no address or key")
	}
	seen := make(map[DeviceID]bool, len(o.Clients))
	for _, c := range o.Clients {
		if _, err := ParseDeviceID(string(c.Device)); err != nil {
			return err
		}
		if seen[c.Device] {
			return fmt.Errorf("group: a hub command hands over %s twice", c.Device)
		}
		seen[c.Device] = true
		if len(c.Key) != 32 || len(c.PSK) != 32 {
			return fmt.Errorf("group: a hub command's keys for %s are not 32 bytes", c.Device)
		}
	}
	return nil
}
