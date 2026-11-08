// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package control is the protocol of the service's local control socket,
// which the command line, tmux, the desktop connector, the Mac's pasteboard
// agent and the console helper use.
//
// Every message is a JSON header on one line, followed by Len bytes of raw
// payload, usually a clipboard text. A client sends a request and reads the
// answers; a watcher keeps its connection open, receives writes and reports
// copies on it. Who may connect is decided by the socket's file permissions:
// only root and the cbb group.
package control

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/HunterEwok/cbb/internal/release"
)

const (
	maxHeader  = 64 << 10
	maxPayload = 1<<20 + 64 // a text of up to 1 MiB
)

// Operations.
const (
	OpCopy        = "copy"           // client → service: make an event from a deliberate action
	OpPaste       = "paste"          // client → service: ask for the member's own clipboard text
	OpStatus      = "status"         // client → service: ask for the status
	OpNew         = "new"            // client → service: create a group with this device as its root
	OpPair        = "pair"           // client → service: open a pairing window; answers follow
	OpJoin        = "join"           // client → service: join a group with a code
	OpDevices     = "devices"        // client → service: list the group's devices
	OpRevoke      = "revoke"         // client → service: remove the device Name names (a name or a device ID)
	OpRename      = "rename"         // client → service: give the device Name names the name NewName
	OpFreeze      = "freeze"         // client → service: freeze the admin computer Name names
	OpThaw        = "thaw"           // client → service: on the root, unfreeze the admin computer Name names
	OpResolve     = "resolve"        // client → service: on the root, void both histories of every key that signed two; Name answers whose
	OpAway        = "away"           // client → service: Name "on", "off", "hub", "hub-off", "move" (to Device) or "relay": sync away from home
	OpSync        = "sync"           // client → service: Name "on" or "off" (for ForMS, 0 for until turned on): sync this device's clipboard with the group, or with Device as an admin (no ForMS)
	OpNetwork     = "network"        // client → service: take the networks this device is on now as known
	OpAdmin       = "admin"          // client → service: on the root, make the device Name names an admin
	OpTakeover    = "takeover"       // client → service: on an admin, take the group over from the lost root Name names
	OpDelay       = "takeover-delay" // client → service: on the root, set how long a claim waits to Value, a duration
	OpKeyLevel    = "key-level"      // client → service: on the root, set the group's key level to Value (proven, hardware or files); answer: Below
	OpIncoming    = "incoming"       // client → service: on the root or an admin, set how long a copy from another device stays live to Value, a duration
	OpRecovery    = "recovery"       // client → service: claim the group with its recovery key, the payload the sheet's text or QR code, or with Name RecoveryCard the YubiKey's PIN
	OpHandover    = "handover"       // client → service: on the root, hand the group to the admin Name names, whose claim then takes effect at once
	OpHubs        = "hubs"           // client → service: on the root or an admin with hub, sign the table of main hubs Hubs (names or device IDs)
	OpLeave       = "leave"          // client → service: leave the group: delete its keys and files, keep the settings, restart in no group
	OpInvite      = "invite"         // client → service: make a remote invitation on the hub; answers and a question follow
	OpAnswer      = "answer"         // client → service: Consent answers the service's question during a request
	OpWatch       = "watch"          // watcher → service: start watching, with what the clipboard holds now
	OpCopied      = "copied"         // watcher → service: the clipboard changed
	OpClipboard   = "clipboard"      // watcher → service: what the clipboard holds, without a change
	OpWrite       = "write"          // service → watcher: put this text into the clipboard; with Kind media, the images paste-media gives
	OpPasteOn     = "paste-on"       // client → service: as an admin, have the member Device put the payload where its focus is
	OpReceive     = "paste-receive"  // client → service: Name "on" or "off": remote paste on this device, or off on Device or All
	OpInject      = "inject"         // service → watcher: put the payload where the focus is, a remote paste
	OpInjected    = "injected"       // watcher → service: how the inject with Seq ended: Error empty, or why not
	OpActionSet   = "action-set"     // client → service: set this device's quick action Actions[0]: on or off, and for whom
	OpActionOn    = "action-on"      // client → service: as an admin, have the member Device run its action Name
	OpActionOff   = "actions-off"    // client → service: as an admin, turn every quick action off on Device or All
	OpActionDel   = "action-remove"  // client → service: remove this device's own action Name
	OpAct         = "act"            // service → watcher: run the quick action Name in the watcher's session
	OpActed       = "acted"          // watcher → service: how the act with Seq ended: Error empty, or why not
	OpReply       = "reply"          // service → client: the answer to a request
	OpCopyMedia   = "copy-media"     // client → service: copy images or files, the payload their plain-text alternative; part and data messages follow
	OpPart        = "part"           // client → service in copy-media, or a reply in paste-media: the next part (Part), its bytes in data messages; Done ends the parts
	OpData        = "data"           // client → service in copy-media, or a reply in paste-media: the next bytes of the part
	OpPasteMedia  = "paste-media"    // client → service: ask for the images or files of the member's own clipboard; parts follow
	OpCopiedMedia = "copied-media"   // watcher → service: the clipboard changed to an image, as copy-media carries it
	OpConfig      = "config"         // client → service: show the settings, or set the setting Name to Value
	OpRelease     = "release"        // client → service: the payload a Release in JSON, a signed release cbb update fetched, for the group
	OpReleaseFile = "release-file"   // client → service: an archive of the held release that cbb update installed, Value its SHA-256 and Part its size, its bytes in data messages
	OpReleaseGet  = "release-get"    // client → service: the archive of the held release whose SHA-256 is Value, from this device or its peers; a reply with Part, its bytes, then Done
	OpReleaseHeld = "release-held"   // client → service: the signed release this device holds, a Release in JSON, for cbb update when no update server answers
	OpEntries     = "entries"        // client → service: the signed entry points, keys.json and entries.json in JSON ({keys, entries}), from cbb update or a string, for the group
	OpEntriesGet  = "entries-get"    // client → service: the signed entry points this device holds, in the same JSON
	OpUpdateWay   = "update-way"     // client → service: the VLESS settings, a tunnel.VLESS in JSON, by which cbb update reaches the mirror on the hub's forwarder; empty without VLESS
	OpReleaseWant = "release-want"   // client → service: on a hub, the names of the held release's archives the group's members update from and it does not hold, in JSON, for cbb update to download
	OpKeyboard    = "keyboard"       // client → service: Name "on" (Keyboard the settings), "off", "pair", "type" (the payload) or "" (status): this computer as a Bluetooth keyboard
	OpKeys        = "keys"           // uinput helper (root) → service: may it press Name ("paste" or "enter") for the user Value, under the grant Keys of an inject
	OpMute        = "mute"           // client → service: as an admin, mute Device for ForMS, 0 for until unmute: its copies then stay its own
	OpUnmute      = "unmute"         // client → service: as an admin, end the mute of Device
	OpRemote      = "remote"         // client → service: Name "add" (Address, Value the kind, NewName, Consent), "code" (Code), "cancel", "remove", "pastes" (Value on or off), "type" (the payload), for the TV Device, or "" (status): this device as a TV's remote
)

// RecoveryCard is OpRecovery's Name when the recovery key is on a YubiKey.
const RecoveryCard = "yubikey"

// Kinds and the ways a text came, as Header.Kind and Header.Via carry them.
const (
	KindText     = "text"
	KindSecret   = "secret"
	KindMedia    = "media"               // images or files
	ViaCopy      = "copy"                // copied on the member
	ViaPhone     = "phone"               // sent from a phone's app
	ViaUniversal = "universal-clipboard" // reached a Mac through Universal Clipboard
)

// Header is the JSON line of a message. Fields that an operation does not
// use stay empty.
type Header struct {
	Op    string `json:"op"`
	Kind  string `json:"kind,omitempty"`   // KindText or KindSecret; text if empty
	Via   string `json:"via,omitempty"`    // ViaCopy, ViaPhone or ViaUniversal; copy if empty
	Seq   uint64 `json:"seq,omitempty"`    // the order of writes
	TTLMS int64  `json:"ttl_ms,omitempty"` // how long a written secret may stay in the clipboard
	Len   int    `json:"len,omitempty"`    // the length of the payload
	Error string `json:"error,omitempty"`  // a failed request
	// Detail is the underlying error of a failed request, which the
	// command shows in a debug build or with CBB_DEBUG=1.
	Detail string `json:"detail,omitempty"`
	Done   bool   `json:"done,omitempty"` // the last answer to a request

	// Remote paste (design.md, "Remote paste"). Method is "paste" (the
	// clipboard and the paste keys) or "type"; Enter presses Enter after
	// it; Console allows text consoles and root's tmux; All turns remote
	// paste off on every member; Inject, in a watch request, is the target
	// the watcher offers ("desktop", "tmux" or "console"), none if empty;
	// PasteOnly, in a watch request, says the watcher holds no clipboard
	// and only pastes, like the Mac app; Refused, in an injected answer,
	// says the target refused rather than failed. NoLockCheck, in
	// paste-receive on and in an inject, lets a target paste where it
	// cannot tell whether the session is locked.
	Method      string `json:"method,omitempty"`
	Enter       bool   `json:"enter,omitempty"`
	Console     bool   `json:"console,omitempty"`
	All         bool   `json:"all,omitempty"`
	Inject      string `json:"inject,omitempty"`
	PasteOnly   bool   `json:"paste_only,omitempty"`
	Refused     bool   `json:"refused,omitempty"`
	NoLockCheck bool   `json:"no_lock_check,omitempty"`
	// Keys, in an inject to a desktop session, is the grant that the
	// session's desktop connector hands the uinput helper, which asks the
	// service with keys whether it may press the paste's keys.
	Keys string `json:"keys,omitempty"`

	// Actions: in action-set, the one action to set. Act, in a watch
	// request, says the watcher runs the quick actions in its session, as
	// the agent does on a Mac and on Windows.
	// Command, in act, is the program and arguments of the user's own
	// action Name.
	Actions []Action `json:"actions,omitempty"`
	Act     bool     `json:"act,omitempty"`
	Command []string `json:"command,omitempty"`

	// Hubs, in hubs, are the group's main hubs in the order they serve, by
	// name or device ID.
	Hubs []string `json:"hubs,omitempty"`
	// Below names, in the answer to key-level, the admins and hubs whose
	// keys the new level would not let in: they stay until removed.
	Below []string `json:"below,omitempty"`

	// Keyboard, in keyboard on, are the Bluetooth keyboard's settings.
	Keyboard *Keyboard `json:"keyboard,omitempty"`

	Code         string   `json:"code,omitempty"`        // pairing code
	Fingerprint  string   `json:"fingerprint,omitempty"` // of the joiner's certificate, for its QR code
	Address      string   `json:"address,omitempty"`     // a member's address for join
	Addrs        []string `json:"addrs,omitempty"`       // where a listening join waits, for its QR code
	Listen       bool     `json:"listen,omitempty"`      // join: wait for a member to dial this device
	Admins       bool     `json:"admins,omitempty"`      // pair: the window may make a phone an admin (on the root)
	Name         string   `json:"name,omitempty"`        // a device name
	NewName      string   `json:"new_name,omitempty"`    // rename: the device's new name
	Device       string   `json:"device,omitempty"`      // mode: the device, by name or ID, whose mode an admin sets, this device if empty; away move: the new hub
	Expires      int      `json:"expires,omitempty"`     // seconds a pairing window stays open; for a listening join, seconds to wait
	Port         int      `json:"port,omitempty"`        // away hub: the UDP port; 0 for the default
	Forwarder    string   `json:"forwarder,omitempty"`   // away hub: the forwarder's address, with its key in ForwarderKey
	ForwarderKey string   `json:"forwarder_key,omitempty"`
	Relay        string   `json:"relay,omitempty"` // away relay: the relay's address, with its key in RelayKey
	RelayKey     string   `json:"relay_key,omitempty"`
	Obfuscate    bool     `json:"obfuscate,omitempty"`    // away hub: speak AmneziaWG instead of plain WireGuard
	VLESS        bool     `json:"vless,omitempty"`        // away hub: the clients come only over VLESS to the forwarder
	Keep         bool     `json:"keep,omitempty"`         // away hub: keep the hub's addresses, port and forwarder where the message gives none
	ForwardOnly  bool     `json:"forward_only,omitempty"` // away hub with a device: make it a hub that only passes copies on, reading none
	Consent      bool     `json:"consent,omitempty"`      // away on, join with an invitation, admin of a device with file keys: the user agreed to what the warning says; answer: yes
	Force        bool     `json:"force,omitempty"`        // away hub-off: stop the hub even though the group has no other one
	Invite       string   `json:"invite,omitempty"`       // the text of a remote invitation: made by invite, used by join
	Joining      *Joining `json:"joining,omitempty"`      // invite: a device to confirm, before it is admitted
	Status       *Status  `json:"status,omitempty"`
	Devices      []Device `json:"devices,omitempty"`

	// Images and files: in a part message, the part whose bytes follow;
	// Value, in config, the setting's new value. Images, Files and HTML,
	// in a watch request, say the watcher's clipboard takes and gives
	// images, files, and formatted text.
	Part  *Part  `json:"part,omitempty"`
	Value string `json:"value,omitempty"`
	// ForMS, in mute, is how long, 0 for until unmute.
	ForMS  int64 `json:"for_ms,omitempty"`
	Images bool  `json:"images,omitempty"`
	Files  bool  `json:"files,omitempty"`
	HTML   bool  `json:"html,omitempty"`
}

// Part is a part of a copy of images or files, as copy-media and
// paste-media carry it: clipboard data of a Type (image/png, image/jpeg,
// text/html), or a file or folder at a Path, names joined by "/".
type Part struct {
	Type string `json:"type,omitempty"`
	Path string `json:"path,omitempty"`
	Dir  bool   `json:"dir,omitempty"`
	Size int64  `json:"size,omitempty"`
}

// Release is a signed release (docs/protocol.md, section 16): keys.json,
// the channel file and release.json, each as published. It goes in the
// payload, which may be larger than a header.
type Release struct {
	Keys    release.File `json:"keys"`
	Channel release.File `json:"channel"`
	Release release.File `json:"release"`
}

// Claim is a claim to take the group over (docs/protocol.md, section 10,
// "Handing the group over"), for cbb status and the apps.
type Claim struct {
	// By names the admin that claims the group: its device's name, or its
	// key hash when no device record names it.
	By string `json:"by"`
	// State is pending, competing or disputed.
	State string `json:"state"`
	// LeftMS is how long a pending claim still waits on this member, 0
	// while it does not know.
	LeftMS int64 `json:"left_ms,omitempty"`
}

// Conflict is a conflict of the group's records, for cbb status and the
// apps.
type Conflict struct {
	// Kind is admins (admins that removed or froze each other without
	// seeing it), claims (two claims) or two_histories (a key that signed
	// two histories).
	Kind string `json:"kind"`
	// Devices name the devices of the signers involved, or their key
	// hashes when no device record names them.
	Devices []string `json:"devices"`
}

// Status describes the service for cbb status.
type Status struct {
	Device string `json:"device"`
	Group  string `json:"group,omitempty"` // the group tag; empty when in no group
	// LeftOldGroup says that the device left a group made before 0.6 when
	// the service started, since 0.6 does not read its records: the group
	// is set up again.
	LeftOldGroup bool `json:"left_old_group,omitempty"`
	// KeyLevel is the group's key level: which keys may be its root, an
	// admin or a hub (proven, hardware or files).
	KeyLevel string `json:"key_level,omitempty"`
	// IncomingMS is how long a copy from another device stays live after
	// it arrives, as the group's records set it (one minute by default):
	// written to the clipboard until then, never after.
	IncomingMS int64 `json:"incoming_ms,omitempty"`
	// KeyProblem says why this device's own key is in a file although the
	// machine has a TPM it may use; empty when nothing failed.
	KeyProblem string `json:"key_problem,omitempty"`
	// Removed says that the group's records revoke this device: its
	// members refuse it until it pairs again.
	Removed bool `json:"removed,omitempty"`
	// Frozen says that the records freeze this admin computer's admin key:
	// the others refuse it until the group's root or an admin phone
	// unfreezes it. Removed is false then.
	Frozen bool `json:"frozen,omitempty"`
	// TakenOverBy names the admin that took the group over from this
	// device, the group's root computer, while it was away; removing that
	// admin here undoes it. Removed is false then.
	TakenOverBy string `json:"taken_over_by,omitempty"`
	// Stop says how far the group's records stop the exchange: "secrets"
	// (no member sends a secret) or "full" (the members exchange records
	// only), empty when nothing stops; Claims and Conflicts say why
	// (docs/protocol.md, section 10, "Stopping the exchange").
	Stop string `json:"stop,omitempty"`
	// Claims are the claims to take the group over that wait or stop the
	// group: pending, competing or disputed.
	Claims []Claim `json:"claims,omitempty"`
	// Conflicts are the conflicts that stop the group until its root
	// decides.
	Conflicts []Conflict `json:"conflicts,omitempty"`
	// Newer is how many records of a later version this member keeps: an
	// update of CBB reads them.
	Newer int `json:"newer,omitempty"`
	// CertEndsMS is when this device's member certificate ends, in Unix
	// milliseconds: the members refuse it afterwards, unless an admin
	// renews it before.
	CertEndsMS int64  `json:"cert_ends_ms,omitempty"`
	Role       string `json:"role"`
	OS         string `json:"os,omitempty"` // this device's operating system
	// Mode is shared while sync is on and own while it is off; "" when in
	// no group. SyncUntilMS is when sync that is off turns on again by
	// itself, in Unix milliseconds; 0 for until it is turned on.
	Mode        string `json:"mode,omitempty"`
	SyncUntilMS int64  `json:"sync_until_ms,omitempty"`
	// Muted says that an admin muted this device, its copies its own,
	// until MutedUntilMS in Unix milliseconds, 0 for until an admin
	// unmutes it.
	Muted        bool     `json:"muted,omitempty"`
	MutedUntilMS int64    `json:"muted_until_ms,omitempty"`
	Peers        []Device `json:"peers,omitempty"`
	// Unreached lists the members at home that could not connect to this
	// device's member port and sync with it only because it dials them:
	// a firewall here likely drops the port.
	Unreached []string `json:"unreached,omitempty"`
	Port      int      `json:"port,omitempty"` // the member port
	// Quiet lists the interfaces on networks this device has not met its
	// group on: it does not publish itself or take connections there.
	Quiet []string `json:"quiet,omitempty"`
	Away  *Away    `json:"away,omitempty"` // sync away from home; nil while it is off
	// Paste is remote paste on this device; nil when in no group.
	Paste *Paste `json:"paste,omitempty"`
	// Keyboard is this computer as a Bluetooth keyboard; nil where there
	// is none (not Linux) and it was never turned on.
	Keyboard *Keyboard `json:"keyboard,omitempty"`
	// TVs are the TVs this device is the remote of (cbb remote).
	TVs []TV `json:"tvs,omitempty"`
	// Actions are this device's quick actions, the presets first, as its
	// user set them; empty when in no group.
	Actions []Action `json:"actions,omitempty"`
	// Media is images and files on this device: its limits and the copy
	// being fetched; nil when in no group.
	Media   *Media `json:"media,omitempty"`
	Version string `json:"version"`
	// Release is the newest signed release the group passed around, and
	// Update that version again when this device runs an older one; ""
	// when none checked out.
	Release string `json:"release,omitempty"`
	Update  string `json:"update,omitempty"`
}

// Media describes images and files on this device: the largest copy it
// sends or fetches at home and away from home, in bytes, and the copy it is
// fetching, if any.
type Media struct {
	MaxCopy     int64 `json:"max_copy"`
	MaxCopyAway int64 `json:"max_copy_away"`
	// Fetching is the size of the copy being fetched, Fetched how much of
	// it has arrived; Failed says why the last copy was not fetched.
	Fetching int64  `json:"fetching,omitempty"`
	Fetched  int64  `json:"fetched,omitempty"`
	From     string `json:"from,omitempty"` // the device it comes from
	Failed   string `json:"failed,omitempty"`
}

// Action is a quick action on this device (design.md, "Quick actions"):
// whether it is on, the kinds of admins that may run it (root, phone,
// computer; every kind when empty), and whether admins whose keys are in
// files may run one that hardware alone runs by default.
type Action struct {
	Name    string   `json:"name"`
	On      bool     `json:"on,omitempty"`
	By      []string `json:"by,omitempty"`
	AnyKey  bool     `json:"any_key,omitempty"`
	Command []string `json:"command,omitempty"` // the user's own action: its program and arguments
}

// Paste describes remote paste on this device: the switches its user set
// and the targets the connected watchers offer.
type Paste struct {
	On          bool     `json:"on,omitempty"`
	Enter       bool     `json:"enter,omitempty"`
	Console     bool     `json:"console,omitempty"`
	NoLockCheck bool     `json:"no_lock_check,omitempty"`
	Targets     []string `json:"targets,omitempty"`
}

// Keyboard describes this computer as a Bluetooth keyboard (cbb keyboard):
// its user's settings, and how it stands.
type Keyboard struct {
	On     bool   `json:"on,omitempty"`
	Layout string `json:"layout,omitempty"` // the host's layout: us or ru
	Rate   int    `json:"rate,omitempty"`   // characters a second
	Pastes bool   `json:"pastes,omitempty"` // remote pastes go to the host
	// Connected is whether a host takes its keys now; VisibleUntilMS when
	// it stops being discoverable, 0 when it is not.
	Connected      bool  `json:"connected,omitempty"`
	VisibleUntilMS int64 `json:"visible_until_ms,omitempty"`
	// Problem is why it is not running, when it is on.
	Problem string `json:"problem,omitempty"`
}

// TV is a TV this device is the remote of: its kind (androidtv or roku),
// its address, and whether remote pastes go to it. Pairing says it shows
// a code that cbb remote code takes.
type TV struct {
	Name    string `json:"name,omitempty"`
	Kind    string `json:"kind"`
	Host    string `json:"host"`
	Pastes  bool   `json:"pastes,omitempty"`
	Pairing bool   `json:"pairing,omitempty"`
}

// Away describes sync away from home on this device.
type Away struct {
	Hub        bool       `json:"hub,omitempty"`        // this device is one of the group's hubs
	Standby    bool       `json:"standby,omitempty"`    // on a hub: a hub above it serves, or it tries those; it is their client
	Port       int        `json:"port,omitempty"`       // the hub's UDP port
	Endpoints  []string   `json:"endpoints,omitempty"`  // the hub's addresses away from home
	Clients    int        `json:"clients,omitempty"`    // on the hub: the devices it admitted
	HubDevice  string     `json:"hub_device,omitempty"` // on a client: the hub; "" until the hub offered its tunnel
	Through    bool       `json:"through,omitempty"`    // on a client: connected to the hub through the tunnel now
	KeysInFile bool       `json:"keys_in_file,omitempty"`
	Obfuscated bool       `json:"obfuscated,omitempty"` // the tunnel speaks AmneziaWG
	VLESS      bool       `json:"vless,omitempty"`      // the clients reach the hub only over VLESS to its forwarder
	Error      string     `json:"error,omitempty"`      // what went wrong last, for the user
	Forwarder  *Forwarder `json:"forwarder,omitempty"`  // on the hub: its forwarder; nil without one
	Relay      *Relay     `json:"relay,omitempty"`      // on a device that meets the others at a relay; nil without one
	Detail     string     `json:"detail,omitempty"`     // the underlying error, for debugging
	// Allow is the group's servers that the service may reach beyond the
	// home network: its hub, forwarder and relay (internal/netguard).
	Allow []string `json:"allow,omitempty"`
}

// Forwarder describes a hub's registration on its forwarder.
type Forwarder struct {
	Endpoint   string `json:"endpoint"`
	Registered bool   `json:"registered,omitempty"`
	Seen       string `json:"seen,omitempty"`       // where the forwarder reaches the hub's port
	OverVLESS  bool   `json:"over_vless,omitempty"` // the hub reaches the forwarder only over VLESS
	// EntriesStale: the project's forwarder does not answer and this
	// device holds no signed entry points that have not expired, so a new
	// list may be what it needs (docs/protocol.md, section 16).
	EntriesStale bool   `json:"entries_stale,omitempty"`
	Error        string `json:"error,omitempty"`  // why the hub is not registered
	Detail       string `json:"detail,omitempty"` // the underlying error, for debugging
}

// Relay describes a device's link to its blind relay.
type Relay struct {
	Endpoint  string   `json:"endpoint"`
	Connected bool     `json:"connected,omitempty"` // registered, with its tunnel
	Online    []string `json:"online,omitempty"`    // the other devices of the group on the relay
	Error     string   `json:"error,omitempty"`     // why it is not connected
	Detail    string   `json:"detail,omitempty"`    // the underlying error, for debugging
}

// Joining is a device that used a remote invitation, for the admin to
// confirm with an answer.
type Joining struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	OS          string `json:"os"`
	Fingerprint string `json:"fingerprint"` // of its key, as cbb pair shows it on the device
}

// Device is a member as status shows it, or a device of the group as
// devices lists it.
type Device struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Role   string `json:"role,omitempty"`
	OS     string `json:"os,omitempty"`      // its operating system; "" when unknown
	Store  string `json:"store,omitempty"`   // where its keys live: group.StoreFile, StoreHardware, StoreProven or StoreRootless; "" when the member does not say
	SkewMS int64  `json:"skew_ms,omitempty"` // how far its clock is ahead of this one
	// Form, OSVersion, Version and MAC are what its hello says about its
	// device; "" when it says nothing or is not connected.
	Form      string `json:"form,omitempty"`
	OSVersion string `json:"os_version,omitempty"`
	Version   string `json:"version,omitempty"`
	MAC       string `json:"mac,omitempty"`
	// Mode is its sync mode, as its hello says; "" when it says none or is
	// not connected.
	Mode string `json:"mode,omitempty"`
	// Muted says that an admin muted it, as its hello says (this device:
	// as it is), until MutedUntilMS in Unix milliseconds, 0 for until an
	// admin unmutes it.
	Muted        bool  `json:"muted,omitempty"`
	MutedUntilMS int64 `json:"muted_until_ms,omitempty"`

	Admin      bool  `json:"admin,omitempty"`        // it can admit and remove devices
	Root       bool  `json:"root,omitempty"`         // it holds the group's root
	Frozen     bool  `json:"frozen,omitempty"`       // an admin computer another admin froze: no admin, and refused
	Online     bool  `json:"online,omitempty"`       // connected to this member now
	LastSeenMS int64 `json:"last_seen_ms,omitempty"` // when this member last saw it connected, Unix milliseconds; 0 if never
	Self       bool  `json:"self,omitempty"`         // this device
	Listed     bool  `json:"listed,omitempty"`       // it has a device record; a member that joined before the list existed may have none yet
	MayHub     bool  `json:"may_hub,omitempty"`      // the records let it be a hub: the root's own device, an admin with the hub power, or a hub that only passes copies on
	// ForwardOnly says that its record makes it a hub that only passes
	// the copies on: none is sealed to it (docs/protocol.md, section 11).
	ForwardOnly bool `json:"forward_only,omitempty"`
	Hub         bool `json:"hub,omitempty"` // one of the group's hubs, as this device knows: itself while it is a hub, or a hub whose offer it keeps; Away.HubDevice says which one it uses
}

// Message is a header and its payload.
type Message struct {
	Header
	Payload []byte
}

// Write sends a message.
func Write(w io.Writer, m *Message) error {
	m.Len = len(m.Payload)
	if m.Len > maxPayload {
		return errors.New("control: the text is larger than 1 MiB")
	}
	line, err := json.Marshal(m.Header)
	if err != nil {
		return err
	}
	if len(line) > maxHeader {
		return errors.New("control: header too long")
	}
	// One write for the whole message.
	var buf bytes.Buffer
	buf.Write(line)
	buf.WriteByte('\n')
	buf.Write(m.Payload)
	_, err = w.Write(buf.Bytes())
	return err
}

// Reader reads messages from a connection.
type Reader struct {
	r *bufio.Reader
}

// NewReader returns a reader for r.
func NewReader(r io.Reader) *Reader { return &Reader{r: bufio.NewReaderSize(r, 4096)} }

// Read reads the next message.
func (r *Reader) Read() (*Message, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.r.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, chunk...)
		if len(line) > maxHeader {
			return nil, errors.New("control: header too long")
		}
		if !isPrefix {
			break
		}
	}
	var m Message
	if err := json.Unmarshal(line, &m.Header); err != nil {
		return nil, fmt.Errorf("control: bad header: %w", err)
	}
	if m.Len < 0 || m.Len > maxPayload {
		return nil, fmt.Errorf("control: bad payload length %d", m.Len)
	}
	if m.Len > 0 {
		// Read the payload as it arrives, rather than allocating what the
		// header promises before a byte of it came.
		p, err := io.ReadAll(io.LimitReader(r.r, int64(m.Len)))
		if err != nil {
			return nil, err
		}
		if len(p) != m.Len {
			return nil, io.ErrUnexpectedEOF
		}
		m.Payload = p
	}
	return &m, nil
}
