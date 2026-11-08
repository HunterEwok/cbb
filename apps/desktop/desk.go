// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/version"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// Desk is what the window and the tray know of the service on this
// computer: its status and the group's devices, read from the control
// socket. Its exported methods are what the window calls.
type Desk struct {
	app    *application.App
	window *application.WebviewWindow
	tray   *application.SystemTray
	// trayState is the glyph the tray shows now (trayState).
	trayState string

	socket       string
	lang         string
	tr           map[string]string
	settingsPath string

	// settingsMu orders the writes of desktop.json.
	settingsMu sync.Mutex

	mu       sync.Mutex
	settings Settings
	status   *control.Status
	devices  []control.Device
	problem  string
	message  string
	busy     bool

	// joinPath is the file of the join running now (join.go), "" when
	// none; joinCancelled whether the window cancelled it.
	joinPath      string
	join          Join
	joinCancelled bool

	// ask is what the window asks for next, once it reads it (TakeAsk):
	// the tray's Settings, or the question before sync away from home.
	ask string
}

// State is the window's whole picture, read again every few seconds.
type State struct {
	Lang     string           `json:"lang"`
	Problem  string           `json:"problem,omitempty"`
	Status   *control.Status  `json:"status,omitempty"`
	Devices  []control.Device `json:"devices"`
	Busy     bool             `json:"busy"`
	Message  string           `json:"message,omitempty"`
	Settings Settings         `json:"settings"`
	Version  string           `json:"version"`
	// Arranged is the devices and collections below this computer in the
	// user's order (Arrangement.View); Custom whether the user changed
	// the order, which Back to the group's order undoes.
	Arranged []Item `json:"arranged"`
	Custom   bool   `json:"custom"`
	// ShowDetails is whether messages show the error underneath, as
	// Settings.Details or else the build sets it.
	ShowDetails bool `json:"show_details"`
	// Languages are the languages the window speaks, by their codes, and
	// AtLogin whether the tray app starts with each sign-in.
	Languages []string `json:"languages"`
	AtLogin   bool     `json:"at_login"`
}

// Settings are the window's choices, kept in the user's configuration
// folder.
type Settings struct {
	Color      string `json:"color"`
	Appearance string `json:"appearance"` // system, dark or light
	Layout     string `json:"layout"`     // tiles, list or orbit
	// Details shows the error underneath each message; nil follows the
	// build and CBB_DEBUG (showDetails).
	Details *bool `json:"details,omitempty"`
	// Lang is the language the user picked, "" for the system's.
	Lang string `json:"lang,omitempty"`
	// Arrangement is the user's order of the tiles and their collections
	// (arrange.go); nil until the user changes something. The window never
	// sends it: Arrange changes it.
	Arrangement *Arrangement `json:"arrangement,omitempty"`
}

// NewDesk reads the settings and the language; it reaches the service only
// when asked.
func NewDesk() *Desk {
	d := &Desk{socket: control.SocketPath(), settings: Settings{Color: "terminal", Appearance: "system", Layout: "tiles"}}
	if dir, err := os.UserConfigDir(); err == nil {
		d.settingsPath = filepath.Join(dir, "cbb", "desktop.json")
		if data, err := os.ReadFile(d.settingsPath); err == nil {
			if err := json.Unmarshal(data, &d.settings); err != nil {
				log.Printf("settings: %v", err)
			}
		}
	}
	d.lang = pickLang(d.settings.Lang)
	d.tr = translations(d.lang)
	return d
}

// T translates an English text into the user's language.
func (d *Desk) T(s string) string {
	d.mu.Lock()
	t, ok := d.tr[s]
	d.mu.Unlock()
	if ok {
		return t
	}
	return s
}

// State reads the service again and returns what the window shows.
func (d *Desk) State() State {
	d.refresh()
	return d.snapshot()
}

func (d *Desk) snapshot() State {
	details := d.showDetails()
	d.mu.Lock()
	defer d.mu.Unlock()
	st := State{Lang: d.lang, Problem: d.problem, Status: d.status, Devices: d.devices, Busy: d.busy,
		Message: d.message, Settings: d.settings, Version: version.String(), ShowDetails: details,
		Languages: languages(), AtLogin: atLogin()}
	if st.Devices == nil {
		st.Devices = []control.Device{} // the window takes null for no list
	}
	if a, ids, self, ok := d.arrangementLocked(); ok {
		st.Arranged = a.View(ids, self)
		st.Custom = len(a.Items) > 0
	}
	st.Settings.Arrangement = nil
	return st
}

// arrangementLocked is the arrangement for the group this computer is in,
// with the devices' IDs and this computer's; ok is false outside a group.
func (d *Desk) arrangementLocked() (a Arrangement, ids []string, self string, ok bool) {
	if d.status == nil || d.status.Group == "" || d.status.Removed {
		return Arrangement{}, nil, "", false
	}
	var stored Arrangement
	if d.settings.Arrangement != nil {
		stored = *d.settings.Arrangement
	}
	for _, dev := range d.devices {
		ids = append(ids, dev.ID)
		if dev.Self {
			self = dev.ID
		}
	}
	return arrangeFor(stored, d.status.Group), ids, self, true
}

// Arrange makes a change to the arrangement of the tiles and keeps it; one
// that does not fit leaves it as it was and says so.
func (d *Desk) Arrange(op ArrangeOp) {
	d.mu.Lock()
	a, ids, self, ok := d.arrangementLocked()
	d.mu.Unlock()
	if !ok {
		return
	}
	if err := a.Apply(op, ids, self); err != nil {
		msg := d.describe(err)
		d.mu.Lock()
		d.message = msg
		d.mu.Unlock()
		return
	}
	d.mu.Lock()
	d.settings.Arrangement = &a
	d.message = ""
	d.mu.Unlock()
	if err := d.writeSettings(); err != nil {
		log.Printf("settings: %v", err)
	}
}

// pruneLocked drops the devices that left the group from the stored
// arrangement, once the list is whole: the group loaded, this computer in
// it. It reports whether the settings changed.
func (d *Desk) pruneLocked() bool {
	if d.settings.Arrangement == nil {
		return false
	}
	a, ids, self, ok := d.arrangementLocked()
	if !ok || self == "" {
		return false
	}
	before, _ := json.Marshal(a)
	a.Prune(ids)
	after, _ := json.Marshal(a)
	if string(before) == string(after) {
		return false
	}
	d.settings.Arrangement = &a
	return true
}

func (d *Desk) refresh() {
	var st *control.Status
	var devices []control.Device
	m, _, err := d.request(control.OpStatus, nil)
	if err == nil {
		st = m.Status
		if st != nil && st.Group != "" && !st.Removed {
			var dm *control.Message
			if dm, _, err = d.request(control.OpDevices, nil); err == nil {
				devices = dm.Devices
			}
		}
	}
	// describe reads the settings under d.mu, so it runs before the lock.
	problem := ""
	if err != nil {
		problem = d.describe(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.problem = problem
		return
	}
	d.problem, d.status, d.devices = "", st, devices
	if d.pruneLocked() {
		go func() {
			if err := d.writeSettings(); err != nil {
				log.Printf("settings: %v", err)
			}
		}()
	}
}

// request sends one request on its own connection and returns the answer
// and its payload.
func (d *Desk) request(op string, payload []byte) (*control.Message, []byte, error) {
	return d.requestHeader(control.Header{Op: op}, payload)
}

// requestHeader is request with a whole header.
func (d *Desk) requestHeader(h control.Header, payload []byte) (*control.Message, []byte, error) {
	c, err := control.Dial(d.socket)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	m, err := c.Do(&control.Message{Header: h, Payload: payload})
	if err != nil {
		return nil, nil, err
	}
	return m, m.Payload, nil
}

// CreateGroup makes a new group with this computer as its root, as cbb
// new does as the administrator.
func (d *Desk) CreateGroup() {
	d.admin([]string{"new"}, false, "The group is made: this computer is its root. Add a device with the + button.")
}

// Rename, Remove, MakeAdmin, Freeze, Unfreeze, MakeHub, StopHub, SetAway and SetSync change the group:
// cbb does them as the administrator (admin_*.go), after the system asks.
// MakeAdmin's dialog warns that the computer's key is a file, which
// -allow-file-key consents to.
func (d *Desk) Rename(id, name string) { d.admin([]string{"rename", id, name}, false, "Renamed.") }
func (d *Desk) Remove(id string)       { d.admin([]string{"remove", id}, false, "Removed from the group.") }
func (d *Desk) MakeAdmin(id string) {
	d.admin([]string{"admin", "-allow-file-key", id}, false, "It is an admin now.")
}

// Leave takes this computer out of its group (cbb leave, D-83): its keys
// and the group's files go, its settings stay, and it may join again.
func (d *Desk) Leave() {
	d.admin([]string{"leave", "-yes"}, false, "Left the group. This computer can join a group again.")
}

func (d *Desk) Freeze(id string)   { d.admin([]string{"freeze", id}, false, "Frozen.") }
func (d *Desk) Unfreeze(id string) { d.admin([]string{"unfreeze", id}, false, "Unfrozen.") }

// MakeHub makes a device a hub of the group for sync away from home:
// this computer, when id is empty, at the addresses cbb global hub finds as
// it does, turning sync away from home on with it when awayOn is set (the
// user said yes to the app's question), or with id another computer, to
// which cbb sends a signed hub command; there sync away from home must be
// on already. A hub that reads the copies is an admin; with forwardOnly a
// computer that is no admin becomes a hub that only passes them on and
// reads none.
func (d *Desk) MakeHub(id string, awayOn, forwardOnly bool) {
	switch {
	case id != "" && forwardOnly:
		d.admin([]string{"global", "hub", "-on", id, "-forward-only"}, false, "It is a hub now that only passes the copies on, and reads none of them.")
	case id != "":
		d.admin([]string{"global", "hub", "-on", id}, false, "It is a hub now.")
	case awayOn:
		d.admin([]string{"global", "hub", "-firewall", "no", "-away-on"}, true, "It is a hub now.")
	default:
		d.admin([]string{"global", "hub", "-firewall", "no"}, false, "It is a hub now.")
	}
}

// StopHub makes a hub stop being one: this computer, or with id another
// device, to which cbb sends a signed hub command. Its clients go to the
// next hub; the app warned first when there is none.
func (d *Desk) StopHub(id string) {
	args := []string{"global", "hub", "off", "-yes"}
	if id != "" {
		args = []string{"global", "hub", "off", "-on", id, "-yes"}
	}
	d.admin(args, false, "It is no hub any more.")
}

// SetHub sets how this hub's tunnel hides (plain, obfuscate for
// AmneziaWG, vless) and, when fwd is given, its forwarder ("default" for
// the project's), keeping its addresses and port: cbb global hub -keep.
func (d *Desk) SetHub(tunnel, fwd, key string) {
	args := []string{"global", "hub", "-keep", "-firewall", "no"}
	switch tunnel {
	case "obfuscate":
		args = append(args, "-obfuscate")
	case "vless":
		args = append(args, "-vless")
	}
	if fwd != "" {
		args = append(args, "-forwarder", fwd)
		if key != "" {
			args = append(args, "-forwarder-key", key)
		}
	}
	d.admin(args, false, "The hub's settings are saved.")
}

// Resolve, on the group's root, voids both histories of every key that
// signed two, as cbb resolve does as the administrator.
func (d *Desk) Resolve() {
	d.admin([]string{"resolve"}, false, "Both histories are void. The device signs its records again by itself.")
}

// Recover claims the group with its recovery key, typed from the sheet or
// its QR code's text, as cbb recovery does as the administrator with the
// key on its standard input; the claim waits as a takeover does.
func (d *Desk) Recover(key string) {
	d.adminWith([]string{"recovery"}, strings.TrimSpace(key)+"\n", "The claim is made: it takes effect after the group's takeover delay.")
}

// Update installs the newest signed release the group passed around, as
// cbb update does as the administrator.
func (d *Desk) Update() { d.admin([]string{"update"}, false, "CBB is updated.") }

// SetAway turns sync away from home on or off; on answers yes to the
// warning the window showed, which cbb asks for.
func (d *Desk) SetAway(on bool) {
	if on {
		d.admin([]string{"global", "on"}, true, "Sync away from home is on.")
	} else {
		d.admin([]string{"global", "off"}, false, "Sync away from home is off.")
	}
}

// SetSync turns sync on or off: this computer's with id empty, for forMS
// (0 for until it is turned on again), which needs no administrator as the
// service takes it on the control socket; or on an admin another device's,
// which cbb sends it as a signed command (docs/design.md, "Sync on and off").
func (d *Desk) SetSync(id string, on bool, forMS int64) {
	name := map[bool]string{true: "on", false: "off"}[on]
	if id != "" {
		d.admin([]string{"sync", "-on", id, name}, false, "Sync is set.")
		return
	}
	d.act(func() (string, error) {
		if _, _, err := d.requestHeader(control.Header{Op: control.OpSync, Name: name, ForMS: forMS}, nil); err != nil {
			return "", err
		}
		if on {
			return d.T("Sync is on here: copies go to the group and come from it."), nil
		}
		return d.T("Sync is off here: the clipboard is this computer's own."), nil
	})
}

// Mute, on an admin, keeps a device's copies from the group for forMS, 0
// for until an admin unmutes it, with a signed command; Unmute ends it.
func (d *Desk) Mute(id string, forMS int64) {
	args := []string{"mute", "-on", id}
	if forMS > 0 {
		args = append(args, "-for", fmt.Sprintf("%dms", forMS))
	}
	d.admin(args, false, "It is muted: its copies do not reach the group.")
}

func (d *Desk) Unmute(id string) {
	d.admin([]string{"unmute", "-on", id}, false, "It is no longer muted.")
}

func (d *Desk) admin(args []string, yes bool, done string) {
	input := ""
	if yes {
		input = "yes\n"
	}
	d.adminWith(args, input, done)
}

// adminWith runs cbb as the administrator with input as its standard input.
func (d *Desk) adminWith(args []string, input, done string) {
	details := d.showDetails()
	d.act(func() (string, error) {
		if err := adminRun(args, input, details); err != nil {
			return "", err
		}
		return d.T(done), nil
	})
}

// act runs one action at a time, then reads the service again.
func (d *Desk) act(work func() (string, error)) {
	d.mu.Lock()
	if d.busy {
		d.mu.Unlock()
		return
	}
	d.busy = true
	d.mu.Unlock()
	msg, err := work()
	if errors.Is(err, errCancelled) {
		msg, err = "", nil
	}
	if err != nil {
		msg = d.describe(err)
	}
	d.mu.Lock()
	d.busy, d.message = false, msg
	d.mu.Unlock()
	d.refresh()
	d.updateTray()
}

// SaveSettings keeps the window's choices; a language picked there is the
// tray's at once too.
func (d *Desk) SaveSettings(s Settings) error {
	lang := pickLang(s.Lang)
	tr := translations(lang)
	d.mu.Lock()
	// The window does not send the arrangement; Arrange keeps it.
	s.Arrangement = d.settings.Arrangement
	d.settings = s
	changed := lang != d.lang
	d.lang, d.tr = lang, tr
	d.mu.Unlock()
	err := d.writeSettings()
	if changed {
		d.updateTray()
	}
	return err
}

// SetAtLogin makes the tray app start, or not, with each sign-in.
func (d *Desk) SetAtLogin(on bool) error {
	if err := setAtLogin(on); err != nil {
		return errors.New(d.describe(err))
	}
	return nil
}

// TakeAsk returns what the window should ask for now, once: "settings"
// after the tray's Settings, "away" after the tray turned sync away from
// home on, which asks first; "" for nothing.
func (d *Desk) TakeAsk() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := d.ask
	d.ask = ""
	return a
}

// openFor shows the window, which then asks for what (TakeAsk).
func (d *Desk) openFor(what string) {
	d.mu.Lock()
	d.ask = what
	d.mu.Unlock()
	d.Open()
}

// writeSettings writes the current settings to desktop.json. It reads them
// under settingsMu, so that of two writes close together the last one
// holds the newer settings, never a copy taken before the other's.
func (d *Desk) writeSettings() error {
	d.settingsMu.Lock()
	defer d.settingsMu.Unlock()
	d.mu.Lock()
	s := d.settings
	d.mu.Unlock()
	if d.settingsPath == "" {
		return errors.New("no configuration folder")
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.settingsPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(d.settingsPath, data, 0o600)
}

// showDetails tells whether messages show the error underneath them: the
// setting when there is one, else as cbb does (CBB_DEBUG=1 or 0, or on in a
// build without a release version).
func (d *Desk) showDetails() bool {
	d.mu.Lock()
	set := d.settings.Details
	d.mu.Unlock()
	if set != nil {
		return *set
	}
	switch os.Getenv("CBB_DEBUG") {
	case "1":
		return true
	case "0":
		return false
	}
	return version.Version == "dev"
}

// describe turns an error into the message for the user, with the error
// underneath when details are on; the log has it either way.
func (d *Desk) describe(err error) string {
	text, detail := d.summary(err)
	log.Printf("%s: %s", text, detail)
	if d.showDetails() && detail != "" && detail != text {
		return text + "\n\n" + detail
	}
	return text
}

func (d *Desk) summary(err error) (string, string) {
	var dial *control.DialError
	var req *control.RequestError
	var adm *adminError
	switch {
	case errors.As(err, &dial) && dial.Denied:
		return d.T(deniedText), dial.Error()
	case errors.As(err, &dial):
		return d.T("The CBB service is not running on this computer."), fmt.Sprint(dial.Err)
	case errors.As(err, &req):
		return req.Msg, req.Detail
	case errors.As(err, &adm):
		return d.T(adm.msg), adm.detail
	case errors.Is(err, errArrange):
		return d.T("The tiles stay as they were: that change does not fit."), err.Error()
	}
	return d.T("Something failed on this computer."), err.Error()
}

// projectTerms is the page of the terms of the project's forwarder and
// relay, in the reader's language.
const projectTerms = "https://cbb.tools/?p=terms.html"

// OpenTerms opens the terms of the project's servers in the browser.
func (d *Desk) OpenTerms() error {
	if d.app == nil {
		return errors.New("no application")
	}
	return d.app.Browser.OpenURL(projectTerms)
}

// Open shows the window.
func (d *Desk) Open() {
	if d.window == nil {
		return
	}
	d.window.Show()
	d.window.Focus()
}

// openIfNoGroup shows the window when this computer is in no group, so
// that the start window greets the user after the install.
func (d *Desk) openIfNoGroup() {
	d.refresh()
	s := d.snapshot()
	if s.Problem == "" && s.Status != nil && s.Status.Group == "" {
		d.Open()
	}
}

// watch keeps the tray up to date.
func (d *Desk) watch() {
	for range time.Tick(5 * time.Second) {
		d.refresh()
		d.updateTray()
	}
}

// syncTimes are the times the tray's and the window's sync switch turns
// sync off for, 0 for until it is turned on again.
var syncTimes = []struct {
	label string
	ms    int64
}{
	{"For 15 minutes", 15 * 60 * 1000},
	{"For an hour", 60 * 60 * 1000},
	{"For 8 hours", 8 * 60 * 60 * 1000},
	{"Until I turn it on", 0},
}

// updateTray writes the tray's menu: where the group stands, the two
// switches (sync, with a time to turn it off for, and sync away from
// home), the window, its settings, an update, quit (docs/apps.md, "The tray
// app").
func (d *Desk) updateTray() {
	if d.tray == nil || d.app == nil {
		return
	}
	s := d.snapshot()
	menu := d.app.NewMenu()
	menu.Add(d.headline(s)).SetEnabled(false)
	if s.Message != "" {
		menu.Add(s.Message).SetEnabled(false)
	}
	inGroup := s.Problem == "" && s.Status != nil && s.Status.Group != "" && !s.Status.Removed
	if inGroup {
		menu.AddSeparator()
		on := s.Status.Mode != "own"
		label := d.T("Sync")
		if !on && s.Status.SyncUntilMS > 0 {
			label = fmt.Sprintf(d.T("Sync off until %s"), time.UnixMilli(s.Status.SyncUntilMS).Format("15:04"))
		}
		menu.AddCheckbox(label, on).SetEnabled(!s.Busy).OnClick(func(*application.Context) { go d.SetSync("", !on, 0) })
		if on {
			off := menu.AddSubmenu(d.T("Turn sync off"))
			for _, t := range syncTimes {
				ms := t.ms
				off.Add(d.T(t.label)).SetEnabled(!s.Busy).OnClick(func(*application.Context) { go d.SetSync("", false, ms) })
			}
		}
		away := s.Status.Away != nil
		menu.AddCheckbox(d.T("Everywhere"), away).SetEnabled(!s.Busy && (on || away)).OnClick(func(*application.Context) {
			if away {
				go d.SetAway(false)
			} else {
				d.openFor("away") // the window asks first
			}
		})
	}
	menu.AddSeparator()
	menu.Add(d.T("Open CBB")).OnClick(func(*application.Context) { d.Open() })
	menu.Add(d.T("Settings")).OnClick(func(*application.Context) { d.openFor("settings") })
	if s.Problem == "" && s.Status != nil && s.Status.Update != "" {
		menu.Add(fmt.Sprintf(d.T("Update to %s"), s.Status.Update)).SetEnabled(!s.Busy).OnClick(func(*application.Context) { go d.Update() })
	}
	menu.AddSeparator()
	menu.Add(d.T("Quit")).OnClick(func(*application.Context) { d.app.Quit() })
	d.tray.SetMenu(menu)
	if state := trayState(s); state != d.trayState {
		d.trayState = state
		setTrayIcon(d.tray, state)
	}
	d.tray.SetTooltip("CBB · " + d.headline(s))
}

// headline is the group in a line.
func (d *Desk) headline(s State) string {
	switch {
	case s.Problem != "":
		return d.T("The service does not answer")
	case s.Status == nil || s.Status.Group == "":
		return d.T("This computer is in no group yet")
	}
	// This computer counts too, online as it is the one in front of the user.
	online := 0
	for _, dev := range s.Devices {
		if dev.Online || dev.Self {
			online++
		}
	}
	return fmt.Sprintf(d.T("%d of %d online"), online, len(s.Devices))
}
