// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

// Package blekeyboard makes a Linux computer a Bluetooth LE keyboard
// (docs/roadmap.md, item 25, way 3): BlueZ publishes the HID service of
// HID over GATT (HOGP) that this package exports on the system bus, and
// a TV, a tablet or another computer that pairs with it takes what it
// types as a keyboard's keys. Nothing is installed there.
//
// It is the LE route on purpose: classic Bluetooth HID needs bluetoothd's
// input plugin off, which would cost the computer its own Bluetooth
// keyboards and mice. LE needs an adapter that can be an LE peripheral
// (most since Bluetooth 4.0) and BlueZ 5.50 or later.
package blekeyboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/keyboard"
)

// Settings are what the computer's user set for its keyboard: whether it
// is on, the layout active on the host, characters a second, and whether
// remote pastes go to the host rather than to this computer's own screen.
type Settings struct {
	On     bool            `json:"on"`
	Layout keyboard.Layout `json:"layout,omitempty"`
	Rate   int             `json:"rate,omitempty"`
	Pastes bool            `json:"pastes,omitempty"`
}

// The slowest, fastest and usual typing, in characters a second, as the
// Nano's and the phone's.
const (
	MinRate     = 5
	MaxRate     = 60
	DefaultRate = 20
)

// MaxChars is the longest text it types: at 20 a second, under four
// minutes.
const MaxChars = 4096

// settingsFile holds the settings in the state directory.
const settingsFile = "keyboard"

// Normal returns s with its defaults filled in and its rate within the
// limits.
func (s Settings) Normal() Settings {
	if !s.Layout.Known() {
		s.Layout = keyboard.US
	}
	if s.Rate == 0 {
		s.Rate = DefaultRate
	}
	s.Rate = min(max(s.Rate, MinRate), MaxRate)
	return s
}

// Load reads the settings from dir: off when there are none.
func Load(dir string) (Settings, error) {
	var s Settings
	b, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return s.Normal(), nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", settingsFile, err)
	}
	return s.Normal(), nil
}

// Save writes the settings to dir.
func Save(dir string, s Settings) error {
	b, err := json.Marshal(s.Normal())
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, settingsFile), append(b, '\n'), 0o600)
}

// BlueZ's names on the system bus.
const (
	bluezBus      = "org.bluez"
	adapterIface  = "org.bluez.Adapter1"
	gattManager   = "org.bluez.GattManager1"
	advManager    = "org.bluez.LEAdvertisingManager1"
	agentManager  = "org.bluez.AgentManager1"
	serviceIface  = "org.bluez.GattService1"
	charIface     = "org.bluez.GattCharacteristic1"
	descIface     = "org.bluez.GattDescriptor1"
	advIface      = "org.bluez.LEAdvertisement1"
	agentIface    = "org.bluez.Agent1"
	objectManager = "org.freedesktop.DBus.ObjectManager"
	propsIface    = "org.freedesktop.DBus.Properties"
)

// root is where the keyboard's objects live on the bus.
const root = dbus.ObjectPath("/io/github/hunterewok/clipboardbridge/keyboard")

// appearanceKeyboard is the GAP appearance of a keyboard.
const appearanceKeyboard = 0x03c1

// The HID service's characteristics (the HID over GATT profile), the
// battery's and the device information's.
const (
	uuidHID          = "1812"
	uuidHIDInfo      = "2a4a"
	uuidReportMap    = "2a4b"
	uuidControlPoint = "2a4c"
	uuidReport       = "2a4d"
	uuidProtocolMode = "2a4e"
	uuidBootInput    = "2a22"
	uuidBootOutput   = "2a32"
	uuidReportRef    = "2908"
	uuidBattery      = "180f"
	uuidBatteryLevel = "2a19"
	uuidDeviceInfo   = "180a"
	uuidPnPID        = "2a50"
)

// ErrNoAdapter is the error of a computer whose BlueZ has no adapter that
// can be an LE peripheral.
var ErrNoAdapter = errors.New("no Bluetooth adapter that can be an LE keyboard: BlueZ 5.50 or later and an adapter with Bluetooth 4.0 or later are needed")

// ErrOff is the error of an adapter that is powered off.
var ErrOff = errors.New("this computer's Bluetooth is off; turn it on (bluetoothctl power on)")

// ErrNotConnected is the error of a text typed while no host listens.
var ErrNotConnected = errors.New("no device is connected to this computer's Bluetooth keyboard; pair one with cbb keyboard pair, then connect it from the device")

// A Keyboard is the keyboard's objects on the system bus, registered with
// BlueZ.
type Keyboard struct {
	conn    *dbus.Conn
	adapter dbus.ObjectPath
	name    string
	dir     string // where it keeps its hosts; "" keeps none
	logf    func(string, ...any)

	mu        sync.Mutex
	chars     []*characteristic
	report    *characteristic // the input report, in report mode
	boot      *characteristic // the boot keyboard's input report, in boot mode
	protocol  *characteristic
	listening int // hosts that take the input reports' notifications
	visible   time.Time
	advertise bool // an advertisement is registered
	agent     bool // the pairing agent is registered
	hosts     []dbus.ObjectPath
	stopWatch func()
	typing    sync.Mutex
}

// Open exports the keyboard on conn, the system bus, and registers it
// with BlueZ's first adapter, which must be powered. It advertises to the
// hosts it bonded with, without being discoverable; Visible makes it
// discoverable for a while. name is what a host shows; dir keeps the hosts
// it had (hosts.go).
func Open(conn *dbus.Conn, name, dir string, logf func(string, ...any)) (*Keyboard, error) {
	adapter, err := findAdapter(conn)
	if err != nil {
		return nil, err
	}
	k := &Keyboard{conn: conn, adapter: adapter, name: name, dir: dir, logf: logf, hosts: loadHosts(dir)}
	if err := k.export(); err != nil {
		k.unexport()
		return nil, err
	}
	obj := conn.Object(bluezBus, adapter)
	if err := obj.Call(gattManager+".RegisterApplication", 0, root, map[string]dbus.Variant{}).Err; err != nil {
		k.unexport()
		return nil, fmt.Errorf("registering the keyboard with BlueZ: %w", err)
	}
	if err := k.advertiseNow(false); err != nil {
		k.Close()
		return nil, err
	}
	k.watchDisconnects()
	return k, nil
}

// findAdapter returns BlueZ's first adapter with the GATT and the
// advertising managers, sorted by path, when it is powered.
func findAdapter(conn *dbus.Conn) (dbus.ObjectPath, error) {
	var objs map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	if err := conn.Object(bluezBus, "/").Call(objectManager+".GetManagedObjects", 0).Store(&objs); err != nil {
		return "", fmt.Errorf("%w (asking BlueZ: %v)", ErrNoAdapter, err)
	}
	var paths []dbus.ObjectPath
	for p, ifaces := range objs {
		_, a := ifaces[adapterIface]
		_, g := ifaces[gattManager]
		_, l := ifaces[advManager]
		if a && g && l {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return "", ErrNoAdapter
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	if on, ok := objs[paths[0]][adapterIface]["Powered"].Value().(bool); ok && !on {
		return "", ErrOff
	}
	return paths[0], nil
}

// Close unregisters the keyboard from BlueZ and takes its objects off the
// bus.
func (k *Keyboard) Close() {
	obj := k.conn.Object(bluezBus, k.adapter)
	k.mu.Lock()
	adv, agent, stop := k.advertise, k.agent, k.stopWatch
	k.advertise, k.agent, k.stopWatch = false, false, nil
	k.mu.Unlock()
	if stop != nil {
		stop()
	}
	if adv {
		obj.Call(advManager+".UnregisterAdvertisement", 0, root+"/advertisement")
	}
	if agent {
		k.conn.Object(bluezBus, "/org/bluez").Call(agentManager+".UnregisterAgent", 0, root+"/agent")
	}
	obj.Call(gattManager+".UnregisterApplication", 0, root)
	k.unexport()
}

// Connected reports whether a host takes the keyboard's keys now.
func (k *Keyboard) Connected() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.listening > 0
}

// VisibleUntil is when the keyboard stops being discoverable; zero when it
// is not.
func (k *Keyboard) VisibleUntil() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	if time.Now().After(k.visible) {
		return time.Time{}
	}
	return k.visible
}

// Visible makes the keyboard discoverable and pairable for d, so that a
// new host finds it in its Bluetooth settings and bonds with it, without a
// code. Its pairing agent is the adapter's default agent meanwhile, and
// takes pairings only then.
func (k *Keyboard) Visible(d time.Duration) error {
	am := k.conn.Object(bluezBus, "/org/bluez")
	k.mu.Lock()
	k.visible = time.Now().Add(d)
	agent := k.agent
	k.mu.Unlock()
	if !agent {
		if err := am.Call(agentManager+".RegisterAgent", 0, root+"/agent", "NoInputNoOutput").Err; err != nil {
			return fmt.Errorf("registering the pairing agent: %w", err)
		}
		k.mu.Lock()
		k.agent = true
		k.mu.Unlock()
	}
	if err := am.Call(agentManager+".RequestDefaultAgent", 0, root+"/agent").Err; err != nil {
		return fmt.Errorf("making the pairing agent the default: %w", err)
	}
	adapter := k.conn.Object(bluezBus, k.adapter)
	if err := adapter.Call(propsIface+".Set", 0, adapterIface, "Pairable", dbus.MakeVariant(true)).Err; err != nil {
		k.logf("cbb: keyboard: making the adapter pairable: %v", err)
	}
	if err := k.advertiseNow(true); err != nil {
		return err
	}
	time.AfterFunc(d, k.hide)
	return nil
}

// hide ends the time the keyboard is discoverable, once it is over: the
// advertisement then reaches the bonded hosts only, and the agent goes, so
// that the desktop's own agent is the default again.
func (k *Keyboard) hide() {
	k.mu.Lock()
	if time.Now().Before(k.visible) {
		k.mu.Unlock()
		return
	}
	agent := k.agent
	k.agent = false
	k.mu.Unlock()
	if agent {
		k.conn.Object(bluezBus, "/org/bluez").Call(agentManager+".UnregisterAgent", 0, root+"/agent")
	}
	if err := k.advertiseNow(false); err != nil {
		k.logf("cbb: keyboard: advertising again: %v", err)
	}
}

// advertiseNow registers the advertisement again, discoverable or not;
// BlueZ reads an advertisement's properties only when it is registered.
func (k *Keyboard) advertiseNow(discoverable bool) error {
	obj := k.conn.Object(bluezBus, k.adapter)
	path := root + "/advertisement"
	k.mu.Lock()
	had := k.advertise
	k.advertise = false
	k.mu.Unlock()
	if had {
		obj.Call(advManager+".UnregisterAdvertisement", 0, path)
	}
	k.conn.Export(nil, path, advIface)
	k.conn.Export(nil, path, propsIface)
	if err := k.conn.Export(advertisement{}, path, advIface); err != nil {
		return err
	}
	props := map[string]any{
		"Type":         "peripheral",
		"ServiceUUIDs": []string{uuidHID},
		"Appearance":   uint16(appearanceKeyboard),
		"LocalName":    k.name,
		"Discoverable": discoverable,
	}
	pm := map[string]*prop.Prop{}
	for n, v := range props {
		pm[n] = &prop.Prop{Value: v, Emit: prop.EmitFalse}
	}
	if _, err := prop.Export(k.conn, path, prop.Map{advIface: pm}); err != nil {
		return err
	}
	if err := obj.Call(advManager+".RegisterAdvertisement", 0, path, map[string]dbus.Variant{}).Err; err != nil {
		return fmt.Errorf("advertising the keyboard: %w", err)
	}
	k.mu.Lock()
	k.advertise = true
	k.mu.Unlock()
	return nil
}

// Check says whether Type would type text in the layout l now: nil, a
// *Refusal for a text it will not type, or ErrNotConnected.
func (k *Keyboard) Check(text string, l keyboard.Layout) error {
	if n := len([]rune(text)); n > MaxChars {
		return &Refusal{fmt.Sprintf("the text has %d characters, more than the %d a keyboard types", n, MaxChars)}
	}
	if _, ok := l.Reports(text); !ok {
		var cs []string
		for _, r := range l.Untypeable(text) {
			cs = append(cs, string(r))
		}
		return &Refusal{fmt.Sprintf("the host's layout (%s) has no key for %s; set the host's layout with cbb keyboard on -layout", l, strings.Join(cs, " "))}
	}
	if !k.Connected() {
		return ErrNotConnected
	}
	return nil
}

// Type types text on the connected host, at rate characters a second, in
// the layout l, and returns when it is typed. A text the layout cannot
// type is refused whole and its characters named (Check), rather than
// typed as other characters. One text at a time.
func (k *Keyboard) Type(ctx context.Context, text string, l keyboard.Layout, rate int) error {
	if err := k.Check(text, l); err != nil {
		return err
	}
	reports, _ := l.Reports(text)
	k.typing.Lock()
	defer k.typing.Unlock()
	rate = min(max(rate, MinRate), MaxRate)
	pause := time.Second / time.Duration(2*rate)
	for _, r := range reports {
		if err := k.send(r); err != nil {
			k.send(keyboard.Release)
			return err
		}
		select {
		case <-ctx.Done():
			k.send(keyboard.Release)
			return ctx.Err()
		case <-time.After(pause):
		}
	}
	return nil
}

// A Refusal is a text the keyboard will not type, and why.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

// send notifies the host of the input report r, on the boot keyboard's
// report when the host chose the boot protocol.
func (k *Keyboard) send(r [8]byte) error {
	k.mu.Lock()
	if k.listening == 0 {
		k.mu.Unlock()
		return ErrNotConnected
	}
	c := k.report
	if k.protocol.value()[0] == 0 {
		c = k.boot
	}
	k.mu.Unlock()
	return c.notify(r[:])
}

// export puts the keyboard's application, its services, characteristics
// and descriptors, the advertisement and the agent on the bus.
func (k *Keyboard) export() error {
	hid := root + "/hid"
	report := k.char(hid, "report", uuidReport, []string{"encrypt-read", "notify"}, make([]byte, 8))
	report.desc("ref", uuidReportRef, []byte{0, 1}) // report ID 0, input
	out := k.char(hid, "output", uuidReport, []string{"encrypt-read", "encrypt-write", "write-without-response"}, []byte{0})
	out.desc("ref", uuidReportRef, []byte{0, 2}) // report ID 0, output
	k.report = report
	k.boot = k.char(hid, "boot_input", uuidBootInput, []string{"encrypt-read", "notify"}, make([]byte, 8))
	k.char(hid, "boot_output", uuidBootOutput, []string{"encrypt-read", "encrypt-write", "write-without-response"}, []byte{0})
	// HID 1.11, no country, normally connectable.
	k.char(hid, "info", uuidHIDInfo, []string{"encrypt-read"}, []byte{0x11, 0x01, 0x00, 0x02})
	k.char(hid, "map", uuidReportMap, []string{"encrypt-read"}, keyboard.Descriptor)
	k.char(hid, "control", uuidControlPoint, []string{"write-without-response"}, []byte{0})
	// The report protocol until the host asks for the boot one.
	k.protocol = k.char(hid, "protocol", uuidProtocolMode, []string{"encrypt-read", "write-without-response"}, []byte{1})
	k.char(root+"/battery", "level", uuidBatteryLevel, []string{"read", "notify"}, []byte{100})
	// The vendor ID source (USB), the Linux Foundation's vendor ID, a
	// product and a version.
	k.char(root+"/info", "pnp", uuidPnPID, []string{"read"}, []byte{0x02, 0x6b, 0x1d, 0x46, 0x01, 0x00, 0x01})
	if err := k.conn.Export(application{k}, root, objectManager); err != nil {
		return err
	}
	for _, c := range k.chars {
		if err := k.conn.Export(c, c.path, charIface); err != nil {
			return err
		}
		for _, d := range c.descs {
			if err := k.conn.Export(d, d.path, descIface); err != nil {
				return err
			}
		}
	}
	return k.conn.Export(agent{k}, root+"/agent", agentIface)
}

func (k *Keyboard) unexport() {
	k.conn.Export(nil, root, objectManager)
	for _, c := range k.chars {
		k.conn.Export(nil, c.path, charIface)
		for _, d := range c.descs {
			k.conn.Export(nil, d.path, descIface)
		}
	}
	k.conn.Export(nil, root+"/advertisement", advIface)
	k.conn.Export(nil, root+"/advertisement", propsIface)
	k.conn.Export(nil, root+"/agent", agentIface)
}

// The services, by their paths under root.
var services = map[dbus.ObjectPath]string{root + "/hid": uuidHID, root + "/battery": uuidBattery, root + "/info": uuidDeviceInfo}

// char adds a characteristic to the service at svc.
func (k *Keyboard) char(svc dbus.ObjectPath, name, uuid string, flags []string, v []byte) *characteristic {
	c := &characteristic{k: k, path: svc + "/" + dbus.ObjectPath(name), svc: svc, uuid: uuid, flags: flags, val: v}
	k.chars = append(k.chars, c)
	return c
}

// application is the keyboard's GATT application: what BlueZ asks of it
// when it registers.
type application struct{ k *Keyboard }

func (a application) GetManagedObjects() (map[dbus.ObjectPath]map[string]map[string]dbus.Variant, *dbus.Error) {
	out := map[dbus.ObjectPath]map[string]map[string]dbus.Variant{}
	for p, uuid := range services {
		out[p] = map[string]map[string]dbus.Variant{serviceIface: {
			"UUID":    dbus.MakeVariant(uuid),
			"Primary": dbus.MakeVariant(true),
		}}
	}
	for _, c := range a.k.chars {
		out[c.path] = map[string]map[string]dbus.Variant{charIface: {
			"UUID":    dbus.MakeVariant(c.uuid),
			"Service": dbus.MakeVariant(c.svc),
			"Flags":   dbus.MakeVariant(c.flags),
		}}
		for _, d := range c.descs {
			out[d.path] = map[string]map[string]dbus.Variant{descIface: {
				"UUID":           dbus.MakeVariant(d.uuid),
				"Characteristic": dbus.MakeVariant(c.path),
				"Flags":          dbus.MakeVariant([]string{"encrypt-read"}),
			}}
		}
	}
	return out, nil
}

// A characteristic is one of the keyboard's GATT characteristics.
type characteristic struct {
	k     *Keyboard
	path  dbus.ObjectPath
	svc   dbus.ObjectPath
	uuid  string
	flags []string
	descs []*descriptor

	mu        sync.Mutex
	val       []byte
	notifying bool
}

func (c *characteristic) value() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.val)
}

func (c *characteristic) desc(name, uuid string, v []byte) {
	c.descs = append(c.descs, &descriptor{path: c.path + "/" + dbus.ObjectPath(name), uuid: uuid, val: v})
}

func (c *characteristic) ReadValue(opts map[string]dbus.Variant) ([]byte, *dbus.Error) {
	c.k.sawHost(opts)
	return c.value(), nil
}

func (c *characteristic) WriteValue(v []byte, _ map[string]dbus.Variant) *dbus.Error {
	if !slices.Contains(c.flags, "write-without-response") && !slices.Contains(c.flags, "encrypt-write") {
		return dbus.NewError("org.bluez.Error.NotPermitted", nil)
	}
	c.mu.Lock()
	c.val = slices.Clone(v)
	c.mu.Unlock()
	return nil
}

func (c *characteristic) StartNotify() *dbus.Error {
	if !slices.Contains(c.flags, "notify") {
		return dbus.NewError("org.bluez.Error.NotSupported", nil)
	}
	c.mu.Lock()
	was := c.notifying
	c.notifying = true
	c.mu.Unlock()
	if !was && c.isInput() {
		c.k.mu.Lock()
		c.k.listening++
		c.k.mu.Unlock()
		c.k.logf("cbb: keyboard: a host connected")
	}
	return nil
}

func (c *characteristic) StopNotify() *dbus.Error {
	c.mu.Lock()
	was := c.notifying
	c.notifying = false
	c.mu.Unlock()
	if was && c.isInput() {
		c.k.mu.Lock()
		c.k.listening--
		c.k.mu.Unlock()
		c.k.logf("cbb: keyboard: a host disconnected")
	}
	return nil
}

// isInput reports whether c is one of the input reports; a host
// subscribes to the one of its protocol, or both.
func (c *characteristic) isInput() bool { return c == c.k.report || c == c.k.boot }

// notify sets the value and tells the host, as BlueZ hears of a changed
// value through PropertiesChanged.
func (c *characteristic) notify(v []byte) error {
	c.mu.Lock()
	c.val = slices.Clone(v)
	c.mu.Unlock()
	return c.k.conn.Emit(c.path, propsIface+".PropertiesChanged", charIface, map[string]dbus.Variant{"Value": dbus.MakeVariant(v)}, []string{})
}

// A descriptor is a characteristic's descriptor, read only.
type descriptor struct {
	path dbus.ObjectPath
	uuid string
	val  []byte
}

func (d *descriptor) ReadValue(map[string]dbus.Variant) ([]byte, *dbus.Error) {
	return slices.Clone(d.val), nil
}

// advertisement is the LE advertisement; its properties are exported
// beside it.
type advertisement struct{}

func (advertisement) Release() *dbus.Error { return nil }

// agent is the pairing agent while the keyboard is discoverable: it takes
// a pairing without a code then, and refuses it otherwise.
type agent struct{ k *Keyboard }

func (a agent) pairing() *dbus.Error {
	if a.k.VisibleUntil().IsZero() {
		return dbus.NewError("org.bluez.Error.Rejected", []any{"the keyboard is not discoverable now"})
	}
	return nil
}

func (a agent) Release() *dbus.Error { return nil }
func (a agent) RequestPinCode(dbus.ObjectPath) (string, *dbus.Error) {
	return "", dbus.NewError("org.bluez.Error.Rejected", nil)
}
func (a agent) DisplayPinCode(dbus.ObjectPath, string) *dbus.Error { return nil }
func (a agent) RequestPasskey(dbus.ObjectPath) (uint32, *dbus.Error) {
	return 0, dbus.NewError("org.bluez.Error.Rejected", nil)
}
func (a agent) DisplayPasskey(dbus.ObjectPath, uint32, uint16) *dbus.Error { return nil }
func (a agent) RequestConfirmation(dbus.ObjectPath, uint32) *dbus.Error    { return a.pairing() }
func (a agent) RequestAuthorization(dbus.ObjectPath) *dbus.Error           { return a.pairing() }
func (a agent) AuthorizeService(dbus.ObjectPath, string) *dbus.Error       { return a.pairing() }
func (a agent) Cancel() *dbus.Error                                        { return nil }
