// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package service is the clipboardbridge service: it holds the device's identity,
// the sync engine and the member connections, publishes and browses with
// mDNS (D-12, D-32), admits devices,
// and serves the local control socket.
package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/actions"
	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/benchtime"
	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/hlc"
	"github.com/HunterEwok/clipboardbridge/internal/mdns"
	"github.com/HunterEwok/clipboardbridge/internal/netguard"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/phone"
	"github.com/HunterEwok/clipboardbridge/internal/remotepaste"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// markFile holds the hybrid clock's saved mark, in the state directory.
const markFile = "hlc.mark"

// Config configures the service.
type Config struct {
	StateDir string    // identity and clock mark
	Socket   string    // the control socket; the admin socket is next to it (control.AdminSocketFor)
	Role     node.Role // every role listens and publishes; a computer is node.Full
	// OS is this device's operating system (group.OSLinux, OSWindows or
	// OSMacOS), shown to the others; a Mac does not admit devices yet.
	OS string
	// Device is this device's form, versions and MAC address, shown to the
	// others in the hello.
	Device group.DeviceInfo
	Name   string // this device's name, shown to the others; the host name if empty
	Logf   func(format string, args ...any)
	// Interfaces limits the member port, a listening join and mDNS to
	// these network interfaces, by name; Interfaces() (CBB_INTERFACES) if
	// nil, and every interface if that is empty.
	Interfaces []string

	// Discover publishes this member and finds the others; mDNS if nil.
	// Tests replace it.
	Discover func(DiscoveryConfig) (Discovery, error)

	// listen opens the member port; the one Port names, or any free port,
	// on all addresses if nil.
	listen func() (net.Listener, error)
	// now is the clock for certificates; time.Now if nil.
	now func() time.Time
	// browseFor is how long join looks for a pairing window; ten seconds
	// if zero.
	browseFor time.Duration
	// joinID returns the device ID a join takes; a new random one if nil.
	// Tests set it to choose which of two devices has the lower ID.
	joinID func() group.DeviceID
	// joinListen opens the port a listening join waits at, the member port or any
	// free port on all addresses if nil; joinAddrs returns the addresses for its QR code,
	// joinAddresses if nil.
	joinListen func() (net.Listener, error)
	joinAddrs  func(port uint16) []string
	// battery reports whether the machine has a battery, for the holder
	// priority; hasBattery if nil.
	battery func() bool
	// peerOf tells who is at the other end of a control connection, and
	// atScreen whether that user may take a target's remote pastes; the
	// system's if nil (peer.go).
	peerOf   func(net.Conn) peer
	atScreen func(peer, string) verdict
	// fallbackAfter is how long a full member waits for one with a lower
	// device ID to dial it before it dials that one; fallbackDial if zero.
	fallbackAfter time.Duration
	// ReleaseRoots are the release root keys that the signed releases the
	// group passes around are checked against; release.Roots if nil.
	ReleaseRoots [][]byte

	// Container says that the service runs in the image (InContainer);
	// there it makes no group and takes no admin key unless KeysInFile
	// (KeysInFileAllowed).
	Container, KeysInFile bool
	// Rootless says that this is a rootless install (rootless.Is): it
	// makes no group and takes no admin key at all, and its hello says
	// group.StoreRootless (D-79).
	Rootless bool

	// runner carries out the quick actions' presets; actions.System if
	// nil.
	runner actions.Runner
	// actInSession runs the presets through the agent, as on a Mac and
	// on Windows, whatever the system.
	actInSession bool

	// KeyboardBus connects to the bus BlueZ is on, for the Bluetooth
	// keyboard; the system bus on Linux if nil. Tests replace it.
	KeyboardBus keyboardDialer

	// newMode is the sync mode of a device that makes or joins a group;
	// clip.Own if nil. Tests that sync take clip.Shared.
	newMode *clip.Mode
}

// MemberPort is the member port by default (CBB_PORT moves it, see
// Port), so a firewall can open it; a listening join, which comes before
// the device is in a group, waits there too. When it is taken, any free port
// does, since discovery and the QR code carry the port.
const MemberPort = 8764

// listenPreferring listens on port on all addresses, or on any free port if
// that one is taken.
func listenPreferring(port int) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		ln, err = net.Listen("tcp", ":0")
	}
	return ln, err
}

// maxHandshakes is how many connections to the member port may wait for
// their TLS handshake, or run a pairing attempt, at once.
const maxHandshakes = 32

// DiscoveryConfig is what discovery publishes and whom it tells.
type DiscoveryConfig struct {
	ID         string
	Port       uint16
	TXT        []string
	BrowseOnly bool // find members without publishing this device
	// Publish tells whether to publish this device on an interface, by its
	// name and networks; everywhere if nil.
	Publish func(name string, prefixes []netip.Prefix) bool
	// Only, if set, limits discovery to the interfaces it allows, by name:
	// it neither publishes nor browses elsewhere (Config.Interfaces).
	Only    func(name string) bool
	OnPeers func([]mdns.Peer)
	Logf    func(string, ...any)
}

// Discovery publishes a member and finds the others.
type Discovery interface {
	Run(ctx context.Context) error
	SetTXT(txt []string)
	SetHolder(hold bool)
}

func mdnsDiscovery(c DiscoveryConfig) (Discovery, error) {
	return mdns.New(mdns.Config{ID: c.ID, Port: c.Port, TXT: c.TXT, BrowseOnly: c.BrowseOnly, Publish: c.Publish, Interfaces: c.Only, OnPeers: c.OnPeers, Logf: c.Logf})
}

// Service is a running clipboardbridge service.
type Service struct {
	cfg   Config
	clock *hlc.Clock
	logf  func(string, ...any)
	// repeated holds the lines logRepeat logged lately, with their time.
	repeatMu sync.Mutex
	repeated map[string]time.Time
	broken   *control.RequestError // the group's files cannot be read; set once at start

	// The Bluetooth keyboard, on Linux (keyboard_linux.go).
	kbd keyboardState
	// The TV pairing in progress (tvremote.go).
	tv tvState

	createMu      sync.Mutex // one group creation at a time
	mu            sync.Mutex
	id            *group.Identity // nil while the device is in no group
	eng           *clip.Engine    // made with the identity
	nd            *node.Node
	responder     Discovery
	nets          *networks // the known networks; set before the group starts
	discoveryStop context.CancelFunc
	discoveryDone chan struct{}
	port          uint16
	window        *pair.Window // announced; takes pairing connections
	opening       bool         // a pairing window is being opened, maybe with a new group
	phoneWindow   *phone.Window
	phoneOpening  bool          // an iPhone pairing window is being opened
	phoneConns    *connListener // the shortcut's HTTPS on the member port; nil if not served
	phoneTLS      *tls.Config   // the shortcut's TLS, with phoneConns
	profileConns  *connListener // the profile's plain HTTP while an iPhone pairing window is open
	joining       bool          // a join is running
	stopping      bool          // the service is stopping: no new group, no election
	holder        bool
	holdSetting   string // HolderAuto, HolderFirst, HolderFallback or HolderNever
	battery       bool   // the machine has a battery, guessed at the start
	// pendingPhoneCA is an iPhone CA another admin sent while this one held
	// another that still stood, kept in case the records revoke that one.
	pendingPhoneCA *group.CA
	dialers        map[group.DeviceID]*dialer
	nearby         map[group.DeviceID]time.Duration // the members of the group that discovery finds on this network, by the uptime they were first found
	prio           map[group.DeviceID]int           // their holder priority (TXT h), for those that can hold the name
	watchers       map[*watcher]bool
	pastes         remotepaste.Limiter // remote pastes per sender
	actionLimit    remotepaste.Limiter // quick actions per sender, as remote pastes
	restart        chan struct{}       // an admin had the service restart (actions.Restart)
	lastSeq        uint64
	pending        *node.Write                      // a write that no watcher got, for the next one
	mediaWait      *node.Write                      // a copy of images or files the watchers that take them get once it has arrived
	seen           map[group.DeviceID]time.Time     // when each peer was last seen connected
	adminCAsUnder  map[group.DeviceID]group.KeyHash // the root this root last sent each admin a new admin CA under
	pendingAdminCA []byte                           // an admin CA that came before the records that make it valid
	// commands holds the IDs of the commands carried out, until they
	// expire, so that none is carried out twice; the cache starts empty, so
	// a command signed before startedMS is refused.
	commands map[string]time.Time
	// typing holds the targets that type a paste after its answer (the
	// Bluetooth keyboard, a Roku): one text at a time on each.
	typing map[string]bool
	// keys holds the grants of the remote pastes handed to desktop
	// sessions, for the uinput helper (keysGrant).
	keys      map[string]*keysGrant
	startedMS int64
	online    map[group.DeviceID]bool
	// unreached holds the members at home that could not connect to this
	// one and synced only because it dialed them back (cbb status).
	unreached map[group.DeviceID]bool

	listMu sync.Mutex // one ensureListed at a time, so a device is recorded once

	// signedMu guards the log of the records this device signed
	// (signed.json, resign.go), and lets one resignVoided run at a time.
	signedMu sync.Mutex
	resignMu sync.Mutex
	// attMu guards the revocation list and the evidence of the connected
	// peers (evidence.go); taken alone.
	attMu       sync.Mutex
	attRevoked  map[string]bool
	attEvidence map[group.DeviceID]peerEvidence
	// tpmMu guards this device's TPM attestation and, on the root, the
	// credentials sent to peers (evidence_tpm.go); taken alone.
	tpmMu      sync.Mutex
	tpmAtt     *tpmAttestation
	tpmPending map[group.DeviceID]tpmPending
	// tpmOpening is held while the TPM opens a root's credential, one at
	// a time.
	tpmOpening  sync.Mutex
	recMu       sync.Mutex         // guards records; taken after mu, never before
	records     *group.Records     // the group's device records; nil while in no group
	creds       *group.Credentials // the group's server credentials, under recMu as records
	serverKeys  *group.ServerKeys  // this device's keys for the servers, under recMu as records
	sealSecret  []byte             // this device's secret for sealed messages (internal/seal); nil if it could not be loaded
	sealPublic  []byte             // its public key, which the hello offers
	credChanged chan struct{}      // closed when creds change, under recMu
	credMu      sync.Mutex         // serialises refreshCredential, taken before mu and recMu

	// The newest signed release the group passed around (releases.go);
	// relMu guards it, taken alone.
	relMu  sync.Mutex
	rel    *heldRelease
	relRan bool // the file was read

	// Images and files (media.go): the cache, which is nil until the
	// service runs; mediaMu guards the rest, taken after mu, never before.
	content     *contentStore
	mediaMu     sync.Mutex
	limits      mediaLimits
	fetch       *fetchRun // the copy being fetched; nil if none
	fetchFailed string    // why the last copy was not fetched, for status

	tunMu      sync.Mutex            // guards tunnel and the rest of the tun fields; taken after mu, before recMu
	tunnel     *tunnel.State         // the tunnel keys (tunnel.go); nil while sync away from home is off
	tunCtx     context.Context       // the group's context, for the tunnel; nil while in no group
	tunSelf    string                // this device's ID, for its tunnel address
	tunRun     *tunRun               // the hub or the link to it, while it runs
	tunThrough bool                  // connected to the hub through the tunnel now
	tunUsing   string                // the hub this member uses now; "" while it reaches none
	tunServing bool                  // on a hub: it serves now, since no hub above it answers
	givingWay  bool                  // on a hub that serves: it passes a hub above's offer on before it gives way
	tunErr     string                // what went wrong last, for status; "" if nothing
	tunDetail  string                // the underlying error
	tunFwd     *control.Forwarder    // on the hub: its registration with its forwarder; nil without one
	tunRelay   *control.Relay        // on a device with a relay: its link to it; nil without one
	tunRelayed int                   // member connections through the relay now
	guests     map[netip.Addr]*guest // on the hub: the guest tunnels of open remote invitations (invite.go)

	groupCtx    context.Context
	groupCancel context.CancelFunc
	wg          sync.WaitGroup
}

// Run runs the service until ctx is done.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Name == "" {
		cfg.Name, _ = os.Hostname()
	}
	if cfg.Discover == nil {
		cfg.Discover = mdnsDiscovery
	}
	if cfg.now == nil {
		cfg.now = benchtime.Now
	}
	if cfg.browseFor == 0 {
		cfg.browseFor = 10 * time.Second
	}
	cgnat, err := HomeCGNAT()
	if err != nil {
		return err
	}
	netguard.SetCGNAT(cgnat)
	if cgnat {
		cfg.Logf("cbb: 100.64.0.0/10 counts as the home network (CBB_HOME_CGNAT=1)")
	}
	if cfg.Interfaces == nil {
		if cfg.Interfaces, err = Interfaces(); err != nil {
			return err
		}
	}
	if len(cfg.Interfaces) > 0 {
		cfg.Logf("cbb: the member port and mDNS work only on %s (CBB_INTERFACES)", strings.Join(cfg.Interfaces, ", "))
	}
	if cfg.listen == nil || cfg.joinListen == nil {
		port, err := Port()
		if err != nil {
			return err
		}
		if cfg.listen == nil {
			cfg.listen = func() (net.Listener, error) { return listenPreferring(port) }
		}
		if cfg.joinListen == nil {
			cfg.joinListen = func() (net.Listener, error) { return listenPreferring(port) }
		}
	}
	if cfg.joinAddrs == nil {
		only := onlyIn(cfg.Interfaces)
		cfg.joinAddrs = func(port uint16) []string { return joinAddresses(port, only) }
	}
	if cfg.battery == nil {
		cfg.battery = hasBattery
	}
	if cfg.peerOf == nil {
		cfg.peerOf = connPeer
	}
	if cfg.atScreen == nil {
		cfg.atScreen = atScreen
	}
	if cfg.fallbackAfter == 0 {
		cfg.fallbackAfter = fallbackDial
	}
	if cfg.runner == nil && !cfg.actInSession {
		cfg.runner = actions.System()
	}
	s := &Service{cfg: cfg, logf: cfg.Logf, dialers: map[group.DeviceID]*dialer{}, watchers: map[*watcher]bool{}, restart: make(chan struct{}, 1),
		seen: map[group.DeviceID]time.Time{}, online: map[group.DeviceID]bool{}, unreached: map[group.DeviceID]bool{}, battery: cfg.battery(),
		startedMS: cfg.now().UnixMilli()}
	if s.cfg.runner == nil {
		// A Mac and Windows run the presets in the signed-in user's
		// session, through the agent.
		s.cfg.runner = sessionRunner{s}
	}
	if s.holdSetting, err = loadHolder(cfg.StateDir); err != nil {
		cfg.Logf("cbb: the holder setting: %v; using auto", err)
	}

	floor, err := loadMark(cfg.StateDir)
	if err != nil {
		return err
	}
	if f, reset := hlc.Floor(floor, benchtime.Now()); reset {
		cfg.Logf("cbb: the clock's saved mark (%s) is more than 7 days ahead of this device's clock; this device's clock was ahead and is right now, so it starts from it", time.UnixMilli(floor.Wall).UTC().Format(time.RFC3339))
		floor = f
	}
	clock := hlc.NewClock(benchtime.Now, floor, func(m hlc.Timestamp) error {
		err := atomicfile.Write(filepath.Join(cfg.StateDir, markFile), []byte(m.String()+"\n"), 0o600)
		if err != nil {
			cfg.Logf("cbb: saving the clock mark: %v", err)
		}
		return err
	})

	id, err := group.Load(cfg.StateDir)
	switch {
	case errors.Is(err, group.ErrNoGroup):
		cfg.Logf("cbb: this device is in no group yet")
		id = nil
	case err != nil:
		// The service keeps running without its group, so that cbb
		// says what is wrong, and refuses everything else, so that
		// nothing writes over the damaged file.
		s.broken = &control.RequestError{Msg: errBroken, Detail: err.Error()}
		cfg.Logf("cbb: %s (%v)", errBroken, err)
		id = nil
	}
	s.clock = clock

	s.nets = loadNetworks(cfg.StateDir, id != nil, cfg.Interfaces, cfg.Logf)
	if s.limits, err = loadLimits(cfg.StateDir); err != nil {
		cfg.Logf("cbb: the limits of a copy: %v; using %s and %s", err, SizeText(s.limits.Home), SizeText(s.limits.Away))
	}
	if s.content, err = openContent(filepath.Join(cfg.StateDir, contentDir), time.Now); err != nil {
		cfg.Logf("cbb: the cache of images and files: %v; this device does not serve or fetch them", err)
		s.content = nil
	}

	// The admin socket first: on Windows its directory is in the control
	// socket's, whose access list lets the group make directories.
	adminLn, err := listenControl(control.AdminSocketFor(cfg.Socket), true)
	if err != nil {
		return err
	}
	defer adminLn.Close()
	ln, err := listenControl(cfg.Socket, false)
	if err != nil {
		return err
	}
	defer ln.Close()
	go s.serveControl(ctx, ln, false)
	go s.serveControl(ctx, adminLn, true)

	if id != nil {
		if err := s.startGroup(id); err != nil {
			return err
		}
	}
	go s.watchSleep(ctx)
	if s.content != nil {
		go s.sweepContent(ctx, contentSweepEvery)
	}
	go s.applyKeyboard()
	defer s.closeKeyboard()
	defer s.endTVPairing()

	select {
	case <-ctx.Done():
		s.stopGroup()
		return nil
	case <-s.restart:
		cfg.Logf("cbb: %v", ErrRestart)
		s.stopGroup()
		return ErrRestart
	}
}

// errBroken is what the user sees when the device's group file cannot be
// read.
const errBroken = "this device's group file (identity.json in the service's state directory) is damaged, so the service does not start the group; restore the file from a backup, or remove clipboardbridge with its keys (uninstall --purge, -Purge on Windows), install it again and join"

// engine returns the sync engine, or nil while the device is in no group.
func (s *Service) engine() *clip.Engine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eng
}

func loadMark(dir string) (hlc.Timestamp, error) {
	data, err := os.ReadFile(filepath.Join(dir, markFile))
	if errors.Is(err, os.ErrNotExist) {
		return hlc.Timestamp{}, nil
	}
	if err != nil {
		return hlc.Timestamp{}, err
	}
	var ts hlc.Timestamp
	if err := ts.UnmarshalText([]byte(strings.TrimSpace(string(data)))); err != nil {
		return hlc.Timestamp{}, fmt.Errorf("%s: %w", markFile, err)
	}
	return ts, nil
}

// startGroup starts the network part with an identity: the member
// connections, discovery and the member port; on Linux also
// clipboardbridge.local. Its state is set only when all of it started.
//
// The group's context does not derive from Run's: only stopGroup ends it,
// after the goodbyes, so a stopping service leaves in order.
func (s *Service) startGroup(id *group.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.stopping:
		return errors.New("the service is stopping")
	case s.id != nil:
		return errors.New("this device is already in a group")
	}
	id = s.withAdminKey(id)
	gctx, cancel := context.WithCancel(context.Background())
	mode, err := loadMode(s.cfg.StateDir)
	if err != nil {
		s.logf("cbb: the sync mode: %v; using shared", err)
	}
	eng := clip.New(clip.Config{Self: string(id.ID), Clock: s.clock, Mode: mode, Wall: s.cfg.now})
	s.recMu.Lock()
	s.records = s.loadRecords(id)
	s.creds = s.loadCredentials(id, s.records)
	s.serverKeys = s.loadServerKeys()
	s.recMu.Unlock()
	tun := s.loadTunnel(id)
	s.tunMu.Lock()
	s.tunnel, s.tunCtx, s.tunSelf = tun, gctx, string(id.ID)
	s.guardLocked()
	s.tunMu.Unlock()
	tunKey, tunPSK := tunnelKey(tun)
	s.loadSealSecretLocked()
	nd := node.New(node.Config{
		Content: s.nodeContent(), Identity: id, Role: s.cfg.Role, Name: s.cfg.Name, OS: s.cfg.OS, Device: s.cfg.Device, Engine: eng, KeyStore: s.keyStore(id), Actions: s.actionsOn,
		OnWrite: s.write, OnRelay: s.relayed, Serves: s.serves, OnPeers: s.peersChanged, OnCert: s.certRenewed, OnAdmin: s.becomeAdmin, OnCommand: s.command,
		PhoneCAFor: s.phoneCAFor, OnPhoneCA: s.phoneCAReceived, Now: s.cfg.now, Logf: s.logf,
		Records: recordStore{s}, Credentials: credentialStore{s}, Releases: releaseStore{s}, Allow: s.allow, NoSecrets: s.noSecretsTo,
		TunnelKey: tunKey, TunnelPSK: tunPSK, OnTunnelKey: s.tunnelKeyOffered, OnTunnel: s.tunnelOffered, SealKey: s.sealPublic,
		HubShare: s.hubShare, OnHubs: s.hubsShared, OnEvidence: s.evidenceReceived, Evidence: s.ownEvidence(id),
	})
	// Every member listens, so that phones and lite members reach it, and
	// the other full members when it has the lower device ID.
	ln, err := s.cfg.listen()
	if err != nil {
		cancel()
		return err
	}
	dc := DiscoveryConfig{ID: string(id.ID), TXT: txt(id, s.priorityLocked(id), false), OnPeers: s.found, Logf: s.logf,
		Port: uint16(ln.Addr().(*net.TCPAddr).Port), Publish: s.nets.Publish, Only: s.only()}
	r, err := s.cfg.Discover(dc)
	if err != nil {
		ln.Close()
		cancel()
		return err
	}

	s.id, s.eng, s.nd, s.port = id, eng, nd, dc.Port
	s.groupCtx, s.groupCancel = gctx, cancel
	if err := s.adoptRootsLocked(); err != nil {
		s.logf("cbb: trusting the group's new root: %v", err)
	}
	nd.Rejoin() // the service just started; there are no connections yet
	s.wg.Add(4)
	go func() {
		defer s.wg.Done()
		s.renewLoop(gctx)
	}()
	go func() {
		defer s.wg.Done()
		s.claimLoop(gctx)
	}()
	go func() {
		defer s.wg.Done()
		s.statusLoop(gctx)
	}()
	go func() {
		defer s.wg.Done()
		s.ensureListed()
	}()
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.accept(gctx, ln)
	}()
	go func() {
		defer s.wg.Done()
		s.servePhone(gctx, ln.Addr())
	}()
	// Discovery has its own context, so it can say goodbye for
	// clipboardbridge.local before the member connections close.
	dctx, dcancel := context.WithCancel(gctx)
	s.responder, s.discoveryStop, s.discoveryDone = r, dcancel, make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		if err := r.Run(dctx); err != nil {
			s.logf("cbb: discovery: %v", err)
		}
	}(s.discoveryDone)
	s.electLocked() // alone, a member that can hold clipboardbridge.local holds it at once
	s.tunMu.Lock()
	s.runTunnelLocked()
	s.tunMu.Unlock()
	return nil
}

// stopGroup stops the network part: first discovery, which sends the
// goodbyes for this member's names, then the member connections, which say
// goodbye too, so the next holder takes clipboardbridge.local over at once.
func (s *Service) stopGroup() {
	s.mu.Lock()
	s.stopping = true
	cancel, nd, w, pw := s.groupCancel, s.nd, s.window, s.phoneWindow
	stopDiscovery, discoveryDone := s.discoveryStop, s.discoveryDone
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
	if pw != nil {
		pw.Close()
	}
	if stopDiscovery != nil {
		stopDiscovery()
		<-discoveryDone
	}
	if nd != nil {
		nd.Close()
	}
	s.tunMu.Lock()
	s.tunCtx = nil // a control request still running may not start the tunnel again
	s.stopTunnelLocked()
	s.tunMu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

// txtLocked returns the TXT record of this member.
func (s *Service) txtLocked() []string { return txt(s.id, s.priorityLocked(s.id), s.window != nil) }

// priorityLocked returns this member's priority for clipboardbridge.local,
// 0 if it never holds the name (see priority).
func (s *Service) priorityLocked(id *group.Identity) int {
	return priority(s.holdSetting, id != nil && id.Phone != nil, s.battery)
}

// txt returns a TXT record: the protocol version, the group tag, the
// holder priority if the member can hold clipboardbridge.local, and whether
// a pairing window is open.
func txt(id *group.Identity, prio int, window bool) []string {
	t := []string{"v=1", "g=" + group.Tag(id.GroupCA.Cert)}
	if prio > 0 {
		t = append(t, "h="+strconv.Itoa(prio))
	}
	if window {
		t = append(t, "p=1")
	}
	return t
}

// accept serves the member port: pairing connections while a window is
// open, member connections otherwise. Only addresses of the home network
// are accepted, and at most maxHandshakes connections that have not yet
// proved they belong to the group.
func (s *Service) accept(ctx context.Context, ln net.Listener) {
	slots := make(chan struct{}, maxHandshakes)
	acceptLoop(ctx, ln, s.logf, "the member port", func(raw net.Conn) {
		ap, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
		if !mdns.Published(ap.Addr()) && !ap.Addr().Unmap().IsLoopback() {
			raw.Close()
			return
		}
		if !ap.Addr().Unmap().IsLoopback() && !s.takesOn(raw.LocalAddr()) {
			// A network this device has not met its group on.
			s.logRepeat("cbb: a connection from %v to %v, on a network this device has not met its group on; closed", ap.Addr(), raw.LocalAddr())
			raw.Close()
			return
		}
		if !s.arrivedOn(raw) {
			raw.Close() // not from the interfaces the service is limited to
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			raw.Close()
			return
		}
		go s.serveMember(ctx, raw, func() { <-slots })
	})
}

// acceptLoop accepts connections until ctx is done or ln is closed. Other
// errors, such as running out of file descriptors, only pause it, with a
// growing pause as net/http does.
func acceptLoop(ctx context.Context, ln net.Listener, logf func(string, ...any), what string, handle func(net.Conn)) {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	defer ln.Close()
	var pause time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			pause = min(max(2*pause, 5*time.Millisecond), time.Second)
			logf("cbb: %s: %v; trying again in %v", what, err, pause)
			select {
			case <-ctx.Done():
				return
			case <-time.After(pause):
			}
			continue
		}
		pause = 0
		handle(c)
	}
}
