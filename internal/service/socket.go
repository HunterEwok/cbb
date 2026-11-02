// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
	"github.com/HunterEwok/clipboardbridge/internal/benchtime"
	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/mdns"
	"github.com/HunterEwok/clipboardbridge/internal/netguard"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/version"
)

// serveControl answers on the control socket, or with admin on the admin
// socket, which alone takes the operations that change the group.
func (s *Service) serveControl(ctx context.Context, ln net.Listener, admin bool) {
	what := "the control socket"
	if admin {
		what = "the admin socket"
	}
	var users controlUsers
	acceptLoop(ctx, ln, s.logf, what, func(c net.Conn) {
		user := connPeer(c).String()
		if !users.add(user) {
			s.logf("service: %s has %d connections to %s open; refused another", user, maxControlPerUser, what)
			c.Close()
			return
		}
		control.SetBuffers(c)
		go func() {
			defer users.done(user)
			s.handleControl(ctx, c, admin)
		}()
	})
}

// maxControlPerUser bounds one user's open connections to a control
// socket, so that one user of the group cannot use up the service's
// descriptors; a user's watchers and commands need a few. firstRequestTime
// bounds how long a connection may wait before its first request.
const maxControlPerUser = 64

var firstRequestTime = 30 * time.Second // a variable for the tests

// controlUsers counts the open connections of each user.
type controlUsers struct {
	mu sync.Mutex
	n  map[string]int
}

func (u *controlUsers) add(user string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.n == nil {
		u.n = map[string]int{}
	}
	if u.n[user] >= maxControlPerUser {
		return false
	}
	u.n[user]++
	return true
}

func (u *controlUsers) done(user string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.n[user]--; u.n[user] <= 0 {
		delete(u.n, user)
	}
}

func reply(c net.Conn, h control.Header, payload []byte) error {
	h.Op = control.OpReply
	return control.Write(c, &control.Message{Header: h, Payload: payload})
}

// fail answers a request with err. The cause of a pair.CauseError goes in
// the detail, which cbb shows only in debug mode.
func fail(c net.Conn, err error) {
	h := control.Header{Error: err.Error(), Done: true}
	var ce *pair.CauseError
	if errors.As(err, &ce) {
		h.Detail = ce.Err.Error()
		h.Error = strings.TrimSuffix(h.Error, ": "+h.Detail)
	}
	reply(c, h, nil)
}

// errNoGroup is the error for a request that needs a group.
func (s *Service) errNoGroup() error {
	return errors.New("this device is in no group; run cbb new here to start one, or cbb pair to join one")
}

func (s *Service) handleControl(ctx context.Context, c net.Conn, admin bool) {
	defer c.Close()
	r := control.NewReader(c)
	c.SetReadDeadline(time.Now().Add(firstRequestTime))
	m, err := r.Read()
	if err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	if control.IsAdmin(m.Op) && !admin {
		fail(c, fmt.Errorf("%q changes the group, so the service takes it only on its admin socket, which only the administrator reaches", m.Op))
		return
	}
	if s.broken != nil {
		reply(c, control.Header{Error: s.broken.Msg, Detail: s.broken.Detail, Done: true}, nil)
		return
	}
	switch m.Op {
	case control.OpCopy:
		kind, via, err := parseKind(m.Kind, m.Via)
		if err == nil {
			err = s.withNode(func(nd *node.Node) error { return nd.Send(string(m.Payload), kind, via) })
		}
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Done: true}, nil)
	case control.OpCopyMedia, control.OpCopiedMedia:
		if err := s.copyMedia(c, r, m); err != nil {
			fail(c, err)
			// Read what the client still sends before closing: closing a
			// socket with unread data resets it, and on Windows the reset
			// drops the reply before the client reads it.
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			io.Copy(io.Discard, c)
			return
		}
		reply(c, control.Header{Done: true}, nil)
	case control.OpPasteMedia:
		if err := s.pasteMedia(ctx, c); err != nil {
			fail(c, err)
		}
	case control.OpConfig:
		if m.Name != "" {
			if err := s.setConfig(m.Name, m.Value); err != nil {
				fail(c, err)
				return
			}
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpPaste:
		e := s.engine()
		if e == nil {
			fail(c, s.errNoGroup())
			return
		}
		text, kind, ok := pasteText(e)
		if !ok {
			if hasMedia(e) {
				fail(c, errors.New("the clipboard holds images or files without a text; cbb paste -o DIR saves them"))
				return
			}
			fail(c, errors.New("the clipboard is empty"))
			return
		}
		reply(c, control.Header{Kind: kindName(kind), Done: true}, []byte(text))
	case control.OpMode:
		if m.Device != "" {
			if err := s.setModeOn(ctx, m.Device, m.Name); err != nil {
				fail(c, err)
				return
			}
			reply(c, control.Header{Done: true}, nil)
			return
		}
		if err := s.setMode(m.Name); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpStatus:
		reply(c, control.Header{Status: s.statusWithRemoved(), Done: true}, nil)
	case control.OpRelease:
		var r node.ReleaseSet
		if err := json.Unmarshal(m.Payload, &r); err != nil {
			fail(c, fmt.Errorf("the request carries no release: %w", err))
			return
		}
		if err := s.putRelease(r); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Done: true}, nil)
	case control.OpReleaseFile:
		if err := s.receiveReleaseFile(r, m); err != nil {
			fail(c, err)
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			io.Copy(io.Discard, c)
			return
		}
		reply(c, control.Header{Done: true}, nil)
	case control.OpReleaseGet:
		if err := s.sendReleaseFile(ctx, c, m); err != nil {
			fail(c, err)
		}
	case control.OpPasteOn:
		if err := s.sendPaste(ctx, m); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Done: true}, nil)
	case control.OpKeyboard:
		if err := s.keyboard(ctx, m); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpKeys:
		// The uinput helper runs as root with no capability, so it reaches
		// the control socket through its group, not the admin socket.
		if p := s.cfg.peerOf(c); !p.known || !p.privileged() {
			fail(c, errors.New("only the uinput helper, as root, asks for a paste's keys"))
			return
		}
		if err := s.takeKeys(m.Keys, m.Name, m.Value); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Done: true}, nil)
	case control.OpRemote:
		if err := s.remote(ctx, m); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpReceive:
		if err := s.setReceive(ctx, m); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpActionSet:
		if err := s.setAction(m); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpActionDel:
		if err := s.removeAction(m); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpActionOn:
		if err := s.runActionOn(ctx, m); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Done: true}, nil)
	case control.OpActionOff:
		if err := s.actionsOffOn(ctx, m); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpNew:
		if _, err := s.newGroup(); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpPair:
		s.pair(ctx, c, r)
	case control.OpPairPhone:
		s.pairPhone(ctx, c, r, m.NewToken)
	case control.OpJoin:
		s.join(ctx, c, r, m)
	case control.OpInvite:
		s.invite(ctx, c, r, m)
	case control.OpWatch:
		s.watch(ctx, c, r, m)
	case control.OpDevices:
		devs, err := s.devices()
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Devices: devs, Done: true}, nil)
	case control.OpAway:
		if err := s.away(ctx, m); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpNetwork:
		s.learnNetworks()
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpHolder:
		if err := s.setHolder(m.Name); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpAdmin:
		name, err := s.makeAdmin(m.Name, m.Consent)
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Name: name, Done: true}, nil)
	case control.OpTakeover:
		name, err := s.takeOver(m.Name)
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Name: name, Done: true}, nil)
	case control.OpRevoke:
		name, err := s.revoke(m.Name)
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Name: name, Done: true}, nil)
	case control.OpDelay:
		if err := s.setTakeoverDelay(m.Value); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Done: true}, nil)
	case control.OpHubs:
		if err := s.setHubs(m.Hubs); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Done: true}, nil)
	case control.OpRename:
		name, err := s.rename(m.Name, m.NewName)
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Name: name, Done: true}, nil)
	case control.OpResolve:
		who, err := s.resolveHistories()
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Name: strings.Join(who, ", "), Done: true}, nil)
	case control.OpFreeze, control.OpThaw:
		name, err := s.freeze(m.Name, m.Op == control.OpFreeze)
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Name: name, Done: true}, nil)
	default:
		fail(c, fmt.Errorf("unknown operation %q", m.Op))
	}
}

func parseKind(kind, via string) (clip.Kind, clip.Via, error) {
	var k clip.Kind
	var v clip.Via
	if kind == "" {
		kind = control.KindText
	}
	if via == "" {
		via = control.ViaCopy
	}
	if err := k.UnmarshalText([]byte(kind)); err != nil {
		return 0, 0, err
	}
	if err := v.UnmarshalText([]byte(via)); err != nil {
		return 0, 0, err
	}
	return k, v, nil
}

// secretLeft returns how long the secret in the member's own clipboard
// may still be used: the secret lifetime less its age.
func (s *Service) secretLeft() time.Duration {
	e := s.engine()
	if e == nil {
		return 0
	}
	if _, kind, age, ok := e.Local(); ok && kind == clip.Secret {
		return max(clip.DefaultSecretTTL-age, time.Millisecond)
	}
	return time.Millisecond
}

func kindName(k clip.Kind) string {
	b, _ := k.MarshalText()
	return string(b)
}

func viaName(v clip.Via) string {
	b, _ := v.MarshalText()
	return string(b)
}

func (s *Service) withNode(f func(*node.Node) error) error {
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	if nd == nil {
		return s.errNoGroup()
	}
	return f(nd)
}

func (s *Service) status() *control.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &control.Status{Role: string(s.cfg.Role), OS: s.cfg.OS, Version: version.String(), Holder: s.holder,
		HoldSetting: s.holdSetting, HoldPriority: s.priorityLocked(s.id), Battery: s.battery}
	st.Release, st.Update = s.releaseStatus()
	st.TVs = s.tvStatus()            // a TV's remote needs no group
	st.Keyboard = s.keyboardStatus() // nor does the Bluetooth keyboard
	if s.id == nil {
		return st
	}
	st.Device, st.Group = string(s.id.ID), group.Tag(s.id.GroupCA.Cert)
	st.CertEndsMS = s.id.Cert.NotAfter.UnixMilli()
	st.Mode = s.eng.Mode().String()
	skews := s.eng.Skews()
	for _, p := range s.nd.Peers() {
		st.Peers = append(st.Peers, control.Device{ID: string(p.ID), Role: string(p.Role), OS: p.OS, SkewMS: skews[string(p.ID)].Milliseconds()})
	}
	for id := range s.unreached {
		st.Unreached = append(st.Unreached, string(id))
	}
	slices.Sort(st.Unreached)
	st.Port, _ = Port()
	st.Quiet = s.nets.Unknown()
	st.Away = s.awayStatus()
	s.relayNames(st.Away)
	st.Paste = s.pasteStatusLocked()
	st.Actions = s.actionStatus()
	st.Media = s.mediaStatus()
	return st
}

// statusWithRemoved is status, with Removed set when the records revoke
// this device. The records' lock is not taken under s.mu.
func (s *Service) statusWithRemoved() *control.Status {
	st := s.status()
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id == nil {
		return st
	}
	switch err := s.allow(id.ID, ownChain(id)); {
	case errors.Is(err, group.ErrStopped):
	case errors.Is(err, group.ErrRecordsOnly):
		st.TakenOverBy = s.takenOverBy(id)
	case err != nil && s.frozen(id):
		st.Frozen = true
	case err != nil:
		st.Removed = true
	}
	s.groupStatus(st)
	return st
}

// groupStatus adds to st what the records stop and why: the claims that
// wait or stop the group, the conflicts, and the records of a later
// version (docs/protocol.md, section 10, "Stopping the exchange").
func (s *Service) groupStatus(st *control.Status) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return
	}
	gs := s.records.State()
	if gs.Stop != authority.StopNone {
		st.Stop = gs.Stop
	}
	for _, c := range gs.Claims {
		switch c.State {
		case "pending", "competing", "disputed":
			st.Claims = append(st.Claims, control.Claim{By: s.records.SignerName(c.Claimant), State: c.State, LeftMS: c.LeftMS})
		}
	}
	for _, c := range gs.Conflicts {
		cf := control.Conflict{Kind: c.Kind}
		for _, k := range c.Signers {
			cf.Devices = append(cf.Devices, s.records.SignerName(k))
		}
		st.Conflicts = append(st.Conflicts, cf)
	}
	st.Newer = len(gs.Newer)
}

// pair opens a pairing window and reports its end; a client that hangs up
// closes the window.
func (s *Service) pair(ctx context.Context, c net.Conn, r *control.Reader) {
	w, _, end, err := s.openWindow(pair.NewCode())
	if err != nil {
		fail(c, err)
		return
	}
	defer end()
	s.mu.Lock()
	port := s.port
	s.mu.Unlock()
	reply(c, control.Header{Code: w.Code(), Expires: int(pair.Lifetime / time.Second), Address: localAddress(port)}, nil)
	hangup := make(chan struct{})
	go func() {
		r.Read() // returns when the client hangs up
		close(hangup)
	}()
	select {
	case <-w.Done():
	case <-hangup:
		return
	case <-ctx.Done():
		return
	}
	res, err := s.windowResult(w)
	end()
	if err != nil {
		fail(c, err)
		return
	}
	reply(c, control.Header{Name: res.Info.Name, Done: true}, nil)
}

// openWindow reserves the pairing window and opens it with code, on the
// group's root or an admin; the window is published and takes pairing
// connections on the member port. end closes the window and frees it; it may be called
// more than once, and runs before the last answer to a client, so it can
// pair again at once.
func (s *Service) openWindow(code string) (*pair.Window, *group.Identity, func(), error) {
	s.mu.Lock()
	id, busy, joining := s.id, s.window != nil || s.opening, s.joining
	if !busy && !joining {
		s.opening = true
	}
	s.mu.Unlock()
	switch {
	case busy:
		return nil, nil, nil, errors.New("a pairing window is already open: stop the cbb pair that opened it (Ctrl+C in its terminal), or wait until it closes, 5 minutes after it opened")
	case joining:
		return nil, nil, nil, errors.New("this device is joining a group")
	}
	var w *pair.Window
	ended := false
	end := func() {
		if ended {
			return
		}
		ended = true
		if w != nil {
			w.Close()
		}
		s.mu.Lock()
		if s.window != nil && s.window == w {
			s.window = nil
			s.responder.SetTXT(s.txtLocked())
		}
		s.opening = false
		s.mu.Unlock()
	}
	switch {
	case id == nil:
		end()
		return nil, nil, nil, s.errNoGroup()
	case !id.IsAdmin():
		end()
		return nil, nil, nil, s.errNotAdmitter()
	}
	opened, err := pair.Open(id, code, pair.Options{Now: benchtime.Now, Records: s.pathRecords, ClaimTimes: s.claimTimes, Taken: s.idTaken})
	if err != nil {
		end()
		return nil, nil, nil, err
	}
	w = opened
	s.learnNetworks() // the user opens a window where the group is
	s.mu.Lock()
	s.window = w
	s.responder.SetTXT(s.txtLocked())
	s.opening = false
	s.mu.Unlock()
	return w, id, end, nil
}

// newGroup creates a group with this device as its root and starts it;
// a device that is in a group already keeps it.
func (s *Service) newGroup() (*group.Identity, error) {
	s.mu.Lock()
	in, busy := s.id != nil, s.joining
	s.mu.Unlock()
	switch {
	case in:
		return nil, errors.New("this device is already in a group; cbb status shows it")
	case busy:
		return nil, errors.New("this device is joining a group")
	}
	if err := s.keysAllowed(); err != nil {
		return nil, err
	}
	return s.createGroup()
}

// errNotAdmitter is the error for a member that may not admit devices: it
// names those that may.
func (s *Service) errNotAdmitter() error {
	devs, err := s.devices()
	if err != nil {
		return err
	}
	var names []string
	for _, d := range devs {
		if (d.Root || d.Admin) && !d.Self {
			names = append(names, d.Name)
		}
	}
	if len(names) == 0 {
		return errors.New("only the group's root or an admin adds devices, and this device is neither")
	}
	return fmt.Errorf("only the group's root or an admin adds devices; run cbb pair on %s", strings.Join(names, " or "))
}

// createGroup creates a group on a device in no group, with this device as
// its root, and starts it.
// One creation runs at a time, so two requests cannot save two identities.
func (s *Service) createGroup() (*group.Identity, error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id != nil {
		return id, nil // another request created it meanwhile
	}
	id, err := group.Create(time.Now())
	if err == nil {
		err = id.Save(s.cfg.StateDir)
	}
	if err == nil {
		err = s.newDeviceMode()
	}
	if err == nil {
		s.nets.learnAll() // a group is made where it is used
		err = s.startGroup(id)
	}
	if err != nil {
		return nil, fmt.Errorf("creating the group: %w", err)
	}
	s.logf("cbb: created a new group %s", group.Tag(id.GroupCA.Cert))
	return id, nil
}

// windowResult returns how a window that closed ended, and logs it.
func (s *Service) windowResult(w *pair.Window) (*pair.Result, error) {
	res, err := w.Result()
	if err != nil {
		return nil, err
	}
	if !res.Confirmed {
		// It holds a certificate, and on Linux the CA keys, but may not
		// have stored them.
		s.logf("cbb: %s (%s) got its certificate but did not confirm it stored it", res.Info.Name, res.Device)
		return nil, fmt.Errorf("%s got its certificate but did not confirm that it stored it; check it with cbb status there, and pair it again if needed", res.Info.Name)
	}
	s.logf("cbb: %s (%s) joined the group", res.Info.Name, res.Device)
	s.recordAdmitted(res)
	return res, nil
}

// localAddress returns an address of this member that a joining device can
// use when multicast does not work: the first private IPv4 address.
func localAddress(port uint16) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil && ip4.IsPrivate() {
				return net.JoinHostPort(ip4.String(), fmt.Sprint(port))
			}
		}
	}
	return ""
}

// joinTimeout bounds a whole join: browsing, dialing and the attempt.
const joinTimeout = 2 * time.Minute

// join joins a group with a code. With Listen it waits for a member to dial
// this device, at the addresses and with the certificate it answers with
// first, for the QR code; otherwise it dials the address the user gave, or
// the one member that announces an open pairing window; with an
// invitation, it joins through the hub's tunnel (invite.go). A client that
// hangs up cancels the join.
func (s *Service) join(ctx context.Context, c net.Conn, r *control.Reader, m *control.Message) {
	var code string
	var err error
	if m.Invite == "" {
		if code, err = pair.NormalizeCode(m.Code); err != nil {
			fail(c, err)
			return
		}
	}
	s.mu.Lock()
	inGroup, busy := s.id != nil, s.joining || s.opening
	if !inGroup && !busy {
		s.joining = true
	}
	s.mu.Unlock()
	switch {
	case inGroup:
		fail(c, errors.New("this device is already in a group"))
		return
	case busy:
		fail(c, errors.New("a join or a pairing is already running here"))
		return
	}
	// end ends the join; it runs before the answer, so the client can try
	// again at once.
	ended := false
	end := func() {
		if !ended {
			ended = true
			s.mu.Lock()
			s.joining = false
			s.mu.Unlock()
		}
	}
	defer end()
	wait := joinTimeout + s.cfg.browseFor
	if m.Invite != "" {
		wait = joinTimeout + confirmWait
	} else if m.Listen {
		wait = pair.Lifetime
		if m.Expires > 0 {
			wait = min(time.Duration(m.Expires)*time.Second, wait)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	go func() {
		r.Read() // returns when the client hangs up, or when the join ends
		cancel()
	}()

	s.mu.Lock()
	s.loadSealSecretLocked()
	sealKey := s.sealPublic
	s.mu.Unlock()
	j, err := pair.NewJoiner(pair.Info{Name: s.cfg.Name, OS: s.cfg.OS, Seal: sealKey})
	if err != nil {
		end()
		fail(c, err)
		return
	}
	if s.cfg.joinID != nil {
		j.ID = s.cfg.joinID()
	}
	var id *group.Identity
	var after func(bool)
	switch {
	case m.Invite != "":
		id, after, err = s.joinInvite(ctx, c, j, m)
	case m.Listen:
		id, err = s.listenForMember(ctx, c, j, code)
	default:
		id, err = s.dialMember(ctx, j, code, m.Address)
	}
	if err == nil {
		err = s.newDeviceMode()
	}
	if err == nil {
		if m.Invite == "" {
			// Joined at home; a remote invitation comes from away, so the
			// network it came through stays unknown.
			s.nets.learnAll()
		}
		err = s.startGroup(id)
		if after != nil {
			after(err == nil)
		}
	}
	end()
	if err != nil {
		fail(c, err)
		return
	}
	if !m.Listen && m.Address != "" && j.Member != "" {
		s.dialJoined(j.Member, m.Address)
	}
	reply(c, control.Header{Done: true}, nil)
}

// saveJoined returns what saves the identity a join of j made: first the
// records that lead to its roots, so that it never trusts roots its records
// do not name, then the identity.
func (s *Service) saveJoined(j *pair.Joiner) func(*group.Identity) error {
	return func(id *group.Identity) error {
		recs := group.NewRecords(id.GroupCA.Cert)
		recs.AddAll(j.Records)
		recs.TakeClaimTimes(j.ClaimTimes)
		if err := recs.Save(s.cfg.StateDir); err != nil {
			return err
		}
		return id.Save(s.cfg.StateDir)
	}
}

// pathRecords returns the records that lead to the group's roots, for a
// Welcome.
func (s *Service) pathRecords() []group.Record {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return nil
	}
	return s.records.PathRecords()
}

// claimTimes returns when this member first held each claim, for the
// Welcome.
func (s *Service) claimTimes() []group.ClaimTime {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return nil
	}
	return s.records.ClaimTimes()
}

// dialMember joins at the address the user gave, or at the one member that
// announces an open pairing window. It tries that member's addresses until
// one answers, and stops after the first attempt in which the other side
// could check the code, so a device on the network that only pretends to
// pair gets one guess at most.
func (s *Service) dialMember(ctx context.Context, j *pair.Joiner, code, address string) (*group.Identity, error) {
	addrs := []string{address}
	if address == "" {
		var err error
		if addrs, err = s.findPairing(ctx, s.cfg.browseFor); err != nil {
			return nil, err
		}
	}
	var lastErr error
	for i, addr := range addrs {
		if i == pair.MaxFailures {
			break
		}
		d := net.Dialer{Timeout: handshakeTimeout, Control: netguard.Control}
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = err
			continue
		}
		id, err := j.Join(ctx, raw, code, s.saveJoined(j))
		if err == nil {
			return id, nil
		}
		if ctx.Err() != nil {
			err = fmt.Errorf("the join was cancelled or took too long: %w", err)
		}
		lastErr = err
		if pair.Spent(err) || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// listenForMember waits for a member, or a phone, to dial this device and
// admit it. It first answers the client with the addresses it listens at and
// the fingerprint of the joiner's certificate, for the QR code. Only devices
// on the home network may connect, one attempt at a time; the member
// confirms the code first, so a wrong attempt reveals nothing, and the join
// ends after three of them.
func (s *Service) listenForMember(ctx context.Context, c net.Conn, j *pair.Joiner, code string) (*group.Identity, error) {
	fp, err := j.Fingerprint()
	if err != nil {
		return nil, err
	}
	ln, err := s.cfg.joinListen()
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	reply(c, control.Header{Addrs: s.cfg.joinAddrs(port), Fingerprint: fp}, nil)
	failures := 0
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil, errors.New("no device added this one in time; scan the QR code with the phone, or run cbb pair on the group's root or an admin and type its code here")
			}
			return nil, err
		}
		ap, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
		if !mdns.Published(ap.Addr()) && !ap.Addr().Unmap().IsLoopback() || !s.arrivedOn(raw) {
			raw.Close()
			continue
		}
		id, err := j.Accept(ctx, raw, code, s.saveJoined(j))
		if err == nil {
			return id, nil
		}
		s.logf("cbb: a pairing attempt from %s failed: %v", ap.Addr(), err)
		switch {
		case ctx.Err() != nil:
			return nil, fmt.Errorf("the join was cancelled or took too long: %w", err)
		case pair.Spent(err):
			return nil, err // the welcome came, but saving failed
		case errors.Is(err, pair.ErrWrongCode):
			if failures++; failures >= pair.MaxFailures {
				return nil, pair.ErrTooMany
			}
		}
	}
}

// joinAddresses returns where a listening join can be reached: the
// addresses mDNS would publish, IPv4 first, at most four, on the
// interfaces only allows (all if nil).
func joinAddresses(port uint16, only func(string) bool) []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var v4, v6 []string
	for _, ifc := range ifs {
		if only != nil && !only(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			// Link-local addresses need a zone, which a QR code cannot carry.
			if !ok || !mdns.Published(ip) || ip.IsLinkLocalUnicast() {
				continue
			}
			hp := netip.AddrPortFrom(ip.Unmap(), port).String()
			if ip.Unmap().Is4() {
				v4 = append(v4, hp)
			} else {
				v6 = append(v6, hp)
			}
		}
	}
	all := append(v4, v6...)
	return all[:min(len(all), 4)]
}

// pairingSettle is how long a joiner listens for other pairing windows
// after it found one.
const pairingSettle = 2 * time.Second

// findPairing returns the addresses of the one member that announces an
// open pairing window, best first, browsing for up to browse. When
// more than one announces a window, it refuses: the user gives the address
// that pair showed. Once one window is found it listens a little longer
// (pairingSettle) for others, which answer the same query a moment later,
// so that a code is never tried on another group's window.
func (s *Service) findPairing(ctx context.Context, browse time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, browse)
	defer cancel()
	found := make(chan []mdns.Peer, 1)
	d, err := s.cfg.Discover(DiscoveryConfig{
		ID: "browse-" + clip.NewID()[:16], BrowseOnly: true, Only: s.only(), Logf: s.logf,
		OnPeers: func(peers []mdns.Peer) {
			var open []mdns.Peer
			for _, p := range peers {
				if v, _ := p.TXTValue("p"); v == "1" && len(p.Addrs) > 0 {
					open = append(open, p)
				}
			}
			if len(open) > 0 {
				// Only the newest set counts.
				select {
				case <-found:
				default:
				}
				found <- open
			}
		},
	})
	if err != nil {
		return nil, err
	}
	go d.Run(ctx)
	select {
	case open := <-found:
		settle := time.NewTimer(pairingSettle)
		defer settle.Stop()
		for waiting := true; waiting; {
			select {
			case open = <-found:
			case <-settle.C:
				waiting = false
			case <-ctx.Done():
				waiting = false
			}
		}
		if len(open) > 1 {
			var ids []string
			for _, p := range open {
				ids = append(ids, p.ID)
			}
			return nil, fmt.Errorf("%d devices announce a pairing window (%s); give the address that cbb pair showed", len(open), strings.Join(ids, ", "))
		}
		return addresses(open[0]), nil
	case <-ctx.Done():
		return nil, errors.New("no member with an open pairing window found; run cbb pair on the group's root or an admin, or give its address")
	}
}

// watcher is a desktop connector or pasteboard agent connected to the
// socket, or a paste target without a clipboard: the tmux or console
// helper, or the Mac app.
type watcher struct {
	out       chan node.Write
	inject    string       // the target it offers for remote paste; "" for none
	pasteOnly bool         // it holds no clipboard, whatever its target
	act       bool         // it runs the quick actions in its session
	images    bool         // its clipboard takes and gives images
	files     bool         // and files
	html      bool         // and formatted text
	injects   chan *inject // remote pastes for it
	peer      peer         // its user, read when it offers a target or the actions
}

// board says whether the watcher holds a clipboard: the tmux and console
// helpers and the Mac app only paste, so they get no writes and report no
// copies.
func (w *watcher) board() bool {
	return !w.pasteOnly && w.inject != targetTmux && w.inject != targetConsole
}

// takes says whether the watcher's clipboard takes the copy m whole:
// files, an image, or formatted text.
func (w *watcher) takes(m *clip.Manifest) bool {
	if m.Files() {
		return w.files
	}
	return w.images && imageCopy(m) || w.html && htmlCopy(m)
}

// send queues a write. A watcher that does not keep up loses its oldest
// queued write, never the newest: the clipboard must end on the latest.
func (w *watcher) send(wr node.Write) {
	for {
		select {
		case w.out <- wr:
			return
		default:
		}
		select {
		case <-w.out:
		default:
		}
	}
}

// watch serves a watcher: writes go out, reported copies come in. The watch
// request carries what the clipboard holds. A write that no watcher got,
// such as the group's text after the service started, goes to the clipboard
// instead, if it is still the member's own text.
func (s *Service) watch(ctx context.Context, c net.Conn, r *control.Reader, m *control.Message) {
	w := &watcher{out: make(chan node.Write, 16), injects: make(chan *inject, 1)}
	switch m.Inject {
	case "", targetDesktop, targetTmux, targetConsole:
		w.inject = m.Inject
	default:
		s.logf("cbb: a watcher offers the paste target %q, which is not known", m.Inject)
	}
	w.pasteOnly, w.act, w.images, w.files, w.html = m.PasteOnly, m.Act, m.Images, m.Files, m.HTML
	if w.inject != "" || w.act {
		w.peer = s.cfg.peerOf(c)
		// Whether the user is at the screen is asked at each paste; a user
		// the system does not name, or a console helper that is not root,
		// never takes one.
		if w.inject != "" && (!w.peer.known || w.inject == targetConsole && !w.peer.privileged()) {
			s.logRepeat("cbb: a watcher offers the paste target %s as %s, which may not take it; it gets no remote pastes", w.inject, w.peer)
			w.inject = ""
		}
		if w.act && !w.peer.known {
			s.logRepeat("cbb: a watcher offers to run the quick actions as %s; it runs none", w.peer)
			w.act = false
		}
	}
	s.mu.Lock()
	eng := s.eng
	if eng == nil {
		s.mu.Unlock()
		fail(c, s.errNoGroup())
		return
	}
	replay := false
	if p := s.pending; p != nil && w.board() {
		text, _, _, ok := eng.Local()
		replay = ok && text == p.Text
		s.pending = nil
		if replay {
			w.send(*p)
		}
	}
	if !replay && len(m.Payload) > 0 && w.board() {
		if kind, _, err := parseKind(m.Kind, m.Via); err != nil {
			s.logf("cbb: a watcher reported a clipboard that is not understood: %v", err)
		} else {
			eng.ClipboardIs(string(m.Payload), kind)
		}
	}
	s.watchers[w] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.watchers, w)
		s.mu.Unlock()
	}()
	reply(c, control.Header{}, nil)
	done := make(chan struct{})
	var injMu sync.Mutex
	injected := map[uint64]*inject{}
	answer := func(seq uint64, res node.Result) {
		injMu.Lock()
		in := injected[seq]
		delete(injected, seq)
		injMu.Unlock()
		if in != nil {
			s.endKeys(in.keys)
			res.ID = in.body.ID
			in.done <- res
		}
	}
	var injSeq uint64
	go func() {
		defer close(done)
		for {
			m, err := r.Read()
			if err != nil {
				return
			}
			if m.Op == control.OpInjected || m.Op == control.OpActed {
				res := node.Result{Status: node.ResultDone}
				if m.Error != "" {
					res.Status, res.Reason = node.ResultFailed, m.Error
					if m.Refused {
						res.Status = node.ResultRefused
					}
					if m.Detail != "" {
						res.Reason += ": " + m.Detail
					}
				}
				answer(m.Seq, res)
				continue
			}
			if !w.board() {
				s.logf("cbb: the %s paste target sent %q, which it does not send", w.inject, m.Op)
				continue
			}
			kind, via, err := parseKind(m.Kind, m.Via)
			if err != nil {
				s.logf("cbb: a watcher's report is not understood: %v", err)
				continue
			}
			switch m.Op {
			case control.OpCopied:
				s.withNode(func(nd *node.Node) error {
					_, err := nd.Copied(string(m.Payload), kind, via)
					return err
				})
			case control.OpClipboard:
				if e := s.engine(); e != nil {
					e.ClipboardIs(string(m.Payload), kind)
				}
			default:
				s.logf("cbb: a watcher sent %q, which is not a report", m.Op)
			}
		}
	}()
	for {
		select {
		case wr := <-w.out:
			// The clipboard will hold this text. A report that came in
			// after the engine decided on it, such as the watch request
			// itself, must not leave the engine thinking otherwise.
			if e := s.engine(); e != nil && wr.Kind != clip.Media {
				if text, _, _, ok := e.Local(); !ok || text != wr.Text {
					e.ClipboardIs(wr.Text, wr.Kind)
				}
			}
			h := control.Header{Op: control.OpWrite, Kind: kindName(wr.Kind), Via: viaName(wr.Via), Seq: wr.Seq}
			if wr.Kind == clip.Secret {
				h.TTLMS = s.secretLeft().Milliseconds()
			}
			if control.Write(c, &control.Message{Header: h, Payload: []byte(wr.Text)}) != nil {
				return
			}
		case in := <-w.injects:
			injSeq++
			in.keys = s.grantKeys(in, w)
			injMu.Lock()
			injected[injSeq] = in
			injMu.Unlock()
			h := control.Header{Op: control.OpInject, Seq: injSeq, Method: in.body.Mode, Enter: in.body.Enter, Kind: in.body.Kind, Name: s.deviceName(in.body.By), Keys: in.keys, NoLockCheck: in.noLockCheck}
			if in.body.Type == group.CommandAction {
				h = control.Header{Op: control.OpAct, Seq: injSeq, Name: in.body.Action, Command: in.command}
			}
			if control.Write(c, &control.Message{Header: h, Payload: []byte(in.text)}) != nil {
				answer(injSeq, node.Result{Status: node.ResultFailed, Reason: "the connection to the paste target closed"})
				return
			}
		case <-done:
			return
		case <-ctx.Done():
			return
		}
	}
}
