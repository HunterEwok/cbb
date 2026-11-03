// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mdns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/HunterEwok/cbb/internal/netguard"
)

// fakeLink is a network segment: multicast reaches every interface on it,
// the sender's own included, as multicast loopback does.
type fakeLink struct {
	mu    sync.Mutex
	ports []*fakePort
}

// fakePort is one interface of a host, on one link.
type fakePort struct {
	host  *fakeHost
	link  *fakeLink
	index int
	name  string
	mu    sync.Mutex
	pfx   []netip.Prefix
}

func (p *fakePort) prefixes() []netip.Prefix {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.pfx)
}

// setAddrs changes the interface's addresses, as DHCP might.
func (p *fakePort) setAddrs(addrs ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pfx = prefixes(addrs...)
}

// sentPacket is a packet a host sent, for tests to inspect.
type sentPacket struct {
	data    []byte
	dst     netip.AddrPort
	ifIndex int
}

type fakeHost struct {
	mu      sync.Mutex
	cut     bool // off the network: it sends and gets nothing, as behind a firewall
	ports   []*fakePort
	packets chan packet
	sent    chan sentPacket
	once    sync.Once
	closed  chan struct{}
}

func prefixes(addrs ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range addrs {
		ip := netip.MustParseAddr(a)
		bits := 24
		if ip.Is6() {
			bits = 64
		}
		out = append(out, netip.PrefixFrom(ip, bits))
	}
	return out
}

func newHost() *fakeHost {
	return &fakeHost{packets: make(chan packet, 1024), sent: make(chan sentPacket, 1024), closed: make(chan struct{})}
}

// attach puts the host on a link with an interface and its addresses.
func (h *fakeHost) attach(l *fakeLink, name string, addrs ...string) *fakePort {
	h.mu.Lock()
	p := &fakePort{host: h, link: l, index: len(h.ports) + 1, name: name, pfx: prefixes(addrs...)}
	h.ports = append(h.ports, p)
	h.mu.Unlock()
	l.mu.Lock()
	l.ports = append(l.ports, p)
	l.mu.Unlock()
	return p
}

// setCut takes the host off the network, or puts it back, without a change
// to its interfaces.
func (h *fakeHost) setCut(cut bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cut = cut
}

func (h *fakeHost) isCut() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cut
}

// host makes a host with one interface, eth0, on the link.
func (l *fakeLink) host(addrs ...string) *fakeHost {
	h := newHost()
	h.attach(l, "eth0", addrs...)
	return h
}

func (h *fakeHost) port(index int) *fakePort {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.ports {
		if p.index == index {
			return p
		}
	}
	return nil
}

func (h *fakeHost) read() (packet, error) {
	select {
	case p := <-h.packets:
		return p, nil
	case <-h.closed:
		return packet{}, net.ErrClosed
	}
}

func (h *fakeHost) send(data []byte, ifIndex int, dst netip.AddrPort) error {
	return h.sendFrom(ifIndex, Port, data, dst)
}

// sendFrom sends from a port number, as a legacy resolver would.
func (h *fakeHost) sendFrom(ifIndex int, srcPort uint16, data []byte, dst netip.AddrPort) error {
	select {
	case <-h.closed:
		return net.ErrClosed
	default:
	}
	from := h.port(ifIndex)
	if from == nil {
		return net.ErrClosed
	}
	if h.isCut() {
		return errors.New("operation not permitted")
	}
	var src netip.Addr
	for _, p := range from.prefixes() {
		if p.Addr().Is4() == dst.Addr().Is4() {
			src = p.Addr()
			break
		}
	}
	if !src.IsValid() {
		return nil // no address of that family on the interface
	}
	select {
	case h.sent <- sentPacket{data: slices.Clone(data), dst: dst, ifIndex: ifIndex}:
	default:
	}
	from.link.mu.Lock()
	ports := slices.Clone(from.link.ports)
	from.link.mu.Unlock()
	for _, to := range ports {
		if !dst.Addr().IsMulticast() && !slices.ContainsFunc(to.prefixes(), func(p netip.Prefix) bool { return p.Addr() == dst.Addr() }) || to.host.isCut() {
			continue
		}
		select {
		case to.host.packets <- packet{data: slices.Clone(data), src: netip.AddrPortFrom(src, srcPort), ifIndex: to.index}:
		case <-to.host.closed:
		default:
		}
	}
	return nil
}

func (h *fakeHost) interfaces() ([]iface, error) {
	h.mu.Lock()
	ports := slices.Clone(h.ports)
	h.mu.Unlock()
	var out []iface
	for _, p := range ports {
		if f := newIface(p.index, p.name, p.prefixes()); len(f.addrs) > 0 {
			out = append(out, f)
		}
	}
	return out, nil
}

func (h *fakeHost) close() error {
	h.once.Do(func() { close(h.closed) })
	return nil
}

const (
	idA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type running struct {
	r     *Responder
	peers chan []Peer
	stop  func()
}

func start(t *testing.T, h *fakeHost, id string, port uint16, clock *fakeClock, opts ...func(*Config)) running {
	t.Helper()
	peers := make(chan []Peer, 256)
	cfg := Config{ID: id, Port: port, TXT: []string{"v=1", "g=0123456789abcdef"}, net: h,
		OnPeers: func(p []Peer) { peers <- p }, Logf: t.Logf}
	if clock != nil {
		cfg.Now = clock.now
	}
	for _, o := range opts {
		o(&cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			cancel()
			<-done
		}
	}
	t.Cleanup(stop)
	return running{r: r, peers: peers, stop: stop}
}

// settle moves the clock past the announcements, so the records may be
// multicast again, and gives the responders time to notice.
func settle(clock *fakeClock) {
	for range announceCount {
		clock.advance(1500 * time.Millisecond)
		time.Sleep(3 * tick)
	}
	clock.advance(1500 * time.Millisecond)
	time.Sleep(3 * tick)
}

func waitPeers(t *testing.T, ch <-chan []Peer, ok func([]Peer) bool) []Peer {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case p := <-ch:
			if ok(p) {
				return p
			}
		case <-timeout:
			t.Fatal("timed out waiting for peers")
		}
	}
}

func peerEqual(a, b Peer) bool {
	return a.ID == b.ID && a.Port == b.Port && slices.Equal(a.TXT, b.TXT) && slices.Equal(a.Addrs, b.Addrs)
}

func q(n string, t dnsmessage.Type) dnsmessage.Question {
	return dnsmessage.Question{Name: dnsmessage.MustNewName(n), Type: t, Class: classIN}
}

// ask sends a query from a host that runs no responder and returns the
// first response that answers it: one whose answers all name the first
// question's name, and, for a legacy query from a port other than 5353,
// with the query's ID. It returns nil if none arrives within a second.
func ask(t *testing.T, client *fakeHost, srcPort uint16, qs ...dnsmessage.Question) *dnsmessage.Message {
	t.Helper()
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: 77}, Questions: qs}
	data, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return askRaw(t, client, srcPort, data, qs[0].Name.String())
}

func askRaw(t *testing.T, client *fakeHost, srcPort uint16, data []byte, name string) *dnsmessage.Message {
	t.Helper()
	if err := client.sendFrom(1, srcPort, data, group4); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(time.Second)
	for {
		select {
		case p := <-client.packets:
			var m dnsmessage.Message
			if m.Unpack(p.data) != nil || !m.Response || (srcPort != Port && m.ID != 77) {
				continue
			}
			// An announcement carries other names too; an answer only the
			// name asked for.
			if len(m.Answers) > 0 && !slices.ContainsFunc(m.Answers, func(r dnsmessage.Resource) bool {
				return !sameName(r.Header.Name, name)
			}) {
				return &m
			}
		case <-timeout:
			return nil
		}
	}
}

func drain(h *fakeHost) {
	for {
		select {
		case <-h.packets:
		case <-h.sent:
		default:
			return
		}
	}
}

func waitFor(h *fakeHost, ok func(*dnsmessage.Message) bool) bool {
	timeout := time.After(5 * time.Second)
	for {
		select {
		case p := <-h.packets:
			var m dnsmessage.Message
			if m.Unpack(p.data) == nil && ok(&m) {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

func TestTwoMembersFindEachOther(t *testing.T) {
	var l fakeLink
	a := l.host("192.168.1.10", "fe80::a")
	b := l.host("192.168.1.11", "fd00::b")
	ra := start(t, a, idA, 4001, nil)
	rb := start(t, b, idB, 4002, nil)
	got := waitPeers(t, ra.peers, func(p []Peer) bool { return len(p) == 1 && len(p[0].Addrs) == 2 })
	want := Peer{ID: idB, Port: 4002, TXT: []string{"v=1", "g=0123456789abcdef"},
		Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.11"), netip.MustParseAddr("fd00::b")}}
	if !peerEqual(got[0], want) {
		t.Errorf("A found %+v, want %+v", got[0], want)
	}
	if v, ok := got[0].TXTValue("G"); !ok || v != "0123456789abcdef" {
		t.Errorf("TXTValue(G) = %q, %v", v, ok)
	}
	got = waitPeers(t, rb.peers, func(p []Peer) bool { return len(p) == 1 && len(p[0].Addrs) == 2 })
	if got[0].ID != idA || got[0].Addrs[1] != netip.MustParseAddr("fe80::a").WithZone("eth0") {
		t.Errorf("B found %+v; want A with a link-local address on eth0", got[0])
	}
}

func TestSetTXTReachesOthers(t *testing.T) {
	var l fakeLink
	clock := newClock()
	a, b := l.host("192.168.1.10"), l.host("192.168.1.11")
	ra := start(t, a, idA, 4001, clock)
	rb := start(t, b, idB, 4002, clock)
	waitPeers(t, ra.peers, func(p []Peer) bool { return len(p) == 1 })
	clock.advance(5 * time.Second) // past the cache-flush guard of a second
	rb.r.SetTXT([]string{"v=1", "g=0123456789abcdef", "p=1"})
	got := waitPeers(t, ra.peers, func(p []Peer) bool {
		v, ok := len(p) == 1, false
		if v {
			_, ok = p[0].TXTValue("p")
		}
		return ok
	})
	if len(got[0].TXT) != 3 {
		t.Errorf("TXT %v", got[0].TXT)
	}
}

func TestAnswersOnTheArrivalInterface(t *testing.T) {
	// A has two interfaces on two links; a client on one gets only the
	// addresses of that one.
	var lan, docker fakeLink
	a := newHost()
	a.attach(&lan, "eth0", "192.168.1.10", "fe80::a")
	a.attach(&docker, "docker0", "172.17.0.1")
	client := lan.host("192.168.1.20")
	clock := newClock()
	start(t, a, idA, 4001, clock)
	settle(clock)
	m := ask(t, client, Port, q("cb-"+idA+".local.", dnsmessage.TypeALL))
	if m == nil {
		t.Fatal("no answer")
	}
	for _, r := range m.Answers {
		if a, ok := r.Body.(*dnsmessage.AResource); ok && netip.AddrFrom4(a.A) != netip.MustParseAddr("192.168.1.10") {
			t.Errorf("answered with %v from another interface", netip.AddrFrom4(a.A))
		}
	}
}

func TestHolder(t *testing.T) {
	var l fakeLink
	a := l.host("192.168.1.10")
	client := l.host("192.168.1.20")
	clock := newClock()
	ra := start(t, a, idA, 4001, clock)
	if m := ask(t, client, Port, q(PhoneName, dnsmessage.TypeA)); m != nil {
		t.Fatalf("answered for cbb.local without holding it: %v", m)
	}
	ra.r.SetHolder(true)
	time.Sleep(3 * tick)
	settle(clock)
	drain(client)
	m := ask(t, client, Port, q(PhoneName, dnsmessage.TypeA))
	if m == nil {
		t.Fatal("no answer for cbb.local")
	}
	ans := m.Answers[0]
	if a, ok := ans.Body.(*dnsmessage.AResource); !ok || netip.AddrFrom4(a.A) != netip.MustParseAddr("192.168.1.10") ||
		ans.Header.TTL != 10 || ans.Header.Class != classIN|cacheFlush {
		t.Errorf("answer %v, want A 192.168.1.10 with TTL 10 and the cache-flush bit", ans.GoString())
	}
	// A question for AAAA gets the NSEC record, which says there is none.
	settle(clock)
	m = ask(t, client, Port, q(PhoneName, dnsmessage.TypeAAAA))
	if m == nil || typeOf(m.Answers[0]) != typeNSEC {
		t.Errorf("AAAA question: %v, want NSEC", m)
	}
	// Giving it up sends a goodbye.
	drain(client)
	ra.r.SetHolder(false)
	if !waitFor(client, func(m *dnsmessage.Message) bool {
		return len(m.Answers) > 0 && sameName(m.Answers[0].Header.Name, PhoneName) && m.Answers[0].Header.TTL == 0
	}) {
		t.Error("no goodbye for cbb.local")
	}
}

func TestHolderGoodbyeOnStop(t *testing.T) {
	// A holder that stops says goodbye for cbb.local, even when it
	// gave the name up just before and the change was not applied yet.
	for _, release := range []bool{false, true} {
		var l fakeLink
		a := l.host("192.168.1.10")
		client := l.host("192.168.1.20")
		ra := start(t, a, idA, 4001, nil)
		ra.r.SetHolder(true)
		time.Sleep(300 * time.Millisecond)
		drain(client)
		if release {
			ra.r.SetHolder(false)
		}
		ra.stop()
		if !waitFor(client, func(m *dnsmessage.Message) bool {
			return slices.ContainsFunc(m.Answers, func(r dnsmessage.Resource) bool {
				return sameName(r.Header.Name, PhoneName) && r.Header.TTL == 0
			})
		}) {
			t.Errorf("release=%v: no goodbye for cbb.local on stop", release)
		}
	}
}

func TestLegacyUnicast(t *testing.T) {
	var l fakeLink
	a := l.host("192.168.1.10")
	client := l.host("192.168.1.20")
	start(t, a, idA, 4001, nil)
	m := ask(t, client, 40000, q(ServiceName, dnsmessage.TypePTR))
	if m == nil {
		t.Fatal("no answer to a legacy query")
	}
	if m.ID != 77 || len(m.Questions) != 1 {
		t.Errorf("legacy answer %v", m.GoString())
	}
	for _, r := range append(slices.Clone(m.Answers), m.Additionals...) {
		if r.Header.TTL > 10 || r.Header.Class != classIN {
			t.Errorf("legacy record %v", r.Header.GoString())
		}
	}
	if len(m.Additionals) == 0 {
		t.Error("no additionals to check")
	}
	// A flood of legacy queries from one source gets a few answers a second.
	drain(client)
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: 77}, Questions: []dnsmessage.Question{q(ServiceName, dnsmessage.TypePTR)}}
	data, _ := msg.Pack()
	for range 20 {
		client.sendFrom(1, 40000, data, group4)
	}
	time.Sleep(300 * time.Millisecond)
	answered := 0
	for len(client.packets) > 0 {
		var m dnsmessage.Message
		if p := <-client.packets; m.Unpack(p.data) == nil && m.Response && m.ID == 77 {
			answered++
		}
	}
	if answered > legacyPerSecond {
		t.Errorf("%d answers to 20 legacy queries at once", answered)
	}
}

func TestMulticastRateLimit(t *testing.T) {
	// A record goes out at most once a second on an interface, however
	// many queries ask for it.
	var l fakeLink
	a := l.host("192.168.1.10")
	client := l.host("192.168.1.20")
	clock := newClock()
	start(t, a, idA, 4001, clock)
	settle(clock)
	drain(client)
	msg := dnsmessage.Message{Questions: []dnsmessage.Question{q("cb-"+idA+".local.", dnsmessage.TypeA)}}
	data, _ := msg.Pack()
	for range 10 {
		client.sendFrom(1, Port, data, group4)
	}
	time.Sleep(300 * time.Millisecond)
	n := 0
	for {
		select {
		case p := <-client.packets:
			var m dnsmessage.Message
			if m.Unpack(p.data) == nil && m.Response {
				n++
			}
			continue
		default:
		}
		break
	}
	if n != 1 {
		t.Errorf("%d answers to 10 queries within a second, want 1", n)
	}
}

func TestDottedNamesDoNotHideQuestions(t *testing.T) {
	// An Apple device packs other questions and their known answers, with
	// names such as "Mr. Smith's iPad", next to ours; dnsmessage cannot
	// read those labels, and they must not cost our question.
	var l fakeLink
	a := l.host("192.168.1.10")
	client := l.host("192.168.1.20")
	clock := newClock()
	ra := start(t, a, idA, 4001, clock)
	ra.r.SetHolder(true)
	time.Sleep(3 * tick)
	settle(clock)
	drain(client)
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: 77}, Questions: []dnsmessage.Question{
		q(PhoneName, dnsmessage.TypeA), q("_companion-link._tcp.local.", dnsmessage.TypePTR)}}
	data, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	data = appendDottedPTR(data)
	if m := askRaw(t, client, Port, data, PhoneName); m == nil {
		t.Error("a dotted known answer hid the question for cbb.local")
	}
}

// appendDottedPTR adds a known answer whose instance label holds a dot.
func appendDottedPTR(msg []byte) []byte {
	labels := func(b []byte, ls ...string) []byte {
		for _, l := range ls {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
		return append(b, 0)
	}
	b := labels(nil, "_companion-link", "_tcp", "local")
	b = binary.BigEndian.AppendUint16(b, uint16(dnsmessage.TypePTR))
	b = binary.BigEndian.AppendUint16(b, uint16(classIN))
	b = binary.BigEndian.AppendUint32(b, 4500)
	rdata := labels(nil, "Mr. Smith's iPad", "_companion-link", "_tcp", "local")
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	b = append(b, rdata...)
	out := append(slices.Clone(msg), b...)
	binary.BigEndian.PutUint16(out[6:], binary.BigEndian.Uint16(out[6:])+1) // ANCOUNT
	return out
}

func TestParseSkipsWhatItCannotRead(t *testing.T) {
	msg := dnsmessage.Message{Questions: []dnsmessage.Question{q(PhoneName, dnsmessage.TypeA)}}
	data, _ := msg.Pack()
	m, err := parse(appendDottedPTR(data))
	if err != nil || len(m.Questions) != 1 || len(m.Answers) != 0 {
		t.Errorf("parse = %+v, %v", m, err)
	}
	if _, err := parse([]byte{1, 2, 3}); err == nil {
		t.Error("parsed a truncated header")
	}
}

func TestOffLinkPacketsAreIgnored(t *testing.T) {
	var l fakeLink
	a := l.host("192.168.1.10")
	stranger := l.host("192.168.7.20") // another network, same wire
	clock := newClock()
	ra := start(t, a, idA, 4001, clock)
	settle(clock)
	if m := ask(t, stranger, Port, q(servicesName, dnsmessage.TypePTR)); m != nil {
		t.Errorf("answered a query from another network: %v", m)
	}
	neighbour := l.host("192.168.1.30")
	if m := ask(t, neighbour, Port, q(servicesName, dnsmessage.TypePTR)); m == nil {
		t.Error("no answer to a query from the same network")
	}
	// A response from another network does not make a member.
	z := newZone(idB, 4002, []string{"v=1"})
	resp := dnsmessage.Message{Header: dnsmessage.Header{Response: true}}
	for _, r := range z.all([]netip.Addr{netip.MustParseAddr("192.168.7.20")}) {
		resp.Answers = append(resp.Answers, r.res)
	}
	data, _ := resp.Pack()
	stranger.sendFrom(1, Port, data, group4)
	select {
	case p := <-ra.peers:
		if len(p) > 0 {
			t.Errorf("a member from another network: %+v", p)
		}
	case <-time.After(500 * time.Millisecond):
	}
}

func TestBrowseOnly(t *testing.T) {
	var l fakeLink
	a, b := l.host("192.168.1.10"), l.host("192.168.1.11")
	client := l.host("192.168.1.20")
	ra := start(t, a, idA, 4001, nil)
	rb := start(t, b, idB, 4002, nil, func(c *Config) { c.BrowseOnly = true })
	// The browser finds the member, but publishes nothing itself.
	waitPeers(t, rb.peers, func(p []Peer) bool { return len(p) == 1 && p[0].ID == idA })
	if m := ask(t, client, Port, q("cb-"+idB+".local.", dnsmessage.TypeA)); m != nil {
		t.Errorf("a browser answered for itself: %v", m)
	}
	select {
	case p := <-ra.peers:
		if len(p) > 0 {
			t.Errorf("the member found the browser: %+v", p)
		}
	case <-time.After(1500 * time.Millisecond):
	}
}

func TestGoodbyeOnStop(t *testing.T) {
	var l fakeLink
	clock := newClock()
	a := l.host("192.168.1.10")
	b := l.host("192.168.1.11")
	ra := start(t, a, idA, 4001, clock)
	rb := start(t, b, idB, 4002, clock)
	waitPeers(t, ra.peers, func(p []Peer) bool { return len(p) == 1 })
	rb.stop()
	// The goodbye leaves the records a second to live: move the clock on
	// until A has dropped B, well before B's records would expire.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				clock.advance(500 * time.Millisecond)
			}
		}
	}()
	waitPeers(t, ra.peers, func(p []Peer) bool { return len(p) == 0 })
	if waited := clock.now().Sub(time.Unix(1_000_000, 0)); waited > 60*time.Second {
		t.Errorf("A dropped B only after %v", waited)
	}
}

func TestRefreshKeepsMembers(t *testing.T) {
	// A member that stays keeps being found after its records' lifetime,
	// because the browser asks for them again before they expire; the
	// refresh questions are on the wire.
	var l fakeLink
	clock := newClock()
	a, b := l.host("192.168.1.10"), l.host("192.168.1.11")
	ra := start(t, a, idA, 4001, clock)
	start(t, b, idB, 4002, clock)
	waitPeers(t, ra.peers, func(p []Peer) bool { return len(p) == 1 && len(p[0].Addrs) == 1 })
	sawRefresh := false
	for range 20 {
		clock.advance(15 * time.Second)
		time.Sleep(300 * time.Millisecond)
		for len(ra.peers) > 0 {
			if p := <-ra.peers; len(p) != 1 || len(p[0].Addrs) != 1 {
				t.Fatalf("at %v A sees %+v", clock.now().Sub(time.Unix(1_000_000, 0)), p)
			}
		}
		for len(a.sent) > 0 {
			sp := <-a.sent
			var m dnsmessage.Message
			if m.Unpack(sp.data) == nil && !m.Response && slices.ContainsFunc(m.Questions, func(q dnsmessage.Question) bool {
				return q.Type == dnsmessage.TypeSRV && sameName(q.Name, idB+"."+ServiceName)
			}) {
				sawRefresh = true
			}
		}
	}
	if !sawRefresh {
		t.Error("A never asked for B's SRV record again")
	}
}

func TestRefindAfterOutage(t *testing.T) {
	// B is off the network long enough that A's records of it expire, and
	// back with no change to its interfaces. A browses again soon after it
	// lost B, though its browse queries had long been far apart, without B
	// as a known answer, and they find each other again.
	var l fakeLink
	clock := newClock()
	a, b := l.host("192.168.1.10"), l.host("192.168.1.11")
	ra := start(t, a, idA, 4001, clock)
	rb := start(t, b, idB, 4002, clock)
	waitPeers(t, ra.peers, func(p []Peer) bool { return len(p) == 1 && len(p[0].Addrs) == 1 })
	waitPeers(t, rb.peers, func(p []Peer) bool { return len(p) == 1 && len(p[0].Addrs) == 1 })
	// The responders look at the clock every 250 ms.
	step := func(d time.Duration, wait time.Duration) {
		clock.advance(d)
		time.Sleep(wait)
	}
	// browses counts A's browse queries sent since the last call, and
	// reports whether any listed B as a known answer.
	browses := func() (n int, knownB bool) {
		for len(a.sent) > 0 {
			sp := <-a.sent
			var m dnsmessage.Message
			if m.Unpack(sp.data) != nil || m.Response || len(m.Questions) == 0 || m.Questions[0].Type != dnsmessage.TypePTR {
				continue
			}
			n++
			knownB = knownB || slices.ContainsFunc(m.Answers, func(r dnsmessage.Resource) bool {
				ptr, ok := r.Body.(*dnsmessage.PTRResource)
				return ok && strings.HasPrefix(ptr.PTR.String(), idB)
			})
		}
		return n, knownB
	}
	for range 100 { // 50 minutes: the browse queries are far apart now
		step(30*time.Second, 20*time.Millisecond)
	}
	b.setCut(true)
	lost := false
	for range 30 { // B's address and SRV records expire within 120 s
		step(5*time.Second, 300*time.Millisecond)
		for len(ra.peers) > 0 {
			lost = len(<-ra.peers) == 0
		}
		if lost {
			break
		}
	}
	if !lost {
		t.Fatal("A kept B while it was off the network")
	}
	browses()
	for range 20 {
		step(time.Second, 300*time.Millisecond)
	}
	if n, knownB := browses(); n < 2 || knownB {
		t.Errorf("A sent %d browse queries in the 20 s after it lost B, B a known answer: %v; want 2 or more, without B", n, knownB)
	}
	b.setCut(false)
	// found follows a member's peers to the last list it reported. B
	// need not have lost A: when A's records were younger in B's cache
	// than B's in A's, they outlive the outage and B keeps A throughout.
	found := func(ch <-chan []Peer, ok bool) bool {
		for len(ch) > 0 {
			p := <-ch
			ok = len(p) == 1 && len(p[0].Addrs) == 1
		}
		return ok
	}
	foundA, foundB := false, found(rb.peers, true)
	for i := 0; i < 24 && !(foundA && foundB); i++ { // 2 minutes
		step(5*time.Second, 300*time.Millisecond)
		foundA = found(ra.peers, foundA)
		foundB = found(rb.peers, foundB)
	}
	if !foundA || !foundB {
		t.Errorf("not found again within 2 minutes after the outage: A finds B %v, B finds A %v", foundA, foundB)
	}
}

func TestAnnounceOnPeerFound(t *testing.T) {
	// A member found that was not among the peers may have lost this one
	// in an outage and browse again only minutes later, after the queries
	// it sent while off the network: this member announces itself once.
	r, err := New(Config{ID: idA, Port: 4001, TXT: []string{"v=1"}, net: newHost()})
	if err != nil {
		t.Fatal(err)
	}
	s := &state{r: r}
	t0 := time.Unix(1000, 0)
	instance := name(idB + "." + ServiceName)
	host := name("cb-" + idB + ".local.")
	b := &dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: name(ServiceName), Class: classIN, TTL: 4500}, Body: &dnsmessage.PTRResource{PTR: instance}},
		{Header: dnsmessage.ResourceHeader{Name: instance, Class: classIN, TTL: 120}, Body: &dnsmessage.SRVResource{Port: 4002, Target: host}},
		{Header: dnsmessage.ResourceHeader{Name: host, Class: classIN, TTL: 120}, Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 11}}},
	}}
	s.cache.add(b, "eth0", t0)
	s.updatePeers(t0)
	if len(s.peers) != 1 || len(s.announce) != 1 || s.announce[0].left != 1 {
		t.Fatalf("B found: peers %v, announcements %+v; want B and one announcement", s.peers, s.announce)
	}
	// Nothing more while B stays, and no second one while one is due.
	s.cache.add(b, "eth0", t0.Add(time.Second))
	s.updatePeers(t0.Add(time.Second))
	if len(s.announce) != 1 {
		t.Errorf("%d announcements with B known", len(s.announce))
	}
	// B lost and found again: one more.
	s.announce = nil
	s.cache.expire(t0.Add(5 * time.Minute))
	s.updatePeers(t0.Add(5 * time.Minute))
	if len(s.peers) != 0 || len(s.announce) != 0 {
		t.Fatalf("B gone: peers %v, announcements %+v", s.peers, s.announce)
	}
	s.cache.add(b, "eth0", t0.Add(6*time.Minute))
	s.updatePeers(t0.Add(6 * time.Minute))
	if len(s.peers) != 1 || len(s.announce) != 1 {
		t.Errorf("B found again: peers %v, announcements %+v; want B and one announcement", s.peers, s.announce)
	}
}

func TestRefreshSchedule(t *testing.T) {
	var c cache
	t0 := time.Unix(1000, 0)
	srv := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(idB + "." + ServiceName), Class: classIN, TTL: 120},
		Body:   &dnsmessage.SRVResource{Target: name("cb-" + idB + ".local."), Port: 1},
	}
	c.add(&dnsmessage.Message{Answers: []dnsmessage.Resource{srv}}, "eth0", t0)
	for _, es := range c.byName {
		for _, e := range es {
			e.jitter = 0
		}
	}
	peers := []Peer{{ID: idB}}
	at := func(s int) int { return len(c.refresh(t0.Add(time.Duration(s)*time.Second), peers)) }
	if n := at(95); n != 0 {
		t.Errorf("%d questions at 95 s", n)
	}
	for _, s := range []int{96, 102, 108, 114} { // 80, 85, 90 and 95 percent of 120 s
		if n := at(s); n != 1 {
			t.Errorf("%d questions at %d s, want 1", n, s)
		}
	}
	if n := at(119); n != 0 {
		t.Errorf("%d questions after the fourth", n)
	}
	// Records of no member are not refreshed.
	if n := len(c.refresh(t0.Add(200*time.Second), nil)); n != 0 {
		t.Errorf("refreshed %d records of no member", n)
	}
	// A fresh copy starts the schedule again.
	c.add(&dnsmessage.Message{Answers: []dnsmessage.Resource{srv}}, "eth0", t0.Add(115*time.Second))
	for _, es := range c.byName {
		for _, e := range es {
			e.jitter = 0
		}
	}
	if n := len(c.refresh(t0.Add(115*time.Second+96*time.Second), peers)); n != 1 {
		t.Errorf("%d questions after a fresh copy", n)
	}
}

func TestKnownAnswersInBrowseQueries(t *testing.T) {
	// After A found B, its browse queries list B's PTR record, so B does
	// not answer them.
	var l fakeLink
	clock := newClock()
	a, b := l.host("192.168.1.10"), l.host("192.168.1.11")
	ra := start(t, a, idA, 4001, clock)
	start(t, b, idB, 4002, clock)
	waitPeers(t, ra.peers, func(p []Peer) bool { return len(p) == 1 })
	drain(a)
	clock.advance(70 * time.Second) // the next browse query is due
	timeout := time.After(5 * time.Second)
	for {
		select {
		case sp := <-a.sent:
			var m dnsmessage.Message
			if m.Unpack(sp.data) != nil || m.Response || len(m.Questions) == 0 || m.Questions[0].Type != dnsmessage.TypePTR {
				continue
			}
			if !slices.ContainsFunc(m.Answers, func(r dnsmessage.Resource) bool {
				ptr, ok := r.Body.(*dnsmessage.PTRResource)
				return ok && strings.HasPrefix(ptr.PTR.String(), idB)
			}) {
				t.Errorf("a browse query without B as a known answer: %v", m.Answers)
			}
			return
		case <-timeout:
			t.Fatal("no browse query")
		}
	}
}

func TestCacheFlush(t *testing.T) {
	var c cache
	t0 := time.Unix(1000, 0)
	host := name("cb-" + idB + ".local.")
	a := func(ip string) dnsmessage.Resource {
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: host, Class: classIN | cacheFlush, TTL: 120},
			Body: &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()}}
	}
	// Two addresses in one packet do not flush each other.
	c.add(&dnsmessage.Message{Answers: []dnsmessage.Resource{a("192.168.1.11"), a("192.168.1.12")}}, "eth0", t0)
	c.expire(t0.Add(5 * time.Second))
	if c.count != 2 {
		t.Fatalf("%d records after one packet", c.count)
	}
	// A new address two seconds later flushes the old ones a second after.
	c.add(&dnsmessage.Message{Answers: []dnsmessage.Resource{a("192.168.1.13")}}, "eth0", t0.Add(2*time.Second))
	c.expire(t0.Add(2*time.Second + 500*time.Millisecond))
	if c.count != 3 {
		t.Errorf("%d records within the second", c.count)
	}
	c.expire(t0.Add(3*time.Second + time.Millisecond))
	if c.count != 1 {
		t.Errorf("%d records after the flush, want only the new one", c.count)
	}
}

func TestAddressChange(t *testing.T) {
	// B's address changes; after its next look at the interfaces it
	// announces the new one, and A forgets the old.
	var l fakeLink
	clock := newClock()
	a, b := l.host("192.168.1.10"), l.host("192.168.1.11")
	ra := start(t, a, idA, 4001, clock)
	start(t, b, idB, 4002, clock)
	waitPeers(t, ra.peers, func(p []Peer) bool { return len(p) == 1 })
	b.port(1).setAddrs("192.168.1.99")
	clock.advance(rescanEvery + 2*time.Second)
	// Keep time moving, a little at a time, until A has dropped the old
	// address; it must happen through the cache flush, long before the
	// old record's two minutes are up.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				clock.advance(500 * time.Millisecond)
			}
		}
	}()
	waitPeers(t, ra.peers, func(p []Peer) bool {
		return len(p) == 1 && slices.Equal(p[0].Addrs, []netip.Addr{netip.MustParseAddr("192.168.1.99")})
	})
	if d := clock.now().Sub(time.Unix(1_000_000, 0)); d > 60*time.Second {
		t.Errorf("the old address went only after %v", d)
	}
}

func TestAddressGoodbye(t *testing.T) {
	// When an address goes away, the member says goodbye for it, without
	// the cache-flush bit, so the address that stays is kept.
	var l fakeLink
	clock := newClock()
	b := l.host("192.168.1.11", "192.168.1.12")
	client := l.host("192.168.1.20")
	start(t, b, idB, 4002, clock)
	time.Sleep(3 * tick)
	drain(client)
	b.port(1).setAddrs("192.168.1.12")
	clock.advance(rescanEvery + time.Second)
	if !waitFor(client, func(m *dnsmessage.Message) bool {
		return slices.ContainsFunc(m.Answers, func(r dnsmessage.Resource) bool {
			a, ok := r.Body.(*dnsmessage.AResource)
			return ok && netip.AddrFrom4(a.A) == netip.MustParseAddr("192.168.1.11") && r.Header.TTL == 0 &&
				r.Header.Class == classIN
		})
	}) {
		t.Error("no goodbye, without the cache-flush bit, for the address that went away")
	}
}

func TestReceivedRecordsAreChecked(t *testing.T) {
	var c cache
	t0 := time.Unix(1000, 0)
	fake := "0fake"
	z := newZone(fake, 80, nil)
	var msg dnsmessage.Message
	for _, r := range z.all([]netip.Addr{netip.MustParseAddr("192.168.1.1")}) {
		r.res.Header.TTL = 1_000_000_000
		msg.Answers = append(msg.Answers, r.res)
	}
	c.add(&msg, "eth0", t0)
	if p := c.peers("", t0); len(p) != 0 {
		t.Errorf("a peer with a bad device ID: %+v", p)
	}
	// A huge TTL is capped at cbb's own lifetimes.
	good := newZone(idB, 4002, nil)
	var gm dnsmessage.Message
	for _, r := range good.all([]netip.Addr{netip.MustParseAddr("192.168.1.11"), netip.MustParseAddr("8.8.8.8")}) {
		r.res.Header.TTL = 1_000_000_000
		gm.Answers = append(gm.Answers, r.res)
	}
	c.add(&gm, "eth0", t0)
	p := c.peers("", t0)
	if len(p) != 1 || !slices.Equal(p[0].Addrs, []netip.Addr{netip.MustParseAddr("192.168.1.11")}) {
		t.Errorf("peers %+v; a public address must not appear", p)
	}
	c.expire(t0.Add(hostTTL*time.Second + time.Second))
	if p := c.peers("", t0.Add(hostTTL*time.Second+time.Second)); len(p) != 0 {
		t.Errorf("a record with a huge TTL outlived %d s: %+v", hostTTL, p)
	}
}

func TestRunOnce(t *testing.T) {
	var l fakeLink
	r, err := New(Config{ID: idA, net: l.host("192.168.1.10")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Run(ctx)
	if err := r.Run(ctx); err == nil {
		t.Error("a second Run succeeded")
	}
}

func TestNewChecksItsInput(t *testing.T) {
	for _, cfg := range []Config{
		{ID: ""}, {ID: "a.b"}, {ID: strings.Repeat("a", 60)},
		{ID: idA, TXT: []string{strings.Repeat("x", 256)}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
	r, err := New(Config{ID: idA, TXT: []string{"v=1"}})
	if err != nil {
		t.Fatal(err)
	}
	r.SetTXT([]string{strings.Repeat("x", 256)})
	if got := r.zone().txt; !slices.Equal(got, []string{"v=1"}) {
		t.Errorf("an oversized TXT record replaced the old one: %v", got)
	}
}

func TestPublished(t *testing.T) {
	for addr, want := range map[string]bool{
		"192.168.1.1": true, "10.0.0.1": true, "172.16.5.4": true, "fd12::1": true, "fe80::1": true,
		"8.8.8.8": false, "169.254.1.1": false, "127.0.0.1": false, "::1": false, "2001:db8::1": false,
		"100.64.0.1": false, "::ffff:192.168.1.1": true,
	} {
		if got := Published(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Published(%s) = %v, want %v", addr, got, want)
		}
	}
	netguard.SetCGNAT(true)
	defer netguard.SetCGNAT(false)
	if !Published(netip.MustParseAddr("100.64.0.1")) || Published(netip.MustParseAddr("100.128.0.1")) {
		t.Error("with CBB_HOME_CGNAT=1, Published takes 100.64.0.0/10 and nothing next to it")
	}
}

func TestNewIface(t *testing.T) {
	f := newIface(3, "wlan0", prefixes("203.0.113.5", "169.254.3.3", "192.168.1.5", "fe80::5", "2001:db8::5", "fd00::5"))
	want := []netip.Addr{netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("fd00::5"), netip.MustParseAddr("fe80::5")}
	if !slices.Equal(f.addrs, want) || !f.has4 || !f.has6 || len(f.prefixes) != 6 {
		t.Errorf("newIface = %+v", f)
	}
	if g := newIface(1, "eth1", prefixes("203.0.113.5")); len(g.addrs) != 0 || g.has4 {
		t.Errorf("a public address was published: %+v", g)
	}
}

func TestAnswer(t *testing.T) {
	z := newZone(idA, 4001, []string{"v=1"})
	ips := []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("fe80::a")}
	query := func(known []dnsmessage.Resource, qs ...dnsmessage.Question) ([]rr, []rr) {
		return z.answer(&dnsmessage.Message{Questions: qs, Answers: known}, ips)
	}
	ans, add := query(nil, q(ServiceName, dnsmessage.TypePTR))
	if len(ans) != 1 || typeOf(ans[0].res) != dnsmessage.TypePTR || ans[0].unique {
		t.Errorf("PTR answers %v", ans)
	}
	// SRV, TXT, A, AAAA and NSEC.
	if len(add) != 5 {
		t.Errorf("PTR additionals %d, want 5", len(add))
	}
	// A known answer with enough lifetime left is not repeated.
	ans, _ = query([]dnsmessage.Resource{z.ptr().res}, q(ServiceName, dnsmessage.TypePTR))
	if len(ans) != 0 {
		t.Errorf("known answer repeated: %v", ans)
	}
	old := z.ptr().res
	old.Header.TTL = otherTTL/2 - 1
	if ans, _ = query([]dnsmessage.Resource{old}, q(ServiceName, dnsmessage.TypePTR)); len(ans) != 1 {
		t.Error("a known answer about to expire was suppressed")
	}
	// Names are case-insensitive.
	if ans, _ = query(nil, q("CB-"+idA+".Local.", dnsmessage.TypeALL)); len(ans) != 2 {
		t.Errorf("ANY for the host: %d answers, want A and AAAA", len(ans))
	}
	if ans, _ = query(nil, q(servicesName, dnsmessage.TypePTR)); len(ans) != 1 {
		t.Error("no answer to service enumeration")
	}
	if ans, _ = query(nil, q("other.local.", dnsmessage.TypeA), q(PhoneName, dnsmessage.TypeA)); len(ans) != 0 {
		t.Errorf("answered for names it does not own: %v", ans)
	}
	if ans, _ = z.answer(&dnsmessage.Message{Questions: []dnsmessage.Question{q(ServiceName, dnsmessage.TypePTR)}}, nil); len(ans) != 0 {
		t.Error("answered on an interface without addresses")
	}
	// With only IPv6, an A question gets the NSEC record.
	ans, _ = z.answer(&dnsmessage.Message{Questions: []dnsmessage.Question{q("cb-"+idA+".local.", dnsmessage.TypeA)}},
		[]netip.Addr{netip.MustParseAddr("fd00::a")})
	if len(ans) != 1 || typeOf(ans[0].res) != typeNSEC {
		t.Errorf("an A question on IPv6 only: %v", ans)
	}
}

func TestNSEC(t *testing.T) {
	for _, tt := range []struct {
		has4, has6 bool
		bitmap     []byte
	}{
		{true, true, []byte{0, 4, 0x40, 0, 0, 0x08}},
		{true, false, []byte{0, 1, 0x40}},
		{false, true, []byte{0, 4, 0, 0, 0, 0x08}},
	} {
		r := nsec("cb-x.local.", 120, tt.has4, tt.has6)
		want := append(appendWireName(nil, "cb-x.local."), tt.bitmap...)
		if got := r.res.Body.(*dnsmessage.UnknownResource).Data; string(got) != string(want) {
			t.Errorf("NSEC(%v, %v) data %x, want %x", tt.has4, tt.has6, got, want)
		}
	}
}

func TestCacheBounds(t *testing.T) {
	var c cache
	now := time.Unix(1000, 0)
	for i := range 2 * maxEntries {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		c.add(&dnsmessage.Message{Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name("cb-" + idB + ".local."), Class: classIN, TTL: 120},
			Body:   &dnsmessage.AResource{A: ip.As4()},
		}}}, "eth0", now.Add(time.Duration(i)*time.Millisecond))
	}
	if c.count > maxEntries {
		t.Errorf("cache holds %d entries", c.count)
	}
	c.expire(now.Add(200 * time.Second))
	if c.count != 0 {
		t.Errorf("%d entries after expiry", c.count)
	}
}

// TestPublishOnlyWhereAllowed checks Config.Publish: a member that may not
// publish on its network only browses there, until Recheck lets it, and
// says goodbye when it may no longer.
func TestPublishOnlyWhereAllowed(t *testing.T) {
	var l fakeLink
	clock := newClock()
	a, b := l.host("192.168.1.10"), l.host("192.168.1.11")
	var allowed atomic.Bool
	ra := start(t, a, idA, 4001, clock)
	rb := start(t, b, idB, 4002, clock, func(c *Config) {
		c.Publish = func(string, []netip.Prefix) bool { return allowed.Load() }
	})
	// The quiet member finds the other one, but is not found.
	waitPeers(t, rb.peers, func(p []Peer) bool { return len(p) == 1 && p[0].ID == idA })
	select {
	case p := <-ra.peers:
		if len(p) > 0 {
			t.Errorf("a member that may not publish was found: %+v", p)
		}
	case <-time.After(1500 * time.Millisecond):
	}
	allowed.Store(true)
	rb.r.Recheck()
	waitPeers(t, ra.peers, func(p []Peer) bool { return len(p) == 1 && p[0].ID == idB })
	allowed.Store(false)
	rb.r.Recheck()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				clock.advance(500 * time.Millisecond)
			}
		}
	}()
	waitPeers(t, ra.peers, func(p []Peer) bool { return len(p) == 0 })
}

func TestOnlyListedInterfaces(t *testing.T) {
	// A router limited to br-lan is found on its home network, and neither
	// publishes nor browses on its internet side, even with a private
	// address there (double NAT).
	var lan, wan fakeLink
	router := newHost()
	router.attach(&lan, "br-lan", "192.168.0.1")
	router.attach(&wan, "wan", "192.168.1.2")
	home, outside := lan.host("192.168.0.10"), wan.host("192.168.1.1")
	clock := newClock()
	rr := start(t, router, idA, 4001, clock, func(c *Config) {
		c.Interfaces = func(name string) bool { return name == "br-lan" }
	})
	rh := start(t, home, idB, 4002, clock)
	ro := start(t, outside, "cccccccccccccccccccccccccccccccc", 4003, clock)
	waitPeers(t, rh.peers, func(p []Peer) bool { return len(p) == 1 && p[0].ID == idA })
	waitPeers(t, rr.peers, func(p []Peer) bool { return len(p) == 1 && p[0].ID == idB })
	settle(clock)
	select {
	case p := <-ro.peers:
		if len(p) > 0 {
			t.Errorf("the router was found on its internet side: %+v", p)
		}
	case <-time.After(1500 * time.Millisecond):
	}
	if m := ask(t, outside, Port, q("cb-"+idA+".local.", dnsmessage.TypeALL)); m != nil && len(m.Answers) > 0 {
		t.Errorf("the router answered on its internet side: %+v", m.Answers)
	}
}
