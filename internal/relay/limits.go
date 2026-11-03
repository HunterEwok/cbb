// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/budget"
)

// Limits bound what an open relay (Config.Open), which serves any group
// that registers, gives the groups and the addresses they come from, so
// that groups nobody vouches for cannot fill it or take all its bandwidth.
// A zero field takes its value from DefaultOpenLimits; a relay for the
// user's own groups has no limits but the per-group ones.
type Limits struct {
	Groups     int // groups on the relay at once
	PerAddress int // registrations from one IP address
	PerNetwork int // registrations from one IPv4 /24 or IPv6 /64
	PerWide    int // registrations from one IPv4 /16 or IPv6 /48
	// PerProvider bounds the registrations from one IPv6 /32, which holds
	// tens of thousands of /48s; an IPv4 /16 is its own provider.
	PerProvider int
	ByteRate    float64 // bytes a second the relay copies for one group, both ways together

	// GroupRecordBytes bounds the bytes of authority records the relay keeps
	// for one group, and RecordBytes those it keeps for all groups. The
	// records a source brings are charged to it too: a network may bring
	// 4 groups' worth, a wide network 16 and an IPv6 provider 64.
	GroupRecordBytes int
	RecordBytes      int
}

// DefaultOpenLimits are an open relay's limits: enough for clipboards,
// which are small, and for a few thousand groups on a small server.
var DefaultOpenLimits = Limits{Groups: 4096, PerAddress: 16, PerNetwork: 64, PerWide: 256, PerProvider: 1024, ByteRate: 1 << 20,
	GroupRecordBytes: 256 << 10, RecordBytes: 128 << 20}

func (l Limits) withDefaults() Limits {
	d := DefaultOpenLimits
	if l.Groups <= 0 {
		l.Groups = d.Groups
	}
	if l.PerAddress <= 0 {
		l.PerAddress = d.PerAddress
	}
	if l.PerNetwork <= 0 {
		l.PerNetwork = d.PerNetwork
	}
	if l.PerWide <= 0 {
		l.PerWide = d.PerWide
	}
	if l.PerProvider <= 0 {
		l.PerProvider = d.PerProvider
	}
	if l.ByteRate <= 0 {
		l.ByteRate = d.ByteRate
	}
	if l.GroupRecordBytes <= 0 {
		l.GroupRecordBytes = d.GroupRecordBytes
	}
	if l.RecordBytes <= 0 {
		l.RecordBytes = d.RecordBytes
	}
	return l
}

// registrationCaps are the caps of the registrations an open relay holds,
// by the source they came from.
func (l Limits) registrationCaps() budget.Caps {
	return budget.Caps{Address: l.PerAddress, Network: l.PerNetwork, Wide: l.PerWide, Provider: l.PerProvider}
}

// recordCaps are the caps of the records an open relay keeps, by the
// source that brought them and in all.
func (l Limits) recordCaps() budget.Caps {
	return budget.Caps{Network: 4 * l.GroupRecordBytes, Wide: 16 * l.GroupRecordBytes, Provider: 64 * l.GroupRecordBytes, All: l.RecordBytes}
}

// addrOf returns the IP address of a connection's remote end, or the zero
// address if it has none.
func addrOf(c net.Conn) netip.Addr {
	a := c.RemoteAddr()
	if a == nil {
		return netip.Addr{}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// The work a source may start each second, in units: a registration's
// setup costs setupCost, each record the relay must verify one more. An
// address earns addressRate units a second and may save up to addressBurst,
// a network networkRate and networkBurst, a wide network wideRate and
// wideBurst, an IPv6 provider providerRate and providerBurst; the burst lets one registration of a group with a full claim
// (1024 records) through, and the rates keep the checks of a source that
// registers over and over to a small share of a processor (a record's check
// takes about 45 microseconds).
const (
	setupCost     = 4
	addressRate   = 64.0
	addressBurst  = 1536.0
	networkRate   = 256.0
	networkBurst  = 4096.0
	wideRate      = 1024.0
	wideBurst     = 8192.0
	providerRate  = 2048.0
	providerBurst = 16384.0
)

// newAllowance returns what each source address, network, wide network and
// provider may still start (docs/relay-budget.md).
func newAllowance() *budget.Rates {
	return budget.NewRates(budget.Rate{PerSecond: addressRate, Burst: addressBurst},
		budget.Rate{PerSecond: networkRate, Burst: networkBurst}, budget.Rate{PerSecond: wideRate, Burst: wideBurst},
		budget.Rate{PerSecond: providerRate, Burst: providerBurst})
}

// rate is a token bucket that holds up to two seconds of its rate; take
// waits until the tokens are there. It is shared by a group's connections.
type rate struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	at     time.Time
}

func newRate(r float64) *rate {
	return &rate{rate: r, tokens: 2 * r, at: time.Now()}
}

// take waits for n tokens, or until done is closed; false then.
func (b *rate) take(n int, done <-chan struct{}) bool {
	b.mu.Lock()
	now := time.Now()
	b.tokens = min(2*b.rate, b.tokens+now.Sub(b.at).Seconds()*b.rate)
	b.at = now
	b.tokens -= float64(n)
	wait := time.Duration(0)
	if b.tokens < 0 {
		wait = time.Duration(-b.tokens / b.rate * float64(time.Second))
	}
	b.mu.Unlock()
	if wait == 0 {
		return true
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-done:
		return false
	}
}

// limitedCopy copies src to dst as io.Copy does, at the rate of b when b
// is not nil.
func limitedCopy(dst io.Writer, src io.Reader, b *rate, done <-chan struct{}) {
	if b == nil {
		io.Copy(dst, src)
		return
	}
	buf := make([]byte, 16<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if !b.take(n, done) {
				return
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
