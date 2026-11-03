// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package cbbtun

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/relay"
)

// RelayEvents is how the kit takes part in the phone's link to a blind
// relay (docs/protocol.md, section 14). The relay joins the phone's member
// connections to the other devices' end to end; the kit runs member TLS
// over them on the loopback address.
type RelayEvents interface {
	// Dial: the relay joined a connection to peer, which the kit takes by
	// connecting to 127.0.0.1:port and running member TLS as the client,
	// expecting peer's certificate. The port takes one connection.
	Dial(peer string, port int)
	// Calling: peer called, and its connection comes to the kit's member
	// listener from 127.0.0.1:localPort. The kit serves it only if the
	// client certificate names peer, so the relay cannot pose as another
	// device of the group.
	Calling(peer string, localPort int)
	// Wanted tells whether to connect to peer through the relay: false
	// while the kit is connected to it another way.
	Wanted(peer string) bool
	// Changed: the link stands as State says now.
	Changed(state string)
}

// RelayState is how the phone's link to its relay stands, in JSON as
// RelayEvents.Changed gets it: registered with its tunnel and its watch,
// the other devices of the group on the relay, the member connections
// through it, and why it is not connected.
type RelayState struct {
	Connected bool     `json:"connected"`
	Online    []string `json:"online"`
	Through   int      `json:"through"`
	Error     string   `json:"error,omitempty"`
}

// dialWait is how long a Dial's port waits for the kit's connection.
const dialWait = 10 * time.Second

// Relay is the phone's link to its blind relay while the app is open.
type Relay struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	records []group.Record
	cred    *relay.Credentialed // nil registers with the member certificate
	names   map[string]string   // pseudonyms at the relay, by the device they stand for
	changed chan struct{}       // closed when cred changes
}

// StartRelay keeps the phone registered with the blind relay at endpoint
// ("ip:port"), whose key pin pins, until Close: private is its WireGuard
// private key, device its device ID, chain and signer its member
// certificate and key as Hub.Register takes them, records the group's
// authority records, and memberPort the loopback port of the kit's member
// listener, to which the calls go.
func StartRelay(private []byte, device, endpoint, pin, chain string, signer Signer, records string, memberPort int, events RelayEvents) (*Relay, error) {
	k, err := key(private, "private key")
	if err != nil {
		return nil, err
	}
	ep, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("cbbtun: %q is not an endpoint: %w", endpoint, err)
	}
	if err := relay.CheckPin(pin); err != nil {
		return nil, fmt.Errorf("cbbtun: %w", err)
	}
	if _, err := group.ParseDeviceID(device); err != nil {
		return nil, fmt.Errorf("cbbtun: %w", err)
	}
	if memberPort <= 0 || memberPort > 65535 {
		return nil, fmt.Errorf("cbbtun: %d is not the member listener's port", memberPort)
	}
	if events == nil {
		return nil, errors.New("cbbtun: no events for the relay")
	}
	cert, err := memberCert(chain, signer)
	if err != nil {
		return nil, err
	}
	recs, err := parseRecords(records)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Relay{ctx: ctx, cancel: cancel, done: make(chan struct{}), records: recs, changed: make(chan struct{})}
	member := net.JoinHostPort("127.0.0.1", strconv.Itoa(memberPort))
	cfg := relay.MemberConfig{
		Link: relay.Link{Endpoint: netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()), Pin: pin},
		Self: device, Key: k,
		Cert: func() tls.Certificate { return cert },
		Records: func() []group.Record {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.records
		},
		Credentialed: func() (relay.Credentialed, bool) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.cred == nil {
				return relay.Credentialed{}, false
			}
			return *r.cred, true
		},
		CredentialsChanged: func() <-chan struct{} {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.changed
		},
		// The kit knows the devices by their IDs: a pseudonym it was given
		// stands for its device.
		Want: func(peer string) bool { return events.Wanted(r.device(peer)) },
		Dialed: func(ctx context.Context, peer string, c net.Conn) error {
			peer = r.device(peer)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return err
			}
			defer ln.Close()
			events.Dial(peer, ln.Addr().(*net.TCPAddr).Port)
			go func() {
				select {
				case <-ctx.Done():
				case <-time.After(dialWait):
				}
				ln.Close()
			}()
			k, err := ln.Accept()
			if err != nil {
				return fmt.Errorf("the app did not take the connection to %s: %w", peer, err)
			}
			ln.Close()
			return join(ctx, c, k)
		},
		Called: func(ctx context.Context, peer string, c net.Conn) error {
			peer = r.device(peer)
			var d net.Dialer
			k, err := d.DialContext(ctx, "tcp", member)
			if err != nil {
				return err
			}
			// The kit learns whose connection it is before a byte of TLS
			// reaches it.
			events.Calling(peer, k.LocalAddr().(*net.TCPAddr).Port)
			return join(ctx, c, k)
		},
		Report: func(rp relay.Report) {
			st := RelayState{Connected: rp.Connected, Online: []string{}, Through: rp.Through}
			for _, name := range rp.Online {
				st.Online = append(st.Online, r.device(name))
			}
			if rp.Err != nil {
				st.Error = rp.Err.Error()
			}
			b, _ := json.Marshal(st)
			events.Changed(string(b))
		},
	}
	go func() {
		defer close(r.done)
		relay.Join(ctx, cfg)
	}()
	return r, nil
}

// join copies between the relay's connection and the kit's until either
// ends or ctx is done.
func join(ctx context.Context, a, b net.Conn) error {
	stop := context.AfterFunc(ctx, func() {
		a.Close()
		b.Close()
	})
	defer stop()
	splice(a, b)
	return nil
}

// SetRecords replaces the authority records that the next registration
// shows the relay, as StartRelay takes them.
func (r *Relay) SetRecords(records string) error {
	recs, err := parseRecords(records)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.records = recs
	r.mu.Unlock()
	return nil
}

// device returns the device a name at the relay stands for: the device
// of a pseudonym SetCredentials named, or the name itself.
func (r *Relay) device(name string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := r.names[name]; ok {
		return d
	}
	return name
}

// SetCredentials makes the registrations from now on use the group's
// server credentials (docs/protocol.md, section 18) in place of the member
// certificate and the records, and registers again at once: serverKey is
// the phone's server key for the period, a SubjectPublicKeyInfo, DER, and
// signer signs with it; creds is a JSON array of the period's hubs' and
// members' credentials, which must list the key, and may hold the period
// credential too; roots a JSON array of the group's roots, DER, the group
// CA first; names a JSON object of the pseudonyms of the group's other
// devices, by pseudonym, with the device each stands for. An empty creds
// goes back to the member certificate.
func (r *Relay) SetCredentials(serverKey []byte, signer Signer, creds, roots, names string) error {
	var cred *relay.Credentialed
	var ns map[string]string
	if creds != "" {
		c, err := credentialed(serverKey, signer, creds, roots)
		if err != nil {
			return err
		}
		if names != "" {
			if err := json.Unmarshal([]byte(names), &ns); err != nil {
				return fmt.Errorf("cbbtun: the pseudonyms: %w", err)
			}
		}
		cred = &c
	}
	r.mu.Lock()
	r.cred, r.names = cred, ns
	close(r.changed)
	r.changed = make(chan struct{})
	r.mu.Unlock()
	return nil
}

func credentialed(serverKey []byte, signer Signer, creds, roots string) (relay.Credentialed, error) {
	pub, err := x509.ParsePKIXPublicKey(serverKey)
	if err != nil {
		return relay.Credentialed{}, fmt.Errorf("cbbtun: the server key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || signer == nil {
		return relay.Credentialed{}, errors.New("cbbtun: the server key is no ECDSA key with a signer")
	}
	cert, err := group.ServerCertificate(digestSigner{pub: ec, s: signer})
	if err != nil {
		return relay.Credentialed{}, fmt.Errorf("cbbtun: the server key's certificate: %w", err)
	}
	var cs []group.Credential
	if err := json.Unmarshal([]byte(creds), &cs); err != nil {
		return relay.Credentialed{}, fmt.Errorf("cbbtun: the credentials: %w", err)
	}
	out := relay.Credentialed{Cert: cert, Self: group.Pseudonym(group.PublicKeyHash(ec))}
	for _, c := range cs {
		b, err := c.Open()
		if err != nil {
			return relay.Credentialed{}, fmt.Errorf("cbbtun: the credentials: %w", err)
		}
		if b.Type == group.CredentialPeriod {
			out.Period = c
		} else {
			out.Creds = append(out.Creds, c)
		}
	}
	if _, err := group.CheckPresented(out.Creds, time.Now()); err != nil {
		return relay.Credentialed{}, fmt.Errorf("cbbtun: the credentials: %w", err)
	}
	if roots != "" {
		if err := json.Unmarshal([]byte(roots), &out.Roots); err != nil {
			return relay.Credentialed{}, fmt.Errorf("cbbtun: the roots: %w", err)
		}
	}
	return out, nil
}

// Close leaves the relay and ends every connection through it.
func (r *Relay) Close() {
	r.cancel()
	<-r.done
}
