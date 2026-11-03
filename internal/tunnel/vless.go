// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

// VLESS is what a client needs to reach the hub's forwarder inside VLESS,
// for networks that block WireGuard (docs/design.md, "Blocked networks"),
// in one of two transports. With REALITY (Transport "") the forwarder
// borrows a well-known site's TLS: the link has the forwarder's VLESS
// address, its REALITY key and the site whose name the handshake carries.
// With XHTTP (Transport "xhttp") the forwarder sits behind a web server
// that has the site's own certificate and passes it one path: the link has
// the web server's address, the site's name, which the certificate must
// carry, and the path. Either way it has the group's VLESS user ID. The hub
// learns all but the ID when it registers with the forwarder and gives it
// to its clients with its offer (docs/protocol.md, section 11). Package
// vless runs it.
type VLESS struct {
	Transport  string         `json:"transport,omitempty"`  // "" for REALITY, or "xhttp"
	Endpoint   netip.AddrPort `json:"endpoint"`             // the forwarder's VLESS port, or the web server's, TCP
	PublicKey  []byte         `json:"public_key,omitempty"` // REALITY: the forwarder's key, X25519
	ShortID    string         `json:"short_id,omitempty"`   // REALITY: the short ID, hex
	ServerName string         `json:"server_name"`          // the site the handshake names
	Path       string         `json:"path,omitempty"`       // XHTTP: the path the web server passes
	ID         string         `json:"id"`                   // the group's VLESS user ID, a UUID
}

// The transports of VLESS.
const (
	TransportReality = ""
	TransportXHTTP   = "xhttp"
)

// Check refuses a link that cannot work, or of a transport this version
// does not know.
func (v *VLESS) Check() error {
	if !v.Endpoint.IsValid() || v.Endpoint.Port() == 0 {
		return errors.New("tunnel: vless: the forwarder's VLESS address is missing")
	}
	switch v.Transport {
	case TransportReality:
		switch {
		case len(v.PublicKey) != 32:
			return errors.New("tunnel: vless: the forwarder's REALITY key is not 32 bytes")
		case !shortIDPattern.MatchString(v.ShortID):
			return fmt.Errorf("tunnel: vless: %q is not a REALITY short ID", v.ShortID)
		case v.Path != "":
			return errors.New("tunnel: vless: REALITY has no path")
		}
	case TransportXHTTP:
		if len(v.PublicKey) != 0 || v.ShortID != "" {
			return errors.New("tunnel: vless: XHTTP has no REALITY key")
		}
		if err := CheckVLESSPath(v.Path); err != nil {
			return err
		}
	default:
		return fmt.Errorf("tunnel: vless: the transport %q needs a newer version", v.Transport)
	}
	if err := CheckServerName(v.ServerName); err != nil {
		return err
	}
	return CheckVLESSID(v.ID)
}

// CheckVLESSPath refuses what is not a path for XHTTP: a
// slash and 8 to 64 letters, digits, '-' or '_'.
func CheckVLESSPath(p string) error {
	if !vlessPathPattern.MatchString(p) {
		return fmt.Errorf("tunnel: vless: %q is not a path such as /AbC-12_xyz0123456", p)
	}
	return nil
}

// NewVLESSPath returns a new random path for XHTTP, which keeps scanners
// off the forwarder's listener; it is not a secret the design relies on.
func NewVLESSPath() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "/" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Equal tells whether v and w are the same link; nil is none.
func (v *VLESS) Equal(w *VLESS) bool {
	if v == nil || w == nil {
		return v == w
	}
	return v.Transport == w.Transport && v.Endpoint == w.Endpoint && string(v.PublicKey) == string(w.PublicKey) &&
		v.ShortID == w.ShortID && v.ServerName == w.ServerName && v.Path == w.Path && v.ID == w.ID
}

var (
	shortIDPattern    = regexp.MustCompile(`^([0-9a-f]{2}){1,8}$`)
	serverNamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	vlessPathPattern  = regexp.MustCompile(`^/[A-Za-z0-9_-]{8,64}$`)
	vlessIDPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// CheckServerName refuses what is not a site's name, such as
// www.example.com.
func CheckServerName(name string) error {
	if !serverNamePattern.MatchString(name) {
		return fmt.Errorf("tunnel: vless: %q is not a site's name, such as www.example.com", name)
	}
	return nil
}

// NewVLESSID returns a new random VLESS user ID for a group.
func NewVLESSID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// CheckVLESSID refuses what is not a user ID NewVLESSID would make.
func CheckVLESSID(id string) error {
	if !vlessIDPattern.MatchString(id) {
		return fmt.Errorf("tunnel: vless: %q is not a VLESS user ID", id)
	}
	return nil
}
