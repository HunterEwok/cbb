// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// VLESS is what a client needs to reach the hub's forwarder inside VLESS,
// for networks that block WireGuard (docs/design.md, "Blocked networks"),
// over XHTTP (Transport "xhttp"): the forwarder sits behind a web server
// that has the site's own certificate and passes it one path. The link has
// the web server's address, the site's name, which the certificate must
// carry, the path and the group's VLESS user ID. The hub
// learns all but the ID when it registers with the forwarder and gives it
// to its clients with its offer (docs/protocol.md, section 11). Package
// vless runs it.
type VLESS struct {
	Transport  string         `json:"transport"`   // "xhttp", the only one
	Endpoint   netip.AddrPort `json:"endpoint"`    // the web server's address, TCP
	ServerName string         `json:"server_name"` // the site the handshake names
	Path       string         `json:"path"`        // the path the web server passes
	ID         string         `json:"id"`          // the group's VLESS user ID, a UUID
}

// TransportXHTTP is the transport of VLESS, the only one; an older
// version's forwarder may offer REALITY, an empty transport, which this
// version refuses.
const TransportXHTTP = "xhttp"

// Check refuses a link that cannot work, or of a transport this version
// does not know.
func (v *VLESS) Check() error {
	if !v.Endpoint.IsValid() || v.Endpoint.Port() == 0 {
		return errors.New("tunnel: vless: the forwarder's VLESS address is missing")
	}
	switch v.Transport {
	case TransportXHTTP:
		if err := CheckVLESSPath(v.Path); err != nil {
			return err
		}
	case "":
		return errors.New("tunnel: vless: the forwarder offers VLESS inside REALITY, which this version no longer speaks; it needs XHTTP")
	default:
		return fmt.Errorf("tunnel: vless: the transport %q needs a newer version", v.Transport)
	}
	if err := CheckServerName(v.ServerName); err != nil {
		return err
	}
	return CheckVLESSID(v.ID)
}

// CheckVLESSPath refuses what is not a path for XHTTP: a
// slash and 8 to 64 letters, digits, '-' or '_', then for a group's path a
// slash and its own part (CheckGroupPath).
func CheckVLESSPath(p string) error {
	if !vlessPathPattern.MatchString(p) {
		return fmt.Errorf("tunnel: vless: %q is not a path such as /AbC-12_xyz0123456", p)
	}
	return nil
}

// CheckGroupPath refuses what is not a group's own part of an XHTTP path,
// which the forwarder gives each group: 16 to 64 letters, digits, '-' or
// '_'.
func CheckGroupPath(p string) error {
	if !groupPathPattern.MatchString(p) {
		return fmt.Errorf("tunnel: vless: %q is not a group's path", p)
	}
	return nil
}

// GroupPath returns the group's own part of the XHTTP path for its VLESS
// user ID id (docs/protocol.md, section 13, "VLESS"): the first 16 bytes of
// SHA-256 over "cbb group path", a zero byte and the ID, in unpadded
// base64url. It is unknown to anyone who does not know the ID, and a hub
// knows the path of its next ID before it registers it (section 11, "The
// hub's key"); the Rust core's vless::group_path is the same.
func GroupPath(id string) string {
	sum := sha256.Sum256([]byte("cbb group path\x00" + id))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// RegistrationPath returns the XHTTP path a hub registers on: p without the
// group's own part.
func RegistrationPath(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return p
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
	return v.Transport == w.Transport && v.Endpoint == w.Endpoint && v.ServerName == w.ServerName && v.Path == w.Path && v.ID == w.ID
}

var (
	serverNamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	vlessPathPattern  = regexp.MustCompile(`^/[A-Za-z0-9_-]{8,64}(/[A-Za-z0-9_-]{16,64})?$`)
	groupPathPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
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
