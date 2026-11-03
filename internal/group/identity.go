// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/tpmkey"
)

// FileName is the name of the identity file in the state directory.
const FileName = "identity.json"

// ErrNoGroup reports that the device is in no group yet.
var ErrNoGroup = errors.New("group: this device is in no group; run cbb new to start one or cbb pair to join one")

// ErrOldGroup reports an identity of a group made before 0.4, whose group
// CA certifies no admin CAs: such groups went with records of version 1,
// and are set up again (docs/records-v2.md).
var ErrOldGroup = errors.New("group: this device's group was made before 0.4 and is set up again from 0.6 on")

// An Identity is this device's place in a group: its device ID, its key,
// its member certificate and the group CA. The computer that created the
// group holds the root key; it and the admins it made hold the iPhone CA
// key and their own cbb.local certificates, so they can serve
// the shortcut. Every other full member holds an admin key that waits for
// an admin CA (docs/design.md, "Full members, admins and the operating
// system").
//
// An Identity is not changed after it is made; renewing returns a new one.
type Identity struct {
	ID   DeviceID
	Key  crypto.Signer     // a P-256 key: an *ecdsa.PrivateKey in the file, a *tpmkey.Key or a *sekey.Key
	Cert *x509.Certificate // from the group CA, or from Issuer
	// Issuer is the admin CA that issued Cert, in a group whose root is a
	// phone and where another admin phone admitted this device; nil when
	// the group CA issued it (docs/protocol.md, section 10).
	Issuer *x509.Certificate
	// GroupCA is the group's first root, which names the group (its tag)
	// for good.
	GroupCA CA
	// Roots are the roots that took a phone group over from GroupCA, in
	// order, as the root records say; the last is the current root. Empty
	// in a group that was never handed over (docs/protocol.md, section 10).
	Roots []*x509.Certificate
	// RootKey is the key of the last of Roots on the admin that took the
	// group over with it (TakenOver), which is the group's root from then
	// on; nil elsewhere.
	RootKey crypto.Signer
	// PhoneCA is the iPhone CA with its key, and Phone the
	// cbb.local certificate for Key, on a member that serves
	// the shortcut: the root computer and its admins. Both are nil
	// elsewhere.
	PhoneCA *CA
	Phone   *x509.Certificate
	// AdminKey is the key a full member signs with once the root makes it
	// an admin: the hello offers it until AdminCA, from the root,
	// certifies it (docs/protocol.md, section 10). Both are nil on the
	// root.
	AdminKey crypto.Signer // as Key
	AdminCA  *x509.Certificate
	// PrevCert and PrevIssuer are the member certificate for Key, and its
	// admin CA, that this device held before it took the group over: its
	// member connections present them while they last, so that a member
	// that missed the takeover, which knows only the old root, can verify
	// them and take the root record (docs/protocol.md, section 10). Nil
	// elsewhere.
	PrevCert, PrevIssuer *x509.Certificate
	// Claim is the new root, with its key, of a claim this admin, or
	// this member with the group's recovery key, signed to take the group
	// over that has not taken effect yet: when the
	// records make it the current root, TakenOver makes this device the
	// root with it (docs/protocol.md, section 10, "Handing the group over"). Nil
	// elsewhere.
	Claim *CA
}

// Create creates a new group on this device, its root: a device ID, a key,
// the root CA, the iPhone CA and the device's certificates.
func Create(now time.Time) (*Identity, error) {
	key, err := NewDeviceKey()
	if err != nil {
		return nil, err
	}
	groupCA, err := NewRootCA(now)
	if err != nil {
		return nil, err
	}
	phoneCA, err := NewPhoneCA(now)
	if err != nil {
		return nil, err
	}
	id := NewDeviceID()
	cert, err := groupCA.IssueMember(id, PublicKey(key), now)
	if err != nil {
		return nil, err
	}
	phone, err := phoneCA.IssuePhone(PublicKey(key), now)
	if err != nil {
		return nil, err
	}
	return &Identity{ID: id, Key: key, Cert: cert, GroupCA: *groupCA, PhoneCA: phoneCA, Phone: phone}, nil
}

// Root returns the group's current root: the last of Roots, or the group
// CA.
func (id *Identity) Root() *x509.Certificate {
	if n := len(id.Roots); n > 0 {
		return id.Roots[n-1]
	}
	return id.GroupCA.Cert
}

// Trusted returns every root the group had, the group CA first: member
// certificates and admin CAs from any of them verify.
func (id *Identity) Trusted() []*x509.Certificate {
	return append([]*x509.Certificate{id.GroupCA.Cert}, id.Roots...)
}

// RootCA returns the CA of the group's current root with its key, when
// this device holds it: the group CA on the computer that created the
// group, or the root this device took the group over with. It returns nil
// elsewhere.
func (id *Identity) RootCA() *CA {
	switch {
	case id.GroupCA.Key != nil:
		return &id.GroupCA
	case id.RootKey != nil:
		return &CA{Cert: id.Root(), Key: id.RootKey}
	}
	return nil
}

// ServesPhone reports whether this device holds the iPhone CA key and its
// cbb.local certificate, so it can serve the shortcut.
func (id *Identity) ServesPhone() bool {
	return id.PhoneCA != nil && id.PhoneCA.Key != nil && id.Phone != nil
}

// IsAdmin reports whether this device admits devices, signs records and
// renews certificates: it holds the root key or an admin CA.
func (id *Identity) IsAdmin() bool {
	ca, _ := id.Signer()
	return ca != nil
}

// IsRoot reports whether this device holds the key of the group's current
// root, as the computer that created a group does, or the admin that took
// it over.
func (id *Identity) IsRoot() bool { return id.RootCA() != nil }

// Signer returns the CA this device admits devices and signs records with,
// and the chain its records carry: the root's CA on the root (RootCA), the
// admin CA on a member that the root made an admin. It returns nil when this device is no admin.
func (id *Identity) Signer() (*CA, []*x509.Certificate) {
	if ca := id.RootCA(); ca != nil {
		return ca, nil
	}
	switch {
	case id.AdminCA != nil:
		return &CA{Cert: id.AdminCA, Key: id.AdminKey}, []*x509.Certificate{id.AdminCA}
	}
	return nil, nil
}

// StaleAdminCA reports whether this admin's CA is from a root before the
// group's current one, as after another admin took the group over: a root
// record it signed would hang under that earlier root and split the
// group's roots, so its hello offers its admin key again, and the current
// root certifies the same key anew (docs/protocol.md, section 10).
func (id *Identity) StaleAdminCA() bool {
	return id.AdminCA != nil && id.AdminCA.CheckSignatureFrom(id.Root()) != nil
}

// NeedsAdminKey reports whether this device should make an admin key for
// the root to certify: it is not the root, and has none yet.
func (id *Identity) NeedsAdminKey() bool {
	return !id.IsRoot() && id.AdminKey == nil
}

// WithAdminKey returns the identity with a new admin key, for a full member
// that has none yet (NeedsAdminKey).
func (id *Identity) WithAdminKey() (*Identity, error) {
	if !id.NeedsAdminKey() {
		return nil, errors.New("group: only a member of a group with a root, not the root, and without one gets an admin key")
	}
	key, err := NewDeviceKey()
	if err != nil {
		return nil, err
	}
	next := *id
	next.AdminKey = key
	return &next, nil
}

// WithAdminCA returns the identity with the admin CA that the root issued
// for its admin key, which makes this member an admin, and a new
// member certificate from that admin CA: a device it admits then checks
// both against the one issuer in the Welcome.
func (id *Identity) WithAdminCA(der []byte, now time.Time) (*Identity, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("group: the admin CA: %w", err)
	}
	next := *id
	next.AdminCA = c
	if err := next.checkAdmin(); err != nil {
		return nil, err
	}
	ca, _ := next.Signer()
	if next.Cert, err = ca.IssueMember(id.ID, PublicKey(id.Key), now); err != nil {
		return nil, err
	}
	next.Issuer = c
	if err := next.Check(); err != nil {
		return nil, err
	}
	return &next, nil
}

// TakenOver returns the identity of an admin, or of a member that claimed
// with the recovery key, that took the group over from a lost root
// (docs/protocol.md, section 10): roots, as the records lead
// to them after its root record, end with root, whose key this device
// holds from now on as the group's root, and its admin key and admin CA
// go. Its member certificate is reissued from the new root at once: a
// Welcome names one issuer for the new device's certificate and the
// admitter's alike, so a root admits only with a certificate of its own.
func (id *Identity) TakenOver(root *CA, roots []*x509.Certificate, now time.Time) (*Identity, error) {
	switch {
	case id.IsRoot() || id.Claim == nil && id.AdminCA == nil:
		return nil, errors.New("group: only an admin, or a member that claimed with the recovery key, takes a group with a root over")
	case root.Key == nil || len(roots) == 0 || !roots[len(roots)-1].Equal(root.Cert):
		return nil, errors.New("group: the records do not lead to the new root; another admin may have taken the group over first")
	}
	next := *id
	next.Roots, next.RootKey = roots, root.Key
	next.AdminKey, next.AdminCA = nil, nil
	next.PrevCert, next.PrevIssuer = id.Cert, id.Issuer
	next.Claim = nil
	var err error
	if next.Cert, err = root.IssueMember(id.ID, PublicKey(id.Key), now); err != nil {
		return nil, err
	}
	next.Issuer = nil
	// The root serves the shortcut: a member that claimed with the
	// recovery key held no iPhone CA, so it makes one; the new root
	// replaces it anyway once it took over.
	if next.PhoneCA == nil {
		if next.PhoneCA, err = NewPhoneCA(now); err != nil {
			return nil, err
		}
		if next.Phone, err = next.PhoneCA.IssuePhone(PublicKey(id.Key), now); err != nil {
			return nil, err
		}
	}
	if err := next.Check(); err != nil {
		return nil, err
	}
	return &next, nil
}

// WithClaim returns the identity of an admin, or of a member with the
// group's recovery key, that signed a claim to take the group over with the
// new root ca (Claim); nil ca drops it, as after
// the claim was cancelled.
func (id *Identity) WithClaim(ca *CA) (*Identity, error) {
	next := *id
	next.Claim = ca
	if err := next.Check(); err != nil {
		return nil, err
	}
	return &next, nil
}

// WithRoots returns the identity trusting roots, the roots the records lead
// to after a root record. A device that held the root it replaces no longer
// is the root, and gives up the iPhone CA with it.
func (id *Identity) WithRoots(roots []*x509.Certificate) (*Identity, error) {
	next := *id
	next.Roots = roots
	if id.RootKey != nil && (len(roots) == 0 || !SameKey(id.RootKey, roots[len(roots)-1].PublicKey)) {
		next.RootKey, next.PhoneCA, next.Phone = nil, nil, nil
	}
	if err := next.Check(); err != nil {
		return nil, err
	}
	return &next, nil
}

// WithPhoneCA returns the identity with the iPhone CA ca, its key
// included, and a new cbb.local certificate from it: for an
// admin of a group a computer created, which serves the shortcut with it.
func (id *Identity) WithPhoneCA(ca CA, now time.Time) (*Identity, error) {
	if ca.Key == nil {
		return nil, errors.New("group: the iPhone CA comes without its key")
	}
	if err := checkCA(&ca, "iPhone CA", 0); err != nil {
		return nil, err
	}
	phone, err := ca.IssuePhone(PublicKey(id.Key), now)
	if err != nil {
		return nil, err
	}
	next := *id
	next.PhoneCA, next.Phone = &ca, phone
	if err := next.Check(); err != nil {
		return nil, err
	}
	return &next, nil
}

// WithoutPhoneCA returns the identity without the iPhone CA and its
// cbb.local certificate, after the records revoked that CA.
func (id *Identity) WithoutPhoneCA() *Identity {
	next := *id
	next.PhoneCA, next.Phone = nil, nil
	return &next
}

// AdminName is the subject CN of the admin CA of a device.
func AdminName(dev DeviceID) string { return "cbb admin " + string(dev) }

// Check reports whether the parts of the identity belong together: the
// certificates name this device and its key and were signed by the CAs, and
// the CA keys match the CA certificates. It does not check expiry.
func (id *Identity) Check() error {
	if _, err := ParseDeviceID(string(id.ID)); err != nil {
		return err
	}
	if id.Key == nil || PublicKey(id.Key) == nil {
		return errors.New("group: the device key is not a P-256 key")
	}
	if err := checkCA(&id.GroupCA, "group CA", maxGroupCAPath); err != nil {
		return err
	}
	if id.GroupCA.Cert.MaxPathLen < maxGroupCAPath {
		return ErrOldGroup
	}
	if len(id.Roots) > 0 && id.GroupCA.Key != nil {
		return errors.New("group: only a group with a root, on a member that does not hold the first root's key, has later roots")
	}
	for _, r := range id.Roots {
		if err := checkRoot(r); err != nil {
			return err
		}
	}
	if id.RootKey != nil && (len(id.Roots) == 0 || !SameKey(id.RootKey, id.Root().PublicKey)) {
		return errors.New("group: the root key is not the key of the group's current root")
	}
	if id.Claim != nil {
		if id.IsRoot() || id.Claim.Key == nil || !SameKey(id.Claim.Key, id.Claim.Cert.PublicKey) {
			return errors.New("group: only a member that is not the root holds a claim's new root, with its key")
		}
		if err := checkRoot(id.Claim.Cert); err != nil {
			return err
		}
	}
	issuers := id.Trusted()
	if id.Issuer != nil {
		err := errors.New("group: the issuer is not an admin CA of the group")
		for _, root := range issuers {
			if err = checkAdminCA(id.Issuer, root); err == nil {
				break
			}
		}
		if err != nil {
			return err
		}
		issuers = []*x509.Certificate{id.Issuer}
	}
	var err error
	for _, issuer := range issuers {
		if err = checkLeaf(id.Cert, issuer, id.Key, "member certificate"); err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	if dev, err := DeviceOf(id.Cert); err != nil || dev != id.ID {
		return fmt.Errorf("group: the member certificate does not name the device %s", id.ID)
	}
	if !hasUsage(id.Cert, x509.ExtKeyUsageServerAuth) || !hasUsage(id.Cert, x509.ExtKeyUsageClientAuth) {
		return errors.New("group: the member certificate is not for client and server use")
	}
	if err := id.checkAdmin(); err != nil {
		return err
	}
	// The iPhone CA comes with its key and the cbb.local
	// certificate. The root holds it, an admin may.
	serves := id.PhoneCA != nil
	if serves != (id.Phone != nil) || serves && id.PhoneCA.Key == nil {
		return errors.New("group: the identity holds only some of the iPhone CA, its key and the cbb.local certificate")
	}
	switch {
	case id.IsRoot() && !serves:
		return errors.New("group: the root holds no iPhone CA")
	case !id.IsRoot() && serves && id.AdminCA == nil:
		return errors.New("group: only an admin holds the iPhone CA")
	}
	if !serves {
		return nil
	}
	if err := checkCA(id.PhoneCA, "iPhone CA", 0); err != nil {
		return err
	}
	if err := checkLeaf(id.Phone, id.PhoneCA.Cert, id.Key, "cbb.local certificate"); err != nil {
		return err
	}
	if err := id.Phone.VerifyHostname(PhoneName); err != nil {
		return fmt.Errorf("group: %w", err)
	}
	return nil
}

// checkAdmin checks the admin key and the admin CA: not on the root, the CA for that key, under one of the group's
// roots, naming this device.
func (id *Identity) checkAdmin() error {
	if id.AdminKey == nil {
		if id.AdminCA != nil {
			return errors.New("group: the identity has an admin CA but no admin key")
		}
		return nil
	}
	if id.IsRoot() {
		return errors.New("group: only a member that is not the root has an admin key")
	}
	if PublicKey(id.AdminKey) == nil {
		return errors.New("group: the admin key is not a P-256 key")
	}
	if id.AdminCA == nil {
		return nil
	}
	if !SameKey(id.AdminKey, id.AdminCA.PublicKey) {
		return errors.New("group: the admin CA is not for this device's admin key")
	}
	if id.AdminCA.Subject.CommonName != AdminName(id.ID) {
		return fmt.Errorf("group: the admin CA does not name the device %s", id.ID)
	}
	err := errors.New("group: the admin CA is not from a root of the group")
	for _, root := range id.Trusted() {
		if err = checkAdminCA(id.AdminCA, root); err == nil {
			break
		}
	}
	return err
}

// maxGroupCAPath is the path a group CA allows: 1, since a root certifies
// admin CAs (docs/protocol.md, sections 9 and 10); a group made before 0.4
// had 0 (ErrOldGroup).
const maxGroupCAPath = 1

// checkCA checks a CA certificate: self-signed, a P-256 key, and a path
// length from 0 to maxPath.
func checkCA(ca *CA, what string, maxPath int) error {
	c := ca.Cert
	if c == nil || !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen < 0 || c.MaxPathLen > maxPath ||
		(c.MaxPathLen == 0 && !c.MaxPathLenZero) {
		return fmt.Errorf("group: the %s certificate is not a CA with a path length of at most %d", what, maxPath)
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return fmt.Errorf("group: the %s key is not a P-256 key", what)
	}
	if c.CheckSignatureFrom(c) != nil {
		return fmt.Errorf("group: the %s certificate is not self-signed", what)
	}
	if ca.Key != nil && !SameKey(ca.Key, c.PublicKey) {
		return fmt.Errorf("group: the %s key does not match its certificate", what)
	}
	return nil
}

func checkLeaf(c, ca *x509.Certificate, key crypto.Signer, what string) error {
	if c == nil {
		return fmt.Errorf("group: the %s is missing", what)
	}
	if c.IsCA {
		return fmt.Errorf("group: the %s is a CA", what)
	}
	if err := c.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("group: the %s is not from its CA: %w", what, err)
	}
	if !SameKey(key, c.PublicKey) {
		return fmt.Errorf("group: the %s does not match the device key", what)
	}
	return nil
}

func hasUsage(c *x509.Certificate, u x509.ExtKeyUsage) bool {
	for _, have := range c.ExtKeyUsage {
		if have == u {
			return true
		}
	}
	return false
}

// Renew returns an identity with new certificates for those that end
// within their renewal period (240 days for the member certificate, 60 days
// for the cbb.local one), and reports whether anything changed. A
// cbb.local certificate that starts in the future, issued while the
// clock was ahead, is replaced too, since the iPhone would reject it. A
// certificate that already ends with its CA is kept: a new one could not
// last longer. Only a device that holds the CA keys, or an admin CA, renews
// its own certificates; others get theirs from a member that does
// (RenewMember).
func (id *Identity) Renew(now time.Time) (*Identity, bool, error) {
	next := *id
	changed := false
	if ca := id.RootCA(); ca != nil && renewable(id.Cert, ca.Cert, now, memberRenewBefore) {
		cert, err := ca.IssueMember(id.ID, PublicKey(id.Key), now)
		if err != nil {
			return id, false, err
		}
		next.Cert, next.Issuer, changed = cert, nil, true
	}
	if id.AdminCA != nil && renewable(id.Cert, id.AdminCA, now, memberRenewBefore) {
		ca, _ := id.Signer()
		cert, err := ca.IssueMember(id.ID, PublicKey(id.Key), now)
		if err != nil {
			return id, false, err
		}
		next.Cert, next.Issuer, changed = cert, id.AdminCA, true
	}
	if id.Phone != nil && id.PhoneCA.Key != nil && renewable(id.Phone, id.PhoneCA.Cert, now, phoneRenewBefore) {
		cert, err := id.PhoneCA.IssuePhone(PublicKey(id.Key), now)
		if err != nil {
			return id, false, err
		}
		next.Phone, changed = cert, true
	}
	return &next, changed, nil
}

// RenewMember returns a new member certificate for the member at the other
// end of a connection, whose certificate peer ends within its renewal
// period, for the same device and key, and the admin CA that issued it, nil
// for the group CA. It returns nil when the certificate is not due, or this
// device is no admin: then another member renews it. An admin computer
// renews any member's certificate, as an admin phone does; the TLS
// handshake already checked that peer is from the group.
func (id *Identity) RenewMember(peer *x509.Certificate, now time.Time) (cert, issuer *x509.Certificate, err error) {
	ca, chain := id.Signer()
	if ca == nil || !renewable(peer, ca.Cert, now, memberRenewBefore) {
		return nil, nil, nil
	}
	if chain == nil {
		if err := peer.CheckSignatureFrom(ca.Cert); err != nil {
			return nil, nil, fmt.Errorf("group: the certificate to renew is not from the group CA: %w", err)
		}
	}
	dev, err := DeviceOf(peer)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := peer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("group: the certificate to renew has no ECDSA key")
	}
	if cert, err = ca.IssueMember(dev, pub, now); err != nil {
		return nil, nil, err
	}
	return cert, id.AdminCA, nil
}

// WithCert returns the identity with a member certificate that another
// member renewed for it. The certificate must be from the issuer of the
// current one, or from one of the group's roots, name this device and its
// key, and end later than the current one.
func (id *Identity) WithCert(der []byte) (*Identity, error) { return id.WithCertFrom(der, nil) }

// WithCertFrom is WithCert for a certificate that the admin CA issuer
// issued, as an admin phone renews the certificates of devices that
// another admin admitted (docs/protocol.md, section 10): issuer must be an
// admin CA under one of the group's roots, and becomes the identity's
// Issuer. Without issuer it is WithCert.
func (id *Identity) WithCertFrom(der, issuer []byte) (*Identity, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("group: the renewed certificate: %w", err)
	}
	next := *id
	next.Cert = cert
	if issuer != nil {
		if next.Issuer, err = x509.ParseCertificate(issuer); err != nil {
			return nil, fmt.Errorf("group: the renewed certificate's issuer: %w", err)
		}
	}
	if err := next.Check(); err != nil {
		if id.Issuer == nil || issuer != nil {
			return nil, err
		}
		// A root renewed a certificate that an admin CA had issued.
		next.Issuer = nil
		if next.Check() != nil {
			return nil, err
		}
	}
	if !cert.NotAfter.After(id.Cert.NotAfter) {
		return nil, errors.New("group: the renewed certificate does not end later than the current one")
	}
	return &next, nil
}

// renewable reports whether a certificate should be replaced: it starts in
// the future, or it ends within before and its CA lasts longer than it. A
// clock before the CA's start is wrong, and nothing is renewed then.
func renewable(c, ca *x509.Certificate, now time.Time, before time.Duration) bool {
	switch {
	case now.Before(ca.NotBefore):
		return false
	case now.Before(c.NotBefore):
		return true
	}
	return now.After(c.NotAfter.Add(-before)) && ca.NotAfter.After(c.NotAfter)
}

// identityFile is the format of the identity file. Keys are PKCS #8 and
// certificates DER, both base64 in JSON.
type identityFile struct {
	Version    int      `json:"v"`
	Device     string   `json:"device"`
	Key        []byte   `json:"key,omitempty"`
	Cert       []byte   `json:"cert"`
	Issuer     []byte   `json:"issuer,omitempty"`
	GroupCA    []byte   `json:"group_ca"`
	Roots      [][]byte `json:"roots,omitempty"`
	GroupCAKey []byte   `json:"group_ca_key,omitempty"`
	RootKey    []byte   `json:"root_key,omitempty"`
	PhoneCA    []byte   `json:"phone_ca,omitempty"`
	PhoneCAKey []byte   `json:"phone_ca_key,omitempty"`
	Phone      []byte   `json:"phone,omitempty"`
	AdminKey   []byte   `json:"admin_key,omitempty"`
	AdminCA    []byte   `json:"admin_ca,omitempty"`
	PrevCert   []byte   `json:"prev_cert,omitempty"`
	PrevIssuer []byte   `json:"prev_issuer,omitempty"`
	Claim      []byte   `json:"claim,omitempty"`
	ClaimKey   []byte   `json:"claim_key,omitempty"`
	// KeyTPM and AdminKeyTPM stand for Key and AdminKey when those live
	// in the TPM: the blob that only this machine's TPM loads.
	KeyTPM      *tpmkey.Blob `json:"key_tpm,omitempty"`
	AdminKeyTPM *tpmkey.Blob `json:"admin_key_tpm,omitempty"`
	// KeySE and AdminKeySE stand for them when they live in a Mac's
	// Secure Enclave: the blob that only this Mac's enclave loads.
	KeySE      []byte `json:"key_se,omitempty"`
	AdminKeySE []byte `json:"admin_key_se,omitempty"`
}

const fileVersion = 1

// Save writes the identity to dir/identity.json, readable only by its
// owner. It replaces the file in one step, so a crash leaves either the old
// identity or the new one.
func (id *Identity) Save(dir string) error {
	if err := id.Check(); err != nil {
		return err
	}
	f := identityFile{
		Version: fileVersion,
		Device:  string(id.ID),
		Cert:    id.Cert.Raw,
		GroupCA: id.GroupCA.Cert.Raw,
	}
	if id.Issuer != nil {
		f.Issuer = id.Issuer.Raw
	}
	for _, r := range id.Roots {
		f.Roots = append(f.Roots, r.Raw)
	}
	key, err := storeKey(id.Key)
	if err != nil {
		return err
	}
	f.Key, f.KeyTPM, f.KeySE = key.der, key.tpm, key.se
	if id.GroupCA.Key != nil {
		if f.GroupCAKey, err = x509.MarshalPKCS8PrivateKey(id.GroupCA.Key); err != nil {
			return err
		}
	}
	if id.RootKey != nil {
		if f.RootKey, err = x509.MarshalPKCS8PrivateKey(id.RootKey); err != nil {
			return err
		}
	}
	if id.PhoneCA != nil {
		f.PhoneCA, f.Phone = id.PhoneCA.Cert.Raw, id.Phone.Raw
		if id.PhoneCA.Key != nil {
			if f.PhoneCAKey, err = x509.MarshalPKCS8PrivateKey(id.PhoneCA.Key); err != nil {
				return err
			}
		}
	}
	if id.AdminKey != nil {
		key, err := storeKey(id.AdminKey)
		if err != nil {
			return err
		}
		f.AdminKey, f.AdminKeyTPM, f.AdminKeySE = key.der, key.tpm, key.se
	}
	if id.AdminCA != nil {
		f.AdminCA = id.AdminCA.Raw
	}
	if id.PrevCert != nil {
		f.PrevCert = id.PrevCert.Raw
	}
	if id.PrevIssuer != nil {
		f.PrevIssuer = id.PrevIssuer.Raw
	}
	if id.Claim != nil {
		f.Claim = id.Claim.Cert.Raw
		if f.ClaimKey, err = x509.MarshalPKCS8PrivateKey(id.Claim.Key); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, FileName), append(data, '\n'), 0o600)
}

// Load reads the identity from dir/identity.json. It returns ErrNoGroup if
// there is none.
func Load(dir string) (*Identity, error) {
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoGroup
	}
	if err != nil {
		return nil, err
	}
	id, err := parseIdentity(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, FileName), err)
	}
	return id, nil
}

func parseIdentity(data []byte) (*Identity, error) {
	var f identityFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("unknown identity file version %d", f.Version)
	}
	id := &Identity{ID: DeviceID(f.Device)}
	var err error
	if id.Key, err = (storedKey{f.Key, f.KeyTPM, f.KeySE}).load(); err != nil {
		return nil, err
	}
	if id.Cert, err = x509.ParseCertificate(f.Cert); err != nil {
		return nil, err
	}
	if f.Issuer != nil {
		if id.Issuer, err = x509.ParseCertificate(f.Issuer); err != nil {
			return nil, err
		}
	}
	if id.GroupCA, err = parseCA(f.GroupCA, f.GroupCAKey); err != nil {
		return nil, err
	}
	for _, der := range f.Roots {
		r, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		id.Roots = append(id.Roots, r)
	}
	if f.RootKey != nil {
		if id.RootKey, err = parseKey(f.RootKey); err != nil {
			return nil, err
		}
	}
	if f.PhoneCA != nil || f.PhoneCAKey != nil || f.Phone != nil {
		phoneCA, err := parseCA(f.PhoneCA, f.PhoneCAKey)
		if err != nil {
			return nil, err
		}
		id.PhoneCA = &phoneCA
		if id.Phone, err = x509.ParseCertificate(f.Phone); err != nil {
			return nil, err
		}
	}
	if f.AdminKey != nil || f.AdminKeyTPM != nil || f.AdminKeySE != nil {
		if id.AdminKey, err = (storedKey{f.AdminKey, f.AdminKeyTPM, f.AdminKeySE}).load(); err != nil {
			return nil, err
		}
	}
	if f.AdminCA != nil {
		if id.AdminCA, err = x509.ParseCertificate(f.AdminCA); err != nil {
			return nil, err
		}
	}
	if f.PrevCert != nil {
		if id.PrevCert, err = x509.ParseCertificate(f.PrevCert); err != nil {
			return nil, err
		}
	}
	if f.PrevIssuer != nil {
		if id.PrevIssuer, err = x509.ParseCertificate(f.PrevIssuer); err != nil {
			return nil, err
		}
	}
	if f.Claim != nil || f.ClaimKey != nil {
		claim, err := parseCA(f.Claim, f.ClaimKey)
		if err != nil {
			return nil, err
		}
		id.Claim = &claim
	}
	if err := id.Check(); err != nil {
		return nil, err
	}
	return id, nil
}

func parseCA(cert, key []byte) (CA, error) {
	var ca CA
	var err error
	if ca.Cert, err = x509.ParseCertificate(cert); err != nil {
		return CA{}, err
	}
	if key != nil {
		if ca.Key, err = parseKey(key); err != nil {
			return CA{}, err
		}
	}
	return ca, nil
}

func parseKey(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("a key is not a P-256 key")
	}
	return key, nil
}
