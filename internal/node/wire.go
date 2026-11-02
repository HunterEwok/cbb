// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/jsonnum"
	signed "github.com/HunterEwok/clipboardbridge/internal/release"
)

// The member protocol runs over a TLS connection made with the group's
// member configuration. Each side sends frames of a 4-byte big-endian length
// and a JSON message. The first message of each side is a hello; then
// events follow, and a ping whenever the side has sent nothing for a while,
// so a silent connection is a dead one. A member that holds the group CA key
// sends a cert message with a renewed certificate to a peer whose
// certificate is due for renewal. The group's signed records travel in
// records messages to a peer whose hello names other records. The group's
// root sends an admin message with an admin CA to a member whose hello
// offers an admin key. In a group a computer created, an admin sends a
// phone_ca message with the iPhone CA and its key to an admin whose hello
// names another one. The group's hub sends a tunnel message to a member
// whose hello offers a tunnel key. An admin sends a command message with a
// signed command for the receiver, such as a sync mode, which answers with
// a result message. A hub sends a hubs message to another device that may
// be a hub, with its offer and its clients' keys. A device whose keys an
// attestation proves sends an evidence message with it after the hello.
// A member that keeps the group's server credentials sends them in a
// credentials message after the hello, and passes new ones on. A member
// that holds a signed release newer than the one a peer's hello names sends
// it in a release message, and passes newer ones on.
const (
	typeHello   = "hello"
	typeEvent   = "event"
	typePing    = "ping"
	typeBye     = "bye"
	typeCert    = "cert"
	typeRecs    = "records"
	typeAdmin   = "admin"
	typePhoneCA = "phone_ca"
	typeTun     = "tunnel"
	typeCommand = "command"
	typeResult  = "result"
	typeHubs    = "hubs"
	typeEvid    = "evidence"
	typeCreds   = "credentials"
	typeRelease = "release"
	typeGet     = "get"
	typeMissing = "missing"
	typeChunk   = "chunk" // a binary frame, never JSON

	// maxFrame bounds a frame: a text of up to 1 MiB, which JSON may
	// escape to six bytes per byte for control characters, and the rest
	// of the event.
	maxFrame = 7 << 20

	// minRate is the slowest transfer a frame is given time for, on top
	// of the timeout, so a large text over a slow link still arrives.
	minRate = 16 << 10 // bytes per second
)

// FeatureMedia, in a hello's features, tells that the sender serves the
// content of media events ("Content" of docs/protocol.md, section 4), so
// that others may send it get. maxFeatures is how many names of a hello's
// features a receiver reads.
const (
	FeatureMedia = "media"
	maxFeatures  = 32
)

// Role tells what kind of member is at the other end.
type Role string

const (
	Full  Role = "full"  // a computer with the service: Linux, Windows or macOS
	Phone Role = "phone" // a phone app: only dials, never dialed
	Lite  Role = "lite"  // a lite member for small devices
)

// known reports whether a peer may claim the role in its hello.
func (r Role) known() bool {
	switch r {
	case Full, Phone, Lite:
		return true
	}
	return false
}

// message is one frame of the member protocol. The hello and the event are
// decoded on their own, so an event this member cannot read, for example
// from a newer version, is dropped without ending the connection.
type message struct {
	Type  string          `json:"t"`
	Role  Role            `json:"role,omitempty"`  // in a hello
	Hello json.RawMessage `json:"hello,omitempty"` // in a hello: clip.Hello
	Event json.RawMessage `json:"event,omitempty"` // in an event: clip.Event
	Cert  []byte          `json:"cert,omitempty"`  // in a cert: the renewed member certificate, DER
	// Issuer, in a cert from an admin phone, is its admin CA, which
	// issued Cert; absent when a root did.
	Issuer []byte `json:"issuer,omitempty"`

	Records []group.Record `json:"records,omitempty"` // in a records message
	// Credentials, in a credentials message, are the group's server
	// credentials (docs/protocol.md, section 18).
	Credentials []group.Credential `json:"credentials,omitempty"`
	// Release, in a release message, is the newest signed release the
	// sender holds (docs/protocol.md, section 16, "In the group").
	Release *ReleaseSet `json:"release,omitempty"`
	// AdminCA, in an admin message from the group's root, is the
	// receiver's admin CA for the admin key its hello offered, DER.
	AdminCA []byte `json:"admin_ca,omitempty"`
	// PhoneCA and PhoneCAKey, in a phone_ca message from an admin, are
	// the group's iPhone CA, DER, and its key, PKCS #8.
	PhoneCA    []byte `json:"phone_ca,omitempty"`
	PhoneCAKey []byte `json:"phone_ca_key,omitempty"`
	// Tunnel, in a tunnel message from the group's hub, is its offer for
	// the tunnel key the receiver's hello carried.
	Tunnel *TunnelOffer `json:"tunnel,omitempty"`
	// Command, in a command message from an admin, is a command signed
	// for the receiver (group.CommandBody).
	Command *group.Record `json:"command,omitempty"`
	// Result, in a result message, answers a command.
	Result *Result `json:"result,omitempty"`
	// Hubs, in a hubs message, is what a hub shares with the group's other
	// hubs (docs/protocol.md, section 11, "Several hubs").
	Hubs *HubShare `json:"hubs,omitempty"`
	// Evidence, in an evidence message, proves where the sender's keys
	// live (docs/protocol.md, section 17, "Evidence").
	Evidence *Evidence `json:"evidence,omitempty"`
	// Get, in a get message, asks for a range of a part of a media event;
	// in a missing message, it is the get the sender cannot answer.
	Get *Get `json:"get,omitempty"`

	chunk *chunk // a binary chunk frame, which readMessage decoded
}

// Evidence is an attestation of one of the sender's keys.
type Evidence struct {
	// Format is EvidenceAndroid: Chain is the Keystore's certificate
	// chain, leaf first, DER.
	Format string `json:"format"`
	// Key names the attested key: EvidenceMember for the member key of
	// the sender's TLS certificate.
	Key string `json:"key"`
	// GroupTag and Salt made the attestation challenge with the key
	// (attest.Challenge); GroupTag is "" for a key made outside a group.
	GroupTag string `json:"group_tag,omitempty"`
	// Salt and Chain are never null, for the kits' decoders: an empty
	// salt and chain in the formats without them.
	Salt  []byte   `json:"salt"`
	Chain [][]byte `json:"chain"`
	// TPM, in EvidenceTPM, is the TPM's attestation of the key.
	TPM *TPMEvidence `json:"tpm,omitempty"`
	// Credential and Secret, in EvidenceTPMCredential, are what the root
	// encrypted to the sender's EK for its AK; Secret, in
	// EvidenceTPMActivated, is what the TPM recovered of it.
	Credential []byte `json:"credential,omitempty"`
	Secret     []byte `json:"secret,omitempty"`
}

// TPMEvidence is a TPM's attestation of a key (docs/protocol.md, section
// 17, "TPM evidence"): Chain holds the EK certificate and the
// certificates the device has between it and its maker.
type TPMEvidence struct {
	EK        []byte `json:"ek"`
	AK        []byte `json:"ak"`
	Key       []byte `json:"key"`
	Attest    []byte `json:"attest"`
	Signature []byte `json:"signature"`
}

// The formats and keys of Evidence.
const (
	EvidenceAndroid       = "android-key"
	EvidenceTPM           = "tpm"
	EvidenceTPMCredential = "tpm-credential"
	EvidenceTPMActivated  = "tpm-activated"
	EvidenceMember        = "member"
)

// HubShare is what a hub tells another device that may be a hub: its offer
// without a preshared key, whether it serves its clients now, and the
// clients it keeps, itself among them, with their keys, so that each hub
// of the group can take every client (docs/protocol.md, section 11,
// "Several hubs").
type HubShare struct {
	Serving bool              `json:"serving,omitempty"`
	Offer   *TunnelOffer      `json:"offer,omitempty"`
	Clients []group.HubClient `json:"clients,omitempty"`
}

// Result answers a command (docs/protocol.md, section 15).
type Result struct {
	ID string `json:"id"` // the command's ID
	// By is the device that answered, the command's receiver; a member
	// that passes the result back leaves it as it is.
	By     group.DeviceID `json:"by,omitempty"`
	Status string         `json:"status"` // ResultDone, ResultRefused or ResultFailed
	// Reason says why it was refused or failed, for the sender to show.
	Reason string `json:"reason,omitempty"`
	// Tunnel, in the result of a hub command that was carried out, is the
	// new hub's offer without a preshared key: its key and its addresses,
	// which the old hub passes to each client with the client's own
	// preshared key (docs/protocol.md, section 11, "Moving the hub").
	Tunnel *TunnelOffer `json:"tunnel,omitempty"`
	// Written, if set, is closed once the result has been written to the
	// peer that sent the command, or could not be: a command that ends
	// the connection, as away-off does, waits for it.
	Written chan struct{} `json:"-"`
}

// The statuses of a Result.
const (
	ResultDone    = "done"
	ResultRefused = "refused" // the receiver does not take the command: its signer, times or content
	ResultFailed  = "failed"  // the receiver took it but could not carry it out
)

// TunnelOffer is the group's hub's answer to a member's tunnel key
// (docs/protocol.md, section 11): the hub's WireGuard public key, the
// member's own preshared key, the hub's addresses away from home, the
// group's obfuscation settings and the way over VLESS when it has them.
type TunnelOffer struct {
	HubKey    []byte   `json:"hub_key"`
	PSK       []byte   `json:"psk"`
	Endpoints []string `json:"endpoints,omitempty"`
	// Obfuscation is the group's AmneziaWG settings, a JSON object that
	// internal/tunnel reads; absent for plain WireGuard.
	Obfuscation json.RawMessage `json:"obfuscation,omitempty"`
	// VLESS is how a member reaches the hub's forwarder over VLESS, a JSON
	// object that internal/tunnel reads; with it, it is the only way to
	// the hub.
	VLESS json.RawMessage `json:"vless,omitempty"`
	// Hub, in an offer a hub passes on, is the hub it is for: another of
	// the group's hubs, or the new hub when the sender hands the hub over
	// (section 11, "Several hubs" and "Moving the hub"); absent when the
	// offer is the sender's own.
	Hub group.DeviceID `json:"hub,omitempty"`
	// Moved, in an offer passed on, tells that the sender is no hub any
	// more: the receiver forgets the sender's own offer.
	Moved bool `json:"moved,omitempty"`
	// NextKey is the key the hub serves with in the next period of the
	// group's server credentials, which the receiver tries after HubKey
	// (section 11, "The hub's key"); absent for none.
	NextKey []byte `json:"next_key,omitempty"`
}

// helloBody is the content of a hello, with its current event left to
// decode on its own.
type helloBody struct {
	Wall    int64           `json:"wall_ms"`
	Current json.RawMessage `json:"current,omitempty"`
	Records string          `json:"records,omitempty"` // the digest of the sender's records
	Name    string          `json:"name,omitempty"`    // the sender's device name
	OS      string          `json:"os,omitempty"`      // the sender's operating system
	// Device is what the sender says about its device, for showing.
	Device *group.DeviceInfo `json:"device,omitempty"`
	// TunnelKey is the sender's WireGuard public key, for the hub.
	TunnelKey []byte `json:"tunnel_key,omitempty"`
	// TunnelPSK is the sender's own preshared key, which every hub uses
	// for it; a tunnel key comes with it.
	TunnelPSK []byte `json:"tunnel_psk,omitempty"`
	// Mode is the sender's sync mode, for showing; "" from a member that
	// has none, such as a phone.
	Mode string `json:"mode,omitempty"`
	// AdminKey is the admin key the sender offers, for the root.
	AdminKey []byte `json:"admin_key,omitempty"`
	// PhoneCA is the SHA-256 of the SubjectPublicKeyInfo of the iPhone CA
	// whose key the sender holds.
	PhoneCA []byte `json:"phone_ca,omitempty"`
	// KeyStore is where the sender says its keys live (group.StoreFile or
	// group.StoreHardware or group.StoreRootless).
	KeyStore string `json:"key_store,omitempty"`
	// Actions are the sender's quick actions that are on, for the
	// buttons.
	Actions []string `json:"actions,omitempty"`
	// Features are what the sender supports beyond the protocol of its
	// ALPN version (FeatureMedia); a receiver ignores names it does not
	// know.
	Features []string `json:"features,omitempty"`
	// Seal is the sender's public key for sealed messages.
	Seal []byte `json:"seal,omitempty"`
	// ReleaseSeq is the seq of the channel file of the signed release
	// the sender holds; 0 for none.
	ReleaseSeq uint64 `json:"release_seq,omitempty"`
	// ReleaseKeys is the seq of that release's keys.json; 0 for none.
	ReleaseKeys uint64 `json:"release_keys_seq,omitempty"`
}

// helloOut is the hello this member sends: the engine's hello, the digest
// of its records, its name, the admin key it offers and its tunnel key.
type helloOut struct {
	clip.Hello
	Records string `json:"records,omitempty"`
	Name    string `json:"name,omitempty"`
	OS      string `json:"os,omitempty"`
	// Device is this member's form, versions and MAC address, for the
	// others to show.
	Device *group.DeviceInfo `json:"device,omitempty"`
	// AdminKey is the SubjectPublicKeyInfo of the admin key of a member
	// that is no admin yet, DER, for the group's root to certify when it
	// makes the member an admin.
	AdminKey []byte `json:"admin_key,omitempty"`
	// PhoneCA is the SHA-256 of the SubjectPublicKeyInfo of the iPhone CA
	// whose key this member holds, so another admin knows whether to send
	// it a newer one.
	PhoneCA []byte `json:"phone_ca,omitempty"`
	// TunnelKey is this member's WireGuard public key, for the group's hub.
	TunnelKey []byte `json:"tunnel_key,omitempty"`
	// TunnelPSK is this member's own preshared key, for every hub.
	TunnelPSK []byte `json:"tunnel_psk,omitempty"`
	// Mode is this member's sync mode (clip.Mode), for the others to show.
	Mode string `json:"mode,omitempty"`
	// KeyStore is where this member's keys live, for the root that makes
	// it an admin.
	KeyStore string `json:"key_store,omitempty"`
	// Actions are this member's quick actions that are on, for the
	// admins' buttons.
	Actions []string `json:"actions,omitempty"`
	// Features are what this member supports beyond the protocol of its
	// ALPN version.
	Features []string `json:"features,omitempty"`
	// GroupCA is the group's first root, DER, which a full member sends
	// on a records-only connection with a device no record names yet, as a
	// new phone restoring the group with the recovery key: so it builds
	// the group's path from the records (docs/protocol.md, section 10,
	// "The recovery key").
	GroupCA []byte `json:"group_ca,omitempty"`
	// Seal is this member's public key for sealed messages, for the root
	// or an admin to put in its device record.
	Seal []byte `json:"seal,omitempty"`
	// ReleaseSeq is the seq of the channel file of the signed release
	// this member holds, and ReleaseKeys that of its keys.json, so that a
	// peer sends only a newer one.
	ReleaseSeq  uint64 `json:"release_seq,omitempty"`
	ReleaseKeys uint64 `json:"release_keys_seq,omitempty"`
}

// ReleaseOrder is where a signed release stands among others: the seq of
// its keys.json, then that of its channel file.
type ReleaseOrder struct{ Keys, Channel uint64 }

// After reports whether o is newer than p.
func (o ReleaseOrder) After(p ReleaseOrder) bool {
	return o.Keys > p.Keys || o.Keys == p.Keys && o.Channel > p.Channel
}

// ReleaseSet is a signed release as members pass it to each other: the
// files a device fetches to look for an update (docs/protocol.md, section
// 16), each still in its signed envelope.
type ReleaseSet struct {
	Keys    signed.File `json:"keys"`
	Channel signed.File `json:"channel"`
	Release signed.File `json:"release"`
}

// recordsChunk bounds the records of one message, well below maxFrame.
const recordsChunk = 1 << 20

// chunkRecords splits records into groups whose encoded size stays near
// recordsChunk, so each fits a frame.
func chunkRecords(rs []group.Record) [][]group.Record {
	var out [][]group.Record
	var cur []group.Record
	size := 0
	for _, r := range rs {
		n := len(r.Body) + len(r.Sig)
		for _, c := range r.Chain {
			n += len(c)
		}
		n = n*4/3 + 64 // base64 and the JSON around it
		if len(cur) > 0 && size+n > recordsChunk {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, r)
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// encode marshals v as JSON without escaping <, > and &, which would make
// texts that contain them up to six times longer.
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// transferTime is how long a frame of n bytes may take, beyond the timeout.
func transferTime(n int) time.Duration { return time.Duration(n/minRate) * time.Second }

// frame encodes a message as a frame.
func frame(m *message) ([]byte, error) {
	data, err := encode(m)
	if err != nil {
		return nil, err
	}
	if len(data) > maxFrame {
		return nil, errors.New("node: message too large")
	}
	return append(binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(data)), uint32(len(data))), data...), nil
}

// deadliner is the part of a connection readMessage needs to give a large
// frame more time once its length is known.
type deadliner interface {
	io.Reader
	SetReadDeadline(time.Time) error
}

// readMessage reads one frame. The caller sets the deadline for its
// start; once the length is known, the deadline grows with it.
func readMessage(r deadliner, timeout time.Duration) (*message, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	bin := size&binaryFrame != 0
	size &^= binaryFrame
	if size > maxFrame || bin && size > maxChunkFrame {
		return nil, fmt.Errorf("node: a frame of %d bytes is too large", size)
	}
	r.SetReadDeadline(time.Now().Add(timeout + transferTime(int(size))))
	// Read the body as it arrives, rather than allocating what the length
	// promises before a byte of it came.
	data, err := io.ReadAll(io.LimitReader(r, int64(size)))
	if err != nil {
		return nil, err
	}
	if len(data) != int(size) {
		return nil, io.ErrUnexpectedEOF
	}
	if bin {
		ch, err := decodeChunk(data)
		if err != nil {
			return nil, err
		}
		return &message{Type: typeChunk, chunk: &ch}, nil
	}
	return decodeMessage(data)
}

// decodeMessage decodes the JSON of a frame. A number that is not an
// integer as in a signed body makes it no message, wherever it is.
func decodeMessage(data []byte) (*message, error) {
	var m message
	if jsonnum.IntegersOnly(data) != nil || json.Unmarshal(data, &m) != nil {
		return nil, errors.New("node: a frame is not a message")
	}
	return &m, nil
}
