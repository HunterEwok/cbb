// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"encoding/binary"

	"golang.org/x/crypto/chacha20"

	"github.com/HunterEwok/cbb/internal/tunnel"
)

// An obfuscated group's packets (docs/design.md, "Blocked networks") start
// with random padding, the first 12 bytes of which are the nonce of the
// header protection: ChaCha20 under the group's header key, whose key
// stream is XORed over the message after the padding, all of a handshake
// message and the 16-byte header of a data message. The message type is
// then a value from the group's range for that type instead of WireGuard's
// 1 to 4. The forwarder takes the protection off a copy to read the type,
// the indices and mac1, as the hub does, and passes the packet on as it
// came: the protection is the group's own, end to end.

// headerNonceSize is the length of the header protection's nonce.
const headerNonceSize = 12

// dataHeaderSize is the part of a data message under the protection: its
// type, the receiver's index and the counter.
const dataHeaderSize = 16

// open reads the packet p of a group with the settings o, nil for plain
// WireGuard. It returns the WireGuard message type and the message without
// padding or protection, in buf for an obfuscated group, as much of it as
// the forwarder looks at; or 0 when p is none of the group's messages.
func open(o *tunnel.Obfuscation, p []byte, buf *[initiationSize]byte) (byte, []byte) {
	if o == nil {
		return messageType(p), p
	}
	if len(p) < headerNonceSize {
		return 0, nil
	}
	c, err := chacha20.NewUnauthenticatedCipher(o.HeaderKey[:], p[:headerNonceSize])
	if err != nil {
		return 0, nil
	}
	var stream [initiationSize]byte
	c.XORKeyStream(stream[:], stream[:])
	kinds := []struct {
		t       byte
		padding int
		size    int // the size of the message without padding; data may be longer
		types   tunnel.Range
	}{
		{msgInitiation, o.S1, initiationSize, o.H1},
		{msgResponse, o.S2, responseSize, o.H2},
		{msgCookie, o.S3, cookieSize, o.H3},
		{msgData, o.S4, dataMinSize, o.H4},
	}
	for _, k := range kinds {
		if len(p) != k.padding+k.size && (k.t != msgData || len(p) < k.padding+k.size) {
			continue
		}
		m := p[k.padding:]
		if !k.types.Contains(binary.LittleEndian.Uint32(m[:4]) ^ binary.LittleEndian.Uint32(stream[:4])) {
			continue
		}
		n := k.size
		if k.t == msgData {
			n = dataHeaderSize
		}
		for i := range n {
			buf[i] = m[i] ^ stream[i]
		}
		return k.t, buf[:n]
	}
	return 0, nil
}

// initSize is the size of an obfuscated group's handshake initiation.
func initSize(o *tunnel.Obfuscation) int { return o.S1 + initiationSize }
