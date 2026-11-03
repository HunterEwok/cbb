// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package strict reads the strict form of signed bodies, which every
// implementation reads alike (docs/protocol.md, Conventions, "Signed
// bodies"): records, commands, server credentials and the files of a
// release.
package strict

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/HunterEwok/cbb/internal/jsonnum"
)

// maxStrictDepth bounds how deeply a signed body nests arrays and objects.
const maxStrictDepth = 16

// Check checks that b is a signed body in the strict form every
// member reads alike (docs/protocol.md, Conventions, "Signed bodies"): one
// JSON object in valid UTF-8; member names of 1 to 64 of a-z, 0-9 and _,
// without escapes, none twice in one object; no null; integers only,
// without fraction or exponent, in the range of int64; a surrogate escape
// only as one half of a pair. Each name in required must be a member of
// the object.
func Check(b []byte, required ...string) error {
	if !utf8.Valid(b) {
		return errors.New("a signed body is not valid UTF-8")
	}
	p := strictParser{b: b}
	p.space()
	if p.i >= len(b) || b[p.i] != '{' {
		return errors.New("a signed body is not a JSON object")
	}
	names, err := p.object(0)
	if err != nil {
		return fmt.Errorf("a signed body: %w", err)
	}
	p.space()
	if p.i != len(b) {
		return errors.New("a signed body has more after its object")
	}
	for _, n := range required {
		if !names[n] {
			return fmt.Errorf("a signed body has no %s", n)
		}
	}
	return nil
}

type strictParser struct {
	b []byte
	i int
}

func (p *strictParser) space() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *strictParser) value(depth int) error {
	p.space()
	if p.i >= len(p.b) {
		return errors.New("it ends early")
	}
	switch c := p.b[p.i]; {
	case c == '{':
		if depth >= maxStrictDepth {
			return errors.New("it nests too deeply")
		}
		_, err := p.object(depth + 1)
		return err
	case c == '[':
		if depth >= maxStrictDepth {
			return errors.New("it nests too deeply")
		}
		return p.array(depth + 1)
	case c == '"':
		return p.str()
	case c == 't':
		return p.literal("true")
	case c == 'f':
		return p.literal("false")
	case c == 'n':
		return errors.New("it has a null")
	case c == '-' || c >= '0' && c <= '9':
		return p.integer()
	}
	return fmt.Errorf("an unexpected %q", p.b[p.i])
}

// object reads an object at p.i and returns its member names.
func (p *strictParser) object(depth int) (map[string]bool, error) {
	p.i++ // {
	names := map[string]bool{}
	p.space()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return names, nil
	}
	for {
		p.space()
		name, err := p.name()
		if err != nil {
			return nil, err
		}
		if names[name] {
			return nil, fmt.Errorf("the member %s is there twice", name)
		}
		names[name] = true
		p.space()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, errors.New("a member has no value")
		}
		p.i++
		if err := p.value(depth); err != nil {
			return nil, err
		}
		p.space()
		if p.i >= len(p.b) {
			return nil, errors.New("it ends early")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return names, nil
		default:
			return nil, fmt.Errorf("an unexpected %q in an object", p.b[p.i])
		}
	}
}

// name reads a member name: 1 to 64 of a-z, 0-9 and _ in quotes.
func (p *strictParser) name() (string, error) {
	if p.i >= len(p.b) || p.b[p.i] != '"' {
		return "", errors.New("a member has no name")
	}
	start := p.i + 1
	for p.i = start; p.i < len(p.b) && p.b[p.i] != '"'; p.i++ {
		if c := p.b[p.i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return "", errors.New("a member name is not of a-z, 0-9 and _")
		}
	}
	if p.i >= len(p.b) {
		return "", errors.New("it ends early")
	}
	name := string(p.b[start:p.i])
	p.i++
	if name == "" || len(name) > 64 {
		return "", errors.New("a member name is not 1 to 64 characters")
	}
	return name, nil
}

func (p *strictParser) array(depth int) error {
	p.i++ // [
	p.space()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return nil
	}
	for {
		if err := p.value(depth); err != nil {
			return err
		}
		p.space()
		if p.i >= len(p.b) {
			return errors.New("it ends early")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return nil
		default:
			return fmt.Errorf("an unexpected %q in an array", p.b[p.i])
		}
	}
}

func (p *strictParser) str() error {
	p.i++ // "
	for p.i < len(p.b) {
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return nil
		case c < 0x20:
			return errors.New("a string holds a control character")
		case c != '\\':
			p.i++
			continue
		}
		p.i++
		if p.i >= len(p.b) {
			break
		}
		switch p.b[p.i] {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			p.i++
		case 'u':
			r, err := p.hex4()
			if err != nil {
				return err
			}
			switch {
			case utf16.IsSurrogate(r) && r < 0xdc00:
				if p.i+1 >= len(p.b) || p.b[p.i] != '\\' || p.b[p.i+1] != 'u' {
					return errors.New("a string has half a surrogate pair")
				}
				p.i++
				low, err := p.hex4()
				if err != nil {
					return err
				}
				if low < 0xdc00 || low > 0xdfff {
					return errors.New("a string has half a surrogate pair")
				}
			case utf16.IsSurrogate(r):
				return errors.New("a string has half a surrogate pair")
			}
		default:
			return errors.New("a string has an unknown escape")
		}
	}
	return errors.New("it ends early")
}

// hex4 reads the u and four hex digits of a \u escape.
func (p *strictParser) hex4() (rune, error) {
	if p.i+5 > len(p.b) {
		return 0, errors.New("it ends early")
	}
	v, err := strconv.ParseUint(string(p.b[p.i+1:p.i+5]), 16, 16)
	if err != nil {
		return 0, errors.New("a string has a wrong \\u escape")
	}
	p.i += 5
	return rune(v), nil
}

func (p *strictParser) literal(s string) error {
	if p.i+len(s) > len(p.b) || string(p.b[p.i:p.i+len(s)]) != s {
		return errors.New("an unknown literal")
	}
	p.i += len(s)
	return nil
}

// integer reads an integer as jsonnum.Integer does.
func (p *strictParser) integer() error {
	end, err := jsonnum.Integer(p.b, p.i)
	if err != nil {
		return err
	}
	p.i = end
	return nil
}

// EncodeBase64 encodes b as standard base64 with padding, the one form
// DecodeBase64 takes.
func EncodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// DecodeBase64 decodes s, standard base64 with padding, only when s is
// the one encoding of its bytes.
func DecodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("not base64 in its standard form")
	}
	return b, nil
}
