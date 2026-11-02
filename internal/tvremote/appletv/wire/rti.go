// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package wire

import (
	"errors"
	"fmt"
)

// The text field: "_tiStart" answers with the field's state in "_tiD", an
// archive of NSKeyedArchiver whose "sessionUUID" names the field's input
// session, and the remote types with a "_tiC" event that carries an
// RTITextOperations archive for that session. A field opens a new session,
// so the remote asks for it again before each text.

// ErrArchive is an archive without what the remote needs.
var ErrArchive = errors.New("the text field's archive is not as expected")

// classOf is an archive's class entry.
func classOf(name string) map[string]any {
	return map[string]any{"$classname": name, "$classes": []any{name, "NSObject"}}
}

// TextArchive is the "_tiD" of a "_tiC" event that types text into the
// field of the input session; text "" with clear set clears the field.
func TextArchive(session []byte, text string, clear bool) ([]byte, error) {
	if len(session) != 16 {
		return nil, fmt.Errorf("%w: an input session of %d bytes", ErrArchive, len(session))
	}
	ops := map[string]any{
		"$class":            UID(6),
		"keyboardOutput":    UID(2),
		"targetSessionUUID": UID(4),
	}
	output := map[string]any{"$class": UID(3)}
	if clear {
		ops["textToAssert"] = UID(7)
	} else {
		output["insertionText"] = UID(7)
	}
	objects := []any{
		"$null",
		ops,
		output,
		classOf("TIKeyboardOutput"),
		map[string]any{"NS.uuidbytes": session, "$class": UID(5)},
		classOf("NSUUID"),
		classOf("RTITextOperations"),
		text,
	}
	return EncodePlist(map[string]any{
		"$version":  int64(100000),
		"$archiver": "RTIKeyedArchiver",
		"$top":      map[string]any{"textOperations": UID(1)},
		"$objects":  objects,
	})
}

// archive reads an archive's top and objects.
func archive(b []byte) (top map[string]any, objects []any, err error) {
	v, err := DecodePlist(b)
	if err != nil {
		return nil, nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("%w: not a dictionary", ErrArchive)
	}
	top, ok1 := m["$top"].(map[string]any)
	objects, ok2 := m["$objects"].([]any)
	if !ok1 || !ok2 {
		return nil, nil, fmt.Errorf("%w: no $top or $objects", ErrArchive)
	}
	return top, objects, nil
}

// follow walks keys from the top, through the UIDs into the objects.
func follow(top map[string]any, objects []any, keys ...string) (any, bool) {
	var e any = top
	for _, k := range keys {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		e, ok = m[k]
		if !ok {
			return nil, false
		}
		if u, ok := e.(UID); ok {
			if uint64(u) >= uint64(len(objects)) {
				return nil, false
			}
			e = objects[u]
		}
	}
	return e, true
}

// InputSession reads the input session from a "_tiStart" answer's "_tiD".
func InputSession(b []byte) ([]byte, error) {
	top, objects, err := archive(b)
	if err != nil {
		return nil, err
	}
	v, _ := follow(top, objects, "sessionUUID")
	if m, ok := v.(map[string]any); ok { // an NSUUID object
		v = m["NS.uuidbytes"]
	}
	s, ok := v.([]byte)
	if !ok || len(s) != 16 {
		return nil, fmt.Errorf("%w: no sessionUUID", ErrArchive)
	}
	return s, nil
}

// TextOperation reads a "_tiC" event's "_tiD": the input session, and the
// text typed or, with clear, that the field is cleared. The fake TV of the
// tests reads it.
func TextOperation(b []byte) (session []byte, text string, clear bool, err error) {
	top, objects, err := archive(b)
	if err != nil {
		return nil, "", false, err
	}
	v, _ := follow(top, objects, "textOperations", "targetSessionUUID", "NS.uuidbytes")
	session, ok := v.([]byte)
	if !ok || len(session) != 16 {
		return nil, "", false, fmt.Errorf("%w: no targetSessionUUID", ErrArchive)
	}
	if _, ok := follow(top, objects, "textOperations", "textToAssert"); ok {
		return session, "", true, nil
	}
	v, _ = follow(top, objects, "textOperations", "keyboardOutput", "insertionText")
	text, ok = v.(string)
	if !ok {
		return nil, "", false, fmt.Errorf("%w: no insertionText", ErrArchive)
	}
	return session, text, false, nil
}

// SessionArchive is a "_tiD" of a "_tiStart" answer with the input
// session, for the fake TV of the tests.
func SessionArchive(session []byte) ([]byte, error) {
	return EncodePlist(map[string]any{
		"$version":  int64(100000),
		"$archiver": "RTIKeyedArchiver",
		"$top":      map[string]any{"sessionUUID": UID(1), "documentState": UID(2)},
		"$objects":  []any{"$null", session, map[string]any{}},
	})
}
