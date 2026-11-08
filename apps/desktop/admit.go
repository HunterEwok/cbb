// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"strings"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"

	"github.com/HunterEwok/cbb/internal/phone"
)

// Admitting a new device that shows a code and waits: on the root or an
// admin, the user types the six digits it shows, pastes its QR code's text
// or opens a picture of it, and cbb pair -qr runs as the administrator with
// the code on its standard input, never on its command line.

// maxImage bounds the picture ReadQR decodes.
const maxImage = 16 << 20

// ReadQR reads the QR code in a picture (PNG or JPEG, base64) and returns
// its text when it is a code of a device that waits to join.
func (d *Desk) ReadQR(b64 string) (string, error) {
	if len(b64) > maxImage*4/3+4 {
		return "", errors.New(d.T("The picture is too large."))
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", errors.New(d.T("This file is no picture."))
	}
	text, err := readQR(data)
	if err != nil {
		return "", errors.New(d.T(err.Error()))
	}
	return text, nil
}

func readQR(data []byte) (string, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", errors.New("This file is no picture.")
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", errors.New("No QR code was found in the picture.")
	}
	hints := map[gozxing.DecodeHintType]any{gozxing.DecodeHintType_TRY_HARDER: true}
	res, err := qrcode.NewQRCodeReader().Decode(bmp, hints)
	if err != nil {
		return "", errors.New("No QR code was found in the picture.")
	}
	text := strings.TrimSpace(res.GetText())
	if !waitingJoiner(text) {
		return "", errors.New("This QR code is not of a device that waits to join.")
	}
	return text, nil
}

// waitingJoiner tells whether text is the QR code of a device that listens
// for the member that admits it: an address and a fingerprint.
func waitingJoiner(text string) bool {
	jc, ok := phone.ParseJoinQR(text)
	return ok && len(jc.Addrs) > 0 && jc.Fingerprint != ""
}

// shownCode is the six digits a new device shows, as typed: spaces and
// dashes between them are fine; "" when text is not such a code.
func shownCode(text string) string {
	digits := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r == ' ' || r == '-':
			return -1
		}
		return 'x'
	}, text)
	if len(digits) != 6 || strings.Contains(digits, "x") {
		return ""
	}
	return digits
}

// Admit admits the new device that shows text and waits: the six digits it
// shows, typed here, or its QR code's text; cbb pair -qr does it as the
// administrator, finding the device by its code on the home network. With
// admin, on the group's root, a phone that asks to be an admin becomes one
// (cbb pair -qr -admin).
func (d *Desk) Admit(text string, admin bool) {
	text = strings.TrimSpace(text)
	if code := shownCode(text); code != "" {
		text = code
	} else if !waitingJoiner(text) {
		msg := d.T("Type the six digits the new device shows.") // T takes d.mu
		d.mu.Lock()
		d.message = msg
		d.mu.Unlock()
		return
	}
	args := []string{"pair", "-qr"}
	if admin {
		args = append(args, "-admin")
	}
	d.adminWith(args, text+"\n", "It joined the group.")
}
