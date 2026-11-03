// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/HunterEwok/cbb/internal/service"
)

// AppJoin is what cbb pair -app writes for the desktop app that started it:
// the QR code's text, how long the wait lasts, and the member port a
// firewall must let the phone reach.
type AppJoin struct {
	QR      string `json:"qr"`
	Expires int    `json:"expires"`
	Port    int    `json:"port"`
}

// appFilePoll is how often cbb pair -app looks whether the app still wants
// the join.
var appFilePoll = time.Second

// joinForApp joins by the phone's QR code for a desktop app, which runs cbb
// as the administrator and so sees what it prints only once it ends: the
// code's text goes into the file the app made, and the app removes the file
// to cancel. The file must exist already and be a regular file, so that cbb,
// which runs as the administrator, only ever writes over the app's own.
func joinForApp(path string, stdout, stderr io.Writer) int {
	fi, err := os.Lstat(path)
	if err != nil {
		return fail(stderr, err)
	}
	if !fi.Mode().IsRegular() {
		return fail(stderr, fmt.Errorf("%s is not a regular file", path))
	}
	c, text, expires, err := listenForPhone()
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	port, err := service.Port()
	if err != nil {
		port = service.MemberPort
	}
	data, err := json.Marshal(AppJoin{QR: text, Expires: expires, Port: port})
	if err != nil {
		return fail(stderr, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fail(stderr, err)
	}
	_, err = f.Write(append(data, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fail(stderr, err)
	}

	ended := make(chan error, 1)
	go func() {
		_, err := c.Receive()
		ended <- err
	}()
	tick := time.NewTicker(appFilePoll)
	defer tick.Stop()
	for {
		select {
		case err := <-ended:
			if err != nil {
				return fail(stderr, err)
			}
			fmt.Fprintln(stdout, "Joined the group.")
			return 0
		case <-tick.C:
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				// The app closed its window: hanging up ends the wait.
				fmt.Fprintln(stderr, "cbb: cancelled")
				return 1
			}
		}
	}
}
