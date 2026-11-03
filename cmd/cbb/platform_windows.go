// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/HunterEwok/cbb/internal/control"
)

// serviceName is the name of the Windows service, as install.ps1 creates it.
const serviceName = "cbb"

// runService runs the service under the service manager, logging to
// ProgramData\cbb\logs\service.log, or in a console until
// Ctrl+C when started by hand.
func runService(stderr io.Writer, run func(context.Context, func(string, ...any)) error) int {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fail(stderr, err)
	}
	if !isService {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
		if err := run(ctx, logf); err != nil {
			return fail(stderr, err)
		}
		return 0
	}
	l, err := openLog(filepath.Join(control.ProgramData(), "cbb", "logs", "service.log"))
	if err != nil {
		return 1 // nowhere to say why; the service manager shows the exit
	}
	defer l.Close()
	h := &handler{run: run, log: l}
	if err := svc.Run(serviceName, h); err != nil {
		return fail(l, err)
	}
	return h.code
}

// handler runs the service for the service manager: it reports it running,
// and stops it on a stop request or at shutdown.
type handler struct {
	run  func(context.Context, func(string, ...any)) error
	log  io.Writer
	code int
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logf := func(format string, args ...any) { fmt.Fprintf(h.log, format+"\n", args...) }
	done := make(chan error, 1)
	go func() { done <- h.run(ctx, logf) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	finish := func(err error) (bool, uint32) {
		if err != nil {
			fail(h.log, err)
			h.code = 1
			return true, 1 // a failure of its own, so the recovery actions restart it
		}
		return false, 0
	}
	for {
		select {
		case err := <-done:
			return finish(err)
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				return finish(<-done)
			}
		}
	}
}

// agentLog returns where the agent logs: its standard error in a console,
// else LocalAppData\cbb\agent.log, since the sign-in starts it
// without one.
func agentLog(stderr io.Writer) (io.Writer, func(), error) {
	if h, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE); err == nil && h != 0 && h != windows.InvalidHandle {
		return stderr, func() {}, nil
	}
	dir, err := os.UserCacheDir() // LocalAppData
	if err != nil {
		return stderr, func() {}, err
	}
	l, err := openLog(filepath.Join(dir, "cbb", "agent.log"))
	if err != nil {
		return stderr, func() {}, err
	}
	return l, func() { l.Close() }, nil
}

// firstAgent reports whether no other agent runs in this session. Its
// mutex stays open until the agent exits, so a second agent sees it and
// leaves.
func firstAgent() bool {
	name, _ := windows.UTF16PtrFromString(`Local\cbb-agent`)
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(h)
		return false
	}
	return true // without a mutex, running twice beats not running
}

func defaultStateDir() string {
	return filepath.Join(control.ProgramData(), "cbb", "state")
}
