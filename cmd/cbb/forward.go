// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/HunterEwok/cbb/internal/forward"
)

// cmdForward runs a forwarder: a server that holds no keys and passes the
// encrypted WireGuard packets of hubs that their clients cannot reach
// directly (docs/design.md, "The forwarder"). It runs in the foreground, for
// systemd or a terminal.
func cmdForward(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("forward", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8764", "the address to listen on, UDP and TCP")
	keyFile := fs.String("key", defaultForwarderKey(), "the forwarder's key, made on the first run")
	showKey := fs.Bool("show-key", false, "print the key for cbb global hub -forwarder-key and stop")
	vlessSite := fs.String("vless-site", "", "take VLESS with REALITY too, borrowing the TLS of this well-known site, such as www.example.com")
	vlessXHTTP := fs.String("vless-xhttp", "", "take VLESS over XHTTP too, behind the web server of this site, such as cbb.tools, which passes -vless-path to -vless-listen")
	vlessPath := fs.String("vless-path", "", "with -vless-xhttp, the path the web server passes (default: made once and kept in the key file)")
	vlessPort := fs.Uint("vless-port", 443, "with -vless-xhttp, the web server's TCP port at the forwarder's address")
	vlessListen := fs.String("vless-listen", "", "the TCP address to listen on for VLESS (default :443 with -vless-site, 127.0.0.1:3276 with -vless-xhttp)")
	state := fs.String("state", "", "the file that keeps, under a hash of each group's tag, the version of its newest credential (default: forward-state.json next to the key; \"none\" keeps them in memory only)")
	records := fs.String("records", "", "where earlier versions kept a file for each group; they are deleted (default: groups next to the key)")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "cbb: forward takes only flags")
		return 2
	}
	cert, err := forward.LoadCert(*keyFile)
	if err != nil {
		return fail(stderr, err)
	}
	pin := forward.Pin(cert.Leaf)
	if *showKey {
		fmt.Fprintln(stdout, pin)
		return 0
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	cfg := forward.Config{Listen: *listen, Cert: cert, Logf: logf}
	switch *state {
	case "none":
	case "":
		cfg.StateFile = filepath.Join(filepath.Dir(*keyFile), "forward-state.json")
	default:
		cfg.StateFile = *state
	}
	old := *records
	if old == "" || old == "none" {
		old = filepath.Join(filepath.Dir(*keyFile), "groups")
	}
	if n, err := forward.RemoveGroupFiles(old); err != nil {
		logf("cbb forward: deleting the group files of earlier versions: %v", err)
	} else if n > 0 {
		logf("cbb forward: deleted the %d group files that earlier versions kept", n)
	}
	switch {
	case *vlessSite != "" && *vlessXHTTP != "":
		fmt.Fprintln(stderr, "cbb: forward takes -vless-site or -vless-xhttp, not both")
		return 2
	case *vlessSite != "":
		key, err := forward.LoadRealityKey(*keyFile)
		if err != nil {
			return fail(stderr, err)
		}
		if *vlessListen == "" {
			*vlessListen = ":443"
		}
		cfg.VLESS = &forward.VLESSConfig{Listen: *vlessListen, Site: *vlessSite, Key: key}
	case *vlessXHTTP != "":
		if *vlessPort == 0 || *vlessPort > 65535 {
			fmt.Fprintln(stderr, "cbb: forward: -vless-port is not a TCP port")
			return 2
		}
		path := *vlessPath
		if path == "" {
			if path, err = forward.LoadXHTTPPath(*keyFile); err != nil {
				return fail(stderr, err)
			}
		}
		if *vlessListen == "" {
			*vlessListen = "127.0.0.1:3276"
		}
		cfg.VLESS = &forward.VLESSConfig{Listen: *vlessListen, XHTTP: &forward.XHTTPConfig{Host: *vlessXHTTP, Port: uint16(*vlessPort), Path: path}}
	}
	f, err := forward.Listen(cfg)
	if err != nil {
		return fail(stderr, err)
	}
	logf("cbb forward: listening on UDP and TCP port %d; its key, for cbb global hub -forwarder-key: %s", f.Addr().Port(), pin)
	if v := cfg.VLESS; v != nil && v.XHTTP != nil {
		logf("cbb forward: VLESS over XHTTP on %s, behind the web server of %s on TCP port %d, which passes the path %s to it; hubs ask for it with cbb global hub -vless", *vlessListen, v.XHTTP.Host, v.XHTTP.Port, v.XHTTP.Path)
	} else if v != nil {
		logf("cbb forward: VLESS on TCP %s, with the TLS of %s; hubs ask for it with cbb global hub -vless", *vlessListen, *vlessSite)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if os.Getenv("CBB_DEBUG") == "1" {
		// Counts only: the forwarder logs nothing about a group or a device.
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					st := f.Stats()
					logf("cbb forward: %d hubs, %d sessions, %d handshakes waiting", st.Groups, st.Sessions, st.Waiting)
				}
			}
		}()
	}
	if err := f.Serve(ctx); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// defaultForwarderKey is where the forwarder keeps its key: in systemd's
// state directory for it, or next to the service's state.
func defaultForwarderKey() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return filepath.Join(d, "forwarder.pem")
	}
	return filepath.Join(defaultStateDir(), "forwarder.pem")
}
