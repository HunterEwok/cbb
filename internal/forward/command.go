// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/HunterEwok/cbb/internal/refused"
)

// Command runs a forwarder: a server that holds no keys and passes the
// encrypted WireGuard packets of hubs that their clients cannot reach
// directly (docs/design.md, "The forwarder"). It runs in the foreground, for
// systemd or a terminal; defaultKey is where -key points unless it is given.
func Command(args []string, stdout, stderr io.Writer, defaultKey string) int {
	fs := flag.NewFlagSet("forward", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8764", "the address to listen on, UDP and TCP")
	keyFile := fs.String("key", defaultKey, "the forwarder's key, made on the first run")
	showKey := fs.Bool("show-key", false, "print the key for cbb global hub -forwarder-key and stop")
	vlessXHTTP := fs.String("vless-xhttp", "", "take VLESS over XHTTP too, behind the web server of this site, such as cbb.tools, which passes -vless-path to -vless-listen")
	vlessPath := fs.String("vless-path", "", "with -vless-xhttp, the path the web server passes (default: made once and kept in the key file)")
	vlessPort := fs.Uint("vless-port", 443, "with -vless-xhttp, the web server's TCP port at the forwarder's address")
	vlessMirror := fs.String("vless-mirror", "", "with VLESS, the TCP address of the mirror of the releases on this server, such as 127.0.0.1:443, which the clients of registered hubs reach over VLESS for their updates")
	vlessListen := fs.String("vless-listen", "127.0.0.1:3276", "with -vless-xhttp, the TCP address to listen on for the web server in front")
	state := fs.String("state", "", "the file that keeps, under a hash of each group's tag, the version of its newest credential (default: forward-state.json next to the key; \"none\" keeps them in memory only)")
	refusedFile := fs.String("refused", "", "the list of groups refused after an abuse report, a tag a line, read again when it changes (default: refused-groups next to the key; \"none\" refuses none)")
	records := fs.String("records", "", "where earlier versions kept a file for each group; they are deleted (default: groups next to the key)")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "cbb: forward takes only flags")
		return 2
	}
	cert, err := LoadCert(*keyFile)
	if err != nil {
		return fail(stderr, err)
	}
	pin := Pin(cert.Leaf)
	if *showKey {
		fmt.Fprintln(stdout, pin)
		return 0
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	cfg := Config{Listen: *listen, Cert: cert, Logf: logf}
	if cfg.Refused, err = refused.Open(*refusedFile, *keyFile); err != nil {
		return fail(stderr, err)
	}
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
	if n, err := RemoveGroupFiles(old); err != nil {
		logf("cbb forward: deleting the group files of earlier versions: %v", err)
	} else if n > 0 {
		logf("cbb forward: deleted the %d group files that earlier versions kept", n)
	}
	if *vlessXHTTP != "" {
		if *vlessPort == 0 || *vlessPort > 65535 {
			fmt.Fprintln(stderr, "cbb: forward: -vless-port is not a TCP port")
			return 2
		}
		path := *vlessPath
		if path == "" {
			if path, err = LoadXHTTPPath(*keyFile); err != nil {
				return fail(stderr, err)
			}
		}
		cfg.VLESS = &VLESSConfig{Listen: *vlessListen, XHTTP: &XHTTPConfig{Host: *vlessXHTTP, Port: uint16(*vlessPort), Path: path}}
	}
	if *vlessMirror != "" {
		if cfg.VLESS == nil {
			fmt.Fprintln(stderr, "cbb: forward: -vless-mirror goes with -vless-xhttp")
			return 2
		}
		if _, _, err := net.SplitHostPort(*vlessMirror); err != nil {
			fmt.Fprintln(stderr, "cbb: forward: -vless-mirror is host:port")
			return 2
		}
		cfg.VLESS.Mirror = *vlessMirror
	}
	f, err := Listen(cfg)
	if err != nil {
		return fail(stderr, err)
	}
	logf("cbb forward: listening on UDP and TCP port %d; its key, for cbb global hub -forwarder-key: %s", f.Addr().Port(), pin)
	if v := cfg.VLESS; v != nil {
		logf("cbb forward: VLESS over XHTTP on %s, behind the web server of %s on TCP port %d, which passes the path %s to it; hubs ask for it with cbb global hub -vless", *vlessListen, v.XHTTP.Host, v.XHTTP.Port, v.XHTTP.Path)
	}
	if *vlessMirror != "" {
		logf("cbb forward: the clients of registered hubs reach the mirror at %s over VLESS", *vlessMirror)
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

// fail prints err after the program's name and returns the exit code 1.
func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "cbb:", err)
	return 1
}
