// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// buildForge builds tools/bench/forge, a static Linux program the
// containers run, from the source the bench runs from (go run ./tools/bench
// at the repository's top).
func buildForge(ctx context.Context, dir string) (string, error) {
	if _, err := os.Stat(filepath.Join("tools", "bench", "forge", "main.go")); err != nil {
		return "", fmt.Errorf("run the bench at the repository's top, where tools/bench/forge is: %v", err)
	}
	out := filepath.Join(dir, "forge")
	c := exec.CommandContext(ctx, "go", "build", "-o", out, "./tools/bench/forge")
	c.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	if b, err := c.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build ./tools/bench/forge: %v: %s", err, b)
	}
	return out, nil
}

// forgeHost starts a container that runs tools/bench/forge as the member
// m, with the state of m and of each signer under /tmp/NAME; m itself goes
// off, so that only the copy connects as it.
func forgeHost(ctx context.Context, f *Fleet, m *Device, signers ...*Device) (*Device, error) {
	return forgeHostOn(ctx, f, f.net, m, signers...)
}

// forgeDeviceFile is where forgeHost leaves a copied state's device ID,
// which forge reads (tools/bench/forge/tunnel.go).
const forgeDeviceFile = "bench-device-id"

// forgeHostOn is forgeHost with the container on the network net.
func forgeHostOn(ctx context.Context, f *Fleet, net string, m *Device, signers ...*Device) (*Device, error) {
	dir, err := os.MkdirTemp("", "cbbfleet-forge")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	bin, err := buildForge(ctx, dir)
	if err != nil {
		return nil, err
	}
	h, err := f.AddOn(ctx, net)
	if err != nil {
		return nil, err
	}
	for _, d := range append([]*Device{m}, signers...) {
		sd := filepath.Join(dir, d.Name)
		if err := os.Mkdir(sd, 0o700); err != nil {
			return nil, err
		}
		if _, err := docker(ctx, "cp", d.Container+":/var/lib/cbb/.", sd); err != nil {
			return nil, err
		}
		// The forge's tunnel cases need the device ID, which the copied
		// state keeps sealed.
		id, err := deviceOf(ctx, d)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(sd, forgeDeviceFile), []byte(id), 0o600); err != nil {
			return nil, err
		}
		if _, err := docker(ctx, "cp", sd, h.Container+":/tmp/"+d.Name); err != nil {
			return nil, err
		}
	}
	if err := f.stop(ctx, m); err != nil {
		return nil, err
	}
	if _, err := docker(ctx, "cp", bin, h.Container+":/usr/local/bin/cbbbench-forge"); err != nil {
		return nil, err
	}
	return h, nil
}

// forgeServer starts a container on the network net that runs forge with
// args, such as the stand-in for a well-known site.
func forgeServer(ctx context.Context, f *Fleet, net, args string) (*Device, error) {
	dir, err := os.MkdirTemp("", "cbbfleet-forge")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	bin, err := buildForge(ctx, dir)
	if err != nil {
		return nil, err
	}
	d, err := f.addServer(ctx, net, nil, "while [ ! -x /usr/local/bin/cbbbench-forge ]; do sleep 0.2; done; exec cbbbench-forge "+args)
	if err != nil {
		return nil, err
	}
	_, err = docker(ctx, "cp", bin, d.Container+":/usr/local/bin/cbbbench-forge")
	return d, err
}

// forgeOn copies forge into the member d and returns its name there.
func forgeOn(ctx context.Context, d *Device) (string, error) {
	dir, err := os.MkdirTemp("", "cbbfleet-forge")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	bin, err := buildForge(ctx, dir)
	if err != nil {
		return "", err
	}
	_, err = docker(ctx, "cp", bin, d.Container+":/usr/local/bin/cbbbench-forge")
	return "cbbbench-forge", err
}
