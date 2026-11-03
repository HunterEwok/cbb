// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The fleet: full members in containers on the controller itself, each with
// its own network namespace and state, on a Docker network of their own
// (docs/testbench-catalogue.md, section 0.1). Cases that need many devices,
// groups thrown away by the dozen or faults the real devices must not see
// run there. A fleet member is a Device with os "fleet": the bench reaches it
// with docker exec, not SSH, and it runs as root, so cbb needs no sudo.

// fleetImage is the image every fleet member runs: a plain Debian with the
// tools the cases use inside (tc and iptables for network faults, tmux as a
// remote paste target), and the cbb under test mounted from the controller.
const fleetImage = "cbbbench-fleet:2"

const fleetDockerfile = `FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables procps tmux curl ca-certificates && rm -rf /var/lib/apt/lists/*
`

// fleetCoverDir, when set (-coverdir), is where a cbb built with -cover
// writes its coverage from every container of the fleet.
var fleetCoverDir string

// Fleet is one run's containers and their network.
type Fleet struct {
	run, net, cbb string
	members       []*Device
	extra         []string // the run's other networks
	mu            sync.Mutex
	n, nets       int
	// serverEnv is the environment of the forwarders and relays started
	// from then on.
	serverEnv []string
}

// NewFleet makes the run's network; members come with Add. cbb is a static
// Linux binary of the build under test for the controller's CPU.
func NewFleet(ctx context.Context, cbb string) (*Fleet, error) {
	abs, err := filepath.Abs(cbb)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(abs); err != nil || fi.IsDir() {
		return nil, fmt.Errorf("the fleet needs -cbb FILE, a static Linux cbb of the build under test: %v", err)
	}
	if _, err := docker(ctx, "version", "-f", "{{.Server.Version}}"); err != nil {
		return nil, fmt.Errorf("the fleet needs Docker on the controller (tools/bench/setup-controller.sh): %w", err)
	}
	if _, err := docker(ctx, "image", "inspect", fleetImage); err != nil {
		c := exec.CommandContext(ctx, "docker", "build", "-q", "-t", fleetImage, "-")
		c.Stdin = strings.NewReader(fleetDockerfile)
		if out, err := c.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("cannot build the fleet's image: %v: %s", err, out)
		}
	}
	f := &Fleet{run: "cbbfleet-" + runID()[9:], cbb: abs}
	f.net = f.run
	if _, err := docker(ctx, "network", "create", "--label", "cbbbench=fleet", f.net); err != nil {
		return nil, err
	}
	return f, nil
}

// docker runs a docker command on the controller.
func docker(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return string(out), &RunError{Device: "controller", Cmd: "docker " + strings.Join(args, " "), Err: err, Output: string(out)}
	}
	return string(out), nil
}

// Network makes another network of the run, such as one with addresses of
// carrier-grade NAT or only IPv6; args go to docker network create.
func (f *Fleet) Network(ctx context.Context, args ...string) (string, error) {
	f.mu.Lock()
	f.nets++
	name := fmt.Sprintf("%s-net%d", f.run, f.nets)
	f.mu.Unlock()
	_, err := docker(ctx, append(append([]string{"network", "create", "--label", "cbbbench=fleet"}, args...), name)...)
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	f.extra = append(f.extra, name)
	f.mu.Unlock()
	return name, nil
}

// Add starts a new member in no group. env adds variables to the service's
// environment, such as CBB_DEBUG=1.
func (f *Fleet) Add(ctx context.Context, env ...string) (*Device, error) {
	return f.AddOn(ctx, f.net, env...)
}

// AddOn starts a new member in no group on the network net.
func (f *Fleet) AddOn(ctx context.Context, net string, env ...string) (*Device, error) {
	return f.AddWith(ctx, net, nil, env...)
}

// AddWith starts a new member in no group on the network net, with more
// arguments for docker run, such as a small tmpfs for its state.
func (f *Fleet) AddWith(ctx context.Context, net string, run []string, env ...string) (*Device, error) {
	// sh stands in for the service manager: it starts the service again
	// a second after it dies, as systemd's Restart= does.
	d, err := f.container(ctx, net, run, env, "mkdir -p /run/cbb /var/lib/cbb; while :; do cbb service; sleep 1; done")
	if err != nil {
		return nil, err
	}
	if err := eventually(ctx, 20*time.Second, func() error {
		_, err := Run(ctx, d, "cbb status", "")
		return err
	}); err != nil {
		return nil, fmt.Errorf("%s did not start: %w", d.Name, err)
	}
	return d, nil
}

// addServer starts a container on the network net that runs cmd instead
// of the service, such as a forwarder or the stand-in for the internet.
func (f *Fleet) addServer(ctx context.Context, net string, run []string, cmd string) (*Device, error) {
	return f.container(ctx, net, run, f.serverEnv, cmd)
}

// container starts a container of the fleet's image that runs cmd with sh.
func (f *Fleet) container(ctx context.Context, net string, run, env []string, cmd string) (*Device, error) {
	return f.containerOf(ctx, f.cbb, net, run, env, cmd)
}

// containerOf is container with bin, not the fleet's cbb, as its cbb.
func (f *Fleet) containerOf(ctx context.Context, bin, net string, run, env []string, cmd string) (*Device, error) {
	f.mu.Lock()
	f.n++
	n := f.n
	f.mu.Unlock()
	name := fmt.Sprintf("%s-%02d", f.run, n)
	args := []string{"run", "-d", "--name", name, "--hostname", fmt.Sprintf("m%02d", n),
		"--network", net, "--label", "cbbbench=fleet",
		"--cap-add", "NET_ADMIN",
		"-v", bin + ":/usr/local/bin/cbb:ro"}
	if fleetCoverDir != "" {
		args = append(args, "-v", fleetCoverDir+":/cover", "-e", "GOCOVERDIR=/cover")
	}
	args = append(args, run...)
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, fleetImage, "sh", "-c", cmd)
	if _, err := docker(ctx, args...); err != nil {
		return nil, err
	}
	d := &Device{Name: fmt.Sprintf("m%02d", n), OS: "fleet", Clipboard: "none", Container: name, Roles: []string{"member"}, Network: net}
	f.mu.Lock()
	f.members = append(f.members, d)
	f.mu.Unlock()
	return d, nil
}

// AddN starts n members at once.
func (f *Fleet) AddN(ctx context.Context, n int, env ...string) ([]*Device, error) {
	out := make([]*Device, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i], errs[i] = f.Add(ctx, env...)
		}()
	}
	wg.Wait()
	return out, errors.Join(errs...)
}

// Close removes the run's containers and network.
func (f *Fleet) Close(ctx context.Context) {
	ctx = context.WithoutCancel(ctx)
	f.mu.Lock()
	ms := f.members
	f.mu.Unlock()
	if len(ms) > 0 && fleetCoverDir != "" {
		// A program built with -cover writes its counters when it exits:
		// let the services end before their containers go.
		var wg sync.WaitGroup
		for _, d := range ms {
			wg.Add(1)
			go func() {
				defer wg.Done()
				docker(ctx, "exec", d.Container, "sh", "-c", "pkill -TERM -x cbb; sleep 2")
			}()
		}
		wg.Wait()
	}
	if len(ms) > 0 {
		args := []string{"rm", "-f", "-v"}
		for _, d := range ms {
			args = append(args, d.Container)
		}
		docker(ctx, args...)
	}
	docker(ctx, append([]string{"network", "rm", f.net}, f.extra...)...)
}

// cleanFleet removes what an earlier run left behind, as when the
// controller lost its power during a run.
func cleanFleet(ctx context.Context) {
	if out, err := docker(ctx, "ps", "-aq", "--filter", "label=cbbbench=fleet"); err == nil && strings.TrimSpace(out) != "" {
		docker(ctx, append([]string{"rm", "-f", "-v"}, strings.Fields(out)...)...)
	}
	if out, err := docker(ctx, "network", "ls", "-q", "--filter", "label=cbbbench=fleet"); err == nil && strings.TrimSpace(out) != "" {
		docker(ctx, append([]string{"network", "rm"}, strings.Fields(out)...)...)
	}
}

// stop and start a member's container, as a power cut and its return;
// pause and unpause freeze it whole.
func (f *Fleet) stop(ctx context.Context, d *Device) error {
	_, err := docker(ctx, "stop", "-t", "0", d.Container)
	return err
}

func (f *Fleet) start(ctx context.Context, d *Device) error {
	if _, err := docker(ctx, "start", d.Container); err != nil {
		return err
	}
	return eventually(ctx, 20*time.Second, func() error {
		_, err := Run(ctx, d, "cbb status", "")
		return err
	})
}

// cut drops every packet between a and b both ways; heal takes it back.
func cut(ctx context.Context, a, b *Device) error {
	ab, err := fleetIP(ctx, b)
	if err != nil {
		return err
	}
	ba, err := fleetIP(ctx, a)
	if err != nil {
		return err
	}
	if _, err := Run(ctx, a, "iptables -I INPUT -s "+ab+" -j DROP && iptables -I OUTPUT -d "+ab+" -j DROP", ""); err != nil {
		return err
	}
	_, err = Run(ctx, b, "iptables -I INPUT -s "+ba+" -j DROP && iptables -I OUTPUT -d "+ba+" -j DROP", "")
	return err
}

func heal(ctx context.Context, ds ...*Device) error {
	var errs []error
	for _, d := range ds {
		_, err := Run(context.WithoutCancel(ctx), d, "iptables -F INPUT && iptables -F OUTPUT", "")
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// fleetIP is a member's address on the network it started on, its IPv6
// address on a network with no IPv4.
func fleetIP(ctx context.Context, d *Device) (string, error) {
	return fleetIPOn(ctx, d, d.Network)
}

// fleetIPOn is a member's address on the network net.
func fleetIPOn(ctx context.Context, d *Device, net string) (string, error) {
	at := fmt.Sprintf("{{with index .NetworkSettings.Networks %q}}", net)
	out, err := docker(ctx, "inspect", "-f", at+"{{.IPAddress}}{{end}}", d.Container)
	ip := strings.TrimSpace(out)
	if err == nil && ip == "" {
		out, err = docker(ctx, "inspect", "-f", at+"{{.GlobalIPv6Address}}{{end}}", d.Container)
		ip = strings.TrimSpace(out)
	}
	if err == nil && ip == "" {
		err = fmt.Errorf("%s has no address", d.Name)
	}
	return ip, err
}

// fleetKill kills a member's service as a crash would; its stand-in
// service manager starts it again.
const fleetKill = `for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = cbb ] && tr '\0' ' ' <$p/cmdline | grep -q 'cbb service' && kill -KILL ${p#/proc/}; done; true`
