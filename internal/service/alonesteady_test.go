// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestAloneSteadyPeers runs three Rust services as the soak does
// (tools/soak/soak.sh): on the loopback address, without mDNS, each given
// the other two with -peer, the group made on the first and the other two
// joined with cbb pair -code ADDRESS while their services run. Each pair
// of members keeps one connection: a member given only an address used to
// dial a connected member every second, and the new connection replaced
// the old one on one side while the other dropped it, so the two
// reconnected without end. The joined members take their service's -name.
func TestAloneSteadyPeers(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	const n = 3
	ports := make([]int, n)
	for i := range ports {
		free, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports[i] = free.Addr().(*net.TCPAddr).Port
		free.Close()
	}
	addr := func(i int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[i])) }
	// The members reach each other through a proxy that counts the
	// connections, which tells whether a member dials one it is connected
	// to.
	proxies := make([]*countingProxy, n)
	for i := range proxies {
		proxies[i] = newCountingProxy(t, addr(i))
	}
	name := func(i int) string { return "steady-" + strconv.Itoa(i+1) }
	members := make([]*testService, n)
	start := func(i int, dir string) {
		args := []string{"-name", name(i), "-port", strconv.Itoa(ports[i]), "-no-mdns"}
		for j := range members {
			if j != i {
				args = append(args, "-peer", proxies[j].addr())
			}
		}
		members[i] = startAlone(t, bin, dir, args...)
	}
	for i := range members {
		start(i, t.TempDir())
	}
	// cbb with the member's state folder and socket, as the soak runs it.
	run := func(i int, stdin string, args ...string) (string, error) {
		m := members[i]
		return runCLI(cli, m.socket, stdin, append([]string{"-state", m.dir, "-socket", m.socket}, args...)...)
	}
	if out, err := run(0, "", "new"); err != nil {
		t.Fatalf("cbb new: %v\n%s", err, out)
	}
	waitFor(t, "the first member in its group", func() bool {
		st, err := members[0].do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && st.Status.Group != ""
	})
	codeLine := regexp.MustCompile(`^Pairing code: (\d{3}) ?(\d{3})$`)
	for i := 1; i < n; i++ {
		window := exec.Command(cli, "-state", members[0].dir, "-socket", members[0].socket, "pair")
		stdout, err := window.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := window.Start(); err != nil {
			t.Fatal(err)
		}
		codes := make(chan string, 1)
		go func() {
			sc := bufio.NewScanner(stdout)
			for sc.Scan() {
				if m := codeLine.FindStringSubmatch(sc.Text()); m != nil {
					codes <- m[1] + m[2]
				}
			}
		}()
		var code string
		select {
		case code = <-codes:
		case <-time.After(20 * time.Second):
			window.Process.Kill()
			t.Fatal("cbb pair showed no code")
		}
		if out, err := run(i, code+"\n", "pair", "-code", addr(0)); err != nil {
			window.Process.Kill()
			window.Wait()
			t.Fatalf("%s: cbb pair -code: %v\n%s", name(i), err, out)
		}
		window.Wait()
	}

	// Restarted in the group, as the soak's kill step does, each member
	// dials the others every second from the start, not after the waits
	// its failed dials before the group grew to.
	for i, m := range members {
		m.stop()
		start(i, m.dir)
	}

	// Every member connects to the other two.
	connected := func(i int) int {
		st, err := members[i].do(t, control.Header{Op: control.OpDevices}, "")
		if err != nil {
			return 0
		}
		up := 0
		for _, d := range st.Devices {
			if d.Online && !d.Self {
				up++
			}
		}
		return up
	}
	for i := range members {
		waitUpTo(t, 30*time.Second, name(i)+" connected to the other two", func() bool { return connected(i) == n-1 })
	}

	// Then the connections settle and stay. A member's first dial that
	// gets through may still replace a connection the other one dialed
	// (its dial loop learns only then which member the address is), once;
	// a member that redialed a connected member every second never
	// settled, so the wait runs out.
	count := func() []int {
		c := make([]int, n)
		for i, m := range members {
			c[i] = len(m.linesWith("cbb: connected to ")) + len(m.linesWith("said goodbye"))
		}
		return c
	}
	quiet := func(d time.Duration) bool {
		before := count()
		time.Sleep(d)
		return slices.Equal(before, count())
	}
	waitUpTo(t, time.Minute, "the connections to settle", func() bool { return quiet(3 * time.Second) })
	before := count()
	dials := make([]int64, n)
	for i, p := range proxies {
		dials[i] = p.count.Load()
	}
	time.Sleep(10 * time.Second)
	after := count()
	for i := range members {
		if got := after[i] - before[i]; got > 0 {
			t.Errorf("%s connected or saw a connection end %d times in 10 s with every member up", name(i), got)
		}
		// Each member connected redialed it every second, which the
		// member with the lower device ID refused, until a race left the
		// higher one's connection up and the lower one's dials replaced it.
		if got := proxies[i].count.Load() - dials[i]; got > 0 {
			t.Errorf("%s was dialed %d times in 10 s while connected to both others", name(i), got)
		}
	}

	// The group knows each member by the -name of its service.
	st, err := members[0].do(t, control.Header{Op: control.OpDevices}, "")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range st.Devices {
		names = append(names, d.Name)
	}
	for i := range members {
		if !strings.Contains(strings.Join(names, "\n"), name(i)) {
			t.Errorf("the group's devices are %q, without %s", names, name(i))
		}
	}
}

// countingProxy passes TCP connections on to a member's port and counts
// them.
type countingProxy struct {
	ln    net.Listener
	count atomic.Int64
}

func newCountingProxy(t *testing.T, to string) *countingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &countingProxy{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.count.Add(1)
			go func() {
				defer c.Close()
				up, err := net.DialTimeout("tcp", to, 5*time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				done := make(chan struct{}, 2)
				pipe := func(dst, src net.Conn) {
					io.Copy(dst, src)
					if tc, ok := dst.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
					done <- struct{}{}
				}
				go pipe(up, c)
				go pipe(c, up)
				<-done
				<-done
			}()
		}
	}()
	return p
}

func (p *countingProxy) addr() string { return p.ln.Addr().String() }
