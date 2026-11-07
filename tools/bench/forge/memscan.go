// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// runMemscan looks for text in the memory of every cbb service in the
// container, the bench's check that a device holds no copy it must not read
// (docs/testbench-catalogue.md, S25, S26, Y36): it prints "memscan: found N"
// or "memscan: none", and fails when it finds no service or reads none of
// its memory. The container runs it with --privileged, since the service
// may make itself undumpable.
func runMemscan(text string) error {
	if text == "" {
		return fmt.Errorf("memscan takes the text to look for")
	}
	pids, err := servicePIDs()
	if err != nil {
		return err
	}
	if len(pids) == 0 {
		return fmt.Errorf("no cbb service runs here")
	}
	found, read := 0, int64(0)
	for _, pid := range pids {
		n, r, err := scanProcess(pid, []byte(text))
		if err != nil {
			return fmt.Errorf("process %d: %w", pid, err)
		}
		found += n
		read += r
	}
	if read == 0 {
		return fmt.Errorf("read none of the services' memory")
	}
	if found == 0 {
		fmt.Println("memscan: none")
	} else {
		fmt.Printf("memscan: found %d\n", found)
	}
	return nil
}

// servicePIDs lists the processes named cbb whose command line runs the
// service.
func servicePIDs() ([]int, error) {
	dirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, d := range dirs {
		comm, err := os.ReadFile(d + "/comm")
		if err != nil || strings.TrimSpace(string(comm)) != "cbb" {
			continue
		}
		cmd, err := os.ReadFile(d + "/cmdline")
		if err != nil || !bytes.Contains(cmd, []byte("service")) {
			continue
		}
		if pid, err := strconv.Atoi(filepath.Base(d)); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// scanProcess counts text in each readable mapping of the process pid and
// returns how many bytes it read.
func scanProcess(pid int, text []byte) (int, int64, error) {
	maps, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, 0, err
	}
	defer maps.Close()
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return 0, 0, err
	}
	defer mem.Close()
	const chunk = 1 << 20
	buf := make([]byte, chunk+len(text))
	found, read := 0, int64(0)
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[1][0] != 'r' || (len(f) > 5 && (f[5] == "[vvar]" || f[5] == "[vsyscall]")) {
			continue
		}
		lo, hi, ok := strings.Cut(f[0], "-")
		if !ok {
			continue
		}
		start, err1 := strconv.ParseUint(lo, 16, 64)
		end, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		// Each chunk overlaps the next by the text's length less one, so a
		// text across their border is found once.
		for off := start; off < end; off += chunk {
			n := min(uint64(len(buf)), end-off)
			got, _ := mem.ReadAt(buf[:n], int64(off))
			if got <= 0 {
				break
			}
			read += int64(got)
			// Count only the matches that start in this chunk.
			b := buf[:min(got, chunk+len(text)-1)]
			found += bytes.Count(b, text)
		}
	}
	return found, read, sc.Err()
}
