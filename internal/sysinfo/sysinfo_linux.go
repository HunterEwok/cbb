// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package sysinfo

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"github.com/HunterEwok/cbb/internal/openwrt"
)

func form() string {
	if openwrt.Is() {
		return "router"
	}
	model, _ := os.ReadFile("/proc/device-tree/model")
	product, _ := os.ReadFile("/sys/class/dmi/id/product_name")
	chassis, _ := os.ReadFile("/sys/class/dmi/id/chassis_type")
	return formOf(string(bytes.TrimRight(model, "\x00\n")), strings.TrimSpace(string(product)), strings.TrimSpace(string(chassis)))
}

// formOf tells the form from the device tree's model (boards), the DMI
// product name (the Steam Deck) and the DMI chassis type (SMBIOS 7.4.1).
func formOf(model, product, chassis string) string {
	switch {
	case model != "":
		return "board"
	case product == "Jupiter" || product == "Galileo":
		return "console"
	}
	switch chassis {
	case "8", "9", "10", "11", "14", "30", "31", "32":
		return "laptop"
	case "3", "4", "5", "6", "7", "13", "15", "16", "35", "36":
		return "desktop"
	case "17", "23", "28", "29":
		return "server"
	}
	return ""
}

func osVersion() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	return osRelease(f)
}

// osRelease is the pretty name of os-release, or its name and version when
// that is too long.
func osRelease(f *os.File) string {
	v := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		if k, val, ok := strings.Cut(s.Text(), "="); ok {
			v[k] = strings.Trim(val, `"'`)
		}
	}
	if p := v["PRETTY_NAME"]; p != "" && len(p) <= 32 {
		return p
	}
	return strings.TrimSpace(v["NAME"] + " " + v["VERSION_ID"])
}
