// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/tvremote/androidtv/atvtest"
)

// The TVs (T17, T19): forge tv:androidtv plays an Android TV on the ports
// 6467 and 6466 with a text field open, and forge tv:roku plays a Roku's
// External Control Protocol on port 8060 (tv:roku-off one with "Control by
// mobile apps" off). Each writes what the bench reads into DIR: the code
// the TV shows (code) and what came into its text field (text).

func runTV(kind, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	write := func(name, s string) {
		os.WriteFile(dir+"/"+name+".new", []byte(s), 0o644)
		os.Rename(dir+"/"+name+".new", dir+"/"+name)
	}
	switch kind {
	case "androidtv":
		tv, err := atvtest.Start(":6467")
		if err != nil {
			return err
		}
		defer tv.Close()
		tv.Focus()
		fmt.Println("tv: an Android TV on 6467 and 6466")
		for {
			write("code", tv.Code())
			text, _ := tv.Text()
			if len(text) > 0 {
				write("text", text[len(text)-1])
			}
			time.Sleep(100 * time.Millisecond)
		}
	case "roku", "roku-off":
		var mu sync.Mutex
		var typed strings.Builder
		mux := http.NewServeMux()
		mux.HandleFunc("GET /query/device-info", func(w http.ResponseWriter, r *http.Request) {
			if kind == "roku-off" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8" ?><device-info><user-device-name>Bench Roku</user-device-name><friendly-model-name>Roku Ultra</friendly-model-name></device-info>`)
		})
		mux.HandleFunc("POST /keypress/{key}", func(w http.ResponseWriter, r *http.Request) {
			if kind == "roku-off" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			key := r.PathValue("key")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case key == "Enter":
				typed.WriteString("\n")
			case strings.HasPrefix(key, "Lit_"):
				s, err := url.PathUnescape(strings.TrimPrefix(key, "Lit_"))
				if err != nil {
					http.Error(w, "bad key", http.StatusBadRequest)
					return
				}
				typed.WriteString(s)
			default:
				http.Error(w, "unknown key", http.StatusBadRequest)
				return
			}
			write("text", typed.String())
		})
		fmt.Println("tv: a Roku on 8060")
		return http.ListenAndServe(":8060", mux)
	}
	return fmt.Errorf("no TV %q", kind)
}
