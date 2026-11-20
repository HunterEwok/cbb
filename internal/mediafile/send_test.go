// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mediafile

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
)

// service listens on a socket in a temporary folder and gives what one
// client sends, in order.
func service(t *testing.T) (string, <-chan []*control.Message) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Skip("no Unix sockets:", err)
	}
	t.Cleanup(func() { l.Close() })
	got := make(chan []*control.Message, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		r := control.NewReader(c)
		var ms []*control.Message
		for {
			m, err := r.Read()
			if err != nil {
				got <- ms
				return
			}
			ms = append(ms, m)
		}
	}()
	return path, got
}

func TestSend(t *testing.T) {
	dir := t.TempDir()
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<17) // 2 MiB, more than one message
	os.WriteFile(filepath.Join(dir, "big"), big, 0o644)
	os.WriteFile(filepath.Join(dir, "small"), []byte("hi"), 0o644)
	parts := []Part{
		{Part: control.Part{Path: "f", Dir: true}},
		{Part: control.Part{Path: "f/big", Size: int64(len(big))}, File: filepath.Join(dir, "big")},
		{Part: control.Part{Path: "f/small", Size: 2}, File: filepath.Join(dir, "small")},
	}
	if n := Size(parts); n != int64(len(big))+2 {
		t.Errorf("Size = %d", n)
	}
	path, got := service(t)
	c, err := control.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Send(c, control.OpCopyMedia, parts, "text"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	ms := <-got
	if len(ms) < 6 {
		t.Fatalf("%d messages", len(ms))
	}
	if ms[0].Op != control.OpCopyMedia || string(ms[0].Payload) != "text" {
		t.Errorf("first %+v", ms[0].Header)
	}
	var paths []string
	var data bytes.Buffer
	for _, m := range ms[1 : len(ms)-1] {
		switch m.Op {
		case control.OpPart:
			paths = append(paths, m.Part.Path)
		case control.OpData:
			data.Write(m.Payload)
		default:
			t.Errorf("op %q", m.Op)
		}
	}
	if strings.Join(paths, ",") != "f,f/big,f/small" {
		t.Errorf("parts %v", paths)
	}
	if !bytes.Equal(data.Bytes(), append(big, "hi"...)) {
		t.Errorf("%d bytes sent", data.Len())
	}
	if last := ms[len(ms)-1]; last.Op != control.OpPart || !last.Done {
		t.Errorf("last %+v", last.Header)
	}
}

func TestSendFails(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte("hi"), 0o644)
	for name, part := range map[string]Part{
		"a file that is gone":     {Part: control.Part{Path: "x", Size: 2}, File: filepath.Join(dir, "gone")},
		"a file that got shorter": {Part: control.Part{Path: "x", Size: 10}, File: short},
	} {
		path, got := service(t)
		c, err := control.Dial(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := Send(c, control.OpCopyMedia, []Part{part}, ""); err == nil {
			t.Errorf("%s was sent", name)
		}
		c.Close()
		<-got
	}
	// A closed connection fails at once.
	path, got := service(t)
	c, err := control.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	<-got
	if err := Send(c, control.OpCopyMedia, nil, ""); err == nil {
		t.Error("sent over a closed connection")
	}
	if _, err := control.Dial(filepath.Join(dir, "none")); err == nil {
		t.Error("dialed no service")
	}
}

// answers is a Receiver that gives its messages, then fails.
type answers []*control.Message

func (a *answers) Receive() (*control.Message, error) {
	if len(*a) == 0 {
		return nil, errors.New("the connection closed")
	}
	m := (*a)[0]
	*a = (*a)[1:]
	return m, nil
}

func part(p control.Part) *control.Message {
	return &control.Message{Header: control.Header{Op: control.OpPart, Part: &p}}
}

func data(s string) *control.Message {
	return &control.Message{Header: control.Header{Op: control.OpData}, Payload: []byte(s)}
}

func done() *control.Message {
	return &control.Message{Header: control.Header{Op: control.OpPart, Done: true}}
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	a := answers{
		part(control.Part{Path: "trip", Dir: true}),
		part(control.Part{Path: "trip/a.txt", Size: 5}), data("he"), data("llo"),
		part(control.Part{Path: "trip/empty"}),
		part(control.Part{Type: clip.TypeJPEG, Size: 2}), data("jp"),
		part(control.Part{Type: clip.TypeGIF, Size: 1}), data("g"),
		part(control.Part{Type: clip.TypeHTML, Size: 3}), data("<b>"),
		done(),
	}
	top, err := Save(&a, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"trip", "image.jpg", "image.gif", "clipboard.html"}
	if len(top) != len(want) {
		t.Fatalf("top %v", top)
	}
	for i, w := range want {
		if top[i] != filepath.Join(dir, w) {
			t.Errorf("top %d = %s, want %s", i, top[i], w)
		}
	}
	for name, body := range map[string]string{"trip/a.txt": "hello", "trip/empty": "", "image.jpg": "jp", "clipboard.html": "<b>"} {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || string(b) != body {
			t.Errorf("%s = %q, %v", name, b, err)
		}
		if info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name))); err == nil && info.Mode()&0o111 != 0 {
			t.Errorf("%s is executable: %v", name, info.Mode())
		}
	}
}

func TestSaveRefuses(t *testing.T) {
	cases := map[string]answers{
		"bytes without their part": {data("x")},
		"a path out of the folder": {part(control.Part{Path: "../x", Size: 1}), data("x")},
		"a name Windows reserves":  {part(control.Part{Path: "con.txt", Size: 1}), data("x")},
		"an unknown type":          {part(control.Part{Type: "image/webp", Size: 1}), data("x")},
		"more bytes than said":     {part(control.Part{Path: "a", Size: 1}), data("xy")},
		"no bytes":                 {part(control.Part{Path: "a", Size: 1}), data("")},
		"a part in the bytes":      {part(control.Part{Path: "a", Size: 1}), part(control.Part{Path: "b"})},
		"the end in the bytes":     {part(control.Part{Path: "a", Size: 1}), done()},
		"a closed connection":      {part(control.Part{Path: "d", Dir: true}), part(control.Part{Path: "d/a", Size: 3}), data("x")},
		"no end":                   {part(control.Part{Path: "a"})},
		"a folder twice":           {part(control.Part{Path: "d", Dir: true}), part(control.Part{Path: "d", Dir: true})},
		"a file twice":             {part(control.Part{Path: "a"}), part(control.Part{Path: "a"})},
		"a file in no folder":      {part(control.Part{Path: "none/a"})},
	}
	for name, a := range cases {
		dir := t.TempDir()
		if _, err := Save(&a, dir); err == nil {
			t.Errorf("%s: saved", name)
		}
		// What it made is gone.
		if left, _ := os.ReadDir(dir); len(left) != 0 {
			t.Errorf("%s: left %d entries", name, len(left))
		}
	}
	// It never replaces a file that is there.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a"), []byte("mine"), 0o644)
	a := answers{part(control.Part{Path: "a", Size: 1}), data("x"), done()}
	if _, err := Save(&a, dir); err == nil {
		t.Error("replaced a file")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a")); string(b) != "mine" {
		t.Errorf("the file holds %q", b)
	}
}
