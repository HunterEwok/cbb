// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package mediafile sends files and folders to the service as a copy and
// saves a copy's parts in a folder (design.md, "Images and files"), for
// cbb copy and cbb paste -o and for the desktop connectors. It reads and
// writes the files as the user who runs it and streams their bytes over
// the control socket; the service keeps them in its cache.
package mediafile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
)

// A Part is a part to send, with the file it comes from.
type Part struct {
	control.Part
	File string // "" for a folder
}

// Collect lists the parts of a copy of the files and folders at paths:
// each by its cleaned name, a folder with its tree, links and special
// files left out (it returns how many).
func Collect(paths []string) ([]Part, int, error) {
	var parts []Part
	seen := map[string]bool{}
	skipped, names := 0, 0
	add := func(p Part) error {
		if seen[p.Path] {
			return fmt.Errorf("two files would be %q in the copy", p.Path)
		}
		seen[p.Path] = true
		names += len(p.Path)
		switch {
		case len(parts) == clip.MaxParts:
			return fmt.Errorf("a copy has at most %d files and folders", clip.MaxParts)
		case names > clip.MaxPaths:
			return errors.New("the names in the copy are too long together")
		case len(p.Path) > clip.MaxPath:
			return fmt.Errorf("the path %q is too long", p.Path)
		}
		parts = append(parts, p)
		return nil
	}
	for _, arg := range paths {
		abs, err := filepath.Abs(arg)
		if err != nil {
			return nil, 0, err
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, 0, err
		}
		top := clip.CleanName(filepath.Base(abs))
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				return nil, 0, fmt.Errorf("%s is not a file or a folder", arg)
			}
			if err := add(Part{Part: control.Part{Path: top, Size: info.Size()}, File: abs}); err != nil {
				return nil, 0, err
			}
			continue
		}
		err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(abs, p)
			if err != nil {
				return err
			}
			name := top
			if rel != "." {
				var clean []string
				for n := range strings.SplitSeq(filepath.ToSlash(rel), "/") {
					clean = append(clean, clip.CleanName(n))
				}
				name = path.Join(top, path.Join(clean...))
			}
			switch {
			case d.IsDir():
				return add(Part{Part: control.Part{Path: name, Dir: true}})
			case !d.Type().IsRegular():
				skipped++ // links are neither followed nor sent
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			return add(Part{Part: control.Part{Path: name, Size: info.Size()}, File: p})
		})
		if err != nil {
			return nil, 0, err
		}
	}
	return parts, skipped, nil
}

// Size is the bytes of the parts' files together.
func Size(parts []Part) int64 {
	var total int64
	for _, p := range parts {
		total += p.Size
	}
	return total
}

// Send sends the request op (control.OpCopyMedia, or OpCopiedMedia from a
// watcher) with text as the copy's plain-text alternative, each part and
// its bytes, and the end. The caller then reads the service's answer.
func Send(c *control.Client, op string, parts []Part, text string) error {
	if err := c.Send(&control.Message{Header: control.Header{Op: op}, Payload: []byte(text)}); err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	for _, p := range parts {
		if err := c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Part: &p.Part}}); err != nil {
			return err
		}
		if p.Dir {
			continue
		}
		if err := sendFile(c, p, buf); err != nil {
			return err
		}
	}
	return c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Done: true}})
}

// sendFile sends exactly the size the part says of its file.
func sendFile(c *control.Client, p Part, buf []byte) error {
	f, err := os.Open(p.File)
	if err != nil {
		return err
	}
	defer f.Close()
	left := p.Size
	for left > 0 {
		n, err := io.ReadFull(f, buf[:min(int64(len(buf)), left)])
		if n > 0 {
			if err := c.Send(&control.Message{Header: control.Header{Op: control.OpData}, Payload: buf[:n]}); err != nil {
				return err
			}
			left -= int64(n)
		}
		if err != nil && left > 0 {
			return fmt.Errorf("%s changed while it was copied", p.File)
		}
	}
	return nil
}

// A Receiver gives the service's answers, as a *control.Client does.
type Receiver interface {
	Receive() (*control.Message, error)
}

// Save writes the parts the service sends after its first answer to
// paste-media into dir, until the last answer: files and folders by their
// names, an image as image.png or image.jpg, HTML as clipboard.html. It
// never replaces a file, makes nothing executable, and marks each file as
// downloaded where the system has such a mark (quarantine on a Mac, the
// Mark of the Web on Windows). It returns the paths of the copy's top
// names; when it fails, it removes what it made.
func Save(c Receiver, dir string) ([]string, error) {
	var made []string
	failed := func(err error) ([]string, error) {
		for i := len(made) - 1; i >= 0; i-- {
			os.Remove(made[i])
		}
		return nil, err
	}
	var top []string
	for {
		m, err := c.Receive()
		if err != nil {
			return failed(err)
		}
		if m.Done {
			return top, nil
		}
		if m.Part == nil {
			return failed(errors.New("the service sent bytes without their part"))
		}
		name, err := SavedName(*m.Part)
		if err != nil {
			return failed(err)
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		if !strings.Contains(name, "/") {
			top = append(top, target)
		}
		if m.Part.Dir {
			if err := os.Mkdir(target, 0o755); err != nil {
				return failed(err)
			}
			made = append(made, target)
			continue
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return failed(err)
		}
		made = append(made, target)
		err = receive(c, f, m.Part.Size)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = markDownload(target)
		}
		if err != nil {
			return failed(err)
		}
	}
}

// SavedName is where a part goes in the folder: its path, checked again,
// with the device names of Windows renamed (clip.SavePath), or a name for
// its type.
func SavedName(p control.Part) (string, error) {
	switch p.Type {
	case "":
		return clip.SavePath(p.Path), clip.CheckPath(p.Path)
	case clip.TypePNG:
		return "image.png", nil
	case clip.TypeJPEG:
		return "image.jpg", nil
	case clip.TypeGIF:
		return "image.gif", nil
	case clip.TypeHTML:
		return "clipboard.html", nil
	}
	return "", fmt.Errorf("the clipboard holds %s, which this cbb does not know", p.Type)
}

// receive writes size bytes of the service's answers to f.
func receive(c Receiver, f *os.File, size int64) error {
	for got := int64(0); got < size; {
		m, err := c.Receive()
		if err != nil {
			return err
		}
		if m.Part != nil || m.Done || len(m.Payload) == 0 || int64(len(m.Payload)) > size-got {
			return errors.New("the service sent the bytes of a part not as said")
		}
		if _, err := f.Write(m.Payload); err != nil {
			return err
		}
		got += int64(len(m.Payload))
	}
	return nil
}
