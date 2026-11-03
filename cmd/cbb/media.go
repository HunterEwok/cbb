// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/mediafile"
	"github.com/HunterEwok/cbb/internal/service"
)

// Images and files on the command line (design.md, "Images and files"):
// cbb copy FILE... sends files and folders, or with -type one image, and
// cbb paste -o DIR saves what the clipboard holds, through mediafile.

// mediaType reads the -type of cbb copy: png, jpeg or html, or the type
// itself.
func mediaType(t string) (string, error) {
	switch strings.ToLower(t) {
	case "png", clip.TypePNG:
		return clip.TypePNG, nil
	case "jpeg", "jpg", clip.TypeJPEG:
		return clip.TypeJPEG, nil
	case "html", clip.TypeHTML:
		return clip.TypeHTML, nil
	}
	return "", fmt.Errorf("-type is png, jpeg or html, not %q", t)
}

// copyMedia sends the files at paths, or with typ the one file as an
// image or HTML, as the clipboard's new content, with text as its plain
// text, if any.
func copyMedia(paths []string, typ, text string, stdout, stderr io.Writer) int {
	var parts []mediafile.Part
	if typ != "" {
		if len(paths) != 1 {
			fmt.Fprintln(stderr, "cbb: copy -type takes one file")
			return 2
		}
		t, err := mediaType(typ)
		if err != nil {
			fmt.Fprintln(stderr, "cbb:", err)
			return 2
		}
		info, err := os.Stat(paths[0])
		if err != nil {
			return fail(stderr, err)
		}
		if !info.Mode().IsRegular() {
			return fail(stderr, fmt.Errorf("%s is not a file", paths[0]))
		}
		parts = []mediafile.Part{{Part: control.Part{Type: t, Size: info.Size()}, File: paths[0]}}
	} else {
		var skipped int
		var err error
		if parts, skipped, err = mediafile.Collect(paths); err != nil {
			return fail(stderr, err)
		}
		if skipped > 0 {
			fmt.Fprintf(stderr, "cbb: left out %d links and special files; only files and folders are copied\n", skipped)
		}
	}
	total := mediafile.Size(parts)
	if total > clip.MaxMedia {
		return fail(stderr, fmt.Errorf("the copy is %s; CBB carries at most 1 GiB", service.SizeText(total)))
	}
	c, err := control.DialFor(control.OpCopyMedia)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if err := mediafile.Send(c, control.OpCopyMedia, parts, text); err != nil {
		// The service may have refused the copy midway and said why.
		if m, rerr := c.Receive(); rerr != nil && m != nil {
			return fail(stderr, rerr)
		}
		return fail(stderr, err)
	}
	if _, err := c.Receive(); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Copied %s to the group.\n", describe(parts, total))
	return 0
}

// describe says what a copy holds: an image, a file, or so many files and
// folders, and its size.
func describe(parts []mediafile.Part, total int64) string {
	files, dirs := 0, 0
	for _, p := range parts {
		switch {
		case p.Type != "":
			return fmt.Sprintf("the %s (%s)", p.Type, service.SizeText(total))
		case p.Dir:
			dirs++
		default:
			files++
		}
	}
	switch {
	case dirs == 0 && files == 1:
		return fmt.Sprintf("%s (%s)", parts[0].Path, service.SizeText(total))
	case dirs == 0:
		return fmt.Sprintf("%d files (%s)", files, service.SizeText(total))
	}
	return fmt.Sprintf("%d files in %d folders (%s)", files, dirs, service.SizeText(total))
}

// pasteMedia saves the images or files of the clipboard in dir, as
// mediafile.Save does.
func pasteMedia(dir string, stdout, stderr io.Writer) int {
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return fail(stderr, fmt.Errorf("%s is not a folder", dir))
	}
	c, err := control.DialFor(control.OpPasteMedia)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPasteMedia}}); err != nil {
		return fail(stderr, err)
	}
	top, err := mediafile.Save(c, dir)
	if err != nil {
		return fail(stderr, err)
	}
	for _, t := range top {
		fmt.Fprintln(stdout, t)
	}
	return 0
}

// cmdConfig shows or changes this device's settings: the largest copy of
// images and files it sends or fetches, at home and away from home.
func cmdConfig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if fs.Parse(args) != nil {
		return 2
	}
	if n := fs.NArg(); n != 0 && n != 2 {
		fmt.Fprintln(stderr, "usage: cbb config\n       cbb config max-copy|max-copy-away SIZE (such as 200MiB)")
		return 2
	}
	h := control.Header{Op: control.OpConfig, Name: fs.Arg(0), Value: fs.Arg(1)}
	c, err := control.DialFor(h.Op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h})
	if err != nil {
		return fail(stderr, err)
	}
	if m.Status == nil || m.Status.Media == nil {
		return fail(stderr, errors.New("this device is in no group; run cbb new here to start one, or cbb pair to join one"))
	}
	fmt.Fprintf(stdout, "max-copy       %s  the largest copy of images and files this device sends or fetches at home\n", service.SizeText(m.Status.Media.MaxCopy))
	fmt.Fprintf(stdout, "max-copy-away  %s  the same away from home\n", service.SizeText(m.Status.Media.MaxCopyAway))
	return 0
}

// writeMedia says in cbb status what is being fetched, or why the last
// copy was not.
func writeMedia(w io.Writer, st *control.Media) {
	switch {
	case st == nil:
	case st.Fetching > 0:
		from := ""
		if st.From != "" {
			from = " from " + st.From
		}
		fmt.Fprintf(w, "Fetching a copy of %s%s: %d%%.\n", service.SizeText(st.Fetching), from, st.Fetched*100/st.Fetching)
	case st.Failed != "":
		fmt.Fprintf(w, "The last copy of images or files was not fetched: %s.\n", st.Failed)
	}
}
