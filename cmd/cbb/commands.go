// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/actions"
	"github.com/HunterEwok/clipboardbridge/internal/benchtime"
	"github.com/HunterEwok/clipboardbridge/internal/connector"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/pasteboard"
	"github.com/HunterEwok/clipboardbridge/internal/phone"
	"github.com/HunterEwok/clipboardbridge/internal/rootless"
	"github.com/HunterEwok/clipboardbridge/internal/service"
	"github.com/HunterEwok/clipboardbridge/internal/sysinfo"
	"github.com/HunterEwok/clipboardbridge/internal/version"
)

const maxText = 1 << 20

// cmdCopy sends standard input to the group as a deliberate copy, or the
// files and folders it names.
func cmdCopy(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("copy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	secret := fs.Bool("secret", false, "send the text as a secret: kept only in memory, gone after 60 seconds")
	typ := fs.String("type", "", "with one FILE, send it as clipboard data of this type: png, jpeg or html")
	alt := fs.String("text", "", "with FILE, the plain text that goes with the copy, for the devices that take only text")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		if *secret {
			fmt.Fprintln(stderr, "cbb: -secret is for a text, not for files")
			return 2
		}
		return copyMedia(fs.Args(), *typ, *alt, stdout, stderr)
	}
	if *typ != "" || *alt != "" {
		fmt.Fprintln(stderr, "cbb: -type and -text go with FILE")
		return 2
	}
	text, err := io.ReadAll(io.LimitReader(stdin, maxText+1))
	if err != nil {
		return fail(stderr, err)
	}
	if len(text) > maxText {
		return fail(stderr, errors.New("the text is larger than 1 MiB"))
	}
	kind := control.KindText
	if *secret {
		kind = control.KindSecret
	}
	c, err := control.DialFor(control.OpCopy)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpCopy, Kind: kind}, Payload: text}); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// cmdPaste writes the member's own clipboard text to standard output. With
// -terminal it makes the text safe to paste into a terminal: see terminalText.
func cmdPaste(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if slices.ContainsFunc(args, func(a string) bool {
		return a == "-on" || a == "--on" || strings.HasPrefix(a, "-on=") || strings.HasPrefix(a, "--on=")
	}) {
		return cmdPasteOn(args, stdin, stdout, stderr)
	}
	fs := flag.NewFlagSet("paste", flag.ContinueOnError)
	fs.SetOutput(stderr)
	terminal := fs.Bool("terminal", false, "make the text safe for a terminal: no control characters, only the first line")
	lines := fs.Bool("lines", false, "with -terminal, keep every line instead of only the first")
	secret := fs.Bool("secret", false, "with -terminal, paste a secret too")
	out := fs.String("o", "", "save the clipboard's images or files in this folder")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "cbb: paste takes no arguments")
		return 2
	}
	if *out != "" {
		if *terminal || *lines || *secret {
			fmt.Fprintln(stderr, "cbb: -o saves images or files; -terminal, -lines and -secret are for a text")
			return 2
		}
		return pasteMedia(*out, stdout, stderr)
	}
	if (*lines || *secret) && !*terminal {
		fmt.Fprintln(stderr, "cbb: -lines and -secret go with -terminal")
		return 2
	}
	c, err := control.DialFor(control.OpPaste)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPaste}})
	if err != nil {
		return fail(stderr, err)
	}
	text := m.Payload
	if *terminal {
		if m.Kind == control.KindSecret && !*secret {
			return fail(stderr, errors.New("the clipboard holds a secret; add -secret to paste it"))
		}
		t, dropped := terminalText(string(m.Payload), *lines)
		if dropped > 0 {
			fmt.Fprintf(stderr, "cbb: pasted only the first line; %d more left out (add -lines to paste them)\n", dropped)
		}
		text = []byte(t)
	}
	if _, err := stdout.Write(text); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// terminalText makes a text safe to paste into a terminal. It drops the
// control characters of C0 but tab and line feed, DEL and those of C1, which
// could move the cursor, end a bracketed paste or talk to the terminal
// itself, and bytes that are not UTF-8. It ends with no line feed, so that a
// shell does not run the text by itself, and unless all is set it keeps only
// the first line, returning how many lines it left out.
func terminalText(text string, all bool) (string, int) {
	text = strings.ToValidUTF8(strings.ReplaceAll(text, "\r\n", "\n"), "")
	text = strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n':
			return r
		case r < 0x20 || r >= 0x7f && r < 0xa0:
			return -1
		}
		return r
	}, text)
	text = strings.Trim(text, "\n")
	if all {
		return text, 0
	}
	first, rest, more := strings.Cut(text, "\n")
	if !more {
		return first, 0
	}
	return first, strings.Count(rest, "\n") + 1
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "cbb: status takes no arguments")
		return 2
	}
	c, err := control.DialFor(control.OpStatus)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
	if err != nil {
		return fail(stderr, err)
	}
	st := m.Status
	if st == nil {
		return fail(stderr, errors.New("the service sent no status"))
	}
	var devs []control.Device
	if st.Group != "" {
		d, err := control.DialFor(control.OpDevices)
		if err != nil {
			return fail(stderr, err)
		}
		defer d.Close()
		m, err := d.Do(&control.Message{Header: control.Header{Op: control.OpDevices}})
		if err != nil {
			return fail(stderr, err)
		}
		devs = m.Devices
	}
	var out bytes.Buffer
	writeStatus(&out, st, devs, benchtime.Now())
	if _, err := stdout.Write(out.Bytes()); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// noPasteboard says, on a Mac, when this cbb was built without cgo and so
// without the pasteboard: its agent cannot link the clipboard. It is ""
// everywhere else.
func noPasteboard() string {
	if runtime.GOOS != "darwin" || pasteboard.Supported {
		return ""
	}
	return "This cbb was built without cgo, so it has no pasteboard support: its agent cannot link this Mac's clipboard. Install a release build, or build with CGO_ENABLED=1."
}

// certWarning is how long before its end status warns that this device's
// member certificate was not renewed: an admin renews it from 240 days
// before, so this late no admin has met the device for months.
var certWarning = benchtime.D(30 * 24 * time.Hour)

// certLine warns when this device's member certificate has ended, or ends
// soon, or says nothing.
func certLine(endsMS int64, now time.Time) string {
	if endsMS == 0 {
		return ""
	}
	end := time.UnixMilli(endsMS)
	switch {
	case !now.Before(end):
		return fmt.Sprintf("This device's certificate ended on %s, before an admin renewed it: the group's members refuse it. If this device's date (%s) is wrong, set it right; otherwise, to join again, remove Clipboard Bridge with its keys (uninstall --purge), install it again and join.", end.Local().Format(time.DateOnly), now.Local().Format(time.DateOnly))
	case end.Sub(now) < certWarning:
		return fmt.Sprintf("This device's certificate ends on %s and no admin has renewed it: connect it to the group's root or an admin before then, or it must join again.", end.Local().Format(time.DateOnly))
	}
	return ""
}

// writeStatus prints this device, its group and the group's devices.
func writeStatus(w io.Writer, st *control.Status, devs []control.Device, now time.Time) {
	fmt.Fprintf(w, "%s\n", st.Version)
	if st.Update != "" {
		fmt.Fprintf(w, "Clipboard Bridge %s is available. To install it: %s\n", st.Update, updateCommand())
	}
	if np := noPasteboard(); np != "" {
		fmt.Fprintln(w, np)
	}
	if st.Group == "" {
		fmt.Fprintln(w, "Not in a group. Run cbb new here to start one, or cbb pair to join one.")
		return
	}
	fmt.Fprintf(w, "Device %s (%s, %s), group %s\n", st.Device, group.OSName(st.OS), st.Role, st.Group)
	if st.Removed {
		fmt.Fprintln(w, "This device was removed from the group: its members refuse it. To join again, remove Clipboard Bridge with its keys (uninstall --purge), install it again and join.")
	} else if st.Frozen {
		fmt.Fprintln(w, "Another admin froze this computer's admin key: its members refuse it until the group's root or an admin phone unfreezes it (cbb unfreeze on the root).")
	} else if st.TakenOverBy != "" {
		fmt.Fprintf(w, "%[1]s, an admin, took the group over from this computer, its root, while it was away. If this computer is not lost, sudo cbb revoke %[1]s undoes it; otherwise the group is %[1]s's now.\n", st.TakenOverBy)
	} else if c := certLine(st.CertEndsMS, now); c != "" {
		fmt.Fprintln(w, c)
	}
	for _, l := range stopLines(st) {
		fmt.Fprintln(w, l)
	}
	if st.Mode != "" {
		fmt.Fprintln(w, modeLine(st.Mode))
	}
	fmt.Fprintln(w, holderLine(st))
	if q := quietLine(st); q != "" {
		fmt.Fprintln(w, q)
	}
	writeAway(w, st.Away)
	writeMedia(w, st.Media)
	if len(st.Peers) == 0 {
		fmt.Fprintln(w, "No members connected.")
	}
	writeUnreached(w, st, devs)
	writeDevices(w, devs, st.Peers, st.Release, now)
}

// writeUnreached says when members at home could not connect to this
// device and sync with it only because it dials them back: a firewall here
// that the installer does not know, or a rule that is missing, drops the
// member port. A device that cannot dial out, a phone, would not sync.
func writeUnreached(w io.Writer, st *control.Status, devs []control.Device) {
	if len(st.Unreached) == 0 {
		return
	}
	var names []string
	for _, id := range st.Unreached {
		name := id
		for _, d := range devs {
			if d.ID == id && d.Name != "" {
				name = d.Name
			}
		}
		names = append(names, name)
	}
	port := st.Port
	if port == 0 {
		port = 8764
	}
	fmt.Fprintf(w, "Warning: %s could not connect to this device; they sync only because this device connects to them.\n", strings.Join(names, ", "))
	fmt.Fprintf(w, "A firewall here likely drops TCP %d from the home network, and phones cannot reach this device.\n", port)
	fmt.Fprintln(w, "Allow TCP "+strconv.Itoa(port)+" and UDP 5353 from the home network, or run the installer again with "+expressHint+".")
}

// cmdNew creates a group with this computer as its root.
func cmdNew(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "cbb: new takes no arguments")
		return 2
	}
	c, err := control.DialFor(control.OpNew)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpNew}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Created the group %s; this computer is its root.\n", m.Status.Group)
	// Until the service keeps its keys in the TPM or the Secure Enclave
	// (docs/protocol.md, section 17), the root key is a file.
	fmt.Fprintln(stdout, "Its root key is a file here: guard this computer, since whoever copies the file can act as the group's root. A group made on a phone keeps its root key in the phone's hardware.")
	fmt.Fprintln(stdout, "Add a computer: cbb pair here, then cbb pair on the new computer.")
	fmt.Fprintln(stdout, "Add an iPhone with the shortcut: cbb pair -phone.")
	return 0
}

// cmdPair adds a device, on whichever side this computer is: in a group it
// opens a pairing window for a new computer; in no group it joins one, by
// the phone's QR code or by the code that cbb pair shows on the group's
// root or an admin.
func cmdPair(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	phone := fs.Bool("phone", false, "pair an iPhone or iPad with the shortcut")
	newToken := fs.Bool("new-token", false, "with -phone: revoke the token of every shortcut paired so far, and pair this iPhone with a new one")
	typed := fs.Bool("code", false, "join with the code that cbb pair shows on the group's root or an admin, read from standard input")
	invitation := fs.String("invite", "", "join from afar with the invitation file that cbb invite made on the group's hub")
	if fs.Parse(args) != nil {
		return 2
	}
	rest := fs.Args()
	switch {
	case *phone && (*typed || *invitation != "" || len(rest) != 0),
		*newToken && !*phone,
		*invitation != "" && (*typed || len(rest) != 0),
		len(rest) > 1 || len(rest) == 1 && (!*typed || !strings.Contains(rest[0], ":")):
		fmt.Fprintln(stderr, pairUsage)
		return 2
	case *phone:
		return cmdPairPhone(*newToken, stdout, stderr)
	case *invitation != "":
		return cmdJoinInvite(*invitation, stdin, stdout, stderr)
	case *typed:
		address := ""
		if len(rest) == 1 {
			address = rest[0]
		}
		if f, ok := stdin.(*os.File); ok && isTerminal(f) {
			fmt.Fprint(stdout, "Pairing code: ")
		}
		line, err := readLine(stdin)
		if err != nil {
			return fail(stderr, err)
		}
		return joinWithCode(line, address, stdout, stderr)
	}
	st, err := serviceStatus()
	if err != nil {
		return fail(stderr, err)
	}
	if st.Group == "" {
		return joinByQR(stdin, stdout, stderr)
	}
	return admit(stdout, stderr)
}

const pairUsage = `usage: cbb pair                  in a group: show a code for a new computer;
                                in no group: join by the phone's QR code or a typed code
       cbb pair -code [address:port]   join with the code, read from standard input
       cbb pair -phone          pair an iPhone with the shortcut
       cbb pair -phone -new-token   revoke every shortcut's token, then pair with a new one
       cbb pair -invite file    join from afar with an invitation`

// serviceStatus asks the service for its status.
func serviceStatus() (*control.Status, error) {
	c, err := control.DialFor(control.OpStatus)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
	if err != nil {
		return nil, err
	}
	return m.Status, nil
}

// admit opens a pairing window and waits until a device joins, the window
// closes, or the user presses Ctrl+C.
func admit(stdout, stderr io.Writer) int {
	c, err := control.DialFor(control.OpPair)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPair}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Pairing code: %s %s\n\n", m.Code[:3], m.Code[3:])
	fmt.Fprintln(stdout, "On the new computer run cbb pair and type the code.")
	if m.Address != "" {
		fmt.Fprintf(stdout, "If it cannot find this one: cbb pair -code %s\n", m.Address)
	}
	fmt.Fprintf(stdout, "\nWaiting up to %d minutes. Press Ctrl+C to cancel.\n", m.Expires/60)
	m, err = c.Receive()
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s joined the group.\n", m.Name)
	adminHint(stdout)
	return 0
}

// cmdPairPhone opens an iPhone pairing window and walks the user through
// it: the profile first, the fingerprint, and only then the code. With
// newToken the service first revokes the token of every shortcut.
func cmdPairPhone(newToken bool, stdout, stderr io.Writer) int {
	c, err := control.DialFor(control.OpPairPhone)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPairPhone, NewToken: newToken}})
	if err != nil {
		return fail(stderr, err)
	}
	if newToken {
		fmt.Fprintln(stdout, "The tokens of every shortcut paired so far are revoked; pair each iPhone again.")
		fmt.Fprintln(stdout)
	}
	fmt.Fprintln(stdout, "Scan this with the iPhone's camera and follow the page:")
	fmt.Fprintln(stdout)
	if err := writeQR(stdout, "http://"+m.Address+"/"); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "\n  (or open http://%s/ in Safari)\n\n", m.Address)
	fmt.Fprintf(stdout, "The profile's fingerprint must start with:  %s\n", shortFingerprint(m.Fingerprint))
	fmt.Fprintln(stdout, "  Compare it on the iPhone before you trust the profile: Settings > General >")
	fmt.Fprintln(stdout, "  VPN & Device Management > Clipboard Bridge > More Details. Only this terminal")
	fmt.Fprintln(stdout, "  shows the right one; if it differs, remove the profile and stop.")
	fmt.Fprintf(stdout, "The code the shortcut asks for:            %s %s\n", m.Code[:3], m.Code[3:])
	fmt.Fprintf(stdout, "\nWaiting up to %d minutes. Press Ctrl+C to cancel.\n", m.Expires/60)
	if _, err := c.Receive(); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "The iPhone is paired. Press the shortcut to sync.")
	return 0
}

// shortFingerprint returns the first eight groups of a fingerprint, the part
// the user compares.
func shortFingerprint(fp string) string {
	if len(fp) > 23 {
		return fp[:23]
	}
	return fp
}

// joinWithCode joins the group with the code that cbb pair shows on the
// group's root or an admin, at address or at the member that announces an
// open window. The code comes from standard input, never from the command
// line, where other users of the machine could read it.
func joinWithCode(line, address string, stdout, stderr io.Writer) int {
	code, err := pair.NormalizeCode(line)
	if err != nil {
		return fail(stderr, err)
	}
	c, err := control.DialFor(control.OpJoin)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Code: code, Address: address}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "Joined the group.")
	return 0
}

// joinByQR joins a group by the QR code the phone scans, the group's main
// device: it shows the QR code and waits for the window the phone opens.
// Meanwhile the user may type the code that cbb pair shows on a computer
// of the group instead.
func joinByQR(stdin io.Reader, stdout, stderr io.Writer) int {
	h := control.Header{Op: control.OpJoin, Code: pair.NewCode(), Expires: int(pair.Lifetime / time.Second), Listen: true}
	c, err := control.DialFor(control.OpJoin)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h})
	if err != nil {
		return fail(stderr, err)
	}
	// The service listens and answers first with where, for the QR code,
	// then once more when the join ends.
	if len(m.Addrs) == 0 {
		return fail(stderr, errors.New("this device has no address on the home network; connect it to the network, or use cbb pair -code"))
	}
	fmt.Fprintln(stdout, "In the Clipboard Bridge app, tap \"Connect a new device\" (or run the shortcut")
	fmt.Fprintln(stdout, "\"clipboardbridge: add a computer\") and scan this:")
	fmt.Fprintln(stdout)
	jc := phone.JoinCode{Code: h.Code, Addrs: m.Addrs, Fingerprint: m.Fingerprint}
	text := phone.JoinQR(jc)
	if err := writeQR(stdout, text); err != nil {
		return fail(stderr, err)
	}
	// The same code as text, for a phone without a camera, such as the
	// app in the iOS simulator.
	fmt.Fprintf(stdout, "\nOr paste this into the app: %s\n", text)
	fmt.Fprintf(stdout, "\nWaiting up to %d minutes. Press Ctrl+C to cancel.\n", h.Expires/60)
	port, err := service.Port()
	if err != nil {
		port = service.MemberPort
	}
	fmt.Fprintf(stdout, "If the phone cannot connect, a firewall may be in the way: TCP %d must be open to\n", port)
	fmt.Fprintln(stdout, "the home network; the installer opens it in ufw or firewalld (docs/guide/install.md).")
	fmt.Fprint(stdout, "\nWithout a phone: run cbb pair on the group's root or an admin and type its code here: ")

	ended := make(chan error, 1)
	go func() {
		_, err := c.Receive()
		ended <- err
	}()
	lines := make(chan string)
	go func() {
		for {
			line, err := readLine(stdin)
			if err != nil {
				return // no terminal, or it closed: the phone may still come
			}
			lines <- line
		}
	}()
	for {
		select {
		case err := <-ended:
			if err != nil {
				return fail(stderr, err)
			}
			fmt.Fprintln(stdout, "\nJoined the group.")
			return 0
		case line := <-lines:
			if line == "" {
				continue
			}
			if _, err := pair.NormalizeCode(line); err != nil {
				fmt.Fprintf(stderr, "cbb: %v; type the six digits again: ", err)
				continue
			}
			// Any message ends the wait for the phone; the join with the
			// code starts once the service has said so.
			c.Send(&control.Message{Header: control.Header{Op: control.OpAnswer}})
			<-ended
			return joinWithCode(line, "", stdout, stderr)
		}
	}
}

func readLine(r io.Reader) (string, error) {
	var b strings.Builder
	buf := make([]byte, 1)
	for b.Len() < 64 {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			if err == io.EOF && b.Len() > 0 {
				break
			}
			return "", err
		}
	}
	return strings.TrimSpace(b.String()), nil
}

// cmdAgent links the desktop's clipboard to the service: the Mac's
// pasteboard, where launchd starts it in the user's session; the Windows
// clipboard, started at sign-in; a Linux or FreeBSD desktop's clipboard,
// started with the desktop session.
func cmdAgent(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "cbb: agent takes no arguments")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" {
		logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
		return runDesktop(ctx, logf, stderr)
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return fail(stderr, fmt.Errorf("the agent has no clipboard to link on %s", runtime.GOOS))
	}
	stderr, closeLog, err := agentLog(stderr)
	if err != nil {
		return fail(stderr, err)
	}
	defer closeLog()
	if !firstAgent() {
		return 0 // another agent links this session's clipboard already
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	if err := letServiceQuery(); err != nil {
		logf("cbb: the service may not see who runs this agent, so it gets no remote pastes or quick actions: %v", err)
	}
	b := pasteboard.General()
	if _, _, err := b.Read(); errors.Is(err, pasteboard.ErrUnsupported) {
		return fail(stderr, err)
	}
	w := pasteboard.NewWatch(b)
	if err := connector.Run(ctx, connector.Config{Socket: control.SocketPath(), Board: w, Target: agentTarget(w), Actor: actions.Session(), Commands: true, Files: receivedFiles(), Logf: logf}); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// cmdService runs the service; systemd and launchd start it.
func cmdService(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state", defaultStateDir(), "the directory for the identity and the clock mark")
	socket := fs.String("socket", control.SocketPath(), "the control socket")
	runUser := fs.String("user", "", "started as root, run as this user after opening the mDNS sockets (FreeBSD's rc script)")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "cbb: service takes only flags")
		return 2
	}
	if *runUser != "" {
		if err := runAs(*runUser, func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }); err != nil {
			return fail(stderr, err)
		}
	}
	// For tests, the release roots in CBB_RELEASE_ROOTS, as cbb update
	// takes them.
	var roots [][]byte
	if file := os.Getenv("CBB_RELEASE_ROOTS"); file != "" {
		var err error
		if roots, err = readRoots(file); err != nil {
			return fail(stderr, err)
		}
	}
	return runService(stderr, func(ctx context.Context, logf func(string, ...any)) error {
		return service.Run(ctx, service.Config{StateDir: *stateDir, Socket: *socket, Role: node.Full, OS: hostOS(),
			Device: sysinfo.Device(strings.TrimPrefix(version.Version, "v")), Logf: logf, ReleaseRoots: roots,
			Container: service.InContainer(), KeysInFile: service.KeysInFileAllowed(), Rootless: rootless.Is()})
	})
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "clipboardbridge:", err)
	if !debugErrors() {
		return 1
	}
	if re := (*control.RequestError)(nil); errors.As(err, &re) && re.Detail != "" {
		fmt.Fprintln(stderr, "  Detail:", re.Detail)
	} else if de := (*control.DialError)(nil); errors.As(err, &de) && de.Err != nil {
		fmt.Fprintln(stderr, "  Detail:", de.Err)
	}
	return 1
}

// receivedFiles is the folder where the agent keeps the files the group
// copies, a folder for each copy, in the user's cache: ~/.cache on Linux,
// ~/Library/Caches on a Mac, %LocalAppData% on Windows. "" takes no files.
func receivedFiles() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "clipboardbridge", "received")
}

// hostOS names this computer's operating system as device records do.
func hostOS() string {
	switch runtime.GOOS {
	case "darwin":
		return group.OSMacOS
	case "windows":
		return group.OSWindows
	}
	return group.OSLinux
}

// adminHint suggests a second admin on a root computer that has none: a
// group whose root is lost is taken over by an admin (cbb takeover), or
// made anew.
func adminHint(w io.Writer) {
	c, err := control.DialFor(control.OpDevices)
	if err != nil {
		return
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpDevices}})
	if err != nil {
		return
	}
	root := false
	for _, d := range m.Devices {
		switch {
		case d.Self && d.Root:
			root = true
		case d.Admin && !d.Root:
			return
		}
	}
	if root {
		fmt.Fprintln(w, "This computer is the group's only admin. Make another computer one with cbb admin NAME,")
		fmt.Fprintln(w, "so that it can take the group over if this one is lost (cbb takeover).")
	}
}
