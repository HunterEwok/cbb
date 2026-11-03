// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// wlEnv reaches the Wayland display of the signed-in session.
const wlEnv = `XDG_RUNTIME_DIR=/run/user/$(id -u) WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-wayland-0} `

// linuxDesktop runs the cases of the Linux member's desktop: the primary
// selection (Y26), formatted text and images to the other desktops (O4,
// O1), the X11 apps of a Wayland session (H1), the keys helper's limits
// (T15), the text console's tmux (H4), where its keys live (K13) and
// files through the Flatpak portals (O12).
func linuxDesktop(ctx context.Context, r *Report, g *benchGroup, l *Device, desks []*Device, timeout time.Duration) {
	p := "desktop/linux/" + l.Name
	if l.Clipboard != "x11" && l.Clipboard != "wayland" {
		r.Skip(p, "the Linux member has no desktop clipboard")
		return
	}
	primarySelection(ctx, r, g, l, desks, timeout)
	for _, d := range desks {
		formats(ctx, r, g.run, l, d, timeout)
	}
	sessionKinds(ctx, r, g.run, l, desks, timeout)
	keysHelper(ctx, r, l)
	consoleTmux(ctx, r, l)
	tpmKeys(ctx, r, g, l)
	if len(desks) > 0 {
		flatpakFiles(ctx, r, g.run, l, desks[0], timeout)
	}
}

// primarySelection (Y26): a text from the group lands in the primary
// selection too, for the middle button; a selection made with the mouse,
// which sets only the primary selection, is not sent.
func primarySelection(ctx context.Context, r *Report, g *benchGroup, l *Device, desks []*Device, timeout time.Duration) {
	if len(desks) == 0 {
		r.Skip("desktop/Y26-primary/"+l.Name, "needs a Mac or a Windows PC beside the Linux member")
		return
	}
	d := desks[0]
	primary := func() (string, error) {
		if l.Clipboard == "wayland" {
			return Run(ctx, l, wlEnv+"timeout 5 wl-paste --primary -n 2>/dev/null || true", "")
		}
		return Run(ctx, l, x11Env+"timeout 5 xclip -selection primary -o 2>/dev/null || true", "")
	}
	r.Do("desktop/Y26-primary/"+l.Name+"/written", func() error {
		text := fmt.Sprintf("cbb-bench %s Y26 for the middle button", g.run)
		if err := Copy(ctx, d, text); err != nil {
			return err
		}
		want := seen(text, d, l)
		return eventually(ctx, timeout, func() error {
			got, err := primary()
			if err == nil && got != want {
				err = fmt.Errorf("the primary selection on %s holds %s", l.Name, describe(got))
			}
			return err
		})
	})
	r.Do("desktop/Y26-primary/"+l.Name+"/selection-not-sent", func() error {
		text := fmt.Sprintf("cbb-bench %s Y26 selected with the mouse", g.run)
		var err error
		if l.Clipboard == "wayland" {
			_, err = Run(ctx, l, wlEnv+"wl-copy --primary >/dev/null 2>&1", text)
		} else {
			_, err = Run(ctx, l, x11Env+"xclip -selection primary -i >/dev/null 2>&1", text)
		}
		if err != nil {
			return err
		}
		return notSent(ctx, d, seen(text, l, d), "a mouse selection")
	})
}

// formats (O4, O1): formatted text and a PNG copied on the Linux member
// reach the desktop d as formatted text and as an image, and the members
// without a desktop clipboard get the plain text.
func formats(ctx context.Context, r *Report, run string, l, d *Device, timeout time.Duration) {
	put := func(mime, data string) error {
		if l.Clipboard == "wayland" {
			_, err := Run(ctx, l, wlEnv+"wl-copy -t "+mime+" >/dev/null 2>&1", data)
			return err
		}
		_, err := Run(ctx, l, x11Env+"xclip -selection clipboard -t "+mime+" -i >/dev/null 2>&1", data)
		return err
	}
	hasType := func(want ...string) error {
		return eventually(ctx, timeout, func() error {
			types, err := clipTypes(ctx, d)
			if err != nil {
				return err
			}
			for _, w := range want {
				if strings.Contains(strings.ToLower(types), strings.ToLower(w)) {
					return nil
				}
			}
			return fmt.Errorf("the clipboard of %s holds %q, none of %q", d.Name, types, want)
		})
	}
	r.Do("desktop/O4-html/"+l.Name+"-to-"+d.Name, func() error {
		word := fmt.Sprintf("cbb-bench-%s-O4", run)
		if err := put("text/html", "<p><b>"+word+"</b> formatted</p>"); err != nil {
			return err
		}
		// macOS names it public.html, Windows HTML Format.
		if err := hasType("public.html", "HTML Format"); err != nil {
			return err
		}
		got, err := Paste(ctx, d)
		if err == nil && !strings.Contains(got, word) {
			err = fmt.Errorf("the plain text beside the HTML on %s is %s", d.Name, describe(got))
		}
		return err
	})
	r.Do("desktop/O1-png/"+l.Name+"-to-"+d.Name, func() error {
		// A PNG made by the bench's own Python: 4x4 pixels of the run's
		// colour, so each run's image differs.
		png, err := Run(ctx, l, `python3 -c 'import sys,zlib,struct,hashlib
c=hashlib.sha256(sys.argv[1].encode()).digest()[:3]
raw=b"".join(b"\0"+c*4 for _ in range(4))
def ch(t,d): return struct.pack(">I",len(d))+t+d+struct.pack(">I",zlib.crc32(t+d))
sys.stdout.buffer.write(b"\x89PNG\r\n\x1a\n"+ch(b"IHDR",struct.pack(">IIBBBBB",4,4,8,2,0,0,0))+ch(b"IDAT",zlib.compress(raw))+ch(b"IEND",b""))' `+shellQuote(run)+` >/tmp/o1.png && echo ok`, "")
		if err != nil || strings.TrimSpace(png) != "ok" {
			return fmt.Errorf("making the PNG on %s: %v %s", l.Name, err, png)
		}
		if l.Clipboard == "wayland" {
			_, err = Run(ctx, l, wlEnv+"wl-copy -t image/png </tmp/o1.png >/dev/null 2>&1", "")
		} else {
			_, err = Run(ctx, l, x11Env+"xclip -selection clipboard -t image/png -i /tmp/o1.png >/dev/null 2>&1", "")
		}
		if err != nil {
			return err
		}
		return hasType("public.png", "PNG", "Bitmap")
	})
}

// sessionKinds (H1): on a GNOME or KDE Wayland session, an X11 program's
// copy (through XWayland) reaches the group as a native program's does.
func sessionKinds(ctx context.Context, r *Report, run string, l *Device, desks []*Device, timeout time.Duration) {
	p := "desktop/H1-session/" + l.Name
	if len(desks) == 0 {
		r.Skip(p, "needs a Mac or a Windows PC beside the Linux member")
		return
	}
	d := desks[0]
	r.Do(p+"/kind", func() error {
		out, err := Run(ctx, l, `loginctl show-session $(loginctl show-seat seat0 -p ActiveSession --value) -p Type -p Desktop --value 2>/dev/null | paste -sd' ' -`, "")
		if err != nil {
			return err
		}
		r.Note(p+"/kind", "the session on the screen: "+strings.TrimSpace(out))
		return nil
	})
	if l.Clipboard != "wayland" {
		return
	}
	r.Do(p+"/xwayland", func() error {
		out, err := Run(ctx, l, "command -v xclip >/dev/null && ls /run/user/$(id -u)/.mutter-Xwaylandauth.* /tmp/.X11-unix/X0 2>/dev/null | head -n1", "")
		if err != nil || strings.TrimSpace(out) == "" {
			return Skipped("no XWayland or xclip on " + l.Name)
		}
		text := fmt.Sprintf("cbb-bench %s H1 from an X11 program", run)
		if _, err := Run(ctx, l, x11Env+"xclip -selection clipboard -i >/dev/null 2>&1", text); err != nil {
			return err
		}
		return arrives(ctx, d, seen(text, l, d), timeout)
	})
}

// keysHelper (T15): the uinput keys helper presses only paste and enter,
// and only for a remote paste the service handed to the session's user;
// another user is refused.
func keysHelper(ctx context.Context, r *Report, l *Device) {
	p := "desktop/T15-keys-helper/" + l.Name
	ask := func(user, line string) (string, error) {
		py := `python3 -c 'import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect("/run/cbb-keys/keys")
s.sendall(sys.argv[1].encode()+b"\n"); print(s.makefile().readline().strip())' ` + shellQuote(line)
		if user != "" {
			py = "sudo -n -u " + user + " " + py
		}
		out, err := Run(ctx, l, py, "")
		return strings.TrimSpace(out), err
	}
	if r.Do(p+"/present", func() error {
		out, err := Run(ctx, l, "test -S /run/cbb-keys/keys && echo yes || true", "")
		if err == nil && strings.TrimSpace(out) != "yes" {
			return Skipped("the keys helper is off on " + l.Name + " (cbb paste-helper uinput on)")
		}
		return err
	}) != nil {
		return
	}
	for _, c := range []struct{ name, line, want string }{
		{"only-paste-and-enter", "type a", "error the keys helper presses paste or enter"},
		{"needs-a-grant", "paste", "refused the keys helper presses keys only for a remote paste"},
		{"grant-checked", "paste forged-grant", "refused"},
	} {
		r.Do(p+"/"+c.name, func() error {
			got, err := ask("", c.line)
			if err == nil && !strings.HasPrefix(got, c.want) {
				err = fmt.Errorf("the helper answered %q to %q, not %q…", got, c.line, c.want)
			}
			return err
		})
	}
	r.Do(p+"/other-user", func() error {
		got, err := ask("nobody", "paste forged-grant")
		if err != nil {
			return Skipped("cannot act as another user on " + l.Name + " (sudo -n -u nobody)")
		}
		if !strings.HasPrefix(got, "refused") && !strings.HasPrefix(got, "error") {
			return fmt.Errorf("the helper answered %q to another user", got)
		}
		return nil
	})
}

// consoleTmux (H4): a login on a text console, with the login snippet
// installed, starts tmux there.
func consoleTmux(ctx context.Context, r *Report, l *Device) {
	p := "desktop/H4-console/" + l.Name
	r.Do(p, func() error {
		out, err := Run(ctx, l, "test -f /etc/profile.d/cbb-console.sh && command -v tmux >/dev/null && command -v openvt >/dev/null && sudo -n true 2>/dev/null && echo yes || true", "")
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "yes" {
			return Skipped("needs the console snippet (install.sh --console), tmux, openvt and sudo on " + l.Name)
		}
		// A login shell on console 12, as the user, kept open for a while.
		if _, err := Run(ctx, l, `sudo -n openvt -c 12 -f -- su -l "$(id -un)" -c 'TERM=linux exec bash -l' ; true`, ""); err != nil {
			return err
		}
		defer Run(context.WithoutCancel(ctx), l, "tmux kill-session -t console-tty12 2>/dev/null; sudo -n pkill -t tty12 2>/dev/null; true", "")
		return eventually(ctx, 15*time.Second, func() error {
			out, err := Run(ctx, l, "tmux ls 2>/dev/null || true", "")
			if err == nil && !strings.Contains(out, "console-tty12") {
				err = fmt.Errorf("no tmux session console-tty12 after a console login; tmux has %q", strings.TrimSpace(out))
			}
			return err
		})
	})
}

// tpmKeys (K13): a Linux member whose keys the installer put in the TPM
// says so in the group's device list: hardware, or proven hardware when
// its TPM's endorsement certificate vouched for the key.
func tpmKeys(ctx context.Context, r *Report, g *benchGroup, l *Device) {
	p := "desktop/K13-tpm/" + l.Name
	r.Do(p, func() error {
		out, err := Run(ctx, l, "test -c /dev/tpmrm0 && echo yes || true", "")
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "yes" {
			return Skipped(l.Name + " has no TPM")
		}
		return eventually(ctx, 60*time.Second, func() error {
			list, err := Run(ctx, g.hub, cbbCmd(g.hub)+" devices", "")
			if err != nil {
				return err
			}
			for _, line := range strings.Split(list, "\n") {
				if !strings.Contains(line, l.Name) {
					continue
				}
				switch {
				case strings.Contains(line, "proven hardware"):
					r.Note(p, "the TPM's endorsement vouched for the key")
					return nil
				case strings.Contains(line, "hardware"):
					r.Note(p, "keys in the TPM, without an endorsement certificate to prove it")
					return nil
				}
				return fmt.Errorf("the hub lists %s as %q, with its keys not in hardware", l.Name, strings.TrimSpace(line))
			}
			return fmt.Errorf("the hub's device list has no %s", l.Name)
		})
	})
}

// pasteFile is what the file name holds in the copy that d's cbb paste -o
// saves into a new folder.
func pasteFile(ctx context.Context, d *Device, name string, timeout time.Duration) (string, error) {
	if d.OS == "windows" {
		return RunFor(ctx, d, `$o = Join-Path $env:TEMP 'cbb-bench-paste'; Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $o; New-Item -ItemType Directory $o | Out-Null; `+cbbCmd(d)+` paste -o $o | Out-Null; Get-Content -Raw (Join-Path $o '`+name+`')`, "", timeout)
	}
	return RunFor(ctx, d, "o=/tmp/cbb-bench-paste; rm -rf $o && mkdir $o && "+cbbCmd(d)+" paste -o $o >/dev/null && cat $o/"+name, "", timeout)
}

// copyFile makes a file name holding text in d's temporary folder and
// copies it with cbb copy.
func copyFile(ctx context.Context, d *Device, name, text string) error {
	var err error
	if d.OS == "windows" {
		_, err = RunFor(ctx, d, `$f = Join-Path $env:TEMP '`+name+`'; [IO.File]::WriteAllText($f, '`+strings.ReplaceAll(text, "'", "''")+`'); `+cbbCmd(d)+` copy $f`, "", time.Minute)
	} else {
		_, err = RunFor(ctx, d, "printf %s "+shellQuote(text)+" >/tmp/"+name+" && "+cbbCmd(d)+" copy /tmp/"+name, "", time.Minute)
	}
	return err
}

// flatpakFiles (O12): a file a Flatpak app copies is under the document
// portal's /run/user/UID/doc, which the agent reads and sends; a file from
// the group is offered to Flatpak apps through the FileTransfer portal
// beside its path.
func flatpakFiles(ctx context.Context, r *Report, run string, l, d *Device, timeout time.Duration) {
	p := "desktop/O12-flatpak/" + l.Name
	if l.Clipboard != "wayland" {
		r.Skip(p, "checked under Wayland")
		return
	}
	text := fmt.Sprintf("cbb-bench %s O12 from a Flatpak app", run)
	r.Do(p+"/document-portal", func() error {
		if _, err := Run(ctx, l, "printf %s "+shellQuote(text)+" >/tmp/o12-doc.txt", ""); err != nil {
			return err
		}
		out, err := Run(ctx, l, "command -v flatpak >/dev/null && "+wlEnv+"flatpak document-export --app=org.cbbbench.App /tmp/o12-doc.txt", "")
		doc := strings.TrimSpace(out)
		if err != nil || !strings.HasPrefix(doc, "/run/user/") {
			return Skipped("no flatpak or document portal on " + l.Name)
		}
		defer Run(context.WithoutCancel(ctx), l, wlEnv+"flatpak document-unexport /tmp/o12-doc.txt; rm -f /tmp/o12-doc.txt", "")
		if _, err := Run(ctx, l, wlEnv+"wl-copy -t text/uri-list "+shellQuote("file://"+doc), ""); err != nil {
			return err
		}
		return eventually(ctx, timeout+time.Minute, func() error {
			got, err := pasteFile(ctx, d, "o12-doc.txt", time.Minute)
			if err == nil && strings.TrimSpace(got) != text {
				err = fmt.Errorf("%s saved %q from the document portal's file, not %q", d.Name, firstLine(got), text)
			}
			return err
		})
	})
	r.Do(p+"/file-transfer", func() error {
		has, _ := Run(ctx, l, "gdbus introspect --session -d org.freedesktop.portal.Documents -o /org/freedesktop/portal/documents 2>/dev/null | grep -c org.freedesktop.portal.FileTransfer || true", "")
		if strings.TrimSpace(has) == "0" || strings.TrimSpace(has) == "" {
			return Skipped("no FileTransfer portal on " + l.Name)
		}
		// A file copied on d reaches l's clipboard with the portal's key
		// beside its path.
		name := "cbb-bench-" + run + "-O12.txt"
		if err := copyFile(ctx, d, name, text+" written"); err != nil {
			return err
		}
		return eventually(ctx, timeout, func() error {
			types, err := Run(ctx, l, wlEnv+"wl-paste --list-types", "")
			if err != nil {
				return err
			}
			if !strings.Contains(types, "application/vnd.portal.filetransfer") {
				return fmt.Errorf("the clipboard offers %q, without the FileTransfer portal's key", strings.ReplaceAll(strings.TrimSpace(types), "\n", " "))
			}
			key, err := Run(ctx, l, wlEnv+"wl-paste -t application/vnd.portal.filetransfer", "")
			if err != nil {
				return err
			}
			got, err := Run(ctx, l, "gdbus call --session -d org.freedesktop.portal.Documents -o /org/freedesktop/portal/documents -m org.freedesktop.portal.FileTransfer.RetrieveFiles "+shellQuote(strings.TrimSpace(strings.TrimRight(key, "\x00")))+" '{}'", "")
			if err != nil {
				return fmt.Errorf("the portal gives no files for the clipboard's key: %w", err)
			}
			if !strings.Contains(got, "O12.txt") {
				return fmt.Errorf("the portal gives %q for the clipboard's key, not the file", strings.TrimSpace(got))
			}
			return nil
		})
	})
}
