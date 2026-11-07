// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command cbb shares one clipboard between Apple devices and the Linux
// and Windows computers of a home network. The design is in docs/design.md.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/HunterEwok/cbb/internal/core"
	"github.com/HunterEwok/cbb/internal/version"
)

const usage = `Usage: cbb <command> [arguments]

Commands:
  copy [-secret]          Send standard input to the group.
  copy [-text TEXT] FILE...
                          Send files and folders to the group; -type png|jpeg|html FILE
                          sends one image or HTML as clipboard data.
  paste [-terminal [-lines] [-secret]]
                          Print this member's clipboard text; -terminal makes it
                          safe to paste into a terminal.
  paste -o DIR            Save the clipboard's images or files in the folder DIR.
  paste -on DEVICE [-type] [-enter] [-secret]
                          On an admin: put standard input, or this clipboard, where the
                          focus is on another device that allows remote paste.
  paste-receive [on [-enter] [-console] [-no-lock-check] | off]
                          Show, or turn on or off, remote paste on this device;
                          off -on DEVICE or off -all on an admin turns it off elsewhere.
  keyboard [on [-layout us|ru] [-rate N] [-pastes] | off | pair | type [TEXT]]
                          Make this Linux computer a Bluetooth keyboard for a TV, a tablet
                          or a computer near it: pair shows it to a new one for two minutes,
                          type types TEXT or standard input there.
  remote [add [-roku -consent] [-name NAME] ADDRESS | code CODE | cancel | remove TV
         | pastes TV on|off | type [-tv TV] [TEXT]]
                          Be the remote of a TV on the home network: an Android TV or a
                          Google TV pairs with the code it shows, a Roku over plain HTTP;
                          type types TEXT or standard input in its open text field.
  action [enable NAME [-by KINDS] [-any-key] | disable NAME | off]
                          Show this device's quick actions (lock, sleep, reboot, shutdown,
                          cancel-shutdown, restart, keyboard-layout), or turn one on or off here.
  action -on DEVICE NAME  On an admin: run the quick action NAME on another device;
                          action off -on DEVICE or -all turns them off elsewhere.
  status                  Show this device, its group and the group's devices.
  remove <name or ID>     Remove a device from the group.
  rename <name or ID> <new name>
                          Give a device of the group another name (on an admin).
  admin <name or ID>      Make a computer an admin of the group (on the group's root).
  takeover <name or ID>   Claim the group from its lost root computer (on an admin); it waits.
  takeover -delay <duration>
                          Set how long such a claim waits, 0s to 168h (on the root; 72h by default).
  keys [proven|hardware|files]
                          Show or set which keys may be the group's root, an admin or a hub
                          (on the root; hardware by default, files for a root with a key in a file).
  incoming [duration]     Show or set how long a copy from another device stays live after it
                          arrives, 5s to 1h (on the root or an admin; 1m by default): it goes
                          into the clipboard until then, and never after.
  recovery [-yubikey]     Claim the group with its recovery key, typed from the sheet or on a
                          YubiKey, when every phone with the group is lost; it waits as a
                          takeover does.
  handover <name or ID>   Let an admin take the group over at once, as a new phone (on the root).
  freeze <name or ID>     Stop an admin computer, as a stolen one, until the root decides.
  unfreeze <name or ID>   Make a frozen admin computer an admin again (on the group's root).
  resolve                 Void both histories of a key that signed two (on the group's root).
  global [on|off]         Show, or turn on or off, sync over the internet on this device.
  global hub address:port Make this device the group's hub for sync over the internet.
  global relay address:port
                          Meet the group's other devices over the internet at a relay.
  global hubs <name or ID>...
                          Set the group's main hubs, in the order they serve, before the
                          others (on the root, or an admin that may be a hub).
  forward                 Run a forwarder for hubs that clients cannot reach directly.
  relay -group TAG        Run a blind relay for groups without a hub.
  new                     Create a group with this computer as its root.
  leave [-yes]            Leave the group: delete this device's keys and the group's files,
                          keep the settings; then it can join this group or another one.
  sync [on | off [-for DURATION]]
                          Show or set whether this clipboard syncs with the group; off
                          for a while, or until cbb sync on. A new device syncs.
  sync -on DEVICE on|off  On an admin: turn sync on or off on another device of the group.
  mute -on DEVICE [-for DURATION]
                          On an admin: keep a device's copies from the group for a
                          while, or until another admin's cbb unmute -on.
  unmute -on DEVICE       On an admin: end a device's mute.
  config [max-copy|max-copy-away SIZE]
                          Show or set the largest copy of images and files this device
                          sends or fetches, at home (100MiB) and away from home (25MiB).
  pair                    In a group: show a code for a new computer. In none: join one,
                          by the phone's QR code or the code from cbb pair on the group.
  pair -qr                In a group: admit the new device that shows a code and waits;
                          type its code, or paste its QR code's text.
  pair -code [address]    Join with the code from cbb pair on the root or an admin.
  pair -invite file       Join from afar with an invitation from cbb invite.
  invite [-for 1h]        Invite a device from afar: run on the group's hub.
  update [-check | -to VERSION]
                          Install the newest signed release, as root or administrator;
                          -check only says whether there is one.
  update -auto [on|off]   Show, or turn on or off, updating once a day by itself.
  version                 Print the version and the platform.
  help                    Print this help.

Rarely needed:
  network                 Take the network this computer is on now as one where the group
                          is: it publishes itself and takes connections only on those.
  install [options]       Windows, after winget: install the service from this copy
                          (the options of install.ps1, such as -Express).
  service                 Run the service (started by systemd, launchd or Windows).
  agent                   Link this desktop's clipboard to the service (started at sign-in).
  paste-helper tmux|console|uinput
                          Take remote pastes into tmux (started by cbb.conf)
                          or the Linux text console (the cbb-console unit).

The design is in docs/design.md.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run executes one command line and returns the exit code: 0 on success,
// 1 on a failure, 2 on a usage error.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version", "-version", "--version":
		if len(rest) > 0 {
			fmt.Fprintf(stderr, "cbb: %s takes no arguments\n", cmd)
			return 2
		}
		fmt.Fprintln(stdout, version.String())
		// The group's rules: the Rust core in a release build.
		fmt.Fprintln(stdout, "rules: "+core.Rules())
		if w := noPasteboard(); w != "" {
			fmt.Fprintln(stdout, w)
		}
		return 0
	case "copy":
		return cmdCopy(rest, stdin, stdout, stderr)
	case "paste":
		return cmdPaste(rest, stdin, stdout, stderr)
	case "paste-receive":
		return cmdPasteReceive(rest, stdout, stderr)
	case "keyboard":
		return cmdKeyboard(rest, stdin, stdout, stderr)
	case "remote":
		return cmdRemote(rest, stdin, stdout, stderr)
	case "action":
		return cmdAction(rest, stdin, stdout, stderr)
	case "status":
		return cmdStatus(rest, stdout, stderr)
	case "global":
		return cmdGlobal(rest, stdin, stdout, stderr)
	case "remove":
		return cmdRemove(rest, stdout, stderr)
	case "rename":
		return cmdRename(rest, stdout, stderr)
	case "install":
		return cmdInstall(rest, stdout, stderr)
	case "takeover":
		return cmdTakeover(rest, stdout, stderr)
	case "keys":
		return cmdKeys(rest, stdout, stderr)
	case "incoming":
		return cmdIncoming(rest, stdout, stderr)
	case "recovery":
		return cmdRecovery(rest, stdin, stdout, stderr)
	case "handover":
		return cmdHandover(rest, stdout, stderr)
	case "freeze", "unfreeze":
		return cmdFreeze(rest, cmd == "freeze", stdout, stderr)
	case "resolve":
		return cmdResolve(rest, stdout, stderr)
	case "admin":
		return cmdAdmin(rest, stdout, stderr)
	case "new":
		return cmdNew(rest, stdout, stderr)
	case "leave":
		return cmdLeave(rest, stdin, stdout, stderr)
	case "pair":
		return cmdPair(rest, stdin, stdout, stderr)
	case "invite":
		return cmdInvite(rest, stdin, stdout, stderr)
	case "sync":
		return cmdSync(rest, stdout, stderr)
	case "mute", "unmute":
		return cmdMute(rest, cmd == "unmute", stdout, stderr)
	case "config":
		return cmdConfig(rest, stdout, stderr)
	case "network":
		return cmdNetwork(rest, stdout, stderr)
	case "forward":
		return cmdForward(rest, stdout, stderr)
	case "relay":
		return cmdRelay(rest, stdout, stderr)
	case "service":
		return cmdService(rest, stderr)
	case "agent":
		return cmdAgent(rest, stderr)
	case "paste-helper":
		return cmdPasteHelper(rest, stderr)
	case "update":
		return cmdUpdate(rest, stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		if cmd == "cbb" && len(rest) > 0 {
			// cbb cbb status: the program's name typed twice, as after a
			// path to cbb.exe.
			fmt.Fprintf(stderr, "cbb: unknown command \"cbb\"; the command comes right after the program: cbb %s\n", strings.Join(rest, " "))
		} else {
			fmt.Fprintf(stderr, "cbb: unknown command %q; cbb help lists the commands\n", cmd)
		}
		return 2
	}
}
