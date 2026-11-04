module github.com/HunterEwok/cbb/apps/desktop

go 1.27.0

toolchain go1.27.3

require (
	github.com/HunterEwok/cbb v0.0.0
	github.com/coder/websocket v1.8.15
	github.com/godbus/dbus/v5 v5.2.2
	github.com/wailsapp/wails/v3 v3.0.0-beta.34
	golang.org/x/sys v0.49.0
	rsc.io/qr v0.2.0
)

require (
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
)

// The app speaks the service's control socket with the service's own code.
replace github.com/HunterEwok/cbb => ../..

// Wails asks for godbus 5.2.2, and godbus 5.2.0 to 5.2.4 stop the program
// on a message with an array of file descriptors, which any peer on the
// session bus may send (.github/dependabot.yml); 5.1.0, as the service
// uses, has the same API. Drop this once a fixed 5.2 is out.
replace github.com/godbus/dbus/v5 => github.com/godbus/dbus/v5 v5.1.0
