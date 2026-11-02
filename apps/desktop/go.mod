module github.com/HunterEwok/clipboardbridge/apps/desktop

go 1.27.0

toolchain go1.27.3

require (
	github.com/HunterEwok/clipboardbridge v0.0.0
	github.com/coder/websocket v1.8.15
	github.com/godbus/dbus/v5 v5.2.2
	github.com/wailsapp/wails/v3 v3.0.0-beta.34
	golang.org/x/sys v0.49.0
)

require (
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
)

// The app speaks the service's control socket with the service's own code.
replace github.com/HunterEwok/clipboardbridge => ../..
