module github.com/HunterEwok/clipboardbridge

go 1.27.0

toolchain go1.27.3

tool (
	github.com/rhysd/actionlint/cmd/actionlint
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
	golang.org/x/vuln/cmd/govulncheck
	honnef.co/go/tools/cmd/staticcheck
)

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/amnezia-vpn/amneziawg-go v0.2.20-0.20260724121833-457d920a1a7d
	github.com/godbus/dbus/v5 v5.2.4
	github.com/google/go-tpm v0.9.8
	github.com/jezek/xgb v1.3.1
	github.com/tetratelabs/wazero v1.12.0
	github.com/xtls/reality v0.0.0-20261014101318-83f621788ca8
	github.com/xtls/xray-core v1.260327.1-0.20261021115930-1b1647cd9ddf
	github.com/yuin/goldmark v1.8.6
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
	google.golang.org/protobuf v1.36.12
	gvisor.dev/gvisor v0.0.0-20260122175437-89a5d21be8f0
	rsc.io/qr v0.2.0
)

require (
	github.com/andybalholm/brotli v1.2.3 // indirect
	github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e // indirect
	github.com/bmatcuk/doublestar/v4 v4.10.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.21 // indirect
	github.com/mattn/go-shellwords v1.0.12 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/pires/go-proxyproto v0.15.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af // indirect
	github.com/rhysd/actionlint v1.7.12 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/yuin/gopher-lua v1.1.2 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.3 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto/x509roots/fallback v0.0.0-20261020153306-9f2b28d4331a // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mobile v0.0.0-20261011034528-197770444867 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/telemetry v0.0.0-20261010193011-f71dc92da45e // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.9.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/grpc v1.84.0 // indirect
	honnef.co/go/tools v0.8.2 // indirect
	layeh.com/gopher-luar v1.0.11 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)

// A copy with a fix for a data race in its timers; see its README.md.
replace github.com/amnezia-vpn/amneziawg-go => ./internal/third_party/amneziawg-go
