# The lite member's network code on embassy-net

The part of the [Nano ESP32 firmware](../esp32) that needs a network and nothing of the
chip: joining a group by the phone (`src/pair.rs`), on
[embassy-net](https://docs.embassy.dev/embassy-net/) TCP around the TLS of `core/`.
It is `no_std` with `alloc`, like the core.

With the feature `host` the crate also builds `esp32-on-linux`, the same code as a Linux
program: embassy-net runs over a TAP interface with a fixed address instead of the chip's
Wi-Fi and DHCP, so the pairing can be tested without the board.

```sh
sudo ip tuntap add name tap0 mode tap user "$USER"
sudo ip addr add 192.168.69.1/24 dev tap0 && sudo ip link set tap0 up
cargo build --release -p cbb-embassy --features host
target/release/esp32-on-linux -tap tap0 -addr 192.168.69.2/24 -name board -identity identity.json
```

It prints the `cbb://join` link to paste into the app, waits up to five minutes
for the phone, and writes the identity the phone's Welcome gives it to the file. `-debug`
shows the details of errors. The Go test `TestEmbassyJoiner` (internal/service) plays the
phone.
