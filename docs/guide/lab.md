<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The lab

For anyone curious about experimental Connect Beyond Borders features beyond everyday clipboard
syncing.

Connect Beyond Borders focuses on one core promise: a single encrypted clipboard shared across
your phones and computers. The lab is where additional ways to use your group are tested. Every
experiment below builds and passes automated tests in CI, but these features are experimental:
they may change or be removed, and most have limited testing on physical hardware. See
[Platform parity](../parity.md#on-real-devices) for current real-hardware status.

## Experiments

| Experiment | What it does | Guide |
|---|---|---|
| **Bluetooth and USB keyboards** | An Android, Aurora OS, or HarmonyOS phone, a Linux computer, or an Arduino Nano ESP32 types text into a TV, tablet, game console, or computer that does not run Connect Beyond Borders | [Keyboards and TVs](keyboards-and-tvs.md) |
| **TV remotes** | A computer on your home network types directly into an Android TV, Google TV, Apple TV, or Roku over the local network as its remote | [Keyboards and TVs](keyboards-and-tvs.md#a-computer-as-the-tvs-remote) |
| **Arduino Nano ESP32** | Low-cost microcontroller firmware running Wi-Fi, a TLS 1.3 protocol self-test, and a USB and Bluetooth LE keyboard (joining a group and clipboard syncing are on the [roadmap](../roadmap.md)) | [ESP32 firmware](../../esp32/README.md) |
| **ZX Spectrum Next** | Copies text and secrets, pastes text, displays group images on Layer 2, and receives remote paste through the Raspberry Pi inside an Accelerated Next | [`.cbb` for the Next](../../apps/zxnext/README.md) |

## Where to find lab features

- **Phone apps (Android, Aurora OS, and HarmonyOS):** Open **Settings**, turn on **Advanced
  settings**, and scroll to **Lab** (contains the **Bluetooth keyboard** controls).
- **Computers:** Use `cbb keyboard` (Linux) and `cbb remote` (Linux, macOS, Windows, and FreeBSD)
  in a terminal; see [Commands](../reference/cli.md).
- **ESP32 and ZX Spectrum Next:** Follow each device's setup instructions linked in the table
  above.

## Share feedback

If you try an experiment on real hardware, report how it works in a
[GitHub issue](https://github.com/HunterEwok/cbb/issues). Experiments that prove reliable on real
devices may move out of the lab into supported features.
