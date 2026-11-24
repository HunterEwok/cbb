<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Keyboards and TVs

For anyone who wants to type a long password, URL, or search query into a TV, tablet, game
console, or computer that does not run Connect Beyond Borders. One device in your group acts as a
Bluetooth keyboard, a USB keyboard, or a network TV remote.

Keyboards and TV remotes are experimental features in [The lab](lab.md). For current testing
status on physical hardware, see [Platform parity](../parity.md#on-real-devices).

## Choose a method

| Method | Types into | Requirements |
|---|---|---|
| [Phone as a Bluetooth keyboard](#a-phone-as-a-bluetooth-keyboard) | Anything that accepts a Bluetooth keyboard: TVs, tablets, phones, computers, Steam Deck, PlayStation 5 | Android 10 or later (with Bluetooth HID profile), Aurora OS, or HarmonyOS phone |
| [Linux computer as a Bluetooth keyboard](#a-linux-computer-as-a-bluetooth-keyboard) | Anything that accepts a Bluetooth LE keyboard | Linux with BlueZ 5.50 or later, Bluetooth 4.0+ adapter, and `cbb-helper` |
| [Arduino Nano ESP32 as a USB or Bluetooth keyboard](#the-nano-esp32-as-a-usb-or-bluetooth-keyboard) | Anything with USB or BLE keyboard input—including BIOS/UEFI, disk-encryption prompts, Xbox, and Nintendo Switch over USB | An Arduino Nano ESP32 flashed with `esp32/` firmware |
| [Computer as a TV remote](#a-computer-as-the-tvs-remote) | Android TV, Google TV, Apple TV, or Roku on your home network | Linux, macOS, Windows, or FreeBSD computer at home with `cbb-helper` |

Xbox and Nintendo Switch accept USB keyboards only, so use the Arduino Nano ESP32 for those
consoles. iPhone, macOS, and Windows do not allow apps to act as a Bluetooth keyboard.

## Match the keyboard layout and speed

A Bluetooth or USB keyboard sends physical key codes, not characters: the target device turns each
key code into a character using its active keyboard layout.

- **Layout:** Set the keyboard layout in Connect Beyond Borders to match the layout active on the
  target device—**English (US)** (`us`) or **Russian** (`ru`). If your text contains a character
  the chosen layout cannot type, Connect Beyond Borders refuses the whole text and names the
  unsupported characters instead of typing wrong ones. Line breaks send Enter and tabs send Tab.
- **Speed:** Typing defaults to **20 characters a second** because some TVs drop keys that arrive
  faster. Lower the speed (for example, to 10 characters a second) if characters go missing.
- **Length limit:** A Bluetooth or USB keyboard types at most **4,096 characters** at a time.

## A phone as a Bluetooth keyboard

Supported on **Android**, **Aurora OS**, and **HarmonyOS** phones.

1. Open **CBB**, go to **Settings**, turn on **Advanced settings**, and open **Lab > Bluetooth
   keyboard**.
2. Turn on **Act as a Bluetooth keyboard** and allow Bluetooth permission if asked.
   - On Android, if the app reports that the phone cannot act as a keyboard, the device maker
     omitted the Bluetooth HID Device profile; use another method. If another app holds the
     keyboard profile, turn it off there first because Android allows only one keyboard app at a
     time.
3. Pair the target device with your phone:
   - **Android:** Tap **Make this phone visible** (discoverable for 2 minutes), pair your phone in
     the target device's Bluetooth settings, then select the target under **Type into**.
   - **Aurora OS:** Tap **Make this phone visible** (discoverable for 2 minutes) and connect to
     `CBB keyboard` from the target device's Bluetooth settings.
   - **HarmonyOS:** While the keyboard switch is on, connect to your phone by its device name from
     the target device's Bluetooth settings.

   **Result:** The screen shows `Connected to …` (or `A device is connected.`).

4. Set **The device's keyboard layout** (`English (US)` or `Russian`) and, if needed, **Speed**
   (`10`, `20`, or `40` characters a second).
5. Focus a text field on the target device, then tap **Type the clipboard** (on HarmonyOS, tap the
   system **Paste** button next to **Type the clipboard**).

**Result:** Your phone types the clipboard text into the focused field on the target device.

## A Linux computer as a Bluetooth keyboard

Run these commands on a Linux computer with `cbb-helper` installed:

1. Register the Bluetooth LE keyboard with BlueZ:

   ```sh
   sudo cbb keyboard on -layout us
   ```

   Optional flags: `-rate N` (5 to 60 characters a second; default 20) and `-pastes` (routes
   incoming [remote pastes](remote-paste.md) to the paired Bluetooth device instead of this
   computer's screen; line breaks require `sudo cbb paste-receive on -enter`).

2. Make the computer discoverable for 2 minutes:

   ```sh
   sudo cbb keyboard pair
   ```

3. On the target device, open its Bluetooth settings and pair with `CBB <your computer name>`.
4. Check the connection and type text:

   ```sh
   cbb keyboard
   echo 'the text' | sudo cbb keyboard type
   ```

**Result:** `cbb keyboard` confirms that a device is connected, and `cbb keyboard type` prints
`Typed.` after sending the text. Your Linux computer's own Bluetooth keyboards and mice keep
working normally.

To turn the Bluetooth keyboard off, run `sudo cbb keyboard off`.

## The Nano ESP32 as a USB or Bluetooth keyboard

The [Arduino Nano ESP32 firmware](../../esp32/README.md) runs a USB boot keyboard and a Bluetooth
LE keyboard controlled from its serial console (joining a group and clipboard syncing are on the
[roadmap](../roadmap.md)).

1. Connect to the board's serial console and choose a mode:
   - **USB keyboard:** Run `usb keyboard`. The board restarts with its USB-C port acting as both a
     boot keyboard (working in BIOS/UEFI, disk-encryption prompts, and consoles) and a serial
     console. Plug the board into the target device.
   - **Bluetooth LE keyboard:** Run `ble on`, then `ble pair`, and pair `CBB Nano ESP32` in the
     target device's Bluetooth settings within 2 minutes. The board remembers up to 4 paired hosts
     (`ble forget` clears them).
2. Set the target's layout and typing speed:

   ```text
   layout us
   rate 20
   ```

   Use `layout ru` for Russian.
3. On firmware built with `--features console-type`, type text with:

   ```text
   type hello world
   ```

**Result:** The board types on the connected Bluetooth host if one is active, or on the USB
keyboard otherwise.

## A computer as the TV's remote

Any Linux, macOS, Windows, or FreeBSD computer with `cbb-helper` on your home network can type
into an Android TV, Google TV, Apple TV, or Roku over the local network. Nothing is installed on
the TV, and the TV never joins your group. Use `sudo` on Unix systems (omit `sudo` in an
administrator terminal on Windows).

### 1. Pair or add the TV

Choose the commands for your TV:

- **Android TV or Google TV:**

  ```sh
  sudo cbb remote add -name living-room-tv living-room-tv.lan
  sudo cbb remote code
  ```

  Type the 6-digit code shown on the TV screen within 2 minutes.

- **Apple TV:** First set **Settings > AirPlay and HomeKit > Allow Access** on the Apple TV to
  **Everyone on the Same Network** (**Only People Sharing This Home** refuses pairing). Then run:

  ```sh
  sudo cbb remote add -appletv -name lounge 192.168.1.30
  sudo cbb remote code
  ```

  Type the 4-digit PIN shown on the Apple TV within 2 minutes.

- **Roku:** Roku's External Control Protocol uses unencrypted HTTP with no pairing. First set
  **Settings > System > Advanced system settings > Control by mobile apps** on the Roku to
  **Enabled** or **Permissive**. Then add it with `-consent`:

  ```sh
  sudo cbb remote add -roku -consent 192.168.1.40
  ```

**Result:** Run `cbb remote` with no arguments to verify that the TV appears in your list.

### 2. Type into the TV or forward remote pastes

1. Open a search box or text field on the TV using its own remote.
2. Type text from the computer:

   ```sh
   echo 'the film' | sudo cbb remote type
   ```

   Add `-tv NAME` when you have more than one TV configured. On Android TV and Roku, line breaks
   press Enter; on Apple TV, line breaks stay inside the text.

   **Result:** The text appears in the TV's focused text field and `cbb remote type` prints
   `Typed.`

3. Optionally route incoming [remote pastes](remote-paste.md) from your group's admins to the TV
   (one TV at a time; line breaks require `sudo cbb paste-receive on -enter`):

   ```sh
   sudo cbb remote pastes living-room-tv on
   ```

To forget a TV, run `sudo cbb remote remove NAME`. If an Android TV or Apple TV is reset or
forgets your computer, pair it again.

## Safety

- **Bluetooth keyboards:** A Bluetooth keyboard types wherever the paired device has keyboard
  focus. Pair only with devices you intend to control, and forget the pairing on both sides when
  you stop using it.
- **Remote pastes to keyboards and TVs:** While remote paste forwarding is on (`-pastes` or
  `cbb remote pastes TV on`), any admin in your group can type into that device. Turning remote
  paste off stops forwarding as well.
- **Home network only for TVs:** `cbb remote` connects only to addresses on your home network and
  refuses any address outside it.
- **No passwords to a Roku:** Text sent to a Roku crosses your home network as plain HTTP. Never
  send passwords or other secrets to a Roku.

For all CLI flags, see [Commands](../reference/cli.md). For TV network ports, see
[Devices, ports and files](../reference/devices.md#ports).
