<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Keyboards and TVs

For anyone who wants to type a long password, a link or a search into a TV, a tablet, a
console or a computer that has nothing of Copy Beyond Borders on it. One device of your group
types the text there as a keyboard or as the TV's remote, at your tap or when an admin sends
a remote paste.

## Pick a way

| Way | Types into | Needs |
|---|---|---|
| [An Android phone as a Bluetooth keyboard](#an-android-phone-as-a-bluetooth-keyboard) | anything that takes a Bluetooth keyboard: TVs, tablets, phones, computers, the Steam Deck, the PlayStation 5 | Android 10 or later with the Bluetooth keyboard profile |
| [A Linux computer as a Bluetooth keyboard](#a-linux-computer-as-a-bluetooth-keyboard) | anything that takes a Bluetooth LE keyboard | BlueZ 5.50 or later and an adapter with Bluetooth 4.0 or later |
| [The Nano ESP32 as a USB or Bluetooth keyboard](#the-nano-esp32-as-a-usb-or-bluetooth-keyboard) | over USB also a BIOS, a disk-encryption prompt, the Xbox and the Nintendo Switch | an Arduino Nano ESP32 in your group |
| [A computer as the TV's remote](#a-computer-as-the-tvs-remote) | an Android TV, a Google TV or a Roku on your home network | a Linux, macOS, Windows or FreeBSD computer at home |

The Xbox and the Nintendo Switch take only USB keyboards, so for them use the Nano ESP32.
macOS, Windows and iPhones let no app act as a Bluetooth keyboard.

## The layout must match

A keyboard sends keys, not characters: the device typed on turns each key into a character
with its own layout. So tell the keyboard which layout is active there, English (US) or
Russian. A text with a character that layout has no key for is not typed at all, and you are
told which characters they are; nothing else is typed in their place. A line break presses
Enter and a tab presses Tab.

Typing is slow on purpose, 20 characters a second by default: some TVs drop keys that come
faster. Turn it down if letters go missing.

## An Android phone as a Bluetooth keyboard

1. In the app, open Settings, Bluetooth keyboard, and turn on **Act as a Bluetooth
   keyboard**. Allow Bluetooth ("Nearby devices") if asked.
   If the app says the phone cannot act as a keyboard, its maker left the profile out
   (for example the Fairphone 6 and some Huawei, Honor and older Xiaomi phones); use
   another way.
   If it says another app may be the phone's keyboard, turn that app's keyboard off: one
   app at a time may be it.
2. Tap **Make this phone visible**. Within two minutes, add the phone on the device, in its
   own Bluetooth settings, as you would add a keyboard.
3. Under **Type into**, pick the device. The app says "Connected to …".
4. Set **The device's keyboard layout** and, if needed, the **Speed** (10, 20 or 40
   characters a second).
5. Tap **Type the clipboard**. The text appears where the device has its focus, so open a
   text field there first.

To have an admin's remote pastes typed there instead of on the phone, turn on remote paste
in the app and then **Type remote pastes there**. A text with a line break needs Enter
allowed for remote paste.

## A Linux computer as a Bluetooth keyboard

```sh
sudo cbb keyboard on -layout us    # registers the keyboard with BlueZ
sudo cbb keyboard pair             # discoverable for two minutes
# add "CBB <this computer's name>" on the device, in its Bluetooth settings
cbb keyboard                       # shows whether it is connected
echo 'the text' | sudo cbb keyboard type
```

`on` also takes `-rate N`, the speed, 5 to 60 characters a second, and `-pastes`, which
sends the group's remote pastes to the device instead of this computer's screen:
`sudo cbb keyboard on -layout us -rate 10 -pastes`. `sudo cbb keyboard off` stops it.
The computer's own Bluetooth keyboards and mice keep working.

## The Nano ESP32 as a USB or Bluetooth keyboard

The board is a lite member of your group. On its console:

- `usb keyboard` makes its USB port a keyboard, with the console as a second serial port
  beside it; plug it into the device. It works before any system starts: in a BIOS, a UEFI
  setup or a disk-encryption prompt.
- `ble on`, then `ble pair`, makes it a Bluetooth LE keyboard; add "CBB Nano ESP32" on the
  device within two minutes. It remembers up to four devices; `ble forget` forgets them.
- `layout ru` or `layout us` and `rate N` set the layout and the speed.
- `type TEXT` types on the connected Bluetooth device, or else on the USB one.

The group's remote pastes to the board are typed the same way. The board's own guide is in
[esp32/](../../esp32/README.md).

## A computer as the TV's remote

A computer at home can type on a TV over the network, as its remote does. Nothing is
installed on the TV, and the TV never joins the group.

An Android TV or a Google TV pairs once:

```sh
sudo cbb remote add -name living-room-tv living-room-tv.lan   # the TV shows a six-digit code
sudo cbb remote code 123456              # within two minutes
```

An Apple TV pairs the same way, with the four-digit PIN it shows. On the Apple TV, set
Settings, AirPlay and HomeKit, Allow Access to "Everyone on the Same Network" first: with
"Only People Sharing This Home" it refuses every pairing.

```sh
sudo cbb remote add -appletv -name lounge 192.168.1.30   # the Apple TV shows a four-digit PIN
sudo cbb remote code 1234                # within two minutes
```

A Roku has no pairing and no encryption: the text crosses your home network as plain HTTP,
so it is added only when you say so with `-consent`. On the Roku, set Settings, System,
Advanced system settings, Control by mobile apps to Enabled or Permissive first.

```sh
sudo cbb remote add -roku -consent 192.168.1.40
```

Then open a search or text field on the TV with its own remote, and type:

```sh
echo 'the film' | sudo cbb remote type
sudo cbb remote pastes living-room-tv on   # an admin's remote pastes go to that TV
```

`cbb remote` lists the TVs, `-tv NAME` picks one when there are several, and
`sudo cbb remote remove NAME` forgets one. An Android TV or an Apple TV that was reset, or
that forgot this computer, must pair again.

## Safety

- A Bluetooth keyboard types wherever the device has its focus, as if you were at its
  keyboard. Pair it only with devices you mean to type on, and forget it on both ends when
  you stop.
- With remote pastes sent to a keyboard or a TV, any admin of your group can type there.
  Turn it on only where you need it; it turns off with remote paste.
- A TV is reached only on the home network: an address outside it is refused, whatever the
  name resolves to later.
- A Roku's text is not encrypted on the home network. Do not send passwords to a Roku.

## Limits

- Tried on a real TV only with an Apple TV 4K, typing through `cbb remote`; the rest runs in
  tests against a fake BlueZ, a fake Android TV, a fake Apple TV and a fake Roku.
- The phones' apps cannot be a TV's remote yet; Samsung and LG TVs follow
  ([roadmap](../roadmap.md), item 25).
- A keyboard types at most 4,096 characters at a time.

Every flag is in [the commands](../reference/cli.md); the ports of the TVs are in
[devices, ports and files](../reference/devices.md#ports); how it works inside is in the
[app specification](../apps.md#android-the-bluetooth-keyboard).
