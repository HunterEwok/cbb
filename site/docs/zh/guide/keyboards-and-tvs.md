<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 9b05c71a6bfc -->
# 键盘与电视

适合想往电视、平板、游戏机，或没有安装 Copy Beyond Borders 的电脑里输入长密码、链接或搜索词的人。群组中的一台设备以键盘或电视遥控器的身份把文本输入到那里，由你点一下触发，或在管理员发送远程粘贴时触发。

## 选一种方式

| 方式 | 输入到 | 需要 |
|---|---|---|
| [Android 手机作为蓝牙键盘](#an-android-phone-as-a-bluetooth-keyboard) | 任何接受蓝牙键盘的设备：电视、平板、手机、电脑、Steam Deck、PlayStation 5 | Android 10 或更高版本，并带蓝牙键盘配置文件 |
| [Linux 电脑作为蓝牙键盘](#a-linux-computer-as-a-bluetooth-keyboard) | 任何接受蓝牙 LE 键盘的设备 | BlueZ 5.50 或更高版本，以及蓝牙 4.0 或更高版本的适配器 |
| [Nano ESP32 作为 USB 或蓝牙键盘](#the-nano-esp32-as-a-usb-or-bluetooth-keyboard) | 通过 USB 还能输入到 BIOS、磁盘加密提示、Xbox 和 Nintendo Switch | 你的群组中有一块 Arduino Nano ESP32 |
| [电脑作为电视遥控器](#a-computer-as-the-tvs-remote) | 你家庭网络中的 Android TV、Google TV 或 Roku | 家里的一台 Linux、macOS、Windows 或 FreeBSD 电脑 |

Xbox 和 Nintendo Switch 只接受 USB 键盘，所以它们要用 Nano ESP32。macOS、Windows 和 iPhone 不允许任何应用充当蓝牙键盘。

## 键盘布局必须一致

键盘发送的是按键，而不是字符：被输入的设备会按它自己的布局把每个按键变成字符。所以要告诉键盘那台设备当前使用哪种布局，英语（美国）还是俄语。如果文本中有该布局没有对应按键的字符，整段文本都不会输入，并会告诉你是哪些字符；不会用别的字符代替。换行会按下 Enter，制表符会按下 Tab。

输入速度是故意放慢的，默认每秒 20 个字符：有些电视会丢掉来得更快的按键。如果漏字，请调低速度。

## Android 手机作为蓝牙键盘

1. 在应用中，打开设置，蓝牙键盘，并开启 **Act as a Bluetooth keyboard**。如果提示，请允许蓝牙（“附近的设备”）。如果应用说这部手机无法充当键盘，说明厂商没有包含该配置文件（例如 Fairphone 6 以及一些华为、荣耀和较旧的小米手机）；请改用其他方式。如果它说另一个应用可能是手机的键盘，请关闭那个应用的键盘：同一时间只能有一个应用担任此角色。
2. 点按 **Make this phone visible**。在两分钟内，到设备自己的蓝牙设置中添加这部手机，就像添加一个键盘那样。
3. 在 **Type into** 下选择设备。应用会显示“Connected to …”。
4. 设置 **The device's keyboard layout**，必要时设置 **Speed**（每秒 10、20 或 40 个字符）。
5. 点按 **Type the clipboard**。文本会出现在设备获得焦点的地方，所以请先在设备上打开一个文本框。

如果想让管理员的远程粘贴输入到那里，而不是输入到手机上，请在应用中开启远程粘贴，然后开启 **Type remote pastes there**。含换行的文本要求远程粘贴允许 Enter。

## Linux 电脑作为蓝牙键盘

```sh
sudo cbb keyboard on -layout us    # registers the keyboard with BlueZ
sudo cbb keyboard pair             # discoverable for two minutes
# add "CBB <this computer's name>" on the device, in its Bluetooth settings
cbb keyboard                       # shows whether it is connected
echo 'the text' | sudo cbb keyboard type
```

`on` 还接受 `-rate N`（速度，每秒 5 到 60 个字符）和 `-pastes`，后者把群组的远程粘贴发送到该设备，而不是这台电脑的屏幕：`sudo cbb keyboard on -layout us -rate 10 -pastes`。`sudo cbb keyboard off` 会停止它。这台电脑自己的蓝牙键盘和鼠标仍然可用。

## Nano ESP32 作为 USB 或蓝牙键盘

这块板子是你群组中的一个轻量成员。在它的控制台上：

- `usb keyboard` 让它的 USB 口成为键盘，控制台则作为旁边的第二个串口；把它插到设备上。它在任何系统启动之前就能工作：在 BIOS、UEFI 设置或磁盘加密提示中也可以。
- `ble on`，然后 `ble pair`，让它成为蓝牙 LE 键盘；在两分钟内到设备上添加“CBB Nano ESP32”。它最多记住四台设备；`ble forget` 会忘记它们。
- `layout ru` 或 `layout us` 以及 `rate N` 用来设置布局和速度。
- `type TEXT` 会在已连接的蓝牙设备上输入，否则在 USB 设备上输入。

发往这块板子的群组远程粘贴也以同样的方式输入。板子自己的指南在 [esp32/](../../esp32/README.md)。

## 电脑作为电视遥控器

家里的一台电脑可以像遥控器那样，通过网络在电视上输入。电视上什么都不用安装，电视也不会加入群组。

Android TV 或 Google TV 只需配对一次：

```sh
sudo cbb remote add -name living-room-tv living-room-tv.lan   # the TV shows a six-digit code
sudo cbb remote code 123456              # within two minutes
```

Apple TV 的配对方式相同，使用它显示的四位 PIN 码。请先在 Apple TV 上把“设置”、“隔空播放与 HomeKit”、“允许访问”设为“同一网络中的所有人”：若设为“仅共享此家庭的成员”，它会拒绝任何配对。

```sh
sudo cbb remote add -appletv -name lounge 192.168.1.30   # the Apple TV shows a four-digit PIN
sudo cbb remote code 1234                # within two minutes
```

Roku 没有配对也没有加密：文本会以明文 HTTP 在你的家庭网络中传输，所以只有在你用 `-consent` 明确同意时才会添加。请先在 Roku 上把“设置”、“系统”、“高级系统设置”、“移动应用控制”设为“已启用”或“宽松”。

```sh
sudo cbb remote add -roku -consent 192.168.1.40
```

然后用电视自己的遥控器打开搜索或文本框，再输入：

```sh
echo 'the film' | sudo cbb remote type
sudo cbb remote pastes living-room-tv on   # an admin's remote pastes go to that TV
```

`cbb remote` 会列出电视，有多台时用 `-tv NAME` 选择其中一台，`sudo cbb remote remove NAME` 会忘记一台。被重置过或忘记了这台电脑的 Android TV 或 Apple TV 必须重新配对。

## 安全

- 蓝牙键盘会输入到设备获得焦点的地方，就像你坐在它的键盘前一样。只与你打算往里输入的设备配对，不再使用时要在两端都忘记它。
- 当远程粘贴被发送到键盘或电视时，群组的任何管理员都可以在那里输入。只在需要的地方开启；它会随远程粘贴一起关闭。
- 只能在家庭网络中访问电视：家庭网络之外的地址会被拒绝，无论该名称之后解析成什么。
- Roku 的文本在家庭网络中没有加密。不要向 Roku 发送密码。

## 局限

- 在真实电视上只试过 Apple TV 4K，通过 `cbb remote` 输入文字；其余部分在测试中针对模拟的 BlueZ、Android TV、Apple TV 和 Roku 运行。
- 手机应用目前还不能充当电视遥控器；Samsung 和 LG 电视将随后支持（[路线图](../roadmap.md)，第 25 项）。
- 键盘一次最多输入 4,096 个字符。

所有参数见[命令](../reference/cli.md)；电视使用的端口见[设备、端口与文件](../reference/devices.md#ports)；其内部运作方式见[应用规范](../apps.md#android-the-bluetooth-keyboard)。
