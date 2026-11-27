<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 30d3986ec6a3 -->
# 键盘和电视

适合想往未运行 Connect Beyond Borders 的电视、平板电脑、游戏机或电脑中输入长密码、网址或搜索词的人。你群组中的一台设备可以充当蓝牙键盘、USB 键盘或网络电视遥控器。

键盘和电视遥控器是[实验室](lab.md)中的实验性功能。关于在真实硬件上的当前测试状态，见[平台对等](../parity.md#on-real-devices)。

## 选择一种方式

| 方式 | 输入目标 | 所需条件 |
|---|---|---|
| [将手机作为蓝牙键盘](#a-phone-as-a-bluetooth-keyboard) | 任何接受蓝牙键盘的设备：电视、平板电脑、手机、电脑、Steam Deck、PlayStation 5 | Android 10 或更高版本（带蓝牙 HID 配置文件）、Aurora OS 或 HarmonyOS 手机 |
| [将 Linux 电脑作为蓝牙键盘](#a-linux-computer-as-a-bluetooth-keyboard) | 任何接受蓝牙 LE 键盘的设备 | 带 BlueZ 5.50 或更高版本、蓝牙 4.0+ 适配器和 `cbb-helper` 的 Linux |
| [将 Arduino Nano ESP32 作为 USB 或蓝牙键盘](#the-nano-esp32-as-a-usb-or-bluetooth-keyboard) | 任何支持 USB 或 BLE 键盘输入的设备——通过 USB 时还包括 BIOS/UEFI、磁盘加密提示、Xbox 和 Nintendo Switch | 刷写了 `esp32/` 固件的 Arduino Nano ESP32 |
| [将电脑作为电视遥控器](#a-computer-as-the-tvs-remote) | 你家庭网络中的 Android TV、Google TV、Apple TV 或 Roku | 家中运行 `cbb-helper` 的 Linux、macOS、Windows 或 FreeBSD 电脑 |

Xbox 和 Nintendo Switch 只接受 USB 键盘，因此这些游戏机请使用 Arduino Nano ESP32。iPhone、macOS 和 Windows 不允许应用充当蓝牙键盘。

## 匹配键盘布局和速度

蓝牙或 USB 键盘发送的是物理按键代码，而不是字符：目标设备会使用当前启用的键盘布局将每个按键代码转换成字符。

- **布局：**在 Connect Beyond Borders 中设置键盘布局，使其与目标设备上当前启用的布局一致——**英语（美国）**（`us`）或**俄语**（`ru`）。如果你的文本包含所选布局无法输入的字符，Connect Beyond Borders 会拒绝整段文本并列出不支持的字符，而不会输入错误字符。换行会发送回车（Enter），制表符会发送 Tab。
- **速度：**输入速度默认为**每秒 20 个字符**，因为有些电视会丢掉来得更快的按键。如果出现漏字，请调低速度（例如每秒 10 个字符）。
- **长度限制：**蓝牙或 USB 键盘一次最多输入 **4,096 个字符**。

## 将手机作为蓝牙键盘

支持 **Android**、**Aurora OS** 和 **HarmonyOS** 手机。

1. 打开 **CBB**，前往**设置**，开启**高级设置**，然后打开**实验室 > 蓝牙键盘**。
2. 开启**充当蓝牙键盘**，如有询问请允许蓝牙权限。
   - 在 Android 上，如果应用提示此手机无法充当键盘，说明设备制造商在系统中省略了蓝牙 HID 设备配置文件；请改用其他方式。如果另一个应用占用了键盘配置文件，请先在那个应用中将其关闭，因为 Android 同一时间只允许一个键盘应用。
3. 将目标设备与你的手机配对：
   - **Android：**点按**让这部手机可被发现**（可被发现 2 分钟），在目标设备的蓝牙设置中配对你的手机，然后在**输入到**下选择该目标设备。
   - **Aurora OS：**点按**让这部手机可被发现**（可被发现 2 分钟），然后在目标设备的蓝牙设置中连接到 `CBB keyboard`。
   - **HarmonyOS：**在键盘开关开启期间，从目标设备的蓝牙设置中按设备名称连接到你的手机。

   **结果：**屏幕会显示“已连接到 …”`Connected to …`（或“已有设备连接。”`A device is connected.`）。

4. 设置**设备的键盘布局**（`English (US)` 即**英语（美国）**，或 `Russian` 即**俄语**），如有需要再设置**速度**（每秒 `10`、`20` 或 `40` 个字符）。
5. 在目标设备上将光标定位到文本框，然后点按**输入剪贴板内容**（在 HarmonyOS 上，点按**输入剪贴板内容**旁边的系统**粘贴**按钮）。

**结果：**你的手机会将剪贴板文本输入到目标设备上获得焦点的文本框中。

## 将 Linux 电脑作为蓝牙键盘

在安装了 `cbb-helper` 的 Linux 电脑上运行以下命令：

1. 向 BlueZ 注册蓝牙 LE 键盘：

   ```sh
   sudo cbb keyboard on -layout us
   ```

   可选参数：`-rate N`（每秒 5 到 60 个字符；默认 20）和 `-pastes`（将收到的[远程粘贴](remote-paste.md)路由到已配对的蓝牙设备，而不是这台电脑的屏幕；换行需要 `sudo cbb paste-receive on -enter`）。

2. 让这台电脑在 2 分钟内可被发现：

   ```sh
   sudo cbb keyboard pair
   ```

3. 在目标设备上打开蓝牙设置，与 `CBB <your computer name>` 配对。
4. 检查连接并输入文本：

   ```sh
   cbb keyboard
   echo 'the text' | sudo cbb keyboard type
   ```

**结果：**`cbb keyboard` 会确认设备已连接，`cbb keyboard type` 发送完文本后会打印 `Typed.`。你的 Linux 电脑自己的蓝牙键盘和鼠标仍可正常使用。

要关闭蓝牙键盘，请运行 `sudo cbb keyboard off`。

## 将 Nano ESP32 作为 USB 或蓝牙键盘

[Arduino Nano ESP32 固件](../../esp32/README.md)运行一个由串口控制台控制的 USB 启动键盘和蓝牙 LE 键盘（加入群组和剪贴板同步已在[路线图](../roadmap.md)中）。

1. 连接到开发板的串口控制台并选择一种模式：
   - **USB 键盘：**运行 `usb keyboard`。开发板会重启，其 USB-C 接口同时充当启动键盘（可在 BIOS/UEFI、磁盘加密提示和游戏机中使用）和串口控制台。将开发板插入目标设备。
   - **蓝牙 LE 键盘：**运行 `ble on`，再运行 `ble pair`，并在 2 分钟内在目标设备的蓝牙设置中配对 `CBB Nano ESP32`。开发板最多记住 4 台配对主机（`ble forget` 可清除它们）。
2. 设置目标设备的布局和输入速度：

   ```text
   layout us
   rate 20
   ```

   俄语请使用 `layout ru`。
3. 在使用 `--features console-type` 构建的固件上，使用以下命令输入文本：

   ```text
   type hello world
   ```

**结果：**如果有活跃的已连接蓝牙主机，开发板会向该主机输入；否则通过 USB 键盘输入。

## 将电脑作为电视遥控器

你家庭网络中任何安装了 `cbb-helper` 的 Linux、macOS、Windows 或 FreeBSD 电脑，都可以通过局域网向 Android TV、Google TV、Apple TV 或 Roku 输入文字。电视上无需安装任何软件，电视也不会加入你的群组。在 Unix 系统上请使用 `sudo`（在 Windows 的管理员终端中省略 `sudo`）。

### 1. 配对或添加电视

根据你的电视选择对应命令：

- **Android TV 或 Google TV：**

  ```sh
  sudo cbb remote add -name living-room-tv living-room-tv.lan
  sudo cbb remote code
  ```

  在 2 分钟内输入电视屏幕上显示的 6 位数字代码。

- **Apple TV：**先在 Apple TV 上将**设置 > 隔空播放与 HomeKit > 允许访问**设为**同一网络中的所有人**（设为**仅共享此家庭的成员**会拒绝配对）。然后运行：

  ```sh
  sudo cbb remote add -appletv -name lounge 192.168.1.30
  sudo cbb remote code
  ```

  在 2 分钟内输入 Apple TV 显示的 4 位 PIN 码。

- **Roku：**Roku 的外部控制协议使用未加密的 HTTP 且没有配对。请先在 Roku 上将**设置 > 系统 > 高级系统设置 > 移动应用控制**设为**已启用**（Enabled）或**宽松**（Permissive）。然后使用 `-consent` 添加它：

  ```sh
  sudo cbb remote add -roku -consent 192.168.1.40
  ```

**结果：**不带参数运行 `cbb remote`，确认该电视出现在你的列表中。

### 2. 向电视输入或转发远程粘贴

1. 用电视自己的遥控器打开电视上的搜索框或文本框。
2. 从电脑输入文本：

   ```sh
   echo 'the film' | sudo cbb remote type
   ```

   配置了多台电视时，请加上 `-tv NAME`。在 Android TV 和 Roku 上，换行会按下回车；在 Apple TV 上，换行会保留在文本中。

   **结果：**文本会出现在电视获得焦点的文本框中，且 `cbb remote type` 会打印 `Typed.`。

3. 你也可以选择将来自群组管理员的[远程粘贴](remote-paste.md)路由到这台电视（一次仅限一台电视；换行需要 `sudo cbb paste-receive on -enter`）：

   ```sh
   sudo cbb remote pastes living-room-tv on
   ```

要忘记某台电视，请运行 `sudo cbb remote remove NAME`。如果 Android TV 或 Apple TV 被重置或忘记了你的电脑，请重新配对。

## 安全

- **蓝牙键盘：**蓝牙键盘会输入到已配对设备上当前获得键盘焦点的任何位置。只与你打算控制的设备配对，不再使用时请在两端都取消配对。
- **转发到键盘和电视的远程粘贴：**开启远程粘贴转发（`-pastes` 或 `cbb remote pastes TV on`）期间，群组中的任何管理员都可以向该设备输入。关闭远程粘贴时，转发也会随之停止。
- **电视仅限家庭网络：**`cbb remote` 只连接你家庭网络中的地址，并拒绝其外的任何地址。
- **不要向 Roku 发送密码：**发送到 Roku 的文本以明文 HTTP 经过你的家庭网络。切勿向 Roku 发送密码或其他机密内容。

所有命令行参数见[命令](../reference/cli.md)。电视网络端口见[设备、端口和文件](../reference/devices.md#ports)。
