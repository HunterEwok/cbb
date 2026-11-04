<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: e3cc41b050a0 -->
# 应用

Copy Beyond Borders 有适用于手机、手表和桌面的应用。手机应用保管群组；桌面应用是进入电脑上已在运行的服务的一扇窗口。

| 应用 | 获取方式 | 状态 |
|---|---|---|
| Android | 每个[版本](https://github.com/HunterEwok/cbb/releases)中的 `cbb-X.Y.Z.apk` | 已在 CI 中构建并测试，尚未在真机上测试 |
| 不含 Google 服务的 Android | `cbb-fdroid-X.Y.Z.apk`，通过审核后还会上架 F-Droid：与上面是同一款应用，只是没有 Wear OS 手表功能 | 已在 CI 中构建并测试 |
| iPhone 和 iPad | TestFlight（开放后） | 已在 CI 中构建并测试；用开发者自己的团队构建后可在 iPhone 上运行 |
| Wear OS | `cbb-wear-X.Y.Z.apk`，在应用上架 Google Play 之前，需要在电脑上通过手表的无线调试使用 `adb install` 安装到手表上 | 已构建 |
| Apple Watch | 随 iPhone 应用一起提供 | 已构建；可与 iPhone 应用一起在 Apple Watch 上运行 |
| Mac 应用 | 暂时还不能下载：目前需要从 `apps/macos` 自行构建 | 已构建 |
| Linux 和 Windows 的托盘应用 | 包含在每个版本的 Windows 和 Linux 压缩包中，随服务一起安装 | 已构建；已在 Windows 11 虚拟机中运行 |

## 手机

### 创建群组

1. 在电脑上[安装](install.md) Copy Beyond Borders，并在那里运行 `sudo cbb pair`。它会显示一个二维码。
2. 打开应用，点按 **Connect a new device**，然后扫描该二维码。应用会在手机的安全芯片中（iPhone 上是 Secure Enclave，Android 上是 Keystore）生成群组的密钥，添加这台电脑，并打开主页。
3. 之后每添加一台电脑，都在主页点 **+**。轻量成员的加入方式相同（在它上面运行 `sudo -u cbb cbb pair` 会显示它的二维码）。

摄像头无法使用时：在 iPhone 上，输入电脑显示的六位数字；在 Android 上，粘贴二维码的文本，`cbb pair` 也会打印这段文本。

### 日常使用

- **主页**以磁贴或列表显示群组的每台设备，并用一个圆点表示它是否在线。大按钮会发送手机当前持有的内容；如果电脑刚刚复制了新内容，则会获取电脑最新的那一份。
- **iPhone**：iOS 只允许应用在位于前台时使用剪贴板，所以 iPhone 通过一个手势来同步：轻点背面或“操作”按钮上的“Sync clipboard”动作、控制中心中的控件，或主屏幕小组件。通过“共享”，选择 Copy Beyond Borders，可以立即发送一段文本或一个链接。
- **Android**：电脑上的复制内容会自动到达。要让手机的复制内容也自动发送，请打开 **Send my copies by themselves**（一项无障碍服务；应用会说明它读取什么）。不开启的话，点一下就行：快速设置中的 **Send clipboard** 磁贴、通知中的 Send、主屏幕小组件，或者“共享”和文本选择菜单中的 Copy Beyond Borders。
- **通知**会在设备加入或被移除、成为管理员，或离家时中枢没有应答时提醒你。每种通知在设置中都有各自的开关。

### 设备

点按一台设备可以查看它的类型、系统、版本和角色。在管理员手机上，你还可以：

- **重命名**或**移除**它；移除时会先确认一次，然后要求验证你的面容、指纹或密码。在 Android 上每次签名都会询问：添加第一台电脑会问五次（先是群组自己的证书，然后是电脑的），之后每台问两次，其他每个操作问一次；每次询问都会说明是第几次（“Signature 2 of 5”）。当某台电脑的证书需要续期，或群组用于离家同步的密钥需要更新时，应用会在你打开它时询问。
- 对电脑执行 **Make it an admin**：之后它可以用 `sudo cbb pair` 和 `sudo cbb remove` 添加和移除设备。它的密钥是电脑上的一个文件（带 TPM 的 Linux 电脑除外），应用会先就此提醒你；所以请选择你信任的电脑，最好是始终开机、同时也是[中枢](away-from-home.md)的那台。

### 第二部手机，以及丢失的手机

- **第二部手机**：在它上面点按 **I already use Copy Beyond Borders on another phone**；它会显示一个二维码，由第一部手机用 **+** 扫描。第一部手机，也就是根，会把它设为管理员，这样丢了一部手机也不会损失任何东西。
- **丢失的手机**：在你的另一部手机上，到设备列表中把它移除。电脑仍留在群组中；如果丢失的是根手机，另一部手机会在同一步中接管群组。更多内容见[设备丢失或被盗时](lost-device.md)。

### 设置

- **Sync away from home**：参见[离家使用](away-from-home.md#3-turn-it-on-on-the-other-devices)。
- **主题**：十种颜色，各有深色和浅色，或跟随系统；Android 上还可以使用壁纸的颜色。
- **语言**：跟随系统、英语或俄语。
- **通知**，每种各有一个开关。
- **Show error details**：连续点按版本号七次即可显示此开关。开启后，错误会在简短的消息下方显示原因，在你报告问题时很有帮助。

## 手表

Apple Watch 和 Wear OS 应用会显示群组的设备及其是否在线、最近的事件，以及离家同步的开关。它们通过配对的手机工作。

## 桌面应用

Mac 应用以及适用于 Linux 和 Windows 的托盘应用显示的内容与手机相同：以磁贴、列表或轨道形式显示的设备、设备详情、**Send the clipboard** 和 **Fetch**，以及离家同步的开关。对群组的更改（重命名、移除、设为管理员）需要输入管理员密码。添加设备仍需在终端中运行（`sudo cbb pair`）。无论应用是否打开，服务都会持续同步。

出问题时，参见[故障排除](troubleshooting.md)。
