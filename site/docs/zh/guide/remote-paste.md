<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 92bb7661d223 -->
# 远程粘贴

适合想把文本、图片或文件从手机或管理员电脑直接粘贴到另一台电脑上当前获得焦点的应用中的人——例如把密码粘贴到登录框、把命令粘贴到终端，或把截图粘贴到聊天窗口。

由管理员签署粘贴请求，目标电脑通过粘贴或逐键输入的方式将内容放到其键盘焦点所在之处。远程粘贴在每台电脑上默认关闭，直到该电脑自己的用户在本机将其开启；任何人都无法从远程开启它。手机向电脑发送远程粘贴，不接收远程粘贴。

## 1. 在目标电脑上开启远程粘贴

根据目标电脑的操作系统执行相应步骤：

| 目标系统 | 设置步骤 | 粘贴落点 |
|---|---|---|
| **Linux** | 运行 `sudo cbb paste-receive on` | 当前获得焦点的桌面应用（X11、Wayland、GNOME、KDE）、活动的 `tmux` 窗格，以及（使用 `-console` 时）Linux 文本控制台 |
| **FreeBSD** | 运行 `sudo cbb paste-receive on` | X11 和 wlroots Wayland 合成器（例如 sway 和 Hyprland）上获得焦点的应用；不支持 FreeBSD 上的 GNOME，因为无法获取锁屏状态 |
| **Windows** | 以管理员身份打开终端并运行 `cbb paste-receive on` | 获得焦点的窗口 |
| **macOS** | 运行 `sudo cbb paste-receive on`，保持 **CBB** 菜单栏应用打开，并在**系统设置 > 隐私与安全性 > 辅助功能**中允许它 | 获得焦点的应用 |
| **没有桌面的小型 Linux 设备** | 运行 `sudo cbb paste-receive on`（Linux 文本控制台请加 `-console`） | 活动的 `tmux` 窗格或文本控制台 |

`cbb paste-receive on` 的可选参数：

- `-enter`：允许远程粘贴在内容之后按回车。不加 `-enter` 时，任何包含换行的文本都会被拒绝，以免粘贴在终端中意外执行命令。
- `-console`：允许向 Linux 文本控制台和 `root` 的 `tmux` 会话远程粘贴（无 root 安装中不可用）。
- `-no-lock-check`：在没有 `logind` 的 Linux 和 FreeBSD 上，当系统无法报告会话锁定状态时允许远程粘贴（正在运行的锁屏程序仍会阻止粘贴）。

**结果：**不带参数运行 `cbb paste-receive`，确认远程粘贴已开启并查看哪些选项处于启用状态。

### Linux 上的额外辅助程序

- **GNOME 和 KDE 桌面对话框：**首次远程粘贴会打开桌面的远程控制确认对话框；允许一次，桌面便会记住它。要跳过该对话框（并在没有其他输入途径的桌面上允许按键输入），请使用 `--uinput` 重新安装：

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --uinput
  ```

  这会添加 `cbb-uinput.service`，一个仅为已登录用户按下 Shift+Insert 和 Enter 的虚拟键盘。
- **无桌面 `tmux` 和文本控制台：**每次 Linux 安装都会将 Connect Beyond Borders 的钩子添加到 `/etc/tmux.conf`，使 `tmux` 自动启动其粘贴辅助程序。如需用于 Linux 文本控制台，请使用 `--console` 安装（见[在 Linux 上安装](install.md#linux)）。

## 2. 从管理员发送远程粘贴

### 从管理员电脑发送

在终端中运行 `cbb paste -on DEVICE`（`DEVICE` 是 `cbb status` 中显示的目标名称或设备 ID）：

```sh
echo 'the text' | cbb paste -on DEVICE              # paste text from standard input
cbb paste -on DEVICE                                # paste this computer's clipboard text
cbb paste -on DEVICE -type < note.txt               # type text key by key (up to 4 KiB)
cbb paste -on DEVICE -enter -secret < pass.txt      # paste as a secret and press Enter
cbb paste -on DEVICE photo.jpg notes/               # paste files into the focused app
cbb paste -on DEVICE -image screenshot.png          # paste a PNG or JPEG as an image
cbb paste -on DEVICE -copy                          # paste the group's current image or files
```

**结果：**当目标接受并送达粘贴时，命令会打印 `Pasted on DEVICE.`；否则会报告目标拒绝它的确切原因。

### 从管理员手机发送

1. 打开 **CBB**，在**主页**上点按目标电脑，然后点按**在其上粘贴…**。
2. 选择要发送的内容：
   - **文本：**输入文本（或将文本框留空以发送手机剪贴板的内容），可按需选择逐键输入、**机密**或**之后按回车**，然后点按**粘贴**。
   - **图片或文件：**点按**粘贴图片或文件…**（在 iPhone 上点按**粘贴图片…**或**粘贴文件…**）并选择项目。
3. 用你的面容、指纹、密码或（在 Aurora OS 上）管理员 PIN 确认。

在 iPhone 上，将**设置 > App > CBB > 从其他 App 粘贴**设为**允许**，这样 iOS 就不会在应用每次读取剪贴板时都询问。

**结果：**目标电脑会将内容粘贴或输入到获得焦点的窗口中，应用会显示**已粘贴。**

### 粘贴与输入对比

- **粘贴**适用于大多数桌面应用，支持文本（最多 1 MiB）、图片和文件。
- **输入**（`-type`）逐个发送按键（仅限文本，最多 4 KiB），适用于阻止剪贴板粘贴的应用。在 X11、带虚拟键盘协议的 Wayland 合成器、Windows 和 macOS 上，输入适用于各种键盘布局。在通过系统远程控制对话框工作的 GNOME 和 KDE 上，粘贴可用，但逐键输入不可用。

## 目标何时拒绝粘贴

出现以下情况时，目标电脑会拒绝远程粘贴：

- 屏幕已锁定、屏幕保护程序正在运行，或正在显示登录界面。
- 在 Windows 上，获得焦点的窗口正以管理员身份运行，或打开了管理员提权提示。
- 在 macOS 上，密码输入框或“安全键盘输入”正持有键盘焦点。
- 在无桌面目标上，没有人连接到 `tmux`，也没有人登录在文本控制台上。
- 文本包含换行，但目标未开启 `-enter`。
- 同一发送者超过了**每秒 1 次粘贴**或**每分钟 30 次粘贴**的速率限制。

返回给发送方的错误消息会说明原因。

## 安全与关闭远程粘贴

- **限制你的管理员：**开启远程粘贴期间，你群组中的任何管理员都可以向该电脑输入内容。只在需要远程粘贴的电脑上开启它，并保持管理员列表精简。
- **粘贴审计日志：**每台目标电脑都会记录最近 100 次粘贴请求（发送者、时间戳、长度、方式和结果——绝不记录粘贴的文本）。机密内容粘贴后不会在目标的剪贴板中留下痕迹。
- **在本机关闭：**在目标电脑上运行 `sudo cbb paste-receive off`（关闭时也会重置 `-enter`、`-console` 和 `-no-lock-check`）。
- **从任意管理员远程关闭：**运行 `sudo cbb paste-receive off -on DEVICE`（或使用 `-all` 关闭群组中每台电脑上的远程粘贴）。只有每台电脑自己的用户才能重新开启它。

确切的大小和速率限制见[限制与有效期](../reference/limits.md#remote-paste-and-quick-actions)。关于远程粘贴的内部工作原理，见[设计：远程粘贴](../design.md#remote-paste)。
