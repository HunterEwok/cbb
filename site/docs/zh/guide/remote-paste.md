<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 503bd28272de -->
# 远程粘贴

适合想把一段文本放进另一台设备上某个应用的人：把密码输入电视的登录表单，把命令输入服务器的终端，把地址输入房间另一头的电脑。由群组的管理员发送文本，它会落到该设备当前获得焦点的地方，以粘贴或逐键输入的方式出现。

在每台设备上，远程粘贴都是关闭的，要由那台设备自己的用户在本机开启。没有人能从远处开启它。

## 在文本要落到的设备上开启

| 设备 | 方法 | 粘贴到哪里 |
|---|---|---|
| Linux | `sudo cbb paste-receive on` | 桌面当前获得焦点的应用（X11、Wayland、GNOME 和 KDE）、活动的 tmux 窗格；加上 `-console` 时还包括文本控制台 |
| FreeBSD | `sudo cbb paste-receive on` | X11 和 wlroots 桌面（sway、Hyprland）上获得焦点的应用；不支持 GNOME，因为那里没有任何办法得知屏幕是否已锁定 |
| Windows | 在以管理员身份打开的终端中运行 `cbb paste-receive on` | 获得焦点的窗口 |
| Mac | `sudo cbb paste-receive on`，并打开 Mac 应用，在“系统设置”、“隐私与安全性”、“辅助功能”中允许它 | 获得焦点的应用 |
| Android 手机或电视 | 设置，“Let the group's admins paste here”，并开启应用的无障碍服务 | 另一个应用中获得焦点的文本框 |
| 轻量成员 | `sudo cbb paste-receive on`；加上 `-console` 时还包括文本控制台 | 正在使用的 tmux 窗格 |

`-enter`（在手机上是“Let a paste press Enter”）让一次粘贴在文本之后按下 Enter。不加它的话，包含换行的文本会被拒绝，因为在不把粘贴当作一个整体接收的终端里，换行可能会把它前面的内容当作命令执行。

在 GNOME 和 KDE 上，第一次粘贴会弹出系统的屏幕远程控制对话框；允许一次，之后就会记住。要跳过这个对话框，请安装 uinput 辅助程序：加上 `--uinput` 重新安装（`curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh -s -- --uinput`），它会添加一个虚拟键盘，只为屏幕前的用户按下 Shift+Insert 和 Enter。

没有桌面时，tmux 和文本控制台需要它们各自的辅助程序。每次安装都会加入 Clipboard Bridge 在 `/etc/tmux.conf` 中的那部分，它会随 tmux 一起启动 tmux 辅助程序；`install.sh --console` 会添加控制台辅助程序的服务。

## 由管理员粘贴

在管理员电脑上：

```sh
echo 'the text' | cbb paste -on DEVICE          # pastes it
cbb paste -on DEVICE                            # pastes this computer's clipboard text
cbb paste -on DEVICE -type < note.txt           # types it key by key, up to 4 KiB
cbb paste -on DEVICE -enter -secret < pass.txt  # presses Enter after it; kept as a secret
```

`DEVICE` 是设备的名称，或 `cbb status` 中显示的它的 ID。命令会告诉你文本何时已送达，或设备为什么拒绝。

在管理员手机上，打开设备页面并选择“Paste on it…”：输入文本，或让输入框留空以发送剪贴板中的内容，选择粘贴还是输入，并用 Face ID 或指纹确认。iPhone 每次都会询问是否允许应用读取剪贴板，直到在“设置”、“App”、CBB 中把“从其他 App 粘贴”设为“允许”。

逐键输入在 X11、带虚拟键盘的 Wayland 合成器、Windows 和 Mac 上适用于任何键盘布局。在 GNOME 和 KDE 上，通过对话框的方式可以粘贴但不能输入，因为按键会遵循用户的键盘布局。

## 何时会被拒绝

设备绝不会在以下情况粘贴：

- 屏幕已锁定、屏幕保护程序或登录界面正在显示时；
- 在 Windows 上，粘贴到以管理员身份运行的窗口，或管理员权限提示之下；
- 在 Mac 上，密码输入框或“安全键盘输入”占用键盘时；
- 没有人连接到 tmux，或没有人在控制台登录时；
- 来自同一发送者的粘贴每秒超过一次，或每分钟超过 30 次。

发送方收到的回答会说明是哪一种情况。

## 安全

- 在远程粘贴开启期间，你群组的任何管理员都可以像坐在你的键盘前一样向你的设备输入内容。只在需要的地方开启它，并保持管理员名单简短。
- 每台设备会保留最近 100 次粘贴的日志：谁发送的、何时发送，但绝不记录文本。Android 还会在通知中显示发送者。
- 任何管理员都可以在另一台设备或所有设备上关闭远程粘贴，比如手机丢失时：`cbb paste-receive off -on DEVICE` 或 `-all`。只有设备自己的用户才能重新开启它。

各项限制见[限制与有效期](../reference/limits.md#remote-paste-and-quick-actions)；其内部运作方式见[设计文档](../design.md#remote-paste)。
