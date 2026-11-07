<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 18b8e122d883 -->
# 出了问题怎么办

先在出问题的设备上运行 `cbb status`：它会告诉你服务是否在运行、在哪个群组里、哪些成员已连接，以及离家同步的状态。每条消息都很简短；`CBB_DEBUG=1 cbb status`（在 Windows 上先运行 `$env:CBB_DEBUG = "1"`）会在它下面显示底层的错误。服务的日志里总有详细信息：在 Linux 上是 `journalctl -u cbb`，桌面连接器的日志在会话的日志里，用 `journalctl --user`；其他系统见[文件和日志](../reference/devices.md#files-and-logs)。包括应用和安装程序在内，每个部分的详细信息开关见[错误消息和详细信息](../reference/errors.md)。

## 命令

**"the CBB service is not running"**：启动它（Linux 上 `sudo systemctl start cbb`；Mac 上 `sudo launchctl kickstart -k system/tools.cbb`；Windows 上 `Start-Service cbb`），然后查看它的日志。

**刚安装完，控制套接字出现 "permission denied"**：安装程序把你加入了 `cbb` 组，而组要到下次登录才生效。请退出再重新登录（在 Windows 上，打开一个新的终端）；在此之前，`sudo cbb ...` 是可以用的。

## 设备互相看不到

- **防火墙。** 成员需要从家庭网络访问 TCP 8764（或你自己的端口）和 UDP 5353（mDNS）。当你回答“是”时，安装程序会添加它们；它们认识哪些防火墙，以及其他防火墙的命令，见[防火墙](install.md#the-firewall)。如果防火墙是之后才开启的，请再运行一次安装程序。如果 `cbb status` 警告其他设备无法连接到这台电脑，说明它的防火墙挡住了成员端口。
- **另一个子网或 VLAN。** mDNS 不能跨越路由器，所以比如 192.168.0.x 和 192.168.20.x 上的设备互相找不到。请开启[离家同步](away-from-home.md)，让一端有一个中枢；对于轻量成员，也可以在它的服务里用 `-peer` 指定一台电脑（[轻量成员](../../member/README.md#install)）。
- 路由器上的**访客 Wi-Fi 或客户端隔离**会让设备根本无法互相通信；请把它们放到主网络。
- **另一个群组。** `cbb status` 会显示群组；两个群组的设备永远不会同步。要把一台电脑移到正确的群组，请在它上面运行 `sudo cbb leave`，然后把它与正确的群组配对，并在错误群组的设备上把它移除。
- **已被移出群组。** `cbb status` 会这样说明，群组成员会拒绝它。在它上面运行 `sudo cbb leave`（在应用中：退出群组），然后重新配对。

## 配对失败

- **"wrong code"**：每个配对窗口允许尝试三次；再运行一次 `cbb pair` 获取新的数字码。
- **扫描二维码后手机连不上电脑**：手机和电脑必须在同一个网络里，并且电脑的端口必须是开放的（见上文）。在 iOS 上，请允许该应用使用本地网络（设置、隐私与安全性、本地网络）。

## 离家同步

在设备上和在中枢上运行 `cbb global` 会告诉你哪里不对。常见原因：路由器没有把中枢的 UDP 端口转发给中枢，中枢的防火墙丢弃了它，或者给 `cbb global hub` 的地址不是互联网能访问到的那个。自从开启离家同步以来、或自从中枢更改了设置（`-obfuscate`、`-vless`）以来，一直没有在家里见过中枢的设备，不知道如何到达它：请把它带回家一次。封锁 VPN 的网络需要 [AmneziaWG 或 VLESS](blocked-networks.md)。在服务的环境里设置 `CBB_DEBUG=1`，日志里还会显示 WireGuard 的握手。在 Linux 上：

```sh
sudo systemctl edit cbb     # add the two lines below, save
# [Service]
# Environment=CBB_DEBUG=1
sudo systemctl restart cbb
```

## Android

- **无法开启无障碍服务**（“受限设置”）：在 Android 13 及更高版本上，打开应用的“应用信息”，点 ⋮，选“允许受限设置”，然后再开启它。
- **来自电脑的复制内容不再到达**：前台服务可能被省电功能停掉了；请在电池设置里让应用不受限制地运行。

## 仍然解决不了

请开一个 [issue](https://github.com/HunterEwok/cbb/issues)，附上 `CBB_DEBUG=1 cbb status` 的输出、日志的相关部分和涉及的系统。请删掉你复制的任何私密内容。安全问题请改为发到 [SECURITY.md](../../SECURITY.md)。
