<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 50c1a7a6666c -->
# 故障排除

写给设备不同步、配对失败或出现报错的人。下面每一条都列出了**现象**、**原因**和**解决方法**。

## 从诊断开始

在更改设置之前，先查看 Connect Beyond Borders 报告了什么：

- **在手机或桌面应用中**：打开**设置**，开启**高级设置**，查看**为什么不同步**，获取通俗的原因说明和下一步操作。要在简短提示下方显示底层技术错误，请在**设置**中连续点按**版本**七次，然后开启**显示错误详情**。
- **在终端中**：运行 `cbb status`，查看服务是否运行、群组状态、已连接的设备以及离家状态。在任意命令前加上 `CBB_DEBUG=1`（在 Windows PowerShell 中，先运行 `$env:CBB_DEBUG = "1"`）即可打印底层错误：

  ```sh
  CBB_DEBUG=1 cbb status
  ```

- **查看服务日志**：在 Linux 上，运行 `journalctl -u cbb` 查看服务日志，运行 `journalctl --user` 查看桌面剪贴板代理日志。macOS、Windows、FreeBSD 和 OpenWrt 的日志路径见[设备、端口和文件](../reference/devices.md#files-and-logs)，各组件的调试开关见[错误信息及其详情](../reference/errors.md)。

## 命令与服务

### "the Connect Beyond Borders service is not running"

- **原因**：后台服务已停止或未能启动。
- **解决方法**：按你的操作系统启动服务；如果它再次退出，请查看其日志：
  - **Linux**：`sudo systemctl start cbb`（无 root：`systemctl --user start cbb`）
  - **macOS**：`sudo launchctl kickstart -k system/tools.cbb`
  - **Windows（管理员 PowerShell）**：`Start-Service cbb`
  - **FreeBSD**：`sudo service cbb start`
  - **OpenWrt**：`/etc/init.d/cbb start`

### 安装后控制套接字出现 "permission denied"

- **原因**：安装程序把你的用户账户加入了 `cbb` 组（macOS 上为 `_cbb`），而新的组成员身份要到下次登录后才会生效。
- **解决方法**：注销并重新登录（在 Windows 上打开新的终端窗口）。重新登录前，可以用 `sudo cbb ...` 运行命令。

## 设备在家中互相看不到

### `cbb status` 警告家中设备无法连接到此电脑

- **原因**：电脑的防火墙阻止了传入的 **TCP 端口 8764**（或你自定义的成员端口）或 **UDP 端口 5353**（mDNS）。
- **解决方法**：重新运行安装程序并在防火墙提示时回答 `y`，或使用[安装：防火墙](install.md#the-firewall)中的命令手动添加规则。

### `cbb status` 对你的家庭网络显示 "Quiet on"

- **原因**：电脑只在已知的家庭网络上宣告自己并接受本地连接。如果你更换了路由器或更改了子网，电脑会把当前网络视为陌生网络。
- **解决方法**：将当前网络标记为家庭网络：在电脑上运行 `sudo cbb network`，或在 Mac 应用或托盘应用中点按**这是我的家庭网络**。

### 设备位于不同的子网或 VLAN

- **原因**：本地网络发现（mDNS）不能跨越不同子网之间的路由器（例如 `192.168.0.x` 和 `192.168.20.x`）。
- **解决方法**：通过中心节点连接两个网络（[离家可用](away-from-home.md)），在同时连接两个子网的路由器上运行 `cbb`，或者在小型设备的服务中传入 `-peer HOST:PORT`（[小型设备](../../member/README.md#install)）。

### Wi-Fi 上的设备完全无法互相连接

- **原因**：路由器启用了**访客 Wi-Fi** 或 **AP / 客户端隔离**，阻止无线设备直接通信。
- **解决方法**：将设备切换到主家庭 Wi-Fi 网络，或在路由器上关闭客户端隔离。

### 两台设备都在线但从不交换副本

- **原因**：其中一台设备在另一个群组中、**同步**已关闭，或管理员将该设备静音了。
- **解决方法**：
  - 检查两台设备的**同步**状态（运行 `cbb status` 或查看应用**主页**），并确认两台设备都未被静音。
  - 检查 `cbb status` 中的群组标签。如果某台电脑加入了错误的群组，请在它上面运行 `sudo cbb leave`，将它与正确的群组配对，然后从错误群组中移除它的旧条目。

### `cbb status` 或应用提示此设备已被移出群组

- **原因**：管理员移除了这台设备，因此其他所有群组成员都会拒绝它的连接。
- **解决方法**：在电脑上运行 `sudo cbb leave`（或在手机或桌面应用中点按**离开群组**），然后将其作为新设备重新配对。

## 配对失败

### 配对提示 "wrong code" 或窗口关闭

- **原因**：每个配对窗口开放 5 分钟，输错 3 次后会自动关闭。
- **解决方法**：打开新的配对窗口（在管理员电脑上运行 `sudo cbb pair`，或在应用中选择 **+ > 添加设备**），然后输入新的 6 位数字或扫描新的二维码。

### 手机扫描二维码后无法连接到电脑

- **原因**：手机和电脑不在同一网络、电脑防火墙阻止了 TCP 端口 8764，或 iOS 拒绝了本地网络访问。
- **解决方法**：
  1. 确认两台设备位于同一个家庭 Wi-Fi 或局域网中。
  2. 确认电脑的防火墙允许 TCP 端口 8764（[防火墙](install.md#the-firewall)）。
  3. 在 iPhone 上，启用**设置 > 隐私与安全性 > 本地网络 > CBB**。

## 离家同步

### 离家设备无法连接到中心节点

- **原因**：以下四个常见原因之一：
  - 你的路由器没有将 UDP 端口 8764 转发给中心节点、中心节点的防火墙丢弃了该端口流量，或者传给 `cbb global hub` 的公网地址位于运营商级 NAT 之后。
  - 自从开启离家同步或中心节点更改隧道设置（`-no-obfuscate`、`-no-vless`）以来，离家设备还没有在家庭网络中遇到过中心节点。
  - 你家的 IP 地址发生了变化，电脑的系统出站规则仍然只允许旧地址。
  - 你当前所处的网络屏蔽了 WireGuard 或 UDP 流量。
- **解决方法**：
  1. 在离家设备和中心节点上都运行 `cbb global`，查看确切的失败原因。
  2. 如果你家位于运营商级 NAT 之后或端口转发无效，请将中心节点切换到转发器（运行 `sudo cbb global hub` 使用项目转发器；见[离家可用](away-from-home.md#5-when-the-internet-cannot-reach-your-home-a-forwarder)）。
  3. 如果 `cbb global` 提示系统的出站网络规则滞后，请在该电脑上运行 `sudo cbb global allow`。
  4. 如果设备在设置变更后从未在家中遇到过中心节点，请先让它连接一次家庭网络（并在手机上短暂打开应用）。
  5. 如果当前网络会过滤 VPN，请确认中心节点上已启用 AmneziaWG 和 VLESS（[屏蔽 VPN 的网络](blocked-networks.md)）。如果项目转发器的入口点已过期，请用 `sudo cbb global entries import STRING` 导入新的已签名入口点。
  6. 要在 Linux 上记录 WireGuard 握手日志，请为服务设置 `CBB_DEBUG=1` 并重启服务：

     ```sh
     sudo systemctl edit cbb
     ```

     添加以下几行，保存并重启：

     ```ini
     [Service]
     Environment=CBB_DEBUG=1
     ```

     ```sh
     sudo systemctl restart cbb
     ```

     然后查看 `journalctl -u cbb`。

## 手机

### Android：“受限设置”阻止开启无障碍服务

- **原因**：Android 13 及更高版本会限制从应用商店之外通过 APK 安装的应用的无障碍权限。
- **解决方法**：打开 Android **设置 > 应用 > CBB**（应用信息），点按右上角的 **⋮** 菜单，点按**允许受限设置**，然后在无障碍设置中开启**剪贴板同步**。

### Android：来自电脑的副本不再在后台到达

- **原因**：电池优化停止了应用的后台前台服务。
- **解决方法**：打开 Android **设置 > 应用 > CBB > 电池**，将其设为**无限制**。

### iPhone：每次同步时 iOS 都询问粘贴权限

- **原因**：iOS 默认将**从其他 App 粘贴**设为**询问**。
- **解决方法**：打开 iPhone **设置 > App > CBB > 从其他 App 粘贴**，选择**允许**。

### Aurora OS 5：管理员密钥已锁定

- **原因**：连续七次输错管理员 PIN 会永久锁定手机安全元件中的管理员密钥。手机仍作为普通成员留在群组中。
- **解决方法**：离开群组，重新安装 **CBB**，然后作为新设备重新加入。

## 仍然无法解决

请提交一个 [GitHub issue](https://github.com/HunterEwok/cbb/issues)，并附上：

- `CBB_DEBUG=1 cbb status` 的输出（如果是离家问题，一并附上 `cbb global` 的输出）
- 服务或应用日志中的相关行
- 涉及的操作系统和 Connect Beyond Borders 版本

请删除任何你不想分享的已复制文本、个人地址或设备名称。安全漏洞请按照 [SECURITY.md](../../SECURITY.md) 私下报告。
