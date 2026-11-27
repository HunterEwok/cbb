<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6e944da2c5ca -->
# 屏蔽 VPN 的网络

适合离家后在过滤或屏蔽 WireGuard 的网络上同步的人，例如酒店 Wi-Fi、办公室网络、移动运营商，或对流量实施严格过滤的国家。在本页中，你可以查看或更改中心节点伪装隧道的方式。

离家时，你的设备通过群组的 WireGuard 隧道连接到中心节点。默认情况下，中心节点会同时使用 **AmneziaWG** 和（搭配支持 VLESS 的转发器时）**VLESS**，让你的隧道穿过实施过滤的网络。无论采用哪种伪装，你的副本始终受 WireGuard、双向 TLS 1.3 和端到端加密保护；见[工作原理](how-it-works.md#networks-that-block-vpns)。

| 传输方式 | 网络看到的内容 | 所需条件 | 支持的设备 |
|---|---|---|---|
| **AmneziaWG**（默认开启） | 带有随机报头和填充的 UDP 数据包 | 中心节点或转发器 | 电脑、小型设备（MIPS 路由器除外）、手机 |
| **VLESS**（搭配 VLESS 转发器时默认开启） | 到转发器网站的 HTTPS 连接 | 开启了 VLESS 的转发器（项目在 `cbb.tools` 上的转发器已开启） | 电脑、小型设备（MIPS 路由器除外）、手机 |
| **普通 WireGuard**（`-no-obfuscate -no-vless`） | 标准 WireGuard UDP 数据包 | 中心节点或转发器 | 电脑、小型设备（MIPS 路由器除外）、手机 |

## 设备如何选择

当中心节点使用支持 VLESS 的转发器时，离家设备会先通过 UDP 尝试 **AmneziaWG**，因为在网络放行 UDP 时它更快。如果 UDP 被屏蔽（例如只允许网页流量的网络），它们会自动切换为通过 HTTPS（TCP 443 端口）向转发器建立 **VLESS** 连接，并持续使用成功的那种传输方式。

启用 VLESS 时，设备绝不会回退到普通 WireGuard，因此过滤网络不会看到未伪装的 VPN 流量。没有转发器的中心节点只提供 AmneziaWG。

如果网络只允许连接到固定名单中批准的 IP 地址或域名，任何隧道伪装都无法生效。

## 在桌面应用中配置隧道伪装

在运行 Mac 应用或 Linux、Windows 托盘应用的中心节点上：

1. 打开 **CBB**，选择这台电脑的设备页面。
2. 在**严格网络**下，切换以下开关：
   - **屏蔽 VPN 的网络（AmneziaWG）**：开启或关闭 AmneziaWG。
   - **只允许网页通行的网络（VLESS）**：开启或关闭 VLESS（需要支持 VLESS 的转发器）。
3. 使用管理员密码、触控 ID、Windows Hello 或 polkit 提示进行确认。
4. 将每台笔记本电脑和手机连接到家庭网络一次，让它们接收中心节点更新后的隧道设置。

**结果：**中心节点会保存更新后的设置，并在下次在家相遇时分享给你的设备。

## AmneziaWG

每台中心节点在设置完成后默认就会启用 AmneziaWG：

```sh
sudo cbb global hub 203.0.113.7:8764
```

中心节点会为你的群组随机生成 AmneziaWG 参数，并在每个服务器凭据周期（大约每月一次）自动轮换，同时提前分发下一套参数。

要在不屏蔽 VPN 的网络上切换回普通 WireGuard（以减少数据包开销）：

1. 在中心节点上运行（使用 `-keep` 保留中心节点现有的地址和转发器）：

   ```sh
   sudo cbb global hub -keep -no-obfuscate -no-vless
   ```

2. 将每台离家使用的笔记本电脑和手机连接到家庭网络一次（手机应用需短暂打开），让它们接收新的设置。

**结果：**你的设备在家获取到更新后的配置后，就会使用普通 WireGuard。

## VLESS

VLESS 将经过 AmneziaWG 伪装的隧道承载在网络看来像是访问转发器网站的普通 HTTPS 连接中。在 VLESS 内部保留 AmneziaWG 可以隐藏 WireGuard 数据包的大小，否则这些特征可能会在 HTTPS 中显露出来。

1. **选择支持 VLESS 的转发器：**
   - **项目在 `cbb.tools` 上的转发器**已启用 VLESS；在网络看来，你的设备就像是在访问 `cbb.tools`。
   - **你自己的转发器：**在持有你网站 TLS 证书的 Web 服务器后面运行 `cbb forward`：

     ```sh
     cbb forward -vless-xhttp vpn.example.org
     ```

     配置你的 Web 服务器，将 `cbb forward` 打印出的路径代理到转发器的本地监听地址（默认为 `127.0.0.1:3276`），同时向其他所有访问者正常提供你自己的网页。在服务器的防火墙中同时开放 **TCP 443 端口**以及 UDP 和 TCP 8764 端口。见[运行你自己的服务器：转发器上的 VLESS](../admin/self-hosting.md#vless-on-the-forwarder)。

2. **将中心节点指向转发器：**在中心节点上向项目的转发器或你自己的转发器登记：

   ```sh
   sudo cbb global hub -forwarder default
   ```

   如果使用你自己的转发器，请改为传入它的地址和密钥：

   ```sh
   sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key KEY
   ```

   **结果：**中心节点会自动请求 VLESS。如果转发器支持 VLESS，它会把自己的网站名称和路径发给中心节点；否则中心节点只登记 UDP。要关闭 VLESS 但保留 AmneziaWG，请传入 `-no-vless`（例如 `sudo cbb global hub -keep -no-vless`）。

3. **在家同步一次：**更改中心节点设置后，把每台笔记本电脑和手机连入家庭网络（并短暂打开手机应用）。

   **结果：**你的设备会收到中心节点的 VLESS 配置，并在 UDP 被屏蔽时自动使用它。

## 针对过滤流量的国家的建议

- **出行前在家完成设置并测试。**设备只在家庭网络中接收中心节点的隧道设置。
- **将转发器托管在过滤国家之外**，选择其 IP 地址在当地未被屏蔽的服务商。
- **做好域名被屏蔽的准备：**转发器的域名会出现在 TLS 握手（SNI）中。如果网络屏蔽了 `cbb.tools`，请在另一个域名后面运行你自己的转发器。
- **保留你的系统 VPN：**Connect Beyond Borders 的隧道在应用内作为普通流量运行，不占用手机的 VPN 名额，因此你自己的 VPN 可以与它同时正常工作。
- **刷新被屏蔽的入口：**如果项目转发器的入口发生变化，而某台设备无法连接它们，可以在已联网的电脑上运行 `cbb global entries export`（或 `-qr`）导出带签名的入口，然后在受影响的电脑上运行 `sudo cbb global entries import STRING` 导入。
- **排查失败原因：**在笔记本电脑上运行 `cbb global` 查看隧道失败的原因，并在服务上启用 `CBB_DEBUG=1` 查看 WireGuard 握手日志（[故障排除：离家同步](troubleshooting.md#sync-away-from-home)）。
