<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 93e712ad5209 -->
# 封锁 VPN 的网络

离家后，你的设备通过群组自己的 WireGuard 隧道连接中枢。有些网络会封锁 WireGuard：酒店和办公室的 Wi-Fi、部分移动运营商，以及整个过滤 VPN 的国家。Copy Beyond Borders 有两种绕开的办法，除非你关闭，中枢会同时使用这两种；设备会在下次回家与中枢碰面时获取更改。

| 方式 | 网络看到的是 | 你需要 | 适用于 |
|---|---|---|---|
| **AmneziaWG**（默认开启；`-no-obfuscate` 加 `-no-vless` 可关闭） | 看不出是什么的 UDP 数据包 | 中枢或转发器 | 电脑、手机 |
| **VLESS**（在转发器上默认开启；`-no-vless` 可关闭） | 一个到某网站的 HTTPS 连接 | 开启了 VLESS 的转发器（项目的转发器已开启） | 电脑、手机 |
| 普通 WireGuard（`-no-obfuscate -no-vless`） | WireGuard 数据包 | 中枢或转发器 | 电脑、手机、小设备 |

无论你选哪一种，剪贴板都留在群组的隧道和设备自己的 TLS 之内，因此你的设备之间的任何东西都无法读取它。伪装只改变数据包在网络上的外观。

## 设备如何选择

设备先通过 UDP 尝试 **AmneziaWG**，在网络放行的地方它最快：大多数检测 WireGuard 的过滤器认不出它。在连它也被封锁的地方，比如封锁一切未知流量的国家，设备通过 **VLESS** 连接转发器，这需要一个在 TCP 443 端口接受 VLESS 的转发器：项目在 cbb.tools 上的转发器就可以，也可以用你自己的。没有转发器的中枢只提供 AmneziaWG。

在只放行一份批准地址名单的网络上，什么办法都没用。

## AmneziaWG

一台设备一成为中枢，就使用 AmneziaWG：

```sh
sudo cbb global hub 203.0.113.7:8764
```

它会随机生成一次群组的设置并一直保留。在什么都不封锁的网络上，普通 WireGuard 稍快一些：

```sh
sudo cbb global hub -no-obfuscate -no-vless 203.0.113.7:8764
```

更改之后，请让每台笔记本和手机回家一次，或在家时保持应用打开，让它获取新的设置。

## VLESS

VLESS 在你的设备和转发器之间运行，包在一个在网络看来就是访问某个网站的普通 HTTPS 连接里。

1. **转发器。** 项目在 cbb.tools 上的转发器已开启 VLESS：在网络看来，你的设备是在访问 `cbb.tools`。你自己的转发器在你网站的 Web 服务器后面运行它：

   ```sh
   cbb forward -vless-xhttp vpn.example.org
   ```

   持有你网站证书的 Web 服务器把转发器打印出的路径转交给它；其他任何人看到的都是你网站自己的页面。在服务器防火墙中开放 TCP 443，以及 UDP 和 TCP 8764。服务器的配置见[运行你自己的服务器](../admin/self-hosting.md#vless-on-the-forwarder)。

2. **在中枢上**：无需操作。使用转发器的中枢会自己请求 VLESS：

   ```sh
   sudo cbb global hub -forwarder default
   ```

   （用你自己的转发器时为 `-forwarder 198.51.100.9:8764 -forwarder-key <key>`。）转发器会把它的网站和路径告诉中枢；没有 VLESS 的转发器只为 UDP 登记该中枢。VLESS 与 AmneziaWG 一起使用：在 VLESS 内部，它隐藏 WireGuard 数据包的大小，否则这些大小会透过 HTTPS 显露出来。`-no-vless` 可关闭 VLESS。

3. **在设备上**：像任何变更之后一样，在家与中枢碰一次面。此后它们先通过 UDP 尝试 AmneziaWG，在网络放行的地方这样更快，不放行时再用 VLESS，并坚持使用成功的那种方式。它们从不尝试普通 WireGuard，所以你想隐瞒隧道的那个网络永远看不到它。

## 针对实施过滤的国家的建议

- **出发前，在家把一切设置好。**设备只在家庭网络中获取中枢的设置。
- 选一个位于实施过滤的国家之外的转发器，托管在那里没有被封锁的服务商处。
- 转发器的网站会出现在每个连接的第一个数据包中：封锁这个网站的网络也就封锁了这条路。这时的办法是在另一个网站上运行你自己的转发器。
- 手机自己的 VPN 仍然可用：应用的隧道只是应用自己的普通流量，不占用手机的 VPN 名额。
- 如果隧道在旅途中失效，在笔记本上运行 `cbb global` 会说明是什么失败了，而 `CBB_DEBUG=1` 会显示详细信息（[故障排除](troubleshooting.md#sync-away-from-home)）。
