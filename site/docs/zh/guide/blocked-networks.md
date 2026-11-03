<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 90564bcf632e -->
# 封锁 VPN 的网络

离家后，你的设备通过群组自己的 WireGuard 隧道连接中枢。有些网络会封锁 WireGuard：酒店和办公室的 Wi-Fi、部分移动运营商，以及整个过滤 VPN 的国家。Copy Beyond Borders 有两种绕开的办法。两者都在中枢上开启，设备会在下次回家与中枢碰面时获取。

| 方式 | 网络看到的是 | 你需要 | 适用于 |
|---|---|---|---|
| 普通 WireGuard（默认） | WireGuard 数据包 | 中枢或转发器 | 电脑、手机、轻量成员 |
| **AmneziaWG**（`-obfuscate`） | 看不出是什么的 UDP 数据包 | 中枢或转发器 | 电脑、手机 |
| **VLESS 与 REALITY**（`-vless`） | 一个到知名网站的 HTTPS 连接 | 开启了 VLESS 的转发器 | 电脑、手机 |

无论你选哪一种，剪贴板都留在群组的隧道和设备自己的 TLS 之内，端到端加密。伪装只改变数据包在网络上的外观。

## 该用哪一种

1. 先试**普通 WireGuard**。它最快，在大多数网络上都能用。
2. 如果隧道在某个网络上建立不起来，或者过一阵就被切断，请开启 **AmneziaWG**。大多数检测 WireGuard 的过滤器已经认不出它了。
3. 如果连这个也被封锁，比如在封锁一切未知流量的国家，请使用 **VLESS 与 REALITY**。它需要一个监听 TCP 443 端口的转发器（你自己的，或者以后项目提供的）。

在只放行一份批准地址名单的网络上，什么办法都没用。

## AmneziaWG

在中枢上：

```sh
sudo cbb global hub -obfuscate 203.0.113.7:8764
```

使用转发器时，同样加上 `-obfuscate`：

```sh
sudo cbb global hub -obfuscate -forwarder 198.51.100.9:8764 -forwarder-key <key>
```

中枢会随机生成一次群组的设置，只要 `-obfuscate` 还在，就一直保留。之后请让每台笔记本和手机回家一次，或在家时保持应用打开，让它获取新的设置。轻量成员只支持普通 WireGuard：在启用混淆的群组中，它只能在家同步。

## VLESS 与 REALITY

VLESS 运行在你的设备和转发器之间。REALITY 让转发器像一个真实的知名网站那样应答：任何没有群组密钥就连上来的人，比如探测它的审查者，得到的是那个网站自己的页面。所以要先设置转发器，再设置中枢。

1. **在转发器上**，选一个大型的、在你旅行所在国家不被封锁且支持 TLS 1.3 的 HTTPS 网站，并用它启动转发器：

   ```sh
   cbb forward -vless-site www.example.com
   ```

   转发器现在还会监听 TCP 443（用 `-vless-listen` 可改用其他端口）。请在服务器的防火墙中开放这个端口，与 UDP 和 TCP 8764 并列。服务器的设置见[运行自己的服务器](../admin/self-hosting.md#vless-on-the-forwarder)。

2. **在中枢上**：

   ```sh
   sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key> -vless
   ```

   你愿意的话也可以加上 `-obfuscate`；两者会同时生效。

3. **在设备上**：像任何变更之后一样，在家与中枢碰一次面。此后它们只通过 VLESS 连接转发器，绝不会先用普通 WireGuard 尝试，所以你想隐瞒隧道的那个网络永远看不到它。

## 针对实施过滤的国家的建议

- **出发前，在家把一切设置好。**设备只在家庭网络中获取中枢的设置。
- 选一个位于实施过滤的国家之外的转发器，托管在那里没有被封锁的服务商处。
- 对于 VLESS，选一个该国民众每天都在用的网站，这样封锁它会得不偿失；并且它所用的服务商要与你的转发器不同。
- 手机自己的 VPN 仍然可用：应用的隧道只是应用自己的普通流量，不占用手机的 VPN 名额。
- 如果隧道在旅途中失效，在笔记本上运行 `cbb global` 会说明是什么失败了，而 `CBB_DEBUG=1` 会显示详细信息（[故障排除](troubleshooting.md#sync-away-from-home)）。
