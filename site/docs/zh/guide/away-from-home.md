<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 7ef91335d714 -->
# 离家使用

在家时，你的设备会自动同步。要让笔记本或手机在别处也能继续同步，需要让家里的一台电脑成为群组的**中枢**，外出的设备通过群组自己的加密隧道连接到它。各种情形的图示见[工作原理](how-it-works.md#away-from-home-the-hub)。

离家同步默认是关闭的，需要在中枢以及每一台要使用它的设备上分别开启。请**在所有设备都在家时**设置：此时它们才会互相交换隧道的密钥。

## 1. 选择中枢

中枢是群组中作为管理员的一台电脑：Linux、Windows、Mac、FreeBSD，或运行 OpenWrt 或 OPNsense 的路由器。最理想的是始终开机的设备：家用服务器、NAS、树莓派。Docker 中的 NAS 只有把密钥放在文件里才能当中枢，而它默认拒绝这样做，除非你明确允许（[镜像的说明](../../packaging/docker/README.md#keys)）。只在需要时才开机的电脑也行；中枢关机期间，离家的设备无法同步，家里的设备仍能正常同步。

在由手机创建的群组中，要先把这台电脑设为管理员：在手机上点按这台电脑，再点 **Make it an admin**。

## 2. 在中枢上开启

在 Linux 上，在中枢的终端中（在 Windows 上，不带 `sudo`，在管理员终端中）：

```sh
sudo cbb global on                        # read what it says about the keys, type yes
sudo cbb global hub 203.0.113.7:8764      # the address the internet reaches your home at
```

- **地址**是你家的公网 IP 地址（IPv4 或 IPv6），或指向它的域名。路由器的状态页面会显示它，也可以用 `ifconfig.me` 之类的网站查看。
- **路由器**必须把 UDP 端口 8764 转发给中枢。在其设置中查找“端口转发”或“虚拟服务器”。
- **中枢的防火墙**：`cbb global hub` 会列出它需要的规则，并在添加之前询问你。

**用 OpenWrt 路由器当中枢**不需要端口转发：以 root 身份（不带 `sudo`）在路由器上运行同样的命令。选择“Yes”后，允许来自 `wan` 的中枢 UDP 端口的规则会成为服务自带防火墙规则的一部分，随服务启停而出现和消失；`/etc/config/firewall` 保持原样。位于另一台路由器之后的路由器（双重 NAT）仍然需要在前一台路由器上做转发，或使用转发器。

没有公网地址，因为你的运营商把你放在运营商级 NAT 之后？那么路由器帮不上忙；请改用转发器（第 5 步）。

## 3. 在其他设备上开启

在家里，中枢开机的状态下：

- **电脑**：`sudo cbb global on`（在 Windows 上，在管理员终端中）。
- **手机**：在应用中，设置，**Sync away from home**。然后在家里让应用保持打开片刻，让它与中枢碰面。iPhone 只在应用打开时才进行离家同步；Android 在后台也可以。在手机上创建的群组中，这部手机一开始就是中枢，等它不再是中枢时才会出现这个开关：在 **Move the hub to a computer** 下把电脑设为中枢（先在手机上保存转发器），或关闭 **This phone as the hub**。
- **轻量成员**：在该设备上运行 `sudo cbb global on`（[轻量成员](../../lite/README.md#sync-away-from-home)）。

## 4. 检查

```sh
cbb global
```

它在每台电脑上显示离家同步是否开启、哪台设备是中枢、隧道是否已建立，以及出错时是什么出了问题。然后让一台笔记本或手机离开家里的 Wi-Fi（手机用移动数据就行），复制点东西试试。

连接不上时，常见原因是路由器没有转发该端口，或者地址不是互联网看到的那个。[故障排除](troubleshooting.md#sync-away-from-home)中有更多说明。

当你家的地址改变时，中枢会在设备下次碰面时告知它们；在电脑上，`cbb global` 此时会提示你运行 `sudo cbb global allow`。

## 5. 当互联网无法访问你家时：转发器

在运营商级 NAT 之后，中枢改为通过一条出站连接向互联网上的**转发器**注册，所以家里不需要开放任何端口。转发器只传递加密数据包，不持有任何密钥。

```sh
sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key>
```

地址和密钥由转发器提供。你可以在任何小型服务器上[运行自己的转发器](../admin/self-hosting.md#a-forwarder)。项目在 `cbb.tools` 的转发器尚未向所有人开放；开放时，它的地址和密钥会写在这里。

中枢可以同时拥有自己的地址和一个转发器：设备先尝试中枢，最后才尝试转发器。

## 6. 封锁 VPN 的网络

酒店、办公室和一些国家会封锁 WireGuard。中枢可以用 AmneziaWG 伪装隧道，或把它藏在 VLESS 中：参见[封锁 VPN 的网络](blocked-networks.md)。

## 不在家的电脑：邀请

离家同步可用之后，远处的电脑可以凭中枢发出的邀请加入群组：

```sh
sudo cbb invite        # on the hub: writes clipboardbridge.cbbinvite, valid for an hour
```

通过你信任的渠道（比如你用来给自己发消息的通讯软件）把这个文件发给新电脑；在使用之前，它是一个秘密。在新电脑上运行 `sudo cbb pair -invite clipboardbridge.cbbinvite`。两台电脑都会显示新电脑的密钥指纹；只有在两者一致时，才在中枢上输入 `yes`。手机目前还不能通过邀请加入：请在家里添加。

通过 SSH 或你自己的 VPN 从远处加入的其他方式，见[不使用应用](without-app.md#joining-from-another-network)。

## 没有电脑可以当中枢

手机在应用打开期间可以当中枢（设置，**This phone as the hub**）。或者，让设备在你自己服务器上的**盲中继**碰面，而不用中枢：电脑使用 `cbb global relay`，手机在设置的 **Blind relay** 下设置。中继无法读取剪贴板，但能看到哪些设备在通信、何时通信以及通信量。参见[运行自己的服务器](../admin/self-hosting.md#a-blind-relay)。

以后将提供：`cbb.tools` 上任何群组都能使用的盲中继。

## 关闭

```sh
sudo cbb global off
```

它会在该设备上忘记隧道的密钥。之后再次 `cbb global on` 所产生的新密钥，只能在家庭网络中传给中枢，所以此刻离家的设备，只有回到家之后才能再次同步。在手机上，请在设置中关闭该开关。
