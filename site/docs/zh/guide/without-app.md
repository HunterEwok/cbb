<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: f06d2929ba18 -->
# 不用应用

群组并不需要手机应用。群组可以由一台电脑来持有，没有应用的 iPhone 则通过快捷指令加入。在 iPhone 应用还在等待 TestFlight 的这段时间，这也是可行的办法。

![一台 Linux 电脑持有群组，用六位数字码添加 Mac 和 Windows，用描述文件和快捷指令添加 iPhone](../images/without-app.svg)

## 1. 在电脑上创建群组

在一台经常开机的电脑上[安装](install.md) Copy Beyond Borders：Linux、Windows、Mac 或 FreeBSD 均可。它持有群组，并为 iPhone 快捷指令提供服务。然后运行：

```sh
sudo cbb new
```

这台电脑现在就是群组的**根**：它持有群组的密钥，负责添加和移除设备。它的密钥是电脑上的一个文件，由系统保护；手机应用则把同样的密钥放在手机的安全芯片里。

## 2. 添加电脑

在根上运行：

```sh
sudo cbb pair
```

它会显示一个六位数字码并等待。在新电脑上同样运行 `sudo cbb pair`：它会先显示一个给手机应用用的二维码，不用理会，然后要求输入数字码；在那里输入这六位数字。新电脑几秒钟内就会加入。

然后在每台电脑上开启共享，方法见[快速入门](quickstart.md#4-share-the-computers-clipboard)：`sudo cbb mode shared`。

## 3. 用快捷指令添加 iPhone

在根上，或在能响应 `clipboardbridge.local` 的管理员电脑上（`cbb status` 会告诉你它是否响应）：

```sh
sudo cbb pair -phone
```

它会打印一个二维码、指纹的开头部分和一个六位数字码。

1. 用 iPhone 的相机扫描二维码，然后按页面提示操作：安装描述文件。
2. 检查描述文件的指纹是否以打印出来的开头一致（设置、通用、VPN 与设备管理，“CBB”，更多详细信息），然后为它开启完全信任（设置、通用、关于本机、证书信任设置）。
3. 从同一页面添加快捷指令“clipboardbridge”并运行一次；它会要求输入六位数字码。
4. 把快捷指令放到操作按钮上，或放到轻点背面上（设置、辅助功能、触控、轻点背面、轻点两下）。

之后只需按一下，它会自己判断方向：如果刚刚在电脑上复制了内容，就传到 iPhone；否则，iPhone 上的新复制内容会传到电脑。

## 4. 不要依赖一台电脑

让第二台电脑成为管理员，这样它也能添加和移除设备：

```sh
sudo cbb admin NAME                   # on the root; NAME as cbb status shows it, and it must be on
sudo cbb admin -allow-file-key NAME   # for a computer without a TPM or a Secure Enclave
```

带 TPM 的 Linux 或 Windows 电脑把管理员密钥保存在 TPM 里，Mac 则保存在 Secure Enclave 里。两者都没有的电脑则把它保存在文件里，所以 `cbb admin` 会先要求你加上 `-allow-file-key`：谁复制了这个文件，谁就能以管理员身份行事，直到另一位管理员移除这台电脑，所以只把你妥善保管的电脑设为管理员。

如果根丢失或损坏，管理员可以接管群组，其他所有设备都保留：

```sh
sudo cbb takeover NAME       # on the admin; NAME is the lost root
```

使用快捷指令的 iPhone 在接管后需要重新配对。详见[设备丢失或被盗时](lost-device.md)。

## 从其他网络加入

不在家的电脑通过中枢发出的邀请加入（[离家](away-from-home.md#a-computer-that-is-not-at-home-an-invitation)），或者通过你已经掌控的连接加入：

- **SSH** 连到根或管理员：在新电脑上运行 `ssh -N -L 18764:localhost:8764 user@that-machine`，然后在那边（另开一个 SSH 会话）运行 `sudo cbb pair`，在这边运行 `sudo cbb pair -code 127.0.0.1:18764`。
- **你自己的 VPN**，让两台机器都有私有地址：在根或管理员上运行 `sudo cbb pair`，然后在这边运行 `sudo cbb pair -code ITS-VPN-ADDRESS:8764`。在 Linux 上，设置好 VPN 后请再运行一次安装程序，让它的防火墙规则放行 VPN 的网络。

数字码从不以明文传输：配对在 SSH 或你的 VPN 内部进行，同时还在 TLS 内部。新电脑会通过这条路径同步，直到它的服务重启；若要之后继续同步，请在关闭连接之前，在两边都开启[离家同步](away-from-home.md)。

## 0.6 之前的群组

0.6 只读取第 2 版的群组记录，不保留回到旧群组的途径。从早期版本更新的电脑在第一次启动时离开旧群组：它把群组的文件移到状态目录中的 `before-0.6`，保留自己的设置，`cbb status` 会说明这一点。请重新建立群组：在一台电脑上运行 `cbb new`，然后在其他电脑上运行 `cbb pair`。
