<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: f88bc63a357c -->
# 不用应用

由电脑组成的群组不需要手机应用：可以由一台电脑来持有群组。

![一台 Linux 电脑持有群组，用六位数字码添加 Mac 和 Windows](../images/without-app.svg)

## 1. 在电脑上创建群组

在一台经常开机的电脑上[安装](install.md) Copy Beyond Borders：Linux、Windows、Mac 或 FreeBSD 均可。它持有群组。然后运行：

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

然后每台电脑都会同步，方法见[快速入门](quickstart.md#4-copy-on-one-paste-on-another)。

## 3. 不要依赖一台电脑

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

详见[设备丢失或被盗时](lost-device.md)。

## 从其他网络加入

不在家的电脑通过中枢发出的邀请加入（[离家](away-from-home.md#a-computer-that-is-not-at-home-an-invitation)），或者通过你已经掌控的连接加入：

- **SSH** 连到根或管理员：在新电脑上运行 `ssh -N -L 18764:localhost:8764 user@that-machine`，然后在那边（另开一个 SSH 会话）运行 `sudo cbb pair`，在这边运行 `sudo cbb pair -code 127.0.0.1:18764`。
- **你自己的 VPN**，让两台机器都有私有地址：在根或管理员上运行 `sudo cbb pair`，然后在这边运行 `sudo cbb pair -code ITS-VPN-ADDRESS:8764`。在 Linux 上，设置好 VPN 后请再运行一次安装程序，让它的防火墙规则放行 VPN 的网络。

数字码从不以明文传输：配对在 SSH 或你的 VPN 内部进行，同时还在 TLS 内部。新电脑会通过这条路径同步，直到它的服务重启；若要之后继续同步，请在关闭连接之前，在两边都开启[离家同步](away-from-home.md)。

## 0.6 之前的群组

0.6 只读取第 2 版的群组记录，不保留回到旧群组的途径。从早期版本更新的电脑在第一次启动时离开旧群组：它把群组的文件移到状态目录中的 `before-0.6`，保留自己的设置，`cbb status` 会说明这一点。请重新建立群组：在一台电脑上运行 `cbb new`，然后在其他电脑上运行 `cbb pair`。
