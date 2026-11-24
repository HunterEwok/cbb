<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 5013aca345ad -->
# 不用应用

由电脑组成的群组不需要手机应用：可以由一台电脑来持有群组。

![一台 Linux 电脑持有群组，用六位数字码添加 Mac 和 Windows](../images/without-app.svg)

## 1. 在电脑上创建群组

在一台经常开机的电脑上[安装](install.md) Connect Beyond Borders：Linux、Windows、Mac 或 FreeBSD 均可。它持有群组。然后运行：

```sh
sudo cbb new
```

这台电脑现在就是群组的**根**：它持有群组的密钥，负责添加和移除设备。如果电脑有 TPM 或 Secure Enclave，它的密钥就放在里面，否则放在一个由系统保护的文件中。

`cbb new` 还会显示一次群组的**恢复纸**：四行字母和数字，以及一个二维码。把它抄下来或打印屏幕，并与你的设备分开保存。如果这台电脑丢失，凭它可以取回群组（`cbb recovery`）；没有任何地方保存副本。

## 2. 添加电脑

在根上运行：

```sh
sudo cbb pair
```

它会打开一个配对窗口，显示六位数字代码并等待。在新电脑上运行 `sudo cbb pair -code` 并输入这个代码：它会在家庭网络中找到窗口，几秒内加入。输错代码会用掉三次机会中的一次；第三次之后，或有电脑加入后，窗口就会关闭。

然后每台电脑都会同步，方法见[快速入门](quickstart.md#4-copy-on-one-paste-on-another)。

## 3. 不要依赖一台电脑

让第二台电脑成为管理员，这样它也能添加和移除设备：

```sh
sudo cbb admin NAME                   # on the root; NAME as cbb status shows it, and it must be on
sudo cbb admin -allow-file-key NAME   # for a computer without a TPM or a Secure Enclave
```

带 TPM 的 Linux 或 Windows 电脑把管理员密钥保存在 TPM 里，Mac 则保存在 Secure Enclave 里。两者都没有的电脑则把它保存在文件里，所以 `cbb admin` 会先要求你加上 `-allow-file-key`：谁复制了这个文件，谁就能以管理员身份行事，直到另一位管理员移除这台电脑，所以只把你妥善保管的电脑设为管理员。

如果根丢失或损坏，另一台电脑可以凭群组的恢复纸成为根，其他所有设备都会留下：

```sh
sudo cbb recovery            # then type the recovery key from the sheet
```

详见[设备丢失或被盗时](lost-device.md)。

## 从其他网络加入

不在家的电脑通过中枢发出的邀请加入（[离家](away-from-home.md#a-computer-that-is-not-at-home-an-invitation)），或者通过你已经掌控的连接加入：

- **SSH** 连到根或管理员：在新电脑上运行 `ssh -N -L 18764:localhost:8764 user@that-machine`，然后在那边（另开一个 SSH 会话）运行 `sudo cbb pair`，在这边运行 `sudo cbb pair -code 127.0.0.1:18764`。
- **你自己的 VPN**，让两台机器都有私有地址：在根或管理员上运行 `sudo cbb pair`，然后在这边运行 `sudo cbb pair -code ITS-VPN-ADDRESS:8764`。在 Linux 上，设置好 VPN 后请再运行一次安装程序，让它的防火墙规则放行 VPN 的网络。

两种方式下，都请输入 `cbb pair` 在数字码下方打印的那一行（`cbb://pair?...`），而不是六位数字：在 mDNS 到达不了的地方，单凭数字指不出任何窗口，而这一行能指出它，里面也是同一个数字码。

代码从不在网络上传输：每台电脑都从配对过程中自行算出自己的代码，而配对在 SSH 或你的 VPN 内、并在 TLS 内进行。新电脑会通过这条路径同步，直到它的服务重启；若要之后继续同步，请在关闭连接之前，在两边都开启[离家同步](away-from-home.md)。

## 0.6 之前的群组

0.6 只读取第 2 版的群组记录，不保留回到旧群组的途径。从早期版本更新的电脑在第一次启动时离开旧群组：它把群组的文件移到状态目录中的 `before-0.6`，保留自己的设置，`cbb status` 会说明这一点。请重新建立群组：在一台电脑上运行 `cbb new`，然后在其他电脑上运行 `cbb pair -code`。
