<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 46c1b3ed05bb -->
# 快速入门

Copy Beyond Borders 让你的手机和电脑共用一个剪贴板：在一台设备上复制，在另一台上粘贴。这些设备在你的家庭网络中组成一个**群组**。手机保管群组的密钥，并由它放行每台新设备，所以没有你的许可，谁也无法加入。

![手机通过二维码添加每台电脑；之后这些设备共用同一个剪贴板](../images/group.svg)

整个过程分四步：安装应用，在电脑上安装 Copy Beyond Borders，扫描电脑上的二维码，然后在这台电脑上开启共享。

群组的核心可以是一台电脑，也可以只由手机组成：两种方式都行，但我们推荐使用一台经常开机的电脑，它能让离家同步随时可用（见[两种群组](how-it-works.md#two-kinds-of-group)）。如果只用手机，请跳过第 2 到第 4 步：在其他每部手机上点按 **I already use Copy Beyond Borders on another phone**，然后在第一部手机上用 **Connect a new device** 扫描它显示的二维码（设备已有之后，改点 **+**）。

## 1. 在手机上安装应用

- **Android** 10 或更高版本：在手机上从[最新版本](https://github.com/HunterEwok/cbb/releases/latest)页面下载 `cbb-X.Y.Z.apk` 并打开；当 Android 询问时，允许浏览器安装应用。
- **iPhone**：应用将通过 TestFlight 发布，目前尚未开放。在此之前，群组可以从 Android 或电脑上开始：参见[不使用应用](without-app.md)。

打开应用。你将在第 3 步添加第一台电脑。

## 2. 在电脑上安装 Copy Beyond Borders

在家庭网络中任选一台电脑：笔记本、台式机或树莓派都可以。

在 **Linux** 或 **Mac** 上，在终端中运行：

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

在 **Windows** 10 或 11 上，在以“以管理员身份运行”打开的 PowerShell 中运行：

```powershell
irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
```

安装程序会校验下载内容，启动 Copy Beyond Borders，并问两个问题：是否为它开放防火墙（回答 `y`），以及是否自动更新（回答 `y` 也很合适）。然后注销再登录一次；在 Windows 上则打开一个新终端。Homebrew、Docker 和更多细节见[安装](install.md)。

## 3. 添加电脑

在电脑上运行：

```sh
sudo cbb pair
```

在 Windows 上，请在管理员终端中运行 `cbb pair`。它会显示一个二维码。也可以不用终端：在电脑上打开 CBB 应用（Windows 和 Linux 上的托盘应用，Mac 上的菜单栏应用），点击**Join a phone's group**：它会要求输入管理员密码，并显示同样的二维码。

在应用中点按 **Connect a new device** 并扫描该二维码。应用会生成群组的密钥（会要求你验证指纹、面容或密码），并添加这台电脑。群组就建好了。

其他每台电脑都用同样的方式添加：安装，运行 `sudo cbb pair`，然后在应用中点 **+**。

## 4. 在一台上复制，在另一台上粘贴

你在电脑上复制的内容会到达群组，群组复制的内容也会到达它。在电脑上复制、在手机上粘贴，或者反过来：

- **Android** 会自动收到电脑上的复制内容。要发送手机上的复制内容，请点按应用主页上的大按钮、快速设置中的 **Send clipboard** 磁贴，或通知中的 Send；也可以在应用中打开 **Send my copies by themselves**，让它自动完成。
- **电脑之间**：在一台上复制，在另一台上粘贴。无需任何操作。

要让某台设备的剪贴板暂时只属于它自己，请关闭同步：应用首屏上的房子按钮，或 `cbb sync off`（见[命令](../reference/cli.md#cbb)）。应用的其余功能见[应用](apps.md)。

## 5. 推荐：让一台始终开机的电脑帮助手机

只用手机，群组也能工作，但如果有一台一直开着的电脑，比如家用服务器、树莓派或台式机，有两件事会做得更好：

- **把它设为管理员。**在手机上，点主页上的这台电脑，再点 **Make it an admin**。没有 TPM 也没有 Secure Enclave 的电脑会把密钥保存在文件中，应用会先就此提醒你（见[密钥](keys.md#the-three-levels)）。之后它也能添加和移除设备（`sudo cbb pair`、`sudo cbb revoke NAME`），这样你就不必每次都带着手机。手机仍然是群组的根，也就是最受信任的设备：根密钥永远不会离开手机的安全芯片。
- **把它设为中枢**，这样你的设备离家后也能继续同步。参见[离家使用](away-from-home.md)。

也建议再添加一部手机，这样丢了一部手机也不会损失任何东西：在第二部手机上点按 **I already use Copy Beyond Borders on another phone**，并在第一部手机上用 **+** 扫描它的二维码。第一部手机会把它设为管理员。

## 接下来

- [工作原理](how-it-works.md)：群组、各种角色，以及设备在家里和离家后各种连接方式的图示。
- [离家使用](away-from-home.md)：通过中枢从任何地方同步。
- [不使用应用](without-app.md)：由电脑保管的群组。
- [故障排除](troubleshooting.md)：出问题时看这里。
