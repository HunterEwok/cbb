<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 0dae45ee8ba4 -->
# 安装

Copy Beyond Borders 在每台电脑上作为一个小型后台服务运行，它的命令是 `cbb`。下面每种方式安装的都是同一个程序，选你喜欢的即可。

## Linux

任何使用 systemd 的 Linux（x86-64、ARM64、ARMv7、ARMv6）：笔记本、台式机、树莓派、服务器、Steam Deck。

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

然后注销再登录一次，这样你的用户无需 `sudo` 就能使用 `cbb`。没有桌面的机器可以用 `--console` 在 tmux 内实现复制和粘贴（`... | sudo sh -s -- --console`）。

在装有 GTK 4 和 WebKitGTK 6.0 的桌面上（x86-64 和 ARM64），它还会安装托盘应用，该应用随会话启动，并出现在应用程序菜单中。缺少它们时，它会列出需要添加的软件包；添加后再运行一次即可装上托盘应用。

在 GNOME 和 KDE 上，管理员第一次远程粘贴要按下按键之前，会先在电脑上弹出一次对话框询问。要跳过这个对话框，请加上 `--uinput`（`... | sudo sh -s -- --uinput`）：之后由一个小型辅助程序为正在使用屏幕的人按下粘贴键（Shift+Insert 和 Enter），在登录界面或锁屏时绝不会按。

只需要同步的小设备，比如路由器或 Raspberry Pi Zero，可以改用更轻量的[轻量成员](../../member/README.md)：`... | sudo sh -s -- --lite`。

### 不使用 sudo（无 root）

在你不能或不想使用 `sudo` 的 Linux 电脑上，可以只为自己的用户安装，不需要 `sudo`：

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

它在你登录期间作为你自己的后台服务运行，并像其他成员一样同步。只有在无法进行常规安装时才使用它：你运行的每个程序都可能复制它的密钥，所以它永远不能成为群组的根、管理员或中枢（[工作原理](how-it-works.md#rootless-members)），而且它没有防火墙规则、没有 TPM，也不能用 `--console` 或 `--uinput`。要让它在你注销后继续运行，需要管理员执行一次 `sudo loginctl enable-linger YOUR-USER`。卸载它：`sh ~/.local/share/cbb/uninstall.sh`。轻量成员也可以这样安装，使用 `--lite --rootless`（[轻量成员](../../member/README.md#without-sudo-rootless)）。

### SteamOS（Steam Deck）

切换到桌面模式，打开 Konsole，如果 `deck` 用户还没有密码，先用 `passwd` 设置一次，然后运行同样的命令。SteamOS 每次更新都会替换它的系统文件，所以安装程序把 Copy Beyond Borders 放在 `/opt/cbb`，而不是 `/usr/local`，并告诉 SteamOS 在 `/etc` 中要保留哪些文件（`/etc/atomic-update.conf.d/cbb.conf`）。SteamOS 更新之后，它仍然保持已安装，也仍在原来的群组中。

- 注销再登录之后，`cbb` 就在新 Konsole 的路径中了。`sudo` 不会去那里查找，所以需要 `sudo` 的命令要写完整路径：`sudo /opt/cbb/bin/cbb pair`。
- 在桌面模式下，剪贴板的同步方式与任何 KDE Plasma 桌面相同。
- 在游戏模式下没有桌面剪贴板，所以那里不会同步；服务继续运行，回到桌面模式后会追上进度。
- 卸载：`sudo sh /opt/cbb/share/uninstall.sh`。

## Mac

Apple 芯片或 Intel，macOS 14 或更高版本：从[最新发布版](https://github.com/HunterEwok/cbb/releases/latest)下载
`cbb-X.Y.Z.pkg` 并打开。它会安装菜单栏中的 CBB 应用和服务，两者都由本项目签名并经 Apple 检查。

或者在“终端”中，不装应用，命令与 Linux 相同：

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

或者使用 Homebrew，它也会负责更新。每次 `brew upgrade` 之后，请再运行第二行：

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
```

## Windows

Windows 10（1809 或更高版本）或 11，x86-64 或 ARM64，在以“以管理员身份运行”打开的 PowerShell 中：

```powershell
irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
```

它让当前在屏幕前登录的用户可以使用 `cbb`（在新终端中），并为该用户启动剪贴板代理。会改变群组的命令要在以管理员身份打开的终端中运行，对应 Linux 和 macOS 中使用 `sudo` 的地方。

它还会安装托盘应用，该应用在登录时启动，并以 CBB 之名出现在“开始”菜单中。

使用 winget（待软件包进入 winget 的软件库之后）：

```powershell
winget install HunterEwok.cbb
cbb install           # in the administrator terminal; again after each winget upgrade
```

## OpenWrt

运行 OpenWrt 25.12 或更高版本、并能容纳 25 MB 程序的路由器（128 MB 或更多闪存，或 eMMC；256 MB 内存），以 root 通过 SSH 执行：

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

它把 `cbb` 安装为只在 `lan` 区域工作的服务，永远不会在 `wan` 上应答。密钥保存在 `/etc/cbb`，sysupgrade 会保留它；在有人值守的 sysupgrade（ASU、owut）之后，请再运行一次该命令。其他区域（比如 IoT 网络）、防火墙和检查见[路由器与 FreeBSD](../admin/routers.md#openwrt)。

也可以使用我们的软件包源，之后 `apk upgrade` 会让它保持最新。软件源的架构取决于路由器的 CPU（`grep DISTRIB_ARCH /etc/openwrt_release`）：`aarch64_*` 用 `arm64`，名称含 `neon` 或 `vfp` 的 `arm_cortex-a*` 用 `armv7`，`mipsel_*` 用 `mipsle`，`mips_*` 用 `mips`，`x86_64` 用 `amd64`。请把第二行中的 `arm64` 换成你的架构：

```sh
uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
apk update && apk add cbb
```

`apk del cbb` 会将其移除，并把密钥保留在 `/etc/cbb`。

## FreeBSD

FreeBSD 15，amd64 或 arm64，以 root 身份（使用 `sudo` 或 `doas`）：

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

它会安装 `cbb` 和一个通过 daemon(8) 运行服务的 rc.d 脚本，并在 rc.conf 中加入 `cbb_enable="YES"` 这一行。密钥保存在 `/var/db/cbb`。

在 OPNsense 上，同一个安装程序还会添加一个插件钩子：服务会显示在 System > Diagnostics > Services 中，它的防火墙规则（在 pf 的锚点 `cbb` 里）会随每次过滤器重载而保持生效。服务运行期间请关闭 mDNS 中继（Services > mDNS Repeater）：两者都需要 UDP 端口 5353，而服务会在每个家庭接口上自行应答 mDNS。不支持 pfSense：安装程序在那里也能运行，但它只会打印防火墙规则，让你到 Firewall > Rules 中自己添加，而且 pfSense 的更新可能会移除 Copy Beyond Borders。

在 FreeBSD 桌面上（X11，或支持 data control 协议的 Wayland，如 KDE、sway 和 Hyprland），会话通过 XDG 自动启动运行 `cbb agent`，剪贴板便加入群组；安装后请重新登录。远程粘贴在 X11 上通过 XTEST 输入，在 wlroots 桌面上通过虚拟键盘输入；GNOME 在 FreeBSD 上不支持远程粘贴，因为没有 logind，就无从得知屏幕是否已锁定。

## Docker

适用于始终开机的 NAS 或家用服务器（[镜像的说明](../../packaging/docker/README.md)；从 0.5 起随每个版本发布）。它作为普通成员加入：请在手机或你保管群组的电脑上创建群组。

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair
```

## 防火墙

Copy Beyond Borders 需要一个 TCP 端口 8764 和 mDNS（UDP 5353），两者都只面向家庭网络。安装程序会找出防火墙（Linux 上的 ufw、firewalld、nftables 或 iptables，FreeBSD 上的 pf 或 ipfw，Mac 的应用程序防火墙，Windows 防火墙），列出每条规则，并询问 `Add these rules now? [y/N]`：

- **是**：它会添加这些规则，每次更新时保持它们有效，并在你卸载时移除它们。它绝不会动其他规则。
- **否**（默认；没有终端可供询问时也是如此）：它什么也不添加，而是打印出确切的命令，由你自己运行。
- `--express`（Windows 上是 `-Express`）不询问直接添加；`--no-firewall` 等同于回答“否”。

nftables 和 iptables 总是只给出命令，因为运行时添加的规则在重启后不会保留。在 FreeBSD 上，pf 的规则放在它自己的锚点中，pf 通过安装程序在 `/etc/pf.conf` 末尾添加（并会再移除）的三行带标记的内容来读取它；ipfw 的规则放在规则集 17 中，每次启动时重新添加。如果你之后才打开防火墙，请再运行一次安装程序。

**使用其他端口**，如果 8764 被占用：`... | sudo sh -s -- --port 9000`（在 Windows 上，先设置 `$env:CBB_PORT = "9000"` 再运行安装程序）。手机应用从二维码中获知端口。

所有安装程序选项见[命令参考](../reference/cli.md#installers)。

## 更新

从 0.6 起，发布的版本都带有签名。要从更早的版本升级到 0.6，请再运行一次安装命令；此后由 `cbb update` 完成。

`sudo cbb update`（在 Windows 上，是在以管理员身份打开的终端中运行 `cbb update`）会在通过 `get.sh`、`get.ps1` 或发布压缩包安装的电脑或轻量成员上安装最新版本；`cbb update -check` 只告诉你是否有新版本。你的设置会保留。它只安装项目签名过的版本，也绝不安装旧版本。如果新版本在一分钟内没有启动，上一个版本会自动恢复。它如何校验签名，见[协议](../protocol.md)第 16 节。

安装程序会问一次是否自动更新（`--auto-update on|off`；在 Windows 上是 `-AutoUpdate on|off` 和 `$env:CBB_AUTO_UPDATE`，可以事先回答）；之后可用 `sudo cbb update -auto on|off` 更改。开启后，定时器每天在各自的时间检查一次：Linux 上是 systemd 定时器，Mac 上是 launchd 任务，Windows 上是以 SYSTEM 身份运行的计划任务，OpenWrt 和 FreeBSD 上是 cron。每次检查都会从 GitHub（GitHub 无响应时从 `dl.cbb.tools`）下载同样的几个小文件，所以和任何下载一样，GitHub 会知道这台设备的地址以及它在使用 Copy Beyond Borders；它不会发送任何关于群组的信息。`sudo cbb update -mirror https://...` 则改从另一个镜像获取更新，这无需任何信任，因为签名会被校验。定时器的日志是 `update.log`，位于 `/var/lib/cbb-update`（Linux）、`/etc/cbb-update`（OpenWrt）、`/var/db/cbb-update`（FreeBSD）、`/Library/Application Support/cbb-update`（Mac）或 `C:\Program Files\cbb-update`（Windows）。

群组中的设备会互相告知它们中任何一台见过的最新已签名版本，所以只要有一台设备检查过，其他设备上的 `cbb status` 和托盘应用就能提示有新版本（托盘应用中的“Update to X”会以管理员身份运行 `cbb update`）。每台设备仍会自己校验签名，并下载自己的压缩包。

再次运行同样的安装命令也能更新。使用 Homebrew 或 winget 时，请在那里升级，然后再运行第二行；`cbb update` 也会这样提示。Docker 和 OpenWrt 软件包则通过 `docker compose pull` 和 `apk upgrade` 更新。

## 校验下载

一行式安装程序会对照版本的 `SHA256SUMS` 校验下载内容。每个发布文件还带有构建来源证明，把它与本仓库以及生成它的构建关联起来；使用 [GitHub CLI](https://cli.github.com/)：

```sh
gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
```

当已安装 `gh` 且已为 root 登录（`sudo gh auth login`）时，`get.sh` 会自行校验；设置 `CBB_ATTESTATION=require` 后，没有它就拒绝安装。

发布的版本还用项目自己的密钥签名，这些密钥从不接触 CI（根密钥存放在离线的硬件密钥上，发布密钥在维护者的 Secure Enclave 中）：`keys.json` 指明根密钥之下的发布密钥，`release.json` 列出该版本每个文件及其哈希，`stable.json` 说明当前是哪个版本。待根密钥内置到安装程序之后，`get.sh`（需要 `openssl`）和 `get.ps1` 会在安装前检查这些文件，并拒绝未签名的版本；在此之前，它们只检查 `SHA256SUMS` 和来源证明。`CBB_VERIFY=skip` 会跳过检查直接安装。

## 卸载

在 Linux 和 Mac 上：

```sh
sudo sh /usr/local/share/cbb/uninstall.sh
```

在 SteamOS 上是 `sudo sh /opt/cbb/share/uninstall.sh`。使用 Homebrew 时，之后再运行 `brew uninstall cbb`。

在 Windows 上：设置，应用，“CBB”，卸载。

这会移除程序、服务、安装程序添加的防火墙规则，以及 Mac 上由 `.pkg` 安装的应用。设备的密钥会保留，所以再次安装可让它回到原来的群组。要连密钥一起删除，请加上 `--purge`（Windows 上是 `-Purge`，命令为 `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1" -Purge`），然后在另一台设备上把这台设备从群组中移除（`sudo cbb remove NAME`，或在手机上操作）。要退出群组但保留 CBB，请改为运行 `sudo cbb leave`：它会删除密钥和群组的文件，之后设备可以重新加入群组。
