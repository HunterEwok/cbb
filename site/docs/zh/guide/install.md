<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: d11a83f383ef -->
# 安装

写给在电脑、路由器或家用服务器上安装、更新、校验或卸载 Connect Beyond Borders 的人。手机、平板电脑、手表和电视应用见[应用](apps.md)。

Connect Beyond Borders 在每台电脑上作为一个小型后台服务运行。它的命令行工具是 `cbb`。下面每种方式安装的都是同一个服务；选择适合你系统的方式即可。

## Linux

支持使用 `systemd`、架构为 x86-64、ARM64、ARMv7 和 ARMv6 的 Linux 系统（笔记本电脑、台式机、树莓派开发板、服务器和 Steam Deck）。

1. 在终端中运行安装程序：

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

2. 回答关于防火墙规则（检测到活动防火墙时显示）和每日自动更新的提示。
3. 注销并重新登录一次，这样你的账户（已加入 `cbb` 组）就可以不用 `sudo` 直接运行 `cbb`。

在装有 GTK 4 和 WebKitGTK 6.0 的 x86-64 和 ARM64 桌面上（Debian 和 Ubuntu 上为 `libgtk-4-1 libwebkitgtk-6.0-4`；Fedora 上为 `gtk4 webkitgtk6.0`），安装程序还会安装托盘应用（`cbb-desktop`），它会随桌面会话启动并出现在应用程序菜单中。如果缺少这些库，安装程序会列出需要安装的软件包名称；安装后再运行一次安装程序即可装上托盘应用。

你可以在 `sh -s --` 后面向 `get.sh` 传入额外选项：

- **文本控制台（`--console`）**：适用于没有桌面的机器，可在 `tmux` 中支持复制和粘贴，并安装 `cbb-console.service` 以在文本控制台中支持远程粘贴：

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --console
  ```

- **跳过桌面粘贴对话框（`--uinput`）**：在 GNOME 和 KDE 上，远程粘贴在按键之前会先弹出一次系统对话框确认。加上 `--uinput` 会安装 `cbb-uinput.service` 并加载 `uinput` 内核模块，让 Connect Beyond Borders 直接按下粘贴键（绝不会在登录界面或锁屏界面执行）。此选项需要 `cbb-helper`。
- **不带辅助程序的小型设备（`--no-helper`）**：在只需同步的小型设备上省略 `cbb-helper`（该辅助程序负责处理 TPM 密钥、桌面剪贴板、远程粘贴按键输入、蓝牙键盘和电视遥控器）：

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --no-helper
  ```

  见[小型设备](../../member/README.md)。MIPS 路由器的归档包默认不包含 `cbb-helper`。一旦设备以不带 `cbb-helper` 的方式安装，后续更新也会保持如此。

也支持在 Linux（x86-64 和 ARM64）上使用 Homebrew：

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/linux/install.sh" "$(brew --prefix)/opt/cbb/bin/cbb"
```

每次执行 `brew upgrade` 后，请重新运行第二条命令。

### 不使用 sudo（无 root）

在没有管理员权限（`sudo`）的 Linux 电脑上，可以不用 `sudo`，只为你自己的用户账户安装 Connect Beyond Borders：

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

这会将 `cbb` 安装到 `~/.local/bin`，并在你登录期间作为 `systemd` 用户服务运行。它不能与系统级安装共存。

只有在无法进行常规安装时才使用无 root 安装。由于在你用户账户下运行的任何程序都可以读取其密钥文件，无 root 设备永远不能成为**主设备**、**管理员**或**中心节点**（[无 root 成员](how-it-works.md#rootless-members)）。无 root 安装也没有防火墙规则、不支持 TPM，也没有 `--console` 或 `--uinput` 辅助程序。

- **注销后保持运行**：如果安装程序无法自动启用驻留（lingering），请让管理员运行一次 `sudo loginctl enable-linger YOUR-USER`。
- **不带辅助程序**：传入 `--no-helper --rootless` 以同时省略 `cbb-helper`（见[小型设备上的无 root 安装](../../member/README.md#without-sudo-rootless)）。
- **卸载**：运行 `sh ~/.local/share/cbb/uninstall.sh`。

### SteamOS（Steam Deck）

1. 切换到**桌面模式**并打开 **Konsole**。
2. 如果你还没有为 `deck` 用户设置密码，请运行 `passwd` 设置一个。
3. 运行 Linux 安装命令：

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

SteamOS 每次系统更新都会替换根文件系统，因此安装程序会把 Connect Beyond Borders 安装在 `/opt/cbb` 而非 `/usr/local`，并将 `/etc` 下的配置文件登记在 `/etc/atomic-update.conf.d/cbb.conf` 中。你的安装和群组成员身份在 SteamOS 更新后会继续保留。

- 注销并重新登录后，`cbb` 会位于 Konsole 的 `PATH` 中。由于 `sudo` 不会搜索 `/opt/cbb/bin`，需要 `sudo` 的命令必须使用完整路径，例如 `sudo /opt/cbb/bin/cbb pair -code`。
- 在桌面模式下，剪贴板同步方式与其他任何 KDE Plasma 桌面相同。
- 在游戏模式下没有桌面剪贴板，因此不会同步；服务会继续运行，并在你回到桌面模式时追上进度。
- 要卸载，请运行 `sudo sh /opt/cbb/share/uninstall.sh`。

## Mac

支持运行 macOS 14 或更高版本的 Apple 芯片和 Intel Mac。

- **安装程序包（推荐，包含菜单栏应用）**：从[最新 GitHub 发布版本](https://github.com/HunterEwok/cbb/releases/latest)下载 `cbb-X.Y.Z.pkg` 并打开。该安装包会安装 **CBB** 菜单栏应用（`/Applications/CBB.app`）和后台服务，两者均已签名并经过公证。
- **终端（仅安装服务和 `cbb`，不含菜单栏应用）**：

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
  ```

- **Homebrew（仅安装服务和 `cbb`，不含菜单栏应用）**：

  ```sh
  brew install hunterewok/tap/cbb
  sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
  ```

  每次执行 `brew upgrade` 后，请重新运行第二条命令，以便用新版本重启服务和剪贴板代理。

## Windows

支持 x86-64 和 ARM64 架构的 Windows 10（1809 或更高版本）和 Windows 11。

1. 右键选择**以管理员身份运行**打开 PowerShell。
2. 运行安装程序：

   ```powershell
   irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
   ```

3. 回答关于 Windows 防火墙规则和每日自动更新的提示。
4. 打开一个新的终端窗口以使用 `cbb`。

安装程序会将当前登录的用户加入 `cbb` 组、启动后台服务和剪贴板代理，并安装托盘应用（登录时启动，在“开始”菜单中名为 **CBB**）。在 Linux 和 macOS 上需要使用 `sudo` 更改群组成员身份或设置的命令，在 Windows 上需在管理员终端中运行。

使用 **winget** 安装（使用 `HunterEwok.cbb` 软件包）：

```powershell
winget install HunterEwok.cbb
cbb install
```

在管理员终端中运行 `cbb install`，以便从已解包的软件包安装服务、剪贴板代理、托盘应用和防火墙规则；每次执行 `winget upgrade` 后也请再次运行该命令。

## OpenWrt

支持运行 OpenWrt 25.12 或更高版本（使用 `apk`）且有空间容纳 25 MB 程序的路由器（至少 128 MB 闪存或 eMMC，以及 256 MB 内存）。

以 `root` 身份通过 SSH 连接并运行：

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

安装程序会将 `cbb`（不含 `cbb-helper`）设置为一个 `procd` 服务，仅监听 `lan` 区域，绝不在 `wan` 上响应。密钥保存在 `/etc/cbb/state` 中，`sysupgrade` 会保留它；在执行有人值守的 sysupgrade（ASU 或 `owut`）后，请再次运行安装命令。在交互式终端中运行时，安装程序会立即开始配对（传入 `--no-pair` 可跳过）。关于其他区域（如 IoT 网络）、防火墙细节和检查项，见[路由器和 FreeBSD](../admin/routers.md#openwrt)。

你也可以从项目的 `apk` 软件包源安装，以便通过 `apk upgrade` 保持更新：

1. 使用 `grep DISTRIB_ARCH /etc/openwrt_release` 查看路由器的架构，并将其对应到软件源目录：
   - `aarch64_*` → `arm64`
   - `arm_cortex-a*`（名称中含 `neon` 或 `vfp`）→ `armv7`
   - `mipsel_*` → `mipsle`
   - `mips_*` → `mips`
   - `x86_64` → `amd64`
2. 添加软件源密钥和仓库（将 `arm64` 替换为你的架构）并安装：

   ```sh
   uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
   echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
   apk update && apk add cbb
   ```

`apk del cbb` 会移除软件包，同时保留 `/etc/cbb` 中的密钥。请注意，`mips` 和 `mipsle` 路由器版本仅在家庭网络内同步（不支持离家同步）。

## FreeBSD

支持 FreeBSD 15（`amd64` 和 `arm64`）。以 `root` 身份（使用 `sudo` 或 `doas`）运行：

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

安装程序会安装 `cbb`，添加一个通过 `daemon(8)` 运行服务的 `rc.d` 脚本，并在 `rc.conf` 中添加 `cbb_enable="YES"`。密钥保存在 `/var/db/cbb`，设置保存在 `/usr/local/etc/cbb`。

- **OPNsense**：同一个安装程序还会添加一个插件钩子，使服务显示在 **System > Diagnostics > Services** 中，并让其防火墙规则（位于 `pf` 锚点 `cbb` 中）在过滤器重载后仍然保留。Connect Beyond Borders 运行期间，请关闭 **Services > mDNS Repeater**，因为两者都需要 UDP 端口 5353，而服务会在每个家庭网络接口上自行响应 mDNS。
- **pfSense（不受支持）**：安装程序可以在 pfSense 上运行，会打印需在 **Firewall > Rules** 中手动添加的规则，但 pfSense 系统更新可能会将其移除。
- **FreeBSD 桌面**：在 X11 上，或在支持 data-control 协议的 Wayland 合成器（如 KDE、sway 和 Hyprland）上，重新登录后 XDG 自动启动会运行 `cbb agent`。远程粘贴在 X11 上使用 XTEST，在 wlroots 桌面上使用虚拟键盘；FreeBSD 上的 GNOME 不接受远程粘贴，因为在没有 `logind` 的情况下无法获知锁屏状态。

## Docker

适用于没有桌面的 NAS 或始终开机的家用服务器（见 [Docker 镜像 README](../../packaging/docker/README.md)）。容器作为普通成员加入；请在手机或你掌控的电脑上创建群组。

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair -code
```

先在手机或管理员电脑上打开配对窗口，然后在 `cbb pair -code` 提示时输入这六位数字。

## 防火墙

Connect Beyond Borders 需要来自家庭网络的传入 **TCP 端口 8764**（或你自定义的成员端口）和 **UDP 端口 5353**（mDNS），仅限家庭网络。

安装程序会检测你的防火墙（Linux 上的 `ufw`、`firewalld`、`nftables` 或 `iptables`；FreeBSD 上的 `pf`、`ipfw` 或 OPNsense；macOS 应用程序防火墙；Windows 防火墙），列出所需的每条规则，并提示 `Add these rules now? [y/N]`（在 macOS 上为 `Add this rule now? [y/N]`）：

- **是**：安装程序会添加这些规则、在升级时保持更新，并在卸载时移除它们，不会修改任何其他规则。
- **否**（默认选项，以及在未连接交互式终端时）：安装程序不添加任何规则，并打印确切的命令供你自行运行。
- **无人值守选项**：
  - 在 Linux、macOS 和 FreeBSD 上：传入 `--express` 以不经询问直接添加规则，或传入 `--no-firewall` 以拒绝并打印命令。
  - 在 Windows 上：在运行 `get.ps1` 前设置 `$env:CBB_FIREWALL = "express"` 或 `$env:CBB_FIREWALL = "no"`（或在运行 `install.ps1` 时传入 `-Express` 或 `-NoFirewall`）。

不同防火墙的具体行为：

- `nftables` 和 `iptables` 始终只打印手动命令，因为运行时规则在重启后不会保留。
- FreeBSD 的 `pf` 将规则放在其专用的 `cbb` 锚点中，并通过添加到 `/etc/pf.conf` 末尾的三行带标记配置加载（卸载时会移除）。FreeBSD 的 `ipfw` 将规则添加到规则集 17，并在每次启动时重新加载。
- 如果你在安装 Connect Beyond Borders 之后才启用防火墙，请重新运行安装程序。

如果 TCP 8764 已被占用，可使用其他成员端口：

- 在 Linux、macOS、FreeBSD 和 OpenWrt 上：传入 `--port 9000`（例如 `... | sudo sh -s -- --port 9000`）。
- 在 Windows 上：在运行 `get.ps1` 前设置 `$env:CBB_PORT = "9000"`（或在运行 `install.ps1` 时传入 `-Port 9000`）。

所有安装程序选项列于[命令参考](../reference/cli.md#installers)。

## 更新

请让群组中的所有设备保持相同版本。兼容性详情见[版本与兼容性](../reference/compatibility.md)。

### 手动更新

- **通过 `get.sh`、`get.ps1` 或发布归档包安装**：
  - 检查是否有新版本：`cbb update -check`
  - 安装最新的已签名版本：`sudo cbb update`（在 Windows 上，在管理员终端中运行 `cbb update`；在无 root 的 Linux 上，不用 `sudo` 直接运行 `cbb update`；在 SteamOS 上，运行 `sudo /opt/cbb/bin/cbb update`）。

  `cbb update` 会保留你的设置和密钥，只安装项目签名的版本，拒绝旧版本；如果更新后的服务在一分钟内未能启动，会自动恢复到上一个版本。重新运行原来的 `get.sh` 或 `get.ps1` 命令同样可以更新。
- **Homebrew**：运行 `brew upgrade cbb`，然后重新运行 [Mac](#mac) 或 [Linux](#linux) 部分的 `install.sh` 命令。
- **winget**：运行 `winget upgrade HunterEwok.cbb`，然后在管理员终端中运行 `cbb install`。
- **Docker**：运行 `docker compose -f compose.home.yaml pull` 并重建容器。
- **OpenWrt 软件包源**：运行 `apk update && apk upgrade`。

### 自动更新

对于通过 `get.sh` 和 `get.ps1` 进行的安装，安装程序会询问一次是否开启每日自动更新。你可以预先指定答案，也可以之后再更改：

- **安装期间**：向 `get.sh` 传入 `--auto-update on` 或 `--auto-update off`；在 Windows 上，运行 `get.ps1` 前设置 `$env:CBB_AUTO_UPDATE = "on"` 或 `"off"`（或向 `install.ps1` 传入 `-AutoUpdate on|off`）。
- **安装之后**：运行 `sudo cbb update -auto on` 或 `sudo cbb update -auto off`（在无 root 的 Linux 上不加 `sudo`；在 Windows 上使用管理员终端）。

开启自动更新后，每日定时任务会检查已签名的新版本：Linux 上为 `systemd` 定时器（无 root 安装为用户定时器），macOS 上为 `launchd` 任务，Windows 上为以 `SYSTEM` 运行的计划任务，OpenWrt 和 FreeBSD 上为 `cron`。

每次检查都会从 GitHub 下载体积很小的已签名元数据文件（如果 GitHub 无响应，则回退到 `dl.cbb.tools`）。GitHub 会看到设备的 IP 地址以及它在请求 Connect Beyond Borders 的元数据，但看不到关于你群组的任何信息。要改用自定义镜像，请运行 `sudo cbb update -mirror https://...`；该镜像无需受信任，因为签名仍会被验证。

自动更新的日志会写入以下目录中的 `update.log`：

| 系统 | 更新日志目录 |
|---|---|
| Linux | `/var/lib/cbb-update` |
| Linux（无 root） | `~/.local/state/cbb-update` |
| SteamOS | `/opt/cbb-update` |
| OpenWrt | `/etc/cbb-update` |
| FreeBSD | `/var/db/cbb-update` |
| macOS | `/Library/Application Support/cbb-update` |
| Windows | `C:\Program Files\cbb-update` |

群组中的设备会共享各自见过的最新已签名版本通知，因此当有可用更新时，`cbb status` 和桌面应用会提醒你。每台设备仍会自行验证签名并下载各自的归档包。

## 校验下载

每个发布归档包都会通过三种方式进行校验：

1. **校验和（`SHA256SUMS`）**：`get.sh` 和 `get.ps1` 都会对照该版本的 `SHA256SUMS` 文件校验下载的归档包。
2. **项目发布签名**：发布版本使用项目的离线根密钥和发布密钥签名（这些密钥从不接触 CI）：`keys.json` 用项目根密钥认证发布密钥，`release.json` 列出每个文件的大小和 SHA-256 哈希，`stable.json` 指定当前稳定版本（[协议](../protocol.md)第 16 节）。`get.sh`（使用 `openssl`）和 `get.ps1` 都内置了项目的根密钥，会拒绝安装签名验证失败的任何版本。安装了 OpenSSL 3.5 或更高版本时，`get.sh` 会同时验证 ES256 和 SLH-DSA-SHA2-128s（较旧的 OpenSSL 上验证 ES256）；`get.ps1` 验证 ES256。如需跳过项目签名校验直接安装，请设置 `CBB_VERIFY=skip`。
3. **构建来源证明**：每个发布文件都带有 GitHub 构建来源证明，将其与本仓库的发布工作流绑定。使用 [GitHub CLI](https://cli.github.com/)（`gh`）可以手动验证任意文件：

   ```sh
   gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
   ```

   如果已安装并登录 `gh`（`gh auth login`；通过 `sudo` 运行 `get.sh` 时需先运行 `sudo gh auth login`），`get.sh` 和 `get.ps1` 会自动执行此检查。设置 `CBB_ATTESTATION=require` 可在缺少已验证证明时拒绝安装，设置 `CBB_ATTESTATION=skip` 则跳过证明检查。

## 卸载

运行适用于你系统的卸载命令：

| 系统 | 命令或步骤 |
|---|---|
| Linux 和 macOS | `sudo sh /usr/local/share/cbb/uninstall.sh` |
| Linux（无 root） | `sh ~/.local/share/cbb/uninstall.sh` |
| SteamOS | `sudo sh /opt/cbb/share/uninstall.sh` |
| FreeBSD | `sudo sh /usr/local/share/cbb/uninstall.sh`（或使用 `doas`） |
| OpenWrt | `sh /usr/share/cbb/uninstall.sh`（若通过软件源安装，则运行 `apk del cbb`） |
| Windows | 打开**设置 > 应用 > CBB > 卸载**，或以管理员身份运行 `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1"` |

如果是通过 Homebrew 安装的，请先运行卸载脚本，再运行 `brew uninstall cbb`。

卸载会移除程序、后台服务、剪贴板代理、更新定时器、安装程序添加的防火墙规则，以及（在 macOS 上）通过 `.pkg` 安装的 `/Applications/CBB.app`。你设备的密钥和群组状态会保留在磁盘上，这样重新安装即可重新加入同一个群组。

- **同时删除密钥和群组状态**：在 Unix 系统上加上 `--purge`，或在 Windows 上以管理员身份在 PowerShell 中运行 `uninstall.ps1 -Purge`。之后，请在管理员设备上将该设备从群组中移除（`sudo cbb remove NAME` 或在手机应用中操作）。
- **退出群组但不卸载**：运行 `sudo cbb leave`（无 root 的 Linux 不加 `sudo`，Windows 上在管理员终端中运行 `cbb leave`）。这会删除设备的密钥和群组文件，同时保留 Connect Beyond Borders 已安装，使该设备可以再次加入群组。
