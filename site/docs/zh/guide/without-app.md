<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 31ed0dc98c03 -->
# 不用应用

写给只想用电脑、不使用手机应用来创建和管理 Connect Beyond Borders 群组的人。在本页中，你会在一台电脑上创建群组、添加家庭网络中的更多电脑、设置第二台管理员，并通过 SSH 或 VPN 从其他网络添加电脑。

![一台 Linux 电脑持有群组，用六位数字码添加 Mac 和 Windows](../images/without-app.svg)

创建群组的电脑会成为群组的**主设备**（在命令行工具和图示中称为 *root*）。[无 root Linux 安装](install.md#without-sudo-rootless)永远不能成为主设备或管理员，而 Docker 容器在保管群组密钥之前需要在环境中设置 `CBB_KEYS_IN_FILE=yes`。

## 1. 在电脑上创建群组

选择一台经常开机的电脑（Linux、macOS、Windows 或 FreeBSD），并[安装 Connect Beyond Borders](install.md)。

1. 在该电脑上运行（在 Windows 上，于管理员终端中不带 `sudo` 运行；或在 Mac 应用或托盘应用中点按**创建群组**）：

   ```sh
   sudo cbb new
   ```

2. 保存屏幕上显示的**恢复单**——四行字母和数字以及一个二维码。将其打印或抄写下来，并与你的设备分开存放。

**结果**：这台电脑成为群组的主设备。在配备 Apple 芯片或 T2 芯片的 Mac，或带有 TPM 2.0 的 Linux 或 Windows 电脑上，其密钥存放在安全硬件中；否则存放在受保护的文件中（`cbb keys` 初始为 `files`；见[密钥与认证](keys.md)）。没有任何地方会保留恢复单的副本——如果这台电脑丢失，它是迁移群组的唯一方式。

## 2. 添加家庭网络中的电脑

在同一家庭网络中的每台其他电脑上安装 Connect Beyond Borders，然后进行配对：

1. 在主设备（或任意管理员电脑）上打开配对窗口：

   ```sh
   sudo cbb pair
   ```

   **结果**：终端会显示 6 位配对码和一个二维码，并等待 5 分钟。你也可以在 Mac 应用或托盘应用中点按 **+** 按钮打开配对窗口。

2. 在新电脑上加入群组：
   - **终端**：运行 `sudo cbb pair -code`（在 Windows 上，于管理员终端中省略 `sudo`），并在提示时输入这 6 位数字。
   - **桌面应用**：打开 **CBB**，选择**加入群组**，然后输入这 6 位数字。

   每次输错代码都会用掉 3 次机会中的一次；失败 3 次后，或者一旦有设备加入，窗口就会关闭。

**结果**：两台电脑都会确认加入，你的剪贴板会自动同步。在一台电脑上复制文本，在另一台上粘贴以验证（见[快速入门：在一台上复制，在另一台上粘贴](quickstart.md#4-copy-on-one-paste-on-another)）。

## 3. 添加第二台管理员并妥善保管恢复单

将第二台电脑提升为**管理员**，这样在主设备离线时你仍然可以添加和移除设备。请注意，只有直接与主设备配对过的电脑才能被提升为管理员。

1. 运行 `cbb status` 查找该电脑的名称或设备 ID。
2. 在主设备上提升该电脑：
   - **带有 TPM 2.0 或 Secure Enclave 的电脑**：

     ```sh
     sudo cbb admin NAME
     ```

   - **密钥存放在文件中的电脑**（需要密钥级别为 `files`，可通过 `sudo cbb keys files` 设置）：

     ```sh
     sudo cbb admin -allow-file-key NAME
     ```

     任何复制了文件密钥管理员的密钥文件的人都可以冒充管理员行事，直到另一位管理员将该电脑移除，因此只对物理安全且磁盘已加密的电脑进行提升。

**结果**：`cbb status` 会将第二台电脑列为管理员，它可以对普通成员运行 `sudo cbb pair` 和 `sudo cbb remove NAME`。

如果主设备将来丢失或损坏，可以使用恢复单将群组移到群组中的另一台电脑：

```sh
sudo cbb recovery -leave LOST-DEVICE
```

然后在提示时输入恢复单上的恢复密钥（如果你将它封装在了 YubiKey 上，则传入 `-yubikey`）。完整步骤见[如果设备丢失或被盗](lost-device.md)。

## 从其他网络加入

要添加不在家庭网络中的电脑，可以通过中心节点发送[邀请](away-from-home.md#a-computer-that-is-not-at-home-an-invitation)，或者通过 SSH 隧道或你自己的 VPN 进行配对。

### 通过 SSH

1. 在新电脑上，将一个本地端口转发到主设备或管理员的成员端口（默认为 8764）：

   ```sh
   ssh -N -L 18764:localhost:8764 user@admin-machine
   ```

2. 在另一个 SSH 会话中，于主设备或管理员电脑上打开配对窗口：

   ```sh
   sudo cbb pair
   ```

   复制 6 位数字下方打印的完整 `cbb://pair?...` 行。（在没有本地网络发现的情况下，单凭 6 位数字无法定位配对窗口；`cbb://pair?...` 行同时包含窗口信息和配对码。）

3. 在新电脑上，通过转发的端口加入，并在提示时粘贴 `cbb://pair?...` 行：

   ```sh
   sudo cbb pair -code 127.0.0.1:18764
   ```

**结果**：新电脑会在 TLS 1.3 内通过 SSH 隧道加入群组。

### 通过你自己的 VPN

1. 在 Linux 上，如果你是在安装 Connect Beyond Borders 之后才设置 VPN 的，请重新运行安装程序，以便防火墙规则允许你的 VPN 子网。
2. 在主设备或管理员电脑上，运行 `sudo cbb pair` 并复制 6 位数字下方打印的 `cbb://pair?...` 行。
3. 在新电脑上，使用管理员电脑的 VPN 地址和端口加入，并在提示时粘贴 `cbb://pair?...` 行：

   ```sh
   sudo cbb pair -code ADMIN-VPN-ADDRESS:8764
   ```

**结果**：新电脑会在 TLS 1.3 内通过 VPN 加入你的群组。

配对秘密绝不会以明文传输：两台电脑会在 TLS 1.3 内各自派生会话证明。新电脑会继续通过临时配对路径同步，直到其服务重启；若希望在关闭 SSH 或 VPN 后长期保持同步，请先在两台设备上设置[离家同步](away-from-home.md)。
