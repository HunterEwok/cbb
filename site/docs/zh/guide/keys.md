<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 09c16892691e -->
# 密钥与认证

适合想了解每台设备在哪里存放加密密钥、设备如何证明密钥位于安全硬件中，以及为群组选择哪个**密钥级别**的人。完整的线路规范见[协议](../protocol.md)第 17 节和[密码学](../cryptography.md)。

群组中的每台设备都持有**成员密钥**，用来向你的其他设备证明身份。**主设备**（在命令行工具中称为 *root*）持有群组的主密钥，每位**管理员**持有一把管理员密钥，用于签署群组变更和命令。设备将这些密钥存放在哪里，决定了设备被盗时攻击者能提取到什么。

## 每台设备在哪里存放密钥

应用中的设备列表以及 `cbb status` 的 `KEYS` 列会显示每台设备的密钥存储层级：**已验证**（`proven hardware`）、**硬件**（`hardware`）、**文件**（`in a file`）或**无 root**（`in a file, rootless`）。

| 设备 | 成员密钥、管理员密钥和主密钥的存放位置 | 主设备/管理员签名前的确认方式 | 显示的存储层级 | 小偷能带走什么 |
|---|---|---|---|---|
| **iPhone 和 iPad** | Secure Enclave（硬件） | 面容 ID、触控 ID 或密码 | `hardware` | 无可复制之物；密钥只在解锁后于该设备上签名 |
| **Android 手机或平板电脑**（引导加载程序已锁定、系统经验证） | Android Keystore（StrongBox 或 TEE，硬件） | 指纹、面容或屏幕锁定（由 Keystore 强制执行） | `proven hardware` | 无可复制之物；群组还会离线验证硬件证明 |
| **Android 手机或平板电脑**（引导加载程序已解锁，或自签名系统如 GrapheneOS） | Android Keystore（StrongBox 或 TEE，硬件） | 指纹、面容或屏幕锁定 | `hardware` | 无可复制之物；Google 的根证书无法为系统验证作保 |
| **Aurora OS 5 手机** | OP-TEE 安全元件（硬件） | 应用自己的管理员 PIN（创建时至少 6 位数字；连续 7 次错误会永久锁定管理员密钥） | `hardware` | 无可复制之物；成员密钥同步无需 PIN，管理员/主密钥需要 PIN |
| **Aurora OS 4 和 Sailfish OS 手机** | 手机上的应用文件 | 无硬件确认 | `in a file` | 密钥文件的副本，在被移除前可在任意位置使用 |
| **HarmonyOS 5+ 手机或平板电脑** | HUKS（TEE，硬件） | 面容、指纹或 PIN（User Authentication Kit） | `hardware` | 无可复制之物；密钥只在验证后于该设备上签名 |
| **搭载 Apple 芯片或 T2 芯片的 Mac** | Secure Enclave（硬件）；本地和隧道机密由 Secure Enclave 密封 | 通过系统提示使用 macOS 触控 ID 或管理员密码 | `hardware` | 无可复制之物；密钥只在该台 Mac 上签名 |
| **没有 T2 芯片的 Intel Mac** | 服务状态文件（`/Library/Application Support/cbb/state`） | macOS 管理员密码 | `in a file` | 若磁盘可读则可复制密钥文件；请用 FileVault 加密 |
| **带 TPM 2.0 和 `cbb-helper` 的 Linux 或 Windows 电脑** | TPM 2.0（硬件）；本地和隧道机密由 TPM 密封 | Linux polkit 或 Windows Hello / 管理员提示 | `proven hardware`（有芯片内 EK 证书）或 `hardware` | 无可复制之物；密钥只在该台电脑上签名 |
| **无 TPM 的 Linux 或 Windows 电脑、FreeBSD、OpenWrt、OPNsense、无 `cbb-helper` 的小型设备、Docker** | 服务状态文件（仅服务账号可读） | 管理员权限（`sudo` 或管理员终端） | `in a file` | 若磁盘或卷可读则可复制密钥文件；请加密磁盘（LUKS、BitLocker） |
| **Linux 无 root 安装（`--rootless`）** | `~/.local/state/cbb` 中的用户文件 | 无（你用户的任何程序都能读取） | `in a file, rootless` | 你账号下运行的任何程序都能复制密钥文件；永不能担任主设备、管理员或中心节点 |

在电脑上设置 `CBB_TPM=off` 会让新生成的密钥保存在文件而非硬件中。Docker 容器默认拒绝保存主密钥或管理员密钥，除非你在其环境中设置了 `CBB_KEYS_IN_FILE=yes`。

### 恢复密钥

创建群组时，Connect Beyond Borders 会从一个随机的 32 字节机密派生出群组的**恢复密钥**（一把 ECDSA P-256 密钥与一把抗量子 SLH-DSA-SHA2-128s 密钥配对）。这个机密只显示一次，绝不保存在群组的任何设备上。你可以把它保存在纸上（恢复单）、密封到 YubiKey（固件 5.3 或更高版本）上一个未使用的退役 PIV 槽位（槽位 95 至 82），或两者都保存。

## 密钥如何被证明

任何设备都可以声称其密钥位于硬件中，被篡改的程序也可以作假声明。**硬件认证**让安全芯片签署加密证明，证实该密钥是在芯片内部生成的且无法离开芯片。

- **Android 密钥认证：**当 Android 应用创建密钥时，Android Keystore 会签发一条以 Google 认证根证书为起点的证书链，描述该密钥（StrongBox 或 TEE、已锁定的引导加载程序、经验证的启动状态）。主设备会离线验证这条证书链，并将该手机记为**已验证**。不会向 Google 发送任何数据。
- **已解锁的引导加载程序和自定义系统：**运行已解锁引导加载程序或自签名操作系统（例如 GrapheneOS）的手机，仍将密钥存放在 StrongBox 或 TEE 中，因此密钥无法被提取。但由于证书链无法为出厂验证的系统作保，群组会将该手机记为**硬件**而非**已验证**。
- **被吊销的 Android 认证密钥：**Google 会公布一份硬件认证密钥已泄露的设备列表。项目在 `cbb.tools` 上的服务器每天获取一次该列表，并提供带签名的副本（`https://cbb.tools/attest/`）。主设备从 `cbb.tools` 获取签名副本，因此你的设备从不联系 Google。证书序列号出现在列表上的任何手机都会从**已验证**降为**硬件**。
- **电脑上的 TPM 2.0 认证：**带有 TPM 2.0 和 `cbb-helper` 的 Linux 或 Windows 电脑会将密钥存放在 TPM 中。如果 TPM 含有制造商写入芯片内的背书密钥（EK）证书（常见于独立 Infineon、ST 和 Nuvoton TPM 芯片，例如树莓派 TPM 板），主设备无需联系任何外部服务器即可离线验证 TPM 的凭据激活，并将该电脑记为**已验证**。固件 TPM（常见于 Intel 和 AMD 处理器）通常不包含芯片内 EK 证书，因此仍记为**硬件**。

## 三个级别

你群组的**密钥级别**规定了设备担任**主设备**、**管理员**或**读取副本的中心节点**所需的最低密钥存储层级。

**只转发副本的中心节点**不需要密钥级别，因为每份副本都端到端密封并绕过它：复制了其密钥的攻击者可以拖延流量并观察元数据（见[隐私：中间的设备能看到什么](privacy.md#what-the-devices-in-between-see)），但无法读取或伪造副本。**无 root 成员**在任何密钥级别下都绝不能成为主设备、管理员或中心节点。

1. **仅限经验证的硬件（`proven`）：**只有密钥经过硬件认证证明的设备（`proven`）才能担任主设备、管理员或读取副本的中心节点。在 Android 上，严格验证要求证书链通过 Google 的远程密钥配置（RKP）签发。自身密钥不是 `proven` 的主设备无法将群组设为这一级别。
2. **密钥在硬件中（`hardware`，默认且推荐）：**任何密钥存放在安全硬件中的设备（`hardware` 或 `proven`）都可以担任主设备、管理员或读取副本的中心节点。离线证明（Android 密钥认证和带芯片内 EK 证书的 TPM）仍会被验证和显示，而且除了从 `cbb.tools` 获取共享的吊销列表外，没有任何设备信息会离开你的家庭网络。
3. **密钥也可在文件中（`files`）：**每次给出明确警告后（终端中为 `cbb admin -allow-file-key`，应用中为警告对话框），也允许密钥存放在文件中的设备（`file`）担任主设备、管理员或读取副本的中心节点。在没有 TPM 或 Secure Enclave 的电脑上创建的群组默认从 `files` 开始。

### 查看或更改密钥级别

只有群组的**主设备**可以更改密钥级别：

- **在手机或桌面应用中：**打开**设置**，开启**高级设置**，然后前往**群组 > 管理员密钥**。
- **在主电脑的终端中：**运行 `cbb keys` 查看当前级别，或用以下命令设置：

  ```sh
  sudo cbb keys proven
  sudo cbb keys hardware
  sudo cbb keys files
  ```

群组中已有较弱密钥的管理员和中心节点在被你移除前仍会保持有效，Connect Beyond Borders 会警告你哪些设备低于新级别。

## 如果设备丢失

请尽快将丢失的设备移出群组；见[如果设备丢失或被盗](lost-device.md)。存放在硬件中的密钥无法被提取，也不能离开该设备使用；存放在文件中的密钥则在你移除该设备前都可以被复制并使用。
