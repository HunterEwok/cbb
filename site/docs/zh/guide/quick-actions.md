<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 2424dc0d0064 -->
# 快捷操作

适合想从管理员手机或群组中的另一台管理员电脑锁定、休眠、重启、关闭某台电脑，或在其上运行固定程序的人。

**管理员**只需点按一下或输入一条命令就能运行快捷操作，但目标电脑只有在其自己的用户于本机开启该操作时才会执行。每项快捷操作默认关闭，任何人都无法从远程开启操作。

## 内置操作

| 操作 | 作用 | 支持的设备 |
|---|---|---|
| `lock` | 锁定屏幕 | 电脑、小型设备 |
| `sleep` | 让电脑进入睡眠 | 电脑、小型设备 |
| `reboot` | 提前 1 分钟警告后重启电脑 | 电脑、小型设备 |
| `shutdown` | 提前 1 分钟警告后关闭电脑 | 电脑、小型设备 |
| `cancel-shutdown` | 取消待执行的重启或关机 | 电脑、小型设备 |
| `restart` | 重启 Connect Beyond Borders 服务 | 电脑、小型设备 |
| `keyboard-layout` | 将电脑[蓝牙键盘](keyboards-and-tvs.md)的当前布局切换到下一个布局 | 开启了蓝牙键盘的 Linux 电脑 |

`reboot` 或 `shutdown` 前的 1 分钟延迟能让正在使用电脑的人有时间保存工作或运行 `cancel-shutdown`。在 Windows 上，已登录的用户还会看到系统警告。

在 macOS 和 Windows 上，会话操作（`lock`、`sleep` 和自定义操作）通过已登录用户的剪贴板代理运行，因此必须有人处于登录状态。在 macOS 上，`lock` 要求将**系统设置 > 锁定屏幕 > 进入屏幕保护程序或关闭显示器后需要密码**设为**立即**。

## 1. 开启内置操作

在目标电脑上运行以下命令（在 Linux、macOS 和 FreeBSD 上使用 `sudo`；在 Windows 上使用管理员终端且省略 `sudo`）：

1. 列出所有操作，并查看哪些管理员被允许运行每项操作：

   ```sh
   cbb action
   ```

2. 开启一项操作：

   ```sh
   sudo cbb action enable lock
   ```

   阅读该操作所允许的内容并输入 `yes`（或在脚本中传入 `-yes`）。

   **结果：**该操作会对群组中的每位管理员开启。在 Linux 上，Connect Beyond Borders 会写入 `/etc/polkit-1/rules.d/60-cbb.rules`，仅向服务授予已开启操作所需的 polkit 权限。

3. 你也可以选择限制哪些管理员可以运行某项操作：
   - 用 `-by` 按签名者类型限制（`root` 表示主设备，`phone` 表示管理员手机，`computer` 表示管理员电脑，`watch` 表示手表签名者）：

     ```sh
     sudo cbb action enable reboot -by root,phone
     ```

   - 默认情况下，`reboot` 和 `shutdown` 只接受密钥存放在硬件中的管理员（手机、带 Secure Enclave 的 Mac 或带 TPM 2.0 的电脑）。要同时允许密钥在文件中的管理员，请加上 `-any-key`：

     ```sh
     sudo cbb action enable reboot -any-key
     ```

要再次关闭某项操作：

```sh
sudo cbb action disable lock
```

**结果：**该操作会立即关闭。在 Linux 上，停用会更新或移除 polkit 规则，从而收回不再使用的权限。

## 2. 添加你自己的操作

每台电脑最多可以定义 32 个自定义操作（名称必须是 1 到 32 个小写字母、数字或连字符，且以字母开头）。

1. 在目标电脑上注册该命令，在 `--` 后提供程序的完整路径：

   ```sh
   sudo cbb action add backup -by phone -- /usr/local/bin/backup.sh --quick
   ```

2. 阅读该操作所允许内容的摘要并输入 `yes`。

**结果：**Connect Beyond Borders 会将该命令保存在你的用户设置（`own-actions.json`）中，因此只有已登录用户的代理能够不经 shell 运行该确切的可执行文件和参数列表。发送方只会收到退出状态。命令必须在 15 秒内结束；耗时更长的任务请在后台启动。

要移除自定义操作：

```sh
sudo cbb action remove backup
```

## 3. 从管理员运行操作

- **从管理员电脑（终端）：**

  ```sh
  cbb action -on DEVICE NAME
  ```

  将 `DEVICE` 替换为 `cbb status` 中显示的目标名称或设备 ID，将 `NAME` 替换为操作名称。

  **结果：**`cbb` 会打印操作是否已运行，或目标拒绝它的原因。

- **从管理员手机：**
  1. 打开 **CBB**，在**主页**上点按在线的目标电脑。
  2. 在**快捷操作**下，点按你要运行的操作。
  3. 用你的面容、指纹、密码或（在 Aurora OS 上）管理员 PIN 确认。`reboot` 和 `shutdown` 会要求第二次确认。

  **结果：**目标会运行该操作，手机会显示**完成。**

## 4. 关闭所有操作

- **在目标电脑本机：**

  ```sh
  sudo cbb action off
  ```

- **从任意管理员电脑远程关闭：**

  ```sh
  sudo cbb action off -on DEVICE     # one computer
  sudo cbb action off -all           # every computer in the group
  ```

- **从管理员手机远程关闭：**在**主页**上打开该设备页面，然后点按**全部关闭**。

**结果：**受影响电脑上的所有快捷操作会立即关闭。只有每台电脑自己的用户才能在本机重新开启它们。

每台目标电脑都会保留一份最近 100 次操作请求的审计日志（`actions-log.json`），记录是谁在何时请求了哪项操作。确切限制见[限制与有效期](../reference/limits.md#remote-paste-and-quick-actions)。
