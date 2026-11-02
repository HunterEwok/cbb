<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: ce6e8f0e4357 -->
# 快捷操作

适合想从手机或群组中的另一台电脑锁定、休眠或重启一台电脑的人。管理员只需点一下或敲一条命令就能执行某个操作；设备只有在它自己的用户已在本机开启该操作时才会执行。

## 这些操作

| 操作 | 作用 | 适用于 |
|---|---|---|
| `lock` | 锁定屏幕 | 电脑 |
| `sleep` | 让电脑进入睡眠 | 电脑 |
| `reboot` | 一分钟后重启电脑 | 电脑、轻量成员 |
| `shutdown` | 一分钟后关闭电脑 | 电脑 |
| `cancel-shutdown` | 取消待执行的重启或关机 | 电脑、轻量成员 |
| `restart` | 重启 Clipboard Bridge 服务 | 电脑、轻量成员 |
| `keyboard-layout` | 在你切换了设备本身的布局之后，把它的[蓝牙键盘](keyboards-and-tvs.md)所用的布局切换到下一个 | 打开了键盘的 Linux 电脑 |
| 你自己的操作 | 以当前登录的用户身份运行你选定的程序 | 电脑 |

重启或关机前有一分钟的预警，让电脑前的人有时间保存工作，或运行 `cancel-shutdown`。Windows 还会向已登录的用户发出警告。

## 开启某个操作

在设备上，以管理员身份（Linux、macOS 和 FreeBSD 上用 `sudo`）：

```sh
cbb action                     # lists the actions and who may run each
sudo cbb action enable lock    # says what it allows and asks you to type yes
sudo cbb action enable reboot -by root,phone
sudo cbb action disable lock
```

`-by` 限制谁可以执行：`root`、`phone`（管理员手机）、`computer`（管理员电脑）、`watch`（拥有管理员密钥的手表）。不加它，则每个管理员都可以。`reboot` 和 `shutdown` 只接受密钥在硬件中的管理员，即手机或带 TPM 的电脑，除非你加上 `-any-key`。

在 Linux 上，启用时会写入 polkit 规则，赋予服务恰好满足已开启操作所需的权限，停用时则收回。

## 你自己的操作

```sh
sudo cbb action add backup -by phone -- /usr/local/bin/backup.sh --quick
sudo cbb action remove backup
```

当前登录用户的代理程序会按完整路径运行该程序，参数完全照此，不经过 shell。发送方只会得到它的退出状态。它必须在 15 秒内结束；任何更耗时的事情请放到后台去启动。

## 执行操作

在管理员电脑上：`cbb action -on DEVICE NAME`，它会说明是否已执行，或为什么没有执行。

在管理员手机上，设备在线时打开它的页面，点按“Quick actions”下的操作；用 Face ID 或指纹确认，重启和关机还会再确认一次。管理员手表可以执行允许 `watch` 使用的操作。

## 全部关闭

在设备上运行 `sudo cbb action off` 会关闭那里的所有操作。管理员可以用 `cbb action off -on DEVICE` 或 `-all` 在另一台设备或所有设备上关闭，手机上的“Turn all off”作用相同；只有各设备自己的用户才能重新开启它们。

每台设备会保留它最近被要求执行的 100 次操作的日志，记录是谁请求的、何时请求的。
