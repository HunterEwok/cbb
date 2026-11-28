<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6f215e8c49c0 -->
# 实验室

写给对日常剪贴板同步之外的 Connect Beyond Borders 实验性功能感兴趣的人。

Connect Beyond Borders 专注于一项核心承诺：让你的手机和电脑共用同一个加密剪贴板。实验室用于测试使用群组的其他方式。下面的每项实验都能构建并在 CI 中通过自动化测试，但它们属于实验性功能：随时可能变更或移除，且大多数在真实硬件上的测试有限。当前真机测试状态见[平台对等](../parity.md#on-real-devices)。

## 实验项目

| 实验项目 | 作用 | 指南 |
|---|---|---|
| **蓝牙和 USB 键盘** | Android、Aurora OS 或 HarmonyOS 手机、Linux 电脑或 Arduino Nano ESP32 向没有运行 Connect Beyond Borders 的电视、平板电脑、游戏机或电脑输入文字 | [键盘和电视](keyboards-and-tvs.md) |
| **电视遥控器** | 家庭网络中的一台电脑通过本地网络充当遥控器，直接向 Android TV、Google TV、Apple TV 或 Roku 输入文字 | [键盘和电视](keyboards-and-tvs.md#a-computer-as-the-tvs-remote) |
| **Arduino Nano ESP32** | 运行 Wi-Fi、TLS 1.3 协议自检以及 USB 和低功耗蓝牙键盘的低成本微控制器固件（加入群组和剪贴板同步已列入[路线图](../roadmap.md)） | [ESP32 固件](../../esp32/README.md) |
| **ZX Spectrum Next** | 通过 Accelerated Next 内部的树莓派复制文本和机密、粘贴文本、在 Layer 2 显示群组图片以及接收远程粘贴 | [Next 的 `.cbb`](../../apps/zxnext/README.md) |

## 在哪里找到实验室功能

- **手机应用（Android、Aurora OS 和 HarmonyOS）**：打开**设置**，开启**高级设置**，然后滚动到**实验室**（包含**蓝牙键盘**控制项）。
- **电脑**：在终端中使用 `cbb keyboard`（Linux）和 `cbb remote`（Linux、macOS、Windows 和 FreeBSD）；见[命令](../reference/cli.md)。
- **ESP32 和 ZX Spectrum Next**：按照上表中链接的各自设备设置说明操作。

## 分享反馈

如果你在真实硬件上试用了某项实验，请在 [GitHub issue](https://github.com/HunterEwok/cbb/issues) 中反馈使用情况。在真机上证明可靠的实验可能会走出实验室，成为正式支持的功能。
