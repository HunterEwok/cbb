<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: ee7b34adad9e -->
# 图片、文件和格式化文本

适合复制的不只是纯文本的人。在本页中，你会了解哪些内容类型可以在电脑和手机之间同步、如何通过命令行或手机发送和保存图片与文件，以及如何更改每台设备的大小限制。

当你在一台设备上复制图片、文件管理器中的文件或格式化文本时，复制的设备会对内容进行端到端密封并通知你的群组。其他开启了**同步**的设备会在各自的大小限制内自动获取。关于端到端加密的工作方式，见[工作原理](how-it-works.md#what-happens-when-you-copy)。

## 什么内容去哪里

| 复制的内容 | 有桌面的电脑 | 手机 | 没有桌面的电脑和小型设备 |
|---|---|---|---|
| **格式化文本**（来自浏览器或办公应用的 HTML） | 带格式粘贴（最多 8 MiB 的 HTML） | 作为纯文本粘贴 | 纯文本 |
| **图片**（PNG、JPEG、GIF；macOS 上的 TIFF 和手机上的 HEIC 会被转换） | 直接作为图片粘贴 | 打开 **CBB** 或点按同步按钮时同步到剪贴板；作为文件接收时，在 Android 和 Aurora OS 上也会保存到图库，在 iPhone 上保存到**照片** | 仅纯文本；用 `cbb paste -o DIR` 保存图片 |
| **文件和文件夹** | 在文件管理器或应用中作为文件粘贴 | **Android：**保存到 `Downloads/CBB`（单张图片或单个视频会存入 `CBB` 图库相册）。**iPhone：**保存到**文件 > 我的 iPhone > CBB**（单张图片或单个视频会存入**照片**）。**Aurora OS：**保存到 `Downloads/CBB`（图片存入图库）。**HarmonyOS：**通过**保存收到的文件**按钮保存 | 用 `cbb paste -o DIR` 保存 |

在文件管理器中剪切文件会被当作复制处理：Connect Beyond Borders 绝不会删除任何设备上的源文件。当桌面剪贴板同时包含文本和图片、且没有单独选择文件时，除非明确复制图片，否则纯文本优先。

## 在手机上发送和保存

1. **从手机发送文件或图片：**打开文件管理器、图库或其他应用，选择**分享 > Connect Beyond Borders**，如有询问请确认。在 Android、iPhone、Aurora OS 和 HarmonyOS 上，分享的图片和文件都会同步到群组中的电脑。
2. **保存手机收到的文件：**打开 **CBB**（或触发同步）。在 Android、iPhone 和 Aurora OS 上，文件会自动保存到上表中的位置。在 HarmonyOS 上，收到文件就绪通知时，在**主页**上点按**保存收到的文件**。

**结果：**分享的图片会出现在你电脑的剪贴板上，收到的文件会出现在手机的下载、文件或图库文件夹中。

## 通过命令行发送和保存

在任意电脑或小型设备上运行以下命令，无需使用 `sudo`：

1. **将文件和文件夹作为一份副本发送：**

   ```sh
   cbb copy photo.jpg notes/
   ```

   添加 `-text "summary"` 可为只接收纯文本的设备附带一段纯文本备选内容。

   **结果：**Connect Beyond Borders 会打印已复制到群组的文件数和字节数。

2. **将单张图片或 HTML 文件作为剪贴板数据发送：**

   ```sh
   cbb copy -type png screenshot.png
   ```

   `-type` 接受 `png`、`jpeg`（或 `jpg`）、`gif` 或 `html`。

   **结果：**桌面电脑会以剪贴板图片或 HTML 数据的形式接收该文件，而不是作为文件附件。

3. **将剪贴板当前的图片或文件保存到文件夹：**

   ```sh
   cbb paste -o ~/Downloads
   ```

   **结果：**如果副本仍在传输中，`cbb` 会等待传输完成，按原有名称写出文件和文件夹（剪贴板数据则保存为 `image.png`、`image.jpg`、`image.gif` 或 `clipboard.html`），并打印所创建的每个顶层路径。它绝不会覆盖已有文件，也不会将任何文件设为可执行。

4. **检查传输进度：**运行 `cbb status` 可查看较大的副本是否仍在到达，或者是否因超过本设备的限制而被跳过。

## 更改大小限制

每台设备都会对图片和文件执行各自的大小限制。离家时，中心节点的 `max-copy-away` 限制会对通过该中心节点连接的每台设备生效。

| 范围 | 默认值 | 允许范围 | 更改方式 |
|---|---|---|---|
| **在家**（电脑和小型设备） | 每份副本 100 MiB | 1 MiB 到 1 GiB | `cbb config max-copy SIZE` |
| **通过群组的隧道**（电脑、小型设备和中心节点） | 每份副本 25 MiB | 1 MiB 到 `max-copy` | `cbb config max-copy-away SIZE` |
| **手机分享表单** | Android 上为 100 MiB；iPhone、Aurora OS 和 HarmonyOS 上为 50 MB | 固定 | 不可更改 |

要在电脑上查看或更改限制：

1. 查看当前限制：

   ```sh
   cbb config
   ```

2. 调高或调低限制（例如，在家设为 250 MiB，离家设为 50 MiB）：

   ```sh
   cbb config max-copy 250MiB
   cbb config max-copy-away 50MiB
   ```

**结果：**设备会立即应用新限制。将 `max-copy` 调低到 `max-copy-away` 以下时，`max-copy-away` 也会同步降低以保持一致。超过某台设备限制的副本不会在该设备上获取，`cbb status` 会注明该副本已被跳过。

所有副本大小和分段限制（包括 10,000 个分段上限和 256 KiB 备选文本上限），见[限制与有效期](../reference/limits.md#copies)。

## 安全

- **私密临时存储：**在桌面电脑上，剪贴板代理会将收到的文件解包到用户缓存中的一个私密文件夹（Linux 和 FreeBSD 上为 `~/.cache/cbb/received`，macOS 上为 `~/Library/Caches/cbb/received`，Windows 上为 `%LocalAppData%\cbb\received`），仅你的用户可读，并在有更新的副本到达 10 分钟后删除较旧的副本文件夹。
- **下载警告：**收到的文件绝不会被标记为可执行。macOS 会添加 `com.apple.quarantine` 属性，Windows 会添加网络标记（`Zone.Identifier`），因此系统会在打开收到的程序之前发出警告。
- **安全文件名：**Connect Beyond Borders 会跨操作系统清理文件名，并跳过复制文件夹中的符号链接和特殊文件。
- **纯文本机密：**绝不会读取机密内容的格式；机密内容只以纯文本传输。
- **服务缓存：**后台服务在运行时最多在其状态目录中保留最近 8 份密封的副本数据块，并在每次重启时清空该缓存。
