<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6f28736f9b01 -->
# 图片、文件和带格式的文本

适合复制的不只是纯文本的人。在一台设备上复制的图片、文件管理器里的文件，或带格式的文本，可以原样粘贴到其他设备上。

## 什么内容去哪里

| 复制的内容 | 有桌面的电脑 | 手机 | 没有桌面的电脑 | 轻量成员 |
|---|---|---|---|---|
| 带格式的文本（浏览器、办公软件） | 带格式粘贴 | 作为纯文本粘贴 | 纯文本 | 纯文本 |
| 图片（PNG、JPEG；Mac 上的 TIFF 和手机上的 HEIC 会被转换） | 作为图片粘贴 | 通过应用中的按钮粘贴；也会自动到达，iPhone 上在应用运行时 | 只有其中的文字；`cbb paste -o DIR` 会保存图片 | 只有其中的文字；它会把图片转交出去 |
| 文件和文件夹 | 作为复制的文件粘贴 | 应用会保存它们：Android 保存到“下载”，iPhone 保存到“文件”中该应用的文件夹 | `cbb paste -o DIR` 会保存它们 | 转交出去，自己不保留 |

同时包含文字和图片的一次复制，按文字发送。在文件管理器中的剪切会被当作复制：任何地方都不会删除任何东西。

## 如何传递

复制的内容本身留在复制它的那台设备上。其他设备只会得知有了新的复制，以及它的大小；开启了同步的设备，会立即从那台设备（或另一台拥有它的设备）获取，走的是与文本相同的加密连接。

离家时，中枢会获取每一份复制，并通过群组的隧道转交出去，大小不超过它自己的上限。

## 大小

| 位置 | 默认值 | 在每台设备上更改 |
|---|---|---|
| 在家 | 每份复制 100 MiB | `cbb config max-copy SIZE`，1 MiB 到 1 GiB |
| 通过群组的隧道 | 每份复制 25 MiB | `cbb config max-copy-away SIZE`，不超过 `max-copy` |
| 来自手机的分享菜单 | Android 100 MiB，iPhone 50 MB | 不可更改 |

超过某台设备上限的复制不会在该设备上获取，`cbb status` 会指出这一点。中枢的 `max-copy-away` 限制了所有从远处连到它的设备。所有上限都列在[限制与有效期](../reference/limits.md#copies)中。

## 通过命令行

```sh
cbb copy photo.jpg notes/              # sends files and folders as one copy
cbb copy -type png screenshot.png      # sends one image as an image
cbb paste -o ~/Downloads               # saves the clipboard's images or files there
cbb status                             # shows a copy that is still arriving
```

`cbb paste -o` 会在复制内容仍在到达时等待，绝不会覆盖已有文件，也不会让任何文件变为可执行。

## 安全

- 收到的文件保存在你的用户缓存中的专用文件夹里，只有你能读取，并在出现更新的复制 10 分钟后被删除。Mac 会将它们标记为已下载（隔离），Windows 会加上网络标记（Mark of the Web），所以其中若有程序，系统会在打开之前发出警告。任何文件都不会变为可执行。
- 名称会被处理成在所有系统上都安全的形式，文件夹中的链接和特殊文件会被略去。
- 机密内容的格式从不会被读取；机密内容只以纯文本发送。
- 服务会在其状态目录中保留当前的复制，以及 10 分钟内的旧复制，重启之后什么都不保留。
