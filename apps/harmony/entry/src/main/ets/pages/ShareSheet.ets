// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The Share menu's sheet (shareextability/ShareExtAbility.ets): what it
// sends and how that ended, and Done to close it.

import { sheet } from '../model/Sheet';

@Entry
@ComponentV2
struct ShareSheet {
  build() {
    Column({ space: 16 }) {
      Text($r('app.string.app_name')).fontSize(18).fontWeight(FontWeight.Medium).fontColor($r('app.color.accent'))
      if (sheet.phase === 'sending') {
        LoadingProgress().width(36).height(36).color($r('app.color.accent'))
      }
      Text(sheet.message)
        .fontColor(sheet.phase === 'failed' ? $r('app.color.error') : $r('app.color.text'))
        .textAlign(TextAlign.Center)
        .copyOption(CopyOptions.LocalDevice)
      if (sheet.phase !== 'sending') {
        Button($r('app.string.done'), { type: ButtonType.Capsule })
          .backgroundColor($r('app.color.accent'))
          .onClick(() => sheet.close())
      }
    }
    .padding(24)
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Center)
    .backgroundColor($r('app.color.background'))
  }
}
