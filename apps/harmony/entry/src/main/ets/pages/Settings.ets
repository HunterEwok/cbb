// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Settings (components/SettingsBody.ets): every part of them on one page.

import { router } from '@kit.ArkUI';
import { PageTitle } from '../components/Common';
import { SettingsBody } from '../components/SettingsBody';

@Entry
@ComponentV2
struct Settings {
  build() {
    Scroll() {
      Column({ space: 12 }) {
        PageTitle({ title: $r('app.string.settings_title'), back: () => {
          router.back();
        } })
        SettingsBody({ part: '' })
      }
      .padding(24)
      .alignItems(HorizontalAlign.Start)
      .width('100%')
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }
}
