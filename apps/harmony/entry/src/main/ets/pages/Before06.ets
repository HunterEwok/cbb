// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// A group from before 0.6, which this version no longer runs (D-126): the
// page says so and offers Leave. Only Leave, the person's choice, deletes
// the old group's files; then the phone makes a new group or joins one.

import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { app } from '../model/AppModel';
import { ErrorText, NORMAL_BUTTON } from '../components/Common';

@Entry
@ComponentV2
struct Before06 {
  async leave(): Promise<void> {
    if (await app.leave()) {
      router.clear();
      router.replaceUrl({ url: 'pages/Start' });
    }
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        Text($r('app.string.before06_title')).fontSize(24).fontWeight(FontWeight.Bold).fontColor($r('app.color.text'))
        Text($r('app.string.before06_body')).fontSize(15).fontColor($r('app.color.text'))
        ErrorText({ text: app.error })
        Button($r('app.string.settings_leave'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).attributeModifier(NORMAL_BUTTON)
          .fontColor($r('app.color.error'))
          .enabled(!app.busy)
          .onClick(() => {
            this.getUIContext().showAlertDialog({
              message: t('settings_leave_confirm'),
              primaryButton: { value: t('cancel'), action: () => {} },
              secondaryButton: { value: t('settings_leave'), fontColor: $r('app.color.error'), action: () => {
                this.leave();
              } }
            });
          })
      }
      .alignItems(HorizontalAlign.Start)
      .padding(16)
      .width('100%')
    }
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }
}
