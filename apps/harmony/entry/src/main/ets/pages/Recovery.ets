// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The root's recovery key (docs/apps.md, "Recovery key"): made, shown once
// as its text and QR code to write down or print, replaced or removed.

import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { app } from '../model/AppModel';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';
import { QrView } from '../components/QrView';

@Entry
@ComponentV2
struct Recovery {
  aboutToDisappear(): void {
    app.forgetRecovery();
  }

  confirm(message: string, button: string, yes: () => void): void {
    this.getUIContext().showAlertDialog({
      message: message,
      primaryButton: { value: t('cancel'), action: () => {} },
      secondaryButton: { value: button, fontColor: $r('app.color.error'), action: yes }
    });
  }

  lead(): string {
    if (app.recoveryText.length > 0) {
      return t('recovery_write_down');
    }
    return app.member.rootView.recovery === true ? t('recovery_has') : t('recovery_none');
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: $r('app.string.recovery_title'), back: () => {
          router.back();
        } })
        Text(this.lead()).fontColor($r('app.color.text'))
        if (app.recoveryText.length > 0) {
          Column() {
            QrView({ modules: app.recoveryModules, side: 240 })
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
          Text(app.recoveryText)
            .fontFamily('monospace')
            .fontSize(18)
            .fontColor($r('app.color.text'))
            .width('100%')
            .textAlign(TextAlign.Center)
          Button($r('app.string.recovery_wrote'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
            app.forgetRecovery();
          })
        } else if (app.isRoot()) {
          Button(app.member.rootView.recovery === true ? t('recovery_make_new') : t('recovery_make'),
            { type: ButtonType.Capsule })
            .width('100%')
            .enabled(!app.busy && app.member.running)
            .onClick(() => {
              if (app.member.rootView.recovery === true) {
                this.confirm(t('recovery_replace_confirm'), t('recovery_make_new'), () => {
                  app.makeRecovery();
                });
              } else {
                app.makeRecovery();
              }
            })
          if (app.member.rootView.recovery === true) {
            Button(t('recovery_remove'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
              .width('100%')
              .fontColor($r('app.color.error'))
              .enabled(!app.busy && app.member.running)
              .onClick(() => {
                this.confirm(t('recovery_remove_confirm'), t('recovery_remove'), () => {
                  app.removeRecovery();
                });
              })
          }
        }
        BusyLine({ busy: app.busy })
        ErrorText({ text: app.error })
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
