// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// "Add a device" in a group of 0.6 (docs/apps.md, "Screens"): the admin
// phone opens its pairing window, shows its QR code and has the core
// announce it at home; a new phone scans the code or finds the window by
// itself, and the code both screens show waits for the person's "they
// match". Leaving the page closes the window.

import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { app } from '../model/AppModel';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';
import { CodeQuestion } from '../components/CodeQuestion';
import { QrView } from '../components/QrView';

@Entry
@ComponentV2
struct OpenWindow {
  aboutToAppear(): void {
    app.openWindow();
  }

  aboutToDisappear(): void {
    app.window.close();
  }

  showsCode(): boolean {
    return app.window.state === 'open' || app.window.state === 'done';
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: $r('app.string.admit_title'), back: () => {
          router.back();
        } })
        if (app.window.state === 'joining') {
          CodeQuestion({
            who: t('window_asks', app.window.joiningName),
            code: app.window.code,
            answered: (yes: boolean) => {
              app.window.answer(yes);
            }
          })
        }
        if (app.window.state === 'done') {
          Text(app.window.joined.length > 0 ? t('admit_done_named', app.window.joined) : t('window_joined'))
            .fontColor($r('app.color.text'))
        }
        if (this.showsCode() && app.window.modules.length > 0) {
          Column() {
            QrView({ modules: app.window.modules, side: 260 })
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
        }
        if (this.showsCode()) {
          Text($r('app.string.window_hint')).fontSize(14).fontColor($r('app.color.secondary'))
          BusyLine({ busy: true, label: $r('app.string.window_waiting') })
        }
        if (app.window.state === 'preparing' || app.window.state === 'idle') {
          BusyLine({ busy: true, label: $r('app.string.admit_connecting') })
        }
        if (app.window.state === 'closed') {
          Text($r('app.string.window_closed')).fontColor($r('app.color.text'))
        }
        ErrorText({ text: app.window.error })
        if (app.window.state === 'failed' || app.window.state === 'closed') {
          Button($r('app.string.try_again'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
            app.openWindow();
          })
        }
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
