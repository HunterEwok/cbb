// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// "Add a device" in a group of 0.6 (docs/apps.md, "Screens"): the admin
// phone opens its home window, shows its QR code and six digits and has the
// core announce it at home; a new phone scans the code, or a device without
// a camera finds the window and its person types the digits. Nobody is
// asked; the window lets one device in. Leaving the page closes the window.

import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { app } from '../model/AppModel';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';
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
    return app.window.state === 'open' || app.window.state === 'joining';
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: $r('app.string.admit_title'), back: () => {
          router.back();
        } })
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
        if (this.showsCode() && app.window.digits.length > 0) {
          // The digits a device without a camera types, in two groups of three.
          Text(`${app.window.digits.substring(0, 3)} ${app.window.digits.substring(3)}`)
            .fontSize(34)
            .fontFamily('monospace')
            .fontWeight(FontWeight.Bold)
            .letterSpacing(4)
            .fontColor($r('app.color.text'))
            .width('100%')
            .textAlign(TextAlign.Center)
            .accessibilityText(app.window.digits.split('').join(' '))
        }
        if (this.showsCode()) {
          Text($r('app.string.window_hint')).fontSize(14).fontColor($r('app.color.secondary'))
          BusyLine({ busy: true, label: $r('app.string.window_waiting') })
        }
        if (app.window.state === 'preparing' || app.window.state === 'idle') {
          BusyLine({ busy: true, label: $r('app.string.admit_connecting') })
        }
        if (app.window.state === 'closed' && app.window.error.length === 0) {
          Text($r('app.string.window_closed')).fontColor($r('app.color.text'))
        }
        ErrorText({ text: app.window.error })
        if (app.window.state === 'failed' || app.window.state === 'closed' || app.window.state === 'done') {
          Button(app.window.state === 'done' ? $r('app.string.admit_title') : $r('app.string.try_again'), { type: ButtonType.Capsule })
            .width('100%')
            .onClick(() => {
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
