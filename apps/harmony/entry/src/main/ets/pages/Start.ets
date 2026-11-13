// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Start, the same on every phone (docs/apps.md, "Start"): no group yet. It
// makes a new group, joins one by the phone's QR code (as an admin too),
// joins by a remote invitation, or restores a group from its recovery sheet.

import { router } from '@kit.ArkUI';
import { app } from '../model/AppModel';
import { BusyLine, ErrorText, KeyGuardNote } from '../components/Common';

@Entry
@ComponentV2
struct Start {
  async makeGroup(): Promise<void> {
    if (await app.makeGroup()) {
      router.replaceUrl({ url: 'pages/Main' });
    }
  }

  @Builder
  choice(label: ResourceStr, note: ResourceStr, primary: boolean, act: () => void) {
    Column({ space: 4 }) {
      Button(label, { type: ButtonType.Capsule, buttonStyle: primary ? ButtonStyleMode.EMPHASIZED : ButtonStyleMode.NORMAL })
        .width('100%')
        .enabled(!app.busy)
        .onClick(act)
      Text(note).fontSize(13).fontColor($r('app.color.secondary'))
    }
    .alignItems(HorizontalAlign.Start)
    .width('100%')
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        Text($r('app.string.start_title')).fontSize(34).fontWeight(FontWeight.Bold).fontColor($r('app.color.text'))
        Text($r('app.string.start_lead')).fontSize(17).fontColor($r('app.color.secondary'))
        Blank().height(16)
        this.choice($r('app.string.start_new_group'), $r('app.string.start_new_group_note'), true, () => {
          this.makeGroup();
        })
        KeyGuardNote({ hint: true })
        this.choice($r('app.string.start_join'), $r('app.string.start_join_note'), false, () => {
          router.pushUrl({ url: 'pages/Join' });
        })
        this.choice($r('app.string.start_invitation'), $r('app.string.start_invitation_note'), false, () => {
          router.pushUrl({ url: 'pages/Invitation' });
        })
        this.choice($r('app.string.start_restore'), $r('app.string.start_restore_note'), false, () => {
          router.pushUrl({ url: 'pages/Restore' });
        })
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
