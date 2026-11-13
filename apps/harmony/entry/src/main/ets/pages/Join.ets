// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Joining a group: the phone's QR code and its numbers while it listens,
// or, joining by an invitation, the words the inviting admin compares.

import { router } from '@kit.ArkUI';
import { app } from '../model/AppModel';
import { Join as JoinModel } from '../model/Join';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';
import { QrView } from '../components/QrView';

@Entry
@ComponentV2
struct Join {
  @Local invite: string = '';
  // The model's join, a field so that the monitor sees its state.
  @Local joining: JoinModel = app.join;

  aboutToAppear(): void {
    const params = router.getParams() as Record<string, Object> | undefined;
    if (params !== undefined) {
      this.invite = params['invite'] !== undefined ? String(params['invite']) : '';
    }
    this.begin();
  }

  aboutToDisappear(): void {
    if (app.join.state !== 'joined') {
      app.join.stop();
    }
  }

  begin(): void {
    if (this.invite.length > 0) {
      app.startJoinByInvite(this.invite);
    } else {
      app.startJoin();
    }
  }

  @Monitor('joining.state')
  joined(): void {
    if (app.join.state === 'joined') {
      router.clear();
      router.replaceUrl({ url: 'pages/Main' });
    }
  }

  title(): ResourceStr {
    if (this.invite.length > 0) {
      return $r('app.string.start_invitation');
    }
    return $r('app.string.start_join');
  }

  lead(): ResourceStr {
    const state = app.join.state;
    if (state === 'joined') {
      return $r('app.string.join_joined');
    }
    if (state === 'joining' && this.invite.length === 0) {
      return $r('app.string.join_joining');
    }
    if (this.invite.length > 0) {
      return state === 'dialing' ? $r('app.string.join_dialing') : $r('app.string.join_invite_lead');
    }
    return $r('app.string.join_lead');
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: this.title(), back: () => {
          router.back();
        } })
        Text(this.lead()).fontSize(16).fontColor($r('app.color.text'))
        if (app.join.state === 'listening' || app.join.state === 'joining') {
          if (app.join.modules.length > 0) {
            Column() {
              QrView({ modules: app.join.modules, side: 260 })
            }
            .width('100%')
            .alignItems(HorizontalAlign.Center)
          }
          Text(app.join.code)
            .fontSize(32)
            .fontFamily('monospace')
            .letterSpacing(4)
            .fontColor($r('app.color.text'))
            .width('100%')
            .textAlign(TextAlign.Center)
            .copyOption(CopyOptions.LocalDevice)
        }
        if (app.join.byInvite && app.join.fingerprint.length > 0 && app.join.state !== 'failed') {
          Text(app.join.fingerprint)
            .fontSize(26)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('app.color.accent'))
            .width('100%')
            .textAlign(TextAlign.Center)
        }
        BusyLine({ busy: app.join.state === 'joining' || app.join.state === 'dialing' || app.join.state === 'idle' })
        ErrorText({ text: app.join.error })
        if (app.join.state === 'failed') {
          Button($r('app.string.try_again'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
            this.begin();
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
